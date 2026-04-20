"""Backend-agnostic memory acquisition engine."""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from memslicer.acquirer.base import AcquireResult, BaseAcquirer
from memslicer.acquirer.bridge import DebuggerBridge, MemoryRange
from memslicer.acquirer.build_id_post import populate_from_bridge
from memslicer.acquirer.identity import AttributionConfig, resolve_target_identity
from memslicer.acquirer.investigation import InvestigationCollector
from memslicer.acquirer.os_detail import pack_os_detail, system_info_to_fields
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    CompAlgo, HashAlgo, OSType, PageState, RegionType, CapBit,
    Endianness, VERSION, HASH_SIZE, FLAG_INVESTIGATION, FLAG_ENCRYPTED,
)
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity, SystemContext,
    ProcessEntry, ConnectionEntry, HandleEntry, TargetIntrospection,
    KernelSymbolBundle,
)
from memslicer.msl.writer import MSLWriter
from memslicer.utils.protection import (
    PROT_R, PROT_W, PROT_X, format_protection, is_rwx, parse_protection,
)
from memslicer.utils.timestamps import now_ns


# Default max chunk size for splitting large regions (same as fridump)
_DEFAULT_MAX_CHUNK = 20971520  # 20 MB


def _build_target_introspection(proc_info, pid: int) -> TargetIntrospection:
    """Project a :class:`TargetProcessInfo` onto a :class:`TargetIntrospection`
    for wire emission (P1.6.3, Block 0x0058).

    Pulled out of the main acquire loop so ``AcquisitionEngine.acquire``
    stays readable — the projection is mechanical and every field has
    the same name on both sides. ``environ`` is stored on the
    ``TargetProcessInfo`` as a ``str`` (the redactor joins entries with
    ``\\x00``) and encoded to bytes here so the wire row carries the
    NUL-separated blob directly.
    """
    environ_blob = b""
    if getattr(proc_info, "environ", ""):
        environ_blob = proc_info.environ.encode("utf-8", errors="replace")
    return TargetIntrospection(
        target_pid=pid,
        tracer_pid=proc_info.tracer_pid,
        login_uid=proc_info.login_uid,
        session_audit_id=proc_info.session_audit_id,
        selinux_context=proc_info.selinux_context,
        target_ns_fingerprint=proc_info.target_ns_fingerprint,
        target_ns_scope_vs_collector=proc_info.target_ns_scope_vs_collector,
        smaps_rollup_pss_kib=proc_info.smaps_rollup_pss_kib,
        smaps_rollup_swap_kib=proc_info.smaps_rollup_swap_kib,
        smaps_anon_hugepages_kib=proc_info.smaps_anon_hugepages_kib,
        rwx_region_count=proc_info.rwx_region_count,
        target_cgroup=proc_info.target_cgroup,
        target_cwd=proc_info.target_cwd,
        target_root=proc_info.target_root,
        cap_eff=proc_info.cap_eff,
        cap_amb=proc_info.cap_amb,
        no_new_privs=proc_info.no_new_privs,
        seccomp_mode=proc_info.seccomp_mode,
        core_dumping=proc_info.core_dumping,
        thread_count=proc_info.thread_count,
        sig_cgt=proc_info.sig_cgt,
        io_rchar=proc_info.io_rchar,
        io_wchar=proc_info.io_wchar,
        io_read_bytes=proc_info.io_read_bytes,
        io_write_bytes=proc_info.io_write_bytes,
        limit_core=proc_info.limit_core,
        limit_memlock=proc_info.limit_memlock,
        limit_nofile=proc_info.limit_nofile,
        personality_hex=proc_info.personality_hex,
        ancestry=proc_info.ancestry,
        exe_comm_mismatch=proc_info.exe_comm_mismatch,
        environ=environ_blob,
        redacted_env_keys=list(proc_info.redacted_env_keys),
    )


def _hex_to_bytes(hex_str: str, *, expected_len: int | None = None) -> bytes:
    """Decode a hex string to raw bytes; return b"" on any failure.

    The P1.6.1 collector stores build-ids, BTF hashes, vmcoreinfo hashes,
    and kernel-config hashes as hex-encoded strings on ``TargetSystemInfo``.
    The wire format (``KernelSymbolBundle`` TLV rows) carries them as raw
    bytes, so this projection is the only place they are decoded.

    When ``expected_len`` is given, the decoded byte string must be
    exactly that long; otherwise the helper returns ``b""`` rather than
    silently emitting a wrong-length TLV row. SHA-256 fields pass
    ``expected_len=32``. The ``kernel_build_id`` field is variable-length
    (typically 20 for SHA-1 builds, 16 for MD5 legacy builds) and does
    not pass this parameter.
    """
    if not hex_str:
        return b""
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return b""
    if expected_len is not None and len(raw) != expected_len:
        return b""
    return raw


def _build_kernel_symbol_bundle(sys_info) -> KernelSymbolBundle:
    """Project a :class:`TargetSystemInfo` onto a :class:`KernelSymbolBundle`
    for wire emission (P1.6.1, Block 0x0055).

    Every field in the bundle corresponds one-for-one to a
    ``TargetSystemInfo`` attribute populated by the P1.6.1 collector
    helpers. String-typed flags (``la57_enabled``, ``pti_active``,
    ``ksm_active``, ``zswap_enabled``) are coerced from the canonical
    ``"1"``/``"0"`` convention into the u8 wire slot; hex fields are
    decoded via :func:`_hex_to_bytes`.
    """
    def _str_flag_to_u8(value: str) -> int:
        return 1 if value == "1" else 0

    return KernelSymbolBundle(
        page_size=sys_info.page_size,
        kernel_build_id=_hex_to_bytes(sys_info.kernel_build_id),
        kaslr_text_va=sys_info.kaslr_text_va,
        kernel_page_offset=sys_info.kernel_page_offset,
        la57_enabled=_str_flag_to_u8(sys_info.la57_enabled),
        pti_active=_str_flag_to_u8(sys_info.pti_active),
        btf_sha256=_hex_to_bytes(sys_info.btf_sha256, expected_len=32),
        btf_size_bytes=sys_info.btf_size_bytes,
        vmcoreinfo_sha256=_hex_to_bytes(sys_info.vmcoreinfo_sha256, expected_len=32),
        kernel_config_sha256=_hex_to_bytes(sys_info.kernel_config_sha256, expected_len=32),
        clock_realtime_ns=sys_info.clock_realtime_ns,
        clock_monotonic_ns=sys_info.clock_monotonic_ns,
        clock_boottime_ns=sys_info.clock_boottime_ns,
        clocksource=sys_info.clocksource,
        thp_mode=sys_info.thp_mode,
        ksm_active=_str_flag_to_u8(sys_info.ksm_active),
        directmap_4k_kib=sys_info.directmap_4k,
        directmap_2m_kib=sys_info.directmap_2m,
        directmap_1g_kib=sys_info.directmap_1g,
        zram_devices_json=sys_info.zram_devices,
        zswap_enabled=_str_flag_to_u8(sys_info.zswap_enabled),
    )


def _connectivity_table_is_empty(table) -> bool:
    """Return True when a :class:`ConnectivityTable` contains no rows of
    any type. Used to decide whether to emit the block at all and
    whether to set bit 4 in ``SystemContext.table_bitmap``.
    """
    if table is None:
        return True
    return not (
        table.ipv4_routes or table.ipv6_routes or table.arp_entries
        or table.packet_sockets or table.netdev_stats
        or table.sockstat_families or table.snmp_counters
    )


def classify_region(file_path: str) -> RegionType:
    """Classify a memory region based on its mapped file path."""
    if not file_path:
        return RegionType.Anon
    if "[heap]" in file_path:
        return RegionType.Heap
    if "[stack]" in file_path:
        return RegionType.Stack
    if file_path.endswith((".so", ".dylib", ".dll", ".exe")):
        return RegionType.Image
    if "/" in file_path or "\\" in file_path:
        return RegionType.MappedFile
    return RegionType.Unknown


def volatility_key(r: MemoryRange) -> tuple[int, int]:
    """Return sort key for volatility-first ordering.

    Priority (most volatile first):
      0 - rw- Anon/Heap/Stack (live runtime state)
      1 - rwx regions (JIT code, changes rapidly)
      2 - r-x Image (executable code, stable)
      3 - r-- MappedFile/Image (disk-backed, lowest priority)
      4 - everything else
    Secondary sort by base address for determinism.
    """
    prot = parse_protection(r.protection)
    region_type = classify_region(r.file_path)

    has_r = prot & PROT_R
    has_w = prot & PROT_W
    has_x = prot & PROT_X

    if has_r and has_w and not has_x:  # rw-
        if region_type in (RegionType.Anon, RegionType.Heap, RegionType.Stack):
            return (0, r.base)
    if is_rwx(prot):  # rwx
        return (1, r.base)
    if has_r and has_x and not has_w:  # r-x
        return (2, r.base)
    if has_r and not has_w and not has_x:  # r--
        return (3, r.base)
    return (4, r.base)


# Progress callback signature:
#   (regions_captured, total_ranges, bytes_captured, modules_captured, regions_processed)
ProgressCallback = Callable[[int, int, int, int, int], None]


# _system_info_to_os_detail_fields used to live here as a private helper.
# It's now the public ``system_info_to_fields`` in ``os_detail.py`` — same
# home as the packer it feeds. A thin alias preserves the old name so any
# external importer keeps working during the transition.
_system_info_to_os_detail_fields = system_info_to_fields


class AcquisitionEngine(BaseAcquirer):
    """Acquires process memory via a DebuggerBridge and writes MSL files.

    Memory reading strategy:
    - Try full region read via bridge.read_memory
    - If region is too large (> max_chunk_size), split into fixed-size chunks
    - On failure for any chunk, fall back to page-by-page reads
    """

    def __init__(
        self,
        bridge: DebuggerBridge,
        comp_algo: CompAlgo = CompAlgo.NONE,
        region_filter: RegionFilter | None = None,
        os_override: OSType | None = None,
        logger: logging.Logger | None = None,
        max_chunk_size: int = _DEFAULT_MAX_CHUNK,
        investigation: bool = False,
        passphrase: str | None = None,
        collector: InvestigationCollector | None = None,
        *,
        attribution: AttributionConfig | None = None,
        hash_algo: HashAlgo = HashAlgo.BLAKE3,
    ) -> None:
        self._bridge = bridge
        self._comp_algo = comp_algo
        self._hash_algo = hash_algo
        self._filter = region_filter or RegionFilter()
        self._os_override = os_override
        self._abort = threading.Event()
        self._progress_callback: ProgressCallback | None = None
        self._log = logger or logging.getLogger("memslicer")
        self._max_chunk_size = max_chunk_size
        self._investigation = investigation
        self._passphrase = passphrase
        self._collector = collector
        # Operator-supplied forensic attribution, pre-validated at the
        # CLI boundary — safe to embed in SystemContext as-is.
        self._attribution = attribution or AttributionConfig()

    def request_abort(self) -> None:
        """Request graceful abort of the current acquisition.

        Sets the abort flag so the acquire loop exits at the next iteration.
        The finally block in acquire() handles bridge cleanup.
        """
        self._abort.set()

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback.

        Signature: callback(regions_captured, total_ranges, bytes_captured,
                           modules_captured, regions_processed)
        """
        self._progress_callback = callback

    def _emit_progress(
        self, region_count: int, total_ranges: int,
        bytes_captured: int, modules: int, regions_processed: int,
    ) -> None:
        if self._progress_callback:
            self._progress_callback(
                region_count, total_ranges, bytes_captured,
                modules, regions_processed,
            )

    def acquire(self, output_path: Path | str) -> AcquireResult:
        """Acquire process memory and write MSL file."""
        start = time.monotonic()
        self._abort.clear()
        output_path = Path(output_path)

        region_count = 0
        total_ranges = 0
        bytes_captured = 0
        module_entries: list[ModuleEntry] = []
        regions_skipped = 0
        rwx_regions = 0
        bytes_attempted = 0
        pages_captured = 0
        pages_failed = 0
        skip_reasons: dict[str, int] = {}

        try:
            self._log.info("Connecting to target...")
            self._bridge.connect()

            self._log.info("Querying platform info...")
            platform = self._bridge.get_platform_info()

            os_type = self._os_override if self._os_override is not None else platform.os
            arch_type = platform.arch
            pid = platform.pid
            page_size = platform.page_size

            self._log.debug(
                "os=%s arch=%s pid=%d page_size=%d",
                os_type.name, arch_type.name, pid, page_size,
            )

            # Refine collector when bridge-detected OS differs from the
            # initial collector (which was based on host platform).  This
            # matters for remote targets where host != target OS.
            if self._investigation and self._collector is not None:
                self._maybe_refine_collector(os_type)

            # Enumerate modules BEFORE creating the header so we can
            # set the CapBitmap accurately.
            self._log.info("Enumerating modules...")
            modules_raw = self._bridge.enumerate_modules()
            self._log.debug("modules: %d", len(modules_raw))
            for m in modules_raw:
                entry = ModuleEntry(
                    base_addr=m.base,
                    module_size=m.size,
                    path=m.path,
                    version="",
                    disk_hash=b'\x00' * HASH_SIZE,
                    native_blob=b"",
                )
                module_entries.append(entry)

            # Live build-id extraction (Path A): reads the first 4 KiB
            # of each module via the debugger bridge and populates
            # ``ModuleEntry.native_blob`` + ``disk_hash``. Opt-in via
            # ``include_module_build_ids`` — the default acquire path
            # produces lean ModuleEntry blocks without build-ids so
            # that a minimal process-centric slice does not pay for
            # per-module bridge reads and hash work. Operators who
            # need build-ids either pass the flag or run
            # ``memslicer-enrich`` on the finished slice (Path C).
            if module_entries and self._attribution.include_module_build_ids:
                try:
                    populate_from_bridge(
                        module_entries, self._bridge, logger=self._log,
                        hash_algo=self._hash_algo,
                    )
                except Exception as exc:  # noqa: BLE001
                    self._log.warning(
                        "build-id extraction failed: %s", exc,
                    )

            # Build CapBitmap dynamically based on what will be emitted
            cap_bitmap = (1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
            if module_entries:
                cap_bitmap |= (1 << CapBit.ModuleList)

            flags = 0
            if self._investigation:
                flags |= FLAG_INVESTIGATION
                cap_bitmap |= (1 << CapBit.SystemContext)

            # Encryption setup
            encryption_key = None
            encryption_params = None
            if self._passphrase is not None:
                from memslicer.msl.encryption import EncryptionParams, derive_key
                flags |= FLAG_ENCRYPTED
                encryption_params = EncryptionParams()
                encryption_key = derive_key(self._passphrase, encryption_params)
                self._log.info("Encryption enabled (AES-256-GCM + Argon2id)")

            header = FileHeader(
                endianness=Endianness.LITTLE,
                version=VERSION,
                flags=flags,
                cap_bitmap=cap_bitmap,
                dump_uuid=uuid.uuid4().bytes,
                timestamp_ns=now_ns(),
                os_type=os_type,
                arch_type=arch_type,
                pid=pid,
                hash_algo=self._hash_algo,
            )

            with open(output_path, "wb") as f:
                writer = MSLWriter(
                    f, header, self._comp_algo,
                    encryption_key=encryption_key,
                    encryption_params=encryption_params,
                )

                try:
                    # Block 0: Process Identity (MUST be first)
                    proc_info = None
                    if self._collector is not None:
                        proc_info = self._collector.collect_process_identity(
                            pid,
                            include_target_introspection=(
                                self._attribution.include_target_introspection
                            ),
                            include_environ=self._attribution.include_environ,
                        )
                        proc_id = ProcessIdentity(
                            ppid=proc_info.ppid,
                            session_id=proc_info.session_id,
                            start_time_ns=proc_info.start_time_ns,
                            exe_path=proc_info.exe_path,
                            cmd_line=proc_info.cmd_line,
                        )
                    else:
                        proc_id = ProcessIdentity(
                            ppid=0, session_id=0, start_time_ns=0,
                            exe_path="", cmd_line="",
                        )
                    writer.write_process_identity(proc_id)

                    # Block 1: Module list (before memory regions per spec).
                    # Note: TargetIntrospection (P1.6.3, Block 0x0058) used
                    # to be emitted here between ProcessIdentity and the
                    # module list, which violated the "ModuleListIndex MUST
                    # be Block 1" rule. It now lands after SystemContext
                    # among the other P1.6 extension blocks.
                    if module_entries:
                        writer.write_module_list(module_entries)

                    # Block 2: SystemContext (Investigation mode only)
                    if self._investigation:
                        import getpass
                        import platform as platform_mod

                        # Collect system tables before writing context
                        # so we can set table_bitmap accurately
                        if self._collector is not None:
                            process_table = self._collector.collect_process_table(pid)
                            connection_table = self._collector.collect_connection_table()
                            handle_table = self._collector.collect_handle_table(pid)
                        else:
                            process_table = self._collect_process_table(pid)
                            connection_table = self._collect_connection_table()
                            handle_table = self._collect_handle_table(pid)

                        # System-context extension block collection. These
                        # must be materialized BEFORE ``SystemContext`` is
                        # written so ``table_bitmap`` can include the bits
                        # for any extension block that will actually appear
                        # in the slice. Collector calls return empty values
                        # when the platform is not Linux.
                        if self._collector is not None:
                            connectivity_table = self._collector.collect_connectivity_table()
                        else:
                            connectivity_table = None

                        # KernelModuleList is opt-in: memslicer is
                        # process-centric and kernel-wide enumeration is
                        # irrelevant to the default per-target workflow.
                        if (
                            self._attribution.include_kernel_modules
                            and self._collector is not None
                        ):
                            kernel_module_list = self._collector.collect_kernel_module_list()
                        else:
                            kernel_module_list = None

                        if self._attribution.include_persistence_manifest and self._collector is not None:
                            persistence_manifest = self._collector.collect_persistence_manifest()
                        else:
                            persistence_manifest = None

                        table_bitmap = 0
                        if process_table:
                            table_bitmap |= 0x01  # bit 0 = ProcessTable
                            cap_bitmap |= (1 << CapBit.SystemProcessTable)
                        if connection_table:
                            table_bitmap |= 0x02  # bit 1 = ConnectionTable
                            cap_bitmap |= (1 << CapBit.SystemNetworkTable)
                        if handle_table:
                            table_bitmap |= 0x04  # bit 2 = HandleTable
                            cap_bitmap |= (1 << CapBit.SystemHandleTable)
                        # System-context extension-block bits. All
                        # bits are opt-in (default off) to keep the
                        # process-centric acquire path lean.
                        # KernelSymbolBundle (bit 4) depends on
                        # ``sys_info`` which is collected below, so its
                        # bit is applied after the ``sys_info`` block.
                        # ConnectivityTable (bit 3), KernelModuleList
                        # (bit 7), PersistenceManifest (bit 6), and
                        # TargetIntrospection (bit 9) are set here when
                        # their operator flag is enabled and the source
                        # data is available. Bit 5 (PhysicalMemoryMap)
                        # and bit 8 (ModuleBuildIdManifest) are reserved
                        # and never set by the acquire path: the
                        # physical memory map is orthogonal to the
                        # process-centric acquisition model, and the
                        # build-ID manifest is produced only by the
                        # separate ``memslicer-enrich`` overlay tool.
                        if not _connectivity_table_is_empty(connectivity_table):
                            table_bitmap |= 0x08  # bit 3 = ConnectivityTable
                        # PersistenceManifest (bit 6) tracks the operator
                        # opt-in flag rather than row presence: the flag
                        # means "emit the block", and an empty manifest is
                        # a valid positive signal (the host had no files
                        # under the scanned persistence roots).
                        if persistence_manifest is not None:
                            table_bitmap |= 0x40  # bit 6
                        if kernel_module_list is not None and kernel_module_list.rows:
                            table_bitmap |= 0x80  # bit 7
                        if (
                            proc_info is not None
                            and self._attribution.include_target_introspection
                        ):
                            table_bitmap |= 0x200  # bit 9 = TargetIntrospection

                        # Update header cap_bitmap before writing tables
                        header.cap_bitmap = cap_bitmap

                        # Operator attribution (CLI-validated).
                        attribution = self._attribution
                        acq_user = attribution.examiner or getpass.getuser()
                        case_ref = attribution.case_ref

                        # Pull raw collector values (or produce empty ones
                        # if no collector is attached).
                        if self._collector is not None:
                            sys_info = self._collector.collect_system_info()
                            boot_time = sys_info.boot_time
                            collector_hostname = sys_info.hostname
                            collector_domain = sys_info.domain
                            raw_os_string = sys_info.os_detail
                        else:
                            sys_info = None
                            boot_time = 0
                            collector_hostname = ""
                            collector_domain = ""
                            raw_os_string = platform_mod.platform()

                        # Hostname/domain resolution — single source of
                        # truth shared with cli_sysctx. On remote targets
                        # the resolver refuses to fall back to
                        # socket.gethostname() (which would mis-attribute
                        # the MSL to the acquisition host).
                        identity = resolve_target_identity(
                            collector_hostname=collector_hostname,
                            collector_domain=collector_domain,
                            is_remote=attribution.is_remote,
                            hostname_override=attribution.hostname_override,
                            domain_override=attribution.domain_override,
                            logger=self._log,
                        )

                        if sys_info is not None:
                            fields = system_info_to_fields(
                                sys_info,
                                include_serials=attribution.include_serials,
                                include_network_identity=attribution.include_network_identity,
                                include_fingerprint=attribution.include_fingerprint,
                                include_kernel_symbols=attribution.include_kernel_symbols,
                            )
                            collector_warnings = list(sys_info.collector_warnings)
                        else:
                            fields = {"raw_os": raw_os_string}
                            collector_warnings = []

                        # Surface resolution warnings (e.g. remote
                        # hostname unavailable) in the packed provenance.
                        collector_warnings.extend(identity.warnings)
                        if collector_warnings:
                            fields["collector_warning"] = ",".join(collector_warnings)

                        os_detail_packed = pack_os_detail(fields)

                        # KernelSymbolBundle (Block 0x0055). Gated on
                        # the ``include_kernel_symbols`` attribution flag
                        # (opt-in). The bundle is built when the flag is
                        # set so the slice carries symbolication anchors
                        # even when the collector could only partially
                        # populate them; readers discover missing data
                        # via the TLV skip-zero contract.
                        kernel_symbol_bundle = None
                        if (
                            sys_info is not None
                            and attribution.include_kernel_symbols
                        ):
                            kernel_symbol_bundle = _build_kernel_symbol_bundle(sys_info)
                            table_bitmap |= 0x10  # bit 4 = KernelSymbolBundle

                        sys_ctx = SystemContext(
                            boot_time=boot_time,
                            target_count=1,
                            table_bitmap=table_bitmap,
                            acq_user=acq_user,
                            hostname=identity.hostname,
                            domain=identity.domain,
                            os_detail=os_detail_packed,
                            case_ref=case_ref,
                        )
                        sys_ctx_uuid = writer.write_system_context(sys_ctx)

                        # P1.6 extension blocks, emitted immediately after
                        # SystemContext so they share the investigation
                        # scope. Ordering within this group is flexible
                        # (readers do not depend on it); we emit
                        # system-wide blocks first, then the per-target
                        # TargetIntrospection, then the classic
                        # Process/Connection/Handle tables.
                        if kernel_symbol_bundle is not None:
                            writer.write_kernel_symbol_bundle(kernel_symbol_bundle)
                        if not _connectivity_table_is_empty(connectivity_table):
                            writer.write_connectivity_table(connectivity_table)
                        if kernel_module_list is not None and kernel_module_list.rows:
                            writer.write_kernel_module_list(kernel_module_list)
                        if persistence_manifest is not None:
                            writer.write_persistence_manifest(persistence_manifest)

                        # P1.6.3 — TargetIntrospection (Block 0x0058).
                        # Per-target metadata; kept separate from the
                        # system-wide P1.6 blocks above. This used to be
                        # emitted between ProcessIdentity and
                        # ModuleListIndex which violated the
                        # "ModuleListIndex MUST be Block 1" rule; it now
                        # lands in the investigation section.
                        if (
                            proc_info is not None
                            and self._attribution.include_target_introspection
                        ):
                            writer.write_target_introspection(
                                _build_target_introspection(proc_info, pid),
                            )

                        # Write classic table blocks referencing
                        # SystemContext as parent.
                        if process_table:
                            writer.write_process_table(process_table, parent_uuid=sys_ctx_uuid)
                        if connection_table:
                            writer.write_connection_table(connection_table, parent_uuid=sys_ctx_uuid)
                        if handle_table:
                            writer.write_handle_table(handle_table, parent_uuid=sys_ctx_uuid)

                    # Memory regions
                    self._log.info("Enumerating memory ranges...")
                    ranges = self._bridge.enumerate_ranges()
                    total_ranges = len(ranges)

                    ranges.sort(key=volatility_key)
                    self._log.info(
                        "Reordered %d ranges by volatility (rw- first)",
                        total_ranges,
                    )

                    if self._log.isEnabledFor(logging.DEBUG):
                        readable_count = sum(
                            1 for r in ranges
                            if parse_protection(r.protection) & PROT_R
                        )
                        self._log.debug(
                            "ranges: %d total, %d readable",
                            total_ranges, readable_count,
                        )

                    # Startup test read
                    self._perform_startup_test_read(ranges, page_size)

                    for idx, r in enumerate(ranges):
                        if self._abort.is_set():
                            break

                        prot = parse_protection(r.protection)

                        # Apply filter
                        reason = self._filter.skip_reason(
                            r.base, r.size, prot, r.file_path,
                        )
                        if reason is not None:
                            regions_skipped += 1
                            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                            self._emit_progress(
                                region_count, total_ranges,
                                bytes_captured, len(module_entries), idx + 1,
                            )
                            continue

                        bytes_attempted += r.size

                        region, data_size = self._read_region(
                            r.base, r.size, prot, r.file_path, page_size,
                        )
                        writer.write_memory_region(region)
                        region_count += 1
                        bytes_captured += data_size
                        captured = region.page_states.count(PageState.CAPTURED)
                        pages_captured += captured
                        pages_failed += len(region.page_states) - captured
                        if is_rwx(prot):
                            rwx_regions += 1

                        self._emit_progress(
                            region_count, total_ranges,
                            bytes_captured, len(module_entries), idx + 1,
                        )

                    self._emit_progress(
                        region_count, total_ranges,
                        bytes_captured, len(module_entries), total_ranges,
                    )

                finally:
                    writer.finalize()

        except Exception:
            if self._abort.is_set():
                self._log.debug("Session ended (abort or target exit)")
            else:
                raise
        finally:
            try:
                self._bridge.disconnect()
            except Exception:
                pass

        duration = time.monotonic() - start
        return AcquireResult(
            regions_captured=region_count,
            regions_total=total_ranges,
            bytes_captured=bytes_captured,
            modules_captured=len(module_entries),
            aborted=self._abort.is_set(),
            duration_secs=duration,
            output_path=str(output_path),
            regions_skipped=regions_skipped,
            rwx_regions=rwx_regions,
            bytes_attempted=bytes_attempted,
            pages_captured=pages_captured,
            pages_failed=pages_failed,
            skip_reasons=skip_reasons,
        )

    def _read_region(
        self,
        base_addr: int,
        size: int,
        protection: int,
        file_path: str,
        page_size: int,
    ) -> tuple[MemoryRegion, int]:
        """Read a memory region using multi-tier fallback strategy.

        Strategy:
        - If region fits in max_chunk_size, try a single read
        - If too large, split into max_chunk_size chunks
        - On failure for any chunk, fall back to page-by-page reads
        """
        # Round up to page boundary: spec requires RegionSize to be multiple of PageSize
        aligned_size = ((size + page_size - 1) // page_size) * page_size
        num_pages = aligned_size // page_size
        page_states: list[PageState] = []
        page_data_chunks: list[bytes] = []
        data_size = 0
        region_type = classify_region(file_path)

        self._log.debug(
            "Region 0x%x size=%d prot=%s type=%s",
            base_addr, size,
            format_protection(protection),
            region_type.name,
        )

        if is_rwx(protection):
            self._log.warning(
                "RWX region at 0x%x (%d bytes, %s) — potential JIT/injection",
                base_addr, size, region_type.name,
            )

        max_chunk = self._max_chunk_size

        if size <= max_chunk:
            data = self._bridge.read_memory(base_addr, size)
            if data is not None:
                page_states = [PageState.CAPTURED] * num_pages
                page_data_chunks = [data]
                data_size = len(data)
                self._log.debug(
                    "Region 0x%x -> read OK (%d bytes)", base_addr, data_size,
                )
            else:
                self._log.debug(
                    "Region 0x%x -> full read FAILED, trying page-by-page fallback",
                    base_addr,
                )
                page_states, page_data_chunks, data_size = self._try_read_pages(
                    base_addr, size, page_size,
                )
        else:
            self._log.debug(
                "Region 0x%x too big (%d), splitting into %d chunks",
                base_addr, size, (size + max_chunk - 1) // max_chunk,
            )
            page_states = [PageState.FAILED] * num_pages
            offset = 0

            while offset < size:
                if self._abort.is_set():
                    break
                chunk_size = min(max_chunk, size - offset)
                chunk_addr = base_addr + offset

                data = self._bridge.read_memory(chunk_addr, chunk_size)
                if data is not None:
                    page_data_chunks.append(data)
                    data_size += len(data)

                    first_page = offset // page_size
                    chunk_pages = (chunk_size + page_size - 1) // page_size
                    for pi in range(first_page, min(first_page + chunk_pages, num_pages)):
                        page_states[pi] = PageState.CAPTURED
                else:
                    self._log.debug(
                        "Chunk 0x%x+%d failed, trying page-by-page fallback",
                        base_addr, offset,
                    )
                    fb_states, fb_chunks, fb_size = self._try_read_pages(
                        chunk_addr, chunk_size, page_size,
                    )
                    if fb_size > 0:
                        page_data_chunks.extend(fb_chunks)
                        data_size += fb_size
                        first_page = offset // page_size
                        for pi_off, st in enumerate(fb_states):
                            pi = first_page + pi_off
                            if pi < num_pages:
                                page_states[pi] = st

                offset += chunk_size

        region = MemoryRegion(
            base_addr=base_addr,
            region_size=aligned_size,
            protection=protection,
            region_type=region_type,
            page_size=page_size,
            timestamp_ns=now_ns(),
            page_states=page_states,
            page_data_chunks=page_data_chunks,
        )
        return region, data_size

    def _perform_startup_test_read(
        self, ranges: list[MemoryRange], page_size: int,
    ) -> None:
        """Pick a small readable region and attempt a single read for early feedback."""
        for r in ranges:
            prot = parse_protection(r.protection)
            if not (prot & PROT_R):
                continue
            if r.size > page_size * 4:
                continue
            test_size = min(r.size, page_size)
            data = self._bridge.read_memory(r.base, test_size)
            if data is not None:
                self._log.info(
                    "Startup test read OK: 0x%x (%d bytes)", r.base, len(data),
                )
            else:
                self._log.warning(
                    "Startup test read FAILED at 0x%x size=%d — "
                    "reads may be blocked; check diagnostics",
                    r.base, test_size,
                )
            return
        self._log.warning("No small readable region found for startup test read")

    def _try_read_pages(
        self, base_addr: int, size: int, page_size: int,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Retry a failed region read page-by-page.

        Returns (page_states, page_data_chunks, data_size).
        """
        num_pages = (size + page_size - 1) // page_size
        page_states: list[PageState] = []
        page_data_chunks: list[bytes] = []
        data_size = 0
        pages_ok = 0

        for i in range(num_pages):
            if self._abort.is_set():
                page_states.extend([PageState.FAILED] * (num_pages - i))
                break
            page_addr = base_addr + i * page_size
            read_size = min(page_size, size - i * page_size)
            data = self._bridge.read_memory(page_addr, read_size)
            if data is not None:
                page_states.append(PageState.CAPTURED)
                page_data_chunks.append(data)
                data_size += len(data)
                pages_ok += 1
            else:
                page_states.append(PageState.FAILED)

        self._log.debug(
            "Page-by-page fallback 0x%x: %d/%d pages captured (%d bytes)",
            base_addr, pages_ok, num_pages, data_size,
        )
        return page_states, page_data_chunks, data_size

    # ------------------------------------------------------------------
    # Collector management
    # ------------------------------------------------------------------

    def _maybe_refine_collector(self, detected_os: OSType) -> None:
        """Re-select the investigation collector if the bridge-detected OS
        differs from what the current collector was built for.

        This handles remote targets where the host OS (used for initial
        collector creation) differs from the target OS.  Only replaces
        standard collectors (identified by `_is_memslicer_collector`
        marker) — user-provided or mock collectors are left untouched.
        """
        if not getattr(self._collector, '_is_memslicer_collector', False):
            return

        from memslicer.acquirer.collectors import create_collector

        current_name = type(self._collector).__name__
        new_collector = create_collector(
            detected_os, is_remote=self._bridge.is_remote, logger=self._log,
        )
        new_name = type(new_collector).__name__

        if new_name != current_name:
            self._log.info(
                "Refined collector: %s -> %s (detected OS: %s)",
                current_name, new_name, detected_os.name,
            )
            self._collector = new_collector

    # ------------------------------------------------------------------
    # System table collection (Investigation mode fallbacks)
    # ------------------------------------------------------------------

    @property
    def _fallback_collector(self):
        """Lazy-initialized LinuxCollector for engine fallback methods."""
        if not hasattr(self, '_fallback_collector_instance'):
            from memslicer.acquirer.collectors.linux import LinuxCollector
            self._fallback_collector_instance = LinuxCollector(logger=self._log)
        return self._fallback_collector_instance

    def _collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Collect system-wide process table. Linux only via /proc."""
        if not os.path.isdir("/proc"):
            self._log.warning(
                "Process table collection not supported: /proc not available"
            )
            return []

        try:
            entries = self._fallback_collector.collect_process_table(target_pid)
            self._log.info("Collected %d process table entries (engine fallback)", len(entries))
            return entries
        except Exception as exc:
            self._log.warning("Failed to collect process table: %s", exc)
            return []

    def _collect_connection_table(self) -> list[ConnectionEntry]:
        """Collect system-wide network connection table from /proc/net."""
        if not os.path.isdir("/proc/net"):
            self._log.warning(
                "Connection table collection not available: /proc/net not found"
            )
            return []

        try:
            entries = self._fallback_collector.collect_connection_table()
            self._log.info("Collected %d connection entries (engine fallback)", len(entries))
            return entries
        except Exception as exc:
            self._log.warning("Connection table collection failed: %s", exc)
            return []

    def _collect_handle_table(self, target_pid: int) -> list[HandleEntry]:
        """Collect file handle table for the target process from /proc."""
        fd_dir = f"/proc/{target_pid}/fd"
        if not os.path.isdir(fd_dir):
            self._log.warning(
                "Handle table collection not available: %s not found", fd_dir,
            )
            return []

        try:
            entries = self._fallback_collector.collect_handle_table(target_pid)
            self._log.info("Collected %d handle entries (engine fallback)", len(entries))
            return entries
        except Exception as exc:
            self._log.warning("Handle table collection failed: %s", exc)
            return []
