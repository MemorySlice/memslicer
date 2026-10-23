"""Backend-agnostic memory acquisition engine."""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, replace
from itertools import chain
from pathlib import Path
from typing import Any, Callable, Sequence

from memslicer.acquirer.base import (
    AcquireResult, BaseAcquirer, UnreadableRange,
)
from memslicer.acquirer.bridge import (
    DebuggerBridge, MemoryRange, ModuleInfo, PlatformInfo, ReadResult,
    ThreadInfo, register_role, stack_pointers_of,
)
from memslicer.acquirer.build_id_post import populate_from_bridge
from memslicer.acquirer.identity import AttributionConfig, resolve_target_identity
from memslicer.acquirer.investigation import InvestigationCollector, TargetSystemInfo
from memslicer.acquirer.os_detail import pack_os_detail, system_info_to_fields
from memslicer.acquirer.region_classify import (
    RegionCategory, RegionClassifier, RegionInfo, classify_name,
    region_type_for_category, strip_deleted,
)
from memslicer.acquirer.region_filter import (
    RegionFilter, is_kernel_pseudo_region, scope_label,
)
from memslicer.acquirer.residency import resident_runs
from memslicer.msl.constants import (
    CompAlgo, HashAlgo, OSType, PageState, RegionType, CapBit,
    Endianness, VERSION, HASH_SIZE, FLAG_INVESTIGATION, FLAG_ENCRYPTED,
    OmissionReason, VasNameSource, ArchType,
    REG_ROLE_PC, REG_ROLE_SP, TC_FLAG_CURRENT, TC_FLAG_PARTIAL,
    TC_FLAG_SUSPENDED,
)
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity, SystemContext,
    ProcessEntry, ConnectionEntry, HandleEntry, TargetIntrospection,
    KernelSymbolBundle, VasEntry, RegionOmissionManifest, RegionOmissionRow,
    ThreadContext, ThreadRegister,
)
from memslicer.msl.writer import MSLWriter
from memslicer.utils.protection import (
    PROT_R, PROT_W, PROT_X, format_protection, is_rwx, parse_protection,
)
from memslicer.utils.timestamps import now_ns


# Default max chunk size for splitting large regions (same as fridump)
_DEFAULT_MAX_CHUNK = 20971520  # 20 MB


@dataclass
class _SystemTables:
    """The investigation tables whose presence the file header advertises."""

    process_table: list[ProcessEntry]
    connection_table: list[ConnectionEntry]
    handle_table: list[HandleEntry]


def _page_count(nbytes: int, page_size: int) -> int:
    """Pages needed to hold *nbytes*."""
    return (nbytes + page_size - 1) // page_size


def _page_span(base: int, size: int, page_size: int) -> tuple[int, int]:
    """The smallest page-aligned span covering ``[base, base + size)``.

    The target maps memory in whole pages, so a range that starts or ends
    inside a page still lives in whole pages; this is the span a Memory
    Region block describes. Frida's ``Process.enumerateRanges`` reports such
    ranges when its Cloak clips its own thread stacks out of a mapping: the
    visible remainder begins at the unaligned end of the cloaked piece.

    Returns:
        ``(aligned_base, aligned_size)``; *aligned_size* is a multiple of
        *page_size* and zero only when *size* is zero on an aligned *base*.
    """
    start = base - base % page_size
    end = _page_count(base + size, page_size) * page_size
    return start, end - start


def _page_align_range(r: MemoryRange, page_size: int) -> MemoryRange:
    """*r* widened to page boundaries, or *r* itself when already aligned."""
    base, size = _page_span(r.base, r.size, page_size)
    if (base, size) == (r.base, r.size):
        return r
    return replace(r, base=base, size=size)


def _whole_pages(data: bytes, page_size: int) -> tuple[int, bytes]:
    """Split a read answer into the pages it covers completely.

    Spec Table 24 gives a Captured page exactly ``PageSize`` bytes, so a
    backend answer that stops mid-page cannot make that page Captured. The
    trailing partial page is dropped and left to the caller's default state
    (Failed), which overstates loss by less than one page rather than
    fabricating the missing bytes as zeros.

    Returns:
        ``(captured_pages, data[:captured_pages * page_size])``.
    """
    captured = len(data) // page_size
    return captured, data[: captured * page_size]


# Bound on the per-run unreadable-range report so a catastrophic capture
# cannot grow the result unboundedly.
_MAX_UNREADABLE_RANGES = 512

# Region kinds whose untouched pages are guaranteed to read as zero, so a
# residency mask can prune them losslessly. File-backed images and mapped
# files are left out: an untouched page there holds the file's content, and
# device or kernel mappings have no meaningful residency at all.
# Only private anonymous memory is safe to prune: a page of it that is neither
# present nor swapped has never been written and reads as zero.  Shared memory
# (memfd, ashmem, SysV, ``[anon_shmem:...]``) and the JIT caches built on it
# may hold pages written by another process or through another mapping that
# this process has not faulted in yet; its pagemap says "absent" although the
# content exists, so those kinds are always read in full.
_PRUNABLE_CATEGORIES = frozenset({
    RegionCategory.ANON, RegionCategory.ANON_NAMED,
    RegionCategory.HEAP_NATIVE, RegionCategory.HEAP_MANAGED,
    RegionCategory.STACK, RegionCategory.BSS,
})

# Mapping-name prefixes that denote shared memory even when the classifier
# files the region under a prunable category (``[anon_shmem:dalvik-...]``).
_SHARED_NAME_PREFIXES = ("[anon_shmem:", "/memfd:", "/dev/", "/SYSV")


def _is_private_anonymous(d: RegionDecision) -> bool:
    """Whether a kept range is private anonymous memory safe to prune."""
    if d.info.category not in _PRUNABLE_CATEGORIES:
        return False
    return not d.range.file_path.startswith(_SHARED_NAME_PREFIXES)

# Page states that are not data loss: captured pages, and pages the residency
# mask proved were never touched (their content is zero by construction).
_NOT_LOST_STATES = (PageState.CAPTURED, PageState.NOT_RESIDENT)


def _nonresident_bytes(region: MemoryRegion, size: int) -> int:
    """Bytes of *region* that were never requested because their pages are
    :attr:`PageState.NOT_RESIDENT`.

    Clipped to the range's real *size*: when the last page is both partial
    and non-resident, only the bytes the range actually covers count.
    """
    states = region.page_states
    pages = states.count(PageState.NOT_RESIDENT)
    nbytes = pages * region.page_size
    if pages and states[-1] == PageState.NOT_RESIDENT:
        nbytes -= region.region_size - size
    return nbytes


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


def _scatter(
    page_states: list[PageState], first_page: int, states: list[PageState],
) -> None:
    """Write *states* into *page_states* at *first_page*, clipped to fit."""
    start = max(0, first_page)
    end = min(len(page_states), first_page + len(states))
    if end > start:
        page_states[start:end] = states[start - first_page:end - first_page]


def coalesce_unreadable(
    region: MemoryRegion, file_path: str = "",
) -> list[UnreadableRange]:
    """Group a region's non-captured pages into contiguous ranges.

    A run is *expected* when its pages are :attr:`PageState.UNMAPPED` — the
    marker :meth:`AcquisitionEngine._read_region` already applied for kernel
    pseudo-mappings. Reading the recorded state rather than re-testing the
    region name keeps this in step with the page-state map that was written.

    :attr:`PageState.NOT_RESIDENT` pages are not lost -- resident-only
    pruning skipped them because they were never touched and read as zero --
    so they neither start a run nor extend one.

    Args:
        region: Region whose ``page_states`` to scan.
        file_path: Mapped name of the region, carried into each range.

    Returns:
        One :class:`UnreadableRange` per contiguous run of lost pages.
    """
    ranges: list[UnreadableRange] = []
    page_size = region.page_size
    states = region.page_states
    run_start: int | None = None

    # The trailing sentinel closes a run that reaches the end of the region.
    for index, state in enumerate(chain(states, (PageState.CAPTURED,))):
        if state not in _NOT_LOST_STATES:
            if run_start is None:
                run_start = index
            continue
        if run_start is not None:
            ranges.append(UnreadableRange(
                base=region.base_addr + run_start * page_size,
                size=(index - run_start) * page_size,
                region_base=region.base_addr,
                file_path=file_path,
                expected=states[run_start] == PageState.UNMAPPED,
            ))
            run_start = None
    return ranges


def _is_bare_token(name: str) -> bool:
    """True for names that are neither a path nor a bracketed pseudo name."""
    return not name.startswith("[") and "/" not in name and "\\" not in name


def classify_region(file_path: str) -> RegionType:
    """Classify a memory region based on its mapped file path.

    Delegates the name rules to :func:`region_classify.classify_name` so
    that ``[anon:...]`` labels, ``" (deleted)"`` suffixes, memfd/ashmem and
    device mappings are recognised. A bare token that is neither a path nor
    a bracketed pseudo name (e.g. ``"something"``) stays
    :attr:`RegionType.Unknown`.
    """
    name = strip_deleted(file_path)
    category = classify_name(name)
    if category is RegionCategory.ANON_NAMED and _is_bare_token(name):
        return RegionType.Unknown
    return region_type_for_category(category)


def build_vas_entries(
    ranges: list[MemoryRange], page_size: int,
    name_source: VasNameSource = VasNameSource.LIVE,
) -> list[VasEntry]:
    """Describe every enumerated range for the VAS Map block, sorted by base.

    Covers captured, filter-skipped and abort-unvisited ranges alike, with
    the full mapping name and the region type a MemoryRegion block for the
    range would carry. Bases and sizes are page-aligned exactly like the
    region blocks (see :func:`_page_span`), so the address-keyed join of spec
    Section 8 holds. *name_source* records where the mapping names came from
    (spec Section 5.8); the engine enumerates them from the running target,
    so ``LIVE`` is the default.
    """
    entries = []
    for r in ranges:
        base, size = _page_span(r.base, r.size, page_size)
        entries.append(VasEntry(
            base_addr=base,
            region_size=size,
            protection=parse_protection(r.protection),
            region_type=classify_region(r.file_path),
            mapped_path=r.file_path or "",
            name_source=name_source,
        ))
    entries.sort(key=lambda e: e.base_addr)
    return entries


_NO_THREAD_CONTEXTS_NOTE = (
    "no thread contexts available from this backend; the capture carries no "
    "Thread Context blocks (e.g. privileged Android system apps, where Frida"
    " enumerates no threads)"
)


def _thread_registers(t: ThreadInfo, arch: ArchType) -> list[ThreadRegister]:
    """Table 19b entries of *t*: lowercase names, roles filled in by *arch*
    when the bridge left them 0."""
    return [
        ThreadRegister(
            name=rv.name.lower(), width=rv.width,
            flags=rv.role or register_role(rv.name, arch), value=rv.value,
        )
        for rv in t.registers
    ]


def _has_roles(registers: list[ThreadRegister], *roles: int) -> bool:
    """Whether every role in *roles* is carried by some register entry."""
    return all(any(r.flags & role for r in registers) for role in roles)


def _thread_flags(t: ThreadInfo) -> int:
    """``Suspended``/``Partial`` exactly as the bridge reported them."""
    flags = 0
    if t.suspended:
        flags |= TC_FLAG_SUSPENDED
    if t.partial:
        flags |= TC_FLAG_PARTIAL
    return flags


def _current_thread_index(contexts: list[ThreadContext], pid: int) -> int:
    """Index of the resumption-point thread: the main thread (``tid == pid``
    on Linux, Android and Windows) when it is present, else the first."""
    for idx, tc in enumerate(contexts):
        if pid and tc.thread_id == pid:
            return idx
    return 0


def _build_thread_contexts(
    threads: list[ThreadInfo], arch: ArchType, *, pid: int = 0,
) -> list[ThreadContext]:
    """Turn bridge :class:`ThreadInfo` records into Thread Context blocks.

    One block per thread, in bridge order. A thread whose register file
    lacks a program counter or stack pointer is dropped: spec Section 5.7
    lets a producer emit a block only with both. ``Suspended`` and
    ``Partial`` come from the bridge; exactly one block carries ``Current``
    (:func:`_current_thread_index`). ``arch`` is written as 0 -- every
    thread executes in the header ``ArchType`` *arch*, which only serves to
    fill in register roles a bridge left unset.
    """
    contexts: list[ThreadContext] = []
    for t in threads:
        registers = _thread_registers(t, arch)
        if not _has_roles(registers, REG_ROLE_PC, REG_ROLE_SP):
            logging.getLogger("memslicer").debug(
                "thread %d dropped: no program counter or stack pointer", t.tid,
            )
            continue
        contexts.append(ThreadContext(
            thread_id=t.tid, flags=_thread_flags(t), state=t.state,
            arch=0, name=t.name, registers=registers,
        ))
    if contexts:
        contexts[_current_thread_index(contexts, pid)].flags |= TC_FLAG_CURRENT
    return contexts


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


@dataclass(frozen=True)
class RegionDecision:
    """What the engine decided about one enumerated range.

    Attributes:
        range: The range as the bridge reported it.
        protection: Parsed protection bits (bit0=R, bit1=W, bit2=X).
        info: Classification of the range by the :class:`RegionClassifier`.
        skip_reason: The :meth:`RegionFilter.skip_reason` code, or ``None``
            when the range is captured.
    """

    range: MemoryRange
    protection: int
    info: RegionInfo
    skip_reason: str | None

    @property
    def kept(self) -> bool:
        """True when the range is captured rather than skipped."""
        return self.skip_reason is None

    @property
    def owner_label(self) -> str:
        """The owning module's name, else the region label, for grouping."""
        if self.info.owner is not None:
            return self.info.owner.name
        return self.info.label or "<unnamed>"


@dataclass
class RegionSurvey:
    """Dry-run view of what an acquisition would capture and skip.

    Produced by :meth:`AcquisitionEngine.survey_regions`. Nothing is read
    from the target beyond its range and module lists and no file is
    written, so it is safe to run while choosing a ``--scope``.

    Attributes:
        os_type: OS the bridge reported (or the operator override).
        page_size: Target page size in bytes.
        modules: Loaded modules, as enumerated.
        decisions: One :class:`RegionDecision` per range, in capture order.
    """

    os_type: OSType
    page_size: int
    modules: list[ModuleInfo]
    decisions: list[RegionDecision]

    def kept(self) -> list[RegionDecision]:
        """Decisions whose range would be captured."""
        return [d for d in self.decisions if d.kept]

    def skipped(self) -> list[RegionDecision]:
        """Decisions whose range would be skipped."""
        return [d for d in self.decisions if not d.kept]

    def bytes_by_category(
        self,
    ) -> dict[RegionCategory, tuple[int, int, int, int]]:
        """Per-category ``(kept_count, kept_bytes, skipped_count, skipped_bytes)``.

        Sizes are the raw range sizes the bridge reported, not page-rounded.
        """
        totals: dict[RegionCategory, list[int]] = {}
        for d in self.decisions:
            row = totals.setdefault(d.info.category, [0, 0, 0, 0])
            slot = 0 if d.kept else 2
            row[slot] += 1
            row[slot + 1] += d.range.size
        return {cat: (r[0], r[1], r[2], r[3]) for cat, r in totals.items()}

    def bytes_by_owner(self, limit: int = 15) -> list[tuple[str, int, int]]:
        """Largest owners as ``(label, kept_bytes, skipped_bytes)``.

        The label is the owning module's name when the region is attributed
        to one, else the region label. Sorted by total bytes, largest first;
        ties break on the label so the order is stable.

        Args:
            limit: Maximum number of rows to return.
        """
        totals: dict[str, list[int]] = {}
        for d in self.decisions:
            row = totals.setdefault(d.owner_label, [0, 0])
            row[0 if d.kept else 1] += d.range.size
        ranked = sorted(
            totals.items(), key=lambda item: (-(item[1][0] + item[1][1]), item[0]),
        )
        return [(label, kept, skipped) for label, (kept, skipped) in ranked[:limit]]

    def skip_reason_counts(self) -> dict[str, int]:
        """Number of skipped ranges per :meth:`RegionFilter.skip_reason` code."""
        counts: dict[str, int] = {}
        for d in self.decisions:
            if d.skip_reason is not None:
                counts[d.skip_reason] = counts.get(d.skip_reason, 0) + 1
        return counts


@dataclass
class _TargetSession:
    """What the bridge told us about the target before any range is read.

    Shared by :meth:`AcquisitionEngine.acquire` and
    :meth:`AcquisitionEngine.survey_regions` so the connect / platform /
    module / identity sequence exists only once.
    """

    platform: PlatformInfo
    os_type: OSType
    page_size: int
    pid: int
    modules_raw: list[ModuleInfo]
    module_entries: list[ModuleEntry]
    proc_info: Any
    proc_id: ProcessIdentity


def _module_entry(m: ModuleInfo) -> ModuleEntry:
    """The lean ModuleEntry for *m*; build-ids are filled in separately."""
    return ModuleEntry(
        base_addr=m.base,
        module_size=m.size,
        path=m.path,
        version="",
        disk_hash=b'\x00' * HASH_SIZE,
        native_blob=b"",
    )


# Skip reasons recorded in the RegionOmissionManifest. Every other reason
# (no-read, max-size, ...) is a capture-policy default rather than a
# deliberate operator omission and is only counted in the result.
_OMISSION_REASONS: dict[str, OmissionReason] = {
    "module-exclude": OmissionReason.MODULE_EXCLUDE,
    "scope": OmissionReason.SCOPE,
}


def _omission_name(info: RegionInfo) -> str:
    """Name recorded for an omitted region.

    The region label, except for a ``.bss`` attributed to a module, where
    the owner's path says more than the bare ``".bss"``.
    """
    if info.category is RegionCategory.BSS and info.owner is not None:
        return info.owner.path
    return info.label


def _omission_row(decision: RegionDecision) -> RegionOmissionRow | None:
    """Manifest row for a skipped *decision*, or ``None`` when its reason
    is not one the manifest records."""
    reason = _OMISSION_REASONS.get(decision.skip_reason or "")
    if reason is None:
        return None
    return RegionOmissionRow(
        base_addr=decision.range.base,
        size=decision.range.size,
        protection=decision.protection,
        region_type=classify_region(decision.range.file_path),
        reason=reason,
        name=_omission_name(decision.info),
    )


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
        app_paths: Sequence[str] = (),
        resident_only: bool = False,
        resident_gap_pages: int = 4,
        capture_registers: bool = True,
    ) -> None:
        self._bridge = bridge
        # Optional ReadMemoryExCapable support, resolved once: this is probed
        # on every read and there are thousands of them per capture.
        self._read_ex_fn = getattr(bridge, "read_memory_ex", None)
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
        # Path prefixes the operator declared app-owned; the classifier
        # never counts files under them as system images.
        self._app_paths = tuple(app_paths)
        # Residency filtering is recorded here and applied by a later step.
        self._resident_only = resident_only
        self._resident_gap_pages = resident_gap_pages
        # Built per session once modules and process identity are known.
        self._classifier: RegionClassifier | None = None
        # Thread Context blocks (spec Section 5.7) are written whenever the
        # bridge can enumerate threads with registers; ``--no-registers``
        # turns the enumeration off altogether.
        self._capture_registers = capture_registers

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
        pages_expected_unreadable = 0
        bytes_expected_unreadable = 0
        expected_unreadable_regions: list[str] = []
        unreadable_ranges: list[UnreadableRange] = []
        unreadable_ranges_truncated = 0
        failed_ranges_kept = 0
        omission_rows: list[RegionOmissionRow] = []
        pages_nonresident = 0
        bytes_nonresident = 0
        residency_method = "none"
        thread_contexts_written = 0

        try:
            session = self._open_session()
            platform = session.platform
            os_type = session.os_type
            arch_type = platform.arch
            pid = session.pid
            page_size = session.page_size
            module_entries = session.module_entries
            proc_info, proc_id = session.proc_info, session.proc_id

            # Threads are enumerated once per capture: the register files
            # become the Thread Context blocks and the stack pointers feed
            # the classifier, so the bridge is not asked twice. This runs
            # before the header because its CapBitmap advertises the blocks.
            threads = self._enumerate_threads()
            thread_contexts = _build_thread_contexts(threads, arch_type, pid=pid)

            # The classifier needs the module list and the executable path,
            # so it is built now and reused for every range decision.
            self._build_classifier(
                os_type, session.modules_raw, proc_id,
                stack_pointers=stack_pointers_of(threads),
            )

            # Asked once per acquisition: the answer names the mechanism in
            # the result and tells the operator up front when pruning is
            # unavailable, rather than silently reading every page.
            residency_method = self._resolve_residency_method()

            # The system tables decide three CapBitmap bits, and the header
            # carrying that bitmap is written by ``MSLWriter.__init__`` --
            # fed to the integrity chain and used as AEAD AAD, so it can
            # never be rewritten afterwards. Collect them first or the bits
            # are lost.
            tables = self._collect_system_tables(pid) if self._investigation else None

            # Build CapBitmap dynamically based on what will be emitted
            cap_bitmap = (1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
            if module_entries:
                cap_bitmap |= (1 << CapBit.ModuleList)
            if thread_contexts:
                cap_bitmap |= (1 << CapBit.ThreadContexts)

            flags = 0
            if self._investigation:
                flags |= FLAG_INVESTIGATION
                cap_bitmap |= (1 << CapBit.SystemContext)
            if tables is not None:
                if tables.process_table:
                    cap_bitmap |= (1 << CapBit.SystemProcessTable)
                if tables.connection_table:
                    cap_bitmap |= (1 << CapBit.SystemNetworkTable)
                if tables.handle_table:
                    cap_bitmap |= (1 << CapBit.SystemHandleTable)

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
                    # Block 0: Process Identity (MUST be first). Already
                    # collected above, so nothing fallible stands between
                    # the header and this write.
                    proc_id_uuid = writer.write_process_identity(proc_id)

                    # Block 1: Module list index. Written unconditionally --
                    # an empty list still gets a block, so Block 1 is always
                    # the Module List and the positions spec Section 2.1
                    # fixes do not shift with module presence.
                    #
                    # Only the index goes here. Its ModuleEntry children are
                    # deferred until after the memory regions (see below),
                    # because Section 2.1 reserves Block 2 for System Context
                    # in investigation mode, and children written here would
                    # occupy Blocks 2..N+1. Figures 2 and 3 place the entries
                    # late for the same reason.
                    #
                    # Note: TargetIntrospection (P1.6.3, Block 0x0058) used
                    # to be emitted here between ProcessIdentity and the
                    # module list, which violated the "ModuleListIndex MUST
                    # be Block 1" rule. It now lands after SystemContext
                    # among the other P1.6 extension blocks.
                    module_index_uuid, module_uuids = writer.write_module_list_index(
                        module_entries,
                    )

                    # Block 2: SystemContext (Investigation mode only)
                    if self._investigation:
                        import getpass
                        import platform as platform_mod

                        # Collected before the header was written, because
                        # the CapBitmap it carries depends on them.
                        process_table = tables.process_table
                        connection_table = tables.connection_table
                        handle_table = tables.handle_table

                        # System-context extension block collection. These
                        # must be materialized BEFORE ``SystemContext`` is
                        # written so ``table_bitmap`` can include the bits
                        # for any extension block that will actually appear
                        # in the slice. Collector calls return empty values
                        # when the platform is not Linux.
                        if self._collector is not None:
                            connectivity_table = self._collect_or_default(
                                "connectivity table",
                                self._collector.collect_connectivity_table,
                                None,
                            )
                        else:
                            connectivity_table = None

                        # KernelModuleList is opt-in: memslicer is
                        # process-centric and kernel-wide enumeration is
                        # irrelevant to the default per-target workflow.
                        if (
                            self._attribution.include_kernel_modules
                            and self._collector is not None
                        ):
                            kernel_module_list = self._collect_or_default(
                                "kernel module list",
                                self._collector.collect_kernel_module_list,
                                None,
                            )
                        else:
                            kernel_module_list = None

                        # A collection *failure* yields ``None`` so bit 6
                        # stays clear; only an actually collected (even
                        # empty) manifest is the positive signal below.
                        if self._attribution.include_persistence_manifest and self._collector is not None:
                            persistence_manifest = self._collect_or_default(
                                "persistence manifest",
                                self._collector.collect_persistence_manifest,
                                None,
                            )
                        else:
                            persistence_manifest = None

                        # The matching CapBitmap bits were set before the
                        # header was written; this bitmap rides in the
                        # SystemContext payload, so it is still built here.
                        table_bitmap = 0
                        if process_table:
                            table_bitmap |= 0x01  # bit 0 = ProcessTable
                        if connection_table:
                            table_bitmap |= 0x02  # bit 1 = ConnectionTable
                        if handle_table:
                            table_bitmap |= 0x04  # bit 2 = HandleTable
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

                        # Operator attribution (CLI-validated).
                        attribution = self._attribution
                        acq_user = attribution.examiner or getpass.getuser()
                        case_ref = attribution.case_ref

                        # Pull raw collector values (or produce empty ones
                        # if no collector is attached).
                        if self._collector is not None:
                            # On failure the placeholder's warning reaches
                            # OSDetail, so the empty fields are explained.
                            sys_info = self._collect_or_default(
                                "system info",
                                self._collector.collect_system_info,
                                TargetSystemInfo(
                                    collector_warnings=["system_info_collection_failed"],
                                ),
                            )
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

                        # The bridge's page size shapes every region's
                        # page-state map, and the finished file cannot show
                        # that it was a default -- PageSizeLog2 and the map
                        # agree either way. Record it where the collector
                        # already records the same doubt about its own.
                        if platform.page_size_assumed:
                            collector_warnings.append("page_size_assumed_4k")

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

                    # Thread Context blocks (0x0011): evidence of the thread
                    # set, written after Block 1 and the investigation blocks
                    # and before the first Memory Region, so a consumer knows
                    # the threads before it classifies regions (spec Section
                    # 5.7). They reference Process Identity as parent.
                    for tc in thread_contexts:
                        writer.write_thread_context(tc, parent_uuid=proc_id_uuid)
                        thread_contexts_written += 1

                    # Memory regions
                    ranges = self._enumerate_ranges(page_size)
                    total_ranges = len(ranges)
                    decisions = self._plan_regions(ranges)

                    # Startup test read, on a range that will be captured.
                    self._perform_startup_test_read(
                        [d.range for d in decisions if d.kept], page_size,
                    )

                    for idx, d in enumerate(decisions):
                        if self._abort.is_set():
                            break

                        r = d.range
                        prot = d.protection

                        # Apply filter
                        reason = d.skip_reason
                        if reason is not None:
                            regions_skipped += 1
                            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                            row = _omission_row(d)
                            if row is not None:
                                omission_rows.append(row)
                            self._log_skip(d)
                            self._emit_progress(
                                region_count, total_ranges,
                                bytes_captured, len(module_entries), idx + 1,
                            )
                            continue

                        region, data_size = self._read_region(
                            r.base, r.size, prot, r.file_path, page_size,
                            residency=self._residency_mask(d, page_size),
                        )
                        writer.write_memory_region(region)
                        region_count += 1
                        bytes_captured += data_size
                        captured = region.page_states.count(PageState.CAPTURED)
                        unmapped = region.page_states.count(PageState.UNMAPPED)
                        nonresident = region.page_states.count(PageState.NOT_RESIDENT)
                        # "Attempted" means bytes actually requested from the
                        # target: pages the residency mask pruned were never
                        # asked for, so they are accounted separately.
                        skipped_bytes = _nonresident_bytes(region, r.size)
                        bytes_attempted += r.size - skipped_bytes
                        pages_nonresident += nonresident
                        bytes_nonresident += skipped_bytes
                        pages_captured += captured
                        pages_failed += (
                            len(region.page_states) - captured - unmapped - nonresident
                        )
                        if unmapped:
                            pages_expected_unreadable += unmapped
                            bytes_expected_unreadable += unmapped * page_size
                            expected_unreadable_regions.append(r.file_path)
                        if captured + nonresident != len(region.page_states):
                            for lost in self._log_unreadable_ranges(
                                region, r.file_path,
                            ):
                                # Expected runs are bounded by the handful of
                                # kernel pseudo-mappings a process has, so only
                                # genuine failures are capped and counted.
                                if lost.expected:
                                    unreadable_ranges.append(lost)
                                elif failed_ranges_kept < _MAX_UNREADABLE_RANGES:
                                    unreadable_ranges.append(lost)
                                    failed_ranges_kept += 1
                                else:
                                    unreadable_ranges_truncated += 1
                        if is_rwx(prot):
                            rwx_regions += 1

                        self._emit_progress(
                            region_count, total_ranges,
                            bytes_captured, len(module_entries), idx + 1,
                        )

                    # RegionOmissionManifest (0x005B): only when the operator
                    # narrowed the capture, so a default run keeps the block
                    # layout it always had.
                    if omission_rows:
                        writer.write_region_omission_manifest(
                            self._omission_manifest(omission_rows),
                        )

                    # The ModuleEntry children their index announced back at
                    # Block 1. They land here so Block 2 could be System
                    # Context, matching Figures 2 and 3.
                    writer.write_module_entries(
                        module_entries, module_index_uuid, module_uuids,
                    )

                    # VAS Map (0x1001): every enumerated range with its full
                    # mapping name, captured or not, so a reader can classify
                    # by name and tell skipped ranges from absent ones.
                    writer.write_vas_map(build_vas_entries(ranges, page_size))

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
            self._disconnect_quietly()

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
            pages_expected_unreadable=pages_expected_unreadable,
            bytes_expected_unreadable=bytes_expected_unreadable,
            expected_unreadable_regions=expected_unreadable_regions,
            unreadable_ranges=unreadable_ranges,
            unreadable_ranges_truncated=unreadable_ranges_truncated,
            regions_omitted=len(omission_rows),
            scope=scope_label(self._filter.scope),
            pages_nonresident=pages_nonresident,
            bytes_nonresident=bytes_nonresident,
            residency_method=residency_method,
            thread_contexts=thread_contexts_written,
        )

    def survey_regions(self) -> RegionSurvey:
        """Plan a capture without performing it.

        Connects and learns the target exactly as :meth:`acquire` does,
        classifies every range and applies the region filter, then
        disconnects. No region is read and no file is written.

        Returns:
            A :class:`RegionSurvey` with one decision per range, in the
            order a capture would visit them.
        """
        try:
            session = self._open_session(with_build_ids=False)
            self._build_classifier(session.os_type, session.modules_raw, session.proc_id)
            decisions = self._plan_regions(
                self._enumerate_ranges(session.page_size),
            )
            return RegionSurvey(
                session.os_type, session.page_size, session.modules_raw, decisions,
            )
        finally:
            self._disconnect_quietly()

    # ------------------------------------------------------------------
    # Target session and region planning
    # ------------------------------------------------------------------

    def _open_session(self, *, with_build_ids: bool = True) -> _TargetSession:
        """Connect and learn what precedes the output file: platform,
        modules and process identity.

        The steps run in the order ``acquire()`` always ran them, so a
        survey sees the target exactly as a capture would. The caller owns
        the bridge and disconnects it.

        Args:
            with_build_ids: Run the opt-in live build-id extraction on the
                module entries. Only a capture needs it; a survey writes no
                ModuleEntry blocks.
        """
        self._log.info("Connecting to target...")
        self._bridge.connect()

        self._log.info("Querying platform info...")
        platform = self._bridge.get_platform_info()
        os_type = self._os_override if self._os_override is not None else platform.os
        self._log.debug(
            "os=%s arch=%s pid=%d page_size=%d",
            os_type.name, platform.arch.name, platform.pid, platform.page_size,
        )

        # Select the investigation collector now that the bridge has told
        # us what the target really is. Remote targets arrive with no
        # collector at all (the CLI cannot know the device's platform
        # before attach), so this must also run for ``None``.
        if self._investigation:
            self._select_collector(os_type)

        # Enumerate modules BEFORE creating the header so the CapBitmap
        # can be set accurately.
        self._log.info("Enumerating modules...")
        modules_raw = self._bridge.enumerate_modules()
        self._log.debug("modules: %d", len(modules_raw))
        module_entries = [_module_entry(m) for m in modules_raw]
        if with_build_ids:
            self._populate_build_ids(module_entries)

        # Process Identity is Block 0, and the spec admits no other block
        # there. Collecting it before the output file is opened keeps a
        # collector failure from producing a file at all -- when this ran
        # inside the writer's ``try``, a raising collector left the
        # ``finally`` to emit EndOfCapture as Block 0.
        proc_info, proc_id = self._build_process_identity(platform.pid)
        return _TargetSession(
            platform=platform,
            os_type=os_type,
            page_size=platform.page_size,
            pid=platform.pid,
            modules_raw=modules_raw,
            module_entries=module_entries,
            proc_info=proc_info,
            proc_id=proc_id,
        )

    def _populate_build_ids(self, module_entries: list[ModuleEntry]) -> None:
        """Live build-id extraction (Path A), when the operator opted in.

        Reads the first 4 KiB of each module via the bridge and fills
        ``ModuleEntry.native_blob`` + ``disk_hash``. Off by default so a
        minimal process-centric slice does not pay for per-module bridge
        reads and hash work; ``memslicer-enrich`` (Path C) is the
        alternative. A failure is logged and the entries stay lean.
        """
        if not (module_entries and self._attribution.include_module_build_ids):
            return
        try:
            populate_from_bridge(
                module_entries, self._bridge, logger=self._log,
                hash_algo=self._hash_algo,
            )
        except Exception as exc:  # noqa: BLE001
            self._log.warning("build-id extraction failed: %s", exc)

    def _build_classifier(
        self, os_type: OSType, modules_raw: list[ModuleInfo],
        proc_id: ProcessIdentity,
        stack_pointers: tuple[int, ...] = (),
    ) -> RegionClassifier:
        """Build the per-session :class:`RegionClassifier` and keep it.

        Args:
            stack_pointers: Stack pointers already known from the thread
                enumeration. When empty, the bridge is asked for them via
                :meth:`_stack_pointers` -- but only when the scope needs
                them.
        """
        self._classifier = RegionClassifier(
            os_type, modules_raw,
            exe_path=proc_id.exe_path or "",
            app_paths=self._app_paths,
            stack_pointers=stack_pointers or self._stack_pointers(),
        )
        return self._classifier

    def _enumerate_threads(self) -> list[ThreadInfo]:
        """Every thread with its register file, ``[]`` when there are none.

        The capability (:class:`ThreadRegistersCapable`) is optional and
        skipped entirely by ``capture_registers=False``. A bridge that has
        it but reports no thread (privileged Android system apps) is noted once at
        INFO so the operator knows why the file has no Thread Context block.
        Any failure degrades to no blocks.
        """
        if not self._capture_registers:
            return []
        enumerate_threads = getattr(self._bridge, "enumerate_threads", None)
        if enumerate_threads is None:
            return []
        self._log.info("Enumerating threads...")
        try:
            threads = list(enumerate_threads())
        except Exception as exc:  # noqa: BLE001 - optional capability
            self._log.warning("thread enumeration failed: %s", exc)
            return []
        if not threads:
            self._log.info(_NO_THREAD_CONTEXTS_NOTE)
        else:
            self._log.debug("threads: %d", len(threads))
        return threads

    def _stack_pointers(self) -> tuple[int, ...]:
        """Thread stack pointers for stack detection, when they matter.

        Only the ``heap`` and ``stack`` scopes classify unnamed regions by
        stack pointer, so the bridge is asked only then: the capability
        (:class:`ThreadStackCapable`) is optional and can be slow. Any
        failure degrades to name-only classification.
        """
        if not ({"heap", "stack"} & self._filter.scope):
            return ()
        enumerate_sps = getattr(self._bridge, "enumerate_stack_pointers", None)
        if enumerate_sps is None:
            return ()
        try:
            return tuple(enumerate_sps())
        except Exception as exc:  # noqa: BLE001 - optional capability
            self._log.debug("stack pointer enumeration failed: %s", exc)
            return ()

    def _enumerate_ranges(self, page_size: int) -> list[MemoryRange]:
        """Enumerate the target's ranges in volatility-first capture order.

        Every range is widened to page boundaries here, once, so the region
        blocks, the VAS Map, the Region Omission Manifest and the residency
        query all describe the same span (see :func:`_page_span`).

        Args:
            page_size: Target page size the ranges are aligned to.
        """
        self._log.info("Enumerating memory ranges...")
        ranges = [
            self._page_aligned(r, page_size)
            for r in self._bridge.enumerate_ranges()
        ]
        ranges.sort(key=volatility_key)
        self._log.info(
            "Reordered %d ranges by volatility (rw- first)", len(ranges),
        )
        if self._log.isEnabledFor(logging.DEBUG):
            readable_count = sum(
                1 for r in ranges if parse_protection(r.protection) & PROT_R
            )
            self._log.debug(
                "ranges: %d total, %d readable", len(ranges), readable_count,
            )
        return ranges

    def _page_aligned(self, r: MemoryRange, page_size: int) -> MemoryRange:
        """*r* aligned to page boundaries, logging the adjustment when one
        was needed so the enumerator's answer stays on record."""
        aligned = _page_align_range(r, page_size)
        if aligned is not r:
            self._log.debug(
                "page-aligned range 0x%x size=%d -> 0x%x size=%d (%s)",
                r.base, r.size, aligned.base, aligned.size, r.file_path or "-",
            )
        return aligned

    def _plan_regions(self, ranges: list[MemoryRange]) -> list[RegionDecision]:
        """Classify every range and decide whether the filter keeps it.

        Requires :meth:`_build_classifier` to have run for this session.
        """
        if self._classifier is None:
            raise RuntimeError("_plan_regions() called before _build_classifier()")
        return [self._decide(r, self._classifier) for r in ranges]

    def _decide(
        self, r: MemoryRange, classifier: RegionClassifier,
    ) -> RegionDecision:
        """Build the :class:`RegionDecision` for one range."""
        info = classifier.classify(r)
        prot = parse_protection(r.protection)
        reason = self._filter.skip_reason(
            r.base, r.size, prot, r.file_path, info=info,
        )
        return RegionDecision(r, prot, info, reason)

    def _log_skip(self, d: RegionDecision) -> None:
        """One DEBUG line per skipped range, naming its class and owner."""
        owner = d.info.owner.name if d.info.owner is not None else "-"
        self._log.debug(
            "skip 0x%x size=%d cat=%s owner=%s reason=%s",
            d.range.base, d.range.size, d.info.category.name, owner,
            d.skip_reason,
        )

    def _omission_manifest(
        self, rows: list[RegionOmissionRow],
    ) -> RegionOmissionManifest:
        """The Block 0x005B payload for the regions the operator left out."""
        return RegionOmissionManifest(
            scope=scope_label(self._filter.scope),
            exclude_patterns=list(self._filter.exclude_modules),
            rows=rows,
        )

    def _disconnect_quietly(self) -> None:
        """Disconnect the bridge; a target that is already gone is not an error."""
        try:
            self._bridge.disconnect()
        except Exception:  # noqa: BLE001
            pass

    def _read_region(
        self,
        base_addr: int,
        size: int,
        protection: int,
        file_path: str,
        page_size: int,
        *,
        residency: bytes | None = None,
    ) -> tuple[MemoryRegion, int]:
        """Read a memory region using multi-tier fallback strategy.

        Strategy:
        - If region fits in max_chunk_size, try a single read
        - If too large, split into max_chunk_size chunks
        - On failure for any chunk, fall back to page-by-page reads

        Args:
            residency: Optional residency mask, one byte per page of the
                region. When given, only the resident runs are read and the
                remaining pages are recorded as :attr:`PageState.NOT_RESIDENT`
                (see :meth:`_read_resident_runs`). ``None`` reads the whole
                region exactly as before.

        Returns:
            ``(region, data_size)`` where *data_size* counts only the bytes
            actually read from the target.

        Note:
            The block always covers whole pages: *base_addr* is rounded down
            and the end rounded up to a page boundary before reading (spec
            Table 13 wants ``RegionSize`` a multiple of ``PageSize``, and
            Table 24 gives every Captured page exactly ``PageSize`` bytes).
            Ranges from :meth:`_enumerate_ranges` are aligned already; this
            keeps the invariant for any other caller.
        """
        aligned_base, aligned_size = _page_span(base_addr, size, page_size)
        if (aligned_base, aligned_size) != (base_addr, size):
            self._log.debug(
                "Region 0x%x size=%d read as page span 0x%x size=%d",
                base_addr, size, aligned_base, aligned_size,
            )
            base_addr, size = aligned_base, aligned_size
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

        if residency is None:
            page_states, page_data_chunks, data_size = self._read_span(
                base_addr, size, page_size,
            )
        else:
            page_states, page_data_chunks, data_size = self._read_resident_runs(
                base_addr, size, page_size, residency,
            )

        # Kernel pseudo-mappings ([vvar] and friends) are mapped but unreadable
        # by design.  Record the kernel's answer as UNMAPPED rather than FAILED
        # so the quality metric does not report them as data loss.
        if is_kernel_pseudo_region(file_path):
            page_states = [
                PageState.UNMAPPED if s == PageState.FAILED else s
                for s in page_states
            ]

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

    def _read_span(
        self, base_addr: int, size: int, page_size: int,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Read an arbitrary span with the single/chunked/split machinery.

        This is the whole-region read path factored out so that
        :meth:`_read_resident_runs` can apply it to each resident run of a
        region without duplicating the fallback logic.

        Args:
            base_addr: Start of the span.
            size: Length of the span in bytes.
            page_size: Target page size.

        Returns:
            ``(page_states, page_data_chunks, data_size)``; the state list has
            one entry per page of the span, and the chunks hold data for the
            captured pages only, in page order.
        """
        if size <= self._max_chunk_size:
            return self._read_single_span(base_addr, size, page_size)
        return self._read_chunked_span(base_addr, size, page_size)

    def _read_single_span(
        self, base_addr: int, size: int, page_size: int,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Read a span that fits one bridge call, splitting on failure."""
        num_pages = _page_count(size, page_size)
        res = self._read_ex(base_addr, size)
        if res.data is None:
            self._log.debug(
                "Region 0x%x -> full read FAILED, splitting at fault boundary",
                base_addr,
            )
            return self._read_span_split(
                base_addr, size, page_size, first_fault=res.fault_addr,
            )
        # Page count comes from what was actually returned: a backend
        # that answers with fewer bytes than asked for must not have
        # the shortfall recorded as captured, or the page data would
        # sit at the wrong offset relative to the page-state map.
        # Clamped because an over-long answer would otherwise build a
        # page-state list longer than the region, which the writer
        # rejects part-way through the file.
        captured, data = _whole_pages(res.data, page_size)
        captured = min(captured, num_pages)
        data = data[: captured * page_size]
        page_states = (
            [PageState.CAPTURED] * captured
            + [PageState.FAILED] * (num_pages - captured)
        )
        self._log.debug(
            "Region 0x%x -> read OK (%d bytes)", base_addr, len(data),
        )
        return page_states, [data], len(data)

    def _read_chunked_span(
        self, base_addr: int, size: int, page_size: int,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Read a span larger than ``max_chunk_size`` in fixed-size chunks."""
        max_chunk = self._max_chunk_size
        num_pages = _page_count(size, page_size)
        self._log.debug(
            "Region 0x%x too big (%d), splitting into %d chunks",
            base_addr, size, (size + max_chunk - 1) // max_chunk,
        )
        page_states = [PageState.FAILED] * num_pages
        page_data_chunks: list[bytes] = []
        data_size = 0
        offset = 0

        while offset < size:
            if self._abort.is_set():
                break
            chunk_size = min(max_chunk, size - offset)
            chunk_addr = base_addr + offset

            res = self._read_ex(chunk_addr, chunk_size)
            if res.data is not None:
                # As above: only the pages returned in full are captured;
                # the rest of the chunk stays FAILED.
                chunk_pages, data = _whole_pages(res.data, page_size)
                page_data_chunks.append(data)
                data_size += len(data)
                _scatter(page_states, offset // page_size,
                         [PageState.CAPTURED] * chunk_pages)
            else:
                self._log.debug(
                    "Chunk 0x%x+%d failed, splitting at fault boundary",
                    base_addr, offset,
                )
                fb_states, fb_chunks, fb_size = self._read_span_split(
                    chunk_addr, chunk_size, page_size,
                    first_fault=res.fault_addr,
                )
                if fb_size > 0:
                    page_data_chunks.extend(fb_chunks)
                    data_size += fb_size
                    _scatter(page_states, offset // page_size, fb_states)

            offset += chunk_size

        return page_states, page_data_chunks, data_size

    def _read_resident_runs(
        self, base_addr: int, size: int, page_size: int, mask: bytes,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Read only the resident runs of a region.

        Every page outside a run is recorded as
        :attr:`PageState.NOT_RESIDENT` without touching the target; gaps of
        at most ``resident_gap_pages`` between runs are bridged and read, as
        :func:`resident_runs` describes. A run is read with :meth:`_read_span`,
        so a fault inside it is still localised to its page.

        Args:
            base_addr: Start of the region.
            size: Length of the region in bytes.
            page_size: Target page size.
            mask: Residency mask with one byte per page of the region.

        Returns:
            The same triple as :meth:`_read_span`, covering the whole region.
        """
        num_pages = _page_count(size, page_size)
        runs = resident_runs(mask, self._resident_gap_pages)
        page_states = [PageState.NOT_RESIDENT] * num_pages
        page_data_chunks: list[bytes] = []
        data_size = 0

        for first_page, count in runs:
            if self._abort.is_set():
                # Resident but unread: never pretend the mask skipped it.
                _scatter(page_states, first_page, [PageState.FAILED] * count)
                continue
            run_offset = first_page * page_size
            run_size = min(count * page_size, size - run_offset)
            states, chunks, nbytes = self._read_span(
                base_addr + run_offset, run_size, page_size,
            )
            _scatter(page_states, first_page, states)
            page_data_chunks.extend(chunks)
            data_size += nbytes

        self._log.debug(
            "resident-only: 0x%x %d/%d pages read (%d runs)",
            base_addr, sum(count for _, count in runs), num_pages, len(runs),
        )
        return page_states, page_data_chunks, data_size

    def _residency_mask(
        self, d: RegionDecision, page_size: int,
    ) -> bytes | None:
        """Residency mask for a kept range, or ``None`` to read it whole.

        Pruning applies only to private anonymous memory (see
        :func:`_is_private_anonymous`), whose untouched pages read as zero.
        A bridge without the ``query_residency`` capability, an answer of
        ``None``, a mask of the wrong length, or an all-ones mask (nothing to
        prune, so the single-read path is cheaper) all yield ``None``.

        Args:
            d: The engine's decision about the range, carrying its class.
            page_size: Target page size, to validate the mask length.

        Returns:
            One byte per page of the range, or ``None``.
        """
        if not self._resident_only:
            return None
        query = getattr(self._bridge, "query_residency", None)
        if query is None or not _is_private_anonymous(d):
            return None
        base, size = d.range.base, d.range.size
        try:
            mask = query(base, size)
        except Exception as exc:  # noqa: BLE001 - a bridge fault must not end the capture
            self._log.debug("residency query failed at 0x%x: %s", base, exc)
            return None
        if mask is None:
            return None
        if len(mask) != _page_count(size, page_size):
            self._log.debug(
                "residency mask for 0x%x has %d entries, expected %d; ignored",
                base, len(mask), _page_count(size, page_size),
            )
            return None
        if all(mask):
            return None
        return mask

    def _resolve_residency_method(self) -> str:
        """Ask the bridge once how it determines residency, and log it.

        Returns:
            The bridge's :meth:`~ResidencyCapable.residency_method` answer, or
            ``"none"`` when pruning is off, the bridge lacks the capability,
            or the probe fails.
        """
        if not self._resident_only:
            return "none"
        probe = getattr(self._bridge, "residency_method", None)
        method = "none"
        if probe is not None:
            try:
                method = str(probe())
            except Exception as exc:  # noqa: BLE001 - degrade to full reads
                self._log.debug("residency_method probe failed: %s", exc)
        self._log.info("resident-only pruning: method=%s", method)
        if method == "none":
            self._log.warning(
                "resident-only pruning is unavailable for this backend/target; "
                "every page will be read",
            )
        return method

    def _log_unreadable_ranges(
        self, region: MemoryRegion, file_path: str,
    ) -> list[UnreadableRange]:
        """Coalesce and log the page runs that could not be captured.

        Derived from page state rather than from backend error messages, so a
        page that failed without producing one is still accounted for.

        Args:
            region: The region whose page states to scan.
            file_path: Mapped name of the region, for the log line.

        Returns:
            One :class:`UnreadableRange` per contiguous run.
        """
        ranges = coalesce_unreadable(region, file_path)
        for r in ranges:
            self._log.log(
                logging.INFO if r.expected else logging.WARNING,
                "unreadable: 0x%x-0x%x (%d pages) in region 0x%x name=%s expected=%s",
                r.base, r.base + r.size, r.size // region.page_size,
                r.region_base, file_path or "?", "yes" if r.expected else "no",
            )
        return ranges

    def _read_ex(self, address: int, size: int) -> ReadResult:
        """Read memory, using fault detail when the bridge can report it.

        Args:
            address: Address to read from.
            size: Number of bytes to read.

        Returns:
            A :class:`ReadResult`; ``fault_addr`` is ``None`` for bridges that
            do not implement the optional ``read_memory_ex`` capability.
        """
        if self._read_ex_fn is None:
            return ReadResult(data=self._bridge.read_memory(address, size))
        res = self._read_ex_fn(address, size)
        if isinstance(res, ReadResult):
            return res
        # A bridge that advertises the capability but returns something else
        # is a programming error; fall back rather than corrupt page states.
        return ReadResult(data=self._bridge.read_memory(address, size))

    def _read_span_split(
        self,
        base_addr: int,
        size: int,
        page_size: int,
        first_fault: int | None = None,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Read a span, splitting at reported fault boundaries.

        On a fault the readable prefix is re-read in a single call, the
        faulting page is marked failed, and reading resumes after it. That
        costs about two reads per bad page instead of one read per page.
        Falls back to :meth:`_try_read_pages` whenever the backend cannot say
        where the fault was.

        Args:
            base_addr: Start of the span.
            size: Length of the span in bytes.
            page_size: Target page size.
            first_fault: Fault address from the caller's already-failed read,
                so that read is not repeated.

        Returns:
            ``(page_states, page_data_chunks, data_size)`` — the same triple as
            :meth:`_try_read_pages`.
        """
        num_pages = _page_count(size, page_size)
        page_states = [PageState.FAILED] * num_pages
        page_data_chunks: list[bytes] = []
        pos = base_addr
        end = base_addr + size
        # The caller's read of this span already failed, so the first pass
        # consumes its outcome instead of repeating it.
        pending: ReadResult | None = ReadResult(data=None, fault_addr=first_fault)

        def absorb(start: int, states: list[PageState], chunks: list[bytes]) -> None:
            page_data_chunks.extend(chunks)
            _scatter(page_states, (start - base_addr) // page_size, states)

        def absorb_read(start: int, data: bytes) -> None:
            # Page count comes from what was actually returned, so a short
            # read is never recorded as a fully captured span.
            captured, data = _whole_pages(data, page_size)
            absorb(start, [PageState.CAPTURED] * captured, [data])

        while pos < end:
            if self._abort.is_set():
                break

            res, pending = pending or self._read_ex(pos, end - pos), None
            if res.data is not None:
                absorb_read(pos, res.data)
                break
            fault = res.fault_addr

            if fault is None or not (pos <= fault < end):
                # Backend could not localise the fault: degrade to page reads.
                absorb(pos, *self._try_read_pages(pos, end - pos, page_size)[:2])
                break

            fault_page = fault - (fault % page_size)
            if fault_page > pos:
                good = fault_page - pos
                res = self._read_ex(pos, good)
                if res.data is not None:
                    absorb_read(pos, res.data)
                else:
                    absorb(pos, *self._try_read_pages(pos, good, page_size)[:2])

            # The faulting page stays FAILED; always advance past it.
            pos = max(fault_page + page_size, pos + page_size)

        data_size = sum(map(len, page_data_chunks))

        if self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(
                "Split read 0x%x: %d/%d pages captured (%d bytes)",
                base_addr, page_states.count(PageState.CAPTURED),
                num_pages, data_size,
            )
        return page_states, page_data_chunks, data_size

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
        num_pages = _page_count(size, page_size)
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
            # A whole page or nothing: a short answer cannot be Captured.
            if data is not None and _whole_pages(data, page_size)[0]:
                page_states.append(PageState.CAPTURED)
                page_data_chunks.append(data[:page_size])
                data_size += page_size
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

    def _bridge_is_remote(self) -> bool:
        """Whether the bridge talks to a process on another machine.

        Probed with ``getattr`` because the bridge protocol does not
        require the attribute; a bridge that does not say is local.
        """
        return bool(getattr(self._bridge, "is_remote", False))

    def _select_collector(self, detected_os: OSType) -> None:
        """Choose the investigation collector for the attached target.

        A user-supplied collector (anything without the
        ``_is_memslicer_collector`` marker) is always kept. For a remote
        bridge the collector must come from the bridge itself, never from
        the host: a host-local collector would read the acquisition host's
        ``/proc`` for the device's pid (GitHub issue #3). Local targets keep
        the existing OS-based refinement.
        """
        if self._collector is not None and not getattr(
            self._collector, "_is_memslicer_collector", False,
        ):
            return
        if self._bridge_is_remote():
            self._collector = self._remote_collector_or_null()
            return
        if self._collector is not None:
            self._maybe_refine_collector(detected_os)

    def _remote_collector_or_null(self) -> InvestigationCollector:
        """Obtain a collector that runs on the remote target, or a null one.

        Mirrors the optional-capability probe used for ``read_memory_ex``:
        a bridge that can collect on the target exposes
        ``create_remote_collector``; otherwise the system tables stay empty
        and the log says so. Host data is never substituted -- it would be
        attributed to the wrong machine.
        """
        factory = getattr(self._bridge, "create_remote_collector", None)
        collector = factory(self._log) if factory is not None else None
        if collector is not None:
            self._log.info(
                "Using %s: investigation data is collected on the target",
                type(collector).__name__,
            )
            return collector
        from memslicer.acquirer.collectors.fallback import NullCollector
        self._log.warning(
            "Investigation data cannot be collected from a remote target "
            "over %s; system tables will be empty",
            type(self._bridge).__name__,
        )
        return NullCollector(logger=self._log)

    def _maybe_refine_collector(self, detected_os: OSType) -> None:
        """Re-select the investigation collector if the bridge-detected OS
        differs from what the current collector was built for.

        Local bridges only: ``_select_collector`` diverts remote bridges to
        the target-side collector before this runs, because every collector
        the factory can return reads the acquisition host. Only replaces
        standard collectors (identified by `_is_memslicer_collector`
        marker) — user-provided or mock collectors are left untouched.
        """
        if not getattr(self._collector, '_is_memslicer_collector', False):
            return

        from memslicer.acquirer.collectors import create_collector

        current_name = type(self._collector).__name__
        new_collector = create_collector(
            detected_os, is_remote=self._bridge_is_remote(), logger=self._log,
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

    def _build_process_identity(self, pid: int) -> tuple[Any, ProcessIdentity]:
        """Collect the Block 0 payload for *pid*.

        Called before the output file is opened. The spec gives Block 0 to
        Process Identity and to nothing else, so this must not run anywhere
        a failure could still leave a partially written file behind.

        Args:
            pid: Target process id.

        Returns:
            ``(proc_info, proc_id)``. ``proc_info`` is the collector's full
            record -- needed later for TargetIntrospection -- and is ``None``
            when no collector is attached, in which case the identity is
            zero-filled as the format allows.
        """
        if self._collector is None:
            return None, ProcessIdentity(
                ppid=0, session_id=0, start_time_ns=0,
                exe_path="", cmd_line="",
            )
        proc_info = self._collector.collect_process_identity(
            pid,
            include_target_introspection=(
                self._attribution.include_target_introspection
            ),
            include_environ=self._attribution.include_environ,
        )
        return proc_info, ProcessIdentity(
            ppid=proc_info.ppid,
            session_id=proc_info.session_id,
            start_time_ns=proc_info.start_time_ns,
            exe_path=proc_info.exe_path,
            cmd_line=proc_info.cmd_line,
        )

    def _collect_system_tables(self, target_pid: int) -> _SystemTables:
        """Collect the investigation tables the file header advertises.

        Their emptiness decides CapBitmap bits 12-14, and the header is
        serialized once in ``MSLWriter.__init__`` with no rewrite path, so
        this has to happen before the writer is constructed.

        Args:
            target_pid: Target process id.

        Returns:
            The three tables, each empty when unavailable.
        """
        collector = self._collector
        if collector is not None:
            sources = (
                ("process table", lambda: collector.collect_process_table(target_pid)),
                ("connection table", collector.collect_connection_table),
                ("handle table", lambda: collector.collect_handle_table(target_pid)),
            )
        elif self._bridge_is_remote():
            # Defensive: ``_select_collector`` never leaves a remote bridge
            # without a collector, but the host fallbacks below read the
            # host's /proc and must never describe a remote target.
            self._log.warning(
                "No investigation collector for remote target; "
                "system tables will be empty"
            )
            return _SystemTables([], [], [])
        else:
            sources = (
                ("process table", lambda: self._collect_process_table(target_pid)),
                ("connection table", self._collect_connection_table),
                ("handle table", lambda: self._collect_handle_table(target_pid)),
            )
        return _SystemTables(*(self._table_or_empty(n, f) for n, f in sources))

    def _table_or_empty(self, name: str, collect: Callable[[], list]) -> list:
        """Run *collect*, degrading a failure to an empty table.

        These run before the output file exists, so an unguarded collector
        raising here would cost the whole capture -- including memory that
        had nothing to do with the failure. A missing table is recorded
        honestly instead: its CapBitmap bit stays clear, so the slice never
        claims to hold something it does not.

        Args:
            name: Table name for the log line.
            collect: Zero-argument collector call.

        Returns:
            The collected rows, or ``[]`` when collection failed.
        """
        return self._collect_or_default(name, collect, [])

    def _collect_or_default(
        self, name: str, collect: Callable[[], Any], default: Any,
    ) -> Any:
        """Run *collect*, degrading a failure to *default*.

        The extension-block collectors run while the writer is open, so an
        unguarded exception would leave a truncated ``.msl`` behind. The
        caller picks a *default* that keeps the slice honest: ``None`` for
        a block whose bit must stay clear, an empty list for a table.

        Args:
            name: Name for the log line.
            collect: Zero-argument collector call.
            default: Value returned when collection failed.

        Returns:
            The collected value, or *default* when collection failed.
        """
        try:
            return collect()
        except Exception as exc:  # noqa: BLE001 - collectors span many OS APIs
            self._log.warning("Failed to collect %s: %s", name, exc)
            return default

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
