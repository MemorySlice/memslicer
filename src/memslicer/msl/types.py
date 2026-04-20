from __future__ import annotations
import uuid
from dataclasses import dataclass, field

from memslicer.msl.constants import (
    OSType, ArchType, CompAlgo, PageState, RegionType, BlockType,
    Endianness, VERSION, HASH_SIZE, ClockSource, HashAlgo,
)


@dataclass
class FileHeader:
    """MSL file header (64 bytes on disk)."""
    endianness: Endianness = Endianness.LITTLE
    version: tuple[int, int] = VERSION
    flags: int = 0
    cap_bitmap: int = 0
    dump_uuid: bytes = field(default_factory=lambda: uuid.uuid4().bytes)
    timestamp_ns: int = 0
    os_type: OSType = OSType.Linux
    arch_type: ArchType = ArchType.x86_64
    pid: int = 0
    clock_source: ClockSource = ClockSource.Unknown
    block_count: int = 0  # 0 = streaming/unknown
    hash_algo: HashAlgo = HashAlgo.BLAKE3  # integrity hash algorithm (spec Section 4.4)


@dataclass
class MemoryRegion:
    """A captured memory region with per-page state."""
    base_addr: int = 0
    region_size: int = 0
    protection: int = 0  # bit0=R, bit1=W, bit2=X
    region_type: RegionType = RegionType.Unknown
    page_size: int = 4096
    timestamp_ns: int = 0
    page_states: list[PageState] = field(default_factory=list)
    page_data_chunks: list[bytes] = field(default_factory=list)
    # page_data_chunks contains data ONLY for CAPTURED pages


@dataclass
class ModuleEntry:
    """A loaded module/library."""
    base_addr: int = 0
    module_size: int = 0
    path: str = ""
    version: str = ""
    disk_hash: bytes = field(default_factory=lambda: b'\x00' * HASH_SIZE)
    native_blob: bytes = b""


@dataclass
class EndOfCapture:
    """End of capture marker."""
    file_hash: bytes = field(default_factory=lambda: b'\x00' * HASH_SIZE)
    acq_end_ns: int = 0


@dataclass
class ProcessIdentity:
    """Process identity metadata (Block 0 for live acquisition)."""
    ppid: int = 0
    session_id: int = 0
    start_time_ns: int = 0
    exe_path: str = ""
    cmd_line: str = ""


@dataclass
class SystemContext:
    """System-wide investigation context (Block 2 when Investigation flag set)."""
    boot_time: int = 0
    target_count: int = 1   # serialized as u8 (TCt, 1 byte)
    table_bitmap: int = 0   # serialized as u32 (TBm, 4 bytes)
    # ``table_bitmap`` bit assignments (spec Table 21):
    #   bit 0  = ProcessTable           (0x0051)
    #   bit 1  = ConnectionTable        (0x0052)
    #   bit 2  = HandleTable            (0x0053)
    #   bit 3  = ConnectivityTable      (0x0054, P1.6.5)
    #   bit 4  = KernelSymbolBundle     (0x0055, P1.6.1)
    #   bit 5  = reserved               (mask 0x0020 — unused in current spec)
    #   bit 6  = PersistenceManifest    (0x0056, P1.6.4)
    #   bit 7  = KernelModuleList       (0x0057, P1.6.2)
    #   bit 8  = reserved               (mask 0x0100 — unused in current spec)
    #   bit 9  = TargetIntrospection    (0x0058, P1.6.3)
    #   bits 10..31 reserved for future system-context extension blocks.
    # Non-spec extension blocks (PhysicalMemoryMap 0x0059, ModuleBuildIdManifest
    # 0x005A) live outside the spec range and are not advertised in this bitmap.
    acq_user: str = ""
    hostname: str = ""
    domain: str = ""
    os_detail: str = ""
    case_ref: str = ""


@dataclass
class ProcessEntry:
    """A single process in the system-wide process table."""
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    is_target: bool = False
    start_time: int = 0
    rss: int = 0
    exe_name: str = ""
    cmd_line: str = ""
    user: str = ""


@dataclass
class ConnectionEntry:
    """A single network connection in the system-wide connection table."""
    pid: int = 0
    family: int = 0x02     # 0x02=IPv4, 0x0A=IPv6
    protocol: int = 0x06   # 0x06=TCP, 0x11=UDP
    state: int = 0         # 0x01=ESTABLISHED, 0x0A=LISTEN, 0x00=N/A
    local_addr: bytes = field(default_factory=lambda: b'\x00' * 16)
    local_port: int = 0
    remote_addr: bytes = field(default_factory=lambda: b'\x00' * 16)
    remote_port: int = 0


@dataclass
class HandleEntry:
    """A single file handle in the system-wide handle table."""
    pid: int = 0
    fd: int = 0
    handle_type: int = 0  # 0x00=Unknown, 0x01=File, 0x02=Dir, 0x03=Socket, 0x04=Pipe, 0x05=Device, 0x06=Registry, 0xFF=Other
    path: str = ""


@dataclass
class KeyHint:
    """Key identification hint (Section 5.6, Table 18)."""
    region_uuid: bytes = field(default_factory=lambda: b'\x00' * 16)
    region_offset: int = 0
    key_len: int = 0          # 0 if unknown
    key_type: int = 0         # key type code
    protocol: int = 0         # protocol code
    confidence: int = 0       # 0x00=Speculative, 0x01=Heuristic, 0x02=Confirmed
    key_state: int = 0        # 0x00=Unknown, 0x01=Active, 0x02=Expired
    note: str = ""


@dataclass
class ImportProvenance:
    """Import provenance metadata (Section 11, Table 28)."""
    source_format: int = 0    # 0x0000=Unknown, 0x0001=Raw, 0x0002=ELF, 0x0003=Minidump, 0x0004=macOS core, 0x0005=ProcDump, 0xFFFF=Other
    tool_name: str = ""
    import_time: int = 0      # ns since epoch
    orig_file_size: int = 0   # 0 if unknown
    note: str = ""


@dataclass
class RelatedDump:
    """Related dump reference (Section 5.5, Table 17). Fixed 24B payload."""
    related_dump_uuid: bytes = field(default_factory=lambda: b'\x00' * 16)
    related_pid: int = 0      # 0 if unknown
    relationship: int = 0     # 0x0001=Parent, 0x0002=Child, 0x0003=SharedMemory, 0x0004=IPC peer, 0x0005=Thread group, 0xFFFF=Other


@dataclass
class KernelSymbolBundle:
    """Kernel symbolication anchors (Block 0x0055, P1.6.1).

    Tagged-row TLV payload. Each tag is emitted only when the
    corresponding value is non-empty / non-zero.
    """
    page_size: int = 0
    kernel_build_id: bytes = b""
    kaslr_text_va: int = 0
    kernel_page_offset: int = 0
    la57_enabled: int = 0
    pti_active: int = 0
    btf_sha256: bytes = b""
    btf_size_bytes: int = 0
    vmcoreinfo_sha256: bytes = b""
    kernel_config_sha256: bytes = b""
    clock_realtime_ns: int = 0
    clock_monotonic_ns: int = 0
    clock_boottime_ns: int = 0
    clocksource: str = ""
    thp_mode: str = ""
    ksm_active: int = 0
    directmap_4k_kib: int = 0
    directmap_2m_kib: int = 0
    directmap_1g_kib: int = 0
    zram_devices_json: str = ""
    zswap_enabled: int = 0


@dataclass
class PhysicalMemoryMap:
    """Parsed /proc/iomem top-level ranges (Block 0x0059, P1.6.1 — non-spec extension)."""
    ranges: list[tuple[int, int, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ConnectivityTable (Block 0x0054, P1.6.5)
# ---------------------------------------------------------------------------


@dataclass
class IPv4RouteRow:
    """An IPv4 routing-table entry (row_type 0x01)."""
    iface: str = ""
    dest: bytes = b"\x00\x00\x00\x00"
    gateway: bytes = b"\x00\x00\x00\x00"
    mask: bytes = b"\x00\x00\x00\x00"
    flags: int = 0
    metric: int = 0
    mtu: int = 0


@dataclass
class IPv6RouteRow:
    """An IPv6 routing-table entry (row_type 0x02)."""
    iface: str = ""
    dest: bytes = field(default_factory=lambda: b"\x00" * 16)
    dest_prefix: int = 0
    next_hop: bytes = field(default_factory=lambda: b"\x00" * 16)
    metric: int = 0
    flags: int = 0


@dataclass
class ArpEntryRow:
    """An ARP neighbour cache entry (row_type 0x03). family=0x02 for IPv4."""
    family: int = 0x02
    ip: bytes = b"\x00\x00\x00\x00"
    hw_type: int = 0
    flags: int = 0
    hw_addr: bytes = field(default_factory=lambda: b"\x00" * 6)
    iface: str = ""


@dataclass
class PacketSocketRow:
    """A raw PF_PACKET socket row (row_type 0x04).

    pid is 0 when attribution via the inode->pid map fails.
    """
    pid: int = 0
    inode: int = 0
    proto: int = 0
    iface_index: int = 0
    user: int = 0
    rmem: int = 0


@dataclass
class NetdevStatsRow:
    """Per-interface byte/packet/error/drop counters (row_type 0x05)."""
    iface: str = ""
    rx_bytes: int = 0
    rx_packets: int = 0
    rx_errs: int = 0
    rx_drop: int = 0
    tx_bytes: int = 0
    tx_packets: int = 0
    tx_errs: int = 0
    tx_drop: int = 0


@dataclass
class SockstatFamilyRow:
    """Aggregate /proc/net/sockstat[6] row (row_type 0x06).

    ``family`` is a section tag, not a strict AF_* value. The mapping is:

    * 0x02 = TCP (IPv4)
    * 0x11 = UDP (IPv4)
    * 0x03 = RAW (IPv4)
    * 0x04 = FRAG (IPv4)
    * 0x0A = TCP6 (IPv6)
    * 0x0B = UDP6 (IPv6)
    * 0xFF = "sockets: used" aggregate
    """
    family: int = 0
    in_use: int = 0
    alloc: int = 0
    mem: int = 0


@dataclass
class SnmpCounterRow:
    """A single MIB counter from /proc/net/snmp or /proc/net/netstat
    (row_type 0x07).
    """
    mib: str = ""
    counter: str = ""
    value: int = 0


@dataclass
class KernelModuleRow:
    name: str = ""
    size: int = 0
    refcount: int = 0
    state: int = 0          # 0=Unknown, 1=Live, 2=Loading, 3=Unloading
    taint: int = 0           # bitmask from /sys/module/<name>/taint
    base: int = 0            # 0 if kptr_restricted
    flags: int = 0           # bit0=proc-only, bit1=sysfs-only


@dataclass
class KernelModuleList:
    """Loaded kernel modules from /proc/modules + /sys/module (Block 0x0057, P1.6.2).

    Includes skew detection between /proc/modules and /sys/module listings
    — rows with flags bit0 or bit1 set indicate LKM rootkit hiding attempts.
    """
    rows: list[KernelModuleRow] = field(default_factory=list)


@dataclass
class ModuleBuildIdRow:
    base_addr: int = 0
    build_id_len: int = 0        # 0, 16, or 20
    build_id_source: int = 0     # 0=none, 1=bridge, 2=map_files, 3=on_disk, 4=captured_region, 5=retroactive
    flags: int = 0               # bit0=deleted, bit1=memfd, bit2=anon_rwx, bit3=unlinked
    build_id: bytes = b""
    disk_hash: bytes = field(default_factory=lambda: b"\x00" * 32)


@dataclass
class ModuleBuildIdManifest:
    """Retroactive build-id enrichment overlay (Block 0x005A, P1.6.2 — non-spec extension).

    Append-only supplement to the original ModuleEntry blocks. Written
    by memslicer-enrich; readers merge rows into the module list by
    matching base_addr. An interrupted enrichment run leaves the
    original bytes untouched.
    """
    rows: list[ModuleBuildIdRow] = field(default_factory=list)


@dataclass
class TargetIntrospection:
    """Per-target process introspection (Block 0x0058, P1.6.3).

    Tagged-row TLV payload. Currently always one block per slice
    (``target_count == 1``); multi-target slices would emit one block
    per target, disambiguated by ``target_pid``.

    **Header distinction**: unlike :class:`KernelSymbolBundle` the
    payload header is ``(target_pid: u32, reserved: u32)`` — NOT
    ``(row_count, reserved)``. Readers walk TLV rows until
    end-of-payload (payload_len minus the 8-byte header). The
    TLV-skip-zero policy makes row_count awkward to pre-compute, and
    walk-to-end is simpler for heterogeneous tag sets.
    """
    target_pid: int = 0
    tracer_pid: int = 0
    login_uid: int = 0
    session_audit_id: int = 0
    selinux_context: str = ""
    target_ns_fingerprint: str = ""
    target_ns_scope_vs_collector: str = ""
    smaps_rollup_pss_kib: int = 0
    smaps_rollup_swap_kib: int = 0
    smaps_anon_hugepages_kib: int = 0
    rwx_region_count: int = 0
    target_cgroup: str = ""
    target_cwd: str = ""
    target_root: str = ""
    cap_eff: str = ""
    cap_amb: str = ""
    no_new_privs: int = 0
    seccomp_mode: int = 0
    core_dumping: int = 0
    thread_count: int = 0
    sig_cgt: str = ""
    io_rchar: int = 0
    io_wchar: int = 0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    limit_core: str = ""
    limit_memlock: str = ""
    limit_nofile: str = ""
    personality_hex: str = ""
    ancestry: str = ""
    exe_comm_mismatch: int = 0
    environ: bytes = b""
    redacted_env_keys: list[str] = field(default_factory=list)


@dataclass
class PersistenceRow:
    """A single filesystem persistence entry (Block 0x0056, P1.6.4).

    Fixed-row schema — every source shares the same layout. ``source``
    is a small integer tag (1..11) identifying the persistence class
    (systemd unit, cron entry, profile.d, pam.d, udev rule, etc.); see
    the writer docstring for the canonical mapping.
    """
    source: int = 0          # 1..11
    path: str = ""           # absolute filesystem path
    mtime_ns: int = 0
    size: int = 0
    mode: int = 0            # st_mode


@dataclass
class PersistenceManifest:
    """Filesystem persistence manifest (Block 0x0056, P1.6.4).

    Names + mtime + size + mode for files under systemd / cron /
    profile.d / pam.d / udev / modprobe / modules / rc_local paths.
    Top-level only (no recursion). **No content reads.** Gated behind
    ``--include-persistence-manifest``.
    """
    rows: list[PersistenceRow] = field(default_factory=list)


@dataclass
class ConnectivityTable:
    """System-wide kernel network state (Block 0x0054, P1.6.5).

    Heterogeneous rows covering route / ARP / packet socket / netdev /
    sockstat / SNMP data. Complements ``ConnectionTable`` (0x0052),
    which holds per-socket pid-attributed endpoint data. ConnectivityTable
    holds kernel network state that does not fit the socket-endpoint
    schema: routing tables, ARP cache, raw packet sockets (without
    addresses), per-interface counters, aggregate counts.
    """
    ipv4_routes: list[IPv4RouteRow] = field(default_factory=list)
    ipv6_routes: list[IPv6RouteRow] = field(default_factory=list)
    arp_entries: list[ArpEntryRow] = field(default_factory=list)
    packet_sockets: list[PacketSocketRow] = field(default_factory=list)
    netdev_stats: list[NetdevStatsRow] = field(default_factory=list)
    sockstat_families: list[SockstatFamilyRow] = field(default_factory=list)
    snmp_counters: list[SnmpCounterRow] = field(default_factory=list)
