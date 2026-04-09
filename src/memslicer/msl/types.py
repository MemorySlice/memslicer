from __future__ import annotations
import uuid
from dataclasses import dataclass, field

from memslicer.msl.constants import (
    OSType, ArchType, CompAlgo, PageState, RegionType, BlockType,
    Endianness, VERSION, HASH_SIZE, ClockSource,
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
    target_count: int = 1
    table_bitmap: int = 0  # bit0=ProcessTable, bit1=ConnectionTable, bit2=HandleTable
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
