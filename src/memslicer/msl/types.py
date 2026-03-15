from __future__ import annotations
import uuid
from dataclasses import dataclass, field

from memslicer.msl.constants import (
    OSType, ArchType, CompAlgo, PageState, RegionType, BlockType,
    Endianness, VERSION, HASH_SIZE,
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
