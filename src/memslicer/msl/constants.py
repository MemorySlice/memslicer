"""MSL file-format constants and enumerations."""

from enum import IntEnum

# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------
FILE_MAGIC: bytes = b"MEMSLICE"   # 8 bytes
BLOCK_MAGIC: bytes = b"MSLC"     # 4 bytes

# ---------------------------------------------------------------------------
# Sizes
# ---------------------------------------------------------------------------
HEADER_SIZE: int = 64
BLOCK_HEADER_SIZE: int = 80
HASH_SIZE: int = 32

# ---------------------------------------------------------------------------
# Block flags
# ---------------------------------------------------------------------------
HAS_CHILDREN: int = 0x0001

# ---------------------------------------------------------------------------
# Format version
# ---------------------------------------------------------------------------
VERSION: tuple[int, int] = (1, 0)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Endianness(IntEnum):
    """Byte-order indicator stored in the file header."""

    LITTLE = 1
    BIG = 2


class OSType(IntEnum):
    """Operating system that produced the capture."""

    Windows = 0
    Linux = 1
    macOS = 2
    Android = 3
    iOS = 4


class ArchType(IntEnum):
    """CPU architecture of the captured process."""

    x86 = 0
    x86_64 = 1
    ARM64 = 2
    ARM32 = 3


class BlockType(IntEnum):
    """Block-type tags used in block headers."""

    MemoryRegion = 0x0001
    ModuleEntry = 0x0002
    ModuleListIndex = 0x0010
    ImportProvenance = 0x0030
    EndOfCapture = 0x0FFF


class CompAlgo(IntEnum):
    """Compression algorithm applied to block payloads."""

    NONE = 0
    ZSTD = 1
    LZ4 = 2


class PageState(IntEnum):
    """State of a captured memory page."""

    CAPTURED = 0
    FAILED = 1
    UNMAPPED = 2


class RegionType(IntEnum):
    """Classification of a memory region."""

    Unknown = 0
    Heap = 1
    Stack = 2
    Image = 3
    MappedFile = 4
    Anon = 5
    SharedMem = 6
    Other = 0xFF


class CapBit(IntEnum):
    """Capability bit-flags advertised in the file header."""

    MemoryRegions = 0
    ModuleList = 1
