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
ENCRYPTED_HEADER_SIZE: int = 128
BLOCK_HEADER_SIZE: int = 80
HASH_SIZE: int = 32

# ---------------------------------------------------------------------------
# Block flags
# ---------------------------------------------------------------------------
COMPRESSED: int = 0x0001
COMPALGO_MASK: int = 0x0006
HAS_KEY_HINTS: int = 0x0008
HAS_CHILDREN: int = 0x0010
CONTINUATION: int = 0x0020

# ---------------------------------------------------------------------------
# File header flags (Flags field at offset 0x0C)
# ---------------------------------------------------------------------------
FLAG_IMPORTED: int = 0x0001        # bit 0
FLAG_INVESTIGATION: int = 0x0002   # bit 1
FLAG_ENCRYPTED: int = 0x0004       # bit 2
FLAG_REDACTED: int = 0x0008        # bit 3

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
    FreeBSD = 5
    NetBSD = 6
    OpenBSD = 7
    QNX = 8
    Fuchsia = 9
    Unknown = 0xFFFF


class ArchType(IntEnum):
    """CPU architecture of the captured process."""

    x86 = 0
    x86_64 = 1
    ARM64 = 2
    ARM32 = 3
    MIPS32 = 4
    MIPS64 = 5
    RISC_V_RV32 = 6
    RISC_V_RV64 = 7
    PPC32 = 8
    PPC64 = 9
    s390x = 10
    LoongArch64 = 11
    Unknown = 0xFFFF


class BlockType(IntEnum):
    """Block-type tags used in block headers."""

    MemoryRegion = 0x0001
    ModuleEntry = 0x0002
    ModuleListIndex = 0x0010
    ThreadContext = 0x0011
    FileDescriptor = 0x0012
    NetworkConnection = 0x0013
    EnvironmentBlock = 0x0014
    SecurityToken = 0x0015
    KeyHint = 0x0020
    ImportProvenance = 0x0030
    ProcessIdentity = 0x0040
    RelatedDump = 0x0041
    SystemContext = 0x0050
    ProcessTable = 0x0051
    ConnectionTable = 0x0052
    HandleTable = 0x0053
    EndOfCapture = 0x0FFF
    VASMap = 0x1001
    PointerGraph = 0x1003


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
    ThreadContexts = 2
    FileDescriptors = 3
    NetworkState = 4
    EnvironmentVars = 5
    SharedMemory = 6
    SecurityContext = 7
    ProcessIdentity = 8
    RelatedDumps = 9
    CryptoHints = 10
    SystemContext = 11
    SystemProcessTable = 12
    SystemNetworkTable = 13
    SystemHandleTable = 14


class ClockSource(IntEnum):
    """Clock source used for timestamps in the capture."""

    Unknown = 0x00
    CLOCK_REALTIME = 0x01
    CLOCK_MONOTONIC_RAW = 0x02
    QueryPerformanceCounter = 0x03
    mach_absolute_time = 0x04
    Other = 0xFF
