"""Tests for MSL constants and enum values."""
from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE, VERSION,
    COMPRESSED, COMPALGO_MASK, HAS_KEY_HINTS, HAS_CHILDREN, CONTINUATION,
    Endianness, OSType, ArchType, BlockType, CompAlgo, PageState,
    RegionType, CapBit, ClockSource, OmissionReason,
    VasNameSource, ThreadState, EXTENSION_FORBIDDEN_TYPES,
    TC_FLAG_CURRENT, TC_FLAG_CRASHED, TC_FLAG_SUSPENDED, TC_FLAG_PARTIAL,
    REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_FP, REG_ROLE_FLAGS, REG_ROLE_TLS,
    REG_ROLE_LR,
)


def test_file_magic():
    assert FILE_MAGIC == b"MEMSLICE"
    assert len(FILE_MAGIC) == 8


def test_block_magic():
    assert BLOCK_MAGIC == b"MSLC"
    assert len(BLOCK_MAGIC) == 4


def test_header_size():
    assert HEADER_SIZE == 64


def test_block_header_size():
    assert BLOCK_HEADER_SIZE == 80


def test_version():
    """MSL 1.1: extension segments, EoC BlockCount, VAS NameSource, Thread Context."""
    assert VERSION == (1, 1)


def test_endianness_values():
    assert Endianness.LITTLE == 1
    assert Endianness.BIG == 2


def test_block_flag_constants():
    assert COMPRESSED == 0x0001
    assert COMPALGO_MASK == 0x0006
    assert HAS_KEY_HINTS == 0x0008
    assert HAS_CHILDREN == 0x0010
    assert CONTINUATION == 0x0020


def test_os_type_values():
    assert OSType.Windows == 0
    assert OSType.Linux == 1
    assert OSType.macOS == 2
    assert OSType.Android == 3
    assert OSType.iOS == 4
    assert OSType.FreeBSD == 5
    assert OSType.NetBSD == 6
    assert OSType.OpenBSD == 7
    assert OSType.QNX == 8
    assert OSType.Fuchsia == 9
    assert OSType.Unknown == 0xFFFF


def test_arch_type_values():
    assert ArchType.x86 == 0
    assert ArchType.x86_64 == 1
    assert ArchType.ARM64 == 2
    assert ArchType.ARM32 == 3
    assert ArchType.MIPS32 == 4
    assert ArchType.MIPS64 == 5
    assert ArchType.RISC_V_RV32 == 6
    assert ArchType.RISC_V_RV64 == 7
    assert ArchType.PPC32 == 8
    assert ArchType.PPC64 == 9
    assert ArchType.s390x == 10
    assert ArchType.LoongArch64 == 11
    assert ArchType.Unknown == 0xFFFF


def test_block_type_values():
    assert BlockType.MemoryRegion == 0x0001
    assert BlockType.ModuleEntry == 0x0002
    assert BlockType.ModuleListIndex == 0x0010
    assert BlockType.ThreadContext == 0x0011
    assert BlockType.FileDescriptor == 0x0012
    assert BlockType.NetworkConnection == 0x0013
    assert BlockType.EnvironmentBlock == 0x0014
    assert BlockType.SecurityToken == 0x0015
    assert BlockType.KeyHint == 0x0020
    assert BlockType.ImportProvenance == 0x0030
    assert BlockType.ProcessIdentity == 0x0040
    assert BlockType.RelatedDump == 0x0041
    assert BlockType.SystemContext == 0x0050
    assert BlockType.ProcessTable == 0x0051
    assert BlockType.ConnectionTable == 0x0052
    assert BlockType.HandleTable == 0x0053
    assert BlockType.EndOfExtension == 0x0FFE
    assert BlockType.EndOfCapture == 0x0FFF
    assert BlockType.VASMap == 0x1001
    assert BlockType.PointerGraph == 0x1003


def test_extension_block_type_values():
    """Non-spec extension blocks sit just above the 0x0054-0x0058 spec range."""
    assert BlockType.PhysicalMemoryMap == 0x0059
    assert BlockType.ModuleBuildIdManifest == 0x005A
    assert BlockType.RegionOmissionManifest == 0x005B


def test_extension_forbidden_types():
    """Evidence block types barred from extension segments (spec Section 4.6)."""
    expected = (
        {0x0001, 0x0002, 0x0030, 0x0040, 0x0FFF}
        | set(range(0x0010, 0x0016))
        | set(range(0x0050, 0x0059))
    )
    assert EXTENSION_FORBIDDEN_TYPES == frozenset(expected)
    # Derived views stay allowed.
    for allowed in (0x0020, 0x0041, 0x0059, 0x005A, 0x005B, 0x0FFE, 0x1001, 0x1003):
        assert allowed not in EXTENSION_FORBIDDEN_TYPES


def test_vas_name_source_values():
    assert VasNameSource.UNSPECIFIED == 0
    assert VasNameSource.LIVE == 1
    assert VasNameSource.SOURCE_METADATA == 2
    assert VasNameSource.SYNTHESIZED == 3
    assert len(VasNameSource) == 4


def test_thread_state_values():
    assert ThreadState.UNKNOWN == 0
    assert ThreadState.RUNNING == 1
    assert ThreadState.SLEEPING == 2
    assert ThreadState.STOPPED == 3
    assert ThreadState.WAITING == 4
    assert ThreadState.UNINTERRUPTIBLE == 5
    assert ThreadState.HALTED == 6
    assert ThreadState.ZOMBIE == 7
    assert len(ThreadState) == 8


def test_thread_context_flag_bits():
    assert TC_FLAG_CURRENT == 0x0001
    assert TC_FLAG_CRASHED == 0x0002
    assert TC_FLAG_SUSPENDED == 0x0004
    assert TC_FLAG_PARTIAL == 0x0008


def test_register_role_bits():
    assert REG_ROLE_PC == 0x0001
    assert REG_ROLE_SP == 0x0002
    assert REG_ROLE_FP == 0x0004
    assert REG_ROLE_FLAGS == 0x0008
    assert REG_ROLE_TLS == 0x0010
    assert REG_ROLE_LR == 0x0020


def test_comp_algo_values():
    assert CompAlgo.NONE == 0
    assert CompAlgo.ZSTD == 1
    assert CompAlgo.LZ4 == 2


def test_page_state_values():
    assert PageState.CAPTURED == 0
    assert PageState.FAILED == 1
    assert PageState.UNMAPPED == 2
    assert PageState.NOT_RESIDENT == 3


def test_page_state_fits_two_bit_map():
    """Every state must be encodable in the 2-bit PageStateMap."""
    assert {int(s) for s in PageState} == {0, 1, 2, 3}
    assert PageState(3) is PageState.NOT_RESIDENT


def test_omission_reason_values():
    assert OmissionReason.MODULE_EXCLUDE == 1
    assert OmissionReason.SCOPE == 2
    assert len(OmissionReason) == 2  # 3+ reserved


def test_region_type_values():
    assert RegionType.Unknown == 0
    assert RegionType.Heap == 1
    assert RegionType.Stack == 2
    assert RegionType.Image == 3
    assert RegionType.MappedFile == 4
    assert RegionType.Anon == 5
    assert RegionType.SharedMem == 6
    assert RegionType.Other == 0xFF


def test_cap_bit_values():
    assert CapBit.MemoryRegions == 0
    assert CapBit.ModuleList == 1
    assert CapBit.ThreadContexts == 2
    assert CapBit.FileDescriptors == 3
    assert CapBit.NetworkState == 4
    assert CapBit.EnvironmentVars == 5
    assert CapBit.SharedMemory == 6
    assert CapBit.SecurityContext == 7
    assert CapBit.ProcessIdentity == 8
    assert CapBit.RelatedDumps == 9
    assert CapBit.CryptoHints == 10
    assert CapBit.SystemContext == 11
    assert CapBit.SystemProcessTable == 12
    assert CapBit.SystemNetworkTable == 13
    assert CapBit.SystemHandleTable == 14


def test_clock_source_values():
    assert ClockSource.Unknown == 0x00
    assert ClockSource.CLOCK_REALTIME == 0x01
    assert ClockSource.CLOCK_MONOTONIC_RAW == 0x02
    assert ClockSource.QueryPerformanceCounter == 0x03
    assert ClockSource.mach_absolute_time == 0x04
    assert ClockSource.Other == 0xFF
