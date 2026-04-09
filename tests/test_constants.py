"""Tests for MSL constants and enum values."""
from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE, VERSION,
    COMPRESSED, COMPALGO_MASK, HAS_KEY_HINTS, HAS_CHILDREN, CONTINUATION,
    Endianness, OSType, ArchType, BlockType, CompAlgo, PageState,
    RegionType, CapBit, ClockSource,
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
    assert VERSION == (1, 0)


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
    assert BlockType.EndOfCapture == 0x0FFF
    assert BlockType.VASMap == 0x1001
    assert BlockType.PointerGraph == 0x1003


def test_comp_algo_values():
    assert CompAlgo.NONE == 0
    assert CompAlgo.ZSTD == 1
    assert CompAlgo.LZ4 == 2


def test_page_state_values():
    assert PageState.CAPTURED == 0
    assert PageState.FAILED == 1
    assert PageState.UNMAPPED == 2


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
