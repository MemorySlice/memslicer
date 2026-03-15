"""Tests for MSL constants and enum values."""
from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE, VERSION,
    Endianness, OSType, ArchType, BlockType, CompAlgo, PageState,
    RegionType, CapBit,
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


def test_os_type_values():
    assert OSType.Windows == 0
    assert OSType.Linux == 1
    assert OSType.macOS == 2
    assert OSType.Android == 3
    assert OSType.iOS == 4


def test_arch_type_values():
    assert ArchType.x86 == 0
    assert ArchType.x86_64 == 1
    assert ArchType.ARM64 == 2
    assert ArchType.ARM32 == 3


def test_block_type_values():
    assert BlockType.MemoryRegion == 0x0001
    assert BlockType.ModuleEntry == 0x0002
    assert BlockType.ModuleListIndex == 0x0010
    assert BlockType.ImportProvenance == 0x0030
    assert BlockType.EndOfCapture == 0x0FFF


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
