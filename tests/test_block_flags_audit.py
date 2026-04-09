"""Audit test: verify block flags are correctly encoded for ALL block types."""
from __future__ import annotations

import io
import struct

import pytest

from memslicer.msl.constants import (
    BLOCK_MAGIC, BLOCK_HEADER_SIZE, HEADER_SIZE,
    HAS_CHILDREN, COMPRESSED, COMPALGO_MASK,
    BlockType, CompAlgo, PageState,
)
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity,
)
from memslicer.msl.writer import MSLWriter


def _parse_block_headers(buf: bytes) -> list[dict]:
    """Parse all block headers from raw MSL bytes (after the file header)."""
    blocks = []
    pos = HEADER_SIZE
    while pos + BLOCK_HEADER_SIZE <= len(buf):
        magic = buf[pos:pos + 4]
        if magic != BLOCK_MAGIC:
            break
        block_type, flags, block_length = struct.unpack_from("<HHI", buf, pos + 4)
        blocks.append({
            "offset": pos,
            "block_type": block_type,
            "block_type_name": BlockType(block_type).name,
            "flags": flags,
            "block_length": block_length,
        })
        pos += block_length
    return blocks


def _create_msl(comp_algo: CompAlgo) -> bytes:
    """Create an MSL with all block types using the given compression algo."""
    out = io.BytesIO()
    header = FileHeader(pid=1234, timestamp_ns=1_000_000_000)
    writer = MSLWriter(out, header, comp_algo)

    # Block 0: ProcessIdentity
    proc = ProcessIdentity(
        ppid=1, session_id=0, start_time_ns=999,
        exe_path="/usr/bin/test", cmd_line="test --flag",
    )
    writer.write_process_identity(proc)

    # MemoryRegion with page data
    region = MemoryRegion(
        base_addr=0x1000,
        region_size=4096,
        protection=0x05,
        page_size=4096,
        timestamp_ns=2_000_000_000,
        page_states=[PageState.CAPTURED],
        page_data_chunks=[b"\xAA" * 4096],
    )
    writer.write_memory_region(region)

    # ModuleList (creates ModuleListIndex + ModuleEntry children)
    mod = ModuleEntry(
        base_addr=0x400000,
        module_size=0x10000,
        path="/lib/libc.so",
        version="2.31",
        disk_hash=b"\x00" * 32,
        native_blob=b"",
    )
    writer.write_module_list([mod])

    # End of capture
    writer.finalize()

    return out.getvalue()


class TestBlockFlagsWithNoCompression:
    """Verify flags when compression is NONE."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.data = _create_msl(CompAlgo.NONE)
        self.blocks = _parse_block_headers(self.data)

    def test_all_blocks_present(self):
        names = [b["block_type_name"] for b in self.blocks]
        assert names == [
            "ProcessIdentity",
            "MemoryRegion",
            "ModuleListIndex",
            "ModuleEntry",
            "EndOfCapture",
        ]

    def test_process_identity_flags(self):
        blk = self.blocks[0]
        assert blk["block_type"] == BlockType.ProcessIdentity
        assert blk["flags"] == 0x0000, f"Expected 0x0000, got 0x{blk['flags']:04X}"

    def test_memory_region_flags_no_compression(self):
        blk = self.blocks[1]
        assert blk["block_type"] == BlockType.MemoryRegion
        assert blk["flags"] == 0x0000, f"Expected 0x0000, got 0x{blk['flags']:04X}"

    def test_module_list_index_flags(self):
        blk = self.blocks[2]
        assert blk["block_type"] == BlockType.ModuleListIndex
        assert blk["flags"] == HAS_CHILDREN, f"Expected 0x{HAS_CHILDREN:04X}, got 0x{blk['flags']:04X}"
        # CRITICAL: HAS_CHILDREN must NOT overlap with compression bits
        assert (blk["flags"] & COMPRESSED) == 0, "ModuleListIndex has COMPRESSED bit set!"
        assert (blk["flags"] & COMPALGO_MASK) == 0, "ModuleListIndex has CompAlgo bits set!"

    def test_module_entry_flags(self):
        blk = self.blocks[3]
        assert blk["block_type"] == BlockType.ModuleEntry
        assert blk["flags"] == 0x0000, f"Expected 0x0000, got 0x{blk['flags']:04X}"

    def test_end_of_capture_flags(self):
        blk = self.blocks[4]
        assert blk["block_type"] == BlockType.EndOfCapture
        assert blk["flags"] == 0x0000, f"Expected 0x0000, got 0x{blk['flags']:04X}"


class TestBlockFlagsWithZSTD:
    """Verify flags when compression is ZSTD."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.data = _create_msl(CompAlgo.ZSTD)
        self.blocks = _parse_block_headers(self.data)

    def test_process_identity_flags_no_compression(self):
        blk = self.blocks[0]
        assert blk["block_type"] == BlockType.ProcessIdentity
        assert blk["flags"] == 0x0000, (
            f"ProcessIdentity should NOT be compressed, got 0x{blk['flags']:04X}"
        )

    def test_memory_region_flags_zstd(self):
        blk = self.blocks[1]
        assert blk["block_type"] == BlockType.MemoryRegion
        expected = 0x0003  # bit0=Compressed + bits1-2=01(ZSTD)
        assert blk["flags"] == expected, f"Expected 0x{expected:04X}, got 0x{blk['flags']:04X}"
        # Verify individual bits
        assert (blk["flags"] & COMPRESSED) != 0, "Compressed bit not set"
        algo_bits = (blk["flags"] & COMPALGO_MASK) >> 1
        assert algo_bits == CompAlgo.ZSTD, f"CompAlgo bits = {algo_bits}, expected ZSTD(1)"

    def test_module_list_index_not_compressed(self):
        blk = self.blocks[2]
        assert blk["block_type"] == BlockType.ModuleListIndex
        assert blk["flags"] == HAS_CHILDREN, (
            f"ModuleListIndex should only have HAS_CHILDREN=0x{HAS_CHILDREN:04X}, "
            f"got 0x{blk['flags']:04X}"
        )
        assert (blk["flags"] & COMPRESSED) == 0, "ModuleListIndex ERRONEOUSLY has Compressed bit!"
        assert (blk["flags"] & COMPALGO_MASK) == 0, "ModuleListIndex ERRONEOUSLY has CompAlgo bits!"

    def test_module_entry_not_compressed(self):
        blk = self.blocks[3]
        assert blk["block_type"] == BlockType.ModuleEntry
        assert blk["flags"] == 0x0000, (
            f"ModuleEntry should NOT be compressed, got 0x{blk['flags']:04X}"
        )

    def test_end_of_capture_not_compressed(self):
        blk = self.blocks[4]
        assert blk["block_type"] == BlockType.EndOfCapture
        assert blk["flags"] == 0x0000, (
            f"EndOfCapture should NOT be compressed, got 0x{blk['flags']:04X}"
        )


class TestBlockFlagsWithLZ4:
    """Verify flags when compression is LZ4."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.data = _create_msl(CompAlgo.LZ4)
        self.blocks = _parse_block_headers(self.data)

    def test_memory_region_flags_lz4(self):
        blk = self.blocks[1]
        assert blk["block_type"] == BlockType.MemoryRegion
        expected = 0x0005  # bit0=Compressed + bits1-2=10(LZ4)
        assert blk["flags"] == expected, f"Expected 0x{expected:04X}, got 0x{blk['flags']:04X}"
        algo_bits = (blk["flags"] & COMPALGO_MASK) >> 1
        assert algo_bits == CompAlgo.LZ4, f"CompAlgo bits = {algo_bits}, expected LZ4(2)"

    def test_module_list_index_not_compressed(self):
        blk = self.blocks[2]
        assert blk["block_type"] == BlockType.ModuleListIndex
        assert blk["flags"] == HAS_CHILDREN
        assert (blk["flags"] & COMPRESSED) == 0


class TestFlagBitPositions:
    """Verify flag constants match the spec (Table 7)."""

    def test_compressed_is_bit_0(self):
        assert COMPRESSED == 0x0001

    def test_compalgo_mask_is_bits_1_2(self):
        assert COMPALGO_MASK == 0x0006

    def test_has_children_is_bit_4(self):
        assert HAS_CHILDREN == 0x0010

    def test_has_children_does_not_overlap_compression(self):
        """CRITICAL: HAS_CHILDREN must not share bits with compression fields."""
        assert (HAS_CHILDREN & COMPRESSED) == 0
        assert (HAS_CHILDREN & COMPALGO_MASK) == 0

    def test_zstd_flags_value(self):
        """ZSTD: compressed=1, algo=01 -> 0b0000_0011 = 0x0003."""
        flags = COMPRESSED | (CompAlgo.ZSTD << 1)
        assert flags == 0x0003

    def test_lz4_flags_value(self):
        """LZ4: compressed=1, algo=10 -> 0b0000_0101 = 0x0005."""
        flags = COMPRESSED | (CompAlgo.LZ4 << 1)
        assert flags == 0x0005

    def test_none_flags_value(self):
        """NONE compression: flags should be 0x0000."""
        assert CompAlgo.NONE == 0
