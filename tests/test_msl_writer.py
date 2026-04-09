"""Tests for MSL writer - verifies binary format correctness."""
import io
import struct
import uuid

import blake3
import pytest

from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE,
    BlockType, CompAlgo, OSType, ArchType, PageState, RegionType,
)
from memslicer.msl.types import FileHeader, MemoryRegion, ModuleEntry
from memslicer.msl.writer import MSLWriter
from memslicer.utils.timestamps import now_ns


@pytest.fixture
def header():
    return FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0x03,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=42,
    )


class TestMinimalMSL:
    """Test writing minimal MSL: header + EoC only."""

    def test_file_starts_with_magic(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        assert data[:8] == FILE_MAGIC

    def test_header_size_64(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        # Before finalize, header is already written
        assert buf.tell() == HEADER_SIZE

    def test_endianness_byte(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        assert data[8] == 1  # little-endian

    def test_header_size_field(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        assert data[9] == HEADER_SIZE

    def test_version_field(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        # Version is uint16 LE with major in high byte: v1.0 = 0x0100 → LE bytes [0x00, 0x01]
        version = struct.unpack_from("<H", data, 10)[0]
        assert version == 0x0100  # major=1, minor=0

    def test_eoc_block_starts_at_64(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        # First block (EoC) starts right after header
        assert data[HEADER_SIZE:HEADER_SIZE + 4] == BLOCK_MAGIC

    def test_eoc_block_type(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        block_type = struct.unpack_from("<H", data, HEADER_SIZE + 4)[0]
        assert block_type == BlockType.EndOfCapture

    def test_eoc_prev_hash_is_header_hash(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        header_bytes = data[:HEADER_SIZE]
        expected_prev_hash = blake3.blake3(header_bytes).digest()

        # PrevHash is at offset 48 within block header (after magic4+type2+flags2+len4+payloadver2+reserved2+uuid16+parent16)
        prev_hash_offset = HEADER_SIZE + 4 + 2 + 2 + 4 + 2 + 2 + 16 + 16
        actual_prev_hash = data[prev_hash_offset:prev_hash_offset + 32]
        assert actual_prev_hash == expected_prev_hash

    def test_eoc_file_hash(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        header_bytes = data[:HEADER_SIZE]

        # EoC payload starts after block header
        eoc_payload_offset = HEADER_SIZE + BLOCK_HEADER_SIZE
        file_hash = data[eoc_payload_offset:eoc_payload_offset + 32]

        # FileHash should be BLAKE3 of everything before the EoC block
        expected = blake3.blake3(header_bytes).digest()
        assert file_hash == expected

    def test_pid_field(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.finalize()

        data = buf.getvalue()
        # pid at offset: 8+1+1+1+1+4+8+16+8+2+2 = 52
        pid = struct.unpack_from("<I", data, 52)[0]
        assert pid == 42


class TestMemoryRegionBlock:
    """Test writing memory region blocks."""

    def test_region_block_type(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        region = MemoryRegion(
            base_addr=0x1000,
            region_size=4096,
            protection=5,
            region_type=RegionType.Image,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b'\xaa' * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()

        data = buf.getvalue()
        # First block at offset 64
        block_type = struct.unpack_from("<H", data, HEADER_SIZE + 4)[0]
        assert block_type == BlockType.MemoryRegion

    def test_region_base_addr(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        region = MemoryRegion(
            base_addr=0xDEADBEEF,
            region_size=4096,
            protection=5,
            region_type=RegionType.Image,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b'\xaa' * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()

        data = buf.getvalue()
        payload_offset = HEADER_SIZE + BLOCK_HEADER_SIZE
        base_addr = struct.unpack_from("<Q", data, payload_offset)[0]
        assert base_addr == 0xDEADBEEF

    def test_page_state_map_encoding(self, header):
        """Test 2-bit MSB-first page state encoding."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        # 4 pages: CAPTURED(00), FAILED(01), UNMAPPED(10), CAPTURED(00)
        region = MemoryRegion(
            base_addr=0x1000,
            region_size=4096 * 4,
            protection=1,
            region_type=RegionType.Anon,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED, PageState.FAILED, PageState.UNMAPPED, PageState.CAPTURED],
            page_data_chunks=[b'\x00' * 4096, b'\x00' * 4096],  # 2 captured pages
        )
        writer.write_memory_region(region)
        writer.finalize()

        data = buf.getvalue()
        # Payload starts at HEADER_SIZE + BLOCK_HEADER_SIZE
        # PageStateMap starts after: BaseAddr(8) + RegionSize(8) + Prot(1) + RegionType(1) + PageSize(2) + MapLen(4) + Timestamp(8) = 32
        psm_offset = HEADER_SIZE + BLOCK_HEADER_SIZE + 32
        # 4 pages = 1 byte: bits 7-6=CAPTURED(00), 5-4=FAILED(01), 3-2=UNMAPPED(10), 1-0=CAPTURED(00)
        # = 0b00_01_10_00 = 0x18
        assert data[psm_offset] == 0x18


class TestModuleBlocks:
    """Test writing module list blocks."""

    def test_module_list_index(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        modules = [
            ModuleEntry(base_addr=0x400000, module_size=0x10000, path="/lib/libc.so"),
        ]
        writer.write_module_list(modules)
        writer.finalize()

        data = buf.getvalue()
        # First block should be ModuleListIndex
        block_type = struct.unpack_from("<H", data, HEADER_SIZE + 4)[0]
        assert block_type == BlockType.ModuleListIndex

        # Flags should have HAS_CHILDREN (0x0010, bit 4)
        flags = struct.unpack_from("<H", data, HEADER_SIZE + 6)[0]
        assert flags & 0x0010


class TestIntegrityChain:
    """Test that integrity chain is correctly maintained across blocks."""

    def test_two_blocks_chain(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        region = MemoryRegion(
            base_addr=0x1000,
            region_size=4096,
            protection=1,
            region_type=RegionType.Anon,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b'\xcc' * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()

        data = buf.getvalue()
        header_bytes = data[:HEADER_SIZE]

        # Block 0 (MemoryRegion) PrevHash = BLAKE3(header)
        prev_hash_0_offset = HEADER_SIZE + 48  # offset within block header
        assert data[prev_hash_0_offset:prev_hash_0_offset + 32] == blake3.blake3(header_bytes).digest()

        # Find Block 1 (EoC) - need Block 0's total length
        block0_len = struct.unpack_from("<I", data, HEADER_SIZE + 8)[0]
        block1_start = HEADER_SIZE + block0_len

        # Block 1 PrevHash = BLAKE3(block0_bytes)
        block0_bytes = data[HEADER_SIZE:HEADER_SIZE + block0_len]
        prev_hash_1_offset = block1_start + 48
        assert data[prev_hash_1_offset:prev_hash_1_offset + 32] == blake3.blake3(block0_bytes).digest()


class TestPageSizeLog2Validation:
    """Test PageSizeLog2 validation in write_memory_region."""

    def _make_region(self, page_size: int) -> MemoryRegion:
        return MemoryRegion(
            base_addr=0x1000,
            region_size=page_size,
            protection=1,
            region_type=RegionType.Anon,
            page_size=page_size,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b'\x00' * page_size],
        )

    def test_non_power_of_two_rejected(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=4096)
        region.page_size = 3000  # not a power of 2
        with pytest.raises(ValueError, match="power of 2"):
            writer.write_memory_region(region)

    def test_zero_page_size_rejected(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=4096)
        region.page_size = 0
        with pytest.raises(ValueError, match="power of 2"):
            writer.write_memory_region(region)

    def test_negative_page_size_rejected(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=4096)
        region.page_size = -4096
        with pytest.raises(ValueError, match="power of 2"):
            writer.write_memory_region(region)

    def test_page_size_too_small_rejected(self, header):
        """page_size=512 -> log2=9, below minimum of 10."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=4096)
        region.page_size = 512  # log2 = 9
        region.region_size = 512
        region.page_data_chunks = [b'\x00' * 512]
        with pytest.raises(ValueError, match="outside valid range"):
            writer.write_memory_region(region)

    def test_valid_4k_page_accepted(self, header):
        """page_size=4096 -> log2=12, within [10, 40]."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=4096)
        writer.write_memory_region(region)
        writer.finalize()
        assert buf.tell() > HEADER_SIZE

    def test_valid_64k_page_accepted(self, header):
        """page_size=65536 -> log2=16, within [10, 40]."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = self._make_region(page_size=65536)
        region.region_size = 65536
        region.page_data_chunks = [b'\x00' * 65536]
        writer.write_memory_region(region)
        writer.finalize()
        assert buf.tell() > HEADER_SIZE
