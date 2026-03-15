"""Full roundtrip test - write MSL and verify every byte offset."""
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
from memslicer.utils.padding import pad8
from memslicer.utils.timestamps import now_ns


@pytest.fixture
def full_msl():
    """Write a complete MSL with 2 regions + 2 modules + EoC, return bytes."""
    buf = io.BytesIO()
    dump_uuid = uuid.uuid4().bytes
    ts = now_ns()

    header = FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0x03,
        dump_uuid=dump_uuid,
        timestamp_ns=ts,
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=9999,
    )

    writer = MSLWriter(buf, header, CompAlgo.NONE)

    # Region 1: fully captured (2 pages)
    region1 = MemoryRegion(
        base_addr=0x10000,
        region_size=8192,
        protection=5,
        region_type=RegionType.Image,
        page_size=4096,
        timestamp_ns=ts,
        page_states=[PageState.CAPTURED, PageState.CAPTURED],
        page_data_chunks=[b'\xaa' * 4096, b'\xbb' * 4096],
    )
    writer.write_memory_region(region1)

    # Region 2: mixed states (3 pages: captured, failed, captured)
    region2 = MemoryRegion(
        base_addr=0x20000,
        region_size=4096 * 3,
        protection=3,
        region_type=RegionType.Heap,
        page_size=4096,
        timestamp_ns=ts,
        page_states=[PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED],
        page_data_chunks=[b'\x11' * 4096, b'\x22' * 4096],  # 2 captured
    )
    writer.write_memory_region(region2)

    # Module list
    modules = [
        ModuleEntry(
            base_addr=0x400000,
            module_size=0x10000,
            path="/usr/lib/libc.so.6",
            version="2.31",
        ),
        ModuleEntry(
            base_addr=0x7f0000,
            module_size=0x5000,
            path="/lib/ld.so",
            version="",
            native_blob=b"\xde\xad",
        ),
    ]
    writer.write_module_list(modules)

    writer.finalize()
    return buf.getvalue()


def _parse_block_at(data: bytes, offset: int) -> dict:
    """Parse a block header at the given offset."""
    magic = data[offset:offset + 4]
    assert magic == BLOCK_MAGIC, f"Bad block magic at {offset}: {magic!r}"

    block_type, flags, block_length, reserved = struct.unpack_from("<HHII", data, offset + 4)
    block_uuid = data[offset + 16:offset + 32]
    parent_uuid = data[offset + 32:offset + 48]
    prev_hash = data[offset + 48:offset + 80]

    return {
        "offset": offset,
        "type": block_type,
        "flags": flags,
        "length": block_length,
        "uuid": block_uuid,
        "parent_uuid": parent_uuid,
        "prev_hash": prev_hash,
        "payload_offset": offset + BLOCK_HEADER_SIZE,
        "payload": data[offset + BLOCK_HEADER_SIZE:offset + block_length],
    }


def test_file_header(full_msl):
    """Verify file header fields."""
    assert full_msl[:8] == FILE_MAGIC
    assert full_msl[8] == 1  # little-endian
    assert full_msl[9] == 64  # header size
    assert full_msl[10] == 1  # version major
    assert full_msl[11] == 0  # version minor

    pid = struct.unpack_from("<I", full_msl, 52)[0]
    assert pid == 9999


def test_block_sequence(full_msl):
    """Verify the sequence of blocks: 2 regions + ModuleListIndex + 2 ModuleEntry + EoC."""
    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    assert len(blocks) == 6  # 2 regions + 1 index + 2 modules + 1 EoC

    assert blocks[0]["type"] == BlockType.MemoryRegion
    assert blocks[1]["type"] == BlockType.MemoryRegion
    assert blocks[2]["type"] == BlockType.ModuleListIndex
    assert blocks[3]["type"] == BlockType.ModuleEntry
    assert blocks[4]["type"] == BlockType.ModuleEntry
    assert blocks[5]["type"] == BlockType.EndOfCapture


def test_integrity_chain(full_msl):
    """Verify the complete BLAKE3 hash chain."""
    header_bytes = full_msl[:HEADER_SIZE]

    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    # Block 0's PrevHash = BLAKE3(header)
    assert blocks[0]["prev_hash"] == blake3.blake3(header_bytes).digest()

    # Each subsequent block's PrevHash = BLAKE3(previous block bytes)
    prev_block_bytes = header_bytes
    for i, block in enumerate(blocks):
        expected_prev_hash = blake3.blake3(prev_block_bytes).digest()
        assert block["prev_hash"] == expected_prev_hash, f"Block {i} PrevHash mismatch"
        prev_block_bytes = full_msl[block["offset"]:block["offset"] + block["length"]]

    # EoC FileHash = BLAKE3 of everything before EoC
    eoc = blocks[-1]
    file_hash = eoc["payload"][:32]
    everything_before_eoc = full_msl[:eoc["offset"]]
    expected_file_hash = blake3.blake3(everything_before_eoc).digest()
    assert file_hash == expected_file_hash


def test_module_parent_uuids(full_msl):
    """Verify ModuleEntry blocks reference ModuleListIndex as parent."""
    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    index_uuid = blocks[2]["uuid"]  # ModuleListIndex
    assert blocks[3]["parent_uuid"] == index_uuid
    assert blocks[4]["parent_uuid"] == index_uuid


def test_page_state_map_mixed(full_msl):
    """Verify PageStateMap encoding for mixed captured/failed region."""
    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    # Region 2 (blocks[1]): CAPTURED(00), FAILED(01), CAPTURED(00)
    payload = blocks[1]["payload"]
    # After BaseAddr(8) + RegionSize(8) + Prot(1) + RegionType(1) + PageSize(2) + MapLen(4) + Timestamp(8) = 32
    psm_byte = payload[32]
    # bits: 00_01_00_00 = 0x10  (3 states in MSB-first, remaining bits zero)
    assert psm_byte == 0x10


def test_region_page_data(full_msl):
    """Verify page data is only present for CAPTURED pages."""
    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    # Region 1: 2 captured pages = 8192 bytes of page data
    region1_payload = blocks[0]["payload"]
    # PageStateMap: 2 pages = 1 byte, padded to 8
    # Page data starts at offset 32 + 8 = 40
    page_data_offset = 32 + 8  # 32 bytes fixed fields + 8 bytes padded PSM
    page_data = region1_payload[page_data_offset:]
    assert page_data[:4096] == b'\xaa' * 4096
    assert page_data[4096:8192] == b'\xbb' * 4096


def test_string_padding(full_msl):
    """Verify module path strings are null-terminated and 8-byte padded."""
    blocks = []
    offset = HEADER_SIZE
    while offset < len(full_msl):
        block = _parse_block_at(full_msl, offset)
        blocks.append(block)
        offset += block["length"]

    # Module 0 (blocks[3]): path="/usr/lib/libc.so.6" (18 chars + null = 19, padded to 24)
    mod_payload = blocks[3]["payload"]
    # After BaseAddr(8) + ModuleSize(8) + PathLen(2) + VersionLen(2) + Reserved(4) = 24
    path_len = struct.unpack_from("<H", mod_payload, 16)[0]
    path_data = mod_payload[24:24 + path_len]
    assert path_data[:18] == b"/usr/lib/libc.so.6"
    assert b'\x00' in path_data  # null terminated
    assert len(path_data) % 8 == 0  # padded to 8B
