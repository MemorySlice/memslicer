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

    block_type, flags, block_length, payload_version, reserved = struct.unpack_from("<HHIHH", data, offset + 4)
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
    # Version is uint16 LE: v1.0 = 0x0100 → LE bytes [0x00, 0x01]
    version = struct.unpack_from("<H", full_msl, 10)[0]
    assert version == 0x0100

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
    assert path_len == 19  # 18 chars + null terminator, pre-padding
    path_data = mod_payload[24:24 + path_len]
    assert path_data[:18] == b"/usr/lib/libc.so.6"
    assert path_data[18:19] == b'\x00'  # null terminated


# ---------------------------------------------------------------------------
# P0.4 wire-format compatibility — packed os_detail is opaque to old readers
# ---------------------------------------------------------------------------

def test_existing_parser_reads_new_os_detail():
    """Pin wire-format stability for the new ``os_detail`` microformat.

    P0.4 packs enrichment data into the spec's ``OSDetail`` string field
    using the ``msl.memslicer/1 <human> | k=v;…`` microformat. Any MSL
    consumer written against spec §6.2 — including the file's own
    writer test helpers, which parse SystemContext bytes by hand
    without knowing about the microformat — MUST still read the field
    byte-identical to what the producer wrote.

    This test:

    1. Builds a realistic enriched ``os_detail`` via ``pack_os_detail``
       with every high-priority field populated.
    2. Writes a full MSL file containing a SystemContext block with
       that value, via the normal ``MSLWriter.write_system_context``
       path.
    3. Parses the SystemContext block with the existing hand-rolled
       block parser (``_parse_block_at``) and a naive
       ``_read_padded_string`` helper, extracting ``os_detail`` as a
       raw UTF-8 string.
    4. Asserts the round-tripped value is **byte-identical** to what
       we put in. Any accidental change to the writer's layout, NUL
       handling, or pad8 math will fail this assertion.

    The test also asserts that
    :func:`memslicer.acquirer.os_detail.parse_os_detail` decodes the
    round-tripped value back to the original field dict, proving the
    end-to-end producer → wire → parser pipeline is stable.
    """
    from memslicer.acquirer.os_detail import pack_os_detail, parse_os_detail
    from memslicer.msl.types import SystemContext
    from memslicer.utils.padding import pad8

    # Realistic enrichment payload. Every key exercises a different
    # field-ordering bucket so a mis-order would be visible as a diff.
    input_fields = {
        "distro": "Ubuntu 24.04.1 LTS",
        "kernel": "6.8.0-45-generic",
        "arch": "x86_64",
        "machine_id": "deadbeefcafef00d",
        "hw_vendor": "Dell Inc.",
        "hw_model": "Latitude 7440",
        "hw_serial": "ABC123XYZ",
        "bios": "1.14.0",
        "cpu": "Intel(R) Core(TM) Ultra 7 155H",
        "cpu_count": 16,
        "ram": 34_359_738_368,
        "boot_id": "e1d2c3b4-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "virt": "none",
        "secure_boot": "1",
        "disk_enc": "luks",
        "selinux": "disabled",
        "apparmor": "enabled",
        "tz": "Europe/Berlin",
        "mode": "safe",
    }
    packed = pack_os_detail(input_fields)

    # Write a complete MSL file: header + SystemContext block + EoC.
    buf = io.BytesIO()
    header = FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=42,
    )
    writer = MSLWriter(buf, header)

    sys_ctx = SystemContext(
        boot_time=1_699_000_000_000_000_000,
        target_count=1,
        table_bitmap=0,
        acq_user="alice",
        hostname="lab-box",
        domain="corp.example",
        os_detail=packed,
        case_ref="CASE-2026-017",
    )
    writer.write_system_context(sys_ctx)
    writer.finalize()
    raw = buf.getvalue()

    # Walk blocks to find SystemContext — same pattern as the other
    # tests in this file, deliberately avoiding any reader abstraction.
    blocks = []
    offset = HEADER_SIZE
    while offset < len(raw):
        block = _parse_block_at(raw, offset)
        blocks.append(block)
        offset += block["length"]

    sys_ctx_blocks = [b for b in blocks if b["type"] == BlockType.SystemContext]
    assert len(sys_ctx_blocks) == 1, "exactly one SystemContext block expected"
    payload = sys_ctx_blocks[0]["payload"]

    # SystemContext fixed header (32 bytes): boot_time(8) + target_count(1)
    # + table_bitmap(4) + acq_user_len(2) + hostname_len(2) + domain_len(2)
    # + os_detail_len(2) + case_ref_len(2) + reserved(9)
    (
        acq_user_len,
        hostname_len,
        domain_len,
        os_detail_len,
        case_ref_len,
    ) = struct.unpack_from("<HHHHH", payload, 13)

    # Variable-length section: each string is NUL-terminated and pad8'd.
    cursor = 32

    def _read_padded(nbytes: int) -> tuple[str, int]:
        raw_bytes = payload[cursor : cursor + nbytes]
        # Strip trailing NUL before padding, per spec §6.2.
        text = raw_bytes.split(b"\x00", 1)[0].decode("utf-8")
        return text, pad8(nbytes)

    acq_user, consumed = _read_padded(acq_user_len)
    cursor += consumed
    hostname, consumed = _read_padded(hostname_len)
    cursor += consumed
    if domain_len > 0:
        domain, consumed = _read_padded(domain_len)
        cursor += consumed
    else:
        domain = ""
    os_detail, consumed = _read_padded(os_detail_len)
    cursor += consumed
    if case_ref_len > 0:
        case_ref, consumed = _read_padded(case_ref_len)
        cursor += consumed
    else:
        case_ref = ""

    # Core field assertions — the existing wire layout must not drift.
    assert acq_user == "alice"
    assert hostname == "lab-box"
    assert domain == "corp.example"
    assert case_ref == "CASE-2026-017"

    # The actual pin: byte-identical round-trip of the packed os_detail.
    # Any writer change to string padding, NUL handling, or encoding
    # would silently break consumers — the assertion fails loudly.
    assert os_detail == packed, (
        "os_detail wire round-trip changed bytes:\n"
        f"  wrote: {packed!r}\n"
        f"  read:  {os_detail!r}"
    )

    # Second-order check: the parser round-trips every input field.
    # This guards against an accidental packer/parser asymmetry that
    # the first check can't catch (e.g. both sides mis-encoding the
    # same way).
    parsed = parse_os_detail(os_detail)
    for key, value in input_fields.items():
        assert parsed.get(key) == str(value), (
            f"field {key!r} lost in round-trip: "
            f"input={value!r}, parsed={parsed.get(key)!r}"
        )
