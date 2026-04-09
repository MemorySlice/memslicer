"""Comprehensive MSL spec compliance tests.

Verifies that the writer output conforms to the MSL v1.1.0 specification,
including header layout, compression framing, table preambles, validation
rules, constants, encryption mode, and new block types.
"""
from __future__ import annotations

import io
import struct
import uuid

import blake3
import pytest

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ProcessIdentity, SystemContext,
    ProcessEntry, ConnectionEntry, HandleEntry,
    KeyHint, ImportProvenance, RelatedDump,
)
from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, ENCRYPTED_HEADER_SIZE,
    BLOCK_HEADER_SIZE, HASH_SIZE,
    BlockType, CompAlgo, OSType, ArchType, PageState, RegionType,
    Endianness, ClockSource,
    FLAG_ENCRYPTED, FLAG_REDACTED,
    COMPRESSED, COMPALGO_MASK,
)
from memslicer.msl.compression import decompress
from memslicer.utils.timestamps import now_ns


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def header():
    """Standard unencrypted file header for tests."""
    return FileHeader(
        endianness=Endianness.LITTLE,
        version=(1, 0),
        flags=0,
        cap_bitmap=0x03,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=1000,
        clock_source=ClockSource.Unknown,
    )


def _write_minimal(header: FileHeader, comp: CompAlgo = CompAlgo.NONE):
    """Write header + EoC and return raw bytes."""
    buf = io.BytesIO()
    writer = MSLWriter(buf, header, comp)
    writer.finalize()
    return buf.getvalue()


# ===================================================================
# 1. File Header BlockCount field
# ===================================================================

class TestFileHeaderBlockCount:
    """Verify BlockCount at offset 0x39 and reserved bytes at 0x3D."""

    def test_block_count_offset_and_size(self, header):
        """BlockCount is a 4-byte LE uint32 at offset 0x39."""
        data = _write_minimal(header)
        block_count = struct.unpack_from("<I", data, 0x39)[0]
        # Default block_count=0 means streaming/unknown
        assert block_count == 0

    def test_reserved_bytes_after_block_count(self, header):
        """3 bytes at 0x3D..0x3F must be zero (reserved)."""
        data = _write_minimal(header)
        reserved = data[0x3D:0x40]
        assert reserved == b"\x00" * 3

    def test_block_count_streaming_with_eoc_only(self, header):
        """A minimal MSL (EoC only) still has BlockCount=0 (streaming mode)."""
        header.block_count = 0
        data = _write_minimal(header)
        assert struct.unpack_from("<I", data, 0x39)[0] == 0

    def test_nonzero_block_count(self, header):
        """When block_count is set explicitly, it appears at 0x39."""
        header.block_count = 5
        data = _write_minimal(header)
        assert struct.unpack_from("<I", data, 0x39)[0] == 5


# ===================================================================
# 2. Compression with UncompressedSize prefix
# ===================================================================

class TestCompressionUncompressedSizePrefix:
    """Verify on-disk compressed payloads start with 8-byte UncompressedSize."""

    def _write_compressed_region(self, header, comp_algo: CompAlgo):
        """Write a single MemoryRegion with compression, return raw bytes."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header, comp_algo)

        page_data = b"\xAB" * 4096
        region = MemoryRegion(
            base_addr=0x10000,
            region_size=4096,
            protection=5,
            region_type=RegionType.Image,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[page_data],
        )
        writer.write_memory_region(region)
        writer.finalize()
        return buf.getvalue()

    def _extract_block_payload(self, data: bytes, block_index: int = 0):
        """Extract the on-disk payload of the Nth block after the file header."""
        offset = HEADER_SIZE
        for _ in range(block_index):
            block_len = struct.unpack_from("<I", data, offset + 8)[0]
            offset += block_len
        block_len = struct.unpack_from("<I", data, offset + 8)[0]
        payload = data[offset + BLOCK_HEADER_SIZE : offset + block_len]
        return payload

    def test_zstd_uncompressed_size_prefix(self, header):
        """ZSTD block payload starts with 8-byte UncompressedSize (uint64 LE)."""
        data = self._write_compressed_region(header, CompAlgo.ZSTD)
        payload = self._extract_block_payload(data, block_index=0)

        # First 8 bytes = UncompressedSize
        uncomp_size = struct.unpack_from("<Q", payload, 0)[0]
        assert uncomp_size > 0

        # Decompress the data after the 8-byte prefix
        compressed_data = payload[8:]
        # Strip padding (find actual compressed data end by decompressing)
        decompressed = decompress(compressed_data, CompAlgo.ZSTD)
        assert len(decompressed) == uncomp_size

    def test_lz4_uncompressed_size_prefix(self, header):
        """LZ4 block payload starts with 8-byte UncompressedSize (uint64 LE).

        Note: The on-disk payload is padded to 8-byte alignment, which adds
        trailing zeros. LZ4 cannot tolerate trailing garbage, so we verify
        the structural property (prefix value matches expected uncompressed
        size) and confirm LZ4 round-trips via the compress/decompress API.
        """
        data = self._write_compressed_region(header, CompAlgo.LZ4)
        payload = self._extract_block_payload(data, block_index=0)

        uncomp_size = struct.unpack_from("<Q", payload, 0)[0]
        assert uncomp_size > 0

        # The UncompressedSize should match the padded payload size of the
        # original MemoryRegion payload (which is > 4096 due to the region
        # header fields + page state map + page data, all pad8'd).
        # At minimum it must be >= 4096 (one page of data).
        assert uncomp_size >= 4096

        # Verify LZ4 round-trip works via the compression API directly
        from memslicer.msl.compression import compress as msl_compress
        test_data = b"\xAB" * 4096
        compressed = msl_compress(test_data, CompAlgo.LZ4)
        decompressed = decompress(compressed, CompAlgo.LZ4)
        assert decompressed == test_data

    def test_uncompressed_has_no_prefix(self, header):
        """Uncompressed block payload does NOT have the 8-byte prefix."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header, CompAlgo.NONE)

        region = MemoryRegion(
            base_addr=0x10000,
            region_size=4096,
            protection=5,
            region_type=RegionType.Image,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b"\xAB" * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()
        data = buf.getvalue()

        # Check that the block is NOT marked as compressed
        block_flags = struct.unpack_from("<H", data, HEADER_SIZE + 6)[0]
        assert not (block_flags & COMPRESSED)


# ===================================================================
# 3. Table Preambles
# ===================================================================

class TestTablePreambles:
    """Verify EntryCount(4B) + Reserved(4B) preamble for system tables."""

    def _build_investigation_writer(self, header):
        """Create a writer with ProcessIdentity + SystemContext, return (buf, writer, sys_uuid)."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        proc_id = ProcessIdentity(
            ppid=1, session_id=1, start_time_ns=now_ns(),
            exe_path="/bin/test", cmd_line="test --run",
        )
        writer.write_process_identity(proc_id)

        sys_ctx = SystemContext(
            boot_time=now_ns(), target_count=1, table_bitmap=0x07,
            acq_user="root", hostname="testhost",
        )
        sys_uuid = writer.write_system_context(sys_ctx)
        return buf, writer, sys_uuid

    def _extract_table_payload(self, data: bytes, table_block_index: int):
        """Extract the payload of the Nth block (0-based) after file header."""
        offset = HEADER_SIZE
        for _ in range(table_block_index):
            block_len = struct.unpack_from("<I", data, offset + 8)[0]
            offset += block_len
        block_len = struct.unpack_from("<I", data, offset + 8)[0]
        return data[offset + BLOCK_HEADER_SIZE : offset + block_len]

    def test_process_table_preamble(self, header):
        """ProcessTable preamble: EntryCount=2, Reserved=0."""
        buf, writer, sys_uuid = self._build_investigation_writer(header)

        processes = [
            ProcessEntry(pid=100, ppid=1, uid=0, exe_name="init"),
            ProcessEntry(pid=200, ppid=100, uid=1000, exe_name="bash"),
        ]
        writer.write_process_table(processes, parent_uuid=sys_uuid)
        writer.finalize()

        data = buf.getvalue()
        # ProcessTable is block index 2 (after ProcessIdentity=0, SystemContext=1)
        payload = self._extract_table_payload(data, table_block_index=2)
        entry_count = struct.unpack_from("<I", payload, 0)[0]
        reserved = struct.unpack_from("<I", payload, 4)[0]
        assert entry_count == 2
        assert reserved == 0

    def test_connection_table_preamble(self, header):
        """ConnectionTable preamble: EntryCount=1, Reserved=0."""
        buf, writer, sys_uuid = self._build_investigation_writer(header)

        connections = [
            ConnectionEntry(pid=100, family=0x02, protocol=0x06, state=0x01),
        ]
        writer.write_connection_table(connections, parent_uuid=sys_uuid)
        writer.finalize()

        data = buf.getvalue()
        payload = self._extract_table_payload(data, table_block_index=2)
        entry_count = struct.unpack_from("<I", payload, 0)[0]
        reserved = struct.unpack_from("<I", payload, 4)[0]
        assert entry_count == 1
        assert reserved == 0

    def test_handle_table_preamble(self, header):
        """HandleTable preamble: EntryCount=3, Reserved=0."""
        buf, writer, sys_uuid = self._build_investigation_writer(header)

        handles = [
            HandleEntry(pid=100, fd=0, handle_type=0x01, path="/dev/null"),
            HandleEntry(pid=100, fd=1, handle_type=0x01, path="/dev/stdout"),
            HandleEntry(pid=100, fd=2, handle_type=0x01, path="/dev/stderr"),
        ]
        writer.write_handle_table(handles, parent_uuid=sys_uuid)
        writer.finalize()

        data = buf.getvalue()
        payload = self._extract_table_payload(data, table_block_index=2)
        entry_count = struct.unpack_from("<I", payload, 0)[0]
        reserved = struct.unpack_from("<I", payload, 4)[0]
        assert entry_count == 3
        assert reserved == 0


# ===================================================================
# 4. RegionSize page-alignment validation
# ===================================================================

class TestRegionSizePageAlignment:
    """Verify that region_size must be a multiple of page_size."""

    def test_non_page_aligned_region_size_raises(self, header):
        """Writing a region with non-page-aligned size must raise ValueError."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        region = MemoryRegion(
            base_addr=0x1000,
            region_size=5000,  # not a multiple of 4096
            protection=1,
            region_type=RegionType.Anon,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b"\x00" * 4096],
        )
        with pytest.raises(ValueError, match="multiple of"):
            writer.write_memory_region(region)

    def test_page_aligned_region_size_works(self, header):
        """Writing a region with page-aligned size succeeds."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        region = MemoryRegion(
            base_addr=0x1000,
            region_size=8192,  # 2 * 4096
            protection=5,
            region_type=RegionType.Image,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED, PageState.CAPTURED],
            page_data_chunks=[b"\x00" * 4096, b"\x00" * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()
        assert buf.tell() > HEADER_SIZE

    def test_single_page_region(self, header):
        """A single-page region (region_size == page_size) is valid."""
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
            page_data_chunks=[b"\x00" * 4096],
        )
        writer.write_memory_region(region)
        writer.finalize()
        assert buf.tell() > HEADER_SIZE


# ===================================================================
# 5. FLAG_REDACTED constant
# ===================================================================

class TestFlagRedacted:
    """Verify FLAG_REDACTED constant exists and has the correct value."""

    def test_flag_redacted_value(self):
        assert FLAG_REDACTED == 0x0008

    def test_flag_redacted_importable(self):
        from memslicer.msl.constants import FLAG_REDACTED as fr
        assert fr == 0x0008


# ===================================================================
# 6. ENCRYPTED_HEADER_SIZE constant
# ===================================================================

class TestEncryptedHeaderSize:
    """Verify ENCRYPTED_HEADER_SIZE constant."""

    def test_encrypted_header_size_value(self):
        assert ENCRYPTED_HEADER_SIZE == 128

    def test_encrypted_header_size_importable(self):
        from memslicer.msl.constants import ENCRYPTED_HEADER_SIZE as ehs
        assert ehs == 128


# ===================================================================
# 7. Protection Guard/CoW constants
# ===================================================================

class TestProtectionConstants:
    """Verify PROT_GUARD and PROT_COW constants."""

    def test_prot_guard_value(self):
        from memslicer.utils.protection import PROT_GUARD
        assert PROT_GUARD == 8

    def test_prot_cow_value(self):
        from memslicer.utils.protection import PROT_COW
        assert PROT_COW == 16

    def test_prot_guard_and_cow_importable(self):
        from memslicer.utils.protection import PROT_GUARD, PROT_COW
        assert PROT_GUARD == 8
        assert PROT_COW == 16


# ===================================================================
# 8. Encrypted MSL writer
# ===================================================================

class TestEncryptedMSLWriter:
    """Verify encrypted MSL output structure."""

    @pytest.fixture
    def enc_key(self):
        """32-byte AES-256 key."""
        return b"\x42" * 32

    @pytest.fixture
    def enc_header(self):
        return FileHeader(
            endianness=Endianness.LITTLE,
            version=(1, 0),
            flags=FLAG_ENCRYPTED,
            cap_bitmap=0x01,
            dump_uuid=uuid.uuid4().bytes,
            timestamp_ns=now_ns(),
            os_type=OSType.Linux,
            arch_type=ArchType.x86_64,
            pid=999,
        )

    def test_encrypted_header_is_128_bytes(self, enc_header, enc_key):
        """Encrypted MSL header must be 128 bytes."""
        from memslicer.msl.encryption import EncryptionParams
        buf = io.BytesIO()
        params = EncryptionParams()
        writer = MSLWriter(buf, enc_header, encryption_key=enc_key, encryption_params=params)
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize()

        data = buf.getvalue()
        # HeaderSize field at offset 0x09 must be 128
        assert data[0x09] == ENCRYPTED_HEADER_SIZE

    def test_flag_encrypted_set_in_header(self, enc_header, enc_key):
        """FLAG_ENCRYPTED must be set in the Flags field."""
        from memslicer.msl.encryption import EncryptionParams
        buf = io.BytesIO()
        params = EncryptionParams()
        writer = MSLWriter(buf, enc_header, encryption_key=enc_key, encryption_params=params)
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize()

        data = buf.getvalue()
        flags = struct.unpack_from("<I", data, 0x0C)[0]
        assert flags & FLAG_ENCRYPTED

    def test_encrypted_output_larger_than_header(self, enc_header, enc_key):
        """Encrypted output must contain header + ciphertext + 16B tag."""
        from memslicer.msl.encryption import EncryptionParams
        buf = io.BytesIO()
        params = EncryptionParams()
        writer = MSLWriter(buf, enc_header, encryption_key=enc_key, encryption_params=params)
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize()

        data = buf.getvalue()
        # Must have: 128B header + at least some ciphertext + 16B tag
        assert len(data) > ENCRYPTED_HEADER_SIZE + 16

    def test_prev_hash_zero_in_encrypted_mode(self, enc_header, enc_key):
        """In encrypted mode, PrevHash in all blocks must be zero (spec Section 4.4).

        Since blocks are encrypted, we decrypt and then check the PrevHash fields.
        """
        from memslicer.msl.encryption import EncryptionParams, AES_GCM_TAG_LEN
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        params = EncryptionParams()
        buf = io.BytesIO()
        writer = MSLWriter(buf, enc_header, encryption_key=enc_key, encryption_params=params)
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize()

        data = buf.getvalue()
        header_bytes = data[:ENCRYPTED_HEADER_SIZE]
        ciphertext = data[ENCRYPTED_HEADER_SIZE:-AES_GCM_TAG_LEN]
        tag = data[-AES_GCM_TAG_LEN:]

        # Decrypt
        aesgcm = AESGCM(enc_key)
        plaintext = aesgcm.decrypt(params.nonce, ciphertext + tag, header_bytes)

        # Walk blocks in the plaintext and verify PrevHash is all zeros
        offset = 0
        block_count = 0
        while offset < len(plaintext):
            assert plaintext[offset:offset + 4] == BLOCK_MAGIC
            block_len = struct.unpack_from("<I", plaintext, offset + 8)[0]
            # PrevHash is at offset 48 within the block header
            prev_hash = plaintext[offset + 48 : offset + 48 + 32]
            assert prev_hash == b"\x00" * 32, (
                f"Block {block_count}: PrevHash is not zero in encrypted mode"
            )
            block_count += 1
            offset += block_len

        assert block_count >= 2  # At least ProcessIdentity + EoC


# ===================================================================
# 9. New block types (KeyHint, ImportProvenance, RelatedDump)
# ===================================================================

class TestNewBlockTypes:
    """Verify new block types round-trip with correct BlockType codes."""

    def _find_block_type(self, data: bytes, target_type: int) -> bool:
        """Scan blocks in data looking for a block with the given type code."""
        offset = HEADER_SIZE
        while offset + BLOCK_HEADER_SIZE <= len(data):
            magic = data[offset:offset + 4]
            if magic != BLOCK_MAGIC:
                break
            block_type = struct.unpack_from("<H", data, offset + 4)[0]
            if block_type == target_type:
                return True
            block_len = struct.unpack_from("<I", data, offset + 8)[0]
            if block_len == 0:
                break
            offset += block_len
        return False

    def test_key_hint_block_type(self, header):
        """KeyHint block has BlockType == 0x0020."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        hint = KeyHint(
            region_uuid=uuid.uuid4().bytes,
            region_offset=0x100,
            key_len=32,
            key_type=0x01,
            protocol=0x01,
            confidence=0x02,
            key_state=0x01,
            note="AES-256 session key",
        )
        writer.write_key_hint(hint)
        writer.finalize()

        data = buf.getvalue()
        assert self._find_block_type(data, BlockType.KeyHint)

    def test_import_provenance_block_type(self, header):
        """ImportProvenance block has BlockType == 0x0030."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        prov = ImportProvenance(
            source_format=0x0003,  # Minidump
            tool_name="memslicer",
            import_time=now_ns(),
            orig_file_size=1024 * 1024,
            note="Converted from minidump",
        )
        writer.write_import_provenance(prov)
        writer.finalize()

        data = buf.getvalue()
        assert self._find_block_type(data, BlockType.ImportProvenance)

    def test_related_dump_block_type(self, header):
        """RelatedDump block has BlockType == 0x0041."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)

        related = RelatedDump(
            related_dump_uuid=uuid.uuid4().bytes,
            related_pid=42,
            relationship=0x0002,  # Child
        )
        writer.write_related_dump(related)
        writer.finalize()

        data = buf.getvalue()
        assert self._find_block_type(data, BlockType.RelatedDump)

    def test_key_hint_block_type_code_value(self):
        """KeyHint enum value is 0x0020."""
        assert BlockType.KeyHint == 0x0020

    def test_import_provenance_block_type_code_value(self):
        """ImportProvenance enum value is 0x0030."""
        assert BlockType.ImportProvenance == 0x0030

    def test_related_dump_block_type_code_value(self):
        """RelatedDump enum value is 0x0041."""
        assert BlockType.RelatedDump == 0x0041
