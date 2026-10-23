"""Tests for extension segments (spec Section 4.6) in MSLWriter.

Covers the segment state machine (begin/finalize/seal guards), the
EndOfExtension byte layout, the per-segment hash, chain continuity across
the EndOfCapture, ``MSLWriter.extend`` on a finished file, encrypted
containers and the 48-byte EndOfCapture payload.
"""
from __future__ import annotations

import io
import struct
import uuid

import blake3
import pytest

from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE, BLOCK_MAGIC, ENCRYPTED_HEADER_SIZE, FLAG_ENCRYPTED,
    HASH_SIZE, HEADER_SIZE, EXTENSION_FORBIDDEN_TYPES,
    BlockType, PageState, RegionType,
)
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.types import (
    FileHeader, KeyHint, MemoryRegion, ModuleBuildIdManifest,
    ModuleBuildIdRow, ProcessIdentity,
)
from memslicer.msl.writer import (
    MSLWriter, _EOX_HEAD, parse_end_of_capture, parse_end_of_extension,
)
from memslicer.utils.timestamps import now_ns

PRODUCER = "memslicer-test/1"
WRITTEN_AT = 777

_BLOCK_HEAD = struct.Struct("<4sHHIHH16s16s32s")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _header() -> FileHeader:
    return FileHeader(dump_uuid=uuid.uuid4().bytes, timestamp_ns=now_ns(), pid=1)


def _manifest() -> ModuleBuildIdManifest:
    row = ModuleBuildIdRow(
        base_addr=0x7F0000001000, build_id_len=20, build_id_source=3,
        build_id=b"\x11" * 20, disk_hash=b"\x22" * 32,
    )
    return ModuleBuildIdManifest(rows=[row])


def _region() -> MemoryRegion:
    return MemoryRegion(
        base_addr=0x10000, region_size=4096, protection=3,
        region_type=RegionType.Anon, page_size=4096,
        timestamp_ns=now_ns(), page_states=[PageState.CAPTURED],
        page_data_chunks=[b"\xAB" * 4096],
    )


def _finished_writer() -> tuple[io.BytesIO, MSLWriter]:
    """Header + ProcessIdentity + EoC; the writer is still usable."""
    buf = io.BytesIO()
    writer = MSLWriter(buf, _header())
    writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
    writer.finalize()
    return buf, writer


def _walk(data: bytes, start: int) -> list[tuple[int, int, bytes]]:
    """Return ``(offset, block_type, block_bytes)`` for every block from *start*."""
    blocks = []
    offset = start
    while offset < len(data):
        magic, btype, _flags, length = struct.unpack_from("<4sHHI", data, offset)
        assert magic == BLOCK_MAGIC
        blocks.append((offset, btype, data[offset:offset + length]))
        offset += length
    assert offset == len(data)
    return blocks


def _prev_hash(block: bytes) -> bytes:
    return _BLOCK_HEAD.unpack_from(block, 0)[8]


def _payload(block: bytes) -> bytes:
    return block[BLOCK_HEADER_SIZE:]


def _write_one_segment(buf: io.BytesIO, writer: MSLWriter) -> tuple[int, int]:
    """Write one manifest segment; return ``(segment_start, terminator_start)``."""
    writer.begin_extension()
    seg_start = buf.tell()
    writer.write_module_build_id_manifest(_manifest())
    term_start = buf.tell()
    writer.finalize_extension(PRODUCER, written_at_ns=WRITTEN_AT)
    return seg_start, term_start


# ---------------------------------------------------------------------------
# State machine guards
# ---------------------------------------------------------------------------

class TestSegmentGuards:
    """finalize/begin_extension/finalize_extension refuse misuse."""

    def test_second_finalize_raises(self):
        _, writer = _finished_writer()
        with pytest.raises(ValueError, match="already written"):
            writer.finalize()

    def test_begin_extension_before_finalize_raises(self):
        writer = MSLWriter(io.BytesIO(), _header())
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        with pytest.raises(ValueError, match="EndOfCapture"):
            writer.begin_extension()

    def test_nested_begin_extension_raises(self):
        _, writer = _finished_writer()
        writer.begin_extension()
        with pytest.raises(ValueError, match="already open"):
            writer.begin_extension()

    def test_finalize_extension_without_segment_raises(self):
        _, writer = _finished_writer()
        with pytest.raises(ValueError, match="no extension segment"):
            writer.finalize_extension(PRODUCER)

    def test_finalize_extension_on_empty_segment_raises(self):
        _, writer = _finished_writer()
        writer.begin_extension()
        with pytest.raises(ValueError, match="no blocks"):
            writer.finalize_extension(PRODUCER)

    def test_block_after_eoc_outside_segment_raises(self):
        _, writer = _finished_writer()
        with pytest.raises(ValueError, match="begin_extension"):
            writer.write_key_hint(KeyHint())

    def test_block_after_closed_segment_raises(self):
        buf, writer = _finished_writer()
        _write_one_segment(buf, writer)
        with pytest.raises(ValueError, match="begin_extension"):
            writer.write_key_hint(KeyHint())


class TestExtensionForbiddenTypes:
    """Evidence block types never appear inside an extension segment."""

    def test_forbidden_set_is_exact(self):
        expected = (
            {0x0001, 0x0002, 0x0030, 0x0040, 0x0FFF}
            | set(range(0x0010, 0x0016))
            | set(range(0x0050, 0x0059))
        )
        assert set(EXTENSION_FORBIDDEN_TYPES) == expected

    def test_allowed_overlay_types_are_not_forbidden(self):
        assert BlockType.KeyHint not in EXTENSION_FORBIDDEN_TYPES
        assert BlockType.ModuleBuildIdManifest not in EXTENSION_FORBIDDEN_TYPES
        assert BlockType.EndOfExtension not in EXTENSION_FORBIDDEN_TYPES

    def test_process_identity_inside_segment_raises(self):
        _, writer = _finished_writer()
        writer.begin_extension()
        # The Block-0 position warning fires before the segment rule refuses.
        with pytest.warns(UserWarning), pytest.raises(ValueError, match="0x0040"):
            writer.write_process_identity(ProcessIdentity(exe_path="/x"))

    def test_memory_region_inside_segment_raises(self):
        _, writer = _finished_writer()
        writer.begin_extension()
        with pytest.raises(ValueError, match="0x0001"):
            writer.write_memory_region(_region())

    def test_forbidden_block_does_not_count_toward_segment(self):
        """A refused block leaves the segment empty, so finalize still refuses."""
        _, writer = _finished_writer()
        writer.begin_extension()
        with pytest.raises(ValueError):
            writer.write_memory_region(_region())
        with pytest.raises(ValueError, match="no blocks"):
            writer.finalize_extension(PRODUCER)


# ---------------------------------------------------------------------------
# Segment hash, terminator layout, chain continuity
# ---------------------------------------------------------------------------

class TestSegmentHash:
    """SegmentHash covers [first segment block, terminator)."""

    def test_segment_hash_matches_independent_blake3(self):
        buf, writer = _finished_writer()
        seg_start, term_start = _write_one_segment(buf, writer)
        data = buf.getvalue()

        expected = blake3.blake3(data[seg_start:term_start]).digest()
        terminator = data[term_start:]
        assert struct.unpack_from("<H", terminator, 4)[0] == BlockType.EndOfExtension
        assert _payload(terminator)[:HASH_SIZE] == expected

    def test_segment_hash_covers_all_segment_blocks(self):
        buf, writer = _finished_writer()
        writer.begin_extension()
        seg_start = buf.tell()
        writer.write_module_build_id_manifest(_manifest())
        writer.write_key_hint(KeyHint(key_len=32, note="n"))
        term_start = buf.tell()
        writer.finalize_extension(PRODUCER)
        data = buf.getvalue()

        expected = blake3.blake3(data[seg_start:term_start]).digest()
        assert _payload(data[term_start:])[:HASH_SIZE] == expected


class TestEndOfExtensionLayout:
    """EndOfExtension payload bytes at the documented offsets."""

    def test_layout_offsets(self):
        buf, writer = _finished_writer()
        _seg_start, term_start = _write_one_segment(buf, writer)
        data = buf.getvalue()
        terminator = data[term_start:]
        payload = _payload(terminator)

        segment_hash = payload[0x00:0x20]
        written_at = struct.unpack_from("<Q", payload, 0x20)[0]
        block_count = struct.unpack_from("<I", payload, 0x28)[0]
        reserved = struct.unpack_from("<I", payload, 0x2C)[0]
        producer_len = struct.unpack_from("<H", payload, 0x30)[0]
        reserved2 = payload[0x32:0x38]

        assert len(segment_hash) == HASH_SIZE and segment_hash != b"\x00" * HASH_SIZE
        assert written_at == WRITTEN_AT
        assert block_count == 1 + 1  # one manifest block + terminator
        assert reserved == 0
        assert producer_len == len(PRODUCER) + 1
        assert reserved2 == b"\x00" * 6
        assert _EOX_HEAD.size == 0x38

        raw = PRODUCER.encode("utf-8") + b"\x00"
        assert payload[0x38:0x38 + producer_len] == raw
        assert payload[0x38 + producer_len:] == b"\x00" * (len(payload) - 0x38 - producer_len)
        assert len(payload) % 8 == 0
        assert len(payload) == 0x38 + 24  # 17 bytes padded to 24
        assert struct.unpack_from("<I", terminator, 8)[0] == BLOCK_HEADER_SIZE + len(payload)

    def test_block_count_counts_every_segment_block(self):
        buf, writer = _finished_writer()
        writer.begin_extension()
        writer.write_module_build_id_manifest(_manifest())
        writer.write_key_hint(KeyHint())
        writer.write_key_hint(KeyHint())
        term_start = buf.tell()
        writer.finalize_extension(PRODUCER)
        payload = _payload(buf.getvalue()[term_start:])
        assert struct.unpack_from("<I", payload, 0x28)[0] == 4

    def test_empty_producer(self):
        buf, writer = _finished_writer()
        writer.begin_extension()
        writer.write_key_hint(KeyHint())
        term_start = buf.tell()
        writer.finalize_extension("", written_at_ns=WRITTEN_AT)
        payload = _payload(buf.getvalue()[term_start:])

        assert len(payload) == 56
        assert struct.unpack_from("<H", payload, 0x30)[0] == 0
        parsed = parse_end_of_extension(payload)
        assert parsed.producer == ""

    def test_parse_end_of_extension_inverse(self):
        buf, writer = _finished_writer()
        seg_start, term_start = _write_one_segment(buf, writer)
        data = buf.getvalue()
        parsed = parse_end_of_extension(_payload(data[term_start:]))

        assert parsed.segment_hash == blake3.blake3(data[seg_start:term_start]).digest()
        assert parsed.written_at_ns == WRITTEN_AT
        assert parsed.block_count == 2
        assert parsed.producer == PRODUCER

    def test_parse_truncated_head_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            parse_end_of_extension(b"\x00" * (_EOX_HEAD.size - 1))

    def test_parse_truncated_producer_raises(self):
        head = _EOX_HEAD.pack(b"\x00" * HASH_SIZE, 1, 2, 0, 5)
        with pytest.raises(ValueError, match="producer truncated"):
            parse_end_of_extension(head + b"ab")

    def test_written_at_defaults_to_now(self):
        buf, writer = _finished_writer()
        writer.begin_extension()
        writer.write_key_hint(KeyHint())
        before = now_ns()
        term_start = buf.tell()
        writer.finalize_extension(PRODUCER)
        after = now_ns()
        parsed = parse_end_of_extension(_payload(buf.getvalue()[term_start:]))
        assert before <= parsed.written_at_ns <= after


class TestChainContinuity:
    """PrevHash stays linear across the EndOfCapture."""

    def test_first_extension_block_prev_hash_is_eoc_hash(self):
        buf, writer = _finished_writer()
        _write_one_segment(buf, writer)
        blocks = _walk(buf.getvalue(), HEADER_SIZE)
        types = [b[1] for b in blocks]
        assert types == [
            BlockType.ProcessIdentity, BlockType.EndOfCapture,
            BlockType.ModuleBuildIdManifest, BlockType.EndOfExtension,
        ]
        eoc = blocks[1][2]
        assert _prev_hash(blocks[2][2]) == blake3.blake3(eoc).digest()

    def test_terminator_prev_hash_is_hash_of_preceding_block(self):
        buf, writer = _finished_writer()
        _write_one_segment(buf, writer)
        blocks = _walk(buf.getvalue(), HEADER_SIZE)
        manifest_block = blocks[2][2]
        assert _prev_hash(blocks[3][2]) == blake3.blake3(manifest_block).digest()

    def test_eoc_prev_hash_unchanged_by_extension(self):
        """Writing a segment never rewrites the capture segment."""
        buf, writer = _finished_writer()
        capture = buf.getvalue()
        _write_one_segment(buf, writer)
        assert buf.getvalue()[:len(capture)] == capture


# ---------------------------------------------------------------------------
# Two segments on one writer
# ---------------------------------------------------------------------------

class TestConsecutiveSegments:
    """Each segment has its own hash; the chain links them."""

    def test_two_segments(self):
        buf, writer = _finished_writer()
        s1_start, t1_start = _write_one_segment(buf, writer)
        writer.begin_extension()
        s2_start = buf.tell()
        writer.write_key_hint(KeyHint(key_len=16))
        t2_start = buf.tell()
        writer.finalize_extension("second")
        data = buf.getvalue()

        blocks = _walk(data, HEADER_SIZE)
        assert [b[1] for b in blocks] == [
            BlockType.ProcessIdentity, BlockType.EndOfCapture,
            BlockType.ModuleBuildIdManifest, BlockType.EndOfExtension,
            BlockType.KeyHint, BlockType.EndOfExtension,
        ]
        term1 = parse_end_of_extension(_payload(blocks[3][2]))
        term2 = parse_end_of_extension(_payload(blocks[5][2]))
        assert term1.segment_hash == blake3.blake3(data[s1_start:t1_start]).digest()
        assert term2.segment_hash == blake3.blake3(data[s2_start:t2_start]).digest()
        assert term1.segment_hash != term2.segment_hash
        assert term1.producer == PRODUCER and term2.producer == "second"
        assert term1.block_count == 2 and term2.block_count == 2

        # Second segment's first block chains off the first terminator.
        assert _prev_hash(blocks[4][2]) == blake3.blake3(blocks[3][2]).digest()
        assert _prev_hash(blocks[5][2]) == blake3.blake3(blocks[4][2]).digest()


# ---------------------------------------------------------------------------
# MSLWriter.extend on a finished file
# ---------------------------------------------------------------------------

def _seed_chain(data: bytes) -> tuple[IntegrityChain, int, list[tuple[int, int, bytes]]]:
    """Feed header + every block of a finished file into a fresh chain."""
    chain = IntegrityChain()
    chain.feed_header(data[:HEADER_SIZE])
    blocks = _walk(data, HEADER_SIZE)
    for _offset, _btype, block in blocks:
        chain.feed_block(block)
    return chain, len(blocks), blocks


class TestWriterExtend:
    """Appending a segment to a file written by someone else."""

    def _extend(self):
        buf, _writer = _finished_writer()
        original = buf.getvalue()
        chain, count, blocks = _seed_chain(original)
        assert blocks[-1][1] == BlockType.EndOfCapture

        out = io.BytesIO()
        out.write(original)
        writer = MSLWriter.extend(out, _header(), chain, count)
        seg_start, term_start = _write_one_segment(out, writer)
        return original, out.getvalue(), seg_start, term_start, blocks

    def test_original_bytes_untouched(self):
        original, data, seg_start, _term_start, _blocks = self._extend()
        assert data[:len(original)] == original
        assert seg_start == len(original)

    def test_chain_continues_across_eoc(self):
        original, data, _seg_start, _term_start, blocks = self._extend()
        eoc = blocks[-1][2]
        appended = _walk(data, len(original))
        assert [b[1] for b in appended] == [
            BlockType.ModuleBuildIdManifest, BlockType.EndOfExtension,
        ]
        assert _prev_hash(appended[0][2]) == blake3.blake3(eoc).digest()
        assert _prev_hash(appended[1][2]) == blake3.blake3(appended[0][2]).digest()

    def test_segment_hash(self):
        _original, data, seg_start, term_start, _blocks = self._extend()
        parsed = parse_end_of_extension(_payload(data[term_start:]))
        assert parsed.segment_hash == blake3.blake3(data[seg_start:term_start]).digest()
        assert parsed.block_count == 2
        assert parsed.producer == PRODUCER
        assert parsed.written_at_ns == WRITTEN_AT

    def test_finalize_on_extend_writer_raises(self):
        buf, _writer = _finished_writer()
        chain, count, _blocks = _seed_chain(buf.getvalue())
        writer = MSLWriter.extend(buf, _header(), chain, count)
        with pytest.raises(ValueError, match="already written"):
            writer.finalize()

    def test_block_outside_segment_on_extend_writer_raises(self):
        buf, _writer = _finished_writer()
        chain, count, _blocks = _seed_chain(buf.getvalue())
        writer = MSLWriter.extend(buf, _header(), chain, count)
        with pytest.raises(ValueError, match="begin_extension"):
            writer.write_key_hint(KeyHint())

    def test_extend_after_existing_segment(self):
        """A second extender chains off the previous terminator."""
        buf, writer = _finished_writer()
        _write_one_segment(buf, writer)
        original = buf.getvalue()
        chain, count, blocks = _seed_chain(original)
        assert blocks[-1][1] == BlockType.EndOfExtension

        out = io.BytesIO()
        out.write(original)
        extender = MSLWriter.extend(out, _header(), chain, count)
        extender.begin_extension()
        extender.write_key_hint(KeyHint())
        extender.finalize_extension("again")
        appended = _walk(out.getvalue(), len(original))
        assert _prev_hash(appended[0][2]) == blake3.blake3(blocks[-1][2]).digest()


# ---------------------------------------------------------------------------
# Encrypted containers
# ---------------------------------------------------------------------------

class TestEncryptedExtension:
    """Segments inside an AEAD container written before seal()."""

    KEY = b"\x42" * 32

    def _enc_writer(self):
        from memslicer.msl.encryption import EncryptionParams

        header = FileHeader(
            flags=FLAG_ENCRYPTED, dump_uuid=uuid.uuid4().bytes,
            timestamp_ns=now_ns(), pid=999,
        )
        params = EncryptionParams()
        buf = io.BytesIO()
        writer = MSLWriter(
            buf, header, encryption_key=self.KEY, encryption_params=params,
        )
        return buf, writer, params

    def _decrypt(self, data: bytes, params) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from memslicer.msl.encryption import AES_GCM_TAG_LEN

        header_bytes = data[:ENCRYPTED_HEADER_SIZE]
        body = data[ENCRYPTED_HEADER_SIZE:]
        assert len(body) > AES_GCM_TAG_LEN
        return AESGCM(self.KEY).decrypt(params.nonce, body, header_bytes)

    def test_segment_inside_container(self):
        buf, writer, params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize(seal=False)
        assert len(buf.getvalue()) == ENCRYPTED_HEADER_SIZE  # nothing flushed yet
        writer.begin_extension()
        writer.write_key_hint(KeyHint(key_len=32))
        writer.finalize_extension("enc", written_at_ns=WRITTEN_AT)
        writer.seal()

        plaintext = self._decrypt(buf.getvalue(), params)
        blocks = _walk(plaintext, 0)
        assert [b[1] for b in blocks] == [
            BlockType.ProcessIdentity, BlockType.EndOfCapture,
            BlockType.KeyHint, BlockType.EndOfExtension,
        ]
        for _offset, _btype, block in blocks:
            assert _prev_hash(block) == b"\x00" * HASH_SIZE

        term = parse_end_of_extension(_payload(blocks[3][2]))
        assert term.producer == "enc"
        assert term.block_count == 2
        assert term.written_at_ns == WRITTEN_AT
        # The chain is fed plaintext, so the segment hash covers the
        # plaintext KeyHint block.
        assert term.segment_hash == blake3.blake3(blocks[2][2]).digest()

    def test_seal_twice_raises(self):
        buf, writer, _params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.finalize(seal=False)
        writer.seal()
        with pytest.raises(ValueError, match="already sealed"):
            writer.seal()

    def test_default_finalize_seals_so_seal_raises(self):
        _buf, writer, _params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.finalize()
        with pytest.raises(ValueError, match="already sealed"):
            writer.seal()

    def test_seal_on_unencrypted_writer_raises(self):
        _buf, writer = _finished_writer()
        with pytest.raises(ValueError, match="encrypted writers only"):
            writer.seal()

    def test_seal_before_finalize_raises(self):
        _buf, writer, _params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        with pytest.raises(ValueError, match="finalize"):
            writer.seal()

    def test_seal_with_open_segment_raises(self):
        _buf, writer, _params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.finalize(seal=False)
        writer.begin_extension()
        writer.write_key_hint(KeyHint())
        with pytest.raises(ValueError, match="still open"):
            writer.seal()

    def test_begin_extension_after_seal_raises(self):
        _buf, writer, _params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.finalize()
        with pytest.raises(ValueError, match="already sealed"):
            writer.begin_extension()

    def test_default_finalize_layout_unchanged(self):
        """finalize() alone still yields header + ciphertext + 16-byte tag."""
        from memslicer.msl.encryption import AES_GCM_TAG_LEN

        buf, writer, params = self._enc_writer()
        writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/sh"))
        writer.finalize()
        data = buf.getvalue()

        plaintext = self._decrypt(data, params)
        blocks = _walk(plaintext, 0)
        assert [b[1] for b in blocks] == [
            BlockType.ProcessIdentity, BlockType.EndOfCapture,
        ]
        assert len(data) == ENCRYPTED_HEADER_SIZE + len(plaintext) + AES_GCM_TAG_LEN


# ---------------------------------------------------------------------------
# EndOfCapture payload
# ---------------------------------------------------------------------------

class TestParseEndOfCapture:
    """48-byte EoC payload with BlockCount at +0x28."""

    def test_real_file_block_count(self):
        buf = io.BytesIO()
        writer = MSLWriter(buf, _header())
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.write_memory_region(_region())
        writer.write_key_hint(KeyHint())
        writer.finalize()
        blocks = _walk(buf.getvalue(), HEADER_SIZE)

        eoc = blocks[-1]
        assert eoc[1] == BlockType.EndOfCapture
        payload = _payload(eoc[2])
        assert len(payload) == 48
        parsed = parse_end_of_capture(payload)
        assert parsed.block_count == len(blocks) == 4
        assert parsed.file_hash == payload[:HASH_SIZE]
        assert parsed.acq_end_ns == struct.unpack_from("<Q", payload, 0x20)[0]
        assert struct.unpack_from("<I", payload, 0x2C)[0] == 0

    def test_legacy_40_byte_payload(self):
        payload = b"\x5a" * HASH_SIZE + struct.pack("<Q", 123456)
        parsed = parse_end_of_capture(payload)
        assert parsed.file_hash == b"\x5a" * HASH_SIZE
        assert parsed.acq_end_ns == 123456
        assert parsed.block_count == 0

    def test_short_payload_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            parse_end_of_capture(b"\x00" * 39)
