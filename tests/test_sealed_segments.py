"""MSL 1.1.1 sealed extension segments (spec Section 10.8, Table 27a).

Builds encrypted slices with the writer, appends sealed segments with
:func:`seal_segment` and checks the read path (:func:`iterate_blocks`,
:func:`decrypt_container`, :func:`verify_slice`) accepts exactly the
verified prefix and treats everything after it as trailing data.
"""
from __future__ import annotations

import io
import struct

import pytest

import memslicer.msl.writer as writer_module
from memslicer.cli_verify import _summary_line
from memslicer.msl.constants import (
    ENCRYPTED_HEADER_SIZE,
    FLAG_ENCRYPTED,
    SEAL_HEADER_SIZE,
    SEAL_MAGIC,
    BlockType,
    HashAlgo,
)
from memslicer.msl.encryption import (
    AES_GCM_TAG_LEN,
    CIPHER_LEN_OFFSET,
    EncryptionParams,
    derive_key,
)
from memslicer.msl.iterator import decrypt_container, iterate_blocks
from memslicer.msl.sealed import (
    SealHeader,
    open_sealed_segments,
    seal_segment,
    verify_segment_plaintext,
)
from memslicer.msl.types import FileHeader, KeyHint, MemoryRegion, ProcessIdentity
from memslicer.msl.verify import verify_slice
from memslicer.msl.writer import MSLWriter

_PASSPHRASE = "correct horse"
_FAST_KDF = dict(kdf_time=1, kdf_memory=8, kdf_lanes=1)
_GARBAGE = b"definitely not a sealed segment" * 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _NonSeekable(io.RawIOBase):
    """Write-only stream that, like a pipe, cannot seek (keeps CipherLen 0)."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b) -> int:
        self.data += bytes(b)
        return len(b)


def _write_capture(writer: MSLWriter, fill: int = 0x41) -> None:
    writer.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x"))
    writer.write_memory_region(MemoryRegion(
        base_addr=0x10000, region_size=4096, protection=3,
        page_states=[0], page_data_chunks=[bytes([fill]) * 4096],
    ))


def _encrypted_writer(output, header=None, params=None) -> MSLWriter:
    params = params or EncryptionParams(**_FAST_KDF)
    header = header or FileHeader(pid=4242, flags=FLAG_ENCRYPTED)
    return MSLWriter(
        output, header, encryption_key=derive_key(_PASSPHRASE, params),
        encryption_params=params,
    )


def _encrypted_slice(header=None, params=None, fill: int = 0x41) -> bytes:
    out = io.BytesIO()
    writer = _encrypted_writer(out, header, params)
    _write_capture(writer, fill)
    writer.finalize()
    return out.getvalue()


def _segment_plaintext(notes=("enriched",), producer="test-enrich/1.0") -> bytes:
    out = io.BytesIO()
    writer = MSLWriter.for_sealed_segment(out, FileHeader(hash_algo=HashAlgo.BLAKE3))
    writer.begin_extension()
    for note in notes:
        writer.write_key_hint(KeyHint(note=note))
    writer.finalize_extension(producer)
    return out.getvalue()


def _container(data: bytes):
    return decrypt_container(io.BytesIO(data), ENCRYPTED_HEADER_SIZE, _PASSPHRASE)


def _seal_all(data: bytes, plaintexts, first_index: int | None = None) -> list[bytes]:
    """Seal ``plaintexts`` as the next segments of ``data``; return each unit."""
    container = _container(data)
    prev_tag = container.last_tag
    index = first_index or len(container.sealed_segments) + 1
    units = []
    for plaintext in plaintexts:
        unit = seal_segment(
            container.cek, container.header, container.kem_ciphertext,
            prev_tag, index, plaintext,
        )
        units.append(unit)
        prev_tag, index = unit[-AES_GCM_TAG_LEN:], index + 1
    return units


def _with_sealed(data: bytes, count: int) -> tuple[bytes, list[bytes]]:
    plaintexts = [_segment_plaintext((f"seg{i}-a", f"seg{i}-b")) for i in range(1, count + 1)]
    units = _seal_all(data, plaintexts)
    return data + b"".join(units), units


def _sealed_records(data: bytes):
    return [r for r in iterate_blocks(io.BytesIO(data), _PASSPHRASE) if r.seal_index]


def _verify(data: bytes):
    return verify_slice(io.BytesIO(data), _PASSPHRASE)


# ---------------------------------------------------------------------------
# SealHeader
# ---------------------------------------------------------------------------
class TestSealHeader:
    def test_pack_layout(self):
        raw = SealHeader(seg_index=3, seg_cipher_len=0x1234, nonce=b"\x07" * 12).pack()
        assert len(raw) == SEAL_HEADER_SIZE == 64
        assert raw[:4] == SEAL_MAGIC == b"MSLS"
        assert struct.unpack_from("<HHQ", raw, 4) == (64, 3, 0x1234)
        assert raw[0x10:0x1C] == b"\x07" * 12
        assert raw[0x1C:] == b"\x00" * (64 - 0x1C)

    def test_unpack_roundtrip(self):
        header = SealHeader(seg_index=65535, seg_cipher_len=1, nonce=b"\x01" * 12)
        assert SealHeader.unpack(header.pack()) == header

    def test_unpack_wrong_size(self):
        with pytest.raises(ValueError, match="64 bytes"):
            SealHeader.unpack(b"\x00" * 63)


# ---------------------------------------------------------------------------
# Writing and reading back
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_one_segment_blocks_follow_the_capture(self):
        data, _units = _with_sealed(_encrypted_slice(), 1)
        records = list(iterate_blocks(io.BytesIO(data), _PASSPHRASE))
        types = [r.block_type for r in records]
        eoc = types.index(BlockType.EndOfCapture)
        assert types[eoc + 1:] == [BlockType.KeyHint, BlockType.KeyHint, BlockType.EndOfExtension]
        assert all(r.segment == 1 and r.seal_index == 1 for r in records[eoc + 1:])
        assert all(r.seal_index == 0 for r in records[:eoc + 1])
        assert b"seg1-a" in records[eoc + 1].payload

    def test_two_segments_in_order(self):
        data, _units = _with_sealed(_encrypted_slice(), 2)
        sealed = _sealed_records(data)
        assert [(r.segment, r.seal_index) for r in sealed] == [(1, 1)] * 3 + [(2, 2)] * 3
        assert b"seg2-a" in sealed[3].payload

    def test_sealed_numbering_continues_after_in_stream_segment(self):
        out = io.BytesIO()
        writer = _encrypted_writer(out)
        _write_capture(writer)
        writer.finalize(seal=False)
        writer.begin_extension()
        writer.write_key_hint(KeyHint(note="inside"))
        writer.finalize_extension("in-stream/1.0")
        writer.seal()
        data, _units = _with_sealed(out.getvalue(), 1)
        tail = [(r.segment, r.seal_index) for r in iterate_blocks(io.BytesIO(data), _PASSPHRASE)
                if r.segment]
        assert tail == [(1, 0), (1, 0), (2, 1), (2, 1), (2, 1)]

    def test_extensions_false_hides_sealed_blocks(self):
        data, _units = _with_sealed(_encrypted_slice(), 1)
        records = list(iterate_blocks(io.BytesIO(data), _PASSPHRASE, extensions=False))
        assert records[-1].block_type == BlockType.EndOfCapture

    def test_verify_counts_segments(self):
        data, units = _with_sealed(_encrypted_slice(), 2)
        report = _verify(data)
        assert report.valid, report.errors
        assert [s.index for s in report.sealed_segments] == [1, 2]
        assert all(s.verified and s.block_count == 3 for s in report.sealed_segments)
        assert report.sealed_segments[0].producer == "test-enrich/1.0"
        assert report.sealed_segments[1].start_offset == report.post_tag_offset + len(units[0])
        assert report.sealed_trailing_bytes == 0
        assert not report.warnings
        assert " sealed=2 " in _summary_line(report)

    def test_container_exposes_append_state(self):
        clean = _encrypted_slice()
        data, units = _with_sealed(clean, 2)
        container = _container(data)
        assert container.sealed_end == len(data)
        assert container.trailing_bytes == 0
        assert container.last_tag == units[1][-AES_GCM_TAG_LEN:]
        assert _container(clean).last_tag == clean[-AES_GCM_TAG_LEN:]

    def test_fresh_nonce_per_seal(self):
        data = _encrypted_slice()
        plaintext = _segment_plaintext()
        first, second = _seal_all(data, [plaintext]), _seal_all(data, [plaintext])
        assert first[0][0x10:0x1C] != second[0][0x10:0x1C]


# ---------------------------------------------------------------------------
# Failure points: everything from the first failing segment is trailing
# ---------------------------------------------------------------------------
class TestTrailing:
    def _assert_prefix(self, data: bytes, verified: int, trailing: int) -> None:
        report = _verify(data)
        assert report.valid, report.errors
        assert len(report.sealed_segments) == verified
        assert report.sealed_trailing_bytes == trailing
        assert len({r.seal_index for r in _sealed_records(data)}) == verified
        if trailing:
            assert any("after the primary AEAD tag" in w for w in report.warnings)

    def test_reordered_segments(self):
        clean = _encrypted_slice()
        _data, (one, two) = _with_sealed(clean, 2)
        self._assert_prefix(clean + two + one, verified=0, trailing=len(one) + len(two))

    def test_flipped_ciphertext_in_second_segment(self):
        clean = _encrypted_slice()
        data, (one, two) = _with_sealed(clean, 2)
        tampered = bytearray(data)
        tampered[len(clean) + len(one) + SEAL_HEADER_SIZE + 5] ^= 0x01
        self._assert_prefix(bytes(tampered), verified=1, trailing=len(two))

    def test_truncated_mid_segment(self):
        data, (_one, two) = _with_sealed(_encrypted_slice(), 2)
        self._assert_prefix(data[:-10], verified=1, trailing=len(two) - 10)

    def test_garbage_after_last_segment(self):
        data, _units = _with_sealed(_encrypted_slice(), 2)
        self._assert_prefix(data + _GARBAGE, verified=2, trailing=len(_GARBAGE))

    def test_wrong_seg_index(self):
        clean = _encrypted_slice()
        (unit,) = _seal_all(clean, [_segment_plaintext()], first_index=2)
        self._assert_prefix(clean + unit, verified=0, trailing=len(unit))

    def test_tampered_reserved_byte_fails_tag(self):
        clean = _encrypted_slice()
        (unit,) = _seal_all(clean, [_segment_plaintext()])
        tampered = bytearray(unit)
        tampered[0x30] = 0xFF  # SealHeader Reserved
        self._assert_prefix(clean + bytes(tampered), verified=0, trailing=len(unit))

    def test_bad_magic(self):
        clean = _encrypted_slice()
        (unit,) = _seal_all(clean, [_segment_plaintext()])
        self._assert_prefix(clean + b"MSLC" + unit[4:], verified=0, trailing=len(unit))

    def test_oversized_seg_cipher_len(self):
        clean = _encrypted_slice()
        (unit,) = _seal_all(clean, [_segment_plaintext()])
        bad = unit[:8] + struct.pack("<Q", len(unit)) + unit[16:]
        self._assert_prefix(clean + bad, verified=0, trailing=len(unit))

    def test_segment_grafted_from_another_file(self):
        params = EncryptionParams(**_FAST_KDF)
        header = FileHeader(pid=4242, flags=FLAG_ENCRYPTED)
        target = _encrypted_slice(header, params, fill=0x41)
        donor = _encrypted_slice(header, params, fill=0x42)  # same CEK, UUID, header
        assert target[:ENCRYPTED_HEADER_SIZE] == donor[:ENCRYPTED_HEADER_SIZE]
        (unit,) = _seal_all(donor, [_segment_plaintext()])
        assert len(_container(donor + unit).sealed_segments) == 1
        self._assert_prefix(target + unit, verified=0, trailing=len(unit))

    def test_segment_from_other_passphrase_file(self):
        target = _encrypted_slice()
        (unit,) = _seal_all(_encrypted_slice(), [_segment_plaintext()])
        self._assert_prefix(target + unit, verified=0, trailing=len(unit))


# ---------------------------------------------------------------------------
# Plaintext must be exactly one valid extension segment
# ---------------------------------------------------------------------------
class TestPlaintextSegment:
    def _sealed_with(self, plaintext: bytes) -> bytes:
        clean = _encrypted_slice()
        return clean + _seal_all(clean, [plaintext])[0]

    def test_valid_plaintext(self):
        report = verify_segment_plaintext(_segment_plaintext(), HashAlgo.BLAKE3, 1)
        assert report is not None and report.block_count == 2

    def test_bytes_after_end_of_extension(self):
        data = self._sealed_with(_segment_plaintext() + b"\x00" * 8)
        assert _container(data).sealed_segments == []

    def test_two_segments_in_one_plaintext(self):
        data = self._sealed_with(_segment_plaintext() + _segment_plaintext())
        assert _container(data).sealed_segments == []

    def test_unterminated_plaintext(self):
        plaintext = _segment_plaintext()
        last_block = struct.unpack_from("<I", plaintext, 8)[0]  # KeyHint length
        data = self._sealed_with(plaintext[:last_block])
        assert _container(data).sealed_segments == []

    def test_non_zero_prev_hash(self):
        out = io.BytesIO()
        chain = writer_module.IntegrityChain(HashAlgo.BLAKE3)
        chain.feed_header(b"chained")
        writer = MSLWriter.extend(out, FileHeader(), chain, block_index=3)
        writer.begin_extension()
        writer.write_key_hint(KeyHint(note="chained"))
        writer.finalize_extension("chained/1.0")
        assert verify_segment_plaintext(out.getvalue(), HashAlgo.BLAKE3, 1) is None
        assert _container(self._sealed_with(out.getvalue())).sealed_segments == []

    def test_forbidden_block_type(self, monkeypatch):
        monkeypatch.setattr(writer_module, "EXTENSION_FORBIDDEN_TYPES", frozenset())
        out = io.BytesIO()
        writer = MSLWriter.for_sealed_segment(out, FileHeader())
        writer.begin_extension()
        writer.write_memory_region(MemoryRegion(base_addr=0x1000, region_size=4096,
                                                page_states=[0], page_data_chunks=[b"\x00" * 4096]))
        writer.finalize_extension("evil/1.0")
        assert verify_segment_plaintext(out.getvalue(), HashAlgo.BLAKE3, 1) is None
        assert _container(self._sealed_with(out.getvalue())).sealed_segments == []


# ---------------------------------------------------------------------------
# CipherLen = 0: no sealed segments
# ---------------------------------------------------------------------------
class TestCipherLenZero:
    def _legacy_slice(self) -> bytes:
        out = _NonSeekable()
        writer = _encrypted_writer(out)
        _write_capture(writer)
        writer.finalize()
        data = bytes(out.data)
        assert struct.unpack_from("<Q", data, CIPHER_LEN_OFFSET)[0] == 0
        return data

    def test_seal_segment_refuses(self):
        data = self._legacy_slice()
        container = _container(data)
        with pytest.raises(ValueError, match="CipherLen"):
            seal_segment(container.cek, container.header, b"", container.tag, 1,
                         _segment_plaintext())

    def test_appended_bytes_break_the_primary_tag(self):
        data = self._legacy_slice()
        assert _container(data).sealed_segments == []
        # The tag is taken from EOF-16, so anything appended changes it.
        with pytest.raises(ValueError, match="could not decrypt"):
            _container(data + _GARBAGE)
        assert not _verify(data + _GARBAGE).valid

    def test_open_sealed_segments_parses_nothing(self):
        data = self._legacy_slice()
        container = _container(data)
        sealed_header = bytearray(container.header)
        struct.pack_into("<Q", sealed_header, CIPHER_LEN_OFFSET, 1)
        (unit,) = [seal_segment(container.cek, bytes(sealed_header), b"", container.tag,
                                1, _segment_plaintext())]
        segments, trailing = open_sealed_segments(
            container.cek, container.header, b"", container.tag, data + unit, len(data),
        )
        assert segments == [] and trailing == len(data)
