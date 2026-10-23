"""Tests for the standalone chain / FileHash verifier and ``memslicer verify``."""
from __future__ import annotations

import io
import struct

import pytest
from click.testing import CliRunner

import memslicer.msl.writer as writer_module
from memslicer.cli import cli
from memslicer.msl.compression import compress
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE, FLAG_ENCRYPTED, BlockType, CompAlgo, HashAlgo, PageState,
)
from memslicer.msl.encryption import EncryptionParams, derive_key
from memslicer.msl.integrity import make_hasher
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleBuildIdManifest, ModuleBuildIdRow, ProcessIdentity,
)
from memslicer.msl.verify import verify_slice
from memslicer.msl.writer import MSLWriter

_PASSPHRASE = "correct horse"
# Cheap Argon2 settings keep the encrypted tests fast.
_FAST_KDF = dict(kdf_time=1, kdf_memory=8, kdf_lanes=1)
_EOC_BLOCK_COUNT_OFFSET = BLOCK_HEADER_SIZE + 0x28
"""Offset of BlockCount inside an EoC block (spec Table 12)."""


def _write_blocks(w: MSLWriter, *, seal: bool = True) -> None:
    w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
    w.write_memory_region(MemoryRegion(
        base_addr=0x10000, region_size=8192, protection=3,
        page_states=[PageState.CAPTURED, PageState.CAPTURED],
        page_data_chunks=[b"\x41" * 4096, bytes(range(256)) * 16],
    ))
    w.finalize(seal=seal)


def _write_segment(w: MSLWriter, producer: str) -> None:
    """Append one two-block extension segment (manifest + terminator)."""
    w.begin_extension()
    w.write_module_build_id_manifest(ModuleBuildIdManifest(rows=[ModuleBuildIdRow(
        base_addr=0x10000, build_id_len=4, build_id_source=1, flags=0,
        build_id=b"abcd", disk_hash=b"\x00" * 32,
    )]))
    w.finalize_extension(producer)


def _slice(comp_algo=CompAlgo.NONE, hash_algo=HashAlgo.BLAKE3) -> bytes:
    buf = io.BytesIO()
    _write_blocks(MSLWriter(buf, FileHeader(pid=4242, hash_algo=hash_algo), comp_algo=comp_algo))
    return buf.getvalue()


def _slice_with_segments(
    n: int = 1, comp_algo=CompAlgo.NONE, hash_algo=HashAlgo.BLAKE3,
) -> bytes:
    """A valid slice followed by *n* extension segments, producers ``test/k``."""
    buf = io.BytesIO()
    w = MSLWriter(buf, FileHeader(pid=4242, hash_algo=hash_algo), comp_algo=comp_algo)
    _write_blocks(w)
    for k in range(1, n + 1):
        _write_segment(w, f"test/{k}")
    return buf.getvalue()


def _encrypted_writer(buf: io.BytesIO) -> MSLWriter:
    params = EncryptionParams(**_FAST_KDF)
    return MSLWriter(
        buf, FileHeader(pid=4242, flags=FLAG_ENCRYPTED),
        encryption_key=derive_key(_PASSPHRASE, params), encryption_params=params,
    )


def _encrypted_slice() -> bytes:
    buf = io.BytesIO()
    _write_blocks(_encrypted_writer(buf))
    return buf.getvalue()


def _encrypted_slice_with_segment() -> bytes:
    """An encrypted slice whose one extension segment lies inside the AEAD."""
    buf = io.BytesIO()
    w = _encrypted_writer(buf)
    _write_blocks(w, seal=False)
    _write_segment(w, "enc/1")
    w.seal()
    return buf.getvalue()


def _block_offsets(raw: bytes) -> list[tuple[int, int, int]]:
    """Return ``(offset, block_type, length)`` for each plaintext block."""
    offset, blocks = raw[9], []
    while offset + BLOCK_HEADER_SIZE <= len(raw):
        block_type, length = struct.unpack_from("<HxxI", raw, offset + 4)
        blocks.append((offset, block_type, length))
        offset += length
    return blocks


def _rechain(raw: bytearray, include_block0: bool = False) -> None:
    """Recompute PrevHash and the EoC FileHash in place (NONE compression only).

    Block 0's PrevHash is only rewritten when *include_block0* is set.
    """
    algo = HashAlgo(raw[0x3D])
    blocks = _block_offsets(bytes(raw))
    if include_block0:
        h = make_hasher(algo)
        h.update(bytes(raw[:raw[9]]))
        raw[raw[9] + 0x30:raw[9] + 0x50] = h.digest()
    for (prev_off, _, prev_len), (off, block_type, _) in zip(blocks, blocks[1:]):
        h = make_hasher(algo)
        h.update(bytes(raw[prev_off:prev_off + prev_len]))
        raw[off + 0x30:off + 0x50] = h.digest()
        if block_type == BlockType.EndOfCapture:
            h = make_hasher(algo)
            h.update(bytes(raw[:off]))
            raw[off + BLOCK_HEADER_SIZE:off + BLOCK_HEADER_SIZE + 32] = h.digest()


def _verify(raw: bytes, passphrase=None):
    return verify_slice(io.BytesIO(raw), passphrase)


@pytest.mark.parametrize("hash_algo", [HashAlgo.BLAKE3, HashAlgo.SHA256, HashAlgo.SHA512_256])
@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_valid_slice_verifies(comp_algo, hash_algo):
    report = _verify(_slice(comp_algo, hash_algo))
    assert report.valid, report.errors
    assert report.hash_algo == hash_algo
    assert report.file_hash_ok is True and report.eoc_present
    assert report.chain_ok and report.broken_at is None
    assert report.block_count == 3
    assert report.header_block_count == 0 and report.eoc_block_count == 3
    assert report.block_count_ok is True
    assert report.segments == [] and report.trailing_bytes == 0
    assert report.capture_ok
    assert report.warnings == []


def test_flipped_region_byte_breaks_following_block():
    raw = bytearray(_slice())
    blocks = _block_offsets(bytes(raw))
    index = next(i for i, b in enumerate(blocks) if b[1] == BlockType.MemoryRegion)
    offset, _, length = blocks[index]
    raw[offset + length - 1] ^= 0xFF
    report = _verify(bytes(raw))
    assert not report.valid
    assert report.broken_at == index + 1
    assert any("PrevHash mismatch" in e for e in report.errors)


def test_corrupted_file_hash_is_reported():
    raw = bytearray(_slice())
    eoc_offset = _block_offsets(bytes(raw))[-1][0]
    raw[eoc_offset + BLOCK_HEADER_SIZE] ^= 0xFF
    report = _verify(bytes(raw))
    assert not report.valid
    assert report.file_hash_ok is False
    assert report.chain_ok


def test_missing_eoc_is_a_warning():
    raw = _slice()
    eoc_offset = _block_offsets(raw)[-1][0]
    report = _verify(raw[:eoc_offset])
    assert report.valid
    assert report.file_hash_ok is None and not report.eoc_present
    assert report.block_count == 2
    assert any("EndOfCapture" in w for w in report.warnings)


@pytest.mark.parametrize("garbage", [b"not msl data", b"\x00" * 128])
def test_trailing_bytes_after_eoc_are_ignored(garbage):
    report = _verify(_slice() + garbage)
    assert report.valid
    assert any("trailing" in w for w in report.warnings)
    assert report.trailing_bytes == len(garbage)
    assert report.segments == []


def test_header_block_count_drift_is_an_error():
    raw = bytearray(_slice())
    struct.pack_into("<I", raw, 0x39, 7)
    _rechain(raw, include_block0=True)
    report = _verify(bytes(raw))
    assert not report.valid
    assert report.header_block_count == 7
    assert report.block_count_ok is False
    assert any("header BlockCount 7 != 3 blocks" in e for e in report.errors)


def test_eoc_block_count_tampered_is_an_error():
    raw = bytearray(_slice())
    eoc_offset = _block_offsets(bytes(raw))[-1][0]
    struct.pack_into("<I", raw, eoc_offset + _EOC_BLOCK_COUNT_OFFSET, 7)
    report = _verify(bytes(raw))
    assert not report.valid
    assert report.file_hash_ok is True  # the FileHash covers bytes before the EoC
    assert report.eoc_block_count == 7 and report.block_count_ok is False
    assert any("EoC BlockCount 7 != 3 blocks" in e for e in report.errors)
    assert not report.capture_ok


# ---------------------------------------------------------------------------
# Extension segments (spec Section 4.6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD])
def test_valid_extension_segment_verifies(comp_algo):
    report = _verify(_slice_with_segments(1, comp_algo))
    assert report.valid, report.errors
    assert report.block_count == 3 and report.chain_ok
    assert report.trailing_bytes == 0 and report.warnings == []
    assert len(report.segments) == 1
    segment = report.segments[0]
    assert segment.verified and segment.chain_ok and segment.segment_hash_ok
    assert segment.index == 1 and segment.terminated
    assert segment.block_count == 2 == segment.declared_block_count
    assert segment.producer == "test/1" and segment.written_at_ns > 0


def test_two_extension_segments_verify():
    report = _verify(_slice_with_segments(2))
    assert report.valid, report.errors
    assert [s.index for s in report.segments] == [1, 2]
    assert all(s.verified for s in report.segments)
    assert [s.producer for s in report.segments] == ["test/1", "test/2"]
    assert report.segments[1].start_offset > report.segments[0].start_offset


def test_flipped_byte_inside_segment_is_an_error():
    raw = bytearray(_slice_with_segments(1))
    start = _verify(bytes(raw)).segments[0].start_offset
    raw[start + 90] ^= 0xFF  # inside the manifest payload
    report = _verify(bytes(raw))
    assert not report.valid
    assert report.capture_ok  # the capture segment is untouched
    assert report.broken_at == 4  # the terminator, block 4 counted globally
    segment = report.segments[0]
    assert segment.chain_ok is False and segment.segment_hash_ok is False
    assert not segment.verified
    assert any("PrevHash mismatch" in e for e in report.errors)
    assert any("segment 1" in e and "SegmentHash mismatch" in e for e in report.errors)
    assert report.trailing_bytes == len(raw) - start


def test_truncated_terminator_is_unterminated_trailing():
    raw = _slice_with_segments(1)
    start = _verify(raw).segments[0].start_offset
    report = _verify(raw[:-10])
    assert report.valid, report.errors
    assert report.capture_ok
    segment = report.segments[0]
    assert segment.terminated is False and not segment.verified
    assert segment.chain_ok is None and segment.segment_hash_ok is None
    assert report.trailing_bytes == len(raw) - 10 - start
    assert any("extension segment 1 unterminated" in w for w in report.warnings)
    assert any("trailing byte(s) after EndOfCapture" in w for w in report.warnings)


def test_segment_after_broken_segment_is_trailing():
    raw = bytearray(_slice_with_segments(2))
    first = _verify(bytes(raw)).segments[0]
    raw[first.start_offset + 90] ^= 0xFF
    report = _verify(bytes(raw))
    assert not report.valid
    assert len(report.segments) == 1  # segment 2 is never presented
    assert report.trailing_bytes == len(raw) - first.start_offset


def test_encrypted_slice_with_in_stream_segment_verifies():
    report = _verify(_encrypted_slice_with_segment(), _PASSPHRASE)
    assert report.valid, report.errors
    assert report.encrypted and report.file_hash_ok is True
    assert report.block_count == 3 and report.trailing_bytes == 0
    assert len(report.segments) == 1 and report.segments[0].verified
    assert report.segments[0].producer == "enc/1"


def test_legacy_zero_block0_prev_hash_is_a_warning():
    raw = bytearray(_slice())
    raw[64 + 0x30:64 + 0x50] = b"\x00" * 32
    _rechain(raw)
    report = _verify(bytes(raw))
    assert report.valid, report.errors
    assert report.file_hash_ok is True
    assert any("legacy" in w for w in report.warnings)


def test_zero_block0_prev_hash_without_rechain_still_breaks_block1():
    raw = bytearray(_slice())
    raw[64 + 0x30:64 + 0x50] = b"\x00" * 32
    report = _verify(bytes(raw))
    assert report.broken_at == 1


def test_encrypted_slice_with_passphrase_verifies():
    report = _verify(_encrypted_slice(), _PASSPHRASE)
    assert report.valid, report.errors
    assert report.encrypted and report.file_hash_ok is True
    assert report.block_count == 3


def test_encrypted_slice_wrong_passphrase_is_invalid():
    report = _verify(_encrypted_slice(), "wrong")
    assert not report.valid
    assert report.block_count == 0


def test_encrypted_slice_without_passphrase_raises():
    with pytest.raises(ValueError, match="passphrase"):
        _verify(_encrypted_slice())


def _legacy_padding_compress(data: bytes, algo: CompAlgo) -> bytes:
    compressed = compress(data, algo)
    return compressed + b"\x00" * (-(8 + len(compressed)) % 8)


def test_legacy_padded_lz4_slice_verifies(monkeypatch):
    monkeypatch.setattr(writer_module, "compress", _legacy_padding_compress)
    report = _verify(_slice(CompAlgo.LZ4))
    assert report.valid, report.errors
    assert report.file_hash_ok is True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_verify_valid(tmp_path):
    path = tmp_path / "ok.msl"
    path.write_bytes(_slice(CompAlgo.LZ4))
    result = CliRunner().invoke(cli, ["verify", str(path)])
    assert result.exit_code == 0, result.output
    assert "blocks=3 (header BlockCount=0, EoC BlockCount=3)" in result.output
    assert "chain: OK" in result.output
    assert "FileHash: OK" in result.output
    assert "extensions: 0 segment(s)" in result.output
    assert "trailing:" not in result.output
    assert result.output.rstrip().endswith("VALID")


def test_cli_verify_lists_extension_segments(tmp_path):
    path = tmp_path / "ext.msl"
    path.write_bytes(_slice_with_segments(1))
    result = CliRunner().invoke(cli, ["verify", str(path)])
    assert result.exit_code == 0, result.output
    assert "extensions: 1 segment(s)" in result.output
    assert "segment 1: OK (2 blocks, producer=test/1)" in result.output
    assert "trailing:" not in result.output
    assert result.output.rstrip().endswith("VALID")


def test_cli_verify_unterminated_segment_is_trailing(tmp_path):
    raw = _slice_with_segments(1)
    path = tmp_path / "cut.msl"
    path.write_bytes(raw[:-10])
    result = CliRunner().invoke(cli, ["verify", str(path)])
    assert result.exit_code == 0, result.output
    assert "segment 1: BROKEN (unterminated)" in result.output
    assert "trailing: " in result.output and "byte(s)" in result.output
    assert result.output.rstrip().endswith("VALID")


def test_cli_verify_tampered_segment_exits_1(tmp_path):
    raw = bytearray(_slice_with_segments(1))
    raw[_verify(bytes(raw)).segments[0].start_offset + 90] ^= 0xFF
    path = tmp_path / "bad-ext.msl"
    path.write_bytes(bytes(raw))
    result = CliRunner().invoke(cli, ["verify", str(path)])
    assert result.exit_code == 1
    assert "segment 1: BROKEN (PrevHash mismatch)" in result.output
    assert "INVALID" in result.output


def test_cli_verify_tampered_exits_1(tmp_path):
    raw = bytearray(_slice())
    raw[_block_offsets(bytes(raw))[1][0] + BLOCK_HEADER_SIZE] ^= 0xFF
    path = tmp_path / "bad.msl"
    path.write_bytes(bytes(raw))
    result = CliRunner().invoke(cli, ["verify", str(path)])
    assert result.exit_code == 1
    assert "chain: BROKEN at block 2" in result.output
    assert "INVALID" in result.output


def test_cli_verify_encrypted_prompts_for_passphrase(tmp_path):
    path = tmp_path / "enc.msl"
    path.write_bytes(_encrypted_slice())
    result = CliRunner().invoke(cli, ["verify", str(path)], input=_PASSPHRASE + "\n")
    assert result.exit_code == 0, result.output
    assert "AEAD tag verified" in result.output


def test_cli_verify_encrypted_wrong_passphrase_exits_1(tmp_path):
    path = tmp_path / "enc.msl"
    path.write_bytes(_encrypted_slice())
    result = CliRunner().invoke(cli, ["verify", str(path), "--passphrase", "nope"])
    assert result.exit_code == 1
    assert "INVALID" in result.output


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_cli_group_help_lists_subcommands(flag):
    result = CliRunner().invoke(cli, [flag])
    assert result.exit_code == 0
    assert "acquire" in result.output and "verify" in result.output
