"""MSL 1.1.1 ``CipherLen`` (header 0x78), tag location and HKDF-BLAKE3.

Spec Sections 3.2 (Table 5), 4.5 (Table 12 FileHash), 10.2 ("Locating the
tag"), 10.7 (the one-time CipherLen patch) and 10.8 (segment subkeys).
"""
from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from memslicer.msl.constants import ENCRYPTED_HEADER_SIZE, FLAG_ENCRYPTED, BlockType
from memslicer.msl.encryption import (
    AES_GCM_TAG_LEN,
    CIPHER_LEN_OFFSET,
    EncryptionParams,
    aad_from_header,
    derive_key,
    derive_segment_key,
    hkdf_blake3,
    pack_encryption_extension,
    primary_ciphertext_span,
    unpack_encryption_extension,
    zero_cipher_len,
)
from memslicer.msl.integrity import make_hasher
from memslicer.msl.iterator import decrypt_container, iterate_blocks
from memslicer.msl.types import FileHeader, MemoryRegion, ProcessIdentity
from memslicer.msl.verify import verify_slice
from memslicer.msl.writer import MSLWriter

_PASSPHRASE = "correct horse"
_FAST_KDF = dict(kdf_time=1, kdf_memory=8, kdf_lanes=1)
_TRAILER = b"not an MSL segment" * 3


class _NonSeekable(io.RawIOBase):
    """Write-only stream that, like a pipe, cannot seek."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b) -> int:
        self.data += bytes(b)
        return len(b)


def _write_slice(output, params: EncryptionParams | None = None) -> None:
    params = params or EncryptionParams(**_FAST_KDF)
    w = MSLWriter(
        output, FileHeader(pid=4242, flags=FLAG_ENCRYPTED),
        encryption_key=derive_key(_PASSPHRASE, params), encryption_params=params,
    )
    w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x"))
    w.write_memory_region(MemoryRegion(
        base_addr=0x10000, region_size=4096, protection=3,
        page_states=[0], page_data_chunks=[bytes(range(256)) * 16],
    ))
    w.finalize()


def _sealed_file(tmp_path: Path) -> Path:
    path = tmp_path / "enc.msl"
    with open(path, "wb") as f:
        _write_slice(f)
    return path


def _cipher_len(data: bytes) -> int:
    return struct.unpack_from("<Q", data, CIPHER_LEN_OFFSET)[0]


def _with_cipher_len(data: bytes, value: int) -> bytes:
    patched = bytearray(data)
    struct.pack_into("<Q", patched, CIPHER_LEN_OFFSET, value)
    return bytes(patched)


def _block_types(data: bytes) -> list[int]:
    with io.BytesIO(data) as f:
        return [b.block_type for b in iterate_blocks(f, _PASSPHRASE)]


def _decrypt(data: bytes):
    return decrypt_container(io.BytesIO(data), ENCRYPTED_HEADER_SIZE, _PASSPHRASE)


_EXPECTED_TYPES = [
    BlockType.ProcessIdentity, BlockType.MemoryRegion, BlockType.EndOfCapture,
]


class TestWriterRecordsCipherLen:
    def test_seekable_file_gets_cipher_len(self, tmp_path):
        data = _sealed_file(tmp_path).read_bytes()
        assert _cipher_len(data) == len(data) - ENCRYPTED_HEADER_SIZE - AES_GCM_TAG_LEN
        assert _block_types(data) == _EXPECTED_TYPES

    def test_non_seekable_output_leaves_zero(self):
        out = _NonSeekable()
        _write_slice(out)
        data = bytes(out.data)
        assert _cipher_len(data) == 0
        assert _block_types(data) == _EXPECTED_TYPES

    def test_preset_cipher_len_mismatch_refuses_to_seal(self):
        params = EncryptionParams(cipher_len=1, **_FAST_KDF)
        with pytest.raises(ValueError, match="cipher_len"):
            _write_slice(io.BytesIO(), params)


class TestTagLocation:
    def test_legacy_zero_cipher_len_still_decrypts(self, tmp_path):
        data = _with_cipher_len(_sealed_file(tmp_path).read_bytes(), 0)
        assert _block_types(data) == _EXPECTED_TYPES
        assert _decrypt(data).post_tag_bytes == 0

    @pytest.mark.parametrize("delta", [-16, 16])
    def test_tampered_cipher_len_never_succeeds(self, tmp_path, delta):
        data = _sealed_file(tmp_path).read_bytes()
        with pytest.raises(ValueError, match="CipherLen|authentication tag"):
            _decrypt(_with_cipher_len(data, _cipher_len(data) + delta))

    @pytest.mark.parametrize("delta", [-16, 16])
    def test_tampered_cipher_len_with_trailer_fails_auth(self, tmp_path, delta):
        data = _sealed_file(tmp_path).read_bytes() + _TRAILER
        with pytest.raises(ValueError, match="authentication tag"):
            _decrypt(_with_cipher_len(data, _cipher_len(data) + delta))

    def test_out_of_bounds_cipher_len_rejected(self, tmp_path):
        data = _with_cipher_len(_sealed_file(tmp_path).read_bytes(), 2**63)
        with pytest.raises(ValueError, match="exceeds"):
            _decrypt(data)

    def test_trailing_bytes_after_tag_still_decrypt(self, tmp_path):
        clean = _sealed_file(tmp_path).read_bytes()
        container = _decrypt(clean + _TRAILER)
        assert container.post_tag_offset == len(clean)
        assert container.post_tag_bytes == len(_TRAILER)
        assert container.tag == clean[-AES_GCM_TAG_LEN:]
        assert _block_types(clean + _TRAILER) == _EXPECTED_TYPES

    def test_span_bounds(self):
        assert primary_ciphertext_span(200, 128, 0, 0) == (128, 184)
        assert primary_ciphertext_span(200, 128, 0, 56) == (128, 184)
        with pytest.raises(ValueError, match="exceeds"):
            primary_ciphertext_span(200, 128, 0, 57)
        with pytest.raises(ValueError, match="truncated"):
            primary_ciphertext_span(143, 128, 0, 0)


class TestFileHash:
    def test_verify_passes_with_patched_cipher_len(self, tmp_path):
        data = _sealed_file(tmp_path).read_bytes()
        assert _cipher_len(data) != 0
        report = verify_slice(io.BytesIO(data), _PASSPHRASE)
        assert report.valid, report.errors
        assert report.file_hash_ok is True
        assert report.cipher_len == _cipher_len(data)
        assert report.post_tag_bytes == 0

    def test_file_hash_covers_zeroed_cipher_len(self, tmp_path):
        data = _sealed_file(tmp_path).read_bytes()
        plaintext = _decrypt(data).plaintext
        eoc = [b for b in iterate_blocks(io.BytesIO(data), _PASSPHRASE)
               if b.block_type == BlockType.EndOfCapture][0]
        hasher = make_hasher(data[0x3D])
        hasher.update(zero_cipher_len(data[:ENCRYPTED_HEADER_SIZE]))
        hasher.update(plaintext[:eoc.start_offset])
        assert eoc.payload[:32] == hasher.digest()

    def test_verify_reports_post_tag_bytes(self, tmp_path):
        clean = _sealed_file(tmp_path).read_bytes()
        report = verify_slice(io.BytesIO(clean + _TRAILER), _PASSPHRASE)
        assert report.valid, report.errors
        assert report.post_tag_offset == len(clean)
        assert report.post_tag_bytes == len(_TRAILER)
        assert any("after the primary AEAD tag" in w for w in report.warnings)


class TestHeaderHelpers:
    def test_pack_unpack_cipher_len_roundtrip(self):
        params = EncryptionParams(cipher_len=0x0102030405060708)
        raw = pack_encryption_extension(params)
        assert raw[-8:] == bytes.fromhex("0807060504030201")
        assert unpack_encryption_extension(raw).cipher_len == params.cipher_len
        assert EncryptionParams().cipher_len == 0

    def test_aad_zeroes_only_cipher_len(self):
        header = bytes(range(128))
        aad = aad_from_header(header, b"kem")
        assert aad[:CIPHER_LEN_OFFSET] == header[:CIPHER_LEN_OFFSET]
        assert aad[CIPHER_LEN_OFFSET:128] == b"\x00" * 8
        assert aad[128:] == b"kem"
        assert zero_cipher_len(header[:64]) == header[:64]


class TestHkdfBlake3:
    """Vectors produced by MemDiver's ``msl.crypto.hkdf_blake3``."""

    CEK = bytes(range(32))
    DUMP_UUID = bytes(range(0xA0, 0xB0))

    def test_segment_key_index_1(self):
        assert derive_segment_key(self.CEK, self.DUMP_UUID, 1).hex() == (
            "c4072a6a7de53d0c6bfca86dd144e285c7f646e5db86835ac27a164ac553821b"
        )

    def test_segment_key_index_65535(self):
        assert derive_segment_key(self.CEK, self.DUMP_UUID, 65535).hex() == (
            "a78262ee27812230053b46b3b21f2740f70c2bbb67a3cdfe2ffc58653374d06d"
        )

    def test_multi_block_output_with_empty_salt(self):
        assert hkdf_blake3(b"ikm", b"", b"info", 80).hex() == (
            "7cdc044a0109a8823f7f5357556654ed0d525c680af21305d8aca51e9e6e5cf7"
            "f780b73e9bb481cd22fc6a212ae62d2f00895d19b1418b4bd0092c6d73b66200"
            "6d706ac705be575066245afdd879766a"
        )

    @pytest.mark.parametrize("index", [0, 65536, -1])
    def test_segment_index_out_of_range(self, index):
        with pytest.raises(ValueError, match="index"):
            derive_segment_key(self.CEK, self.DUMP_UUID, index)

    def test_length_out_of_range(self):
        with pytest.raises(ValueError):
            hkdf_blake3(b"k", b"s", b"i", 0)
