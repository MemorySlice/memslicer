"""Tests for configurable HashAlgo support (spec Section 4.4, Table 12).

Covers:
  - HashAlgo enum values match spec
  - make_hasher() factory for each algorithm
  - IntegrityChain with each algorithm
  - File header offset 0x3D encodes correct HashAlgo byte
  - Round-trip: write with each algo, iterate back, verify header
  - Backward compatibility: 0x00 at 0x3D = BLAKE3 (matches old reserved=0)
"""
from __future__ import annotations

import hashlib
import io
import struct
import sys
from pathlib import Path

import blake3
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.msl.constants import HashAlgo, HASH_SIZE
from memslicer.msl.integrity import IntegrityChain, make_hasher
from memslicer.msl.types import FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity
from memslicer.msl.writer import MSLWriter
from memslicer.msl.iterator import iterate_blocks, read_hash_algo
from memslicer.msl.constants import CompAlgo, PageState


# ---------------------------------------------------------------------------
# HashAlgo enum
# ---------------------------------------------------------------------------

class TestHashAlgoEnum:
    def test_blake3_code(self):
        assert HashAlgo.BLAKE3 == 0x00

    def test_sha256_code(self):
        assert HashAlgo.SHA256 == 0x01

    def test_sha512_256_code(self):
        assert HashAlgo.SHA512_256 == 0x02

    def test_other_code(self):
        assert HashAlgo.OTHER == 0xFF


# ---------------------------------------------------------------------------
# make_hasher()
# ---------------------------------------------------------------------------

class TestMakeHasher:
    def test_blake3_produces_32_bytes(self):
        h = make_hasher(HashAlgo.BLAKE3)
        h.update(b"test data")
        assert len(h.digest()) == 32

    def test_sha256_produces_32_bytes(self):
        h = make_hasher(HashAlgo.SHA256)
        h.update(b"test data")
        assert len(h.digest()) == 32

    def test_sha512_256_produces_32_bytes(self):
        h = make_hasher(HashAlgo.SHA512_256)
        h.update(b"test data")
        assert len(h.digest()) == 32

    def test_blake3_matches_reference(self):
        data = b"hello world"
        h = make_hasher(HashAlgo.BLAKE3)
        h.update(data)
        assert h.digest() == blake3.blake3(data).digest()

    def test_sha256_matches_reference(self):
        data = b"hello world"
        h = make_hasher(HashAlgo.SHA256)
        h.update(data)
        assert h.digest() == hashlib.sha256(data).digest()

    def test_sha512_256_matches_reference(self):
        data = b"hello world"
        h = make_hasher(HashAlgo.SHA512_256)
        h.update(data)
        assert h.digest() == hashlib.new("sha512_256", data).digest()

    def test_other_raises(self):
        with pytest.raises(ValueError, match="unsupported"):
            make_hasher(HashAlgo.OTHER)

    def test_all_algos_produce_hash_size(self):
        """All registered algorithms produce HASH_SIZE (32) bytes."""
        for algo in (HashAlgo.BLAKE3, HashAlgo.SHA256, HashAlgo.SHA512_256):
            h = make_hasher(algo)
            h.update(b"data")
            assert len(h.digest()) == HASH_SIZE


# ---------------------------------------------------------------------------
# IntegrityChain with different algorithms
# ---------------------------------------------------------------------------

class TestIntegrityChainAlgorithms:
    def test_default_is_blake3(self):
        chain = IntegrityChain()
        header = b'\x01' * 64
        result = chain.feed_header(header)
        assert result == blake3.blake3(header).digest()

    def test_sha256_chain(self):
        chain = IntegrityChain(hash_algo=HashAlgo.SHA256)
        header = b'\x01' * 64
        result = chain.feed_header(header)
        assert result == hashlib.sha256(header).digest()

    def test_sha512_256_chain(self):
        chain = IntegrityChain(hash_algo=HashAlgo.SHA512_256)
        header = b'\x01' * 64
        result = chain.feed_header(header)
        assert result == hashlib.new("sha512_256", header).digest()

    def test_sha256_finalize(self):
        chain = IntegrityChain(hash_algo=HashAlgo.SHA256)
        header = b'\x01' * 64
        block = b'\x02' * 100
        chain.feed_header(header)
        chain.feed_block(block)

        expected = hashlib.sha256()
        expected.update(header)
        expected.update(block)
        assert chain.finalize() == expected.digest()

    def test_sha256_feed_block_parts(self):
        chain = IntegrityChain(hash_algo=HashAlgo.SHA256)
        chain.feed_header(b'\x01' * 64)

        part_a = b'\xaa' * 80
        part_b = b'\xbb' * 50
        result = chain.feed_block_parts(part_a, part_b)

        expected = hashlib.sha256()
        expected.update(part_a)
        expected.update(part_b)
        assert result == expected.digest()


# ---------------------------------------------------------------------------
# File header HashAlgo byte at offset 0x3D
# ---------------------------------------------------------------------------

def _write_msl_header(hash_algo: HashAlgo) -> bytes:
    """Write a minimal MSL file and return the raw bytes."""
    buf = io.BytesIO()
    header = FileHeader(hash_algo=hash_algo)
    writer = MSLWriter(buf, header)
    writer.write_process_identity(ProcessIdentity(exe_path="/test"))
    writer.write_module_list([])
    writer.finalize()
    return buf.getvalue()


class TestFileHeaderHashAlgoByte:
    def test_blake3_at_offset_0x3D(self):
        data = _write_msl_header(HashAlgo.BLAKE3)
        assert data[0x3D] == 0x00

    def test_sha256_at_offset_0x3D(self):
        data = _write_msl_header(HashAlgo.SHA256)
        assert data[0x3D] == 0x01

    def test_sha512_256_at_offset_0x3D(self):
        data = _write_msl_header(HashAlgo.SHA512_256)
        assert data[0x3D] == 0x02

    def test_reserved_bytes_at_0x3E_are_zero(self):
        """The 2-byte reserved field after HashAlgo must be zero."""
        for algo in (HashAlgo.BLAKE3, HashAlgo.SHA256, HashAlgo.SHA512_256):
            data = _write_msl_header(algo)
            assert data[0x3E:0x40] == b'\x00\x00', f"failed for {algo.name}"

    def test_header_size_still_64(self):
        """Header size remains 64 bytes (unencrypted)."""
        data = _write_msl_header(HashAlgo.SHA256)
        assert data[0x09] == 64  # HeaderSize byte


# ---------------------------------------------------------------------------
# Round-trip: write + iterate for each algorithm
# ---------------------------------------------------------------------------

class TestRoundTripHashAlgo:
    @pytest.mark.parametrize("algo", [HashAlgo.BLAKE3, HashAlgo.SHA256, HashAlgo.SHA512_256])
    def test_read_hash_algo(self, algo):
        raw = _write_msl_header(algo)
        f = io.BytesIO(raw)
        parsed = read_hash_algo(f)
        assert parsed == algo

    @pytest.mark.parametrize("algo", [HashAlgo.BLAKE3, HashAlgo.SHA256, HashAlgo.SHA512_256])
    def test_iterate_blocks_works(self, algo):
        """Verify we can iterate all blocks regardless of hash algorithm."""
        raw = _write_msl_header(algo)
        f = io.BytesIO(raw)
        blocks = list(iterate_blocks(f))
        # Expect: ProcessIdentity, ModuleListIndex, EndOfCapture
        assert len(blocks) >= 2
        assert blocks[-1].block_type == 0x0FFF  # EndOfCapture


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_zero_byte_at_0x3D_is_blake3(self):
        """Old files had 0x00 at 0x3D (reserved=0). This must parse as BLAKE3."""
        data = _write_msl_header(HashAlgo.BLAKE3)
        # Verify byte is already 0x00
        assert data[0x3D] == 0x00
        f = io.BytesIO(data)
        assert read_hash_algo(f) == HashAlgo.BLAKE3

    def test_default_file_header_uses_blake3(self):
        """FileHeader() with no arguments defaults to BLAKE3."""
        h = FileHeader()
        assert h.hash_algo == HashAlgo.BLAKE3
