"""Integrity hash chain for MSL files.

Supports BLAKE3 (default), SHA-256, and SHA-512/256 as selected by
the ``HashAlgo`` field in the file header (spec Section 4.4).
"""
from __future__ import annotations

import hashlib

import blake3

from memslicer.msl.constants import HashAlgo


def make_hasher(algo: HashAlgo):
    """Return a new hash object for the given algorithm.

    The returned object exposes ``.update(data)`` and ``.digest()``
    (32-byte output for all registered algorithms).
    """
    if algo == HashAlgo.BLAKE3:
        return blake3.blake3()
    if algo == HashAlgo.SHA256:
        return hashlib.sha256()
    if algo == HashAlgo.SHA512_256:
        return hashlib.new("sha512_256")
    raise ValueError(f"unsupported integrity hash algorithm: {algo!r}")


class IntegrityChain:
    """Maintains a rolling hash chain across MSL blocks.

    The chain works as follows:
    - feed_header(header_bytes) hashes the file header, returns digest for Block 0's PrevHash
    - feed_block(block_bytes) hashes a complete block, returns digest for next block's PrevHash
    - prev_hash property returns current PrevHash value for next block
    - finalize() returns running digest of entire file (for EoC FileHash)

    Extension segments (spec Section 4.6) add a second, optional hasher:
    start_segment() opens it, every block fed afterwards updates it too,
    segment_digest() reads it (for the EndOfExtension SegmentHash) and
    end_segment() closes it. The chain itself continues across segments.
    """

    def __init__(self, hash_algo: HashAlgo = HashAlgo.BLAKE3) -> None:
        self._hash_algo = hash_algo
        self._prev_hash: bytes = b'\x00' * 32
        self._file_hasher = make_hasher(hash_algo)
        self._segment_hasher = None

    def _new_hasher(self):
        """Create a fresh per-block hasher."""
        return make_hasher(self._hash_algo)

    @property
    def hash_algo(self) -> HashAlgo:
        """Hash algorithm this chain was created with."""
        return self._hash_algo

    @property
    def prev_hash(self) -> bytes:
        """Current PrevHash value for the next block."""
        return self._prev_hash

    def feed_header(self, header_bytes: bytes) -> bytes:
        """Hash file header bytes, update chain. Returns digest for Block 0's PrevHash."""
        self._file_hasher.update(header_bytes)
        h = self._new_hasher()
        h.update(header_bytes)
        self._prev_hash = h.digest()
        return self._prev_hash

    def feed_block(self, block_bytes: bytes) -> bytes:
        """Hash a complete block, update chain. Returns digest for next block's PrevHash."""
        return self.feed_block_parts(block_bytes)

    def feed_block_parts(self, *parts: bytes) -> bytes:
        """Hash a block from multiple parts without concatenation."""
        block_hasher = self._new_hasher()
        for part in parts:
            self._file_hasher.update(part)
            block_hasher.update(part)
            if self._segment_hasher is not None:
                self._segment_hasher.update(part)
        self._prev_hash = block_hasher.digest()
        return self._prev_hash

    def finalize(self) -> bytes:
        """Return digest of the entire file so far (for EoC FileHash)."""
        return self._file_hasher.digest()

    # ------------------------------------------------------------------
    # Extension segments (spec Section 4.6)
    # ------------------------------------------------------------------

    @property
    def in_segment(self) -> bool:
        """Whether a segment hasher is currently open."""
        return self._segment_hasher is not None

    def start_segment(self) -> None:
        """Open a fresh segment hasher; blocks fed from now on update it."""
        if self._segment_hasher is not None:
            raise ValueError("segment already started")
        self._segment_hasher = self._new_hasher()

    def segment_digest(self) -> bytes:
        """Digest of every block fed since :meth:`start_segment`.

        Raises:
            ValueError: if no segment is open.
        """
        if self._segment_hasher is None:
            raise ValueError("no segment started")
        return self._segment_hasher.digest()

    def end_segment(self) -> None:
        """Close the segment hasher; later blocks no longer update it."""
        if self._segment_hasher is None:
            raise ValueError("no segment started")
        self._segment_hasher = None
