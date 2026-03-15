"""BLAKE3-based integrity chain for MSL files."""
import blake3


class IntegrityChain:
    """Maintains a rolling BLAKE3 hash chain across MSL blocks.

    The chain works as follows:
    - feed_header(header_bytes) hashes the file header, returns digest for Block 0's PrevHash
    - feed_block(block_bytes) hashes a complete block, returns digest for next block's PrevHash
    - prev_hash property returns current PrevHash value for next block
    - finalize() returns running BLAKE3 digest of entire file (for EoC FileHash)
    """

    def __init__(self) -> None:
        self._prev_hash: bytes = b'\x00' * 32
        self._file_hasher = blake3.blake3()

    @property
    def prev_hash(self) -> bytes:
        """Current PrevHash value for the next block."""
        return self._prev_hash

    def feed_header(self, header_bytes: bytes) -> bytes:
        """Hash file header bytes, update chain. Returns digest for Block 0's PrevHash."""
        self._file_hasher.update(header_bytes)
        self._prev_hash = blake3.blake3(header_bytes).digest()
        return self._prev_hash

    def feed_block(self, block_bytes: bytes) -> bytes:
        """Hash a complete block, update chain. Returns digest for next block's PrevHash."""
        self._file_hasher.update(block_bytes)
        self._prev_hash = blake3.blake3(block_bytes).digest()
        return self._prev_hash

    def feed_block_parts(self, *parts: bytes) -> bytes:
        """Hash a block from multiple parts without concatenation."""
        block_hasher = blake3.blake3()
        for part in parts:
            self._file_hasher.update(part)
            block_hasher.update(part)
        self._prev_hash = block_hasher.digest()
        return self._prev_hash

    def finalize(self) -> bytes:
        """Return BLAKE3 digest of the entire file so far (for EoC FileHash)."""
        return self._file_hasher.digest()
