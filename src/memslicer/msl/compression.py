"""Compression/decompression wrappers for MSL page data."""
import zstandard
import lz4.block

from memslicer.msl.constants import CompAlgo

_ZSTD_COMPRESSOR = zstandard.ZstdCompressor()
_ZSTD_DECOMPRESSOR = zstandard.ZstdDecompressor()


def compress(data: bytes, algo: CompAlgo) -> bytes:
    """Compress data using the specified algorithm."""
    if algo == CompAlgo.NONE:
        return data
    if algo == CompAlgo.ZSTD:
        return _ZSTD_COMPRESSOR.compress(data)
    if algo == CompAlgo.LZ4:
        return lz4.block.compress(data, store_size=True)
    raise ValueError(f"Unknown compression algorithm: {algo}")


def decompress(data: bytes, algo: CompAlgo) -> bytes:
    """Decompress data using the specified algorithm."""
    if algo == CompAlgo.NONE:
        return data
    if algo == CompAlgo.ZSTD:
        return _ZSTD_DECOMPRESSOR.decompress(data)
    if algo == CompAlgo.LZ4:
        return lz4.block.decompress(data)
    raise ValueError(f"Unknown compression algorithm: {algo}")


MAX_LEGACY_PAD_TRIM = 7
"""Most trailing zero bytes a legacy writer could have appended (pad to 8B)."""


def decompress_tolerating_padding(data: bytes, algo: CompAlgo) -> bytes:
    """Decompress data, tolerating legacy zero padding after the stream.

    Spec Section 4.2.1 (Table 9) stores compressed payloads unpadded:
    ``BlockLength = 80 + 8 + len(CompressedData)``. memslicer releases
    up to v0.4.4 padded ``UncompressedSize + CompressedData`` to an 8-byte boundary.
    zstd ignores such trailing zeros, but ``lz4.block.decompress``
    rejects them, so those slices could not be read back.

    Strict :func:`decompress` is tried first. On failure, up to
    :data:`MAX_LEGACY_PAD_TRIM` trailing bytes are trimmed one at a time,
    but only while every trimmed byte is zero -- non-zero trailing data
    is never discarded. Callers should still check the decompressed size
    against the block's ``UncompressedSize`` to rule out a false success.

    Raises:
        The original exception from :func:`decompress` when no trimmed
        variant decompresses either.
    """
    try:
        return decompress(data, algo)
    except Exception as original_exc:
        for trim in range(1, MAX_LEGACY_PAD_TRIM + 1):
            if trim >= len(data) or data[len(data) - trim] != 0:
                break
            try:
                return decompress(data[:-trim], algo)
            except Exception:
                continue
        raise original_exc
