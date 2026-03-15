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
