"""Tests for compression wrappers."""
import pytest
from memslicer.msl.constants import CompAlgo
from memslicer.msl.compression import compress, decompress


def test_none_passthrough():
    data = b"hello world" * 100
    assert compress(data, CompAlgo.NONE) == data
    assert decompress(data, CompAlgo.NONE) == data


def test_zstd_roundtrip():
    data = b"hello world" * 100
    compressed = compress(data, CompAlgo.ZSTD)
    assert compressed != data  # Should actually compress
    assert decompress(compressed, CompAlgo.ZSTD) == data


def test_lz4_roundtrip():
    data = b"hello world" * 100
    compressed = compress(data, CompAlgo.LZ4)
    assert compressed != data
    assert decompress(compressed, CompAlgo.LZ4) == data


def test_zstd_empty():
    compressed = compress(b"", CompAlgo.ZSTD)
    assert decompress(compressed, CompAlgo.ZSTD) == b""


def test_lz4_empty():
    compressed = compress(b"", CompAlgo.LZ4)
    assert decompress(compressed, CompAlgo.LZ4) == b""


def test_invalid_algo():
    with pytest.raises(ValueError):
        compress(b"data", 99)
    with pytest.raises(ValueError):
        decompress(b"data", 99)
