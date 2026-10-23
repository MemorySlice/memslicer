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


# --- decompress_tolerating_padding (legacy 8-byte padded payloads) ---

from memslicer.msl.compression import (  # noqa: E402
    MAX_LEGACY_PAD_TRIM, decompress_tolerating_padding,
)

_SAMPLE = b"hello world" * 100


@pytest.mark.parametrize("pad", range(MAX_LEGACY_PAD_TRIM + 1))
def test_tolerating_padding_lz4_trailing_zeros(pad):
    padded = compress(_SAMPLE, CompAlgo.LZ4) + b"\x00" * pad
    assert decompress_tolerating_padding(padded, CompAlgo.LZ4) == _SAMPLE


def test_tolerating_padding_rejects_nonzero_trailing_garbage():
    garbage = compress(_SAMPLE, CompAlgo.LZ4) + b"\x01\x00\x00"
    with pytest.raises(Exception):
        decompress_tolerating_padding(garbage, CompAlgo.LZ4)


def test_tolerating_padding_zstd_with_padding_unaffected():
    padded = compress(_SAMPLE, CompAlgo.ZSTD) + b"\x00" * 5
    assert decompress_tolerating_padding(padded, CompAlgo.ZSTD) == _SAMPLE


def test_plain_decompress_stays_strict_for_padded_lz4():
    padded = compress(_SAMPLE, CompAlgo.LZ4) + b"\x00" * 3
    with pytest.raises(Exception):
        decompress(padded, CompAlgo.LZ4)
