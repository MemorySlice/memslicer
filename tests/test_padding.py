"""Tests for padding utilities."""
from memslicer.utils.padding import pad8, pad_bytes, encode_string


class TestPad8:
    def test_zero(self):
        assert pad8(0) == 0

    def test_one(self):
        assert pad8(1) == 8

    def test_seven(self):
        assert pad8(7) == 8

    def test_eight(self):
        assert pad8(8) == 8

    def test_nine(self):
        assert pad8(9) == 16

    def test_sixteen(self):
        assert pad8(16) == 16


class TestPadBytes:
    def test_empty(self):
        assert pad_bytes(b"") == b""

    def test_already_aligned(self):
        data = b"\x01" * 8
        assert pad_bytes(data) == data

    def test_needs_padding(self):
        data = b"\x01" * 5
        result = pad_bytes(data)
        assert len(result) == 8
        assert result[:5] == data
        assert result[5:] == b"\x00\x00\x00"

    def test_single_byte(self):
        result = pad_bytes(b"\xff")
        assert len(result) == 8
        assert result[0:1] == b"\xff"
        assert result[1:] == b"\x00" * 7


class TestEncodeString:
    def test_ascii(self):
        result = encode_string("hello")
        assert result[0:5] == b"hello"
        assert result[5:6] == b"\x00"  # null terminator
        assert len(result) % 8 == 0

    def test_empty(self):
        result = encode_string("")
        assert result[0:1] == b"\x00"
        assert len(result) % 8 == 0

    def test_unicode(self):
        result = encode_string("über")
        assert b"\xc3\xbc" in result  # ü in UTF-8
        assert result[-1:] != b""  # has content
        assert len(result) % 8 == 0

    def test_exact_alignment(self):
        # "1234567" + null = 8 bytes exactly
        result = encode_string("1234567")
        assert len(result) == 8
        assert result == b"1234567\x00"
