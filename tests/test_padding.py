"""Tests for padding utilities."""
from memslicer.utils.padding import (
    pad8, pad_bytes, encode_string, encode_string_bounded, truncate_utf8,
)


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


class TestTruncateUtf8:
    """Cutting encoded UTF-8 must never leave a partial character."""

    def test_shorter_than_limit_is_unchanged(self):
        assert truncate_utf8(b"abc", 10) == b"abc"

    def test_exact_limit_is_unchanged(self):
        assert truncate_utf8(b"abc", 3) == b"abc"

    def test_ascii_cuts_at_the_limit(self):
        assert truncate_utf8(b"abcdef", 3) == b"abc"

    def test_multibyte_character_is_dropped_whole(self):
        # "ae" is 2 bytes; cutting at 3 would split the second one.
        raw = "aä".encode("utf-8")
        assert len(raw) == 3
        assert truncate_utf8(raw, 2) == b"a"

    def test_result_always_decodes(self):
        raw = ("ä" * 100).encode("utf-8")
        for limit in range(len(raw) + 1):
            truncate_utf8(raw, limit).decode("utf-8")


class TestEncodeStringBounded:
    """The declared length and the bytes on disk must always agree."""

    def test_short_string_matches_encode_string(self):
        encoded, length = encode_string_bounded("/usr/bin/test")
        assert encoded == encode_string("/usr/bin/test")
        assert length == len("/usr/bin/test") + 1

    def test_empty_string_is_a_lone_terminator(self):
        encoded, length = encode_string_bounded("")
        assert length == 1
        assert encoded == b"\x00" * 8

    def test_result_is_padded_to_eight(self):
        encoded, _ = encode_string_bounded("abc")
        assert len(encoded) % 8 == 0

    def test_length_never_exceeds_the_field(self):
        _, length = encode_string_bounded("a" * 200_000)
        assert length <= 0xFFFF

    def test_truncated_value_still_decodes(self):
        encoded, length = encode_string_bounded("ä" * 100_000)
        assert length <= 0xFFFF
        encoded[:length - 1].decode("utf-8")

    def test_exact_boundary_is_not_truncated(self):
        value = "a" * (0xFFFF - 1)
        _, length = encode_string_bounded(value)
        assert length == 0xFFFF

    def test_one_over_boundary_is_truncated(self):
        _, length = encode_string_bounded("a" * 0xFFFF)
        assert length == 0xFFFF

    def test_custom_limit(self):
        encoded, length = encode_string_bounded("abcdef", max_len=4)
        assert length == 4
        assert encoded[:length] == b"abc\x00"
