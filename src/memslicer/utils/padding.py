"""Alignment and string-encoding helpers for 8-byte boundaries."""


def pad8(n: int) -> int:
    """Return the next multiple of 8 that is >= *n*."""
    return (n + 7) & ~7


def pad_bytes(data: bytes) -> bytes:
    """Pad *data* with zero bytes so its length is an 8-byte multiple."""
    padded_len = pad8(len(data))
    return data.ljust(padded_len, b"\x00")


def encode_string(s: str) -> bytes:
    """UTF-8 encode *s*, null-terminate, and pad to an 8-byte boundary."""
    raw = s.encode("utf-8") + b"\x00"
    return pad_bytes(raw)


def truncate_utf8(raw: bytes, max_bytes: int) -> bytes:
    """Cut *raw* to at most *max_bytes*, never mid-character.

    Slicing encoded UTF-8 at an arbitrary offset can leave a partial
    multi-byte sequence, which would put invalid UTF-8 into a field the
    format declares as UTF-8. Continuation bytes match ``0b10xxxxxx``, so
    walking back off them lands on the start of the character that was cut.

    Args:
        raw: Encoded UTF-8 bytes, without a terminator.
        max_bytes: Maximum length to keep.

    Returns:
        A prefix of *raw* that is valid UTF-8 and no longer than *max_bytes*.
    """
    if len(raw) <= max_bytes:
        return raw
    end = max_bytes
    while end > 0 and (raw[end] & 0xC0) == 0x80:
        end -= 1
    return raw[:end]


def encode_string_bounded(s: str, max_len: int = 0xFFFF) -> tuple[bytes, int]:
    """Encode *s* for a field whose length is declared in a bounded integer.

    :func:`encode_string` is the right tool whenever the caller can prove the
    string is short. It cannot be used for process command lines: Linux admits
    an ``argv`` far larger than the ``uint16`` the format reserves for
    ``CmdLineLen``, and ``struct.pack`` answers an oversized value with
    ``struct.error`` -- aborting the capture instead of recording a slightly
    shortened command line.

    The pre-padding length is returned rather than recomputed by the caller,
    so the declared length and the bytes on disk cannot disagree.

    Args:
        s: The string to encode. May be empty.
        max_len: Largest value the length field can carry, terminator included.

    Returns:
        ``(padded_bytes, pre_padding_length)``. The length counts the NUL
        terminator and excludes the 8-byte alignment padding.
    """
    raw = truncate_utf8(s.encode("utf-8"), max_len - 1) + b"\x00"
    return pad_bytes(raw), len(raw)
