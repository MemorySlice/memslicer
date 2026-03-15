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
