"""Shared address decoding utilities for /proc/net and Darwin libproc.

These functions convert hex-encoded addresses from different OS sources
into the 16-byte normalised form used by MSL ConnectionEntry fields.
"""
from __future__ import annotations

import struct


def decode_proc_net_ipv4(hex_addr: str) -> bytes:
    """Decode a /proc/net IPv4 hex address to 16-byte padded network order.

    The hex string is a 32-bit integer in host byte order (little-endian
    on most Linux systems). Convert to 4 bytes in network order, then
    pad to 16 bytes with zeros.
    """
    if not hex_addr:
        return b"\x00" * 16
    host_int = int(hex_addr, 16)
    network_bytes = struct.pack(
        "!I", struct.unpack("<I", struct.pack("=I", host_int))[0],
    )
    return network_bytes + b"\x00" * 12


def decode_proc_net_ipv6(hex_addr: str) -> bytes:
    """Decode a /proc/net IPv6 hex address to 16-byte network order.

    The 32 hex chars represent 4 x 32-bit words in host byte order.
    Each word is byte-reversed to network byte order.
    """
    if not hex_addr:
        return b"\x00" * 16
    result = bytearray(16)
    for i in range(4):
        word_hex = hex_addr[i * 8:(i + 1) * 8]
        word_le = int(word_hex, 16)
        struct.pack_into(
            "!I", result, i * 4,
            struct.unpack("<I", struct.pack("=I", word_le))[0],
        )
    return bytes(result)


def decode_proc_net_addr(hex_addr: str, is_ipv6: bool) -> bytes:
    """Dispatch to IPv4 or IPv6 /proc/net decoder."""
    if not hex_addr:
        return b"\x00" * 16
    if is_ipv6:
        return decode_proc_net_ipv6(hex_addr)
    return decode_proc_net_ipv4(hex_addr)


def decode_network_order_addr(hex_addr: str, is_ipv6: bool) -> bytes:
    """Decode an address already in network byte order (e.g. Darwin libproc).

    The JS side reads raw bytes from sockaddr_in/sockaddr_in6 and
    encodes them as a hex string. No byte swapping is needed.
    IPv4 = up to 4 bytes + 12 zero pad. IPv6 = 16 bytes.
    """
    if not hex_addr:
        return b"\x00" * 16
    raw = bytes.fromhex(hex_addr)
    if is_ipv6:
        return raw[:16].ljust(16, b"\x00")
    return raw[:4].ljust(16, b"\x00")
