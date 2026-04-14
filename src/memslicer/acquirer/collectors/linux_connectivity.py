"""Pure parsers for Linux /proc/net/* connectivity files (P1.6.5).

Pure /proc readers — no external binaries are invoked. Each parser
takes a file path (so
tests can redirect to fixtures) plus an optional logger, and returns a
list of row dataclasses from :mod:`memslicer.msl.types`.

Missing / unreadable / header-only files return ``[]`` — never raise.
"""
from __future__ import annotations

import logging
import socket
import struct

from memslicer.msl.types import (
    ArpEntryRow,
    IPv4RouteRow,
    IPv6RouteRow,
    NetdevStatsRow,
    PacketSocketRow,
    SnmpCounterRow,
    SockstatFamilyRow,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_text(path: str, logger: logging.Logger | None) -> str | None:
    """Read a /proc/net file as text. Returns None on any error."""
    try:
        with open(path, "r") as fh:
            return fh.read()
    except (OSError, PermissionError) as exc:
        if logger is not None:
            logger.debug("linux_connectivity: cannot read %s: %s", path, exc)
        return None


def _proc_net_hex_u32_to_bytes(hex_str: str) -> bytes:
    """Convert a /proc/net hex u32 (little-endian) to network-order bytes.

    ``/proc/net/route`` stores addresses as 8-char hex of the u32 read in
    little-endian form. For 127.0.0.1 the file shows ``"0100007F"``, and
    ``int("0100007F", 16)`` gives ``0x0100007F``. Packing that little-endian
    yields ``b"\\x7f\\x00\\x00\\x01"``, which is network-byte-order for
    127.0.0.1 — the shape we want on the wire.
    """
    return struct.pack("<I", int(hex_str, 16))


# ---------------------------------------------------------------------------
# /proc/net/route — IPv4 routing table
# ---------------------------------------------------------------------------


def parse_ipv4_routes(
    path: str, logger: logging.Logger | None = None,
) -> list[IPv4RouteRow]:
    """Parse ``/proc/net/route`` into IPv4RouteRow list."""
    text = _read_text(path, logger)
    if text is None:
        return []

    rows: list[IPv4RouteRow] = []
    lines = text.splitlines()
    if len(lines) < 2:
        return rows

    for line in lines[1:]:  # skip header
        fields = line.split()
        if len(fields) < 11:
            continue
        try:
            row = IPv4RouteRow(
                iface=fields[0],
                dest=_proc_net_hex_u32_to_bytes(fields[1]),
                gateway=_proc_net_hex_u32_to_bytes(fields[2]),
                flags=int(fields[3], 16),
                metric=int(fields[6]),
                mask=_proc_net_hex_u32_to_bytes(fields[7]),
                mtu=int(fields[8]),
            )
        except (ValueError, IndexError):
            continue
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# /proc/net/ipv6_route — IPv6 routing table (no header line)
# ---------------------------------------------------------------------------


def parse_ipv6_routes(
    path: str, logger: logging.Logger | None = None,
) -> list[IPv6RouteRow]:
    """Parse ``/proc/net/ipv6_route`` into IPv6RouteRow list."""
    text = _read_text(path, logger)
    if text is None:
        return []

    rows: list[IPv6RouteRow] = []
    for line in text.splitlines():
        fields = line.split()
        # Format: dest dest_prefix src src_prefix next_hop metric refcnt use flags iface
        if len(fields) < 10:
            continue
        try:
            dest = bytes.fromhex(fields[0])
            dest_prefix = int(fields[1], 16)
            next_hop = bytes.fromhex(fields[4])
            metric = int(fields[5], 16)
            flags = int(fields[8], 16)
            iface = fields[9]
            if len(dest) != 16 or len(next_hop) != 16:
                continue
        except (ValueError, IndexError):
            continue
        rows.append(IPv6RouteRow(
            iface=iface,
            dest=dest,
            dest_prefix=dest_prefix,
            next_hop=next_hop,
            metric=metric,
            flags=flags,
        ))

    return rows


# ---------------------------------------------------------------------------
# /proc/net/arp — IPv4 ARP cache
# ---------------------------------------------------------------------------


def _parse_mac(mac_str: str) -> bytes | None:
    """Parse ``aa:bb:cc:dd:ee:ff`` into 6 bytes. Returns None on error."""
    parts = mac_str.split(":")
    if len(parts) != 6:
        return None
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        return None


def parse_arp_entries(
    path: str, logger: logging.Logger | None = None,
) -> list[ArpEntryRow]:
    """Parse ``/proc/net/arp`` into ArpEntryRow list.

    Rows whose hw_addr is all zeros (incomplete neighbour entries) are
    dropped.
    """
    text = _read_text(path, logger)
    if text is None:
        return []

    rows: list[ArpEntryRow] = []
    lines = text.splitlines()
    if len(lines) < 2:
        return rows

    for line in lines[1:]:  # skip header
        fields = line.split()
        if len(fields) < 6:
            continue
        ip_str, hw_type_str, flags_str, mac_str, _mask, iface = fields[:6]
        hw_addr = _parse_mac(mac_str)
        if hw_addr is None or hw_addr == b"\x00" * 6:
            continue
        try:
            ip_bytes = socket.inet_aton(ip_str)
            hw_type = int(hw_type_str, 16)
            flags = int(flags_str, 16)
        except (OSError, ValueError):
            continue
        rows.append(ArpEntryRow(
            family=0x02,
            ip=ip_bytes,
            hw_type=hw_type,
            flags=flags,
            hw_addr=hw_addr,
            iface=iface,
        ))

    return rows


# ---------------------------------------------------------------------------
# /proc/net/packet — raw packet sockets
# ---------------------------------------------------------------------------


def parse_packet_sockets(
    path: str,
    inode_pid: dict[int, int],
    logger: logging.Logger | None = None,
) -> list[PacketSocketRow]:
    """Parse ``/proc/net/packet``. Attributes pid via ``inode_pid`` map."""
    text = _read_text(path, logger)
    if text is None:
        return []

    rows: list[PacketSocketRow] = []
    lines = text.splitlines()
    if len(lines) < 2:
        return rows

    for line in lines[1:]:  # skip header
        fields = line.split()
        # sk RefCnt Type Proto Iface R Rmem User Inode
        if len(fields) < 9:
            continue
        try:
            proto = int(fields[3], 16)
            iface_index = int(fields[4])
            rmem = int(fields[6])
            user = int(fields[7])
            inode = int(fields[8])
        except (ValueError, IndexError):
            continue
        pid = inode_pid.get(inode, 0)
        rows.append(PacketSocketRow(
            pid=pid,
            inode=inode,
            proto=proto,
            iface_index=iface_index,
            user=user,
            rmem=rmem,
        ))

    return rows


# ---------------------------------------------------------------------------
# /proc/net/dev — per-interface counters
# ---------------------------------------------------------------------------


def parse_netdev_stats(
    path: str, logger: logging.Logger | None = None,
) -> list[NetdevStatsRow]:
    """Parse ``/proc/net/dev``.

    We keep rx_bytes/packets/errs/drop (counters 0..3) and
    tx_bytes/packets/errs/drop (counters 8..11).
    """
    text = _read_text(path, logger)
    if text is None:
        return []

    rows: list[NetdevStatsRow] = []
    lines = text.splitlines()
    if len(lines) < 3:  # two header lines + at least one data row
        return rows

    for line in lines[2:]:
        if ":" not in line:
            continue
        iface_part, _, counters_part = line.partition(":")
        iface = iface_part.strip()
        counters = counters_part.split()
        if len(counters) < 16:
            continue
        try:
            row = NetdevStatsRow(
                iface=iface,
                rx_bytes=int(counters[0]),
                rx_packets=int(counters[1]),
                rx_errs=int(counters[2]),
                rx_drop=int(counters[3]),
                tx_bytes=int(counters[8]),
                tx_packets=int(counters[9]),
                tx_errs=int(counters[10]),
                tx_drop=int(counters[11]),
            )
        except (ValueError, IndexError):
            continue
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# /proc/net/sockstat (+ sockstat6) — aggregate socket counts
# ---------------------------------------------------------------------------


# Section tag values for SockstatFamilyRow.family (see dataclass docstring).
_SOCKSTAT_TAGS_V4 = {
    "TCP": 0x02,
    "UDP": 0x11,
    "RAW": 0x03,
    "FRAG": 0x04,
}
_SOCKSTAT_TAGS_V6 = {
    "TCP6": 0x0A,
    "UDP6": 0x0B,
    "RAW6": 0x83,
    "FRAG6": 0x84,
}


def _parse_kv_line(rest: str) -> dict[str, int]:
    """Turn ``"inuse 10 orphan 0 alloc 15 mem 2"`` into a dict."""
    tokens = rest.split()
    out: dict[str, int] = {}
    for i in range(0, len(tokens) - 1, 2):
        key = tokens[i]
        try:
            out[key] = int(tokens[i + 1])
        except ValueError:
            continue
    return out


def _parse_sockstat_file(
    text: str, tag_map: dict[str, int],
) -> list[SockstatFamilyRow]:
    rows: list[SockstatFamilyRow] = []
    for line in text.splitlines():
        head, _, rest = line.partition(":")
        head = head.strip()
        if head == "sockets":
            kv = _parse_kv_line(rest)
            rows.append(SockstatFamilyRow(
                family=0xFF,
                in_use=kv.get("used", 0),
            ))
            continue
        if head not in tag_map:
            continue
        kv = _parse_kv_line(rest)
        rows.append(SockstatFamilyRow(
            family=tag_map[head],
            in_use=kv.get("inuse", 0),
            alloc=kv.get("alloc", 0),
            mem=kv.get("mem", kv.get("memory", 0)),
        ))
    return rows


def parse_sockstat(
    path_v4: str,
    path_v6: str | None = None,
    logger: logging.Logger | None = None,
) -> list[SockstatFamilyRow]:
    """Parse ``/proc/net/sockstat`` (and optionally ``sockstat6``)."""
    rows: list[SockstatFamilyRow] = []

    text_v4 = _read_text(path_v4, logger)
    if text_v4 is not None:
        rows.extend(_parse_sockstat_file(text_v4, _SOCKSTAT_TAGS_V4))

    if path_v6 is not None:
        text_v6 = _read_text(path_v6, logger)
        if text_v6 is not None:
            rows.extend(_parse_sockstat_file(text_v6, _SOCKSTAT_TAGS_V6))

    return rows


# ---------------------------------------------------------------------------
# /proc/net/snmp and /proc/net/netstat — MIB counters
# ---------------------------------------------------------------------------


def _parse_mib_file(
    text: str, max_per_mib: int,
) -> list[SnmpCounterRow]:
    rows: list[SnmpCounterRow] = []
    lines = text.splitlines()
    # Pair header + data lines with matching MIB prefix.
    i = 0
    while i + 1 < len(lines):
        header_line = lines[i]
        data_line = lines[i + 1]
        hprefix, _, hrest = header_line.partition(":")
        dprefix, _, drest = data_line.partition(":")
        if hprefix and hprefix == dprefix and hrest and drest:
            names = hrest.split()
            values = drest.split()
            mib = hprefix.strip()
            emitted = 0
            for name, value_str in zip(names, values):
                if emitted >= max_per_mib:
                    break
                try:
                    value = int(value_str)
                except ValueError:
                    continue
                rows.append(SnmpCounterRow(
                    mib=mib,
                    counter=name,
                    value=value,
                ))
                emitted += 1
            i += 2
        else:
            i += 1
    return rows


def parse_snmp_counters(
    snmp_path: str,
    netstat_path: str | None = None,
    logger: logging.Logger | None = None,
    max_per_mib: int = 50,
) -> list[SnmpCounterRow]:
    """Parse ``/proc/net/snmp`` (+ optional ``/proc/net/netstat``)."""
    rows: list[SnmpCounterRow] = []

    snmp_text = _read_text(snmp_path, logger)
    if snmp_text is not None:
        rows.extend(_parse_mib_file(snmp_text, max_per_mib))

    if netstat_path is not None:
        netstat_text = _read_text(netstat_path, logger)
        if netstat_text is not None:
            rows.extend(_parse_mib_file(netstat_text, max_per_mib))

    return rows
