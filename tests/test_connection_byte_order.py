"""Pin MSL spec §6.4 little-endian port serialization.

Spec §6.4 explicitly notes that ``LocalPort`` and ``RemotePort`` in the
ConnectionTable block are **structural little-endian uint16** fields,
despite being conceptually derived from network byte order. Producers
must convert before writing; consumers must not assume network byte
order.

This test file exists to prevent regressions in two places:

1. The writer's ``<H`` format specifier in
   :meth:`memslicer.msl.writer.MSLWriter.write_connection_table` must
   stay little-endian. Accidentally flipping to ``>H`` would silently
   corrupt every future MSL and break cross-tool interop.

2. Every producer call site (per-platform collectors + Frida remote
   JS) must hand ``ConnectionEntry.local_port`` / ``remote_port`` a
   **host-order** Python int, not bytes and not big-endian. A
   collector that accidentally stored ``socket.ntohs(…)`` would
   double-swap on little-endian hosts and produce garbage.

Both invariants are pinned by the byte-level assertions below.
"""
from __future__ import annotations

import io
import struct
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.msl.constants import (
    ArchType, BLOCK_HEADER_SIZE, BlockType, OSType,
)
from memslicer.msl.types import ConnectionEntry, FileHeader
from memslicer.msl.writer import MSLWriter
from memslicer.utils.timestamps import now_ns


# ---------------------------------------------------------------------------
# Wire-level test: write a known port, assert the raw bytes are LE
# ---------------------------------------------------------------------------

def _make_header() -> FileHeader:
    return FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=1234,
    )


def _write_single_connection(local_port: int, remote_port: int) -> bytes:
    """Serialize a minimal MSL buffer containing one ConnectionEntry.

    Returns the raw bytes so tests can byte-scan for the port fields
    without a reader (the whole point: we're verifying the wire layout
    itself, not exercising the reader's ability to parse it).
    """
    buf = io.BytesIO()
    writer = MSLWriter(buf, _make_header())

    entry = ConnectionEntry(
        pid=1234,
        family=0x02,          # IPv4
        protocol=0x06,        # TCP
        state=0x01,           # ESTABLISHED
        local_addr=b"\x7f\x00\x00\x01" + b"\x00" * 12,
        local_port=local_port,
        remote_addr=b"\x08\x08\x08\x08" + b"\x00" * 12,
        remote_port=remote_port,
    )
    writer.write_connection_table([entry], parent_uuid=uuid.uuid4().bytes)
    writer.finalize()
    return buf.getvalue()


def _find_block_payload(raw: bytes, block_type: int) -> bytes:
    """Linear-scan the file looking for a block header matching ``block_type``.

    The test does not depend on :mod:`memslicer.msl.reader` because the
    point is to verify byte layout without going through the reader
    (which could mask the bug the test exists to catch).
    """
    offset = 64  # past the 64-byte file header
    while offset + BLOCK_HEADER_SIZE <= len(raw):
        # Block header layout (per writer.py): magic(4) + block_type(2)
        # + flags(2) + payload_len(8) + block_uuid(16) + parent_uuid(16)
        # + timestamp_ns(8) + data_hash(32) + hash_len(4) + block_index(4)
        magic = raw[offset : offset + 4]
        btype = struct.unpack_from("<H", raw, offset + 4)[0]
        payload_len = struct.unpack_from("<Q", raw, offset + 8)[0]
        if btype == block_type:
            return raw[offset + BLOCK_HEADER_SIZE : offset + BLOCK_HEADER_SIZE + payload_len]
        offset += BLOCK_HEADER_SIZE + payload_len
        # Pad to 8-byte boundary
        if payload_len % 8:
            offset += 8 - (payload_len % 8)
    raise AssertionError(f"block type {block_type!r} not found (magic={magic!r})")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPortByteOrder:
    """Spec §6.4: ``LocalPort``/``RemotePort`` are little-endian uint16."""

    def test_port_443_serializes_as_bb_01_little_endian(self) -> None:
        """The canonical regression probe.

        Port ``443`` in host order is ``0x01BB``. Little-endian
        serialization writes ``bb 01``; big-endian would write
        ``01 bb``. If a refactor accidentally flips the writer's ``<H``
        to ``>H`` (or pipes a pre-swapped value in), this test catches
        it immediately with a literal byte-scan.
        """
        raw = _write_single_connection(local_port=443, remote_port=0)
        payload = _find_block_payload(raw, BlockType.ConnectionTable)

        # Preamble: EntryCount(4) + Reserved(4) = 8 bytes
        entry_start = 8

        # ConnectionEntry layout (48 bytes total, per spec Table 22):
        #   pid(4) family(1) protocol(1) state(1) reserved(1)
        #   local_addr(16) local_port(2) reserved2(2)
        #   remote_addr(16) remote_port(2) reserved3(2)
        # → local_port at entry offset +0x18 (24)
        local_port_offset = entry_start + 0x18
        local_port_bytes = payload[local_port_offset : local_port_offset + 2]

        assert local_port_bytes == b"\xbb\x01", (
            f"expected little-endian b'\\xbb\\x01' for port 443, "
            f"got {local_port_bytes!r}"
        )

    def test_port_80_serializes_as_50_00(self) -> None:
        """Another literal probe — single-byte port value, high byte zero."""
        raw = _write_single_connection(local_port=80, remote_port=0)
        payload = _find_block_payload(raw, BlockType.ConnectionTable)
        entry_start = 8

        local_port_bytes = payload[entry_start + 0x18 : entry_start + 0x1A]
        assert local_port_bytes == b"\x50\x00"

    def test_port_65535_serializes_as_ff_ff(self) -> None:
        """Boundary case: the widest uint16 value."""
        raw = _write_single_connection(local_port=65535, remote_port=65535)
        payload = _find_block_payload(raw, BlockType.ConnectionTable)
        entry_start = 8

        assert payload[entry_start + 0x18 : entry_start + 0x1A] == b"\xff\xff"
        # Remote port sits at +0x2C (44) in the same entry.
        assert payload[entry_start + 0x2C : entry_start + 0x2E] == b"\xff\xff"

    def test_remote_port_0x1234(self) -> None:
        """Round-trip a distinct pair so local and remote can't alias."""
        raw = _write_single_connection(local_port=0xABCD, remote_port=0x1234)
        payload = _find_block_payload(raw, BlockType.ConnectionTable)
        entry_start = 8

        assert payload[entry_start + 0x18 : entry_start + 0x1A] == b"\xcd\xab"
        assert payload[entry_start + 0x2C : entry_start + 0x2E] == b"\x34\x12"


class TestCollectorHostOrderContract:
    """Producer-side: collectors must hand host-order ints to ConnectionEntry.

    A host-order contract violation would manifest as the writer
    producing doubly-swapped bytes on LE hosts. These tests don't
    exercise a real collector (no raw packet socket in the test
    environment), but they lock in the dataclass + writer invariant by
    constructing entries the same way a collector would.
    """

    def test_dataclass_accepts_int_and_writer_preserves_host_value(self) -> None:
        entry = ConnectionEntry(local_port=0x01BB, remote_port=0x0035)
        # Basic int type check — stops refactors that would accidentally
        # store bytes here.
        assert isinstance(entry.local_port, int)
        assert isinstance(entry.remote_port, int)

        buf = io.BytesIO()
        w = MSLWriter(buf, _make_header())
        w.write_connection_table([entry], parent_uuid=uuid.uuid4().bytes)
        w.finalize()
        raw = buf.getvalue()

        payload = _find_block_payload(raw, BlockType.ConnectionTable)
        # local_port=0x01BB (443) and remote_port=0x0035 (53) → LE: bb 01, 35 00
        entry_start = 8
        assert payload[entry_start + 0x18 : entry_start + 0x1A] == b"\xbb\x01"
        assert payload[entry_start + 0x2C : entry_start + 0x2E] == b"\x35\x00"
