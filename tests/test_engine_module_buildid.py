"""Path A live build-id extraction tests (P1.6.2).

Drives :func:`memslicer.acquirer.build_id_post.populate_from_bridge`
with a ``MagicMock`` bridge and a synthetic ELF fixture. The engine
hook is a one-line wrapper over this function, so these tests also
cover the engine's contract end-to-end.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import blake3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.build_id_post import (
    FLAG_DELETED,
    FLAG_MEMFD,
    FLAG_UNLINKED,
    SOURCE_BRIDGE,
    populate_from_bridge,
)
from memslicer.acquirer.elf_notes import ELF_MAGIC
from memslicer.msl.types import ModuleEntry


# ---------------------------------------------------------------------------
# Synthetic ELF fixture
# ---------------------------------------------------------------------------


def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data + (b"\x00" * (4 - rem) if rem else b"")


def _gnu_note(build_id: bytes) -> bytes:
    name = b"GNU\x00"
    return struct.pack("<III", len(name), len(build_id), 3) + _pad4(name) + _pad4(build_id)


def _fake_elf(build_id: bytes = bytes(range(20))) -> bytes:
    eh_size = 64
    ph_size = 56
    ph_offset = eh_size
    note_offset = ph_offset + ph_size
    note_payload = _gnu_note(build_id)

    e_ident = ELF_MAGIC + bytes([2, 1, 1]) + bytes([0]) * 9
    header_tail = struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0, ph_offset, 0, 0, eh_size, ph_size, 1, 0, 0, 0,
    )
    ph_note = struct.pack(
        "<IIQQQQQQ",
        4, 4, note_offset, 0, 0,
        len(note_payload), len(note_payload), 1,
    )
    elf = e_ident + header_tail + ph_note + note_payload
    if len(elf) < 4096:
        elf += b"\x00" * (4096 - len(elf))
    return elf


_BID = bytes(range(20))
_ELF = _fake_elf(_BID)


# ---------------------------------------------------------------------------
# Path A tests
# ---------------------------------------------------------------------------


class TestPopulateFromBridge:
    def _bridge(self, data):
        bridge = MagicMock()
        bridge.read_memory.return_value = data
        return bridge

    def test_populates_native_blob(self):
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_bridge([entry], self._bridge(_ELF))

        assert len(entry.native_blob) == 24
        assert entry.native_blob[0] == 20
        assert entry.native_blob[1] == SOURCE_BRIDGE
        assert entry.native_blob[2] == 0   # no special flags on this path
        assert entry.native_blob[4:] == _BID

    def test_disk_hash_matches(self):
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_bridge([entry], self._bridge(_ELF))

        # The helper hashes exactly the bytes it read from the bridge.
        assert entry.disk_hash == blake3.blake3(_ELF).digest()

    def test_bridge_read_exception_leaves_empty(self):
        bridge = MagicMock()
        bridge.read_memory.side_effect = RuntimeError("ptrace denied")
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")

        populate_from_bridge([entry], bridge)

        assert entry.native_blob == b""

    def test_bridge_returns_none_leaves_empty(self):
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_bridge([entry], self._bridge(None))
        assert entry.native_blob == b""

    def test_skips_entries_with_existing_blob(self):
        preset = b"\x00\x00\x00\x00"
        entry = ModuleEntry(
            base_addr=0x400000, path="/usr/bin/app", native_blob=preset,
        )
        bridge = self._bridge(_ELF)
        populate_from_bridge([entry], bridge)

        # Neither blob nor a read call should have happened.
        assert entry.native_blob == preset
        bridge.read_memory.assert_not_called()

    def test_detects_memfd_flag(self):
        entry = ModuleEntry(base_addr=0x400000, path="memfd:hidden")
        populate_from_bridge([entry], self._bridge(_ELF))

        assert entry.native_blob[2] & FLAG_MEMFD

    def test_detects_deleted_flag(self):
        entry = ModuleEntry(
            base_addr=0x400000, path="/usr/lib/libfoo.so (deleted)",
        )
        populate_from_bridge([entry], self._bridge(_ELF))

        flags_byte = entry.native_blob[2]
        assert flags_byte & FLAG_DELETED
        assert flags_byte & FLAG_UNLINKED

    def test_malformed_elf_no_crash(self):
        garbage = b"\xff" * 4096
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_bridge([entry], self._bridge(garbage))

        # native_blob populated with zero-length build-id + hash of the
        # read bytes. No exception.
        assert entry.native_blob == b"\x00\x01\x00\x00"  # len=0, src=bridge
        assert entry.disk_hash == blake3.blake3(garbage).digest()

    def test_multiple_entries_processed(self):
        entries = [
            ModuleEntry(base_addr=0x400000, path="/usr/bin/app"),
            ModuleEntry(base_addr=0x500000, path="/usr/lib/libc.so"),
            ModuleEntry(base_addr=0x600000, path="/usr/lib/libm.so"),
        ]
        populate_from_bridge(entries, self._bridge(_ELF))
        for e in entries:
            assert e.native_blob[4:] == _BID

    def test_bridge_address_and_size_arguments(self):
        bridge = self._bridge(_ELF)
        entry = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_bridge([entry], bridge)
        bridge.read_memory.assert_called_once_with(0x400000, 4096)
