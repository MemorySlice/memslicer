"""Path B / Path C unit tests for ``build_id_post`` (P1.6.2).

Covers the pure-function side of the D7 hybrid build-id extraction:
``populate_from_regions`` + the low-level helpers
(``_encode_native_blob``, ``_detect_module_flags``).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import blake3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.build_id_post import (
    FLAG_DELETED,
    FLAG_MEMFD,
    FLAG_UNLINKED,
    SOURCE_BRIDGE,
    SOURCE_CAPTURED_REGION,
    SOURCE_NONE,
    SOURCE_RETROACTIVE,
    _detect_module_flags,
    _encode_native_blob,
    populate_from_regions,
)
from memslicer.acquirer.elf_notes import ELF_MAGIC
from memslicer.msl.constants import PageState
from memslicer.msl.types import MemoryRegion, ModuleEntry


# ---------------------------------------------------------------------------
# Synthetic ELF64 with a GNU build-id note (borrowed pattern from
# tests/test_elf_notes.py — small duplication is acceptable here rather
# than forcing a cross-test-module import).
# ---------------------------------------------------------------------------


def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data + (b"\x00" * (4 - rem) if rem else b"")


def _build_gnu_note(build_id: bytes) -> bytes:
    name = b"GNU\x00"
    header = struct.pack("<III", len(name), len(build_id), 3)
    return header + _pad4(name) + _pad4(build_id)


def _make_elf64_with_build_id(build_id: bytes) -> bytes:
    eh_size = 64
    ph_size = 56
    ph_offset = eh_size
    note_offset = ph_offset + ph_size
    note_payload = _build_gnu_note(build_id)

    e_ident = (
        ELF_MAGIC
        + bytes([2, 1, 1])
        + bytes([0]) * 9
    )
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
    # Pad the ELF so it's >= 4096 bytes (matches the real bridge/page
    # read pattern, and guarantees the length-gate inside _apply_extraction
    # never short-circuits on test input).
    if len(elf) < 4096:
        elf += b"\x00" * (4096 - len(elf))
    return elf


_KNOWN_BUILD_ID = bytes(range(20))
_FAKE_ELF = _make_elf64_with_build_id(_KNOWN_BUILD_ID)


def _make_region(
    base_addr: int,
    data: bytes,
    *,
    state: PageState = PageState.CAPTURED,
    page_size: int = 4096,
) -> MemoryRegion:
    return MemoryRegion(
        base_addr=base_addr,
        region_size=page_size,
        protection=5,  # r-x
        page_size=page_size,
        page_states=[state],
        page_data_chunks=[data] if data else [],
    )


# ---------------------------------------------------------------------------
# _encode_native_blob / _detect_module_flags
# ---------------------------------------------------------------------------


class TestNativeBlobLayout:
    def test_native_blob_with_full_build_id(self):
        blob = _encode_native_blob(b"\x01" * 20, SOURCE_BRIDGE, FLAG_DELETED)
        assert len(blob) == 24
        assert blob[0] == 20                 # build_id_len
        assert blob[1] == SOURCE_BRIDGE
        assert blob[2] == FLAG_DELETED
        assert blob[3] == 0                  # reserved
        assert blob[4:] == b"\x01" * 20

    def test_native_blob_with_empty_build_id(self):
        blob = _encode_native_blob(b"", SOURCE_NONE, 0)
        assert len(blob) == 4
        assert blob == b"\x00\x00\x00\x00"

    def test_native_blob_with_md5_length(self):
        blob = _encode_native_blob(b"\x02" * 16, SOURCE_RETROACTIVE, 0)
        assert len(blob) == 20
        assert blob[0] == 16
        assert blob[1] == SOURCE_RETROACTIVE


class TestDetectModuleFlags:
    def test_normal_path(self):
        assert _detect_module_flags("/usr/lib/libfoo.so") == 0

    def test_deleted_path(self):
        flags = _detect_module_flags("/usr/lib/libfoo.so (deleted)")
        assert flags & FLAG_DELETED
        assert flags & FLAG_UNLINKED

    def test_memfd_path(self):
        assert _detect_module_flags("memfd:payload") & FLAG_MEMFD
        assert _detect_module_flags("/memfd:hidden") & FLAG_MEMFD

    def test_memfd_nested_path(self):
        # Common kernel form: "/memfd:name (deleted)".
        flags = _detect_module_flags("/memfd:name (deleted)")
        assert flags & FLAG_MEMFD
        assert flags & FLAG_DELETED


# ---------------------------------------------------------------------------
# populate_from_regions — Path B / Path C
# ---------------------------------------------------------------------------


class TestPopulateFromRegions:
    def test_populates_from_captured_region(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = _make_region(0x400000, _FAKE_ELF)

        populate_from_regions([mod], [region])

        assert mod.native_blob
        assert mod.native_blob[0] == 20
        assert mod.native_blob[1] == SOURCE_CAPTURED_REGION
        assert mod.native_blob[4:4 + 20] == _KNOWN_BUILD_ID
        assert mod.disk_hash == blake3.blake3(_FAKE_ELF[:4096]).digest()

    def test_skips_failed_page(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = _make_region(0x400000, _FAKE_ELF, state=PageState.FAILED)

        populate_from_regions([mod], [region])
        assert mod.native_blob == b""

    def test_skips_already_populated(self):
        preset = b"\x04\x01\x00\x00\xff\xff\xff\xff"
        mod = ModuleEntry(
            base_addr=0x400000, path="/usr/bin/app", native_blob=preset,
        )
        region = _make_region(0x400000, _FAKE_ELF)
        populate_from_regions([mod], [region])
        assert mod.native_blob == preset

    def test_no_matching_region(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = _make_region(0x999000, _FAKE_ELF)  # different base
        populate_from_regions([mod], [region])
        assert mod.native_blob == b""

    def test_retroactive_source_marker(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = _make_region(0x400000, _FAKE_ELF)
        populate_from_regions([mod], [region], source_id=SOURCE_RETROACTIVE)
        assert mod.native_blob[1] == SOURCE_RETROACTIVE

    def test_handles_empty_region_list(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        populate_from_regions([mod], [])
        assert mod.native_blob == b""

    def test_handles_empty_page_data_chunks(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = MemoryRegion(
            base_addr=0x400000, region_size=4096, page_size=4096,
            page_states=[PageState.CAPTURED], page_data_chunks=[],
        )
        populate_from_regions([mod], [region])
        assert mod.native_blob == b""

    def test_handles_empty_chunk_bytes(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = MemoryRegion(
            base_addr=0x400000, region_size=4096, page_size=4096,
            page_states=[PageState.CAPTURED], page_data_chunks=[b""],
        )
        populate_from_regions([mod], [region])
        assert mod.native_blob == b""

    def test_too_short_data_skipped(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        region = _make_region(0x400000, b"short")
        populate_from_regions([mod], [region])
        assert mod.native_blob == b""

    def test_malformed_elf_populates_empty_build_id(self):
        mod = ModuleEntry(base_addr=0x400000, path="/usr/bin/app")
        # 4 KiB of zeros -> parser returns None but we still record
        # disk_hash + empty build-id so we have *some* anchor.
        region = _make_region(0x400000, b"\x00" * 4096)
        populate_from_regions([mod], [region])
        # native_blob: build_id_len=0 + source=CAPTURED_REGION(4) + flags=0 + reserved=0
        assert mod.native_blob == bytes([0, SOURCE_CAPTURED_REGION, 0, 0])
        assert mod.disk_hash == blake3.blake3(b"\x00" * 4096).digest()
