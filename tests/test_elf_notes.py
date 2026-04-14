"""Tests for ``memslicer.acquirer.elf_notes``.

Covers:
- Happy-path ``NT_GNU_BUILD_ID`` extraction on synthetic ELF64 input.
- Negative paths: bad magic, no PT_NOTE, no GNU note, truncated header.
- ``source`` tag pass-through.
- Hypothesis fuzz: parser never raises on adversarial input.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hypothesis import given, settings, strategies as st

from memslicer.acquirer.elf_notes import (
    ELF_MAGIC,
    extract_build_id,
    parse_elf_notes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data + (b"\x00" * (4 - rem) if rem else b"")


def _build_gnu_note(build_id: bytes) -> bytes:
    """Build a single NT_GNU_BUILD_ID note entry."""
    name = b"GNU\x00"
    header = struct.pack("<III", len(name), len(build_id), 3)
    return header + _pad4(name) + _pad4(build_id)


def _build_generic_note(vendor: bytes, ntype: int, desc: bytes) -> bytes:
    name = vendor + b"\x00"
    header = struct.pack("<III", len(name), len(desc), ntype)
    return header + _pad4(name) + _pad4(desc)


def _make_elf64_with_notes(note_payload: bytes) -> bytes:
    """Construct a minimal valid ELF64 LE file with one PT_NOTE segment."""
    eh_size = 64
    ph_size = 56
    ph_offset = eh_size
    note_offset = ph_offset + ph_size

    # ELF64 header (16B e_ident + 48B remainder)
    e_ident = (
        ELF_MAGIC
        + bytes([2])  # EI_CLASS = ELFCLASS64
        + bytes([1])  # EI_DATA = little-endian
        + bytes([1])  # EI_VERSION
        + bytes([0]) * 9  # padding
    )
    header_tail = struct.pack(
        "<HHIQQQIHHHHHH",
        2,                  # e_type = ET_EXEC
        0x3E,               # e_machine = x86_64
        1,                  # e_version
        0,                  # e_entry
        ph_offset,          # e_phoff
        0,                  # e_shoff
        0,                  # e_flags
        eh_size,            # e_ehsize
        ph_size,            # e_phentsize
        1,                  # e_phnum
        0,                  # e_shentsize
        0,                  # e_shnum
        0,                  # e_shstrndx
    )
    elf_header = e_ident + header_tail
    assert len(elf_header) == eh_size

    ph_note = struct.pack(
        "<IIQQQQQQ",
        4,                   # p_type = PT_NOTE
        4,                   # p_flags = PF_R
        note_offset,         # p_offset
        0,                   # p_vaddr
        0,                   # p_paddr
        len(note_payload),   # p_filesz
        len(note_payload),   # p_memsz
        1,                   # p_align
    )
    assert len(ph_note) == ph_size

    return elf_header + ph_note + note_payload


def _make_elf64_no_ph() -> bytes:
    """Minimal ELF64 with zero program headers."""
    e_ident = (
        ELF_MAGIC
        + bytes([2, 1, 1]) + bytes([0]) * 9
    )
    header_tail = struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0, 0, 0, 0, 64, 56, 0, 0, 0, 0,
    )
    return e_ident + header_tail


# ---------------------------------------------------------------------------
# parse_elf_notes
# ---------------------------------------------------------------------------


def test_parse_elf_notes_single_gnu_build_id_le():
    bid = bytes(range(20))
    payload = _build_gnu_note(bid)
    notes = list(parse_elf_notes(payload, is_64bit=True, little_endian=True))
    assert len(notes) == 1
    name, ntype, desc = notes[0]
    assert name == "GNU"
    assert ntype == 3
    assert desc == bid


def test_parse_elf_notes_multiple_entries():
    bid = bytes(range(20))
    other = _build_generic_note(b"CORE", 1, b"\x01\x02\x03\x04")
    payload = _build_gnu_note(bid) + other
    notes = list(parse_elf_notes(payload, is_64bit=True, little_endian=True))
    assert len(notes) == 2
    names = [n[0] for n in notes]
    assert "GNU" in names
    assert "CORE" in names


def test_parse_elf_notes_empty_input():
    assert list(parse_elf_notes(b"", is_64bit=True, little_endian=True)) == []


def test_parse_elf_notes_truncated_mid_note():
    bid = bytes(range(20))
    payload = _build_gnu_note(bid)[:16]  # truncated mid-name
    notes = list(parse_elf_notes(payload, is_64bit=True, little_endian=True))
    # Parser terminates cleanly rather than raising.
    assert notes == [] or all(isinstance(n, tuple) for n in notes)


# ---------------------------------------------------------------------------
# extract_build_id
# ---------------------------------------------------------------------------


def test_extract_build_id_full_elf64_le():
    bid = bytes(range(20))
    elf = _make_elf64_with_notes(_build_gnu_note(bid))
    result = extract_build_id(elf)
    assert result is not None
    assert result == (bid, "bridge")


def test_extract_build_id_source_marker_override():
    bid = b"\xaa" * 20
    elf = _make_elf64_with_notes(_build_gnu_note(bid))
    result = extract_build_id(elf, source="captured_region")
    assert result == (bid, "captured_region")


def test_extract_build_id_no_pt_note():
    elf = _make_elf64_no_ph()
    assert extract_build_id(elf) is None


def test_extract_build_id_pt_note_without_build_id():
    other = _build_generic_note(b"CORE", 1, b"\x00" * 8)
    elf = _make_elf64_with_notes(other)
    assert extract_build_id(elf) is None


def test_extract_build_id_bad_magic():
    assert extract_build_id(b"NOPE" + b"\x00" * 80) is None


def test_extract_build_id_truncated_header():
    assert extract_build_id(b"\x7fELF" + b"\x00" * 16) is None


@settings(deadline=None, max_examples=200)
@given(st.binary(max_size=8192))
def test_extract_build_id_hypothesis_never_raises(data):
    try:
        extract_build_id(data)
    except Exception as exc:  # pragma: no cover - proven by the test
        pytest.fail(f"extract_build_id raised on {data!r}: {exc}")


@settings(deadline=None, max_examples=200)
@given(st.binary(max_size=8192))
def test_parse_elf_notes_hypothesis_never_raises(data):
    try:
        list(parse_elf_notes(data, is_64bit=True, little_endian=True))
        list(parse_elf_notes(data, is_64bit=False, little_endian=False))
    except Exception as exc:  # pragma: no cover
        pytest.fail(f"parse_elf_notes raised on {data!r}: {exc}")
