"""Pure-Python ELF note parser used for ``NT_GNU_BUILD_ID`` extraction.

Shared helper for P1.6.1 (kernel ``.notes`` parsing on Linux) and P1.6.2
(per-module native_blob build-id extraction). The parser is defensive by
construction: adversarial or truncated input must never raise — any
bounds violation terminates iteration / returns ``None``.

No external dependencies; only ``struct`` and typing from the stdlib.
"""
from __future__ import annotations

import struct
from typing import Iterator

ELF_MAGIC = b"\x7fELF"

_EI_CLASS = 4
_EI_DATA = 5

_ELFCLASS32 = 1
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_ELFDATA2MSB = 2

_PT_NOTE = 4
_NT_GNU_BUILD_ID = 3

# Minimum bytes required before we can safely read the e_phoff/e_phnum
# fields. ELF32 header is 52B, ELF64 header is 64B.
_MIN_ELF32 = 52
_MIN_ELF64 = 64


def parse_elf_notes(
    note_bytes: bytes,
    is_64bit: bool,  # noqa: ARG001 — note layout is the same for 32/64
    little_endian: bool,
) -> Iterator[tuple[str, int, bytes]]:
    """Yield ``(name, type, desc)`` triples from a PT_NOTE segment payload.

    ``name`` is the UTF-8 vendor name (e.g. ``"GNU"``) with the trailing
    NUL stripped. ``type`` is the ELF note type. ``desc`` is the raw
    descriptor bytes.

    Note layout (identical for ELF32 and ELF64 on all common
    architectures): ``n_namesz (u32)`` + ``n_descsz (u32)`` +
    ``n_type (u32)`` + ``name`` (padded to 4B) + ``desc`` (padded to 4B).

    The ``is_64bit`` flag is accepted for API symmetry — the note format
    itself is independent of ELF class on the platforms we care about.
    Malformed entries terminate iteration without raising.
    """
    endian = "<" if little_endian else ">"
    header_fmt = endian + "III"
    header_size = struct.calcsize(header_fmt)

    offset = 0
    total = len(note_bytes)
    while offset + header_size <= total:
        try:
            namesz, descsz, ntype = struct.unpack_from(
                header_fmt, note_bytes, offset,
            )
        except struct.error:
            return
        offset += header_size

        # Guard against attacker-controlled sizes before we index.
        if namesz > total or descsz > total:
            return
        name_end = offset + namesz
        if name_end > total:
            return
        name_raw = note_bytes[offset:name_end]
        # Strip trailing NUL(s) if present, decode permissively.
        name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")

        # name is padded to 4-byte alignment
        padded_namesz = (namesz + 3) & ~3
        desc_start = offset + padded_namesz
        desc_end = desc_start + descsz
        if desc_end > total:
            return
        desc = bytes(note_bytes[desc_start:desc_end])

        yield name, int(ntype), desc

        padded_descsz = (descsz + 3) & ~3
        offset = desc_start + padded_descsz


def extract_build_id(
    elf_bytes: bytes,
    *,
    source: str = "bridge",
) -> tuple[bytes, str] | None:
    """Extract ``NT_GNU_BUILD_ID`` from the front of an ELF file/mapping.

    Returns ``(build_id_raw, source)`` on success, where ``build_id_raw``
    is the raw note descriptor (typically 16 or 20 bytes). ``source`` is
    passed through from the caller — P1.6.2 uses this tag to distinguish
    live vs post-processing extraction paths. Valid markers per the plan:
    ``"bridge"``, ``"map_files"``, ``"on_disk"``, ``"captured_region"``,
    ``"retroactive"``. This function does not validate the value; it is
    the caller's responsibility to choose the right marker.

    Returns ``None`` for:
      - Input shorter than the minimum ELF header.
      - Bad ELF magic.
      - Unknown ``EI_CLASS`` / ``EI_DATA`` byte.
      - Missing or mis-sized program header table.
      - No ``PT_NOTE`` segment.
      - ``PT_NOTE`` present but no ``NT_GNU_BUILD_ID`` entry.

    Never raises on adversarial input (Hypothesis-tested).
    """
    if not isinstance(elf_bytes, (bytes, bytearray, memoryview)):
        return None
    data = bytes(elf_bytes)
    if len(data) < _MIN_ELF32:
        return None
    if data[:4] != ELF_MAGIC:
        return None

    ei_class = data[_EI_CLASS]
    ei_data = data[_EI_DATA]
    if ei_class not in (_ELFCLASS32, _ELFCLASS64):
        return None
    if ei_data not in (_ELFDATA2LSB, _ELFDATA2MSB):
        return None

    is_64bit = ei_class == _ELFCLASS64
    little_endian = ei_data == _ELFDATA2LSB
    endian = "<" if little_endian else ">"

    try:
        if is_64bit:
            if len(data) < _MIN_ELF64:
                return None
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
            ph_fmt = endian + "IIQQQQQQ"
            ph_size = 56
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
            # ELF32 program header layout differs from ELF64.
            ph_fmt = endian + "IIIIIIII"
            ph_size = 32
    except struct.error:
        return None

    if e_phentsize < ph_size or e_phnum == 0:
        return None
    # Cap the total program-header-table size against the input length
    # so an attacker-controlled e_phnum can't walk us off the buffer.
    total_ph_bytes = e_phentsize * e_phnum
    if total_ph_bytes > len(data):
        return None
    if e_phoff + total_ph_bytes > len(data):
        return None

    for i in range(e_phnum):
        entry_off = e_phoff + i * e_phentsize
        try:
            if is_64bit:
                (p_type, _p_flags, p_offset, _p_vaddr, _p_paddr,
                 p_filesz, _p_memsz, _p_align) = struct.unpack_from(
                    ph_fmt, data, entry_off,
                )
            else:
                (p_type, p_offset, _p_vaddr, _p_paddr, p_filesz,
                 _p_memsz, _p_flags, _p_align) = struct.unpack_from(
                    ph_fmt, data, entry_off,
                )
        except struct.error:
            return None

        if p_type != _PT_NOTE:
            continue
        if p_offset + p_filesz > len(data):
            return None

        note_bytes = data[p_offset:p_offset + p_filesz]
        for name, ntype, desc in parse_elf_notes(
            note_bytes, is_64bit=is_64bit, little_endian=little_endian,
        ):
            if ntype == _NT_GNU_BUILD_ID and name == "GNU" and desc:
                return desc, source

    return None


__all__ = ("extract_build_id", "parse_elf_notes", "ELF_MAGIC")
