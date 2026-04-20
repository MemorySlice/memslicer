"""Shared helpers for populating ModuleEntry build-ids (P1.6.2 D7).

Three call sites:

  Path A (live):           :func:`populate_from_bridge` — called from
                           ``engine.py`` after
                           ``bridge.enumerate_modules()``. Reads the
                           first 4 KiB of each module via the
                           debugger bridge.
  Path B (post-process):   :func:`populate_from_regions` — called
                           after Path A as a fallback for entries the
                           bridge could not resolve, and also for
                           imported dumps with no live bridge.
  Path C (retroactive):    :func:`populate_from_regions` — called
                           from the ``memslicer-enrich`` CLI on an
                           existing slice, then serialized as a
                           :class:`memslicer.msl.types.ModuleBuildIdManifest`
                           append-only overlay block.

All three paths share the ELF parser in :mod:`memslicer.acquirer.elf_notes`.
"""
from __future__ import annotations

import logging
from typing import Iterable, Protocol

from memslicer.acquirer.elf_notes import extract_build_id
from memslicer.msl.constants import HashAlgo, PageState
from memslicer.msl.integrity import make_hasher
from memslicer.msl.types import MemoryRegion, ModuleEntry


# Flag bits for ModuleEntry.native_blob and ModuleBuildIdRow.flags
FLAG_DELETED = 0x01
FLAG_MEMFD = 0x02
FLAG_ANON_RWX = 0x04
FLAG_UNLINKED = 0x08


# Source markers — must stay in sync with elf_notes.extract_build_id's
# ``source`` kwarg values and the ModuleBuildIdRow.build_id_source field.
SOURCE_NONE = 0
SOURCE_BRIDGE = 1
SOURCE_MAP_FILES = 2
SOURCE_ON_DISK = 3
SOURCE_CAPTURED_REGION = 4
SOURCE_RETROACTIVE = 5


SOURCE_NAME_TO_ID: dict[str, int] = {
    "none": SOURCE_NONE,
    "bridge": SOURCE_BRIDGE,
    "map_files": SOURCE_MAP_FILES,
    "on_disk": SOURCE_ON_DISK,
    "captured_region": SOURCE_CAPTURED_REGION,
    "retroactive": SOURCE_RETROACTIVE,
}

_SOURCE_ID_TO_NAME: dict[int, str] = {v: k for k, v in SOURCE_NAME_TO_ID.items()}


READ_SIZE = 4096  # bytes read per module for build-id + disk_hash


class BridgeProtocol(Protocol):
    """Minimal bridge subset used by :func:`populate_from_bridge`.

    The real :class:`memslicer.acquirer.bridge.DebuggerBridge` satisfies
    this protocol; tests use a ``MagicMock`` shaped to the same surface.
    ``read_memory`` may return ``None`` (documented bridge contract) or
    raise — both are treated as "read failed" and the entry is left
    untouched.
    """

    def read_memory(self, address: int, size: int) -> bytes | None: ...


def _encode_native_blob(
    build_id: bytes,
    source_id: int,
    flags: int,
) -> bytes:
    """Pack the 4-byte header + variable build-id payload into native_blob.

    Layout: ``build_id_len(u8) source_id(u8) flags(u8) reserved(u8)
    build_id[build_id_len]``.
    """
    return bytes([len(build_id), source_id, flags, 0]) + build_id


def _detect_module_flags(path: str) -> int:
    """Infer flags from the module path string.

    Additional flags (e.g. FLAG_ANON_RWX) may be OR'd into the result by
    the caller using region-level protection information.
    """
    flags = 0
    if path.endswith(" (deleted)"):
        flags |= FLAG_DELETED | FLAG_UNLINKED
    # memfd mappings show up with various prefixes across kernels.
    if path.startswith("memfd:") or path.startswith("/memfd:"):
        flags |= FLAG_MEMFD
    last_segment = path.rsplit("/", 1)[-1]
    if last_segment.startswith("memfd:"):
        flags |= FLAG_MEMFD
    return flags


def populate_from_bridge(
    entries: list[ModuleEntry],
    bridge: BridgeProtocol,
    logger: logging.Logger | None = None,
    hash_algo: HashAlgo = HashAlgo.BLAKE3,
) -> list[ModuleEntry]:
    """Path A: live extraction via ``bridge.read_memory``.

    Populates ``native_blob`` and ``disk_hash`` for every entry whose
    ``native_blob`` is currently empty. Mutates and returns the input
    list for call-site chaining.

    Failures are logged at debug level; the entry is left with empty
    ``native_blob`` so a follow-up :func:`populate_from_regions` pass
    can retry from captured bytes.
    """
    log = logger or logging.getLogger("memslicer")
    for entry in entries:
        if entry.native_blob:
            continue
        try:
            data = bridge.read_memory(entry.base_addr, READ_SIZE)
        except Exception as exc:  # noqa: BLE001 — bridge contract is best-effort
            log.debug(
                "bridge.read_memory failed for %s @ 0x%x: %s",
                entry.path, entry.base_addr, exc,
            )
            continue
        if data is None:
            log.debug(
                "bridge.read_memory returned None for %s @ 0x%x",
                entry.path, entry.base_addr,
            )
            continue
        _apply_extraction(entry, data, source_id=SOURCE_BRIDGE, log=log, hash_algo=hash_algo)
    return entries


def populate_from_regions(
    entries: list[ModuleEntry],
    captured_regions: Iterable[MemoryRegion],
    logger: logging.Logger | None = None,
    source_id: int = SOURCE_CAPTURED_REGION,
    hash_algo: HashAlgo = HashAlgo.BLAKE3,
) -> list[ModuleEntry]:
    """Paths B and C: extract from already-captured ``MemoryRegion`` data.

    Builds a ``base_addr -> first-page-bytes`` index from the supplied
    regions, then walks ``entries`` looking for matches. Only regions
    whose first page state is :data:`PageState.CAPTURED` are considered.
    """
    log = logger or logging.getLogger("memslicer")

    region_bytes: dict[int, bytes] = {}
    for region in captured_regions:
        if not region.page_data_chunks:
            continue
        if not region.page_states:
            continue
        if region.page_states[0] != PageState.CAPTURED:
            continue
        first_chunk = region.page_data_chunks[0]
        if not first_chunk:
            continue
        region_bytes[region.base_addr] = first_chunk[:READ_SIZE]

    for entry in entries:
        if entry.native_blob:
            continue
        data = region_bytes.get(entry.base_addr)
        if data is None:
            log.debug(
                "no captured region for module %s @ 0x%x",
                entry.path, entry.base_addr,
            )
            continue
        _apply_extraction(entry, data, source_id=source_id, log=log, hash_algo=hash_algo)
    return entries


def _apply_extraction(
    entry: ModuleEntry,
    data: bytes,
    source_id: int,
    log: logging.Logger,
    hash_algo: HashAlgo = HashAlgo.BLAKE3,
) -> None:
    """Run the ELF parser and populate ``entry`` in place.

    ``native_blob`` always ends up set (possibly with a zero-length
    build-id when extraction failed); ``disk_hash`` is always the
    hash (using the file's selected ``HashAlgo``) of the bytes we
    read, regardless of whether the parser recognised them. Both
    fields serve as collision-resistant anchors for downstream symbol
    lookup even when the build-id is missing.
    """
    if len(data) < 64:
        return

    source_name = _SOURCE_ID_TO_NAME.get(source_id, "bridge")
    result = extract_build_id(data, source=source_name)

    flags = _detect_module_flags(entry.path)

    if result is None:
        build_id = b""
    else:
        build_id, _ = result

    entry.native_blob = _encode_native_blob(build_id, source_id, flags)
    h = make_hasher(hash_algo)
    h.update(data)
    entry.disk_hash = h.digest()


__all__ = (
    "FLAG_DELETED",
    "FLAG_MEMFD",
    "FLAG_ANON_RWX",
    "FLAG_UNLINKED",
    "SOURCE_NONE",
    "SOURCE_BRIDGE",
    "SOURCE_MAP_FILES",
    "SOURCE_ON_DISK",
    "SOURCE_CAPTURED_REGION",
    "SOURCE_RETROACTIVE",
    "SOURCE_NAME_TO_ID",
    "READ_SIZE",
    "BridgeProtocol",
    "populate_from_bridge",
    "populate_from_regions",
)
