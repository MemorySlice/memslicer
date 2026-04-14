"""memslicer-enrich — retroactive build-id enrichment CLI (P1.7).

Walks an existing ``.msl`` slice, extracts ELF build-ids from the
captured :class:`~memslicer.msl.types.MemoryRegion` bytes (Path B per
D7 in the P1.6 plan), and appends a
:class:`~memslicer.msl.types.ModuleBuildIdManifest` (Block ``0x005A``)
overlay to a new output file.

P1.6.2 landed the hybrid D7 build-id paths:

* Path A — live extraction via ``bridge.read_memory`` (engine hook).
* Path B — post-processing from captured ``MemoryRegion`` bytes.

P1.7 activates Path C: walk an existing slice, re-run the Path B
logic against its captured regions, and append the manifest block as
an additive overlay. The original bytes in the input slice are
untouched until the new file is written alongside.

Known limitations (P1.7):

* **Integrity chain**: the appended manifest block is written with a
  fresh ``prev_hash`` chain — it does not chain from the hash of the
  preceding bytes in the original slice. The new ``EndOfCapture``'s
  ``file_hash`` is computed over that fresh chain (fresh file header +
  manifest + EoC), NOT over the full enriched file bytes, so a strict
  chain-continuity validator would reject the enriched file on the
  manifest block's ``prev_hash`` mismatch. Adding a
  ``seed_chain_from_bytes`` API to the writer to preserve full chain
  continuity is P2 scope.

* **Encrypted slices**: not supported (the iterator refuses).

* **Full MemoryRegion parse**: the CLI parses only the first page of
  each region, which is sufficient for build-id extraction. A
  Volatility3 plugin reader needs a full parser; that is P2.

* **Path B is CLI-only**: the acquisition engine does NOT run Path B
  as a fallback to Path A during live acquisition. To enrich slices
  captured with a failed Path A, run this CLI post-hoc.
"""
from __future__ import annotations

import io
import logging
import os
import shutil
import struct
import sys
from pathlib import Path

import click

from memslicer.acquirer.build_id_post import (
    SOURCE_RETROACTIVE,
    populate_from_regions,
)
from memslicer.msl.constants import (
    HEADER_SIZE,
    BlockType,
    CompAlgo,
    PageState,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ModuleBuildIdManifest,
    ModuleBuildIdRow,
    ModuleEntry,
)
from memslicer.msl.writer import MSLWriter


_log = logging.getLogger("memslicer.enrich")


# ---------------------------------------------------------------------------
# Minimal payload parsers
# ---------------------------------------------------------------------------


def _parse_module_entry_minimal(payload: bytes) -> ModuleEntry:
    """Parse a ``ModuleEntry`` block payload into a :class:`ModuleEntry`.

    Minimal parser — recovers the fields needed for retroactive
    build-id enrichment: ``base_addr``, ``module_size``, ``path``,
    ``version``, ``disk_hash`` and existing ``native_blob``. Does not
    validate padding or reserved fields.

    Payload layout (see ``MSLWriter._write_module_entry``):

    ``BaseAddr(8) + ModuleSize(8) + PathLen(2) + VersionLen(2) + Reserved(4)
    + Path(var, pad8) + Version(var, pad8) + DiskHash(32)
    + BlobLen(4) + Reserved2(4) + NativeBlob(var)``
    """
    base_addr, module_size, path_len, version_len, _reserved = struct.unpack(
        "<QQHHI", payload[:24],
    )
    offset = 24

    # Path: path_len bytes (INCLUDING the trailing NUL), padded to 8B
    path_raw = payload[offset : offset + path_len]
    path = path_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
    path_padded_len = (path_len + 7) & ~7
    offset += path_padded_len

    # Version: version_len bytes (or 0 when unavailable), padded to 8B
    if version_len > 0:
        version_raw = payload[offset : offset + version_len]
        version = version_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        version_padded_len = (version_len + 7) & ~7
        offset += version_padded_len
    else:
        version = ""

    # disk_hash (32)
    disk_hash = payload[offset : offset + 32]
    offset += 32

    # blob_len (4) + reserved (4)
    blob_len, _reserved2 = struct.unpack("<II", payload[offset : offset + 8])
    offset += 8

    native_blob = payload[offset : offset + blob_len] if blob_len else b""

    return ModuleEntry(
        base_addr=base_addr,
        module_size=module_size,
        path=path,
        version=version,
        disk_hash=disk_hash,
        native_blob=native_blob,
    )


def _parse_memory_region_for_enrich(payload: bytes) -> MemoryRegion:
    """Parse a ``MemoryRegion`` block payload into a thin
    :class:`MemoryRegion` with only the first page populated.

    The enrich CLI needs only the first 4 KiB of each module region to
    extract build-ids; we skip the full ``page_state_map`` /
    ``page_data_chunks`` parse and populate a single-page chunk when
    the first page's state is :data:`PageState.CAPTURED`. This is
    cheap and sufficient for :func:`populate_from_regions`.

    Payload layout (see ``MSLWriter.write_memory_region``):

    ``BaseAddr(8) + RegionSize(8) + Protection(1) + RegionType(1)
    + PageSizeLog2(1) + Reserved(5) + Timestamp(8)
    + PageStateMap(var, pad8) + PageData(var)``
    """
    # Fixed header: 32 bytes (8+8+1+1+1+5+8)
    base_addr, region_size = struct.unpack("<QQ", payload[:16])
    protection = payload[16]
    region_type = payload[17]
    page_size_log2 = payload[18]
    # payload[19:24] are reserved, payload[24:32] is timestamp_ns

    page_size = 1 << page_size_log2
    if page_size <= 0 or region_size % page_size != 0:
        return MemoryRegion(base_addr=base_addr, region_size=region_size)
    num_pages = region_size // page_size

    # PageStateMap: 2 bits per page, MSB-first packing, padded to 8B.
    psm_byte_len = (num_pages + 3) // 4  # 4 pages per byte
    psm_padded_len = (psm_byte_len + 7) & ~7
    psm_bytes = payload[32 : 32 + psm_padded_len]

    if num_pages == 0 or not psm_bytes:
        first_state = PageState.UNMAPPED
    else:
        # Page 0 is in the top two bits of byte 0 (bits 7..6).
        first_state = PageState((psm_bytes[0] >> 6) & 0x3)

    region = MemoryRegion(
        base_addr=base_addr,
        region_size=region_size,
        protection=protection,
        region_type=region_type,
        page_size=page_size,
    )

    if first_state == PageState.CAPTURED:
        raw_start = 32 + psm_padded_len
        first_chunk = payload[raw_start : raw_start + page_size]
        region.page_states = [PageState.CAPTURED]
        region.page_data_chunks = [first_chunk]
    # else: leave page_states / page_data_chunks empty

    return region


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_blob_fields(native_blob: bytes) -> tuple[int, int, int, bytes]:
    """Decode ``ModuleEntry.native_blob``'s 4-byte header + build-id payload.

    Returns ``(build_id_len, source_id, flags, build_id_bytes)``. Returns
    ``(0, 0, 0, b"")`` on an empty or malformed blob.
    """
    if len(native_blob) < 4:
        return (0, 0, 0, b"")
    build_id_len = native_blob[0]
    source_id = native_blob[1]
    flags = native_blob[2]
    # native_blob[3] is reserved
    build_id = native_blob[4 : 4 + build_id_len]
    if len(build_id) != build_id_len:
        return (0, 0, 0, b"")
    return (build_id_len, source_id, flags, build_id)


def _load_slice(
    slice_path: Path,
) -> tuple[list[ModuleEntry], list[MemoryRegion], int]:
    """Read modules, regions, and the EoC start offset from a slice.

    Returns ``(modules, regions, eoc_start_offset)``. Raises
    :class:`FileNotFoundError` / :class:`ValueError` on missing or
    malformed files.
    """
    modules: list[ModuleEntry] = []
    regions: list[MemoryRegion] = []
    eoc_start: int | None = None

    with open(slice_path, "rb") as f:
        for block in iterate_blocks(f):
            if block.block_type == BlockType.ModuleEntry:
                modules.append(_parse_module_entry_minimal(block.payload))
            elif block.block_type == BlockType.MemoryRegion:
                regions.append(_parse_memory_region_for_enrich(block.payload))
            elif block.block_type == BlockType.EndOfCapture:
                eoc_start = block.start_offset

    if eoc_start is None:
        raise ValueError(
            f"slice at {slice_path} has no EndOfCapture block; "
            f"cannot determine where to append the manifest"
        )

    return modules, regions, eoc_start


def _build_manifest_rows(modules: list[ModuleEntry]) -> list[ModuleBuildIdRow]:
    """Convert populated ``ModuleEntry.native_blob`` fields into manifest rows."""
    rows: list[ModuleBuildIdRow] = []
    for mod in modules:
        if not mod.native_blob:
            continue
        build_id_len, source_id, flags, build_id = _extract_blob_fields(
            mod.native_blob,
        )
        if build_id_len == 0:
            continue
        rows.append(
            ModuleBuildIdRow(
                base_addr=mod.base_addr,
                build_id_len=build_id_len,
                build_id_source=source_id,
                flags=flags,
                build_id=build_id,
                disk_hash=mod.disk_hash,
            )
        )
    return rows


def _render_manifest_tail(manifest: ModuleBuildIdManifest) -> bytes:
    """Serialize a manifest block + fresh EoC using a throwaway writer.

    Returns the bytes AFTER the fresh file header, i.e. exactly the
    manifest block followed by the EoC block. Strips the 64-byte
    file-header preamble from the throwaway writer's output so the
    caller can append the result to the copied input preamble.

    Known limitation: the returned block bytes carry a fresh
    integrity chain seeded from the throwaway header, not from the
    hash of the caller's preamble. See module docstring.
    """
    scratch = io.BytesIO()
    scratch_header = FileHeader()
    scratch_writer = MSLWriter(scratch, scratch_header, CompAlgo.NONE)
    scratch_writer.write_module_build_id_manifest(manifest)
    scratch_writer.finalize()

    scratch_bytes = scratch.getvalue()
    # Skip the 64-byte file header that the throwaway writer emitted.
    return scratch_bytes[HEADER_SIZE:]


def _write_enriched(
    slice_path: Path,
    output_path: Path,
    eoc_start: int,
    manifest: ModuleBuildIdManifest,
) -> None:
    """Write the enriched slice to ``output_path``.

    Copies bytes ``[0, eoc_start)`` verbatim from ``slice_path``, then
    appends the manifest block and a fresh EoC computed by a throwaway
    writer.
    """
    tail = _render_manifest_tail(manifest)

    with open(slice_path, "rb") as src, open(output_path, "wb") as dst:
        remaining = eoc_start
        while remaining > 0:
            chunk = src.read(min(remaining, 1 << 20))
            if not chunk:
                raise IOError(
                    f"unexpected EOF while copying {slice_path} "
                    f"(expected {eoc_start} bytes, "
                    f"got {eoc_start - remaining})"
                )
            dst.write(chunk)
            remaining -= len(chunk)
        dst.write(tail)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.argument(
    "slice_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output path (default: <slice>.enriched).",
)
@click.option(
    "--in-place",
    is_flag=True,
    default=False,
    help="Atomically replace the original slice after writing to <slice>.tmp.",
)
def main(slice_path: Path, output: Path | None, in_place: bool) -> None:
    """Retroactively enrich an ``.msl`` slice with module build-ids.

    Reads the slice, extracts build-ids from captured ``MemoryRegion``
    bytes (Path B per D7 in the P1.6 plan), and appends a
    ``ModuleBuildIdManifest`` block (``0x005A``) to a new output file.
    See the module docstring for known limitations.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if in_place:
        output = slice_path.with_suffix(slice_path.suffix + ".tmp")
    elif output is None:
        output = slice_path.with_suffix(slice_path.suffix + ".enriched")

    try:
        modules, regions, eoc_start = _load_slice(slice_path)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    # Skip modules that already have a populated native_blob.
    unpopulated = [m for m in modules if not m.native_blob]
    if not unpopulated:
        click.echo(
            "nothing to enrich: all modules already have populated build-ids"
        )
        if in_place:
            # Don't touch the original; discard the would-be tmp path.
            return
        shutil.copyfile(slice_path, output)
        return

    populate_from_regions(
        unpopulated,
        regions,
        source_id=SOURCE_RETROACTIVE,
        logger=_log,
    )

    rows = _build_manifest_rows(unpopulated)
    if not rows:
        click.echo(
            f"could not recover any build-ids from captured regions "
            f"({len(unpopulated)} modules needed enrichment; none matched)",
            err=True,
        )
        if in_place:
            return
        shutil.copyfile(slice_path, output)
        return

    manifest = ModuleBuildIdManifest(rows=rows)
    _write_enriched(slice_path, output, eoc_start, manifest)

    if in_place:
        os.replace(output, slice_path)
        click.echo(f"enriched {slice_path} in place ({len(rows)} modules)")
    else:
        click.echo(f"wrote {output} ({len(rows)} modules enriched)")


if __name__ == "__main__":
    main()
