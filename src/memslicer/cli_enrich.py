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

Extension segment (spec Section 4.6): the capture segment -- header,
every block and the original ``EndOfCapture`` -- is copied verbatim,
together with every extension segment that already verifies. The
manifest goes into a new extension segment appended after them, closed
by an ``EndOfExtension`` block that records the segment's hash, its
block count and ``memslicer-enrich/<version>`` as producer. The
``PrevHash`` chain (Section 4.4) continues through the EoC and the
existing segments, so the enriched file still has one linear chain and
the original EoC ``FileHash`` stays valid.

Modules whose build-id an existing manifest (in any segment, including
a pre-1.1 manifest written before a replaced EoC) already covers are
skipped; when nothing is left the slice is not rewritten.

Known limitations (P1.7):

* **Encrypted slices**: not supported. An extension segment would have
  to lie inside the AEAD stream, which nothing here can re-seal.

* **Trailing data**: a slice with bytes after its last verified segment
  (an unterminated or tampered segment, non-MSL garbage) is refused
  rather than built upon (Section 4.6 producer rules).

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

from memslicer import __version__
from memslicer.acquirer.build_id_post import (
    SOURCE_RETROACTIVE,
    populate_from_regions,
)
from memslicer.msl.constants import (
    COMPRESSED,
    BlockType,
    HashAlgo,
    PageState,
)
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.iterator import (
    SegmentSpan,
    _decompress_block_payload,
    _iter_raw_blocks,
    is_encrypted,
    iterate_blocks,
    read_file_header_info,
    read_hash_algo,
    scan_extension_segments,
)
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ModuleBuildIdManifest,
    ModuleBuildIdRow,
    ModuleEntry,
)
from memslicer.msl.writer import (
    MSLWriter,
    parse_end_of_extension,
    parse_module_build_id_manifest,
)

PRODUCER = f"memslicer-enrich/{__version__}"
"""Producer string recorded in the EndOfExtension block (spec Table 12a)."""


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
) -> tuple[list[ModuleEntry], list[MemoryRegion], HashAlgo, set[int]]:
    """Read modules, regions, hash algo and already-enriched bases from a slice.

    Walks the capture segment and every valid extension segment. Rows of
    any ``ModuleBuildIdManifest`` -- in an extension segment, or in the
    capture segment of a pre-1.1 enriched file whose manifest precedes a
    replaced EoC -- contribute their ``base_addr`` to ``enriched_bases``.

    Returns ``(modules, regions, hash_algo, enriched_bases)``. Raises
    :class:`FileNotFoundError` / :class:`ValueError` on missing or
    malformed files, or when the slice has no ``EndOfCapture`` block.
    """
    modules: list[ModuleEntry] = []
    regions: list[MemoryRegion] = []
    enriched_bases: set[int] = set()
    eoc_seen = False

    with open(slice_path, "rb") as f:
        if is_encrypted(f):
            # iterate_blocks can decrypt, but enrichment cannot use that:
            # an extension segment must lie inside the AEAD stream (spec
            # Section 4.6), and appending to a sealed container would
            # invalidate its authentication tag, which nothing here can
            # re-seal.
            raise ValueError(
                f"slice at {slice_path} is encrypted; enrichment would have to "
                f"re-seal the container, which is not supported. Re-acquire "
                f"without encryption to enrich, or enrich before encrypting"
            )
        hash_algo = read_hash_algo(f)
        for block in iterate_blocks(f, extensions=True):
            if block.block_type == BlockType.ModuleEntry:
                modules.append(_parse_module_entry_minimal(block.payload))
            elif block.block_type == BlockType.MemoryRegion:
                regions.append(_parse_memory_region_for_enrich(block.payload))
            elif block.block_type == BlockType.ModuleBuildIdManifest:
                manifest = parse_module_build_id_manifest(block.payload)
                enriched_bases.update(row.base_addr for row in manifest.rows)
            elif block.block_type == BlockType.EndOfCapture:
                eoc_seen = True

    if not eoc_seen:
        raise ValueError(
            f"slice at {slice_path} has no EndOfCapture block; "
            f"cannot determine where to append the manifest"
        )

    return modules, regions, hash_algo, enriched_bases


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


def _seed_chain(slice_path: Path) -> tuple[IntegrityChain, int, int]:
    """Hash a slice's header, capture segment and valid extension segments.

    Feeds the HeaderSize-byte file header, then each block's on-disk
    bytes in order (one block in memory at a time) through the
    ``EndOfCapture``, then every extension segment that is terminated,
    counts its blocks exactly and carries a matching ``SegmentHash``
    (spec Section 4.6). Returns ``(chain, block_index, append_offset)``
    where ``block_index`` is the number of blocks fed and
    ``append_offset`` the end of the last valid segment -- the only place
    a new segment may go.

    Raises :class:`ValueError` when the slice has no ``EndOfCapture``, or
    when bytes follow the last valid segment: a producer must not build
    on unverified trailing data.
    """
    with open(slice_path, "rb") as f:
        header_size, hash_algo, _flags = read_file_header_info(f)
        chain = IntegrityChain(hash_algo=hash_algo)
        chain.feed_header(f.read(header_size))
        block_index, eoc_end = _feed_capture_segment(f, chain)
        if eoc_end is None:
            raise ValueError(f"slice at {slice_path} has no EndOfCapture block")
        block_index, append_offset = _feed_valid_segments(f, eoc_end, chain, block_index)
        f.seek(0, 2)
        trailing = f.tell() - append_offset
    if trailing:
        raise ValueError(
            f"slice at {slice_path} has {trailing} unverified trailing byte(s) "
            f"after offset {append_offset}; refusing to append to it"
        )
    return chain, block_index, append_offset


def _feed_capture_segment(f, chain: IntegrityChain) -> tuple[int, int | None]:
    """Feed every capture-segment block including the EoC into ``chain``.

    Returns ``(blocks_fed, eoc_end_offset)``; the offset is ``None`` when
    the stream ends before an ``EndOfCapture``.
    """
    block_index = 0
    for raw in _iter_raw_blocks(f):
        chain.feed_block_parts(raw.header_bytes, raw.on_disk_payload)
        block_index += 1
        if raw.block_type == BlockType.EndOfCapture:
            return block_index, raw.end_offset
    return block_index, None


def _feed_valid_segments(
    f, start: int, chain: IntegrityChain, block_index: int,
) -> tuple[int, int]:
    """Feed every verifiable extension segment after ``start`` into ``chain``.

    Stops at the first unterminated, miscounted or hash-mismatching
    segment, leaving it (and everything after it) as trailing data.
    Returns ``(block_index, append_offset)``.
    """
    spans, append_offset = scan_extension_segments(f, start)
    for span in spans:
        if not span.terminated or not _feed_segment(f, span, chain):
            return block_index, span.start
        block_index += span.block_count
        append_offset = span.end
    return block_index, append_offset


def _feed_segment(f, span: SegmentSpan, chain: IntegrityChain) -> bool:
    """Feed one terminated span; ``False`` when its terminator disagrees.

    The ``SegmentHash`` is taken before the terminator is fed, matching
    :meth:`MSLWriter.finalize_extension`.
    """
    chain.start_segment()
    f.seek(span.start)
    ok = False
    try:
        for raw in _iter_raw_blocks(f, end=span.end):
            if raw.block_type == BlockType.EndOfExtension:
                payload = (
                    _decompress_block_payload(raw) if raw.flags & COMPRESSED
                    else raw.on_disk_payload
                )
                terminator = parse_end_of_extension(payload)
                ok = (
                    terminator.segment_hash == chain.segment_digest()
                    and terminator.block_count == span.block_count
                )
            chain.feed_block_parts(raw.header_bytes, raw.on_disk_payload)
    except (ValueError, NotImplementedError):
        ok = False
    finally:
        chain.end_segment()
    return ok


def _render_manifest_tail(
    manifest: ModuleBuildIdManifest,
    chain: IntegrityChain,
    block_index: int,
) -> bytes:
    """Serialize a manifest block + new EoC continuing an existing chain.

    ``chain`` must be seeded with the original slice's header and every
    block before its EoC (see :func:`_seed_chain`); ``block_index`` is
    that block count. The writer's header carries the chain's
    ``hash_algo`` so it matches the original slice. Returns exactly the manifest block followed by
    the EoC block -- no file header is emitted -- so the caller appends
    the result to the copied preamble and the chain stays continuous.
    """
    tail = io.BytesIO()
    writer = MSLWriter.resume(
        tail, FileHeader(hash_algo=chain.hash_algo), chain, block_index,
    )
    writer.write_module_build_id_manifest(manifest)
    writer.finalize()
    return tail.getvalue()


def _render_extension_tail(
    manifest: ModuleBuildIdManifest,
    chain: IntegrityChain,
    block_index: int,
) -> bytes:
    """Serialize one extension segment holding the manifest (spec Section 4.6).

    ``chain`` must be seeded with the slice's header, its capture segment
    including the EoC and every valid existing segment (see
    :func:`_seed_chain`); ``block_index`` is that block count. Returns
    exactly the manifest block followed by its ``EndOfExtension`` block
    -- no file header, no EoC -- so the caller appends the result after
    the last valid segment and the chain stays continuous.
    """
    tail = io.BytesIO()
    writer = MSLWriter.extend(
        tail, FileHeader(hash_algo=chain.hash_algo), chain, block_index,
    )
    writer.begin_extension()
    writer.write_module_build_id_manifest(manifest)
    writer.finalize_extension(producer=PRODUCER)
    return tail.getvalue()


def _write_enriched(
    slice_path: Path,
    output_path: Path,
    manifest: ModuleBuildIdManifest,
) -> None:
    """Write the enriched slice to ``output_path``.

    Copies bytes ``[0, append_offset)`` verbatim from ``slice_path`` --
    header, capture segment with its original EoC, and every valid
    extension segment -- then appends a new extension segment holding
    the manifest, whose PrevHash chain continues the original.

    Raises :class:`ValueError` when the slice cannot be appended to (no
    EoC, or unverified trailing bytes).
    """
    chain, block_index, append_offset = _seed_chain(slice_path)
    tail = _render_extension_tail(manifest, chain, block_index)

    with open(slice_path, "rb") as src, open(output_path, "wb") as dst:
        remaining = append_offset
        while remaining > 0:
            chunk = src.read(min(remaining, 1 << 20))
            if not chunk:
                raise IOError(
                    f"unexpected EOF while copying {slice_path} "
                    f"(expected {append_offset} bytes, "
                    f"got {append_offset - remaining})"
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
        modules, regions, hash_algo, enriched_bases = _load_slice(slice_path)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    # Skip modules that already have a populated native_blob, and those
    # an existing manifest already covers.
    unpopulated = [
        m for m in modules
        if not m.native_blob and m.base_addr not in enriched_bases
    ]
    if not unpopulated:
        click.echo(
            "nothing to enrich: all modules already have populated build-ids"
        )
        # Nothing is written: the original is complete as it stands.
        return

    populate_from_regions(
        unpopulated,
        regions,
        source_id=SOURCE_RETROACTIVE,
        logger=_log,
        hash_algo=hash_algo,
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
    try:
        _write_enriched(slice_path, output, manifest)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    if in_place:
        os.replace(output, slice_path)
        click.echo(f"enriched {slice_path} in place ({len(rows)} modules)")
    else:
        click.echo(f"wrote {output} ({len(rows)} modules enriched)")


if __name__ == "__main__":
    main()
