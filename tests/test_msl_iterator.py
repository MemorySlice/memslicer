"""Tests for ``memslicer.msl.iterator`` (P1.7).

Synthesizes MSL files with :class:`MSLWriter` + :class:`io.BytesIO`
and validates round-tripping them through :func:`iterate_blocks`.
"""
from __future__ import annotations

import io
import sys
import warnings
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    HEADER_SIZE,
    BlockType,
    CompAlgo,
    PageState,
    RegionType,
)
from memslicer.msl.iterator import BlockRecord, iterate_blocks
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ModuleEntry,
)
from memslicer.msl.writer import MSLWriter


def _make_slice(
    modules: list[ModuleEntry] | None = None,
    regions: list[MemoryRegion] | None = None,
    comp_algo: CompAlgo = CompAlgo.NONE,
) -> bytes:
    """Synthesize a minimal MSL slice into an in-memory buffer."""
    buf = io.BytesIO()
    header = FileHeader()
    # The writer emits spec-ordering warnings (ProcessIdentity @ block 0,
    # ModuleListIndex @ block 1). Suppress them for these tests.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        writer = MSLWriter(buf, header, comp_algo)
        if regions:
            for region in regions:
                writer.write_memory_region(region)
        if modules:
            writer.write_module_list(modules)
        writer.finalize()
    return buf.getvalue()


def _one_page_region(base_addr: int, page_bytes: bytes) -> MemoryRegion:
    """Build a single 4 KiB captured region at ``base_addr``."""
    assert len(page_bytes) == 4096
    return MemoryRegion(
        base_addr=base_addr,
        region_size=4096,
        page_size=4096,
        region_type=RegionType.Image,
        page_states=[PageState.CAPTURED],
        page_data_chunks=[page_bytes],
    )


class TestIterator:
    def test_iterates_empty_slice(self):
        data = _make_slice()
        with io.BytesIO(data) as f:
            blocks = list(iterate_blocks(f))
        # Should yield at least the EoC block.
        assert len(blocks) >= 1
        assert blocks[-1].block_type == BlockType.EndOfCapture

    def test_iterates_module_list(self):
        modules = [
            ModuleEntry(base_addr=0x1000, module_size=0x1000, path="/bin/a"),
            ModuleEntry(base_addr=0x2000, module_size=0x1000, path="/bin/b"),
        ]
        data = _make_slice(modules=modules)
        with io.BytesIO(data) as f:
            blocks = list(iterate_blocks(f))
        module_blocks = [
            b for b in blocks if b.block_type == BlockType.ModuleEntry
        ]
        assert len(module_blocks) == 2
        # The index block appears exactly once.
        index_blocks = [
            b for b in blocks if b.block_type == BlockType.ModuleListIndex
        ]
        assert len(index_blocks) == 1

    def test_eoc_terminates_iteration(self):
        data = _make_slice()
        # Append garbage after the EoC — iteration must stop at the EoC
        # and not attempt to parse the trailing bytes.
        corrupted = data + b"\x00" * 128
        with io.BytesIO(corrupted) as f:
            blocks = list(iterate_blocks(f))
        assert blocks[-1].block_type == BlockType.EndOfCapture

    def test_bad_block_magic_raises(self):
        data = bytearray(_make_slice())
        # Corrupt the first block's magic (4 bytes right after the
        # 64-byte file header).
        data[HEADER_SIZE : HEADER_SIZE + 4] = b"XXXX"
        with io.BytesIO(bytes(data)) as f:
            with pytest.raises(ValueError, match="bad block magic"):
                list(iterate_blocks(f))

    def test_bad_file_magic_raises(self):
        data = bytearray(_make_slice())
        data[0:8] = b"NOTMSL!!"
        with io.BytesIO(bytes(data)) as f:
            with pytest.raises(ValueError, match="bad MSL file magic"):
                list(iterate_blocks(f))

    def test_truncated_block_header_raises(self):
        data = _make_slice()
        # File header (64) + partial block header (6 of 80 bytes).
        truncated = data[: HEADER_SIZE + 6]
        with io.BytesIO(truncated) as f:
            with pytest.raises(ValueError, match="truncated block header"):
                list(iterate_blocks(f))

    def test_truncated_payload_raises(self):
        modules = [
            ModuleEntry(base_addr=0x1000, module_size=0x1000, path="/bin/a"),
        ]
        data = _make_slice(modules=modules)
        # Chop the tail — guarantees we amputate the middle of some
        # block's payload before its EoC.
        with io.BytesIO(data[:-100]) as f:
            with pytest.raises(ValueError):
                list(iterate_blocks(f))

    def test_start_offset_monotonic_and_past_header(self):
        modules = [
            ModuleEntry(
                base_addr=i * 0x1000, module_size=0x1000, path=f"/m{i}"
            )
            for i in range(3)
        ]
        data = _make_slice(modules=modules)
        with io.BytesIO(data) as f:
            offsets = [b.start_offset for b in iterate_blocks(f)]
        assert offsets == sorted(offsets)
        assert offsets[0] >= HEADER_SIZE

    def test_end_offset_matches_length(self):
        data = _make_slice()
        with io.BytesIO(data) as f:
            for b in iterate_blocks(f):
                assert b.end_offset - b.start_offset == b.length
                assert b.length >= BLOCK_HEADER_SIZE

    def test_payload_decompressed_with_zstd(self):
        """Round-trip a compressed MemoryRegion through the iterator.

        The writer compresses region payloads when ``comp_algo !=
        NONE``; the iterator must decompress transparently so the
        caller sees the original padded payload bytes.
        """
        page = b"\xaa" * 2048 + b"\xbb" * 2048
        region = _one_page_region(0x100000, page)
        data = _make_slice(regions=[region], comp_algo=CompAlgo.ZSTD)

        with io.BytesIO(data) as f:
            blocks = list(iterate_blocks(f))

        region_blocks = [
            b for b in blocks if b.block_type == BlockType.MemoryRegion
        ]
        assert len(region_blocks) == 1
        rb = region_blocks[0]
        # Payload should contain the raw page bytes somewhere after
        # the 32-byte fixed header + padded page state map.
        assert b"\xaa" * 2048 in rb.payload
        assert b"\xbb" * 2048 in rb.payload

    def test_encrypted_slice_refused(self):
        """A file header with ``FLAG_ENCRYPTED`` is refused up-front."""
        from memslicer.msl.constants import FLAG_ENCRYPTED

        data = bytearray(_make_slice())
        # Flags field is the 4-byte uint32 at offset 12 in the file
        # header (see writer._write_header pack format).
        import struct as _struct

        flags = _struct.unpack("<I", data[12:16])[0]
        flags |= FLAG_ENCRYPTED
        data[12:16] = _struct.pack("<I", flags)
        with io.BytesIO(bytes(data)) as f:
            with pytest.raises(ValueError, match="encrypted slices"):
                list(iterate_blocks(f))
