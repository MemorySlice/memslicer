"""Compressed-slice round trip through MSLWriter and iterate_blocks.

Spec Section 4.2.1 (Table 9): a compressed block stores
UncompressedSize(8B) + CompressedData with no padding, so
``BlockLength = 80 + 8 + len(CompressedData)``. lz4 rejects trailing
padding, so a writer that padded made LZ4 slices unreadable; slices
written that way by older memslicer releases must still be readable.
"""
from __future__ import annotations

import io
import struct

import pytest

import memslicer.msl.writer as writer_module
from memslicer.msl.compression import compress
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE, COMPRESSED, BlockType, CompAlgo, PageState,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import FileHeader, MemoryRegion, ProcessIdentity
from memslicer.msl.writer import MSLWriter

_PAGE_A = b"\x41" * 4096
_PAGE_B = bytes(range(256)) * 16


def _write_slice(comp_algo: CompAlgo) -> bytes:
    buf = io.BytesIO()
    w = MSLWriter(buf, FileHeader(pid=4242), comp_algo=comp_algo)
    w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
    w.write_memory_region(MemoryRegion(
        base_addr=0x10000, region_size=8192, protection=3,
        page_states=[PageState.CAPTURED, PageState.CAPTURED],
        page_data_chunks=[_PAGE_A, _PAGE_B],
    ))
    w.finalize()
    return buf.getvalue()


def _region_block(raw: bytes):
    blocks = list(iterate_blocks(io.BytesIO(raw)))
    regions = [b for b in blocks if b.block_type == BlockType.MemoryRegion]
    assert len(regions) == 1
    return regions[0]


def _on_disk_payload(raw: bytes, block) -> bytes:
    return raw[block.start_offset + BLOCK_HEADER_SIZE:block.end_offset]


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_slice_round_trips(comp_algo):
    region = _region_block(_write_slice(comp_algo))
    assert _PAGE_A + _PAGE_B in region.payload


@pytest.mark.parametrize("comp_algo", [CompAlgo.ZSTD, CompAlgo.LZ4])
def test_compressed_payload_is_not_padded(comp_algo):
    raw = _write_slice(comp_algo)
    region = _region_block(raw)
    assert region.flags & COMPRESSED
    on_disk = _on_disk_payload(raw, region)
    compressed = compress(region.payload, comp_algo)
    assert on_disk == struct.pack("<Q", len(region.payload)) + compressed
    assert region.length == BLOCK_HEADER_SIZE + 8 + len(compressed)


def _legacy_padding_compress(data: bytes, algo: CompAlgo) -> bytes:
    """Mimic the old writer: pad UncompressedSize + CompressedData to 8B."""
    compressed = compress(data, algo)
    return compressed + b"\x00" * (-(8 + len(compressed)) % 8)


def test_legacy_padded_lz4_slice_still_readable(monkeypatch):
    monkeypatch.setattr(writer_module, "compress", _legacy_padding_compress)
    raw = _write_slice(CompAlgo.LZ4)
    blocks = list(iterate_blocks(io.BytesIO(raw)))

    compressed_blocks = [b for b in blocks if b.flags & COMPRESSED]
    padded = [
        b for b in compressed_blocks
        if len(_on_disk_payload(raw, b)) - 8 > len(compress(b.payload, CompAlgo.LZ4))
    ]
    assert padded, "monkeypatch produced no padded block; test is vacuous"
    for block in padded:
        assert _on_disk_payload(raw, block).endswith(b"\x00")

    region = next(b for b in blocks if b.block_type == BlockType.MemoryRegion)
    assert _PAGE_A + _PAGE_B in region.payload
