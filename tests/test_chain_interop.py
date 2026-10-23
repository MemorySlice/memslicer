"""PrevHash chain conformance (spec §4.4) and MemDiver interop.

Block 0 PrevHash = hash(file header, all HeaderSize bytes on disk); block i
= hash(block i-1 on-disk bytes); zeros only when encrypted. memslicer's own
verifier (``memslicer.msl.verify.verify_slice``) is checked against
``_spec_chain_errors``, an independent oracle that recomputes the chain from
the raw bytes. The MemDiver half is skipped when the sibling ``memdiver``
package is not importable.
"""
from __future__ import annotations

import io
import struct

import pytest

from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, CompAlgo, PageState,
)
from memslicer.msl.integrity import make_hasher
from memslicer.msl.iterator import read_hash_algo
from memslicer.msl.types import FileHeader, MemoryRegion, ProcessIdentity
from memslicer.msl.verify import verify_slice
from memslicer.msl.writer import MSLWriter


def _digest(algo, data: bytes) -> bytes:
    h = make_hasher(algo)
    h.update(data)
    return h.digest()


def _spec_chain_errors(raw: bytes) -> list[str]:
    """Recompute the §4.4 chain over *raw* (plaintext file); return mismatches.

    Walks on-disk blocks by BlockLength (no decompression: hashes cover the
    raw on-disk bytes) and stops after EndOfCapture.
    """
    algo = read_hash_algo(io.BytesIO(raw))
    offset = raw[9]
    expected = _digest(algo, raw[:offset])
    errors = []
    index = 0
    while offset + BLOCK_HEADER_SIZE <= len(raw) and raw[offset:offset + 4] == BLOCK_MAGIC:
        block_type, length = struct.unpack_from("<HxxI", raw, offset + 4)
        if raw[offset + 0x30:offset + 0x50] != expected:
            errors.append(f"block {index} @0x{offset:X}")
        expected = _digest(algo, raw[offset:offset + length])
        offset += length
        index += 1
        if block_type == BlockType.EndOfCapture:
            break
    return errors


def _memslicer_file(comp_algo: CompAlgo) -> bytes:
    buf = io.BytesIO()
    w = MSLWriter(buf, FileHeader(pid=4242), comp_algo=comp_algo)
    w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
    w.write_memory_region(MemoryRegion(
        base_addr=0x10000, region_size=8192, protection=3,
        page_states=[PageState.CAPTURED, PageState.CAPTURED],
        page_data_chunks=[b"\x41" * 4096, b"\x42" * 4096],
    ))
    w.finalize()
    return buf.getvalue()


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_memslicer_block0_chains_from_final_header(comp_algo):
    """Block 0 PrevHash hashes the header bytes as finally stored (the writer
    never patches the header after the first block)."""
    raw = _memslicer_file(comp_algo)
    assert raw[64 + 0x30:64 + 0x50] == _digest(read_hash_algo(io.BytesIO(raw)), raw[:64])
    assert _spec_chain_errors(raw) == []
    assert verify_slice(io.BytesIO(raw)).valid


@pytest.mark.parametrize("comp_algo", [CompAlgo.NONE, CompAlgo.ZSTD, CompAlgo.LZ4])
def test_memslicer_file_passes_memdiver_verify_chain(tmp_path, comp_algo):
    pytest.importorskip("memdiver.msl.integrity")
    from memdiver.msl.integrity import verify_chain
    from memdiver.msl.reader import MslReader
    path = tmp_path / "ms.msl"
    path.write_bytes(_memslicer_file(comp_algo))
    with MslReader(path) as reader:
        report = verify_chain(reader)
    assert report.valid, report.errors
    assert report.block_count == 3


@pytest.mark.parametrize("streaming", [False, True])
def test_memdiver_written_file_passes_spec_chain(tmp_path, streaming):
    pytest.importorskip("memdiver.msl.writer")
    from memdiver.msl.writer import MslWriter
    path = tmp_path / "md.msl"
    w = MslWriter(path)
    w.add_import_provenance(source_format=1, tool_name="test", orig_file_size=0)
    w.add_memory_region(0x10000, b"\x11" * 4096)
    w.add_end_of_capture()
    w.write_streaming() if streaming else w.write()
    assert _spec_chain_errors(path.read_bytes()) == []


def test_spec_chain_helper_flags_zero_block0():
    raw = bytearray(_memslicer_file(CompAlgo.NONE))
    raw[64 + 0x30:64 + 0x50] = b"\x00" * 32
    assert _spec_chain_errors(bytes(raw))[0].startswith("block 0")


def test_memdiver_segments_pass_memslicer_verify(tmp_path):
    """MemDiver-written extension segments (spec Section 4.6) verify here.

    MemDiver gained chained segments concurrently with this test: the
    pointer graph goes into its own segment, ``add_extension_segment``
    adds another. The test skips against an older MemDiver.
    """
    pytest.importorskip("memdiver.msl.writer")
    from memdiver.msl.writer import ExtensionBlock, MslWriter
    if not hasattr(MslWriter, "add_extension_segment"):
        pytest.skip("MemDiver writer does not produce chained extension segments yet")
    path = tmp_path / "md-ext.msl"
    w = MslWriter(path)
    w.add_import_provenance(source_format=1, tool_name="test", orig_file_size=0)
    w.add_memory_region(0x10000, b"\x11" * 4096)
    w.add_end_of_capture()
    w.add_pointer_graph(nodes=[], edges=[], producer="memdiver-test/graph")
    manifest = struct.pack("<II", 0, 0)  # empty ModuleBuildIdManifest
    w.add_extension_segment(
        "memdiver-test/manifest",
        [ExtensionBlock(int(BlockType.ModuleBuildIdManifest), manifest)],
    )
    w.write()
    with open(path, "rb") as f:
        report = verify_slice(f)
    assert report.valid, report.errors
    assert report.trailing_bytes == 0
    assert [s.producer for s in report.segments] == [
        "memdiver-test/graph", "memdiver-test/manifest",
    ]
    assert all(s.verified and s.block_count == 2 for s in report.segments)
