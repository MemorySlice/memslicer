"""Round-trip tests for the RegionOmissionManifest block (0x005B) and
the ``PageState.NOT_RESIDENT`` page-state value.

The manifest is written into a minimal valid ``.msl`` file with
:class:`MSLWriter`, read back through :func:`iterate_blocks`, and
decoded with :func:`parse_region_omission_manifest`.
"""
from __future__ import annotations

import io
import struct
import sys
import uuid
import warnings
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.cli_enrich import _parse_memory_region_for_enrich
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    HEADER_SIZE,
    ArchType,
    BlockType,
    OSType,
    OmissionReason,
    PageState,
    RegionType,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ProcessIdentity,
    RegionOmissionManifest,
    RegionOmissionRow,
)
from memslicer.msl.writer import MSLWriter, parse_region_omission_manifest
from memslicer.utils.timestamps import now_ns


@pytest.fixture
def header():
    return FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=1,
    )


def _write_slice(path: Path, header: FileHeader, manifest: RegionOmissionManifest) -> None:
    """Write a minimal valid slice: ProcessIdentity, the manifest, EoC."""
    with open(path, "wb") as f:
        writer = MSLWriter(f, header)
        writer.write_process_identity(ProcessIdentity(
            ppid=1, session_id=0, start_time_ns=1,
            exe_path="/usr/bin/test", cmd_line="test",
        ))
        writer.write_region_omission_manifest(manifest)
        writer.finalize()


def _read_manifest(path: Path) -> RegionOmissionManifest:
    with open(path, "rb") as f:
        payloads = [
            b.payload for b in iterate_blocks(f)
            if b.block_type == BlockType.RegionOmissionManifest
        ]
    assert len(payloads) == 1, "expected exactly one 0x005B block"
    return parse_region_omission_manifest(payloads[0])


def _sample_manifest() -> RegionOmissionManifest:
    return RegionOmissionManifest(
        scope="modules",
        exclude_patterns=["libc*", "*.dex", "/vendor/lib64/*"],
        rows=[
            RegionOmissionRow(
                base_addr=0x7f00_0000_0000, size=0x20000, protection=0x05,
                region_type=RegionType.Image,
                reason=OmissionReason.MODULE_EXCLUDE,
                name="/system/lib64/libc.so",
            ),
            RegionOmissionRow(
                base_addr=0x7f00_1000_0000, size=0x1000, protection=0x03,
                region_type=RegionType.Anon, reason=OmissionReason.SCOPE,
            ),
            RegionOmissionRow(
                base_addr=0x7f00_2000_0000, size=0x4000, protection=0x01,
                region_type=RegionType.MappedFile,
                reason=OmissionReason.SCOPE,
                name="/data/app/äöü.dex",  # non-ASCII UTF-8
            ),
        ],
    )


class TestRegionOmissionManifestRoundTrip:
    def test_round_trip_through_iterator(self, tmp_path, header):
        manifest = _sample_manifest()
        path = tmp_path / "omission.msl"
        _write_slice(path, header, manifest)

        parsed = _read_manifest(path)
        assert parsed == manifest
        assert parsed.scope == "modules"
        assert parsed.exclude_patterns == ["libc*", "*.dex", "/vendor/lib64/*"]
        assert [r.name for r in parsed.rows] == [
            "/system/lib64/libc.so", "", "/data/app/äöü.dex",
        ]
        assert isinstance(parsed.rows[0].region_type, RegionType)
        assert isinstance(parsed.rows[0].reason, OmissionReason)

    def test_empty_rows_still_writes_valid_block(self, tmp_path, header):
        path = tmp_path / "empty.msl"
        _write_slice(path, header, RegionOmissionManifest())

        parsed = _read_manifest(path)
        assert parsed.scope == "full"
        assert parsed.exclude_patterns == []
        assert parsed.rows == []

    def test_block_type_is_0x005B(self, header):
        assert BlockType.RegionOmissionManifest == 0x005B
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer.write_region_omission_manifest(RegionOmissionManifest())
            writer.finalize()
        (btype,) = struct.unpack_from("<H", buf.getvalue(), HEADER_SIZE + 4)
        assert btype == 0x005B

    def test_on_disk_layout(self, header):
        """Pin the byte layout so the parser and writer cannot drift apart."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        manifest = RegionOmissionManifest(
            scope="x", exclude_patterns=["ab", "c"],
            rows=[RegionOmissionRow(
                base_addr=0x1000, size=0x2000, protection=0x07,
                region_type=RegionType.Heap,
                reason=OmissionReason.MODULE_EXCLUDE, name="hi",
            )],
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer.write_region_omission_manifest(manifest)
            writer.finalize()
        data = buf.getvalue()
        payload = data[HEADER_SIZE + BLOCK_HEADER_SIZE:]

        assert struct.unpack_from("<II", payload, 0) == (1, 0)
        assert struct.unpack_from("<HHI", payload, 8) == (1, 4, 0)
        assert payload[16:24] == b"x" + b"\x00" * 7          # scope pad8
        assert payload[24:32] == b"ab\nc" + b"\x00" * 4      # patterns pad8
        assert struct.unpack_from("<QQBBBBHH", payload, 32) == (
            0x1000, 0x2000, 0x07, RegionType.Heap, OmissionReason.MODULE_EXCLUDE, 0, 2, 0,
        )
        assert payload[56:64] == b"hi" + b"\x00" * 6         # name pad8

    def test_long_name_raises(self, header):
        writer = MSLWriter(io.BytesIO(), header)
        manifest = RegionOmissionManifest(rows=[RegionOmissionRow(
            base_addr=0, size=0, protection=0,
            region_type=RegionType.Unknown, reason=OmissionReason.SCOPE,
            name="n" * 0x10000,
        )])
        with pytest.raises(ValueError):
            writer.write_region_omission_manifest(manifest)

    def test_long_patterns_raise(self, header):
        writer = MSLWriter(io.BytesIO(), header)
        manifest = RegionOmissionManifest(exclude_patterns=["p" * 0x8000] * 2)
        with pytest.raises(ValueError):
            writer.write_region_omission_manifest(manifest)

    def test_nul_in_string_raises(self, header):
        writer = MSLWriter(io.BytesIO(), header)
        with pytest.raises(ValueError):
            writer.write_region_omission_manifest(
                RegionOmissionManifest(scope="bad\x00scope"),
            )

    def test_parser_rejects_truncated_payload(self):
        with pytest.raises(ValueError):
            parse_region_omission_manifest(b"\x00" * 8)
        # Promises one row but carries none.
        truncated = struct.pack("<II", 1, 0) + struct.pack("<HHI", 0, 0, 0)
        with pytest.raises(ValueError):
            parse_region_omission_manifest(truncated)

    def test_parser_keeps_unknown_reason_as_int(self):
        """A reserved reason (3+) from a newer writer must not be rejected."""
        payload = (
            struct.pack("<II", 1, 0)
            + struct.pack("<HHI", 0, 0, 0)
            + struct.pack("<QQBBBBHH", 0x10, 0x20, 0, RegionType.Anon, 7, 0, 0, 0)
        )
        parsed = parse_region_omission_manifest(payload)
        assert parsed.rows[0].reason == 7
        assert parsed.rows[0].region_type is RegionType.Anon


class TestPageStateNotResident:
    def test_not_resident_region_round_trip(self, header):
        """States [CAPTURED, NOT_RESIDENT, CAPTURED] with 2 pages of data.

        Map byte: bits 7-6 = 00, 5-4 = 11, 3-2 = 00, 1-0 = unused (00)
        -> 0b00_11_00_00 = 0x30.
        """
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = MemoryRegion(
            base_addr=0x1000,
            region_size=4096 * 3,
            protection=0x03,
            region_type=RegionType.Anon,
            page_size=4096,
            timestamp_ns=now_ns(),
            page_states=[PageState.CAPTURED, PageState.NOT_RESIDENT, PageState.CAPTURED],
            page_data_chunks=[b"\xaa" * 4096, b"\xbb" * 4096],
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer.write_memory_region(region)
            writer.finalize()

        with io.BytesIO(buf.getvalue()) as f:
            regions = [
                b.payload for b in iterate_blocks(f)
                if b.block_type == BlockType.MemoryRegion
            ]
        assert len(regions) == 1
        payload = regions[0]
        # Fixed header is 32 bytes; PageStateMap follows, padded to 8.
        psm = payload[32:40]
        assert psm[0] == 0x30
        states = [(psm[0] >> (6 - 2 * i)) & 0x3 for i in range(3)]
        assert [PageState(s) for s in states] == [
            PageState.CAPTURED, PageState.NOT_RESIDENT, PageState.CAPTURED,
        ]
        # NOT_RESIDENT contributes 0 bytes: only the two captured pages follow.
        page_data = payload[40:]
        assert page_data[:4096] == b"\xaa" * 4096
        assert page_data[4096:8192] == b"\xbb" * 4096
        assert len(page_data) == 8192

    def test_encode_page_state_map_accepts_value_3(self):
        encoded = MSLWriter._encode_page_state_map(
            [PageState.NOT_RESIDENT] * 4 + [PageState.NOT_RESIDENT],
        )
        assert encoded == b"\xff\xc0"

    def test_enrich_region_parser_tolerates_not_resident_first_page(self, header):
        """cli_enrich maps the 2-bit value through PageState; value 3 must
        decode and must yield no page data (0-byte state)."""
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        region = MemoryRegion(
            base_addr=0x2000, region_size=4096 * 2, protection=0x01,
            region_type=RegionType.Image, page_size=4096,
            page_states=[PageState.NOT_RESIDENT, PageState.CAPTURED],
            page_data_chunks=[b"\xcc" * 4096],
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer.write_memory_region(region)
            writer.finalize()
        with io.BytesIO(buf.getvalue()) as f:
            payload = next(
                b.payload for b in iterate_blocks(f)
                if b.block_type == BlockType.MemoryRegion
            )
        parsed = _parse_memory_region_for_enrich(payload)
        assert parsed.base_addr == 0x2000
        assert parsed.page_states == []
        assert parsed.page_data_chunks == []
