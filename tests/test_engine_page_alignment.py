"""Memory Region blocks always cover whole pages (spec Tables 13 and 24).

Frida's ``Process.enumerateRanges`` can report a range whose base is not
page-aligned: its Cloak clips Frida's own thread stacks out of a mapping and
the visible remainder begins at the unaligned end of the cloaked piece
(observed on Android: base ``0x70309e8500``, size ``0x3b00``, type Stack).
Capturing such a range used to write a block with four Captured pages but
only ``0x3b00`` bytes of page data. The engine now widens every range to
page boundaries once, at enumeration, so the region block, the VAS Map and
the Region Omission Manifest describe the same span, and a backend answer
that stops mid-page never yields a Captured page without its full data.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange
from memslicer.acquirer.engine import (
    AcquisitionEngine, _page_align_range, _page_span, _whole_pages,
    build_vas_entries,
)
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import BlockType, PageState
from memslicer.msl.writer import parse_region_omission_manifest, parse_vas_map
from test_engine import FaultingBridge, ShortReadBridge, _find_block, _parse_blocks
from test_engine_residency import _decode_region

PAGE = 4096

# The shape Frida reported on the Android capture: a thread-stack remainder
# that starts 0x500 bytes into a page and ends on a page boundary.
CLOAKED_BASE = 0x70309E8500
CLOAKED_SIZE = 0x3B00


def _region_header(payload: bytes) -> tuple[int, int]:
    """``(BaseAddr, RegionSize)`` of a MemoryRegion payload."""
    return struct.unpack_from("<QQ", payload, 0)


def _region_payloads(blocks) -> list[bytes]:
    return [p for bt, _flags, p in blocks if bt == BlockType.MemoryRegion]


class TestPageSpan:
    """The page-aligned span covering an arbitrary byte range."""

    @pytest.mark.parametrize("base,size,expected", [
        (0x1000, 0x4000, (0x1000, 0x4000)),            # already aligned
        (0x1500, 0x3000, (0x1000, 0x4000)),            # straddles both ends
        (CLOAKED_BASE, CLOAKED_SIZE, (0x70309E8000, 0x4000)),
        (0x1000, 0x1001, (0x1000, 0x2000)),            # trailing partial page
        (0x1FFF, 0x2, (0x1000, 0x2000)),               # two bytes, two pages
        (0x1000, 0, (0x1000, 0)),                      # empty on a boundary
    ])
    def test_covers_the_range_with_whole_pages(self, base, size, expected):
        assert _page_span(base, size, PAGE) == expected

    def test_aligned_range_is_returned_unchanged(self):
        r = MemoryRange(base=0x1000, size=0x4000, protection="rw-")
        assert _page_align_range(r, PAGE) is r

    def test_unaligned_range_keeps_its_other_fields(self):
        r = MemoryRange(base=0x1500, size=0x3000, protection="rw-",
                        file_path="[stack]")
        aligned = _page_align_range(r, PAGE)
        assert (aligned.base, aligned.size) == (0x1000, 0x4000)
        assert (aligned.protection, aligned.file_path) == ("rw-", "[stack]")


class TestWholePages:
    """A read answer counts only the pages it covers completely."""

    @pytest.mark.parametrize("length,pages", [
        (0, 0), (PAGE - 1, 0), (PAGE, 1), (PAGE + 100, 1), (3 * PAGE, 3),
    ])
    def test_partial_trailing_page_is_dropped(self, length, pages):
        captured, data = _whole_pages(b"\xa5" * length, PAGE)
        assert captured == pages
        assert len(data) == pages * PAGE


class TestUnalignedRangeCapture:
    """A range at an unaligned base is captured as the pages it lives in."""

    def _capture(self, tmp_path: Path, bridge=None):
        bridge = bridge or FaultingBridge(ranges=[
            MemoryRange(base=0x1500, size=0x3000, protection="rw-",
                        file_path="[anon:libc_malloc]"),
        ])
        result = AcquisitionEngine(bridge).acquire(tmp_path / "dump.msl")
        return bridge, result, _parse_blocks((tmp_path / "dump.msl").read_bytes())

    def test_block_is_well_formed(self, tmp_path: Path):
        _bridge, result, blocks = self._capture(tmp_path)

        payloads = _region_payloads(blocks)
        assert len(payloads) == 1
        assert _region_header(payloads[0]) == (0x1000, 0x4000)
        states, data = _decode_region(payloads[0])
        assert states == [PageState.CAPTURED] * 4
        assert len(data) == 4 * PAGE
        assert result.pages_captured == 4
        assert result.bytes_captured == 4 * PAGE

    def test_target_is_read_at_the_page_boundary(self, tmp_path: Path):
        bridge, _result, _blocks = self._capture(tmp_path)

        # The startup test read takes one page first; the region read follows.
        assert bridge.reads[-1] == (0x1000, 0x4000)
        assert all(addr % PAGE == 0 and size % PAGE == 0 for addr, size in bridge.reads)

    def test_vas_map_names_the_same_base(self, tmp_path: Path):
        _bridge, _result, blocks = self._capture(tmp_path)

        entries = parse_vas_map(_find_block(blocks, BlockType.VASMap))
        region_base, region_size = _region_header(_region_payloads(blocks)[0])
        assert [(e.base_addr, e.region_size) for e in entries] == [
            (region_base, region_size),
        ]

    def test_adjustment_is_logged(self, tmp_path: Path, caplog):
        with caplog.at_level(logging.DEBUG, logger="memslicer"):
            self._capture(tmp_path)

        assert any(
            "page-aligned range 0x1500 size=12288 -> 0x1000 size=16384" in m
            for m in caplog.messages
        )

    def test_survey_plans_on_aligned_ranges(self):
        bridge = FaultingBridge(ranges=[
            MemoryRange(base=0x1500, size=0x3000, protection="rw-"),
        ])
        survey = AcquisitionEngine(bridge).survey_regions()

        assert [(d.range.base, d.range.size) for d in survey.decisions] == [
            (0x1000, 0x4000),
        ]


class TestFridaCloakedStackShape:
    """The exact range shape seen on the Android capture."""

    def test_read_region_widens_to_the_page_span(self):
        bridge = FaultingBridge()
        region, data_size = AcquisitionEngine(bridge)._read_region(
            CLOAKED_BASE, CLOAKED_SIZE, 0x03, "[anon:stack_and_tls:1234]", PAGE,
        )

        assert region.base_addr == 0x70309E8000
        assert region.region_size == 0x4000
        assert region.page_states == [PageState.CAPTURED] * 4
        assert sum(map(len, region.page_data_chunks)) == 4 * PAGE == data_size
        assert bridge.reads == [(0x70309E8000, 0x4000)]


class TestUnalignedRangeOmitted:
    """An omitted unaligned range is recorded with the aligned base, so the
    manifest row, the VAS entry and any region block agree on the key."""

    def test_manifest_and_vas_map_agree(self, tmp_path: Path):
        bridge = FaultingBridge(ranges=[
            MemoryRange(base=CLOAKED_BASE, size=CLOAKED_SIZE, protection="rw-",
                        file_path="[stack]"),
        ])
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="heap"))
        engine.acquire(tmp_path / "heap.msl")
        blocks = _parse_blocks((tmp_path / "heap.msl").read_bytes())

        manifest = parse_region_omission_manifest(
            _find_block(blocks, BlockType.RegionOmissionManifest),
        )
        entries = parse_vas_map(_find_block(blocks, BlockType.VASMap))
        assert [(r.base_addr, r.size) for r in manifest.rows] == [
            (0x70309E8000, 0x4000),
        ]
        assert [(e.base_addr, e.region_size) for e in entries] == [
            (0x70309E8000, 0x4000),
        ]
        assert _region_payloads(blocks) == []


class TestBuildVasEntriesAlignment:
    """``build_vas_entries`` aligns on its own, for callers outside the engine."""

    def test_unaligned_base_is_rounded_down(self):
        entries = build_vas_entries(
            [MemoryRange(base=0x1500, size=0x3000, protection="rw-")], PAGE,
        )
        assert (entries[0].base_addr, entries[0].region_size) == (0x1000, 0x4000)


class TestShortPageRead:
    """The page-by-page fallback never records a short page as Captured."""

    def test_short_page_answer_is_failed(self):
        bridge = ShortReadBridge(returned=PAGE - 1)
        engine = AcquisitionEngine(bridge)

        states, chunks, data_size = engine._try_read_pages(0x1000, 2 * PAGE, PAGE)

        assert states == [PageState.FAILED, PageState.FAILED]
        assert chunks == []
        assert data_size == 0

    def test_over_long_page_answer_is_trimmed(self):
        bridge = ShortReadBridge(returned=PAGE)
        bridge.read_memory = lambda address, size: b"\xa5" * (size + 7)
        engine = AcquisitionEngine(bridge)

        states, chunks, data_size = engine._try_read_pages(0x1000, PAGE, PAGE)

        assert states == [PageState.CAPTURED]
        assert [len(c) for c in chunks] == [PAGE]
        assert data_size == PAGE
