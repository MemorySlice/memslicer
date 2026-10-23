"""Tests for resident-only page pruning in AcquisitionEngine.

A never-touched anonymous page reads as zero, so the engine may skip every
page a residency mask marks ``0`` and record it as ``NOT_RESIDENT`` instead.
These tests drive the engine with a bridge that answers residency queries
from a fixed set of resident pages and records every read it is asked for.
"""
from __future__ import annotations

import logging
import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange
from memslicer.acquirer.engine import (
    AcquisitionEngine, _nonresident_bytes, coalesce_unreadable,
)
from memslicer.msl.constants import BlockType, PageState
from memslicer.utils.padding import pad8
from test_engine import (
    FaultingBridge, _find_block, _make_region, _parse_blocks, _states,
)

PAGE = 4096
BASE = 0x10000

# Offset of the page-state map inside a MemoryRegion payload: BaseAddr(8) +
# RegionSize(8) + Protection(1) + RegionType(1) + PageSizeLog2(1) +
# Reserved(5) + Timestamp(8).
_REGION_FIXED_HEADER = 32


class ResidentBridge(FaultingBridge):
    """A :class:`FaultingBridge` that also answers residency queries.

    Attributes:
        resident_pages: Page-aligned addresses the target has touched; every
            other page of a queried span is reported as never touched.
        method: What :meth:`residency_method` answers.
        residency_queries: Every ``(address, size)`` the engine asked about.
    """

    def __init__(
        self, *args, resident_pages: set[int] | None = None,
        method: str = "pagemap", **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.resident_pages = set(resident_pages or ())
        self.method = method
        self.residency_queries: list[tuple[int, int]] = []

    def residency_method(self) -> str:
        return self.method

    def query_residency(self, address: int, size: int) -> bytes | None:
        self.residency_queries.append((address, size))
        if self.method == "none":
            return None
        pages = (size + PAGE - 1) // PAGE
        return bytes(
            1 if address + i * PAGE in self.resident_pages else 0
            for i in range(pages)
        )


class ShortMaskBridge(ResidentBridge):
    """Answers residency with a mask one entry too short."""

    def query_residency(self, address: int, size: int) -> bytes | None:
        mask = super().query_residency(address, size)
        return mask[:-1] if mask else mask


class RaisingMaskBridge(ResidentBridge):
    """Raises from the residency query, as a broken agent would."""

    def query_residency(self, address: int, size: int) -> bytes | None:
        self.residency_queries.append((address, size))
        raise RuntimeError("agent gone")


def _anon_range(pages: int = 16, name: str = "[anon:dalvik-LinearAlloc]",
                base: int = BASE, size: int | None = None) -> MemoryRange:
    return MemoryRange(
        base=base, size=size if size is not None else pages * PAGE,
        protection="rw-", file_path=name,
    )


def _pages(*indexes: int, base: int = BASE) -> set[int]:
    """Absolute page addresses for page *indexes* of the region at *base*."""
    return {base + i * PAGE for i in indexes}


def _engine(bridge, **kwargs) -> AcquisitionEngine:
    return AcquisitionEngine(bridge, resident_only=True, **kwargs)


def _region_payload(path: Path) -> bytes:
    payload = _find_block(_parse_blocks(path.read_bytes()), BlockType.MemoryRegion)
    assert payload is not None
    return payload


def _decode_region(payload: bytes) -> tuple[list[PageState], bytes]:
    """Decode a MemoryRegion payload into its page states and page data."""
    region_size = struct.unpack_from("<Q", payload, 8)[0]
    page_size = 1 << payload[18]
    num_pages = region_size // page_size
    map_len = pad8((num_pages + 3) // 4)
    packed = payload[_REGION_FIXED_HEADER:_REGION_FIXED_HEADER + map_len]
    states = [
        PageState((packed[i // 4] >> (6 - (i % 4) * 2)) & 0x03)
        for i in range(num_pages)
    ]
    return states, payload[_REGION_FIXED_HEADER + map_len:]


def _touched_pages(reads: list[tuple[int, int]]) -> set[int]:
    """Every page address covered by the recorded reads."""
    touched: set[int] = set()
    for address, size in reads:
        first = address - address % PAGE
        touched.update(range(first, address + size, PAGE))
    return touched


class TestResidentRunsPruning:
    """Case (a): only resident runs are read; the rest is NOT_RESIDENT."""

    def _acquire(self, tmp_path: Path):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 1, 9),
        )
        result = _engine(bridge).acquire(tmp_path / "dump.msl")
        return bridge, result

    def test_reads_never_touch_nonresident_pages(self, tmp_path: Path):
        bridge, _ = self._acquire(tmp_path)

        assert _touched_pages(bridge.reads) == _pages(0, 1, 9)

    def test_runs_are_read_as_two_spans(self, tmp_path: Path):
        bridge, _ = self._acquire(tmp_path)

        assert bridge.reads == [(BASE, 2 * PAGE), (BASE + 9 * PAGE, PAGE)]

    def test_written_page_states_and_data(self, tmp_path: Path):
        self._acquire(tmp_path)

        states, data = _decode_region(_region_payload(tmp_path / "dump.msl"))

        assert states == _states(
            (PageState.CAPTURED, 2), (PageState.NOT_RESIDENT, 7),
            (PageState.CAPTURED, 1), (PageState.NOT_RESIDENT, 6),
        )
        assert len(data) == 3 * PAGE

    def test_result_accounting(self, tmp_path: Path):
        """Case (g): the result reports pruning and no data loss."""
        _, result = self._acquire(tmp_path)

        assert result.pages_nonresident == 13
        assert result.bytes_nonresident == 13 * PAGE
        assert result.residency_method == "pagemap"
        assert result.pages_failed == 0
        assert result.pages_captured == 3
        assert result.bytes_captured == 3 * PAGE
        assert result.bytes_attempted == 3 * PAGE
        assert result.unreadable_ranges == []

    def test_one_debug_line_per_pruned_region(self, tmp_path: Path, caplog):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 1, 9),
        )
        with caplog.at_level(logging.DEBUG, logger="memslicer"):
            _engine(bridge).acquire(tmp_path / "dump.msl")

        lines = [r for r in caplog.records if r.getMessage().startswith("resident-only: ")]
        assert len(lines) == 1
        assert lines[0].getMessage() == f"resident-only: 0x{BASE:x} 3/16 pages read (2 runs)"


class TestGapMerging:
    """Case (b): small gaps are bridged and read as part of the run."""

    def test_pages_within_gap_are_read(self, tmp_path: Path):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 3),
        )
        _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.reads == [(BASE, 4 * PAGE)]
        states, _ = _decode_region(_region_payload(tmp_path / "dump.msl"))
        assert states == _states(
            (PageState.CAPTURED, 4), (PageState.NOT_RESIDENT, 12),
        )

    def test_gap_setting_is_honoured(self, tmp_path: Path):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 3),
        )
        _engine(bridge, resident_gap_pages=0).acquire(tmp_path / "dump.msl")

        assert bridge.reads == [(BASE, PAGE), (BASE + 3 * PAGE, PAGE)]


class TestPruningScope:
    """Which regions and configurations are eligible for pruning."""

    def test_file_backed_region_is_never_pruned(self, tmp_path: Path):
        """Case (c): an untouched page of a mapped file holds file content."""
        bridge = ResidentBridge(ranges=[MemoryRange(
            base=BASE, size=4 * PAGE, protection="r-x",
            file_path="/system/lib64/libfoo.so",
        )])
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == []
        assert (BASE, 4 * PAGE) in bridge.reads
        assert result.pages_nonresident == 0
        assert result.pages_captured == 4

    @pytest.mark.parametrize("name,prot", [
        ("/memfd:jit-cache (deleted)", "rw-"),
        ("[anon_shmem:dalvik-zygote-jit-code-cache]", "r-x"),
        ("[anon_shmem:some-shared-arena]", "rw-"),
        ("/dev/ashmem/dalvik-main space (deleted)", "rw-"),
        ("/dev/zero (deleted)", "rw-"),
    ])
    def test_shared_memory_is_never_pruned(self, tmp_path: Path, name, prot):
        """Shared pages may live in another process's page tables."""
        bridge = ResidentBridge(ranges=[MemoryRange(
            base=BASE, size=4 * PAGE, protection=prot, file_path=name,
        )])
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == []
        assert (BASE, 4 * PAGE) in bridge.reads
        assert result.pages_nonresident == 0
        assert result.pages_captured == 4

    def test_disabled_never_queries_residency(self, tmp_path: Path):
        """Case (d)."""
        bridge = ResidentBridge(ranges=[_anon_range(16)], resident_pages=set())
        result = AcquisitionEngine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == []
        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.residency_method == "none"
        assert result.pages_nonresident == 0

    def test_all_resident_takes_the_single_read_path(self, tmp_path: Path):
        """Case (e)."""
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(*range(16)),
        )
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == [(BASE, 16 * PAGE)]
        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.pages_nonresident == 0
        assert result.pages_captured == 16

    def test_bridge_without_capability_reads_everything(self, tmp_path: Path):
        bridge = FaultingBridge(ranges=[_anon_range(16)])
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.residency_method == "none"

    def test_short_mask_is_ignored(self, tmp_path: Path):
        bridge = ShortMaskBridge(ranges=[_anon_range(16)], resident_pages=_pages(0))
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.pages_nonresident == 0

    def test_raising_query_falls_back_to_full_read(self, tmp_path: Path):
        bridge = RaisingMaskBridge(ranges=[_anon_range(16)])
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == [(BASE, 16 * PAGE)]
        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.pages_captured == 16


class TestResidencyMethod:
    """Case (f): the method is announced once and ``"none"`` warns."""

    def test_unavailable_method_warns_and_reads_everything(self, tmp_path: Path, caplog):
        bridge = ResidentBridge(ranges=[_anon_range(16)], method="none")
        with caplog.at_level(logging.INFO, logger="memslicer"):
            result = _engine(bridge).acquire(tmp_path / "dump.msl")

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("resident-only pruning is unavailable" in r.getMessage()
                   for r in warnings)
        assert "resident-only pruning: method=none" in caplog.text
        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert result.residency_method == "none"
        assert result.pages_nonresident == 0

    def test_available_method_is_logged_at_info(self, tmp_path: Path, caplog):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0), method="mincore",
        )
        with caplog.at_level(logging.INFO, logger="memslicer"):
            result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert "resident-only pruning: method=mincore" in caplog.text
        assert not [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "resident-only" in r.getMessage()
        ]
        assert result.residency_method == "mincore"


class TestFaultInsideResidentRun:
    """Case (h): a fault inside a run is still localised to its page."""

    def test_faulting_page_is_failed_not_nonresident(self, tmp_path: Path):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 1, 2),
            bad_pages=(BASE + PAGE,),
        )
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        states, data = _decode_region(_region_payload(tmp_path / "dump.msl"))
        assert states == _states(
            (PageState.CAPTURED, 1), (PageState.FAILED, 1),
            (PageState.CAPTURED, 1), (PageState.NOT_RESIDENT, 13),
        )
        assert len(data) == 2 * PAGE
        assert result.pages_failed == 1
        assert result.pages_nonresident == 13
        assert result.pages_captured == 2
        assert _touched_pages(bridge.reads) == _pages(0, 1, 2)

    def test_lost_range_covers_only_the_faulting_page(self, tmp_path: Path):
        bridge = ResidentBridge(
            ranges=[_anon_range(16)], resident_pages=_pages(0, 1, 2),
            bad_pages=(BASE + PAGE,),
        )
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert [(r.base, r.size) for r in result.unreadable_ranges] == [
            (BASE + PAGE, PAGE),
        ]


class TestPartialLastPage:
    """A range ending mid-page is widened to whole pages at enumeration, so
    ``bytes_attempted`` and ``bytes_nonresident`` cover the aligned span and
    the region block carries exactly PageSize bytes per Captured page."""

    def test_nonresident_bytes_cover_the_aligned_span(self, tmp_path: Path):
        # Five pages, so the startup test read (<= 4 pages) leaves it alone.
        size = 4 * PAGE + 100
        bridge = ResidentBridge(
            ranges=[_anon_range(size=size)], resident_pages=_pages(0),
        )
        result = _engine(bridge).acquire(tmp_path / "dump.msl")

        assert bridge.residency_queries == [(BASE, 5 * PAGE)]
        assert bridge.reads == [(BASE, PAGE)]
        assert result.pages_nonresident == 4
        assert result.bytes_nonresident == 4 * PAGE
        assert result.bytes_attempted == PAGE
        assert result.bytes_attempted + result.bytes_nonresident == 5 * PAGE
        states, data = _decode_region(_region_payload(tmp_path / "dump.msl"))
        assert states == _states((PageState.CAPTURED, 1), (PageState.NOT_RESIDENT, 4))
        assert len(data) == PAGE

    def test_nonresident_bytes_helper_clips_a_partial_last_page(self):
        """The helper itself still honours a real size shorter than the
        region, for callers that account against the enumerator's answer."""
        region = _make_region(
            [PageState.CAPTURED] + [PageState.NOT_RESIDENT] * 4, page_size=PAGE,
        )
        assert _nonresident_bytes(region, 4 * PAGE + 100) == 3 * PAGE + 100
        assert _nonresident_bytes(region, 5 * PAGE) == 4 * PAGE


class TestReadRegionWithMask:
    """``_read_region`` applies a caller-supplied mask directly."""

    def test_mask_argument_prunes_pages(self):
        bridge = ResidentBridge()
        engine = _engine(bridge)
        mask = bytes([1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])

        region, data_size = engine._read_region(
            BASE, 16 * PAGE, 0x03, "", PAGE, residency=mask,
        )

        assert region.region_size == 16 * PAGE
        assert region.page_states == _states(
            (PageState.CAPTURED, 2), (PageState.NOT_RESIDENT, 7),
            (PageState.CAPTURED, 1), (PageState.NOT_RESIDENT, 6),
        )
        assert data_size == 3 * PAGE
        assert sum(map(len, region.page_data_chunks)) == 3 * PAGE

    def test_no_mask_keeps_the_whole_region_path(self):
        bridge = ResidentBridge()
        engine = _engine(bridge)

        region, data_size = engine._read_region(BASE, 16 * PAGE, 0x03, "", PAGE)

        assert bridge.reads == [(BASE, 16 * PAGE)]
        assert region.page_states == [PageState.CAPTURED] * 16
        assert data_size == 16 * PAGE

    def test_all_zero_mask_reads_nothing(self):
        bridge = ResidentBridge()
        engine = _engine(bridge)

        region, data_size = engine._read_region(
            BASE, 4 * PAGE, 0x03, "", PAGE, residency=bytes(4),
        )

        assert bridge.reads == []
        assert region.page_states == [PageState.NOT_RESIDENT] * 4
        assert region.page_data_chunks == []
        assert data_size == 0


class TestCoalesceIgnoresNotResident:
    """Case (i): NOT_RESIDENT pages are never reported as lost."""

    def test_nonresident_pages_do_not_form_ranges(self):
        region = _make_region([PageState.NOT_RESIDENT] * 4)

        assert coalesce_unreadable(region) == []

    def test_nonresident_pages_terminate_a_failed_run(self):
        region = _make_region(_states(
            (PageState.CAPTURED, 1), (PageState.NOT_RESIDENT, 2),
            (PageState.FAILED, 1), (PageState.NOT_RESIDENT, 1),
            (PageState.FAILED, 1),
        ))

        ranges = coalesce_unreadable(region)

        assert [(r.base, r.size) for r in ranges] == [
            (BASE + 3 * PAGE, PAGE), (BASE + 5 * PAGE, PAGE),
        ]
