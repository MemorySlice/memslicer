"""Tests for region planning: scope / module omission, the 0x005B manifest,
``survey_regions()`` and the per-session classifier wiring."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.acquirer.engine import (
    AcquisitionEngine, RegionDecision, RegionSurvey, classify_region,
)
from memslicer.acquirer.region_classify import RegionCategory
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    ArchType, BlockType, OSType, OmissionReason,
)
from memslicer.msl.writer import parse_region_omission_manifest
from test_engine import MockBridge, _find_block, _parse_blocks


PAGE = 4096
LIBC = "/system/lib64/libc.so"
APK = "/data/app/com.example/base.apk"

# (name, base, pages, prot) -- an Android-like mix. The stack has the lowest
# base so it sorts first among the rw- regions the startup read would pick.
_RANGES = [
    ("[anon:stack_and_tls:4242]", 0x08000, 1, "rw-"),
    ("[anon:scudo:primary]", 0x10000, 2, "rw-"),
    ("[anon:dalvik-main space (region space)]", 0x20000, 4, "rw-"),
    (LIBC, 0x40000, 2, "r-x"),
    (LIBC, 0x42000, 1, "rw-"),
    ("[anon:.bss]", 0x43000, 1, "rw-"),
    (APK, 0x50000, 1, "r--"),
    ("", 0x60000, 1, "rw-"),
    ("[anon:cfi shadow]", 0x70000, 1, "r--"),
    ("", 0x80000, 1, "---"),
]
# libc ends exactly where the .bss starts, so the .bss is attributed to it.
_MODULES = [ModuleInfo(name="libc.so", path=LIBC, base=0x40000, size=0x3000)]

HEAP_KEPT = {0x10000, 0x20000, 0x60000}
HEAP_SCOPE_SKIPPED = {0x08000, 0x40000, 0x42000, 0x43000, 0x50000, 0x70000}
NO_READ = 0x80000
LIBC_REGIONS = {0x40000, 0x42000, 0x43000}


def _ranges() -> list[MemoryRange]:
    return [
        MemoryRange(base=b, size=n * PAGE, protection=p, file_path=name)
        for name, b, n, p in _RANGES
    ]


def _memory(ranges: list[MemoryRange]) -> dict[int, bytes]:
    return {r.base: b"\x5a" * r.size for r in ranges}


class RecordingBridge(MockBridge):
    """A MockBridge that remembers every read address."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.reads: list[tuple[int, int]] = []

    def read_memory(self, address: int, size: int) -> bytes | None:
        self.reads.append((address, size))
        return super().read_memory(address, size)


class StackPointerBridge(MockBridge):
    """A MockBridge that also implements ``enumerate_stack_pointers``."""

    def __init__(self, sps: list[int], *, fail: bool = False, **kwargs) -> None:
        super().__init__(**kwargs)
        self.sps = sps
        self.fail = fail
        self.sp_calls = 0

    def enumerate_stack_pointers(self) -> list[int]:
        self.sp_calls += 1
        if self.fail:
            raise RuntimeError("no thread access")
        return list(self.sps)


def _bridge(cls=MockBridge, **extra) -> MockBridge:
    ranges = _ranges()
    return cls(
        ranges=ranges,
        modules=list(_MODULES),
        platform_info=PlatformInfo(
            arch=ArchType.ARM64, os=OSType.Android, pid=4242, page_size=PAGE,
        ),
        memory=_memory(ranges),
        **extra,
    )


def _region_bases(blocks) -> list[int]:
    import struct
    return [
        struct.unpack_from("<Q", payload, 0)[0]
        for bt, _flags, payload in blocks if bt == BlockType.MemoryRegion
    ]


def _manifest(blocks):
    payload = _find_block(blocks, BlockType.RegionOmissionManifest)
    assert payload is not None, "no RegionOmissionManifest block written"
    return parse_region_omission_manifest(payload)


# ---------------------------------------------------------------------------
# Omission manifest in the written file
# ---------------------------------------------------------------------------


class TestScopeOmissionManifest:
    """``--scope heap`` captures only heap regions and lists the rest."""

    @pytest.fixture
    def run(self, tmp_path: Path):
        engine = AcquisitionEngine(
            _bridge(), region_filter=RegionFilter(scope="heap"),
        )
        output = tmp_path / "heap.msl"
        result = engine.acquire(output)
        return result, _parse_blocks(output.read_bytes())

    def test_only_heap_regions_are_written(self, run):
        _result, blocks = run
        assert set(_region_bases(blocks)) == HEAP_KEPT

    def test_manifest_lists_every_scope_skipped_range(self, run):
        _result, blocks = run
        manifest = _manifest(blocks)
        assert manifest.scope == "heap"
        assert manifest.exclude_patterns == []
        assert {row.base_addr for row in manifest.rows} == HEAP_SCOPE_SKIPPED
        assert all(row.reason == OmissionReason.SCOPE for row in manifest.rows)

    def test_no_read_skips_are_not_in_the_manifest(self, run):
        result, blocks = run
        assert NO_READ not in {r.base_addr for r in _manifest(blocks).rows}
        assert result.skip_reasons == {"scope": 6, "no-read": 1}

    def test_rows_carry_name_protection_and_on_disk_region_type(self, run):
        _result, blocks = run
        rows = {row.base_addr: row for row in _manifest(blocks).rows}
        assert rows[0x08000].name == "stack_and_tls:4242"
        assert rows[0x08000].protection == 0b011
        assert rows[0x40000].name == LIBC
        assert rows[0x40000].protection == 0b101
        assert rows[0x43000].name == LIBC  # .bss names its owning module
        for base, row in rows.items():
            name = next(n for n, b, _, _ in _RANGES if b == base)
            assert row.region_type == classify_region(name)
            assert row.size == PAGE * next(n for _, b, n, _ in _RANGES if b == base)

    def test_result_reports_scope_and_omissions(self, run):
        result, _blocks = run
        assert result.scope == "heap"
        assert result.regions_omitted == len(HEAP_SCOPE_SKIPPED)
        assert result.regions_skipped == len(HEAP_SCOPE_SKIPPED) + 1
        assert result.regions_captured == len(HEAP_KEPT)

    def test_manifest_sits_between_regions_and_module_entries(self, run):
        _result, blocks = run
        types = [bt for bt, _f, _p in blocks]
        manifest_at = types.index(BlockType.RegionOmissionManifest)
        last_region = max(i for i, t in enumerate(types) if t == BlockType.MemoryRegion)
        first_entry = types.index(BlockType.ModuleEntry)
        assert last_region < manifest_at < first_entry
        assert types[-2] == BlockType.VASMap


class TestModuleExcludeOmissionManifest:
    """``--exclude-module libc.so`` drops the module's regions, .bss included."""

    @pytest.fixture
    def run(self, tmp_path: Path):
        engine = AcquisitionEngine(
            _bridge(), region_filter=RegionFilter(exclude_modules=["libc.so"]),
        )
        output = tmp_path / "nolibc.msl"
        result = engine.acquire(output)
        return result, _parse_blocks(output.read_bytes())

    def test_module_regions_are_not_written(self, run):
        _result, blocks = run
        written = set(_region_bases(blocks))
        assert not (written & LIBC_REGIONS)
        assert HEAP_KEPT <= written

    def test_manifest_records_module_exclude_rows(self, run):
        result, blocks = run
        manifest = _manifest(blocks)
        assert manifest.scope == "full"
        assert manifest.exclude_patterns == ["libc.so"]
        assert {r.base_addr for r in manifest.rows} == LIBC_REGIONS
        assert all(r.reason == OmissionReason.MODULE_EXCLUDE for r in manifest.rows)
        assert all(r.name == LIBC for r in manifest.rows)
        assert result.regions_omitted == 3
        assert result.scope == "full"


class TestDefaultRunHasNoManifest:
    def test_full_scope_writes_no_omission_block(self, tmp_path: Path):
        engine = AcquisitionEngine(_bridge())
        output = tmp_path / "full.msl"

        result = engine.acquire(output)

        blocks = _parse_blocks(output.read_bytes())
        assert _find_block(blocks, BlockType.RegionOmissionManifest) is None
        assert result.regions_omitted == 0
        assert result.scope == "full"
        # The no-read range is still skipped and counted as before.
        assert result.skip_reasons == {"no-read": 1}


# ---------------------------------------------------------------------------
# Startup read
# ---------------------------------------------------------------------------


class TestStartupReadHonoursPlan:
    def test_startup_read_never_touches_a_skipped_range(self, tmp_path: Path):
        bridge = _bridge(RecordingBridge)
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="heap"))

        engine.acquire(tmp_path / "heap.msl")

        # The stack at 0x8000 sorts first and is small enough for the test
        # read, but it is out of scope; the first read lands on a kept range.
        assert bridge.reads[0][0] == 0x10000
        touched = {addr for addr, _size in bridge.reads}
        assert not (touched & HEAP_SCOPE_SKIPPED)
        assert NO_READ not in touched


# ---------------------------------------------------------------------------
# survey_regions()
# ---------------------------------------------------------------------------


class TestSurveyRegions:
    def test_survey_plans_without_writing_or_reading(self, tmp_path: Path):
        bridge = _bridge(RecordingBridge)
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="heap"))

        survey = engine.survey_regions()

        assert isinstance(survey, RegionSurvey)
        assert survey.os_type == OSType.Android
        assert survey.page_size == PAGE
        assert survey.modules == _MODULES
        assert len(survey.decisions) == len(_RANGES)
        assert all(isinstance(d, RegionDecision) for d in survey.decisions)
        assert bridge.reads == []
        assert list(tmp_path.iterdir()) == []

    def test_survey_disconnects_the_bridge(self):
        bridge = _bridge()
        engine = AcquisitionEngine(bridge)

        engine.survey_regions()

        assert bridge.connect_count == 1
        assert bridge.disconnect_count == 1
        assert bridge.connected is False

    def test_survey_disconnects_even_when_enumeration_fails(self):
        bridge = _bridge()

        def boom():
            raise RuntimeError("ranges unavailable")

        bridge.enumerate_ranges = boom
        engine = AcquisitionEngine(bridge)

        with pytest.raises(RuntimeError, match="ranges unavailable"):
            engine.survey_regions()
        assert bridge.disconnect_count == 1

    def test_survey_kept_and_skipped_match_the_filter(self):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="heap"))

        survey = engine.survey_regions()

        assert {d.range.base for d in survey.kept()} == HEAP_KEPT
        assert {d.range.base for d in survey.skipped()} == HEAP_SCOPE_SKIPPED | {NO_READ}
        assert survey.skip_reason_counts() == {"scope": 6, "no-read": 1}

    def test_survey_follows_volatility_order(self):
        survey = AcquisitionEngine(_bridge()).survey_regions()

        bases = [d.range.base for d in survey.decisions]
        # rw- anon/heap/stack first (by base), file-backed and no-read last.
        assert bases[:5] == [0x08000, 0x10000, 0x20000, 0x43000, 0x60000]
        assert bases[-1] == NO_READ

    def test_bytes_by_category(self):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="heap"))

        by_cat = engine.survey_regions().bytes_by_category()

        assert by_cat[RegionCategory.HEAP_NATIVE] == (1, 2 * PAGE, 0, 0)
        assert by_cat[RegionCategory.HEAP_MANAGED] == (1, 4 * PAGE, 0, 0)
        assert by_cat[RegionCategory.STACK] == (0, 0, 1, PAGE)
        assert by_cat[RegionCategory.IMAGE] == (0, 0, 2, 3 * PAGE)
        assert by_cat[RegionCategory.BSS] == (0, 0, 1, PAGE)
        # One unnamed rw- kept, one unnamed --- skipped for no-read.
        assert by_cat[RegionCategory.ANON] == (1, PAGE, 1, PAGE)

    def test_bytes_by_owner_groups_module_regions_and_ranks_by_total(self):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="heap"))

        rows = engine.survey_regions().bytes_by_owner()

        by_label = {label: (kept, skipped) for label, kept, skipped in rows}
        assert by_label["libc.so"] == (0, 4 * PAGE)
        assert by_label["dalvik-main space (region space)"] == (4 * PAGE, 0)
        assert by_label["<unnamed>"] == (PAGE, PAGE)
        totals = [kept + skipped for _label, kept, skipped in rows]
        assert totals == sorted(totals, reverse=True)

    def test_bytes_by_owner_limit(self):
        survey = AcquisitionEngine(_bridge()).survey_regions()
        assert len(survey.bytes_by_owner(limit=2)) == 2


# ---------------------------------------------------------------------------
# Classifier wiring: stack pointers and app paths
# ---------------------------------------------------------------------------


class TestStackPointerDetection:
    def test_unnamed_region_holding_an_sp_is_a_stack(self):
        bridge = _bridge(StackPointerBridge, sps=[0x60800])
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="stack"))

        survey = engine.survey_regions()

        assert bridge.sp_calls == 1
        assert {d.range.base for d in survey.kept()} == {0x08000, 0x60000}

    def test_sp_region_leaves_the_heap_scope(self):
        bridge = _bridge(StackPointerBridge, sps=[0x60800])
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="heap"))

        survey = engine.survey_regions()

        assert {d.range.base for d in survey.kept()} == {0x10000, 0x20000}

    def test_full_scope_does_not_ask_for_stack_pointers(self):
        bridge = _bridge(StackPointerBridge, sps=[0x60800])

        AcquisitionEngine(bridge).survey_regions()

        assert bridge.sp_calls == 0

    def test_failing_sp_enumeration_degrades_to_names(self, caplog):
        bridge = _bridge(StackPointerBridge, sps=[0x60800], fail=True)
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope="stack"))

        with caplog.at_level(logging.DEBUG, logger="memslicer"):
            survey = engine.survey_regions()

        assert {d.range.base for d in survey.kept()} == {0x08000}
        assert any("stack pointer enumeration failed" in r.message for r in caplog.records)

    def test_bridge_without_capability_is_fine(self):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="stack"))
        survey = engine.survey_regions()
        assert {d.range.base for d in survey.kept()} == {0x08000}


class TestAppPathsAndStoredOptions:
    def test_constructor_stores_new_options(self):
        engine = AcquisitionEngine(
            _bridge(), app_paths=["/data/app/"], resident_only=True,
            resident_gap_pages=9,
        )
        assert engine._app_paths == ("/data/app/",)
        assert engine._resident_only is True
        assert engine._resident_gap_pages == 9

    def test_defaults_keep_residency_off(self):
        engine = AcquisitionEngine(_bridge())
        assert engine._app_paths == ()
        assert engine._resident_only is False
        assert engine._resident_gap_pages == 4

    def test_app_paths_reach_the_classifier(self):
        clean_system = AcquisitionEngine(
            _bridge(), region_filter=RegionFilter(scope="app"),
        ).survey_regions()
        as_app = AcquisitionEngine(
            _bridge(), region_filter=RegionFilter(scope="app"),
            app_paths=["/system/lib64/"],
        ).survey_regions()

        # A clean r-x system image is outside the app scope...
        assert 0x40000 in {d.range.base for d in clean_system.skipped()}
        # ...unless its directory was declared app-owned.
        assert 0x40000 in {d.range.base for d in as_app.kept()}

    def test_owner_is_attributed_from_the_module_list(self):
        survey = AcquisitionEngine(_bridge()).survey_regions()
        by_base = {d.range.base: d for d in survey.decisions}
        assert by_base[0x40000].info.owner == _MODULES[0]
        assert by_base[0x43000].info.category is RegionCategory.BSS
        assert by_base[0x43000].info.owner == _MODULES[0]
        assert by_base[0x10000].info.owner is None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class TestSkipLogging:
    def test_debug_line_per_skipped_region(self, tmp_path: Path, caplog):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="heap"))

        with caplog.at_level(logging.DEBUG, logger="memslicer"):
            engine.acquire(tmp_path / "heap.msl")

        skips = [r.message for r in caplog.records if r.message.startswith("skip 0x")]
        assert len(skips) == len(HEAP_SCOPE_SKIPPED) + 1
        assert "skip 0x8000 size=4096 cat=STACK owner=- reason=scope" in skips
        assert "skip 0x40000 size=8192 cat=IMAGE owner=libc.so reason=scope" in skips
        assert "skip 0x80000 size=4096 cat=ANON owner=- reason=no-read" in skips

    def test_no_skip_line_below_debug(self, tmp_path: Path, caplog):
        engine = AcquisitionEngine(_bridge(), region_filter=RegionFilter(scope="heap"))

        with caplog.at_level(logging.INFO, logger="memslicer"):
            engine.acquire(tmp_path / "heap.msl")

        assert not [r for r in caplog.records if r.message.startswith("skip 0x")]
