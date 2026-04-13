"""Tests for :mod:`memslicer.acquirer.collectors.source_spec`."""
from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.source_spec import (
    RunResult,
    SourceSpec,
    run_specs,
)


# ---------------------------------------------------------------------------
# Privacy gating
# ---------------------------------------------------------------------------

class TestPrivacyGating:

    def test_public_always_runs(self) -> None:
        r = run_specs([SourceSpec("distro", lambda: "Ubuntu")])
        assert r.values == {"distro": "Ubuntu"}
        assert r.skipped == []

    def test_serial_skipped_without_flag(self) -> None:
        called = []
        spec = SourceSpec("hw_serial", lambda: called.append(1) or "DEADBEEF",
                          privacy="serial")
        r = run_specs([spec], include_serials=False)
        assert called == []  # fn not invoked at all
        assert "hw_serial" not in r.values
        assert "hw_serial" in r.skipped

    def test_serial_runs_with_flag(self) -> None:
        r = run_specs(
            [SourceSpec("hw_serial", lambda: "DEADBEEF", privacy="serial")],
            include_serials=True,
        )
        assert r.values == {"hw_serial": "DEADBEEF"}

    def test_netid_skipped_without_flag(self) -> None:
        r = run_specs(
            [SourceSpec("nic_macs", lambda: "aa:bb:cc", privacy="netid")],
            include_network_identity=False,
        )
        assert "nic_macs" not in r.values
        assert "nic_macs" in r.skipped

    def test_netid_runs_with_flag(self) -> None:
        r = run_specs(
            [SourceSpec("nic_macs", lambda: "aa:bb:cc", privacy="netid")],
            include_network_identity=True,
        )
        assert r.values == {"nic_macs": "aa:bb:cc"}


# ---------------------------------------------------------------------------
# Empty value handling
# ---------------------------------------------------------------------------

class TestEmptyValues:

    def test_empty_string_omitted_from_values(self) -> None:
        r = run_specs([SourceSpec("domain", lambda: "")])
        assert "domain" not in r.values
        assert r.warnings == []  # optional → no warning

    def test_zero_int_omitted_from_values(self) -> None:
        r = run_specs([SourceSpec("ram", lambda: 0)])
        assert "ram" not in r.values

    def test_non_optional_empty_emits_warning(self) -> None:
        r = run_specs(
            [SourceSpec("hostname", lambda: "", optional=False)]
        )
        assert "hostname" not in r.values
        assert "hostname_unreadable" in r.warnings

    def test_zero_from_non_optional_also_warns(self) -> None:
        r = run_specs(
            [SourceSpec("boot_time", lambda: 0, optional=False)]
        )
        assert "boot_time_unreadable" in r.warnings


# ---------------------------------------------------------------------------
# Exception containment
# ---------------------------------------------------------------------------

class TestExceptionContainment:

    def test_raising_spec_does_not_propagate(self) -> None:
        def broken() -> str:
            raise RuntimeError("boom")

        r = run_specs([
            SourceSpec("broken", broken),
            SourceSpec("ok", lambda: "value"),
        ])
        # Earlier spec raised, later spec still ran.
        assert r.values == {"ok": "value"}

    def test_raising_non_optional_emits_warning(self) -> None:
        r = run_specs([
            SourceSpec("critical", lambda: (_ for _ in ()).throw(OSError("x")),
                       optional=False),
        ])
        assert "critical_unreadable" in r.warnings


# ---------------------------------------------------------------------------
# Budgets and timeouts
# ---------------------------------------------------------------------------

class TestBudgets:

    def test_global_budget_stops_later_specs(self) -> None:
        def slow() -> str:
            time.sleep(0.12)
            return "ran"

        r = run_specs(
            [
                SourceSpec("slow1", slow),
                SourceSpec("slow2", slow),
                SourceSpec("slow3", slow),
            ],
            global_budget_ms=100,
        )
        # slow1 runs; budget then blown; slow2/slow3 skipped with warning.
        assert "global_budget_exceeded" in r.warnings
        assert len(r.skipped) >= 1

    def test_per_spec_timeout_drops_late_value(self) -> None:
        def slow() -> str:
            time.sleep(0.05)
            return "late"

        r = run_specs(
            [SourceSpec("late", slow, timeout_ms=1)],
            global_budget_ms=5000,
        )
        # fn returned but took > timeout_ms → dropped.
        assert "late" not in r.values

    def test_per_spec_timeout_non_optional_warns(self) -> None:
        def slow() -> str:
            time.sleep(0.05)
            return "late"

        r = run_specs(
            [SourceSpec("late", slow, timeout_ms=1, optional=False)],
            global_budget_ms=5000,
        )
        assert "late_timeout" in r.warnings


# ---------------------------------------------------------------------------
# RunResult shape
# ---------------------------------------------------------------------------

def test_run_result_is_structured_dataclass() -> None:
    r = run_specs([])
    assert isinstance(r, RunResult)
    assert r.values == {}
    assert r.warnings == []
    assert r.skipped == []
