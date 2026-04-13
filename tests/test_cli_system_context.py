"""Tests for ``memslicer-sysctx`` (the read-only Section 6 inspector).

Uses CliRunner for fast flag / schema / exit-code tests with a
mock collector, plus one real subprocess invocation to catch
entry-point / import-time wiring bugs that CliRunner can't.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer import cli_sysctx
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry


# ---------------------------------------------------------------------------
# Fake collector with configurable richness
# ---------------------------------------------------------------------------

class _FakeCollector:
    """Deterministic collector for sysctx CLI tests.

    Populates every enrichment field so plain/rich/json formatting can
    be exercised against a realistic shape. Process / Connection /
    Handle tables contain one entry each, which is enough to verify
    formatting loops and JSON shape without combinatoric test matrices.
    """

    _is_memslicer_collector = True

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        return TargetProcessInfo(
            ppid=1,
            session_id=2,
            start_time_ns=1_700_000_000_000_000_000,
            exe_path="/usr/bin/fake",
            cmd_line="/usr/bin/fake --flag",
        )

    def collect_system_info(self) -> TargetSystemInfo:
        return TargetSystemInfo(
            boot_time=1_699_000_000_000_000_000,
            hostname="lab-box",
            domain="lab.example",
            os_detail="",
            kernel="6.8.0-45-generic",
            arch="x86_64",
            distro="Ubuntu 24.04.1 LTS",
            machine_id="deadbeefcafe",
            hw_vendor="Dell Inc.",
            hw_model="Latitude 7440",
            bios_version="1.14.0",
            cpu_brand="Intel(R) Core(TM) i7-1365U",
            cpu_count=12,
            ram_bytes=34_359_738_368,
            timezone="Europe/Berlin",
        )

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        return [ProcessEntry(
            pid=1234, ppid=1, uid=1000,
            is_target=(target_pid == 1234),
            start_time=0, rss=65536,
            exe_name="/usr/bin/fake", cmd_line="fake --a", user="alice",
        )]

    def collect_connection_table(self) -> list[ConnectionEntry]:
        return [ConnectionEntry(
            pid=1234, family=0x02, protocol=0x06, state=0x01,
            local_addr=b"\x7f\x00\x00\x01" + b"\x00" * 12,
            local_port=443,
            remote_addr=b"\x08\x08\x08\x08" + b"\x00" * 12,
            remote_port=54321,
        )]

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        return [HandleEntry(pid=pid, fd=3, handle_type=0x01, path="/etc/passwd")]


class _EmptyCollector:
    """Collector that returns nothing — triggers the partial-completion exit."""

    _is_memslicer_collector = True

    def collect_process_identity(self, pid): return TargetProcessInfo()
    def collect_system_info(self): return TargetSystemInfo()
    def collect_process_table(self, pid): return []
    def collect_connection_table(self): return []
    def collect_handle_table(self, pid): return []


# ---------------------------------------------------------------------------
# Shared patch context
# ---------------------------------------------------------------------------

def _run(args: list[str], *, collector=None) -> "tuple[int, str, str]":
    """Invoke the CLI via CliRunner with the collector factory patched."""
    if collector is None:
        collector = _FakeCollector()
    runner = CliRunner()
    with patch.object(cli_sysctx, "_make_collector", return_value=collector):
        result = runner.invoke(cli_sysctx.main, args, catch_exceptions=False)
    # Click 9+ returns stderr via result.stderr_bytes / result.stderr when
    # available; fall back gracefully for older/newer versions.
    stderr = ""
    try:
        stderr = result.stderr or ""
    except (ValueError, AttributeError):
        stderr = ""
    return result.exit_code, result.stdout, stderr


# ---------------------------------------------------------------------------
# JSON output — schema / fields / exit codes
# ---------------------------------------------------------------------------

class TestJsonOutput:

    def test_json_emits_schema_tag(self) -> None:
        code, out, _ = _run(["--format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["schema"] == "memslicer.system-context/v1"

    def test_json_shape_contains_all_sections(self) -> None:
        _, out, _ = _run(["--format", "json"])
        payload = json.loads(out)
        assert "system_context" in payload
        assert "process_table" in payload
        assert "connection_table" in payload
        assert "handle_table" in payload

    def test_system_context_has_core_fields(self) -> None:
        _, out, _ = _run(["--format", "json"])
        sc = json.loads(out)["system_context"]
        assert sc["hostname"] == "lab-box"
        assert sc["domain"] == "lab.example"
        assert "msl.memslicer/1" in sc["os_detail"]
        assert sc["acq_user"]  # getpass default

    def test_examiner_and_case_ref_flow_through(self) -> None:
        _, out, _ = _run([
            "--format", "json",
            "--examiner", "alice",
            "--case-ref", "CASE-2026-017",
        ])
        sc = json.loads(out)["system_context"]
        assert sc["acq_user"] == "alice"
        assert sc["case_ref"] == "CASE-2026-017"

    def test_invalid_case_ref_rejected(self) -> None:
        code, _, err = _run(["--format", "json", "--case-ref", "evil;x=1"])
        assert code != 0
        assert "os_detail microformat" in err.lower() or "not allowed" in err.lower()

    def test_target_pid_populates_process_identity(self) -> None:
        _, out, _ = _run(["--format", "json", "1234"])
        payload = json.loads(out)
        assert payload["process_identity"] is not None
        assert payload["process_identity"]["exe_path"] == "/usr/bin/fake"

    def test_no_target_omits_process_identity_and_handles(self) -> None:
        _, out, _ = _run(["--format", "json"])
        payload = json.loads(out)
        assert payload["process_identity"] is None
        assert payload["handle_table"] == []
        # System-wide tables are still collected — they're not target-scoped.
        assert len(payload["process_table"]) == 1
        assert len(payload["connection_table"]) == 1

    def test_skip_tables_respected(self) -> None:
        _, out, _ = _run(["--format", "json", "--skip-tables", "process,connection"])
        payload = json.loads(out)
        assert payload["process_table"] == []
        assert payload["connection_table"] == []


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:

    def test_complete_collection_returns_zero(self) -> None:
        code, _, _ = _run(["--format", "json"])
        assert code == cli_sysctx.EXIT_OK

    def test_empty_collection_returns_partial(self) -> None:
        code, _, _ = _run(["--format", "json"], collector=_EmptyCollector())
        assert code == cli_sysctx.EXIT_PARTIAL

    def test_strict_upgrades_partial_to_failure(self) -> None:
        code, _, _ = _run(
            ["--format", "json", "--strict"],
            collector=_EmptyCollector(),
        )
        assert code == cli_sysctx.EXIT_FAILURE


# ---------------------------------------------------------------------------
# Remote hostname attribution (same bug as engine P0.1 #3)
# ---------------------------------------------------------------------------

class _RemoteBlindCollector(_FakeCollector):
    def collect_system_info(self) -> TargetSystemInfo:
        return TargetSystemInfo(os_detail="iOS sandbox")


class TestRemoteHostnameNotLeaked:

    def test_usb_empty_hostname_stays_empty(self) -> None:
        with patch(
            "memslicer.acquirer.identity.socket.gethostname",
            side_effect=AssertionError("must not be called on -U"),
        ):
            _, out, _ = _run(
                ["--format", "json", "-U"],
                collector=_RemoteBlindCollector(),
            )
        sc = json.loads(out)["system_context"]
        assert sc["hostname"] == ""
        assert "remote_hostname_unavailable" in sc["collector_warnings"]

    def test_hostname_override_wins(self) -> None:
        _, out, _ = _run(
            ["--format", "json", "-U", "--hostname-override", "device-17"],
            collector=_RemoteBlindCollector(),
        )
        sc = json.loads(out)["system_context"]
        assert sc["hostname"] == "device-17"


# ---------------------------------------------------------------------------
# Plain / Rich output
# ---------------------------------------------------------------------------

class TestPlainOutput:

    def test_plain_contains_core_fields(self) -> None:
        _, out, _ = _run(["--format", "plain"])
        assert "lab-box" in out
        assert "System Context" in out
        assert "os_detail" in out

    def test_plain_no_ansi_escapes(self) -> None:
        _, out, _ = _run(["--format", "plain"])
        assert "\x1b[" not in out  # no ANSI color codes


class TestRichOutput:

    def test_rich_degrades_to_plain_when_missing(self) -> None:
        # Simulate rich being uninstalled by patching its import site.
        import importlib
        real_import = importlib.import_module

        def fake_import(name, *a, **k):
            if name == "rich.console" or name == "rich.table":
                raise ImportError("rich not installed (simulated)")
            return real_import(name, *a, **k)

        with patch("importlib.import_module", side_effect=fake_import):
            _, out, _ = _run(["--format", "rich"])
        # Plain fallback still includes the header.
        assert "System Context" in out


# ---------------------------------------------------------------------------
# Real subprocess entry-point test (catches import wiring)
# ---------------------------------------------------------------------------

class TestEntryPointWiring:

    def test_module_runnable_via_python_dash_m(self) -> None:
        """Run the CLI as ``python -m memslicer.cli_sysctx``.

        CliRunner exercises the click command but cannot catch import
        bugs between ``memslicer.cli_sysctx`` and its transitive
        dependencies. This test does, at the cost of one subprocess.
        """
        result = subprocess.run(
            [sys.executable, "-m", "memslicer.cli_sysctx", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        # Exit code may be 0 or 2 depending on whether the host collector
        # manages to populate the minimum set; both are valid behaviors
        # for the binary. Exit code 1 is a hard failure we DO want to fail on.
        assert result.returncode in (0, 2), (
            f"unexpected exit {result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        payload = json.loads(result.stdout)
        assert payload["schema"] == "memslicer.system-context/v1"
        assert "system_context" in payload
