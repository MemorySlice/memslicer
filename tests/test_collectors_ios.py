"""Tests for IOSCollector (iOS investigation data collection)."""
import sys
import os
import plistlib
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.ios import IOSCollector


def _make_completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture
def collector():
    return IOSCollector()


# ---------------------------------------------------------------------------
# collect_system_info — plist-based OS detail
# ---------------------------------------------------------------------------

class TestCollectSystemInfoIOS:

    def test_system_info_from_plist(self, collector, tmp_path):
        """Read iOS version from a mock SystemVersion.plist."""
        plist_data = {
            "ProductName": "iPhone OS",
            "ProductVersion": "17.4",
            "ProductBuildVersion": "21E219",
        }
        plist_file = tmp_path / "SystemVersion.plist"
        with open(plist_file, "wb") as fh:
            plistlib.dump(plist_data, fh)

        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed("{ sec = 1712345678, usec = 0 }\n"),
            ("domainname",): _make_completed("(none)\n"),
            ("sw_vers",): _make_completed(""),
            ("uname", "-r"): _make_completed(""),
            ("sysctl", "-n", "hw.machine"): _make_completed("iPhone15,2\n"),
        }

        with patch("memslicer.acquirer.collectors.darwin.subprocess.run") as mock_run, \
             patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="iPhone"), \
             patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", str(plist_file)):

            mock_run.side_effect = lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))

            info = collector.collect_system_info()

        assert "iPhone OS" in info.os_detail
        assert "17.4" in info.os_detail
        assert "21E219" in info.os_detail
        assert "iPhone15,2" in info.os_detail

    def test_system_info_plist_missing(self, collector):
        """When SystemVersion.plist doesn't exist, fall back to sw_vers."""
        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed("{ sec = 100, usec = 0 }\n"),
            ("domainname",): _make_completed(""),
            ("sw_vers",): _make_completed("ProductName:\tmacOS\nProductVersion:\t14.0\n"),
            ("uname", "-r"): _make_completed("23.0.0\n"),
            ("sysctl", "-n", "hw.machine"): _make_completed(""),
        }

        with patch("memslicer.acquirer.collectors.darwin.subprocess.run") as mock_run, \
             patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host"), \
             patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", "/nonexistent/path.plist"):

            mock_run.side_effect = lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))
            info = collector.collect_system_info()

        # Falls back to parent's sw_vers output since plist fails
        assert "macOS" in info.os_detail or info.os_detail == ""

    def test_system_info_model_only(self, collector, tmp_path):
        """When plist is missing but hw.machine succeeds, os_detail includes model."""
        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed("", returncode=1),
            ("domainname",): _make_completed(""),
            ("sw_vers",): _make_completed(""),
            ("uname", "-r"): _make_completed(""),
            ("sysctl", "-n", "hw.machine"): _make_completed("iPad13,4\n"),
        }

        with patch("memslicer.acquirer.collectors.darwin.subprocess.run") as mock_run, \
             patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="ipad"), \
             patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", "/nonexistent/path.plist"):

            mock_run.side_effect = lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))
            info = collector.collect_system_info()

        assert "iPad13,4" in info.os_detail


# ---------------------------------------------------------------------------
# _read_device_model
# ---------------------------------------------------------------------------

class TestReadDeviceModel:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_read_device_model_success(self, mock_run, collector):
        mock_run.return_value = _make_completed("iPhone15,2\n")
        assert collector._read_device_model() == "iPhone15,2"

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_read_device_model_failure(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector._read_device_model() == ""


# ---------------------------------------------------------------------------
# Sandbox warnings — empty tables
# ---------------------------------------------------------------------------

class TestSandboxWarnings:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_process_table_empty_warns(self, mock_run, collector):
        """When ps fails on iOS, a sandbox warning should be logged."""
        mock_run.return_value = _make_completed("", returncode=1)

        with patch.object(collector, "_log") as mock_log:
            entries = collector.collect_process_table(1234)

        assert entries == []
        mock_log.warning.assert_called_once()
        assert "sandbox" in mock_log.warning.call_args[0][0].lower()

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_connection_table_empty_warns(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)

        with patch.object(collector, "_log") as mock_log:
            entries = collector.collect_connection_table()

        assert entries == []
        mock_log.warning.assert_called_once()
        assert "lsof" in mock_log.warning.call_args[0][0].lower()

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_handle_table_empty_warns(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)

        with patch.object(collector, "_log") as mock_log:
            entries = collector.collect_handle_table(1234)

        assert entries == []
        mock_log.warning.assert_called_once()
        assert "lsof" in mock_log.warning.call_args[0][0].lower()


# ---------------------------------------------------------------------------
# Fallback behavior — ps/lsof fail
# ---------------------------------------------------------------------------

class TestFallbackBehavior:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_process_identity_fallback_sysctl(self, mock_run, collector):
        """When ps fails, IOSCollector tries sysctl fallback."""
        # All ps commands fail, sysctl kern.proc.pid.42 succeeds
        def side_effect(cmd, **kwargs):
            if cmd[0] == "sysctl" and "kern.proc.pid" in cmd[-1]:
                return _make_completed("some_proc_data\n")
            return _make_completed("", returncode=1)

        mock_run.side_effect = side_effect

        info = collector.collect_process_identity(42)
        # exe_path is still empty (sysctl doesn't populate it in current impl)
        assert info.exe_path == ""
        # But the method shouldn't raise
        assert info.ppid == 0

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_all_commands_fail_no_exception(self, mock_run, collector):
        """No exceptions even if every subprocess call fails."""
        mock_run.side_effect = FileNotFoundError("not found")

        info = collector.collect_process_identity(1)
        assert info.ppid == 0

        with patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host"), \
             patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", "/nonexistent"):
            sys_info = collector.collect_system_info()
        assert sys_info.hostname == "host"

        assert collector.collect_process_table(1) == []
        assert collector.collect_connection_table() == []
        assert collector.collect_handle_table(1) == []
