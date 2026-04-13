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


# ---------------------------------------------------------------------------
# P1.3 iOS enrichment — sysctl-based supplementary fields
# ---------------------------------------------------------------------------


def _base_ios_responses() -> dict:
    """Return a baseline responses dict where every command returns empty.

    Individual tests override specific keys to exercise one enrichment
    path at a time.
    """
    return {
        ("sysctl", "-n", "kern.boottime"):
            _make_completed("{ sec = 1712345678, usec = 0 }\n"),
        ("domainname",): _make_completed("(none)\n"),
        ("sw_vers",): _make_completed(""),
        ("uname", "-r"): _make_completed(""),
        ("sysctl", "-n", "hw.machine"): _make_completed(""),
        ("sysctl", "-n", "hw.model"): _make_completed(""),
        ("sysctl", "-n", "hw.memsize"): _make_completed(""),
        ("sysctl", "-n", "hw.ncpu"): _make_completed(""),
        ("sysctl", "-n", "machdep.cpu.brand_string"): _make_completed(""),
        ("sysctl", "-n", "kern.osrelease"): _make_completed(""),
        ("sysctl", "-n", "kern.osversion"): _make_completed(""),
        ("sysctl", "-n", "kern.osproductversion"): _make_completed(""),
        ("sysctl", "-n", "kern.bootsessionuuid"): _make_completed(""),
        ("sysctl", "-n", "kern.hv_vmm_present"): _make_completed(""),
        ("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"): _make_completed(""),
    }


def _run_collect(collector, responses):
    """Run collect_system_info with the given responses, plist forced missing."""
    with patch("memslicer.acquirer.collectors.darwin.subprocess.run") as mock_run, \
         patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="iPhone"), \
         patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", "/nonexistent/path.plist"):
        mock_run.side_effect = lambda cmd, **kw: responses.get(
            tuple(cmd), _make_completed("", returncode=1)
        )
        return collector.collect_system_info()


class TestIOSEnrichment:
    """Supplementary iOS sysctl-derived fields."""

    def test_board_id_remapped_to_hw_model(self, collector):
        """hw.machine like 'iPhone16,2' moves from arch -> hw_model."""
        responses = _base_ios_responses()
        responses[("sysctl", "-n", "hw.machine")] = _make_completed("iPhone16,2\n")

        # Point jailbreak markers away from any real path to avoid
        # false positives on a jailbroken dev machine.
        collector._jailbreak_markers = {"none": ("/absolutely/not/a/path",)}
        collector._roothide_glob = "/absolutely/not/a/glob-*"

        info = _run_collect(collector, responses)

        assert info.hw_model == "iPhone16,2"
        assert info.arch == "arm64"

    def test_osversion_populates_distro(self, collector):
        """kern.osversion + kern.osproductversion compose info.distro."""
        responses = _base_ios_responses()
        responses[("sysctl", "-n", "kern.osversion")] = _make_completed("21E219\n")
        responses[("sysctl", "-n", "kern.osproductversion")] = _make_completed("17.4\n")

        collector._jailbreak_markers = {"none": ("/nope",)}
        collector._roothide_glob = "/nope-*"

        info = _run_collect(collector, responses)

        assert "iOS 17.4" in info.distro
        assert "21E219" in info.distro

    def test_bootsessionuuid_populates_boot_id(self, collector):
        """kern.bootsessionuuid lands in info.boot_id."""
        uuid = "ABCDEF01-1234-5678-90AB-CDEF01234567"
        responses = _base_ios_responses()
        responses[("sysctl", "-n", "kern.bootsessionuuid")] = _make_completed(f"{uuid}\n")

        collector._jailbreak_markers = {"none": ("/nope",)}
        collector._roothide_glob = "/nope-*"

        info = _run_collect(collector, responses)

        assert info.boot_id == uuid

    def test_macos_like_machine_not_remapped(self, collector):
        """'arm64' from hw.machine stays in arch; hw_model comes from hw.model."""
        responses = _base_ios_responses()
        responses[("sysctl", "-n", "hw.machine")] = _make_completed("arm64\n")
        responses[("sysctl", "-n", "hw.model")] = _make_completed("Macmini9,1\n")

        collector._jailbreak_markers = {"none": ("/nope",)}
        collector._roothide_glob = "/nope-*"

        info = _run_collect(collector, responses)

        assert info.arch == "arm64"
        # Darwin's super() populated hw_model from hw.model; the iOS
        # remap should NOT have clobbered it since hw.machine wasn't a
        # real iOS board ID.
        assert info.hw_model == "Macmini9,1"

    def test_plist_wins_over_sysctl_distro(self, collector, tmp_path):
        """When SystemVersion.plist is readable it overrides sysctl-composed distro."""
        plist_data = {
            "ProductName": "iPhone OS",
            "ProductVersion": "17.4",
            "ProductBuildVersion": "21E219",
        }
        plist_file = tmp_path / "SystemVersion.plist"
        with open(plist_file, "wb") as fh:
            plistlib.dump(plist_data, fh)

        responses = _base_ios_responses()
        responses[("sysctl", "-n", "hw.machine")] = _make_completed("iPhone15,2\n")
        responses[("sysctl", "-n", "kern.osversion")] = _make_completed("21E219\n")
        responses[("sysctl", "-n", "kern.osproductversion")] = _make_completed("17.4\n")

        collector._jailbreak_markers = {"none": ("/nope",)}
        collector._roothide_glob = "/nope-*"

        with patch("memslicer.acquirer.collectors.darwin.subprocess.run") as mock_run, \
             patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="iPhone"), \
             patch.object(IOSCollector, "_SYSTEM_VERSION_PLIST", str(plist_file)):
            mock_run.side_effect = lambda cmd, **kw: responses.get(
                tuple(cmd), _make_completed("", returncode=1)
            )
            info = collector.collect_system_info()

        # Plist's "iPhone OS" wording wins over sysctl's "iOS" wording.
        assert "iPhone OS" in info.os_detail
        assert "17.4" in info.os_detail
        assert "21E219" in info.os_detail
        assert "iPhone15,2" in info.os_detail


# ---------------------------------------------------------------------------
# P1.3 iOS enrichment — jailbreak detection
# ---------------------------------------------------------------------------


class TestIOSJailbreakDetection:
    """Filesystem-marker based jailbreak probe."""

    def test_dopamine_detected(self, collector, tmp_path):
        marker = tmp_path / "var_jb"
        marker.mkdir()
        collector._jailbreak_markers = {"dopamine": (str(marker),)}
        collector._roothide_glob = str(tmp_path / "never_matches_*")

        responses = _base_ios_responses()
        info = _run_collect(collector, responses)

        assert "dopamine" in info.root_method
        assert info.env == "jailbroken"

    def test_palera1n_detected(self, collector, tmp_path):
        marker = tmp_path / "bootstrapped"
        marker.touch()
        collector._jailbreak_markers = {"palera1n": (str(marker),)}
        collector._roothide_glob = str(tmp_path / "never_matches_*")

        responses = _base_ios_responses()
        info = _run_collect(collector, responses)

        assert "palera1n" in info.root_method
        assert info.env == "jailbroken"

    def test_roothide_via_glob(self, collector, tmp_path):
        jbroot = tmp_path / ".jbroot-ABCD"
        jbroot.mkdir()
        collector._jailbreak_markers = {"none": (str(tmp_path / "never_exists"),)}
        collector._roothide_glob = str(tmp_path / ".jbroot-*")

        responses = _base_ios_responses()
        info = _run_collect(collector, responses)

        assert "roothide" in info.root_method
        assert info.env == "jailbroken"

    def test_multiple_jailbreaks_comma_separated(self, collector, tmp_path):
        dop = tmp_path / "var_jb"
        dop.mkdir()
        pal = tmp_path / "bootstrapped"
        pal.touch()
        collector._jailbreak_markers = {
            "dopamine": (str(dop),),
            "palera1n": (str(pal),),
        }
        collector._roothide_glob = str(tmp_path / "never_matches_*")

        responses = _base_ios_responses()
        info = _run_collect(collector, responses)

        assert "dopamine" in info.root_method
        assert "palera1n" in info.root_method
        assert "," in info.root_method
        assert info.env == "jailbroken"

    def test_stock_ios_no_markers(self, collector, tmp_path):
        collector._jailbreak_markers = {
            "dopamine": (str(tmp_path / "nope_a"),),
            "palera1n": (str(tmp_path / "nope_b"),),
        }
        collector._roothide_glob = str(tmp_path / "nope-*")

        responses = _base_ios_responses()
        info = _run_collect(collector, responses)

        assert info.root_method == ""
        assert info.env == "stock"

    def test_detect_jailbreak_unit(self, collector, tmp_path):
        """Unit-level test of _detect_jailbreak without collect_system_info."""
        marker_a = tmp_path / "marker_a"
        marker_a.mkdir()
        marker_b = tmp_path / "marker_b"
        # marker_b intentionally missing
        collector._jailbreak_markers = {
            "methA": (str(marker_a),),
            "methB": (str(marker_b),),
        }
        collector._roothide_glob = str(tmp_path / "no-glob-*")

        result = collector._detect_jailbreak()

        assert "methA" in result
        assert "methB" not in result
        assert "roothide" not in result
