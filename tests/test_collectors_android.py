"""Tests for AndroidCollector – SELinux fallbacks and system properties."""
from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.android import AndroidCollector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_proc_tree(tmp_path: Path, pid: int, *, stat_line: str, cmdline: str = "",
                      exe_target: str | None = None, version: str = "",
                      hostname: str = "localhost", domainname: str = "(none)",
                      btime: int = 1_700_000_000) -> str:
    """Build a minimal /proc hierarchy under *tmp_path* and return its path."""
    proc = tmp_path / "proc"
    pid_dir = proc / str(pid)
    pid_dir.mkdir(parents=True)

    (pid_dir / "stat").write_text(stat_line)
    (pid_dir / "cmdline").write_text(cmdline)

    if exe_target is not None:
        exe_link = pid_dir / "exe"
        exe_link.symlink_to(exe_target)

    # System-wide files used by LinuxCollector.collect_system_info
    stat_global = proc / "stat"
    stat_global.write_text(f"cpu  0 0 0 0 0 0 0 0 0 0\nbtime {btime}\n")

    sys_dir = proc / "sys" / "kernel"
    sys_dir.mkdir(parents=True)
    (sys_dir / "hostname").write_text(hostname)
    (sys_dir / "domainname").write_text(domainname)

    (proc / "version").write_text(version)

    return str(proc)


# ---------------------------------------------------------------------------
# 1. SELinux exe_path fallback
# ---------------------------------------------------------------------------

class TestSELinuxExePathFallback:
    """When /proc/<pid>/exe is unreadable, exe_path should fall back to
    argv[0] from cmdline."""

    def test_fallback_to_cmdline_argv0(self, tmp_path: Path) -> None:
        pid = 1234
        stat_line = f"{pid} (com.example.app) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0"
        cmdline = "/system/bin/app_process\x00-Xzygote\x00/system/bin\x00--zygote"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline, exe_target=None,
        )

        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.exe_path == "/system/bin/app_process"
        assert "app_process" in info.cmd_line

    def test_no_fallback_when_exe_exists(self, tmp_path: Path) -> None:
        pid = 5678
        real_exe = tmp_path / "real_binary"
        real_exe.write_text("ELF")
        stat_line = f"{pid} (myapp) S 1 5678 5678 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 200 0 0 0 0 0 0 0 0 0 0 0 0 0"
        cmdline = "/data/local/tmp/myapp\x00--flag"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline,
            exe_target=str(real_exe),
        )

        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.exe_path == str(real_exe)

    def test_fallback_empty_cmdline(self, tmp_path: Path) -> None:
        """If both exe and cmdline are unavailable, exe_path stays empty."""
        pid = 9999
        stat_line = f"{pid} (gone) S 1 9999 9999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 300 0 0 0 0 0 0 0 0 0 0 0 0 0"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline="", exe_target=None,
        )

        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.exe_path == ""


# ---------------------------------------------------------------------------
# 2. Android OS detail via getprop
# ---------------------------------------------------------------------------

class TestAndroidOsDetail:
    """collect_system_info should build an os_detail string from getprop."""

    _GETPROP_OUTPUT = "\n".join([
        "[ro.build.version.release]: [14]",
        "[ro.build.version.sdk]: [34]",
        "[ro.build.fingerprint]: [google/raven/raven:14/UP1A.231105.001/abc:userdebug/dev-keys]",
        "[ro.product.model]: [Pixel 6 Pro]",
        "[ro.product.manufacturer]: [Google]",
        "[persist.sys.timezone]: [America/New_York]",
    ])

    def _mock_getprop(self, cmd: list[str], **kwargs) -> MagicMock:
        result = MagicMock()
        result.returncode = 0
        result.stdout = self._GETPROP_OUTPUT
        return result

    def test_os_detail_from_getprop(self, tmp_path: Path) -> None:
        proc_root = _create_proc_tree(
            tmp_path, pid=1, stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            hostname="localhost",
        )

        collector = AndroidCollector(proc_root=proc_root)

        with patch("subprocess.run", side_effect=self._mock_getprop):
            info = collector.collect_system_info()

        assert "Android 14" in info.os_detail
        assert "(API 34)" in info.os_detail
        assert "Google" in info.os_detail
        assert "Pixel 6 Pro" in info.os_detail
        assert "google/raven" in info.os_detail

    def test_partial_getprop(self, tmp_path: Path) -> None:
        """Only some properties are available."""
        proc_root = _create_proc_tree(
            tmp_path, pid=1,
            stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        collector = AndroidCollector(proc_root=proc_root)

        partial_output = "[ro.build.version.release]: [13]\n[persist.sys.language]: [en]\n"

        def _partial_getprop(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = partial_output
            return result

        with patch("subprocess.run", side_effect=_partial_getprop):
            info = collector.collect_system_info()

        assert "Android 13" in info.os_detail


# ---------------------------------------------------------------------------
# 3. Inherited LinuxCollector functionality
# ---------------------------------------------------------------------------

class TestInheritedLinuxBehavior:
    """AndroidCollector must expose all LinuxCollector capabilities."""

    def test_process_identity_basic_fields(self, tmp_path: Path) -> None:
        pid = 42
        stat_line = f"{pid} (zygote) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0 0 0 0 0 0 0 0 0 0 0 0"
        real_exe = tmp_path / "zygote_bin"
        real_exe.write_text("ELF")
        cmdline = "/system/bin/zygote\x00--start-system-server"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline,
            exe_target=str(real_exe),
        )

        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.ppid == 1
        assert info.session_id == 42
        assert info.cmd_line == "/system/bin/zygote --start-system-server"

    def test_system_info_hostname(self, tmp_path: Path) -> None:
        proc_root = _create_proc_tree(
            tmp_path, pid=1,
            stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            hostname="android-device",
        )
        collector = AndroidCollector(proc_root=proc_root)

        with patch("subprocess.run", side_effect=FileNotFoundError("getprop")):
            info = collector.collect_system_info()

        assert info.hostname == "android-device"


# ---------------------------------------------------------------------------
# 4. Missing getprop command (FileNotFoundError)
# ---------------------------------------------------------------------------

class TestMissingGetprop:
    """When getprop is not available, system info should still be collected
    with a graceful fallback (no crash, os_detail from /proc/version)."""

    def test_file_not_found_error(self, tmp_path: Path) -> None:
        proc_root = _create_proc_tree(
            tmp_path, pid=1,
            stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            version="Linux version 5.10.0-android",
        )
        collector = AndroidCollector(proc_root=proc_root)

        with patch("subprocess.run", side_effect=FileNotFoundError("getprop")):
            info = collector.collect_system_info()

        # Falls back to /proc/version from LinuxCollector
        assert info.os_detail == "Linux version 5.10.0-android"
        assert info.boot_time > 0

    def test_timeout_error(self, tmp_path: Path) -> None:
        proc_root = _create_proc_tree(
            tmp_path, pid=1,
            stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            version="Linux version 5.10.0-android",
        )
        collector = AndroidCollector(proc_root=proc_root)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("getprop", 5)):
            info = collector.collect_system_info()

        assert info.os_detail == "Linux version 5.10.0-android"
