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
        # P1.2 rewrite: the previous version of this test encoded the
        # old buggy behavior (stuffing argv[0] into exe_path). On Android
        # argv[0] is a package process name (e.g. "com.whatsapp:pushservice"),
        # not a filesystem path. The current contract stores argv[0] in
        # process_name / package and sets exe_path to the canonical
        # app_process64 binary.
        pid = 1234
        stat_line = f"{pid} (com.example.app) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0"
        cmdline = "com.example.app:service\x00arg1\x00arg2"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline, exe_target=None,
        )

        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.exe_path == "/system/bin/app_process64"
        assert info.process_name == "com.example.app:service"
        assert info.package == "com.example.app"

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

        # P1.2: os_detail is now the Linux-style human composition
        # ("distro (kernel arch)"). Fingerprint is captured in
        # info.fingerprint and gated at the projector via
        # --include-fingerprint; it no longer appears in os_detail here.
        assert "Android 14" in info.os_detail
        assert "(API 34)" in info.os_detail
        assert info.hw_vendor == "Google"
        assert info.hw_model == "Pixel 6 Pro"
        assert info.fingerprint.startswith("google/raven")

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

        # Step 7 fix: os_detail is now the human-readable kernel/arch
        # composition, not the raw /proc/version build string. The raw
        # string still survives in raw_os for forensic lookup.
        assert "Linux version 5.10.0-android" not in info.os_detail
        assert info.raw_os == "Linux version 5.10.0-android"
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

        # See note in test_file_not_found_error above — os_detail is no
        # longer the raw /proc/version.
        assert "Linux version 5.10.0-android" not in info.os_detail
        assert info.raw_os == "Linux version 5.10.0-android"


# ---------------------------------------------------------------------------
# 5. P1.2 enrichment: build / verified boot / bootloader / crypto
# ---------------------------------------------------------------------------

def _make_android_getprop_mock(props: dict[str, str]):
    """Return a side_effect callable that mocks ``subprocess.run`` for getprop
    while letting non-``getprop`` invocations pass through (used to make
    ``getenforce`` fall through to default behavior).
    """
    def _run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        if cmd and cmd[0] == "getprop":
            result = MagicMock()
            result.returncode = 0
            result.stdout = "\n".join(
                f"[{k}]: [{v}]" for k, v in props.items()
            )
            return result
        # Anything else (e.g. ``getenforce``): raise FileNotFoundError so
        # the collector takes the "SELinux not detectable" branch.
        raise FileNotFoundError(cmd[0] if cmd else "")
    return _run


def _blank_proc(tmp_path: Path) -> str:
    return _create_proc_tree(
        tmp_path, pid=1,
        stat_line="1 (init) S 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
    )


class TestAndroidEnrichment:
    """P1.2: new structured fields populated from getprop."""

    def test_patch_level_populated(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.build.version.security_patch": "2024-03-01",
        })):
            info = collector.collect_system_info()
        assert info.patch_level == "2024-03-01"

    def test_verified_boot_state(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.boot.verifiedbootstate": "green",
        })):
            info = collector.collect_system_info()
        assert info.verified_boot == "green"

    def test_bootloader_locked(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.boot.flash.locked": "1",
        })):
            info = collector.collect_system_info()
        assert info.bootloader_locked == "1"

    def test_build_type_user(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.build.type": "user",
        })):
            info = collector.collect_system_info()
        assert info.build_type == "user"

    def test_fingerprint_captured_but_field_populated(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.build.fingerprint": "google/raven/raven:14/UP1A.231105.001/abc:user/release-keys",
        })):
            info = collector.collect_system_info()
        assert info.fingerprint.startswith("google/raven")


# ---------------------------------------------------------------------------
# 6. P1.2 environment detection
# ---------------------------------------------------------------------------

class TestAndroidEnvDetection:
    """Android environment classification via getprop."""

    def test_detect_emulator_via_qemu(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.kernel.qemu": "1",
        })):
            info = collector.collect_system_info()
        assert info.env == "emulator"

    def test_detect_cuttlefish_via_hardware(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.hardware": "cutf_cvm",
        })):
            info = collector.collect_system_info()
        assert info.env == "cuttlefish"

    def test_detect_genymotion_via_vbox(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.hardware": "vbox86p",
        })):
            info = collector.collect_system_info()
        assert info.env == "genymotion"

    def test_detect_physical_default(self, tmp_path: Path) -> None:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({
            "ro.product.manufacturer": "Google",
            "ro.product.model": "Pixel 8",
            "ro.hardware": "shiba",
        })):
            info = collector.collect_system_info()
        assert info.env == "physical"


# ---------------------------------------------------------------------------
# 7. P1.2 SELinux mode detection
# ---------------------------------------------------------------------------

class TestAndroidSELinux:
    """SELinux mode detection via sysfs primary and getenforce fallback."""

    def test_selinux_enforcing_from_sysfs(self, tmp_path: Path) -> None:
        sysfs = tmp_path / "selinux_enforce"
        sysfs.write_text("1")

        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        collector._selinux_enforce_path = str(sysfs)

        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert info.selinux == "enforcing"

    def test_selinux_permissive_from_sysfs(self, tmp_path: Path) -> None:
        sysfs = tmp_path / "selinux_enforce"
        sysfs.write_text("0")

        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        collector._selinux_enforce_path = str(sysfs)

        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert info.selinux == "permissive"

    def test_selinux_fallback_to_getenforce(self, tmp_path: Path) -> None:
        # Sysfs probe points at a nonexistent path → fall through.
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        collector._selinux_enforce_path = str(tmp_path / "does_not_exist")

        def _run(cmd, **kwargs):  # type: ignore[no-untyped-def]
            if cmd and cmd[0] == "getprop":
                result = MagicMock()
                result.returncode = 0
                result.stdout = ""
                return result
            if cmd and cmd[0] == "getenforce":
                result = MagicMock()
                result.returncode = 0
                result.stdout = "Enforcing\n"
                return result
            raise FileNotFoundError(cmd[0])

        with patch("subprocess.run", side_effect=_run):
            info = collector.collect_system_info()
        assert info.selinux == "enforcing"


# ---------------------------------------------------------------------------
# 8. P1.2 advisory root detection
# ---------------------------------------------------------------------------

class TestAndroidRootDetection:
    """Advisory root detection via marker-path existence checks."""

    def _collector_with_root_paths(
        self, tmp_path: Path, paths: dict[str, list[str]],
    ) -> AndroidCollector:
        collector = AndroidCollector(proc_root=_blank_proc(tmp_path))
        collector._root_paths = paths
        # Point SELinux probe at a nonexistent path so those calls don't
        # noise the assertion.
        collector._selinux_enforce_path = str(tmp_path / "no_selinux")
        return collector

    def test_magisk_marker(self, tmp_path: Path) -> None:
        marker = tmp_path / "magisk_marker"
        marker.write_text("")
        collector = self._collector_with_root_paths(
            tmp_path, {"magisk": [str(marker)]},
        )
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert "magisk" in info.root_method

    def test_kernelsu_marker(self, tmp_path: Path) -> None:
        marker = tmp_path / "ksu"
        marker.write_text("")
        collector = self._collector_with_root_paths(
            tmp_path, {"kernelsu": [str(marker)]},
        )
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert "kernelsu" in info.root_method

    def test_zygisk_module_glob(self, tmp_path: Path) -> None:
        modules = tmp_path / "modules"
        mod_dir = modules / "zygisk_example"
        mod_dir.mkdir(parents=True)
        (mod_dir / "module.prop").write_text("id=zygisk_example\n")
        collector = self._collector_with_root_paths(
            tmp_path, {"zygisk": [str(modules / "zygisk_*")]},
        )
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert "zygisk" in info.root_method

    def test_no_root_indicators(self, tmp_path: Path) -> None:
        collector = self._collector_with_root_paths(tmp_path, {})
        with patch("subprocess.run", side_effect=_make_android_getprop_mock({})):
            info = collector.collect_system_info()
        assert info.root_method == ""


# ---------------------------------------------------------------------------
# 9. P1.2 exe_path fix edge cases
# ---------------------------------------------------------------------------

class TestAndroidExePathFix:
    """Covers the P1.2 fix for the old argv[0]-as-exe_path bug."""

    def test_package_process_name_with_colon(self, tmp_path: Path) -> None:
        pid = 2000
        stat_line = f"{pid} (pushservice) S 1 2000 2000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0"
        cmdline = "com.whatsapp:pushservice\x00--foo"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline, exe_target=None,
        )
        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.process_name == "com.whatsapp:pushservice"
        assert info.package == "com.whatsapp"
        assert info.exe_path == "/system/bin/app_process64"

    def test_package_no_colon(self, tmp_path: Path) -> None:
        pid = 2001
        stat_line = f"{pid} (app) S 1 2001 2001 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0"
        cmdline = "com.example.app\x00--foo"

        proc_root = _create_proc_tree(
            tmp_path, pid, stat_line=stat_line, cmdline=cmdline, exe_target=None,
        )
        collector = AndroidCollector(proc_root=proc_root)
        info = collector.collect_process_identity(pid)

        assert info.process_name == "com.example.app"
        assert info.package == "com.example.app"
        assert info.exe_path == "/system/bin/app_process64"
