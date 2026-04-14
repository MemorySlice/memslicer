"""Tests for P1.6.3 per-target introspection (Block 0x0058).

Covers:

- :func:`redact_environ` unit tests (secret-shaped key detection).
- Fixture-based ``/proc/<pid>/*`` tests for every new
  :class:`TargetProcessInfo` field populated by ``LinuxCollector``.
- ``ProcessEntry.user`` opportunistic fill from ``/etc/passwd``.
- The ``include_target_introspection=False`` opt-out path.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.linux import (
    LinuxCollector,
    redact_environ,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _make_stat(
    pid: int,
    comm: str = "target",
    state: str = "S",
    ppid: int = 1,
    session: int = 1,
    starttime: int = 5000,
    flags: int = 0,
) -> str:
    """Build a minimal ``/proc/<pid>/stat`` line with the named fields.

    Field indices (0-based, after ``pid (comm) ``): 0=state 1=ppid
    2=pgrp 3=session 4=tty 5=tpgid 6=flags 7..18=padding 19=starttime.
    """
    fields = [state, str(ppid), str(pid), str(session), "0", "0", str(flags)]
    fields += ["0"] * 12  # 7..18
    fields.append(str(starttime))
    fields.append("0")  # vsize tail padding
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def _setup_pid(
    proc_root: Path,
    pid: int,
    *,
    comm: str = "target",
    ppid: int = 1,
    starttime: int = 5000,
    flags: int = 0,
    status_extra: str = "",
    exe_target: str | None = "/usr/bin/target",
) -> Path:
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)
    _write(pid_dir / "stat", _make_stat(
        pid, comm=comm, ppid=ppid, starttime=starttime, flags=flags,
    ))
    _write(pid_dir / "cmdline", f"{comm}\x00")
    base_status = (
        f"Name:\t{comm}\n"
        f"Uid:\t1000\t1000\t1000\t1000\n"
    )
    _write(pid_dir / "status", base_status + status_extra)
    if exe_target is not None:
        exe_link = pid_dir / "exe"
        if exe_link.exists() or exe_link.is_symlink():
            exe_link.unlink()
        exe_link.symlink_to(exe_target)
    _write(proc_root / "stat", "btime 1700000000\n")
    return pid_dir


# ---------------------------------------------------------------------------
# Environ redaction
# ---------------------------------------------------------------------------

class TestEnvironRedaction:

    def test_empty_input_returns_empty(self) -> None:
        assert redact_environ(b"") == ("", [])

    def test_simple_env_not_redacted(self) -> None:
        sanitized, redacted = redact_environ(b"PATH=/usr/bin\x00")
        assert sanitized == "PATH=/usr/bin"
        assert redacted == []

    def test_aws_secret_key_redacted(self) -> None:
        blob = b"AWS_SECRET_ACCESS_KEY=abcdef\x00"
        sanitized, redacted = redact_environ(blob)
        assert sanitized == "AWS_SECRET_ACCESS_KEY=<redacted>"
        assert redacted == ["AWS_SECRET_ACCESS_KEY"]

    def test_database_password_redacted(self) -> None:
        sanitized, redacted = redact_environ(b"DATABASE_PASSWORD=hunter2\x00")
        assert "<redacted>" in sanitized
        assert "DATABASE_PASSWORD" in redacted

    def test_github_token_redacted(self) -> None:
        sanitized, redacted = redact_environ(b"GITHUB_TOKEN=ghp_abc\x00")
        assert "<redacted>" in sanitized
        assert "GITHUB_TOKEN" in redacted

    def test_oauth_refresh_token_redacted_lowercase(self) -> None:
        sanitized, redacted = redact_environ(b"oauth_refresh_token=abc\x00")
        assert "<redacted>" in sanitized
        assert "oauth_refresh_token" in redacted

    def test_pass_exact_match_redacted(self) -> None:
        sanitized, redacted = redact_environ(b"PASS=abc\x00")
        assert sanitized == "PASS=<redacted>"
        assert redacted == ["PASS"]

    def test_benign_substring_not_redacted(self) -> None:
        # KEYBOARD_LAYOUT contains "key" as substring but not as component.
        sanitized, redacted = redact_environ(b"KEYBOARD_LAYOUT=us\x00")
        assert sanitized == "KEYBOARD_LAYOUT=us"
        assert redacted == []

    def test_multiple_entries_mixed(self) -> None:
        blob = (
            b"PATH=/usr/bin\x00"
            b"AWS_SECRET_ACCESS_KEY=xyz\x00"
            b"HOME=/home/user\x00"
        )
        sanitized, redacted = redact_environ(blob)
        assert "PATH=/usr/bin" in sanitized
        assert "HOME=/home/user" in sanitized
        assert "AWS_SECRET_ACCESS_KEY=<redacted>" in sanitized
        assert redacted == ["AWS_SECRET_ACCESS_KEY"]

    def test_entry_without_equals_preserved(self) -> None:
        sanitized, redacted = redact_environ(b"NAKED\x00PATH=/bin\x00")
        assert "NAKED" in sanitized
        assert "PATH=/bin" in sanitized
        assert redacted == []


# ---------------------------------------------------------------------------
# Per-target introspection — field harvesting
# ---------------------------------------------------------------------------

class TestTargetIntrospectionFields:

    def test_tracer_pid_populated(self, tmp_path):
        _setup_pid(tmp_path, 42, status_extra="TracerPid:\t1234\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.tracer_pid == 1234

    def test_login_uid_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "loginuid", "1000\n")
        _write(tmp_path / "42" / "sessionid", "17\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.login_uid == 1000
        assert info.session_audit_id == 17

    def test_login_uid_no_audit_sentinel(self, tmp_path):
        """kernel sentinel ``(uint32)-1`` → ``4294967295`` — preserved verbatim."""
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "loginuid", "4294967295\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.login_uid == 4294967295

    def test_selinux_context_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        attr_dir = tmp_path / "42" / "attr"
        attr_dir.mkdir()
        _write(attr_dir / "current", "system_u:system_r:init_t:s0\x00")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.selinux_context == "system_u:system_r:init_t:s0"

    def test_target_ns_fingerprint_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        ns_dir = tmp_path / "42" / "ns"
        ns_dir.mkdir()
        for ns in ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time"):
            (ns_dir / ns).symlink_to(f"{ns}:[40010000]")
        # Collector's own ns matching exactly → host scope.
        self_ns_dir = tmp_path / "self_ns"
        self_ns_dir.mkdir()
        for ns in ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time"):
            (self_ns_dir / ns).symlink_to(f"{ns}:[40010000]")
        collector = LinuxCollector(proc_root=str(tmp_path))
        collector._self_ns_dir = str(self_ns_dir)
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert "mnt:[40010000]" in info.target_ns_fingerprint
        assert info.target_ns_scope_vs_collector == "host"

    def test_target_ns_scope_container_when_all_differ(self, tmp_path):
        _setup_pid(tmp_path, 42)
        ns_dir = tmp_path / "42" / "ns"
        ns_dir.mkdir()
        for ns in ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time"):
            (ns_dir / ns).symlink_to(f"{ns}:[41000001]")
        self_ns_dir = tmp_path / "self_ns"
        self_ns_dir.mkdir()
        for ns in ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time"):
            (self_ns_dir / ns).symlink_to(f"{ns}:[40000002]")
        collector = LinuxCollector(proc_root=str(tmp_path))
        collector._self_ns_dir = str(self_ns_dir)
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.target_ns_scope_vs_collector == "container"

    def test_smaps_rollup_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "smaps_rollup",
               "55abc0000000-7ffffffff000 ---p 00000000 00:00 0 [rollup]\n"
               "Rss:              102400 kB\n"
               "Pss:               51200 kB\n"
               "Swap:               1024 kB\n"
               "AnonHugePages:      4096 kB\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.smaps_rollup_pss_kib == 51200
        assert info.smaps_rollup_swap_kib == 1024
        assert info.smaps_anon_hugepages_kib == 4096

    def test_rwx_region_count_scans_maps(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "maps",
               "400000-401000 r-xp 00000000 08:01 12345 /usr/bin/target\n"
               "7f0000-7f1000 rwxp 00000000 00:00 0 \n"
               "7f1000-7f2000 rwxp 00000000 00:00 0 [heap]\n"
               "7f2000-7f3000 rw-p 00000000 00:00 0 \n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.rwx_region_count == 2

    def test_target_cgroup_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "cgroup",
               "0::/user.slice/user-1000.slice/session-42.scope\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.target_cgroup == "/user.slice/user-1000.slice/session-42.scope"

    def test_target_cwd_and_root_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        (tmp_path / "42" / "cwd").symlink_to("/home/alice/work")
        (tmp_path / "42" / "root").symlink_to("/")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.target_cwd == "/home/alice/work"
        assert info.target_root == "/"

    def test_io_counters_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "io",
               "rchar: 1000\nwchar: 2000\nread_bytes: 512\nwrite_bytes: 1024\n"
               "cancelled_write_bytes: 0\nsyscr: 5\nsyscw: 6\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.io_rchar == 1000
        assert info.io_wchar == 2000
        assert info.io_read_bytes == 512
        assert info.io_write_bytes == 1024

    def test_limits_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        limits_text = (
            "Limit                     Soft Limit           Hard Limit           Units     \n"
            "Max cpu time              unlimited            unlimited            seconds   \n"
            "Max file size             unlimited            unlimited            bytes     \n"
            "Max data size             unlimited            unlimited            bytes     \n"
            "Max stack size            8388608              unlimited            bytes     \n"
            "Max core file size        0                    unlimited            bytes     \n"
            "Max resident set          unlimited            unlimited            bytes     \n"
            "Max processes             63816                63816                processes \n"
            "Max open files            1024                 1048576              files     \n"
            "Max locked memory         65536                65536                bytes     \n"
        )
        _write(tmp_path / "42" / "limits", limits_text)
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.limit_core == "0"
        assert info.limit_nofile == "1024"
        assert info.limit_memlock == "65536"

    def test_personality_populated(self, tmp_path):
        _setup_pid(tmp_path, 42)
        _write(tmp_path / "42" / "personality", "00000000\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.personality_hex == "00000000"

    def test_ancestry_walks_up_to_pid_1(self, tmp_path):
        # Build a 42 -> 10 -> 1 chain.
        _setup_pid(tmp_path, 42, comm="child", ppid=10, starttime=9000,
                   exe_target="/usr/bin/child")
        _setup_pid(tmp_path, 10, comm="parent", ppid=1, starttime=5000,
                   exe_target="/usr/bin/parent")
        _setup_pid(tmp_path, 1, comm="init", ppid=0, starttime=1000,
                   exe_target="/sbin/init")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        parts = info.ancestry.split(",")
        assert parts[0].startswith("42:child:")
        assert parts[1].startswith("10:parent:")
        assert parts[-1].startswith("1:init:")

    def test_exe_comm_mismatch_detected(self, tmp_path):
        _setup_pid(tmp_path, 42, comm="bash", exe_target="/tmp/evil")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.exe_comm_mismatch == 1

    def test_exe_comm_mismatch_none_when_aligned(self, tmp_path):
        _setup_pid(tmp_path, 42, comm="target", exe_target="/usr/bin/target")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.exe_comm_mismatch == 0

    def test_exe_comm_mismatch_skipped_for_kthread(self, tmp_path):
        # PF_KTHREAD bit set in stat field "flags" (index 6 after comm).
        pid_dir = tmp_path / "42"
        pid_dir.mkdir(parents=True)
        _write(pid_dir / "stat", _make_stat(42, comm="kworker",
                                            flags=0x00200000))
        _write(pid_dir / "cmdline", "")
        _write(pid_dir / "status", "Name:\tkworker\nUid:\t0\t0\t0\t0\n")
        _write(tmp_path / "stat", "btime 1700000000\n")
        # No exe link (kernel threads don't have one).
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)
        assert info.exe_comm_mismatch == 0

    def test_environ_gated_by_flag_off(self, tmp_path):
        _setup_pid(tmp_path, 42)
        (tmp_path / "42" / "environ").write_bytes(b"AWS_SECRET_ACCESS_KEY=xyz\x00")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42, include_environ=False)
        assert info.environ == ""
        assert info.redacted_env_keys == []

    def test_environ_gated_by_flag_on_with_redaction(self, tmp_path):
        _setup_pid(tmp_path, 42)
        (tmp_path / "42" / "environ").write_bytes(
            b"PATH=/bin\x00AWS_SECRET_ACCESS_KEY=xyz\x00",
        )
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42, include_environ=True)
        assert "PATH=/bin" in info.environ
        assert "<redacted>" in info.environ
        assert info.redacted_env_keys == ["AWS_SECRET_ACCESS_KEY"]

    def test_introspection_skipped_when_flag_false(self, tmp_path):
        _setup_pid(tmp_path, 42, status_extra="TracerPid:\t5\nThreads:\t9\n")
        _write(tmp_path / "42" / "loginuid", "1000\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(
                42, include_target_introspection=False,
            )
        # Baseline fields still populated.
        assert info.ppid == 1
        # P1.6.3 fields stay at defaults.
        assert info.tracer_pid == 0
        assert info.login_uid == 0
        assert info.thread_count == 0


# ---------------------------------------------------------------------------
# /etc/passwd -> ProcessEntry.user
# ---------------------------------------------------------------------------

class TestProcessEntryUserPopulated:

    def test_passwd_map_cached_across_calls(self, tmp_path):
        passwd_file = tmp_path / "etc_passwd"
        passwd_file.write_text("alice:x:1000:1000::/home/alice:/bin/bash\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        collector._etc_passwd = str(passwd_file)

        mapping1 = collector._load_passwd_map()
        # Break the file; cached map should still be returned.
        passwd_file.unlink()
        mapping2 = collector._load_passwd_map()
        assert mapping1 is mapping2
        assert mapping1 == {1000: "alice"}

    def test_user_populated_from_passwd(self, tmp_path):
        passwd_file = tmp_path / "etc_passwd"
        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/sh\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
        )
        _setup_pid(tmp_path, 42)
        # Ensure the pid's status says uid=1000 (default from _setup_pid).
        collector = LinuxCollector(proc_root=str(tmp_path))
        collector._etc_passwd = str(passwd_file)
        entries = collector.collect_process_table(target_pid=42)
        assert len(entries) == 1
        assert entries[0].user == "alice"

    def test_unknown_uid_leaves_user_empty(self, tmp_path):
        passwd_file = tmp_path / "etc_passwd"
        passwd_file.write_text("alice:x:1000:1000::/home/alice:/bin/bash\n")
        pid_dir = tmp_path / "77"
        pid_dir.mkdir()
        _write(pid_dir / "stat", _make_stat(77))
        _write(pid_dir / "cmdline", "")
        _write(pid_dir / "status", "Name:\tmystery\nUid:\t4242\t4242\t4242\t4242\n")
        _write(pid_dir / "statm", "100 50 10 5 0 20 0\n")
        _write(tmp_path / "stat", "btime 1700000000\n")
        collector = LinuxCollector(proc_root=str(tmp_path))
        collector._etc_passwd = str(passwd_file)
        entries = collector.collect_process_table(target_pid=77)
        assert len(entries) == 1
        assert entries[0].user == ""
