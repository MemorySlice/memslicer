"""Tests for P1.6.4 — rootkit / anti-forensics / sysctl posture.

Covers the Linux collector additions from P1.6.4:

* ``_decode_kernel_taint`` letter decoding + smoking-gun warnings.
* Rootkit primitives (``kexec_loaded``, wtmp/utmp/btmp/lastlog stat,
  hidden-PID sweep).
* Security sysctl bundle (13 sysctls).
* Auditd / journald / NTP / CPU-vuln posture.
* ``PersistenceManifest`` walk (Block 0x0056).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.linux import (
    LinuxCollector,
    _decode_kernel_taint,
)
from memslicer.msl.types import PersistenceManifest, PersistenceRow

# Reuse the fixture helpers from the sibling Linux-collector test module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_collectors_linux import (  # noqa: E402
    _write,
    _make_posture_collector,
)


# ---------------------------------------------------------------------------
# _decode_kernel_taint — pure unit tests
# ---------------------------------------------------------------------------


class TestKernelTaintDecoding:
    """Pure unit tests on the ``_decode_kernel_taint`` helper."""

    def test_empty_string_returns_empty(self) -> None:
        letters, warnings = _decode_kernel_taint("")
        assert letters == ""
        assert warnings == []

    def test_zero_returns_empty_no_warnings(self) -> None:
        letters, warnings = _decode_kernel_taint("0")
        assert letters == ""
        assert warnings == []

    def test_bit_0_proprietary_not_smoking_gun(self) -> None:
        letters, warnings = _decode_kernel_taint("1")
        assert letters == "P"
        assert warnings == []

    def test_bit_1_forced_module_emits_warning(self) -> None:
        letters, warnings = _decode_kernel_taint("2")
        assert letters == "F"
        assert warnings == ["taint_force_loaded_module"]

    def test_bit_12_out_of_tree_emits_warning(self) -> None:
        letters, warnings = _decode_kernel_taint("4096")
        assert letters == "O"
        assert warnings == ["taint_out_of_tree_module"]

    def test_bit_13_unsigned_module_emits_warning(self) -> None:
        letters, warnings = _decode_kernel_taint("8192")
        assert letters == "E"
        assert warnings == ["taint_unsigned_module_loaded"]

    def test_bit_15_live_patched_emits_warning(self) -> None:
        letters, warnings = _decode_kernel_taint("32768")
        assert letters == "K"
        assert warnings == ["taint_kernel_live_patched"]

    def test_multiple_smoking_guns(self) -> None:
        # Bits 1 + 12 + 13 = 2 + 4096 + 8192 = 12290.
        letters, warnings = _decode_kernel_taint("12290")
        assert letters == "F,O,E"
        assert warnings == [
            "taint_force_loaded_module",
            "taint_out_of_tree_module",
            "taint_unsigned_module_loaded",
        ]

    def test_malformed_input_returns_empty(self) -> None:
        letters, warnings = _decode_kernel_taint("abc")
        assert letters == ""
        assert warnings == []

    def test_bit_13_alone_is_highest_signal(self) -> None:
        """Sanity check: unsigned module loaded is the single highest-signal bit."""
        letters, warnings = _decode_kernel_taint("8192")
        assert letters == "E"
        assert warnings == ["taint_unsigned_module_loaded"]
        assert len(warnings) == 1


# ---------------------------------------------------------------------------
# Hidden-PID sweep
# ---------------------------------------------------------------------------


class TestHiddenPidSweep:
    """``_sweep_hidden_pids`` tests.

    All tests replace ``_kill_func`` with a deterministic stub so no
    real signals are ever sent to the host.
    """

    def _make_visible(self, proc: Path, pids: list[int]) -> None:
        for pid in pids:
            (proc / str(pid)).mkdir(exist_ok=True)

    def test_no_hidden_pids(self, tmp_path) -> None:
        collector, proc = _make_posture_collector(tmp_path)
        self._make_visible(proc, [1, 100])
        _write(
            tmp_path / "p164" / "pid_max",
            "200\n",
        )
        # _always_esrch from _isolate_posture_paths — no hidden.
        count = collector._sweep_hidden_pids()
        assert count == 0

    def test_cap_respects_pid_max_file(self, tmp_path) -> None:
        collector, proc = _make_posture_collector(tmp_path)
        self._make_visible(proc, [1])
        _write(tmp_path / "p164" / "pid_max", "500\n")

        observed: list[int] = []

        def _probe(pid: int, sig: int) -> None:
            observed.append(pid)
            raise ProcessLookupError()

        collector._kill_func = _probe
        collector._sweep_hidden_pids(cap=10000)
        # Should never probe above pid_max=500.
        assert observed
        assert max(observed) <= 500

    def test_sweep_cap_at_32768(self, tmp_path) -> None:
        collector, proc = _make_posture_collector(tmp_path)
        self._make_visible(proc, [1])
        # No pid_max file → fall back to cap argument.
        observed: list[int] = []

        def _probe(pid: int, sig: int) -> None:
            observed.append(pid)
            raise ProcessLookupError()

        collector._kill_func = _probe
        collector._sweep_hidden_pids()  # default cap = 32768
        assert observed
        assert max(observed) <= 32768

    def test_sweep_performed_warning_emitted(self, tmp_path) -> None:
        collector, proc = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "pid_max", "4\n")
        info = collector.collect_system_info()
        assert "hidden_pid_sweep_performed" in info.collector_warnings

    def test_hidden_pid_detected_when_kill_reports_alive(
        self, tmp_path,
    ) -> None:
        """When ``os.kill(pid, 0)`` returns 0 but /proc hides the pid,
        ``_sweep_hidden_pids`` should count it as hidden."""
        collector, proc = _make_posture_collector(tmp_path)
        self._make_visible(proc, [1])
        _write(tmp_path / "p164" / "pid_max", "5\n")

        def _probe(pid: int, sig: int) -> None:
            if pid in (3, 4):
                return  # pretend these pids exist, hidden from /proc
            raise ProcessLookupError()

        collector._kill_func = _probe
        info = collector.collect_system_info()
        assert info.hidden_pid_count == 2
        assert any(
            w.startswith("hidden_pid_count:2")
            for w in info.collector_warnings
        )


# ---------------------------------------------------------------------------
# kexec_loaded
# ---------------------------------------------------------------------------


class TestKexecLoaded:
    def test_kexec_loaded_one_emits_warning(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "kexec_loaded", "1\n")
        info = collector.collect_system_info()
        assert info.kexec_loaded == "1"
        assert "kexec_loaded" in info.collector_warnings

    def test_kexec_loaded_zero_no_warning(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "kexec_loaded", "0\n")
        info = collector.collect_system_info()
        assert info.kexec_loaded == "0"
        assert "kexec_loaded" not in info.collector_warnings

    def test_kexec_file_missing(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.kexec_loaded == ""


# ---------------------------------------------------------------------------
# Auth-log integrity
# ---------------------------------------------------------------------------


class TestAuthLogIntegrity:
    def test_wtmp_size_and_mtime_populated(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        wtmp = tmp_path / "p164" / "wtmp"
        wtmp.parent.mkdir(parents=True, exist_ok=True)
        wtmp.write_bytes(b"\x00" * 384)
        info = collector.collect_system_info()
        assert info.wtmp_size == 384
        assert info.wtmp_mtime_ns > 0

    def test_wtmp_zeroed_warning(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        (p164 / "wtmp").write_bytes(b"")
        # Seed a large monotonic clock so uptime > 1h when computed.
        # The _read_clock_triple() default fallback returns 0; override
        # by writing a clocksource file is not enough — we read via
        # /proc/uptime. Instead, force the warning by giving a fresh
        # collector a high uptime via direct attribute override.
        orig = collector._read_clock_triple
        collector._read_clock_triple = lambda: (0, 0, 7200 * 10**9)  # type: ignore
        try:
            info = collector.collect_system_info()
        finally:
            collector._read_clock_triple = orig
        assert info.wtmp_size == 0
        assert "wtmp_zeroed" in info.collector_warnings

    def test_wtmp_stale_warning(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        wtmp = p164 / "wtmp"
        wtmp.write_bytes(b"\x00" * 100)
        # Set wtmp mtime to 1 (way before any realistic boot_time).
        os.utime(wtmp, (1, 1))
        # Ensure boot_time is non-zero by writing /proc/stat btime.
        info = collector.collect_system_info()
        # info.boot_time should be > wtmp_mtime_ns (mtime=1s).
        assert info.wtmp_mtime_ns > 0
        assert info.wtmp_mtime_ns < info.boot_time
        assert "wtmp_stale" in info.collector_warnings

    def test_utmp_btmp_lastlog_populated(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        (p164 / "utmp").write_bytes(b"\x00" * 200)
        (p164 / "btmp").write_bytes(b"\x00" * 50)
        (p164 / "lastlog").write_bytes(b"\x00" * 100)
        info = collector.collect_system_info()
        assert info.utmp_size == 200
        assert info.btmp_size == 50
        assert info.lastlog_size == 100

    def test_missing_files_no_crash(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.wtmp_size == 0
        assert info.utmp_size == 0
        assert info.btmp_size == 0
        assert info.lastlog_size == 0


# ---------------------------------------------------------------------------
# Security sysctls
# ---------------------------------------------------------------------------


class TestSecuritySysctls:
    def test_all_sysctls_populated(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        files = {
            "kptr_restrict": "2",
            "dmesg_restrict": "1",
            "perf_event_paranoid": "3",
            "unpriv_bpf": "1",
            "unpriv_userns": "0",
            "kexec_load_disabled": "1",
            "sysrq": "176",
            "suid_dumpable": "0",
            "protected_symlinks": "1",
            "protected_hardlinks": "1",
            "protected_fifos": "1",
            "protected_regular": "2",
            "bpf_jit_enable": "1",
        }
        for name, content in files.items():
            (p164 / name).write_text(content + "\n")
        info = collector.collect_system_info()
        assert info.kptr_restrict == "2"
        assert info.dmesg_restrict == "1"
        assert info.perf_event_paranoid == "3"
        assert info.unprivileged_bpf_disabled == "1"
        assert info.unprivileged_userns_clone == "0"
        assert info.kexec_load_disabled == "1"
        assert info.sysrq_state == "176"
        assert info.suid_dumpable == "0"
        assert info.protected_symlinks == "1"
        assert info.protected_hardlinks == "1"
        assert info.protected_fifos == "1"
        assert info.protected_regular == "2"
        assert info.bpf_jit_enable == "1"

    def test_missing_sysctls_leave_empty(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.kptr_restrict == ""
        assert info.dmesg_restrict == ""
        assert info.bpf_jit_enable == ""

    def test_unprivileged_userns_clone_optional(self, tmp_path) -> None:
        """Non-Debian kernels lack this sysctl — must not crash."""
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        (p164 / "kptr_restrict").write_text("2\n")
        info = collector.collect_system_info()
        assert info.kptr_restrict == "2"
        assert info.unprivileged_userns_clone == ""


# ---------------------------------------------------------------------------
# Core pattern
# ---------------------------------------------------------------------------


class TestCorePattern:
    def test_core_pattern_simple(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "core_pattern", "core\n")
        info = collector.collect_system_info()
        assert info.core_pattern == "core"
        assert "core_pattern_pipe" not in info.collector_warnings

    def test_core_pattern_pipe_emits_warning(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(
            tmp_path / "p164" / "core_pattern",
            "|/usr/bin/apport %p %s %c\n",
        )
        info = collector.collect_system_info()
        assert info.core_pattern.startswith("|")
        assert "core_pattern_pipe" in info.collector_warnings

    def test_missing_core_pattern(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.core_pattern == ""


# ---------------------------------------------------------------------------
# Auditd state
# ---------------------------------------------------------------------------


class TestAuditState:
    def test_auditd_running(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        (p164 / "auditd.pid").write_text("1234\n")
        info = collector.collect_system_info()
        assert info.audit_state == "running"

    def test_auditd_rules_counted(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        (p164 / "audit.rules").write_text(
            "# comment line\n"
            "-w /etc/passwd -p wa -k passwd_changes\n"
            "-w /etc/shadow -p wa -k shadow_changes\n"
            "\n"
            "-a always,exit -F arch=b64 -S execve\n"
            "-w /etc/sudoers -p wa -k sudoers\n"
            "-w /var/log/lastlog -p wa -k login\n"
        )
        info = collector.collect_system_info()
        assert info.audit_rules_count == 5

    def test_auditd_absent(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        # neither pid file nor binary present → state empty
        assert info.audit_state == ""
        assert info.audit_rules_count == 0


# ---------------------------------------------------------------------------
# Journald storage
# ---------------------------------------------------------------------------


class TestJournaldStorage:
    def test_persistent_from_conf(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(
            tmp_path / "p164" / "journald.conf",
            "[Journal]\nStorage=persistent\n",
        )
        info = collector.collect_system_info()
        assert info.journald_storage == "persistent"

    def test_volatile_from_conf(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(
            tmp_path / "p164" / "journald.conf",
            "[Journal]\nStorage=volatile\n",
        )
        info = collector.collect_system_info()
        assert info.journald_storage == "volatile"

    def test_directory_fallback(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        p164 = tmp_path / "p164"
        p164.mkdir(parents=True, exist_ok=True)
        persistent_dir = p164 / "journal_persistent"
        persistent_dir.mkdir()
        (persistent_dir / "system.journal").write_bytes(b"")
        info = collector.collect_system_info()
        assert info.journald_storage == "persistent"


# ---------------------------------------------------------------------------
# NTP sync
# ---------------------------------------------------------------------------


class TestNtpSync:
    def test_systemd_timesync_synchronized(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "timesync_synchronized", "")
        info = collector.collect_system_info()
        assert info.ntp_sync == "yes"

    def test_chrony_drift_present(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        _write(tmp_path / "p164" / "chrony_drift", "0.123 0.01\n")
        info = collector.collect_system_info()
        assert info.ntp_sync == "yes"

    def test_unknown(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.ntp_sync == "unknown"


# ---------------------------------------------------------------------------
# CPU vuln digest
# ---------------------------------------------------------------------------


class TestCpuVulnDigest:
    def test_digest_deterministic(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        vuln = tmp_path / "p164" / "cpu_vulnerabilities"
        vuln.mkdir(parents=True, exist_ok=True)
        (vuln / "meltdown").write_text("Mitigation: PTI\n")
        (vuln / "spectre_v1").write_text("Mitigation: usercopy/swapgs barriers\n")
        (vuln / "spectre_v2").write_text(
            "Mitigation: Enhanced IBRS; IBPB: conditional; RSB filling\n",
        )
        first = collector.collect_system_info().cpu_vuln_digest
        second = collector.collect_system_info().cpu_vuln_digest
        assert first == second
        assert len(first) == 16

    def test_empty_dir_returns_empty(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        info = collector.collect_system_info()
        assert info.cpu_vuln_digest == ""


# ---------------------------------------------------------------------------
# PersistenceManifest walk
# ---------------------------------------------------------------------------


class TestPersistenceManifest:
    def test_walk_systemd_dir(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        systemd_dir = tmp_path / "fake_systemd"
        systemd_dir.mkdir()
        for name in ("sshd.service", "custom.service", "rogue.service"):
            (systemd_dir / name).write_text("[Unit]\nDescription=test\n")
        collector._persistence_sources = [(1, str(systemd_dir))]
        collector._persistence_single_files = []

        manifest = collector.collect_persistence_manifest()
        assert len(manifest.rows) == 3
        assert all(r.source == 1 for r in manifest.rows)
        names = {os.path.basename(r.path) for r in manifest.rows}
        assert names == {"sshd.service", "custom.service", "rogue.service"}

    def test_walk_cron_d_and_crontab(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        cron_d = tmp_path / "fake_cron_d"
        cron_d.mkdir()
        (cron_d / "apt").write_text("0 0 * * * root apt update\n")
        (cron_d / "logrotate").write_text("0 1 * * * root logrotate\n")
        crontab = tmp_path / "fake_crontab"
        crontab.write_text("* * * * * root echo hi\n")
        collector._persistence_sources = [(3, str(cron_d))]
        collector._persistence_single_files = [(3, str(crontab))]

        manifest = collector.collect_persistence_manifest()
        assert len(manifest.rows) == 3
        assert all(r.source == 3 for r in manifest.rows)
        assert {os.path.basename(r.path) for r in manifest.rows} == {
            "apt", "logrotate", "fake_crontab",
        }

    def test_skip_non_existent_dirs(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        collector._persistence_sources = [
            (1, str(tmp_path / "nope_a")),
            (2, str(tmp_path / "nope_b")),
        ]
        collector._persistence_single_files = [
            (3, str(tmp_path / "nope_c")),
        ]
        manifest = collector.collect_persistence_manifest()
        assert manifest.rows == []

    def test_mtime_size_mode_populated(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        systemd_dir = tmp_path / "fake_systemd"
        systemd_dir.mkdir()
        unit = systemd_dir / "sshd.service"
        unit.write_text("hello world")
        collector._persistence_sources = [(1, str(systemd_dir))]
        collector._persistence_single_files = []
        manifest = collector.collect_persistence_manifest()
        assert len(manifest.rows) == 1
        row = manifest.rows[0]
        assert row.size == len("hello world")
        assert row.mtime_ns > 0
        assert row.mode != 0

    def test_collect_persistence_manifest_end_to_end(self, tmp_path) -> None:
        collector, _ = _make_posture_collector(tmp_path)
        systemd_dir = tmp_path / "systemd_end_to_end"
        systemd_dir.mkdir()
        (systemd_dir / "a.service").write_text("")
        (systemd_dir / "b.service").write_text("")
        pam_d = tmp_path / "pam_d"
        pam_d.mkdir()
        (pam_d / "common-auth").write_text("")
        crontab = tmp_path / "crontab"
        crontab.write_text("")
        collector._persistence_sources = [
            (1, str(systemd_dir)),
            (7, str(pam_d)),
        ]
        collector._persistence_single_files = [(3, str(crontab))]

        manifest = collector.collect_persistence_manifest()
        assert isinstance(manifest, PersistenceManifest)
        sources = sorted(r.source for r in manifest.rows)
        assert sources == [1, 1, 3, 7]
