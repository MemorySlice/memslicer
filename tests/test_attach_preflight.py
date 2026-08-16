"""Tests for the Linux attach preflight.

Everything runs against a fake ``/proc`` tree built under ``tmp_path``,
mirroring the ``LinuxCollector(proc_root=…)`` pattern used by
``test_collectors_linux.py``, so the suite is platform-independent.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from memslicer.acquirer.attach_preflight import (
    CAP_SYS_PTRACE,
    AttachEnvironment,
    PreflightFinding,
    PreflightResult,
    Severity,
    cap_eff_has,
    detect_lsm,
    parse_status_text,
    preflight_attach,
    probe_proc_mem,
    read_ptrace_scope,
    read_status_fields,
    warn_ptrace_scope,
    yama_remediation,
)
from memslicer.acquirer.errors import (
    EXIT_PREFLIGHT_REFUSED,
    AttachError,
    AttachPreflightError,
    MemslicerError,
)


TARGET_PID = 1234
NO_CAPS = "0000000000000000"
ALL_CAPS = "000001ffffffffff"


# ---------------------------------------------------------------------------
# Helpers for building the fake /proc tree
# ---------------------------------------------------------------------------

def _write(path: Path, content: str) -> None:
    """Write content to a file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _make_target(
    proc_root: Path,
    pid: int = TARGET_PID,
    *,
    name: str = "nano",
    state: str = "S (sleeping)",
    uid: int | None = None,
    gid: int = 1000,
    tracer: int = 0,
    cap_eff: str = NO_CAPS,
    status_text: str | None = None,
    mem: bool = True,
) -> None:
    """Create ``/proc/<pid>`` with a plausible status file.

    ``uid`` defaults to the running euid so that no uid mismatch is
    diagnosed unless a test asks for one.
    """
    if uid is None:
        uid = os.geteuid()
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)
    if status_text is None:
        status_text = (
            f"Name:\t{name}\n"
            f"State:\t{state}\n"
            f"TracerPid:\t{tracer}\n"
            f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
            f"CapEff:\t{cap_eff}\n"
        )
    _write(pid_dir / "status", status_text)
    if mem:
        _write(pid_dir / "mem", "")


def _make_self(proc_root: Path, *, cap_eff: str = NO_CAPS) -> None:
    """Create ``/proc/self/status`` for the acquirer."""
    _write(proc_root / "self" / "status",
           f"Name:\tmemslicer\nState:\tR (running)\nCapEff:\t{cap_eff}\n")


def _make_yama(proc_root: Path, scope: int) -> None:
    """Create the Yama ``ptrace_scope`` sysctl inside the fake tree."""
    _write(proc_root / "sys" / "kernel" / "yama" / "ptrace_scope", f"{scope}\n")


def _make_lsm(tmp_path: Path, modules: str) -> str:
    """Create a fake ``/sys/kernel/security/lsm`` and return its path."""
    path = tmp_path / "lsm"
    _write(path, modules)
    return str(path)


def _basic_tree(tmp_path: Path, **kwargs) -> Path:
    """Build a fake ``/proc`` with a target and an acquirer."""
    proc_root = tmp_path / "proc"
    _make_target(proc_root, **kwargs)
    _make_self(proc_root)
    return proc_root


def _run(proc_root: Path, **kwargs) -> PreflightResult:
    """Call ``preflight_attach`` with the Linux platform forced."""
    kwargs.setdefault("pid", TARGET_PID)
    pid = kwargs.pop("pid")
    kwargs.setdefault("lsm_path", str(proc_root / "missing-lsm"))
    return preflight_attach(pid, proc_root=str(proc_root), platform="linux", **kwargs)


def _codes(result: PreflightResult) -> list[str]:
    """Return the finding codes of a result, in order."""
    return [f.code for f in result.findings]


def _by_code(result: PreflightResult, code: str) -> PreflightFinding:
    """Return the single finding with ``code`` (asserts it exists)."""
    matches = [f for f in result.findings if f.code == code]
    assert matches, f"no {code!r} finding in {_codes(result)}"
    return matches[0]


# ---------------------------------------------------------------------------
# Tests -- cheap gates
# ---------------------------------------------------------------------------

class TestSkipGates:
    """Non-Linux, remote and name targets are never checked."""

    def test_non_linux_skips(self, tmp_path):
        """A darwin platform short-circuits to an unchecked result."""
        result = preflight_attach(TARGET_PID, platform="darwin",
                                  proc_root=str(tmp_path))
        assert result.env.checked is False
        assert result.env.skip_reason == "not-linux"
        assert result.ok is True
        assert result.findings == []

    def test_remote_device_skips(self, tmp_path):
        """A remote debuggee makes the local /proc meaningless."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root, is_remote=True)
        assert result.env.checked is False
        assert result.env.skip_reason == "remote-device"
        assert result.ok is True
        assert result.findings == []

    def test_name_target_skips(self, tmp_path):
        """No PID means nothing to inspect."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root, pid=None)
        assert result.env.checked is False
        assert result.env.skip_reason == "name-target"
        assert result.ok is True

    def test_zero_pid_skips(self, tmp_path):
        """PID 0 is treated as "not resolved yet", not as the kernel."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root, pid=0)
        assert result.env.checked is False
        assert result.env.skip_reason == "name-target"

    def test_skipped_result_logs_one_line(self, tmp_path):
        """The record renders a single explanatory line when skipped."""
        result = preflight_attach(TARGET_PID, platform="win32")
        assert result.env.as_log_lines() == ["preflight: skipped (not-linux)"]

    def test_default_platform_is_sys_platform(self, tmp_path):
        """Omitting ``platform`` falls back to sys.platform."""
        proc_root = _basic_tree(tmp_path)
        with patch("memslicer.acquirer.attach_preflight.sys.platform", "linux"):
            result = preflight_attach(TARGET_PID, proc_root=str(proc_root),
                                      lsm_path=str(tmp_path / "nolsm"))
        assert result.env.checked is True


# ---------------------------------------------------------------------------
# Tests -- existence and liveness
# ---------------------------------------------------------------------------

class TestLiveness:
    """Existence, zombie and already-traced checks."""

    def test_missing_proc_dir_blocks(self, tmp_path):
        """A missing /proc/<pid> is a no-such-process blocker."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root, pid=99999)
        assert _codes(result) == ["no-such-process"]
        assert result.ok is False
        assert result.blockers[0].severity is Severity.BLOCKER

    def test_zombie_blocks(self, tmp_path):
        """State Z means the address space is already gone."""
        proc_root = _basic_tree(tmp_path, state="Z (zombie)")
        result = _run(proc_root)
        assert _codes(result) == ["target-zombie"]
        assert result.ok is False
        assert "zombie" in result.abort_message()

    def test_already_traced_blocks(self, tmp_path):
        """A foreign TracerPid blocks: only one tracer is allowed."""
        proc_root = _basic_tree(tmp_path, tracer=999)
        result = _run(proc_root)
        assert _codes(result) == ["already-traced"]
        assert result.ok is False
        assert "999" in result.blockers[0].detail

    def test_traced_by_self_is_not_a_blocker(self, tmp_path):
        """Our own TracerPid must not be diagnosed as a foreign tracer."""
        proc_root = _basic_tree(tmp_path, tracer=os.getpid())
        result = _run(proc_root)
        assert "already-traced" not in _codes(result)
        assert result.ok is True

    def test_liveness_short_circuits_the_probe(self, tmp_path):
        """A zombie target is never probed."""
        proc_root = _basic_tree(tmp_path, state="Z (zombie)")
        result = _run(proc_root)
        assert result.env.mem_probe_ok is None


# ---------------------------------------------------------------------------
# Tests -- Yama ptrace_scope
# ---------------------------------------------------------------------------

class TestYamaScope:
    """Each scope gets its own code and its own remediation."""

    @pytest.mark.parametrize("scope,code,severity,definitive", [
        (0, "yama-scope-0", Severity.INFO, False),
        (1, "yama-scope-1", Severity.WARNING, False),
        (2, "yama-scope-2", Severity.BLOCKER, False),
        (3, "yama-scope-3", Severity.BLOCKER, True),
    ])
    def test_scope_produces_distinct_code(
        self, tmp_path, scope, code, severity, definitive,
    ):
        """Scopes 0-3 map to distinct codes, severities and conclusiveness.

        Only scope 3 is conclusive on its own: the lower scopes are guesses
        that an unusable probe must not leave standing.
        """
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, scope)
        result = _run(proc_root, probe_mem=False)
        assert code in _codes(result)
        assert _by_code(result, code).severity is severity
        assert _by_code(result, code).definitive is definitive
        assert result.env.yama_ptrace_scope == scope

    def test_remediations_are_distinct(self):
        """Scopes 1, 2 and 3 give three different instructions."""
        texts = {scope: "\n".join(yama_remediation(scope)) for scope in (1, 2, 3)}
        assert len({*texts.values()}) == 3
        assert "echo 0 | sudo tee" in texts[1]
        assert "sysctl -w kernel.yama.ptrace_scope=0" in texts[2]

    def test_scope_three_says_reboot_not_echo(self):
        """Scope 3 is a one-way latch: telling the examiner to echo is wrong."""
        text = "\n".join(yama_remediation(3))
        assert "Reboot" in text
        assert "echo" not in text
        assert "one-way latch" in text

    def test_scope_zero_needs_no_remediation(self):
        """Nothing to fix at scope 0 (or when Yama is absent)."""
        assert yama_remediation(0) == ()
        assert yama_remediation(None) == ()

    def test_scope_two_with_cap_is_only_a_warning(self, tmp_path):
        """CAP_SYS_PTRACE satisfies the admin-only scope."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        _make_self(proc_root, cap_eff=ALL_CAPS)
        _make_yama(proc_root, 2)
        result = _run(proc_root, probe_mem=False)
        assert _by_code(result, "yama-scope-2").severity is Severity.WARNING
        assert result.ok is True

    def test_missing_yama_file_yields_no_finding(self, tmp_path):
        """A kernel without Yama produces no Yama finding at all."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root, probe_mem=False)
        assert result.env.yama_ptrace_scope is None
        assert not [c for c in _codes(result) if c.startswith("yama-")]

    def test_read_ptrace_scope_parses_and_tolerates_garbage(self, tmp_path):
        """The reader returns an int, or None for missing/garbage files."""
        good = tmp_path / "good"
        good.write_text("2\n")
        bad = tmp_path / "bad"
        bad.write_text("not-a-number\n")
        assert read_ptrace_scope(str(good)) == 2
        assert read_ptrace_scope(str(bad)) is None
        assert read_ptrace_scope(str(tmp_path / "absent")) is None


# ---------------------------------------------------------------------------
# Tests -- warn_ptrace_scope (gdb/lldb delegation guard)
# ---------------------------------------------------------------------------

class TestWarnPtraceScope:
    """Messages, levels and args must match the bridges' originals.

    ``test_gdb_bridge.py`` and ``test_lldb_bridge.py`` patch
    ``builtins.open`` globally, so exactly one file may be opened.
    """

    def test_warns_on_high_scope(self):
        """Scope >= 2 warns once with the scope and the path as args."""
        log = MagicMock()
        with patch("builtins.open", mock_open(read_data="2\n")) as opener:
            assert warn_ptrace_scope(log) == 2
        log.warning.assert_called_once()
        assert "ptrace_scope" in log.warning.call_args[0][0]
        assert log.warning.call_args[0][1:] == (
            2, "/proc/sys/kernel/yama/ptrace_scope")
        log.info.assert_not_called()
        assert opener.call_count == 1

    def test_info_on_default_scope(self):
        """Scope 1 is informational, not a warning."""
        log = MagicMock()
        with patch("builtins.open", mock_open(read_data="1\n")):
            assert warn_ptrace_scope(log) == 1
        log.info.assert_called()
        log.warning.assert_not_called()

    def test_silent_on_scope_zero(self):
        """Scope 0 says nothing at all."""
        log = MagicMock()
        with patch("builtins.open", mock_open(read_data="0\n")):
            assert warn_ptrace_scope(log) == 0
        log.warning.assert_not_called()
        log.info.assert_not_called()

    def test_silent_when_not_linux(self):
        """A missing sysctl is silence, not an exception."""
        log = MagicMock()
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert warn_ptrace_scope(log) is None
        log.warning.assert_not_called()

    def test_silent_on_unparseable_content(self):
        """Garbage in the sysctl is treated as "not available"."""
        log = MagicMock()
        with patch("builtins.open", mock_open(read_data="garbage\n")):
            assert warn_ptrace_scope(log) is None
        log.warning.assert_not_called()

    def test_accepts_no_logger(self):
        """A None logger still reports the scope and never raises."""
        with patch("builtins.open", mock_open(read_data="3\n")):
            assert warn_ptrace_scope(None) == 3

    def test_custom_scope_path_is_used_in_the_message(self, tmp_path):
        """The recommended command names the path that was read."""
        path = tmp_path / "ptrace_scope"
        path.write_text("2\n")
        log = MagicMock()
        warn_ptrace_scope(log, scope_path=str(path))
        assert log.warning.call_args[0][2] == str(path)


# ---------------------------------------------------------------------------
# Tests -- status parsing (snippet bug: KeyError on truncated status)
# ---------------------------------------------------------------------------

class TestStatusParsing:
    """``/proc/<pid>/status`` is parsed defensively."""

    def test_parse_status_text_basic(self):
        """Key/value pairs are split on the first colon and stripped."""
        fields = parse_status_text("Name:\tnano\nUid:\t1000\t1000\t1000\t1000\n")
        assert fields["Name"] == "nano"
        assert fields["Uid"] == "1000\t1000\t1000\t1000"

    def test_parse_status_text_ignores_garbage_lines(self):
        """Lines without a colon are skipped rather than crashing."""
        fields = parse_status_text("garbage\n\nName:\tnano\n\x00\n")
        assert fields == {"Name": "nano"}

    def test_parse_status_text_empty(self):
        """An empty file parses to an empty mapping."""
        assert parse_status_text("") == {}

    def test_read_status_fields_missing_file(self, tmp_path):
        """A missing status file yields {} rather than an exception."""
        assert read_status_fields(str(tmp_path / "nope")) == {}

    def test_truncated_status_does_not_raise(self, tmp_path):
        """A status file cut off before Uid must not KeyError."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, status_text="Name:\tnano\nState:\tS (sleeping)\n")
        _make_self(proc_root)
        result = _run(proc_root, probe_mem=False)
        assert result.env.target_uid is None
        assert result.env.target_gid is None
        assert result.env.tracer_pid is None
        assert result.env.target_name == "nano"
        assert "uid-mismatch" not in _codes(result)

    def test_empty_status_does_not_raise(self, tmp_path):
        """A completely empty status file is survivable."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, status_text="")
        _make_self(proc_root)
        result = _run(proc_root, probe_mem=False)
        assert result.env.target_name == ""
        assert result.env.target_state == ""

    def test_malformed_uid_values_are_none(self, tmp_path):
        """Non-numeric Uid fields degrade to None, not to an exception."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, status_text="Uid:\tnobody\tnobody\n")
        _make_self(proc_root)
        result = _run(proc_root, probe_mem=False)
        assert result.env.target_uid is None
        assert result.env.target_euid is None


# ---------------------------------------------------------------------------
# Tests -- capabilities (snippet bug: CapEff read from the target)
# ---------------------------------------------------------------------------

class TestCapabilities:
    """CapEff must come from /proc/self/status, never from the target."""

    def test_cap_eff_comes_from_self_not_target(self, tmp_path):
        """A capability-less target does not mask our own CAP_SYS_PTRACE."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, uid=4242, cap_eff=NO_CAPS)
        _make_self(proc_root, cap_eff="0000003fffffffff")
        result = _run(proc_root, probe_mem=False)
        assert result.env.acquirer_cap_eff == "0000003fffffffff"
        assert result.env.acquirer_has_cap_sys_ptrace is True
        assert "uid-mismatch" not in _codes(result)
        assert result.ok is True

    def test_uid_mismatch_without_cap_blocks(self, tmp_path):
        """Different uid and no CAP_SYS_PTRACE is a definitive blocker."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, uid=4242)
        _make_self(proc_root, cap_eff=NO_CAPS)
        with patch("memslicer.acquirer.attach_preflight._geteuid", return_value=1000):
            result = _run(proc_root, probe_mem=False)
        assert "uid-mismatch" in _codes(result)
        assert _by_code(result, "uid-mismatch").definitive is True
        assert result.ok is False

    def test_unknown_cap_eff_does_not_guess(self, tmp_path):
        """No CapEff line means "unknown" — never assume the cap is absent."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, uid=4242)
        _write(proc_root / "self" / "status", "Name:\tmemslicer\n")
        with patch("memslicer.acquirer.attach_preflight._geteuid", return_value=1000):
            result = _run(proc_root, probe_mem=False)
        assert result.env.acquirer_has_cap_sys_ptrace is None
        assert "uid-mismatch" not in _codes(result)

    @pytest.mark.parametrize("mask,expected", [
        ("0000003fffffffff", True),
        ("0000000000080000", True),
        ("0000000000000000", False),
        ("000000000007ffff", False),
        ("", None),
        ("   ", None),
        ("zzz", None),
    ])
    def test_cap_eff_has(self, mask, expected):
        """The bit test parses hex and reports unknown as None."""
        assert cap_eff_has(mask, CAP_SYS_PTRACE) is expected

    def test_cap_sys_ptrace_bit_index(self):
        """CAP_SYS_PTRACE is bit 19."""
        assert CAP_SYS_PTRACE == 19
        assert cap_eff_has(hex(1 << 19), CAP_SYS_PTRACE) is True


# ---------------------------------------------------------------------------
# Tests -- LSM detection (snippet bugs: SELinux misread, AppArmor blocker)
# ---------------------------------------------------------------------------

class TestLSMDetection:
    """SELinux contexts are recorded; AppArmor confinement only warns."""

    def test_selinux_context_is_not_apparmor_confinement(self, tmp_path):
        """``unconfined_u:unconfined_r:unconfined_t:s0`` is not confinement."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        _make_self(proc_root)
        _write(proc_root / str(TARGET_PID) / "attr" / "current",
               "unconfined_u:unconfined_r:unconfined_t:s0\x00")
        lsm_path = _make_lsm(tmp_path, "capability,selinux")
        result = _run(proc_root, lsm_path=lsm_path, probe_mem=False)
        assert result.env.lsm_active == "selinux"
        assert result.env.target_confined is False
        assert result.env.target_profile == "unconfined_u:unconfined_r:unconfined_t:s0"
        assert "lsm-confined" not in _codes(result)
        assert result.ok is True

    def test_apparmor_confinement_is_warning_only(self, tmp_path):
        """A snap profile warns but never refuses the acquisition."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, name="firefox")
        _make_self(proc_root)
        _write(proc_root / str(TARGET_PID) / "attr" / "apparmor" / "current",
               "snap.firefox.firefox (enforce)\n")
        lsm_path = _make_lsm(tmp_path, "capability,apparmor")
        result = _run(proc_root, lsm_path=lsm_path, probe_mem=False)
        finding = _by_code(result, "lsm-confined")
        assert finding.severity is Severity.WARNING
        assert result.ok is True
        assert result.env.lsm_active == "apparmor"
        assert result.env.target_confined is True
        assert result.env.snap_confined is True
        assert "snap.firefox.firefox" in result.probable_cause()

    def test_apparmor_unconfined_is_not_a_finding(self, tmp_path):
        """The literal string ``unconfined`` means no confinement."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        _make_self(proc_root)
        _write(proc_root / str(TARGET_PID) / "attr" / "current", "unconfined\n")
        lsm_path = _make_lsm(tmp_path, "capability,apparmor,yama")
        result = _run(proc_root, lsm_path=lsm_path, probe_mem=False)
        assert result.env.target_confined is False
        assert "lsm-confined" not in _codes(result)

    def test_apparmor_node_preferred_over_attr_current(self, tmp_path):
        """attr/apparmor/current wins over the ambiguous attr/current."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        _write(proc_root / str(TARGET_PID) / "attr" / "current",
               "unconfined_u:unconfined_r:unconfined_t:s0")
        _write(proc_root / str(TARGET_PID) / "attr" / "apparmor" / "current",
               "/usr/bin/nano (complain)")
        status = detect_lsm(TARGET_PID, proc_root=str(proc_root),
                            lsm_path=str(tmp_path / "absent"))
        assert status.active == "apparmor"
        assert status.confined is True
        assert status.snap_confined is False

    def test_no_lsm_data_is_unknown(self, tmp_path):
        """Nothing readable means "unknown", not "none"."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        status = detect_lsm(TARGET_PID, proc_root=str(proc_root),
                            lsm_path=str(tmp_path / "absent"))
        assert status.active == "unknown"
        assert status.confined is False

    def test_lsm_list_without_mac_module_is_none(self, tmp_path):
        """A kernel with only capability/yama has no MAC module active."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        status = detect_lsm(TARGET_PID, proc_root=str(proc_root),
                            lsm_path=_make_lsm(tmp_path, "capability,yama"))
        assert status.active == "none"
        assert status.lsm_list == "capability,yama"

    def test_trailing_nul_is_stripped(self, tmp_path):
        """attr files are NUL-terminated on some kernels."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        _write(proc_root / str(TARGET_PID) / "attr" / "apparmor" / "current",
               "snap.firefox.firefox (enforce)\x00")
        status = detect_lsm(TARGET_PID, proc_root=str(proc_root),
                            lsm_path=str(tmp_path / "absent"))
        assert status.profile == "snap.firefox.firefox (enforce)"


# ---------------------------------------------------------------------------
# Tests -- the /proc/<pid>/mem probe
# ---------------------------------------------------------------------------

class TestMemProbe:
    """The probe opens and closes; it never reads and never ptraces."""

    def test_probe_opens_read_only_cloexec_and_closes(self, tmp_path):
        """O_RDONLY|O_CLOEXEC, then an immediate close."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root)
        with patch("os.open", wraps=os.open) as opener, \
             patch("os.close", wraps=os.close) as closer:
            ok, err = probe_proc_mem(TARGET_PID, proc_root=str(proc_root))
        assert (ok, err) == (True, None)
        assert opener.call_args[0][1] == os.O_RDONLY | os.O_CLOEXEC
        closer.assert_called_once()

    def test_probe_reports_errno(self, tmp_path):
        """A missing mem node reports ENOENT rather than raising."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, mem=False)
        ok, err = probe_proc_mem(TARGET_PID, proc_root=str(proc_root))
        assert ok is False
        assert err == errno.ENOENT

    def test_permission_denied_blocks_with_yama_remediation(self, tmp_path):
        """Issue #2's exact failure becomes one actionable blocker."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 1)
        with patch("os.open", side_effect=PermissionError(errno.EACCES, "Permission denied")):
            result = _run(proc_root)
        finding = _by_code(result, "mem-permission-denied")
        assert finding.severity is Severity.BLOCKER
        assert result.ok is False
        assert result.env.mem_probe_ok is False
        assert result.env.mem_probe_errno == errno.EACCES
        assert "echo 0 | sudo tee" in "\n".join(finding.remediation)
        assert "/mem" in finding.detail

    def test_eperm_is_also_a_permission_blocker(self, tmp_path):
        """EPERM is handled identically to EACCES."""
        proc_root = _basic_tree(tmp_path)
        with patch("os.open", side_effect=PermissionError(errno.EPERM, "Operation not permitted")):
            result = _run(proc_root)
        assert "mem-permission-denied" in _codes(result)

    def test_denied_remediation_prefers_scope_three(self, tmp_path):
        """Scope 3 outranks every other remediation."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 3)
        with patch("os.open", side_effect=PermissionError(errno.EACCES, "denied")):
            result = _run(proc_root)
        text = "\n".join(_by_code(result, "mem-permission-denied").remediation)
        assert "one-way latch" in text

    def test_denied_remediation_names_uid_mismatch(self, tmp_path):
        """Without Yama, a uid mismatch is the next best explanation."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, uid=4242)
        _make_self(proc_root)
        # Deny only the probe: this assertion needs the environment reads
        # (which go through the hardened os.open-based reader) to succeed.
        with patch("memslicer.acquirer.attach_preflight._geteuid", return_value=1000), \
             patch("memslicer.acquirer.attach_preflight.probe_proc_mem",
                   return_value=(False, errno.EACCES)):
            result = _run(proc_root)
        text = "\n".join(_by_code(result, "mem-permission-denied").remediation)
        assert "uid 4242" in text

    def test_denied_remediation_has_a_generic_fallback(self, tmp_path):
        """Even with no explanation the examiner gets a next step."""
        proc_root = _basic_tree(tmp_path)
        with patch("os.open", side_effect=PermissionError(errno.EACCES, "denied")):
            result = _run(proc_root)
        text = "\n".join(_by_code(result, "mem-permission-denied").remediation)
        assert "root" in text

    def test_raced_away_target_is_no_such_process(self, tmp_path):
        """ENOENT at probe time means the process exited mid-preflight."""
        proc_root = _basic_tree(tmp_path)
        with patch("os.open", side_effect=FileNotFoundError(errno.ENOENT, "No such file")):
            result = _run(proc_root)
        assert "no-such-process" in _codes(result)
        assert result.ok is False

    def test_probe_success_downgrades_yama_two(self, tmp_path):
        """The kernel outranks the heuristic: an open that worked wins."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 2)
        result = _run(proc_root)
        assert result.env.mem_probe_ok is True
        assert _by_code(result, "yama-scope-2").severity is Severity.WARNING
        assert result.ok is True

    def test_probe_success_downgrades_uid_mismatch(self, tmp_path):
        """PR_SET_PTRACER and userns caps read as "no" but work."""
        proc_root = tmp_path / "proc"
        _make_target(proc_root, uid=4242)
        _make_self(proc_root)
        with patch("memslicer.acquirer.attach_preflight._geteuid", return_value=1000):
            result = _run(proc_root)
        assert _by_code(result, "uid-mismatch").severity is Severity.WARNING
        assert result.ok is True

    def test_unexpected_errno_keeps_definitive_blockers(self, tmp_path):
        """An unusable probe leaves the definitive heuristics in charge."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 3)
        with patch("os.open", side_effect=OSError(errno.EIO, "I/O error")):
            result = _run(proc_root)
        assert _by_code(result, "probe-unavailable").severity is Severity.WARNING
        assert _by_code(result, "yama-scope-3").severity is Severity.BLOCKER
        assert result.ok is False

    def test_unexpected_errno_downgrades_provisional_blockers(self, tmp_path):
        """Scope 2 is provisional, so an unusable probe softens it."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 2)
        with patch("os.open", side_effect=OSError(errno.EIO, "I/O error")):
            result = _run(proc_root)
        assert _by_code(result, "yama-scope-2").severity is Severity.WARNING
        assert result.ok is True

    def test_unexpected_errno_keeps_uid_mismatch_blocking(self, tmp_path):
        """A uid mismatch is definitive: an unusable probe must not soften it."""
        proc_root = _basic_tree(tmp_path, uid=4242)
        # Patch the probe rather than os.open: the /proc/<pid>/status reads
        # that produce the uid finding go through os.open via the hardened
        # reader, so a blanket failure would leave target_uid unknown and the
        # finding would never be built -- the test would pass vacuously.
        with patch("memslicer.acquirer.attach_preflight._geteuid", return_value=1000), \
             patch("memslicer.acquirer.attach_preflight.probe_proc_mem",
                   return_value=(False, errno.EIO)):
            result = _run(proc_root)
        assert _by_code(result, "probe-unavailable").severity is Severity.WARNING
        assert _by_code(result, "uid-mismatch").severity is Severity.BLOCKER
        assert result.ok is False

    def test_probe_can_be_disabled(self, tmp_path):
        """probe_mem=False leaves the heuristics untouched."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 2)
        # Patch the probe itself rather than os.open: the environment reads
        # legitimately use os.open via the hardened /proc reader.
        with patch(
            "memslicer.acquirer.attach_preflight.probe_proc_mem",
            side_effect=AssertionError("must not probe"),
        ) as probe:
            result = _run(proc_root, probe_mem=False)
        probe.assert_not_called()
        assert result.env.mem_probe_ok is None
        assert _by_code(result, "yama-scope-2").severity is Severity.BLOCKER


# ---------------------------------------------------------------------------
# Tests -- result rendering
# ---------------------------------------------------------------------------

class TestPreflightResult:
    """The result object renders what the CLI and the log need."""

    def test_ok_result_has_no_abort_message(self, tmp_path):
        """A clean environment produces nothing to render."""
        proc_root = _basic_tree(tmp_path)
        result = _run(proc_root)
        assert result.ok is True
        assert result.abort_message() == ""
        assert result.remediation_lines() == []

    def test_abort_message_names_the_pid_and_the_cause(self, tmp_path):
        """The first line is the single actionable statement."""
        proc_root = _basic_tree(tmp_path, tracer=999)
        result = _run(proc_root)
        assert result.abort_message().startswith(f"cannot attach to PID {TARGET_PID}: ")

    def test_abort_message_lists_additional_blockers(self):
        """Extra blockers appear on their own ``also:`` lines."""
        result = PreflightResult(
            env=AttachEnvironment(checked=True, target_pid=7),
            findings=[
                PreflightFinding("a", Severity.BLOCKER, "first"),
                PreflightFinding("b", Severity.BLOCKER, "second"),
                PreflightFinding("c", Severity.WARNING, "noise"),
            ],
        )
        assert result.abort_message() == "cannot attach to PID 7: first\nalso: second"

    def test_remediation_lines_are_deduplicated(self):
        """The same advice from two blockers is printed once."""
        shared = ("run as root",)
        result = PreflightResult(
            env=AttachEnvironment(checked=True),
            findings=[
                PreflightFinding("a", Severity.BLOCKER, "x", shared),
                PreflightFinding("b", Severity.BLOCKER, "y", shared + ("and pray",)),
            ],
        )
        assert result.remediation_lines() == ["run as root", "and pray"]

    def test_probable_cause_is_empty_without_warnings(self):
        """No warnings means no probable cause."""
        result = PreflightResult(env=AttachEnvironment(checked=True), findings=[
            PreflightFinding("a", Severity.INFO, "fyi"),
        ])
        assert result.probable_cause() == ""

    def test_probable_cause_joins_warnings(self):
        """Warnings are joined into one contributing-cause sentence."""
        result = PreflightResult(env=AttachEnvironment(checked=True), findings=[
            PreflightFinding("a", Severity.WARNING, "first"),
            PreflightFinding("b", Severity.WARNING, "second"),
        ])
        assert result.probable_cause() == "first; second"

    def test_as_log_lines_records_the_environment(self, tmp_path):
        """Every observed aspect lands in the acquisition log."""
        proc_root = _basic_tree(tmp_path, name="nano")
        _make_yama(proc_root, 1)
        result = _run(proc_root)
        text = "\n".join(result.env.as_log_lines())
        assert "name=nano" in text
        assert "ptrace_scope=1" in text
        assert f"pid={TARGET_PID}" in text
        assert "mem_probe ok=True" in text

    def test_as_log_lines_marks_unknowns(self):
        """Unknown values render as ``?`` rather than ``None``."""
        text = "\n".join(AttachEnvironment(checked=True).as_log_lines())
        assert "uid=?" in text
        assert "None" not in text

    def test_logger_receives_findings(self, tmp_path):
        """A logger, when supplied, gets a debug line per finding."""
        proc_root = _basic_tree(tmp_path)
        _make_yama(proc_root, 1)
        logger = MagicMock()
        _run(proc_root, logger=logger)
        assert logger.debug.called

    def test_severity_ordering(self):
        """Severity is an IntEnum so comparisons are meaningful."""
        assert Severity.INFO < Severity.WARNING < Severity.BLOCKER


# ---------------------------------------------------------------------------
# Tests -- no write path
# ---------------------------------------------------------------------------

class TestNoWritePath:
    """The module recommends the sysctl; it never applies it."""

    def test_module_never_opens_anything_for_writing(self):
        """Static guard: no write mode, no os.write, no sysctl call."""
        source = Path(
            __file__).resolve().parent.parent / "src" / "memslicer" / \
            "acquirer" / "attach_preflight.py"
        text = source.read_text()
        for forbidden in ('"w"', "'w'", '"a"', "'a'", "os.write", "O_WRONLY",
                          "O_RDWR", "write_text", "subprocess"):
            assert forbidden not in text, f"{forbidden} must not appear"


# ---------------------------------------------------------------------------
# Tests -- error taxonomy
# ---------------------------------------------------------------------------

class TestErrors:
    """errors.py carries the summary, remediation and probable cause."""

    def test_exit_code_is_three(self):
        """Preflight refusal has its own exit code."""
        assert EXIT_PREFLIGHT_REFUSED == 3

    def test_str_returns_summary_only(self):
        """``str(error)`` never leaks the remediation block."""
        err = AttachError("cannot attach", remediation=["run as root"],
                          probable_cause="apparmor")
        assert str(err) == "cannot attach"

    def test_remediation_accepts_a_plain_string(self):
        """A single string is normalised into a one-element list."""
        assert AttachError("x", remediation="do this").remediation == ["do this"]

    def test_remediation_defaults_to_empty_list(self):
        """Omitting remediation yields a list, not None."""
        err = AttachError("x")
        assert err.remediation == []
        assert err.probable_cause == ""
        assert err.cause is None

    def test_cause_is_chained(self):
        """The originating exception stays reachable for tracebacks."""
        original = PermissionError("denied")
        err = AttachError("x", cause=original)
        assert err.cause is original
        assert err.__cause__ is original

    def test_preflight_error_carries_the_result(self, tmp_path):
        """The refusal keeps the full record for the log and the CLI."""
        proc_root = _basic_tree(tmp_path, state="Z (zombie)")
        result = _run(proc_root)
        err = AttachPreflightError(result.abort_message(), result=result,
                                   remediation=result.remediation_lines())
        assert err.result is result
        assert isinstance(err, AttachError)
        assert isinstance(err, MemslicerError)
        assert str(err) == result.abort_message()
