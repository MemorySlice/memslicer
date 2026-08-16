"""Linux attach preflight — decide *before* touching the target.

Attaching to a live process on Linux fails for a small set of highly
predictable reasons: Yama ``ptrace_scope``, a uid mismatch without
``CAP_SYS_PTRACE``, an LSM profile, a zombie or already-traced target.
All of them are observable from ``/proc`` and ``/sys`` **without**
ptrace-attaching, so a blocked capture can produce one actionable line
instead of a raw backend string such as
``unable to access /proc/3145/mem: Permission denied``.

Two things this module deliberately does **not** do:

- **It never writes.** Yama's ``ptrace_scope`` is only ever *recommended*
  as a command for the examiner to run and document. Silently relaxing a
  kernel security control mid-acquisition would be both a forensic and a
  security problem.
- **It never ptraces.** The only active probe is
  ``os.open("/proc/<pid>/mem", O_RDONLY | O_CLOEXEC)`` followed by an
  immediate ``close()``. The kernel applies ``PTRACE_MODE_ATTACH`` at
  ``open()`` time, which reproduces the real failure without stopping,
  signalling, or otherwise perturbing the target.

Caveats on the probe, which the rest of the design depends on:

1. **Probe success does not guarantee the later ``PTRACE_ATTACH``
   succeeds.** A second tracer can win the race in between, which is why
   ``TracerPid`` is checked independently.
2. **As root the probe always succeeds**, so a root run never hard-aborts
   here. Heuristic findings are downgraded to warnings whenever the
   kernel itself answered the question — Yama scope 1 with a child
   target, ``PR_SET_PTRACER``, or ``CAP_SYS_PTRACE`` inside a user
   namespace all look like "no" to a heuristic yet work in practice.
3. **When the probe could not run at all** (an errno other than a denial
   or a vanished process), the kernel never answered, so conclusive
   findings keep blocking and merely heuristic ones degrade to warnings.
   That distinction is what :attr:`PreflightFinding.definitive` records.

Every filesystem path is injectable (``proc_root``, ``lsm_path``) and the
platform string can be forced, so the whole module is testable against a
fake ``/proc`` tree.
"""
from __future__ import annotations

import errno
import logging
import os
import re
import sys
from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum, auto
from typing import Any

from memslicer.acquirer.collectors._io import read_proc_file
from memslicer.acquirer.errors import AttachPreflightError


CAP_SYS_PTRACE = 19
"""Bit index of ``CAP_SYS_PTRACE`` inside the capability bitmask."""

YAMA_PTRACE_SCOPE_PATH = "/proc/sys/kernel/yama/ptrace_scope"
"""Canonical path of the Yama ``ptrace_scope`` sysctl."""

DEFAULT_LSM_PATH = "/sys/kernel/security/lsm"
"""Canonical path of the active-LSM list."""

_SELINUX_CONTEXT_RE = re.compile(r"^[^\s:]+:[^\s:]+:[^\s:]+(?::.+)?$")

class _ProbeOutcome(Enum):
    """What the ``/proc/<pid>/mem`` probe established, for :func:`_resolve`.

    Deliberately not an :class:`IntEnum`: unlike :class:`Severity` these do
    not order. Success and denial collapse into ``ANSWERED`` because the
    resolver treats them alike — which of the two occurred is recorded on
    :class:`AttachEnvironment` (``mem_probe_ok`` / ``mem_probe_errno``).
    """

    ANSWERED = auto()     # the kernel decided: opened, or refused
    UNAVAILABLE = auto()  # the probe could not run at all
    UNPROBED = auto()     # the probe was disabled by the caller


class Severity(IntEnum):
    """How badly a finding affects the ability to acquire."""

    INFO = 0
    WARNING = 1
    BLOCKER = 2


@dataclass(frozen=True)
class PreflightFinding:
    """A single observation about the attach environment.

    Attributes:
        code: Stable machine-readable identifier (``yama-scope-2``, …).
        severity: How badly this affects the acquisition.
        detail: Human-readable description of what was observed.
        remediation: Concrete next steps, newline-free, one per entry.
        definitive: Meaningful only on the heuristic findings built by
            :func:`_provisional_findings`; the liveness and probe findings
            never reach :func:`_resolve`, so it does not apply to them.
            ``True`` when the observation is conclusive on its own — Yama
            scope 3 forbids ptrace system-wide, and a uid mismatch without
            ``CAP_SYS_PTRACE`` cannot be overcome. :func:`_is_overruled`
            decides what that buys once the probe outcome is known.
    """

    code: str
    severity: Severity
    detail: str
    remediation: tuple[str, ...] = ()
    # Declared last so 3- and 4-argument positional construction keeps working.
    definitive: bool = False


@dataclass
class AttachEnvironment:
    """Forensic environment record — observation only, no judgement.

    Every field is populated from a read-only source and is written to the
    acquisition log verbatim, so a reviewer can reconstruct the privilege
    situation at capture time even when the capture succeeded.
    """

    checked: bool = False
    skip_reason: str = ""  # not-linux | remote-device | name-target
    target_pid: int = 0
    acquirer_pid: int = 0
    acquirer_euid: int = -1
    acquirer_cap_eff: str = ""  # from /proc/self/status, NOT the target's
    acquirer_has_cap_sys_ptrace: bool | None = None
    target_uid: int | None = None
    target_euid: int | None = None
    target_gid: int | None = None
    target_state: str = ""
    target_name: str = ""
    tracer_pid: int | None = None
    yama_ptrace_scope: int | None = None
    lsm_list: str = ""
    lsm_active: str = ""  # apparmor | selinux | none | unknown
    target_profile: str = ""
    target_confined: bool = False
    snap_confined: bool = False
    mem_probe_ok: bool | None = None
    mem_probe_errno: int | None = None

    def as_log_lines(self) -> list[str]:
        """Render the record as log lines, one aspect per line.

        Returns:
            A list of ``preflight: …`` lines suitable for INFO logging.
        """
        if not self.checked:
            return [f"preflight: skipped ({self.skip_reason or 'unknown'})"]
        return [
            f"preflight: target pid={self.target_pid} "
            f"name={self.target_name or '?'} state={self.target_state or '?'}",
            f"preflight: target uid={_fmt(self.target_uid)} "
            f"euid={_fmt(self.target_euid)} gid={_fmt(self.target_gid)} "
            f"tracer_pid={_fmt(self.tracer_pid)}",
            f"preflight: acquirer pid={self.acquirer_pid} "
            f"euid={self.acquirer_euid} cap_eff={self.acquirer_cap_eff or '?'} "
            f"cap_sys_ptrace={_fmt(self.acquirer_has_cap_sys_ptrace)}",
            f"preflight: yama ptrace_scope={_fmt(self.yama_ptrace_scope)}",
            f"preflight: lsm active={self.lsm_active or '?'} "
            f"list={self.lsm_list or '?'} profile={self.target_profile or '?'} "
            f"confined={self.target_confined} snap={self.snap_confined}",
            f"preflight: mem_probe ok={_fmt(self.mem_probe_ok)} "
            f"errno={_errno_name(self.mem_probe_errno)}",
        ]


@dataclass
class PreflightResult:
    """The environment record plus everything derived from it."""

    env: AttachEnvironment
    findings: list[PreflightFinding] = field(default_factory=list)

    @property
    def blockers(self) -> list[PreflightFinding]:
        """Findings that must stop the acquisition."""
        return [f for f in self.findings if f.severity is Severity.BLOCKER]

    @property
    def warnings(self) -> list[PreflightFinding]:
        """Findings worth surfacing but not worth refusing over."""
        return [f for f in self.findings if f.severity is Severity.WARNING]

    @property
    def ok(self) -> bool:
        """``True`` when nothing blocks the acquisition."""
        return not self.blockers

    def abort_message(self) -> str:
        """Build the single actionable message for a refusal.

        Returns:
            A multi-line string, or ``""`` when there is no blocker.
        """
        blockers = self.blockers
        if not blockers:
            return ""
        head = f"cannot attach to PID {self.env.target_pid}: {blockers[0].detail}"
        return "\n".join([head] + [f"also: {f.detail}" for f in blockers[1:]])

    def remediation_lines(self) -> list[str]:
        """Collect the remediation of every blocker, de-duplicated in order."""
        lines: list[str] = []
        for finding in self.blockers:
            for line in finding.remediation:
                if line not in lines:
                    lines.append(line)
        return lines

    def probable_cause(self) -> str:
        """Summarise the warnings as contributing causes.

        Returns:
            ``""`` when there are no warnings, otherwise the warning
            details joined with ``"; "``.
        """
        return "; ".join(f.detail for f in self.warnings)


@dataclass(frozen=True)
class LSMStatus:
    """What the active Linux Security Module says about the target.

    Attributes:
        lsm_list: Raw contents of ``/sys/kernel/security/lsm``.
        active: ``apparmor`` | ``selinux`` | ``none`` | ``unknown``.
        profile: The raw profile or context string, NUL-stripped.
        confined: ``True`` only for a *named* AppArmor profile. An
            SELinux context is never treated as confinement here.
        snap_confined: ``True`` when the AppArmor profile is a snap one.
    """

    lsm_list: str = ""
    active: str = "unknown"
    profile: str = ""
    confined: bool = False
    snap_confined: bool = False


# ---------------------------------------------------------------------------
# Single-file helpers
# ---------------------------------------------------------------------------

def read_ptrace_scope(scope_path: str = YAMA_PTRACE_SCOPE_PATH) -> int | None:
    """Read the Yama ``ptrace_scope`` sysctl.

    Opens exactly one file so it stays predictable under tests that patch
    ``builtins.open`` globally.

    Args:
        scope_path: Path of the sysctl file.

    Returns:
        The scope as an int, or ``None`` when Yama is absent or the file
        is unreadable/unparseable.
    """
    try:
        with open(scope_path) as fh:
            return int(fh.read().strip())
    except (FileNotFoundError, OSError, ValueError):
        return None


def warn_ptrace_scope(
    log: logging.Logger | None = None,
    *,
    scope_path: str = YAMA_PTRACE_SCOPE_PATH,
) -> int | None:
    """Warn about ptrace restrictions on Linux.

    This is the shared implementation behind the GDB and LLDB bridges'
    ``_check_ptrace_scope`` methods. The messages, levels and ``%``-args
    are reproduced verbatim from those methods, and exactly one file is
    opened, so their existing tests keep passing through the delegation.

    Args:
        log: Logger to warn on. ``None`` disables logging entirely.
        scope_path: Path of the Yama ``ptrace_scope`` sysctl.

    Returns:
        The observed scope, or ``None`` when it could not be read.
    """
    scope = read_ptrace_scope(scope_path)
    if scope is None:
        return None  # Not Linux or Yama not enabled
    if log is None:
        return scope
    if scope >= 2:
        log.warning(
            "Yama ptrace_scope is %d — process attachment may be "
            "blocked. Run as root or set ptrace_scope to 0: "
            "echo 0 | sudo tee %s",
            scope, scope_path,
        )
    elif scope == 1:
        log.info(
            "Yama ptrace_scope is 1 (default) — only child processes "
            "can be traced. Run as root to trace arbitrary processes."
        )
    return scope


def parse_status_text(text: str) -> dict[str, str]:
    """Parse ``/proc/<pid>/status`` content into a key→value mapping.

    Tolerates truncation and garbage: lines without a ``":"`` are simply
    skipped, and no key is ever assumed to be present.

    Args:
        text: Raw file content.

    Returns:
        A mapping of field name to the raw (stripped) value.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip()
        if key:
            fields[key] = value.strip()
    return fields


def read_status_fields(status_path: str) -> dict[str, str]:
    """Read and parse a ``/proc/<pid>/status`` file.

    Args:
        status_path: Path of the status file.

    Returns:
        The parsed fields, or ``{}`` when the file is missing/unreadable.
    """
    return parse_status_text(read_proc_file(status_path))


def cap_eff_has(cap_eff: str, cap: int) -> bool | None:
    """Test one capability bit in a ``CapEff`` hex mask.

    Args:
        cap_eff: The hex mask exactly as ``/proc/<pid>/status`` prints it.
        cap: Capability bit index, for example :data:`CAP_SYS_PTRACE`.

    Returns:
        ``True``/``False``, or ``None`` when the mask is absent or
        unparseable — "unknown" must not be confused with "not held".
    """
    text = (cap_eff or "").strip()
    if not text:
        return None
    try:
        mask = int(text, 16)
    except ValueError:
        return None
    return bool(mask & (1 << cap))


def detect_lsm(
    pid: int,
    *,
    proc_root: str = "/proc",
    lsm_path: str = DEFAULT_LSM_PATH,
) -> LSMStatus:
    """Determine which LSM is active and whether the target is confined.

    ``/proc/<pid>/attr/current`` is ambiguous: on Fedora/RHEL it returns
    an SELinux context such as ``unconfined_u:unconfined_r:unconfined_t:s0``
    which is ``!= "unconfined"`` and would be misread as AppArmor
    confinement. This function therefore prefers the unambiguous
    ``attr/apparmor/current`` node, recognises the SELinux ``a:b:c:d``
    shape, and cross-checks against the active-LSM list.

    Args:
        pid: Target process id.
        proc_root: Root of the ``/proc`` filesystem.
        lsm_path: Path of the active-LSM list.

    Returns:
        An :class:`LSMStatus`. ``confined`` is only ever ``True`` for a
        named AppArmor profile.
    """
    lsm_list = _read_text_file(lsm_path)
    modules = {mod.strip() for mod in lsm_list.split(",") if mod.strip()}

    profile = _read_text_file(f"{proc_root}/{pid}/attr/apparmor/current")
    from_apparmor_node = bool(profile)
    if not profile:
        profile = _read_text_file(f"{proc_root}/{pid}/attr/current")

    if _looks_like_selinux_context(profile):
        return LSMStatus(lsm_list=lsm_list, active="selinux", profile=profile)

    if from_apparmor_node or "apparmor" in modules:
        active = "apparmor"
    elif "selinux" in modules:
        active = "selinux"
    elif modules:
        active = "none"
    else:
        active = "unknown"

    confined = active == "apparmor" and _is_confined_apparmor(profile)
    return LSMStatus(
        lsm_list=lsm_list,
        active=active,
        profile=profile,
        confined=confined,
        snap_confined=confined and profile.startswith("snap."),
    )


def probe_proc_mem(pid: int, *, proc_root: str = "/proc") -> tuple[bool, int | None]:
    """Open ``/proc/<pid>/mem`` read-only and close it immediately.

    The kernel applies ``PTRACE_MODE_ATTACH`` during ``open()``, so this
    reproduces the real permission decision without ptrace-attaching and
    without stopping the target. Nothing is ever read from the fd.

    Args:
        pid: Target process id.
        proc_root: Root of the ``/proc`` filesystem.

    Returns:
        ``(True, None)`` on success, otherwise ``(False, errno)``.
    """
    try:
        fd = os.open(f"{proc_root}/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        return False, exc.errno
    os.close(fd)
    return True, None


def yama_remediation(
    scope: int | None,
    *,
    scope_path: str = YAMA_PTRACE_SCOPE_PATH,
) -> tuple[str, ...]:
    """Return the remediation appropriate to a Yama ``ptrace_scope``.

    The three restrictive scopes need genuinely different advice — most
    importantly scope 3, which is a one-way latch that cannot be relaxed
    at runtime, so telling the examiner to ``echo`` into the sysctl would
    be actively wrong.

    Args:
        scope: The observed scope, or ``None``.
        scope_path: Path used in the printed command.

    Returns:
        Zero or more remediation lines.
    """
    if scope == 1:
        return (
            "Yama ptrace_scope is 1: only a direct parent (or a PR_SET_PTRACER "
            "grantee) may attach. Run as root, or: "
            f"echo 0 | sudo tee {scope_path}",
        )
    if scope == 2:
        return (
            "Yama ptrace_scope is 2 (admin-only): attaching requires "
            "CAP_SYS_PTRACE. Run as root, or: "
            "sudo sysctl -w kernel.yama.ptrace_scope=0",
        )
    if scope == 3:
        return (
            "Yama ptrace_scope is 3: ptrace is disabled system-wide and is "
            "not re-enablable at runtime — scope 3 is a one-way latch. "
            "Reboot with kernel.yama.ptrace_scope set to 0-2 via "
            "/etc/sysctl.d/. Record this constraint in the case notes.",
        )
    return ()


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def preflight_attach(
    pid: int | None,
    *,
    is_remote: bool = False,
    proc_root: str = "/proc",
    lsm_path: str = DEFAULT_LSM_PATH,
    probe_mem: bool = True,
    platform: str | None = None,
    logger: logging.Logger | None = None,
) -> PreflightResult:
    """Decide whether attaching to ``pid`` can work, without attaching.

    Args:
        pid: Target process id, or ``None`` for a name target.
        is_remote: ``True`` when the debuggee lives on another device, in
            which case the local ``/proc`` says nothing useful.
        proc_root: Root of the ``/proc`` filesystem.
        lsm_path: Path of the active-LSM list.
        probe_mem: Whether to run the ``/proc/<pid>/mem`` open probe.
        platform: Platform string; defaults to :data:`sys.platform`.
        logger: Optional logger for debug tracing.

    Returns:
        A :class:`PreflightResult`. When the check was skipped the result
        has ``env.checked is False``, ``ok is True`` and no findings.
    """
    skip_reason = _skip_reason(pid, is_remote, platform)
    if skip_reason:
        if logger is not None:
            logger.debug("attach preflight skipped: %s", skip_reason)
        return PreflightResult(env=AttachEnvironment(skip_reason=skip_reason))

    assert pid is not None  # narrowed by _skip_reason
    env = AttachEnvironment(
        checked=True,
        target_pid=int(pid),
        acquirer_pid=os.getpid(),
        acquirer_euid=_geteuid(),
    )

    if not os.path.isdir(f"{proc_root}/{pid}"):
        return _single_blocker(env, _no_such_process(pid))

    liveness = _record_target(env, proc_root)
    if liveness is not None:
        return _single_blocker(env, liveness)

    _record_acquirer(env, proc_root)
    _record_lsm(env, proc_root, lsm_path)
    scope_path = f"{proc_root}/sys/kernel/yama/ptrace_scope"
    env.yama_ptrace_scope = read_ptrace_scope(scope_path)

    provisional = _provisional_findings(env, scope_path)
    mode, probe_finding = _run_probe(env, proc_root, probe_mem, scope_path)

    result = PreflightResult(env=env, findings=_resolve(provisional, mode))
    if probe_finding is not None:
        result.findings.append(probe_finding)
    if logger is not None:
        for finding in result.findings:
            logger.debug("preflight finding %s: %s", finding.code, finding.detail)
    return result


_SEVERITY_LOG_LEVEL = {
    Severity.INFO: logging.INFO,
    Severity.WARNING: logging.WARNING,
    Severity.BLOCKER: logging.ERROR,
}


def enforce_attach_preflight(
    pid: int | None,
    *,
    is_remote: bool = False,
    logger: logging.Logger | None = None,
    **kwargs: Any,
) -> PreflightResult:
    """Run the preflight, log the record, and refuse the attach if blocked.

    Shared by every bridge so the diagnosis, the log format, and the refusal
    behaviour stay identical across backends.

    Args:
        pid: Target PID, or ``None`` when attaching by name.
        is_remote: Whether the backend targets a remote device.
        logger: Logger receiving the environment record and findings.
        **kwargs: Forwarded to :func:`preflight_attach` (test injection).

    Returns:
        The :class:`PreflightResult`, so callers can reuse its warnings as
        probable cause if the attach still fails.

    Raises:
        AttachPreflightError: If any blocking condition was found. Nothing on
            the target has been touched at that point.
    """
    log = logger or logging.getLogger("memslicer")
    result = preflight_attach(pid, is_remote=is_remote, logger=log, **kwargs)

    for line in result.env.as_log_lines():
        log.info("%s", line)
    for finding in result.findings:
        log.log(
            _SEVERITY_LOG_LEVEL[finding.severity],
            "preflight[%s]: %s", finding.code, finding.detail,
        )

    if not result.ok:
        raise AttachPreflightError(
            result.abort_message(),
            result=result,
            remediation=result.remediation_lines(),
            probable_cause=result.probable_cause(),
        )
    return result


def _skip_reason(pid: int | None, is_remote: bool, platform: str | None) -> str:
    """Return the cheap-gate skip reason, or ``""`` when checks apply."""
    plat = platform if platform is not None else sys.platform
    if not str(plat).startswith("linux"):
        return "not-linux"
    if is_remote:
        return "remote-device"
    if not pid:
        return "name-target"
    return ""


def _single_blocker(env: AttachEnvironment, finding: PreflightFinding) -> PreflightResult:
    """Wrap a terminal blocker into a result."""
    return PreflightResult(env=env, findings=[finding])


def _no_such_process(pid: int) -> PreflightFinding:
    """Build the ``no-such-process`` blocker."""
    return PreflightFinding(
        code="no-such-process",
        severity=Severity.BLOCKER,
        detail=f"no process with PID {pid} — it exited or never existed",
        remediation=("Re-check the PID (ps, pgrep) and try again.",),
    )


def _record_target(env: AttachEnvironment, proc_root: str) -> PreflightFinding | None:
    """Fill the target half of ``env`` and return a liveness blocker, if any.

    Only ``Name``/``State``/``Uid``/``Gid``/``TracerPid`` are taken from
    the *target's* status — never ``CapEff``, which describes the target's
    privileges and says nothing about ours.
    """
    fields = read_status_fields(f"{proc_root}/{env.target_pid}/status")
    env.target_name = fields.get("Name", "")
    env.target_state = fields.get("State", "")
    env.target_uid = _nth_int(fields.get("Uid"), 0)
    env.target_euid = _nth_int(fields.get("Uid"), 1)
    env.target_gid = _nth_int(fields.get("Gid"), 0)
    env.tracer_pid = _nth_int(fields.get("TracerPid"), 0)

    if env.target_state.startswith("Z"):
        return PreflightFinding(
            code="target-zombie",
            severity=Severity.BLOCKER,
            detail=(
                f"PID {env.target_pid} ({env.target_name or '?'}) is a zombie "
                "— its address space is already gone"
            ),
            remediation=("Nothing can be acquired from a zombie; capture the parent instead.",),
        )
    if env.tracer_pid and env.tracer_pid != env.acquirer_pid:
        return PreflightFinding(
            code="already-traced",
            severity=Severity.BLOCKER,
            detail=(
                f"PID {env.target_pid} is already being traced by PID "
                f"{env.tracer_pid} — only one tracer is allowed"
            ),
            remediation=(
                "Detach the other debugger, or acquire once it has finished. "
                f"Identify it with: ps -p {env.tracer_pid} -o pid,comm,args",
            ),
        )
    return None


def _record_acquirer(env: AttachEnvironment, proc_root: str) -> None:
    """Fill the acquirer half of ``env`` from ``/proc/self/status``."""
    fields = read_status_fields(f"{proc_root}/self/status")
    env.acquirer_cap_eff = fields.get("CapEff", "")
    env.acquirer_has_cap_sys_ptrace = cap_eff_has(env.acquirer_cap_eff, CAP_SYS_PTRACE)


def _record_lsm(env: AttachEnvironment, proc_root: str, lsm_path: str) -> None:
    """Fill the LSM half of ``env``."""
    status = detect_lsm(env.target_pid, proc_root=proc_root, lsm_path=lsm_path)
    env.lsm_list = status.lsm_list
    env.lsm_active = status.active
    env.target_profile = status.profile
    env.target_confined = status.confined
    env.snap_confined = status.snap_confined


def _provisional_findings(
    env: AttachEnvironment, scope_path: str,
) -> list[PreflightFinding]:
    """Derive heuristic findings from the environment record."""
    candidates = (
        _yama_finding(env, scope_path),
        _uid_finding(env),
        _lsm_finding(env),
    )
    return [finding for finding in candidates if finding is not None]


def _yama_finding(
    env: AttachEnvironment, scope_path: str,
) -> PreflightFinding | None:
    """Build the Yama finding for the observed scope, if any."""
    scope = env.yama_ptrace_scope
    if scope is None:
        return None
    remediation = yama_remediation(scope, scope_path=scope_path)
    if scope <= 0:
        return PreflightFinding(
            code="yama-scope-0",
            severity=Severity.INFO,
            detail="Yama ptrace_scope is 0 — ptrace is unrestricted",
        )
    if scope == 1:
        return PreflightFinding(
            code="yama-scope-1",
            severity=Severity.WARNING,
            detail=(
                "Yama ptrace_scope is 1 — only a direct parent (or a "
                "PR_SET_PTRACER grantee) may attach to the target"
            ),
            remediation=remediation,
        )
    if scope == 2:
        held = env.acquirer_has_cap_sys_ptrace is True
        return PreflightFinding(
            code="yama-scope-2",
            severity=Severity.WARNING if held else Severity.BLOCKER,
            detail=(
                "Yama ptrace_scope is 2 — attaching is admin-only and "
                "requires CAP_SYS_PTRACE"
                + (" (which this process holds)" if held else "")
            ),
            remediation=() if held else remediation,
        )
    return PreflightFinding(
        code="yama-scope-3",
        severity=Severity.BLOCKER,
        detail="Yama ptrace_scope is 3 — ptrace is disabled system-wide",
        remediation=remediation,
        definitive=True,
    )


def _uid_finding(env: AttachEnvironment) -> PreflightFinding | None:
    """Flag a uid mismatch that no capability compensates for."""
    if env.acquirer_euid == 0 or env.target_uid is None:
        return None
    if env.target_uid == env.acquirer_euid:
        return None
    if env.acquirer_has_cap_sys_ptrace is not False:
        return None  # held, or unknown — do not guess
    return PreflightFinding(
        code="uid-mismatch",
        severity=Severity.BLOCKER,
        detail=(
            f"target runs as uid {env.target_uid} while this process runs "
            f"as euid {env.acquirer_euid} without CAP_SYS_PTRACE"
        ),
        remediation=(
            "Run the acquisition as root (sudo), or grant CAP_SYS_PTRACE "
            "to the memslicer binary.",
        ),
        definitive=True,
    )


def _lsm_finding(env: AttachEnvironment) -> PreflightFinding | None:
    """Report AppArmor confinement — as a warning, never as a blocker.

    Many profiles permit ptrace, so refusing here would abandon captures
    that would have worked. Only the ``/proc/<pid>/mem`` probe can block.
    """
    if not env.target_confined:
        return None
    kind = "snap AppArmor profile" if env.snap_confined else "AppArmor profile"
    return PreflightFinding(
        code="lsm-confined",
        severity=Severity.WARNING,
        detail=(
            f"target is confined by {kind} '{env.target_profile}' — the "
            "profile may deny ptrace even for root"
        ),
        remediation=(
            "If the attach fails, check `sudo dmesg | grep -i apparmor` for a "
            f"DENIED line naming {env.target_profile.split(' ')[0]}.",
        ),
    )


def _run_probe(
    env: AttachEnvironment,
    proc_root: str,
    probe_mem: bool,
    scope_path: str,
) -> tuple[_ProbeOutcome, PreflightFinding | None]:
    """Run the ``/proc/<pid>/mem`` probe and interpret its outcome.

    Returns:
        ``(outcome, finding)`` where ``outcome`` drives how the
        provisional findings are resolved and ``finding`` is an extra
        finding to append (or ``None``).
    """
    if not probe_mem:
        return _ProbeOutcome.UNPROBED, None

    ok, err = probe_proc_mem(env.target_pid, proc_root=proc_root)
    env.mem_probe_ok = ok
    env.mem_probe_errno = err
    if ok:
        return _ProbeOutcome.ANSWERED, None
    if err in (errno.EACCES, errno.EPERM):
        return _ProbeOutcome.ANSWERED, PreflightFinding(
            code="mem-permission-denied",
            severity=Severity.BLOCKER,
            detail=(
                f"unable to access {proc_root}/{env.target_pid}/mem: "
                f"{os.strerror(err)} — the kernel denied PTRACE_MODE_ATTACH"
            ),
            remediation=_denied_remediation(env, scope_path),
        )
    if err in (errno.ENOENT, errno.ESRCH):
        return _ProbeOutcome.ANSWERED, _no_such_process(env.target_pid)
    return _ProbeOutcome.UNAVAILABLE, PreflightFinding(
        code="probe-unavailable",
        severity=Severity.WARNING,
        detail=(
            f"could not probe {proc_root}/{env.target_pid}/mem "
            f"({_errno_name(err)}) — falling back to heuristics"
        ),
    )


def _denied_remediation(env: AttachEnvironment, scope_path: str) -> tuple[str, ...]:
    """Pick the remediation for a denied probe, most specific first."""
    scope = env.yama_ptrace_scope
    if scope in (3, 2):
        return yama_remediation(scope, scope_path=scope_path)
    if (
        env.target_uid is not None
        and env.acquirer_euid not in (0, env.target_uid)
        and env.acquirer_has_cap_sys_ptrace is not True
    ):
        return (
            f"The target runs as uid {env.target_uid}; run the acquisition as "
            "root (sudo memslicer …) or grant CAP_SYS_PTRACE.",
        )
    if scope == 1:
        return yama_remediation(1, scope_path=scope_path)
    return (
        "Run the acquisition as root (sudo memslicer …).",
        "If it still fails, check for an LSM policy (AppArmor/SELinux) "
        "denying ptrace on this target.",
    )


def _is_overruled(finding: PreflightFinding, outcome: _ProbeOutcome) -> bool:
    """Whether the probe outcome demotes this heuristic blocker.

    The kernel outranks the heuristics: once ``/proc/<pid>/mem`` answered —
    by opening or by refusing — no heuristic may veto the acquisition, and
    the denial finding carries the blocker instead. Only when the probe
    could not run at all does :attr:`PreflightFinding.definitive` matter,
    and only then does a conclusive observation keep blocking.
    """
    if finding.severity is not Severity.BLOCKER:
        return False
    if outcome is _ProbeOutcome.UNPROBED:
        return False
    return outcome is not _ProbeOutcome.UNAVAILABLE or not finding.definitive


def _resolve(
    provisional: list[PreflightFinding], outcome: _ProbeOutcome,
) -> list[PreflightFinding]:
    """Apply the probe outcome to the heuristic findings.

    Returns a fresh list: :func:`preflight_attach` appends the probe
    finding to it. Demoting never promotes, so re-resolving is idempotent.
    """
    return [
        replace(finding, severity=Severity.WARNING)
        if _is_overruled(finding, outcome)
        else finding
        for finding in provisional
    ]


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _read_text_file(path: str) -> str:
    """Read one file, NUL- and whitespace-stripped; ``""`` on any error.

    Uses the collectors' hardened reader: several of these paths live under
    the *target's* ``/proc`` directory, so ``O_NOFOLLOW`` and the read cap
    matter — the target must not be able to redirect or flood the read.
    """
    return read_proc_file(path).rstrip("\x00").strip()


def _looks_like_selinux_context(text: str) -> bool:
    """Recognise the SELinux ``user:role:type[:level]`` shape."""
    return bool(text) and " " not in text and bool(_SELINUX_CONTEXT_RE.match(text))


def _is_confined_apparmor(profile: str) -> bool:
    """Return ``True`` for a named AppArmor profile such as ``snap.x.y (enforce)``."""
    name = profile.split(" (")[0].strip()
    return bool(name) and name != "unconfined"


def _nth_int(value: str | None, index: int) -> int | None:
    """Return the ``index``-th whitespace-separated int of ``value``.

    ``Uid:`` carries four fields (real, effective, saved, fs), so indexing
    matters. Missing keys and malformed values yield ``None`` rather than
    raising — a truncated status file must never crash the preflight.
    """
    if not value:
        return None
    parts = value.split()
    if index >= len(parts):
        return None
    try:
        return int(parts[index])
    except ValueError:
        return None


def _geteuid() -> int:
    """Return the effective uid, or ``-1`` where the platform lacks it."""
    getter = getattr(os, "geteuid", None)
    return getter() if getter is not None else -1


def _fmt(value: object) -> str:
    """Render an optional value for the log record."""
    return "?" if value is None else str(value)


def _errno_name(err: int | None) -> str:
    """Render an errno as its symbolic name."""
    if err is None:
        return "-"
    return errno.errorcode.get(err, str(err))
