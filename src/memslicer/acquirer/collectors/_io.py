"""Shared I/O utilities for investigation collectors.

Centralizes three concerns:

1. **File reads** from untrusted paths (`/proc`, `/sys`, `/etc`, Android
   system files) with `O_NOFOLLOW | O_CLOEXEC`, size caps, and graceful
   empty-string fallback on any error.

2. **Subprocess execution** with absolute binary paths resolved via the
   ``TRUSTED_BIN`` allowlist, `shell=False`, scrubbed environment, timeout
   enforcement, and output size caps.

3. **Size constants** consumed by every collector to hard-bound memory use
   on hostile inputs (a 10 GB ``/etc/os-release`` must not OOM the collector).
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import Iterable


# Hard caps on read sizes. Every file / subprocess read in enrichment goes
# through these bounds; no unbounded reads from attacker-controlled sources.
MAX_ENRICHMENT_READ = 64 * 1024       # 64 KiB per file read
MAX_PROC_OUTPUT = 256 * 1024          # 256 KiB per subprocess stdout capture


# Absolute paths for trusted external binaries. ``_run_cmd_safe`` refuses to
# run any command whose resolved argv[0] is not in this map. The map is
# populated per-platform; missing entries on the current OS are fine.
TRUSTED_BIN: dict[str, str] = {
    # Linux / generic POSIX
    "ps": "/bin/ps",
    "lsof": "/usr/bin/lsof",
    "sysctl": "/usr/sbin/sysctl",
    "uname": "/usr/bin/uname",
    "readlink": "/usr/bin/readlink",
    "getenforce": "/usr/sbin/getenforce",
    "systemd-detect-virt": "/usr/bin/systemd-detect-virt",
    # macOS
    "ioreg": "/usr/sbin/ioreg",
    "sw_vers": "/usr/bin/sw_vers",
    "scutil": "/usr/sbin/scutil",
    "domainname": "/bin/domainname",
    # Android (shell / adb context)
    "getprop": "/system/bin/getprop",
    # Windows (if resolved by shutil.which fall back to these; the winreg
    # + ctypes paths from P1 are preferred and don't go through TRUSTED_BIN)
    "tzutil": r"C:\Windows\System32\tzutil.exe",
    "wmic": r"C:\Windows\System32\wbem\WMIC.exe",
    "tasklist": r"C:\Windows\System32\tasklist.exe",
    "netstat": r"C:\Windows\System32\NETSTAT.EXE",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
}


# Minimal scrubbed environment for subprocess calls. We don't inherit the
# operator's environment: output stays deterministic (``LC_ALL=C``) and
# nothing from the acquisition host leaks into target-device command
# execution on remote collectors.
#
# ``PATH`` is deliberately absent — ``_resolve_binary`` returns absolute
# paths only, so subprocess never does a ``PATH`` lookup. Leaving it out
# makes any future caller accidentally passing a bare name fail loudly
# instead of silently resolving via an attacker-influenced ``$PATH``.
def _safe_env() -> dict[str, str]:
    if sys.platform == "win32":
        return {
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
            "LC_ALL": "C",
        }
    return {"LC_ALL": "C", "LANG": "C"}


# ---------------------------------------------------------------------------
# File reads
# ---------------------------------------------------------------------------

def read_proc_file(
    path: str,
    max_bytes: int = MAX_ENRICHMENT_READ,
    logger: logging.Logger | None = None,
) -> str:
    """Read a text file with TOCTOU / DoS hardening.

    Opens with ``O_NOFOLLOW | O_CLOEXEC`` to refuse symlink substitution
    attacks against ``/etc/os-release``, ``/sys/class/dmi/id/*``, and
    similar attacker-influenced paths. Reads at most ``max_bytes`` so a
    crafted 10 GB file cannot OOM the collector. Returns ``""`` on any
    error (file missing, permission denied, symlink, decode error).

    Whitespace is stripped from the result because every caller today
    wants a trimmed single-line value; if a caller needs raw bytes (for
    ``/proc/cmdline`` with embedded NULs) use :func:`read_proc_bytes`.
    """
    log = logger or logging.getLogger("memslicer")
    flags = os.O_RDONLY | os.O_CLOEXEC
    # O_NOFOLLOW is POSIX but not Windows; guarded for portability.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow

    fd = -1
    try:
        fd = os.open(path, flags)
    except (OSError, PermissionError) as exc:
        log.debug("read_proc_file: cannot open %s: %s", path, exc)
        return ""

    try:
        chunk = os.read(fd, max_bytes)
    except OSError as exc:
        log.debug("read_proc_file: read failed %s: %s", path, exc)
        return ""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        return chunk.decode("utf-8", errors="replace").strip()
    except Exception as exc:  # pragma: no cover - decode with errors=replace won't raise
        log.debug("read_proc_file: decode failed %s: %s", path, exc)
        return ""


def read_proc_bytes(
    path: str,
    max_bytes: int = MAX_ENRICHMENT_READ,
    logger: logging.Logger | None = None,
) -> bytes:
    """Raw-bytes sibling of :func:`read_proc_file`. No stripping, no decode.

    Use for files with embedded NULs like ``/proc/<pid>/cmdline`` or
    ``/proc/cmdline``. Returns ``b""`` on any error.
    """
    log = logger or logging.getLogger("memslicer")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
    except (OSError, PermissionError) as exc:
        log.debug("read_proc_bytes: cannot open %s: %s", path, exc)
        return b""
    try:
        return os.read(fd, max_bytes)
    except OSError as exc:
        log.debug("read_proc_bytes: read failed %s: %s", path, exc)
        return b""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def read_symlink(path: str, logger: logging.Logger | None = None) -> str:
    """Best-effort ``readlink`` that returns ``""`` on error.

    Used for ``/etc/localtime`` timezone detection and ``/proc/<pid>/exe``
    reads in code paths where a centralized fail-soft behavior is wanted.
    """
    log = logger or logging.getLogger("memslicer")
    try:
        return os.readlink(path)
    except (OSError, PermissionError) as exc:
        log.debug("read_symlink: cannot readlink %s: %s", path, exc)
        return ""


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------

class UntrustedBinaryError(RuntimeError):
    """Raised when an unlisted binary is requested via :func:`run_cmd_safe`.

    Collectors should catch this and degrade gracefully rather than
    propagate — falling back to ``""`` keeps the collection fail-soft
    contract intact.
    """


def _resolve_binary(argv0: str) -> str:
    """Resolve ``argv0`` to an absolute path via ``TRUSTED_BIN``.

    Accepts either a bare name (``"sysctl"`` → ``"/usr/sbin/sysctl"``) or
    an already-absolute path. Absolute paths are accepted only if they
    appear as a value in ``TRUSTED_BIN`` (allowlist). Missing entries on
    the current platform raise :class:`UntrustedBinaryError`.
    """
    # Bare name path: look up in the allowlist.
    if os.sep not in argv0 and (sys.platform != "win32" or "/" not in argv0):
        resolved = TRUSTED_BIN.get(argv0)
        if not resolved:
            raise UntrustedBinaryError(
                f"binary {argv0!r} not in TRUSTED_BIN allowlist"
            )
        return resolved

    # Absolute path: must match an allowlist value.
    if argv0 in TRUSTED_BIN.values():
        return argv0
    raise UntrustedBinaryError(
        f"absolute path {argv0!r} not in TRUSTED_BIN allowlist values"
    )


def run_cmd_safe(
    argv: list[str],
    timeout: float = 3.0,
    max_output: int = MAX_PROC_OUTPUT,
    logger: logging.Logger | None = None,
) -> str:
    """Run ``argv`` with hardened defaults and return stdout (or ``""``).

    - ``shell=False`` always (no command injection).
    - ``argv[0]`` is resolved through :data:`TRUSTED_BIN`; unlisted
      binaries produce ``""`` and a debug log, never a raised exception,
      so collectors can call this freely without try/except wrapping.
    - ``env`` is scrubbed to a minimal locale + trusted PATH (see
      :func:`_safe_env`).
    - Output is truncated to ``max_output`` bytes. A hostile ``lsof``
      producing GB of output cannot OOM the collector.
    - ``timeout`` defaults to 3 s — enrichment should not be slow.

    Any error (missing binary, timeout, non-zero exit, OS error) yields
    ``""``. Callers must treat ``""`` as "not collected" and continue.
    """
    log = logger or logging.getLogger("memslicer")
    if not argv:
        return ""

    try:
        resolved = _resolve_binary(argv[0])
    except UntrustedBinaryError as exc:
        log.debug("run_cmd_safe: %s", exc)
        return ""

    # If the allowlisted path does not exist on this host, degrade silently.
    # This is the common case cross-platform (e.g. /usr/sbin/ioreg on Linux).
    if not os.path.isabs(resolved) or not os.path.exists(resolved):
        log.debug("run_cmd_safe: resolved %s not present", resolved)
        return ""

    full_argv = [resolved, *argv[1:]]
    try:
        result = subprocess.run(
            full_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_safe_env(),
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("run_cmd_safe: %s failed: %s", argv[0], exc)
        return ""

    if result.returncode != 0:
        log.debug("run_cmd_safe: %s exit %d", argv[0], result.returncode)
        return ""

    stdout = result.stdout or ""
    if len(stdout) > max_output:
        log.debug(
            "run_cmd_safe: %s output truncated (%d > %d)",
            argv[0], len(stdout), max_output,
        )
        stdout = stdout[:max_output]
    return stdout


__all__: Iterable[str] = (
    "MAX_ENRICHMENT_READ",
    "MAX_PROC_OUTPUT",
    "TRUSTED_BIN",
    "UntrustedBinaryError",
    "read_proc_bytes",
    "read_proc_file",
    "read_symlink",
    "run_cmd_safe",
)
