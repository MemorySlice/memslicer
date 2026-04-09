"""GDB/MI-based implementation of the DebuggerBridge protocol.

Uses ``subprocess.Popen`` to drive GDB through its Machine Interface (MI3).
This avoids any dependency on GDB's embedded Python interpreter.
"""
from __future__ import annotations

import logging
import os
import queue
import re
import shutil
import subprocess
import threading

from memslicer.acquirer.bridge import (
    MemoryRange,
    ModuleInfo,
    PlatformInfo,
)
from memslicer.acquirer.platform_detect import (
    parse_gdb_architecture,
    parse_proc_maps,
    detect_os_from_maps,
)
from memslicer.msl.constants import OSType

_LOG = logging.getLogger(__name__)


class GDBBridge:
    """DebuggerBridge backed by a GDB/MI subprocess.

    Parameters
    ----------
    target:
        Process ID (``int``) to attach to.  Process names are **not**
        supported by the GDB backend -- pass a PID.
    remote:
        Optional ``host:port`` for ``-target-select remote``.
    gdb_path:
        Path or name of the ``gdb`` binary (default: ``"gdb"``).
    logger:
        Optional logger instance; falls back to module-level logger.
    mi_timeout:
        Timeout in seconds for a single MI command (default: 30).
    """

    def __init__(
        self,
        target: int | str,
        remote: str | None = None,
        gdb_path: str = "gdb",
        logger: logging.Logger | None = None,
        mi_timeout: float = 30.0,
    ) -> None:
        if not isinstance(target, int):
            raise TypeError(
                "GDB backend requires a numeric PID. "
                f"Received {type(target).__name__}: {target!r}"
            )
        self._pid: int = target
        self._remote = remote
        self._gdb_path = gdb_path
        self._log = logger or _LOG
        self._mi_timeout = mi_timeout
        self._proc: subprocess.Popen[str] | None = None
        self._line_queue: queue.Queue[str | None] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self._shutting_down = False

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        return self._remote is not None

    # -- MI transport -------------------------------------------------------

    def _stdout_reader(self) -> None:
        """Background thread that reads GDB stdout and feeds lines into a queue."""
        assert self._proc is not None and self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                self._line_queue.put(line.rstrip("\n"))
        except (ValueError, OSError):
            pass
        finally:
            self._line_queue.put(None)

    def _send_mi_command(self, cmd: str) -> str:
        """Send an MI command and return the result record.

        Raises ``TimeoutError`` if no result record arrives within
        ``mi_timeout`` seconds, or ``RuntimeError`` if GDB exits
        unexpectedly.
        """
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("GDB process is not running")

        self._log.debug("MI >>> %s", cmd)
        self._proc.stdin.write(cmd + "\n")
        self._proc.stdin.flush()

        lines: list[str] = []
        while True:
            try:
                line = self._line_queue.get(timeout=self._mi_timeout)
            except queue.Empty:
                if self._shutting_down:
                    raise RuntimeError("GDB disconnecting")
                raise TimeoutError(
                    f"GDB did not respond within {self._mi_timeout}s "
                    f"(command: {cmd!r})"
                )

            if line is None:
                raise RuntimeError(
                    "GDB process exited unexpectedly "
                    f"(command: {cmd!r}, partial output: {lines!r})"
                )

            self._log.debug("MI <<< %s", line)
            lines.append(line)
            if line.startswith("^"):
                break
            if line == "(gdb)":
                break

        result = "\n".join(lines)
        if result.startswith("^error"):
            msg = re.search(r'msg="([^"]*)"', result)
            detail = msg.group(1) if msg else result
            raise RuntimeError(f"GDB/MI error: {detail}")
        return result

    # -- DebuggerBridge protocol --------------------------------------------

    def connect(self) -> None:
        """Spawn GDB and attach to the target."""
        gdb_bin = shutil.which(self._gdb_path)
        if gdb_bin is None:
            raise FileNotFoundError(
                f"GDB not found at '{self._gdb_path}'. "
                "Install GDB or pass a valid path via gdb_path."
            )

        self._proc = subprocess.Popen(
            [gdb_bin, "--interpreter=mi3", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        self._reader_thread = threading.Thread(
            target=self._stdout_reader, daemon=True,
        )
        self._reader_thread.start()

        self._send_mi_command("")

        if self._remote:
            self._send_mi_command(f"-target-select remote {self._remote}")
        else:
            self._send_mi_command(f"-target-attach {self._pid}")
        self._log.info("Attached to PID %d", self._pid)

    def get_platform_info(self) -> PlatformInfo:
        """Return architecture, OS, PID, and page size."""
        arch_output = self._send_mi_command(
            '-interpreter-exec console "show architecture"'
        )
        arch = parse_gdb_architecture(arch_output)

        maps_path = f"/proc/{self._pid}/maps"
        if os.path.isfile(maps_path):
            with open(maps_path) as fh:
                os_type = detect_os_from_maps(fh.read())
        else:
            import platform as _plat
            name = _plat.system().lower()
            if name == "darwin":
                os_type = OSType.macOS
            elif name == "windows":
                os_type = OSType.Windows
            else:
                os_type = OSType.Linux

        page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        return PlatformInfo(arch=arch, os=os_type, pid=self._pid, page_size=page_size)

    def enumerate_ranges(self) -> list[MemoryRange]:
        """List memory regions from ``/proc/<pid>/maps``."""
        ranges = parse_proc_maps(self._pid, logger=self._log)
        if ranges:
            return ranges

        # Fallback: GDB's info proc mappings does not report permissions,
        # so we use "---" (unknown) to avoid false RWX forensic alerts.
        output = self._send_mi_command(
            '-interpreter-exec console "info proc mappings"'
        )
        for m in re.finditer(
            r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+"
            r"0x[0-9a-fA-F]+\s*(.*)",
            output,
        ):
            base = int(m.group(1), 16)
            end = int(m.group(2), 16)
            path = m.group(3).strip()
            ranges.append(MemoryRange(base, end - base, "---", path))
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List loaded shared libraries via GDB."""
        output = self._send_mi_command(
            '-interpreter-exec console "info sharedlibrary"'
        )
        modules: list[ModuleInfo] = []
        for m in re.finditer(
            r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+\S+\s+(\S+)", output
        ):
            base = int(m.group(1), 16)
            end = int(m.group(2), 16)
            path = m.group(3)
            name = os.path.basename(path)
            modules.append(ModuleInfo(name, path, base, end - base))
        return modules

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes at *address* via ``-data-read-memory-bytes``."""
        try:
            result = self._send_mi_command(
                f"-data-read-memory-bytes {address:#x} {size}"
            )
        except (RuntimeError, TimeoutError):
            self._log.debug("Failed to read %d bytes at %#x", size, address)
            return None

        match = re.search(r'contents="([0-9a-fA-F]+)"', result)
        if match is None:
            return None
        return bytes.fromhex(match.group(1))

    def disconnect(self) -> None:
        """Detach and terminate GDB."""
        if self._proc is None:
            return
        self._shutting_down = True
        try:
            self._send_mi_command("-target-detach")
        except (RuntimeError, OSError, TimeoutError):
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self._proc.kill()
        finally:
            self._proc = None
            self._shutting_down = False
            self._log.info("Disconnected from PID %d", self._pid)
