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

from memslicer.acquirer.attach_preflight import (
    PreflightResult,
    enforce_attach_preflight,
    warn_ptrace_scope,
)
from memslicer.acquirer.bridge import (
    ASSUMED_PAGE_SIZE_WARNING,
    MemoryRange,
    ModuleInfo,
    PlatformInfo,
    ReadResult,
    FALLBACK_PAGE_SIZE,
    fault_addr_from_text,
)
from memslicer.acquirer.errors import AttachError
from memslicer.acquirer.platform_detect import (
    parse_gdb_architecture,
    parse_gdb_auxv_page_size,
    parse_gdb_osabi,
    parse_proc_maps,
    detect_os_from_maps,
    valid_page_size,
)
from memslicer.msl.constants import OSType

_LOG = logging.getLogger(__name__)

# Largest span requested from GDB in a single -data-read-memory-bytes command.
# The reply carries the payload hex-encoded on one line, so a request twice this
# size arrives as a multi-megabyte string through a line-buffered pipe.
_MI_MAX_READ = 1 << 20

# Longest MI line written to the debug log verbatim. A read reply is two hex
# characters per byte captured, so logging replies whole would make the
# companion log larger than the dump it documents.
_MI_LOG_MAX = 200

# MI replies list the bytes read as memory=[{begin=..,offset=..,end=..,
# contents=".."},..].  Anchor on that field rather than scanning the whole
# reply for brace tuples, because async records (=breakpoint-modified,bkpt={..})
# carry them too.  Every pattern here is bounded by an excluded character
# rather than a lazy `.*?`: the payload is megabytes wide, and a lazy repeat
# single-steps across all of it.
_MEM_LIST_RE = re.compile(r"memory=\[([^\]]*)\]")
_BLOCK_RE = re.compile(r"\{([^}]*)\}")
_BEGIN_RE = re.compile(r'begin="(0x[0-9a-fA-F]+)"')
_CONTENTS_RE = re.compile(r'contents="([^"]*)"')


# MI quotes every string it emits and C-escapes the contents, so a payload has
# to be unescaped before anything is matched against it -- otherwise the
# record's own trailing \n, and any quote the text contains, survive into
# whatever was captured.
_MI_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_CONSOLE_RE = re.compile("~" + _MI_QUOTED)
_MSG_RE = re.compile("msg=" + _MI_QUOTED)
_MI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def _unescape_mi(text: str) -> str:
    """Decode the C-style escapes in an MI string payload.

    MI runs with ``sevenbit_strings`` set, so every byte outside printable
    ASCII -- including each byte of a UTF-8 path -- arrives as a three-digit
    octal escape. Those are decoded back to bytes and the result re-decoded as
    UTF-8, so an accented filename survives instead of turning into its digits.
    """
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] != "\\" or i + 1 >= len(text):
            out += text[i].encode()
            i += 1
            continue
        if text[i + 1] in "01234567":
            end = i + 1
            while end < len(text) and end < i + 4 and text[end] in "01234567":
                end += 1
            out.append(int(text[i + 1:end], 8) & 0xFF)
            i = end
            continue
        out += _MI_ESCAPES.get(text[i + 1], text[i + 1]).encode()
        i += 2
    return out.decode("utf-8", "replace")


def _console_text(result: str) -> str:
    """Return the console stream records of an MI reply, unescaped and joined.

    Args:
        result: Raw MI result record.

    Returns:
        The console output. Replies carrying no stream record are returned
        unchanged, so callers handed plain text still work.
    """
    parts = [_unescape_mi(record.group(1)) for record in _CONSOLE_RE.finditer(result)]
    return "".join(parts) if parts else result


def _mi_arg(value: str) -> str:
    """Quote *value* as a single MI command argument.

    MI splits a command on whitespace and reads a quoted string as one
    argument, so anything carrying a space, a quote or a backslash has to be
    wrapped and escaped or GDB receives a different command than was intended.

    Backslash is escaped first: doing the quote first would leave the backslash
    it introduces to be escaped again on the second pass.

    Args:
        value: The argument text.

    Returns:
        *value* quoted and escaped, ready to interpolate into an MI command.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _summarise_mi_line(line: str) -> str:
    """Shorten an MI line for the debug log, keeping its head."""
    if len(line) <= _MI_LOG_MAX:
        return line
    return f"{line[:_MI_LOG_MAX]}... ({len(line)} chars)"


# "info proc mappings" prints Start, End, Size, Offset, and -- since GDB 8.1 --
# a Perms column, before the objfile name. The Perms group is optional so older
# GDB and non-Linux targets still parse; without it the permissions are unknown.
_PROC_MAPPINGS_RE = re.compile(
    r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+"
    r"(?:\s+([-rwxsp]{4})(?=\s|$))?[ \t]*(.*)"
)

# "info sharedlibrary" marks a library whose symbols are only partially read
# with a "(*)" after the Yes/No column, which is not part of the path.
#
# The path is the last field on the line, so it is taken greedily the way
# _PROC_MAPPINGS_RE takes its objfile name: "\S+" would stop at the first
# space and record "/Applications/My" for "/Applications/My App.app/...",
# with a base and size that still look valid. The Yes/No symbols column keeps
# "\S+" -- that field never contains a space.
#
# The column separators are "[ \t]+" rather than "\s+" so that a row with no
# path cannot reach across the newline and adopt the following line. GDB's
# own "(*): Shared library is missing debugging information." footnote is the
# text that would be captured, as a path, with a plausible base and size.
_SHAREDLIB_RE = re.compile(
    r"0x([0-9a-fA-F]+)[ \t]+0x([0-9a-fA-F]+)[ \t]+\S+(?:[ \t]+\(\*\))?[ \t]+(.+)"
)


def _mapping_protection(perms: str | None) -> str:
    """Convert an ``info proc mappings`` Perms field to an ``rwx`` string.

    GDB prints Linux-style ``rw-p``/``r-xs``; only the first three flags are
    protection, the fourth is sharing.

    Args:
        perms: The Perms field, or ``None`` when GDB did not print one.

    Returns:
        An ``rwx``-style string, or ``"---"`` when the permissions are unknown.
        Reporting them as unknown is not free -- the engine skips unreadable
        regions by default -- but claiming read access GDB never confirmed
        would be worse.
    """
    return perms[:3] if perms else "---"


class MIError(RuntimeError):
    """GDB answered with a ``^error`` record.

    Distinct from the transport failures (timeout, GDB exiting) that also
    surface as ``RuntimeError``, so callers can tell "GDB refused this
    command" apart from "GDB is no longer talking to us". Subclasses
    ``RuntimeError`` so existing handlers keep catching it.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"GDB/MI error: {detail}")
        self.detail = detail


def _parse_memory_blocks(result: str) -> list[tuple[int, bytes]] | None:
    """Extract the ``(begin, data)`` pairs from an MI read reply.

    Args:
        result: Raw MI result record.

    Returns:
        One entry per readable block, sorted by address, or ``None`` when the
        reply could not be understood. ``None`` is deliberately distinct from
        ``[]``, which means "GDB answered, and nothing in the span was
        readable". Any malformed block makes the whole listing ``None``:
        dropping it instead would shorten the readable run and make the caller
        report a parse failure as a proven unreadable address, costing a page
        that reads perfectly well.
    """
    listing = _MEM_LIST_RE.search(result)
    if listing is None:
        return None

    blocks: list[tuple[int, bytes]] = []
    for raw in _BLOCK_RE.finditer(listing.group(1)):
        block = raw.group(1)
        begin = _BEGIN_RE.search(block)
        contents = _CONTENTS_RE.search(block)
        if begin is None or contents is None:
            return None
        try:
            data = bytes.fromhex(contents.group(1))
        except ValueError:
            return None
        blocks.append((int(begin.group(1), 16), data))

    blocks.sort()
    return blocks


def _contiguous_prefix(blocks: list[tuple[int, bytes]], address: int) -> bytes:
    """Join the blocks covering *address* onwards without a gap.

    GDB bisects around unreadable holes and answers with one block per readable
    run, so a reply may start past the requested address or skip a hole in the
    middle. Only the run that starts exactly at *address* can be placed with
    confidence.

    Args:
        blocks: Sorted ``(begin, data)`` pairs from :func:`_parse_memory_blocks`.
        address: Address the caller asked about.

    Returns:
        The gapless bytes starting at *address*; empty when *address* itself
        was not readable.
    """
    run: list[bytes] = []
    cursor = address
    for begin, data in blocks:
        if begin != cursor:
            break
        run.append(data)
        cursor += len(data)
    # join() hands back the single element unchanged, which is the usual case.
    return b"".join(run)


class GDBBridge:
    """DebuggerBridge backed by a GDB/MI subprocess.

    Parameters
    ----------
    target:
        Process ID (``int``) or process name (``str``) to attach to.
        When a string is given, it is resolved to a PID via ``/proc``
        or ``pidof``.
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
        if isinstance(target, int):
            self._pid: int = target
        else:
            self._pid: int = self._resolve_pid(str(target), logger or _LOG)
        self._remote = remote
        self._gdb_path = gdb_path
        self._log = logger or _LOG
        self._mi_timeout = mi_timeout
        self._proc: subprocess.Popen[str] | None = None
        self._line_queue: queue.Queue[str | None] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self._shutting_down = False
        self._preflight: PreflightResult | None = None
        # "info proc mappings" output, cached for the life of the connection.
        self._proc_mappings_text: str | None = None

    @staticmethod
    def _resolve_pid(name: str, logger: logging.Logger) -> int:
        """Resolve a process name to a PID via /proc or pidof."""
        # Try /proc first (Linux)
        proc_path = "/proc"
        if os.path.isdir(proc_path):
            for entry in os.listdir(proc_path):
                if not entry.isdigit():
                    continue
                try:
                    cmdline_path = os.path.join(proc_path, entry, "comm")
                    with open(cmdline_path) as fh:
                        comm = fh.read().strip()
                    if comm == name:
                        pid = int(entry)
                        logger.info("Resolved process '%s' to PID %d", name, pid)
                        return pid
                except (OSError, ValueError):
                    continue

        # Fallback: try pidof command
        pidof_bin = shutil.which("pidof")
        if pidof_bin:
            try:
                result = subprocess.run(
                    [pidof_bin, name],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    pids = result.stdout.strip().split()
                    if pids:
                        pid = int(pids[0])
                        logger.info(
                            "Resolved process '%s' to PID %d via pidof",
                            name, pid,
                        )
                        return pid
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass

        raise ValueError(
            f"Could not resolve process name '{name}' to a PID. "
            "Ensure the process is running or pass a numeric PID."
        )

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        # Truthiness, not "is not None": connect() selects the remote target
        # under "if self._remote", so an empty --remote would otherwise attach
        # locally while every probe here took the remote path.
        return bool(self._remote)

    # -- MI transport -------------------------------------------------------

    def _stdout_reader(self) -> None:
        """Background thread that reads GDB stdout and feeds lines into a queue.

        The queue is bound once, at thread start. ``disconnect()`` replaces
        ``self._line_queue`` to drop this thread's end-of-stream sentinel, and
        re-reading the attribute per line would put that sentinel into the
        fresh queue instead -- which the next ``connect()`` would read as a GDB
        that had already exited.
        """
        assert self._proc is not None and self._proc.stdout is not None
        line_queue = self._line_queue
        try:
            for line in self._proc.stdout:
                line_queue.put(line.rstrip("\n"))
        except (ValueError, OSError):
            pass
        finally:
            line_queue.put(None)

    def _send_mi_command(self, cmd: str) -> str:
        """Send an MI command and return the result record.

        Raises ``MIError`` if GDB answers with ``^error``, ``TimeoutError`` if
        no result record arrives within ``mi_timeout`` seconds, or
        ``RuntimeError`` if GDB exits unexpectedly.
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

            if self._log.isEnabledFor(logging.DEBUG):
                self._log.debug("MI <<< %s", _summarise_mi_line(line))
            # GDB writes its prompt as "(gdb) " -- with a trailing space --
            # after the *previous* command's result record, so one is normally
            # queued ahead of this command's output. Dropping it keeps it out
            # of the reply and stops it from displacing the result record.
            if line.strip() == "(gdb)":
                continue
            lines.append(line)
            if line.startswith("^"):
                break

        record = lines[-1]
        if record.startswith("^error"):
            msg = _MSG_RE.search(record)
            raise MIError(_unescape_mi(msg.group(1)) if msg else record)
        return "\n".join(lines)

    def _send_console_command(self, cmd: str) -> str:
        """Run a plain GDB command and return its console output, unescaped.

        Pairs the ``-interpreter-exec console`` wrapper with the escaping and
        unescaping the round trip needs, so no half can be forgotten. Callers
        that parse the result record itself use :meth:`_send_mi_command`.
        """
        return _console_text(
            self._send_mi_command(f"-interpreter-exec console {_mi_arg(cmd)}")
        )

    # -- Pre-flight checks ---------------------------------------------------

    def _check_ptrace_scope(self) -> None:
        """Warn about ptrace restrictions on Linux."""
        warn_ptrace_scope(self._log)

    def _probable_cause(self) -> str:
        """Preflight warnings that may explain an attach failure."""
        return self._preflight.probable_cause() if self._preflight else ""

    # -- DebuggerBridge protocol --------------------------------------------

    def connect(self) -> None:
        """Spawn GDB and attach to the target."""
        gdb_bin = shutil.which(self._gdb_path)
        if gdb_bin is None:
            raise FileNotFoundError(
                f"GDB not found at '{self._gdb_path}'. "
                "Install GDB or pass a valid path via gdb_path."
            )

        self._check_ptrace_scope()
        self._preflight = enforce_attach_preflight(
            self._pid, is_remote=self.is_remote, logger=self._log,
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

        try:
            if self._remote:
                self._send_mi_command(
                    f"-target-select remote {_mi_arg(self._remote)}"
                )
            else:
                self._send_mi_command(f"-target-attach {self._pid}")
        except Exception as e:
            raise AttachError(
                f"attach to {self._pid} failed: {e}",
                probable_cause=self._probable_cause(),
                cause=e,
            ) from e
        self._log.info("Attached to PID %d", self._pid)

    def get_platform_info(self) -> PlatformInfo:
        """Return architecture, OS, PID, and page size."""
        arch = parse_gdb_architecture(
            self._send_console_command("show architecture")
        )

        pid = self._target_pid()
        os_type = self._detect_os(pid)
        page_size, page_size_assumed = self._detect_page_size()

        if os_type == OSType.Android:
            self._log.warning(
                "Android memory acquisition via GDB is limited. "
                "SELinux policies may block process attachment and "
                "/proc access. ART managed heap data will be opaque. "
                "Consider using the Frida backend (-b frida -U) for "
                "more complete Android memory acquisition."
            )

        return PlatformInfo(
            arch=arch, os=os_type, pid=pid, page_size=page_size,
            page_size_assumed=page_size_assumed,
        )

    def _detect_os(self, pid: int) -> OSType:
        """Determine the *target's* OS, preferring answers GDB gives.

        Three sources, best first:

        1. A local ``/proc/<pid>/maps``. Kept first because ``show osabi``
           reports ``GNU/Linux`` for Android too; a remote target recovers that
           distinction through :meth:`_refine_remote_linux` instead.
        2. ``show osabi``. GDB's own view of the target, and the only source
           that survives a remote connection.
        3. The host's ``platform.system()``. A guess about the wrong machine
           whenever the target is remote, so it warns when it is used.

        Args:
            pid: PID of the inferior, as reported by :meth:`_target_pid`.

        Returns:
            The detected :class:`OSType`.
        """
        maps_path = f"/proc/{pid}/maps"
        if not self.is_remote and os.path.isfile(maps_path):
            # isfile() is true for any live PID, including ones this user
            # cannot read, and the inferior can exit between the check and the
            # read. Neither is fatal -- there are two more sources below.
            try:
                with open(maps_path) as fh:
                    return detect_os_from_maps(fh.read())
            except OSError as exc:
                self._log.debug("Could not read %s: %s", maps_path, exc)

        osabi = None
        try:
            osabi = parse_gdb_osabi(self._send_console_command("show osabi"))
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            self._log.debug("GDB could not report the target OS ABI: %s", exc)

        if osabi is not None:
            # "GNU/Linux" covers Android too, and a remote Android target has no
            # local maps file to say so. The mappings GDB already reports name
            # the same paths detect_os_from_maps looks for.
            if osabi == OSType.Linux and self.is_remote:
                return self._refine_remote_linux()
            return osabi

        import platform as _plat
        name = _plat.system().lower()
        if name == "darwin":
            host_os = OSType.macOS
        elif name == "windows":
            host_os = OSType.Windows
        else:
            host_os = OSType.Linux

        self._log.warning(
            "GDB did not report the target OS; assuming %s from this host. "
            "A remote target running a different OS will be recorded wrongly.",
            host_os.name,
        )
        return host_os

    def _refine_remote_linux(self) -> OSType:
        """Tell remote Android from remote Linux using the target's mappings.

        ``info proc mappings`` is the same command :meth:`enumerate_ranges`
        runs, and its paths carry the Android markers
        :func:`detect_os_from_maps` looks for.

        Returns:
            :attr:`OSType.Android` when the mappings say so, else
            :attr:`OSType.Linux`.
        """
        try:
            mappings = self._proc_mappings()
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            self._log.debug("Could not read remote mappings for OS detail: %s", exc)
            return OSType.Linux
        return detect_os_from_maps(mappings)

    def _detect_page_size(self) -> int:
        """Page size of the *target*, not of this host.

        ``sysconf`` describes the machine memslicer runs on, which is the wrong
        machine for every remote capture. The page size is not recoverable from
        the finished file -- only ``PageSizeLog2`` is stored, and the page-state
        map is sized to match -- so a wrong value produces a self-consistent
        capture that no reader can tell is wrong.

        Returns:
            ``(page_size, assumed)``. *assumed* is ``True`` when the value is a
            default rather than an answer from the target, so the caller can
            record the uncertainty in the capture instead of only logging it.
        """
        if not self.is_remote:
            if hasattr(os, "sysconf"):
                try:
                    # sysconf answers -1 for "indeterminate" rather than
                    # raising, and that would only be caught by the MSL writer
                    # once the capture had already run.
                    local = os.sysconf("SC_PAGE_SIZE")
                    if valid_page_size(local):
                        return local, False
                    self._log.debug("sysconf page size not usable: %r", local)
                except (ValueError, OSError) as exc:
                    self._log.debug("sysconf could not report the page size: %s", exc)
            # Platforms without sysconf (Windows) use 4K pages, so the default
            # is right rather than merely assumed. No warning is warranted.
            return FALLBACK_PAGE_SIZE, False

        try:
            probed = parse_gdb_auxv_page_size(
                self._send_console_command("info auxv")
            )
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            self._log.debug("GDB could not report the target auxv: %s", exc)
            probed = None
        if probed is not None:
            return probed, False

        self._log.warning(ASSUMED_PAGE_SIZE_WARNING, FALLBACK_PAGE_SIZE)
        return FALLBACK_PAGE_SIZE, True

    def _target_pid(self) -> int:
        """PID of the inferior GDB is actually attached to.

        For a remote target the constructor's PID was never used to attach --
        ``-target-select remote`` ignores it -- so it names a process on this
        machine, not the one being dumped. Ask GDB instead.
        """
        if not self.is_remote:
            return self._pid
        try:
            output = self._send_mi_command("-list-thread-groups")
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            self._log.warning("Could not ask GDB for the remote PID: %s", exc)
            return 0
        match = re.search(r'pid="(\d+)"', output)
        if match is None:
            self._log.warning(
                "GDB reported no PID for the remote inferior; the capture will "
                "record PID 0"
            )
            return 0
        return int(match.group(1))

    def enumerate_ranges(self) -> list[MemoryRange]:
        """List memory regions from ``/proc/<pid>/maps``, or from GDB.

        The ``/proc`` shortcut only applies locally: for a remote target it
        would describe whichever local process happens to own that PID while
        the reads go to the remote one.
        """
        if not self.is_remote:
            local = parse_proc_maps(self._pid, logger=self._log)
            if local:
                return local

        ranges: list[MemoryRange] = []
        output = self._proc_mappings()
        for m in _PROC_MAPPINGS_RE.finditer(output):
            base = int(m.group(1), 16)
            end = int(m.group(2), 16)
            perms = m.group(3)
            path = m.group(4).strip()
            ranges.append(
                MemoryRange(base, end - base, _mapping_protection(perms), path)
            )
        return ranges

    def _proc_mappings(self) -> str:
        """Console output of ``info proc mappings``, fetched at most once.

        Two callers need it -- :meth:`_refine_remote_linux` during
        ``get_platform_info`` and :meth:`enumerate_ranges` shortly after -- and
        for a browser or JVM it runs to hundreds of kilobytes that would
        otherwise cross the connection twice and be MI-unescaped twice.

        Caching is safe for the same reason the LLDB region cache is: the
        target is stopped for the whole capture, so its mappings cannot change
        underneath the cache. :meth:`disconnect` clears it with the rest of the
        per-connection state.
        """
        if self._proc_mappings_text is None:
            self._proc_mappings_text = self._send_console_command(
                "info proc mappings"
            )
        return self._proc_mappings_text

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List loaded shared libraries via GDB."""
        output = self._send_console_command("info sharedlibrary")
        modules: list[ModuleInfo] = []
        for m in _SHAREDLIB_RE.finditer(output):
            base = int(m.group(1), 16)
            end = int(m.group(2), 16)
            path = m.group(3).strip()
            name = os.path.basename(path)
            modules.append(ModuleInfo(name, path, base, end - base))
        return modules

    def _read_once(
        self, address: int, size: int, span: tuple[int, int],
    ) -> ReadResult:
        """Read a span small enough for a single MI command.

        Args:
            address: Start of this sub-read.
            size: Length of this sub-read.
            span: ``(start, length)`` of the whole request the sub-read belongs
                to, against which a scraped fault address is judged. Chunk
                boundaries past the first are interior to that span, so an
                address echoed there is genuinely new information.
        """
        try:
            result = self._send_mi_command(
                f"-data-read-memory-bytes {address:#x} {size}"
            )
        except MIError as exc:
            self._log.debug(
                "MI read refused at %#x size=%d: %s", address, size, exc.detail,
            )
            return ReadResult(
                None,
                # GDB names the address it was asked about ("Cannot access
                # memory at address 0x..."), which tells the caller nothing it
                # did not already know, so only an interior address is kept.
                fault_addr=fault_addr_from_text(*span, exc.detail),
                error=exc.detail,
            )
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            # The transport died rather than the memory being unreadable, so
            # there is no fault boundary to report. OSError/ValueError cover
            # writing to the pipe of a GDB that has already exited, which must
            # degrade to failed pages rather than abort the capture.
            self._log.debug(
                "MI read transport failure at %#x size=%d: %s", address, size, exc,
            )
            return ReadResult(None, error=str(exc))

        blocks = _parse_memory_blocks(result)
        if blocks is None:
            return ReadResult(
                None, error="unparseable -data-read-memory-bytes reply",
            )

        data = _contiguous_prefix(blocks, address)
        if len(data) >= size:
            return ReadResult(data[:size])

        # GDB bisects byte-exactly around unreadable holes, so the end of the
        # readable prefix is a proven boundary -- including a prefix of zero
        # length, which says the requested address itself is unreadable.
        return ReadResult(
            None,
            fault_addr=address + len(data),
            error=f"partial read: {len(data)}/{size} bytes at {address:#x}",
        )

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        """Read *size* bytes at *address*, reporting the fault on failure.

        Large spans are split across several MI commands: the reply carries the
        payload as hex on a single line, so one command per 20 MB engine chunk
        would mean a 40 MB line through a line-buffered pipe.

        Args:
            address: Address to read from.
            size: Number of bytes to read.

        Returns:
            A :class:`ReadResult` holding the whole span, or no data plus the
            boundary where the read stopped. Partial spans are never returned
            as data, so that every backend answers all-or-nothing and the
            caller can place the bytes it receives without further checks.
        """
        chunks: list[bytes] = []
        for offset in range(0, size, _MI_MAX_READ):
            res = self._read_once(
                address + offset, min(_MI_MAX_READ, size - offset),
                (address, size),
            )
            if res.data is None:
                # An earlier sub-read may have succeeded, but the contract is
                # all-or-nothing; the caller re-reads the prefix in one call.
                return res
            chunks.append(res.data)
        return ReadResult(b"".join(chunks))

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes at *address*. Returns ``None`` on failure."""
        return self.read_memory_ex(address, size).data

    # Longest wait for the stdout reader to notice its pipe has closed.
    _READER_JOIN_TIMEOUT: float = 5.0

    def disconnect(self) -> None:
        """Detach, terminate GDB, and release the pipes and reader thread.

        The process is held in a local until the end: :meth:`_stdout_reader`
        reaches ``self._proc.stdout``, so clearing the attribute before the
        thread has stopped would fault it rather than end it.
        """
        proc = self._proc
        if proc is None:
            return
        self._shutting_down = True
        try:
            self._send_mi_command("-target-detach")
        except (RuntimeError, OSError, TimeoutError):
            pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            # disconnect() is normally called from the caller's finally block,
            # so anything raised here would mask the acquisition error that
            # sent us there. kill() itself can raise, so it is guarded with
            # the wait() that reaps the child -- without that second wait the
            # signal is sent but the zombie stays until this process exits.
            try:
                proc.kill()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self._log.warning("GDB did not exit after kill()")
        finally:
            # Closing the pipes is what ends the reader thread: its loop is
            # blocked on stdout, and the read raises ValueError/OSError, which
            # _stdout_reader already treats as end of stream.
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass

            if self._reader_thread is not None:
                self._reader_thread.join(timeout=self._READER_JOIN_TIMEOUT)
                if self._reader_thread.is_alive():
                    self._log.warning("GDB stdout reader did not stop")
                self._reader_thread = None

            # The reader leaves a None sentinel behind, and a re-connect() would
            # read it as "GDB exited" on its first command. Start from empty.
            self._line_queue = queue.Queue()

            # Describes a process this bridge is no longer attached to.
            self._proc_mappings_text = None

            self._proc = None
            self._shutting_down = False
            self._log.info("Disconnected from PID %d", self._pid)
