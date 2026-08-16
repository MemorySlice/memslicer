"""LLDB-based DebuggerBridge implementation."""
from __future__ import annotations

import logging
import os
from typing import Any

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
    fault_addr_from_text,
)
from memslicer.acquirer.errors import AttachError
from memslicer.acquirer.platform_detect import (
    detect_os_from_maps,
    parse_lldb_triple,
    valid_page_size,
    parse_proc_maps,
)
from memslicer.msl.constants import ArchType, OSType


def _lldb_binding_candidates() -> list[str]:
    """Directories that may hold the LLDB Python bindings, best first.

    ``lldb -P`` is the authoritative answer and the only one that does not
    assume a directory layout, so it is asked first. It covers the
    installations the hard-coded paths miss: a CommandLineTools-only machine
    (which is what ``xcode-select --install`` produces), Homebrew LLVM, and
    distribution packages on Linux.

    Returns:
        Candidate directories, in the order they should be tried. Existence is
        not checked here -- the caller filters.
    """
    import subprocess

    candidates: list[str] = []

    try:
        result = subprocess.run(
            ["lldb", "-P"], capture_output=True, text=True, timeout=5,
        )
        # Some builds print a warning ahead of the path, so every line is kept
        # as a candidate and the caller's isdir check picks the real one.
        candidates.extend(
            line.strip() for line in result.stdout.splitlines() if line.strip()
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    try:
        result = subprocess.run(
            ["xcode-select", "--print-path"],
            capture_output=True, text=True, timeout=5,
        )
        developer_dir = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        developer_dir = ""

    if developer_dir:
        candidates.extend([
            # Full Xcode: .../Xcode.app/Contents/Developer/.. -> Contents.
            os.path.join(
                developer_dir, "..", "SharedFrameworks",
                "LLDB.framework", "Resources", "Python",
            ),
            os.path.join(
                developer_dir, "SharedFrameworks",
                "LLDB.framework", "Resources", "Python",
            ),
            # CommandLineTools keeps LLDB in PrivateFrameworks instead, and
            # has no Contents/SharedFrameworks at all.
            os.path.join(
                developer_dir, "Library", "PrivateFrameworks",
                "LLDB.framework", "Resources", "Python",
            ),
        ])

    return [os.path.normpath(candidate) for candidate in candidates]


def _ensure_lldb_importable() -> str | None:
    """Put the LLDB Python bindings on ``sys.path`` if they are not already.

    LLDB ships bindings that are not on the default Python path, so importing
    them takes a search. Locating them does not guarantee they will load: the
    ``_lldb`` extension inside is built against one specific interpreter, and
    another one cannot import it. Reporting which of the two happened is left
    to the caller, which is why the chosen directory is returned.

    Returns:
        The directory whose bindings imported; failing that, the first
        directory that existed, so the caller can name what it found; or
        ``None`` when ``lldb`` was already importable or nothing was found.
    """
    try:
        import lldb  # noqa: F401
        return None  # Already importable -- nothing to do.
    except ImportError:
        pass

    import importlib
    import sys

    first_existing: str | None = None

    for candidate in _lldb_binding_candidates():
        if not os.path.isdir(candidate):
            continue
        if first_existing is None:
            first_existing = candidate

        inserted = candidate not in sys.path
        if inserted:
            sys.path.insert(0, candidate)
        # A directory added after interpreter start is invisible to the import
        # machinery until its path caches are dropped.
        importlib.invalidate_caches()
        # A failed attempt can leave a half-built package behind, which the
        # next attempt would find instead of importing afresh.
        for name in [n for n in sys.modules if n == "lldb" or n.startswith("lldb.")]:
            del sys.modules[name]

        try:
            importlib.import_module("lldb")
        except ImportError:
            # Present but not loadable by this interpreter. A later candidate
            # may be a different LLDB build that is -- Homebrew LLVM alongside
            # Xcode is the usual way to end up with two.
            if inserted:
                sys.path.remove(candidate)
            continue
        return candidate

    # Nothing imported. The first directory that existed is the one worth
    # naming, so the caller can say the bindings were found but would not load.
    return first_existing


def _lldb_import_message(bindings_dir: str | None, exc: ImportError) -> str:
    """Explain an ``import lldb`` failure in terms of what actually went wrong.

    The two failures need opposite responses, and telling them apart is the
    difference between a fix and an afternoon: bindings that were never found
    are an installation problem, while bindings that were found and still did
    not load mean this interpreter is not the one they were built for.

    Args:
        bindings_dir: Directory :func:`_ensure_lldb_importable` selected, if any.
        exc: The ``ImportError`` raised by ``import lldb``.

    Returns:
        The message for the raised :class:`ImportError`.
    """
    import sys

    if bindings_dir is None:
        return (
            "The 'lldb' Python module is not available, and no LLDB Python "
            "bindings could be found. Install LLDB and make sure 'lldb' is on "
            "PATH -- 'lldb -P' must print the directory holding the bindings. "
            "On macOS: xcode-select --install"
        )

    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    return (
        f"LLDB Python bindings were found at {bindings_dir} but could not be "
        f"loaded by this interpreter (Python {version} at {sys.executable}): "
        f"{exc}. The bindings include a compiled extension that only imports "
        f"into the interpreter LLDB was built against. Re-run memslicer with "
        f"that interpreter -- on macOS that is usually /usr/bin/python3 -- or "
        f"install a build of LLDB matching this one."
    )


# How much of a target's maps file is scanned for Android markers. They appear
# among the first mappings, and reading the whole file costs a round trip
# proportional to the target's address space -- megabytes for a browser or JVM.
_MAPS_SCAN_BYTES = 32768


def _default_page_size(arch: ArchType, os_type: OSType) -> int:
    """Return a sensible default page size for the given platform."""
    if arch == ArchType.ARM64 and os_type in (OSType.macOS, OSType.iOS):
        return 16384
    return 4096


# ---------------------------------------------------------------------------
# Protection string builder
# ---------------------------------------------------------------------------

def _protection_string(region: Any) -> str:
    """Build an ``rwx``-style protection string from an SBMemoryRegionInfo."""
    return (
        ("r" if region.IsReadable() else "-")
        + ("w" if region.IsWritable() else "-")
        + ("x" if region.IsExecutable() else "-")
    )


# ---------------------------------------------------------------------------
# LLDBBridge
# ---------------------------------------------------------------------------

class LLDBBridge:
    """DebuggerBridge implementation using the LLDB Python module.

    The ``lldb`` package is imported lazily inside :meth:`connect` so that
    importing this module never fails -- only attaching does.
    """

    def __init__(
        self,
        target: int | str,
        remote: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._target = target
        self._remote = remote
        self._log = logger or logging.getLogger("memslicer")
        # Bound in connect(); declared here so the methods that need it can say
        # so plainly instead of failing with AttributeError.
        self._lldb: Any | None = None
        self._debugger: Any | None = None
        self._lldb_target: Any | None = None
        self._process: Any | None = None
        # The connected SBPlatform, when the target is remote. It is the only
        # channel that can answer questions about the remote machine itself.
        self._platform: Any | None = None
        self._platform_info: PlatformInfo | None = None
        self._preflight: PreflightResult | None = None
        # Last (readable, base, end) answered by GetMemoryRegionInfo.
        self._region_cache: tuple[bool, int, int] | None = None

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        # Truthiness, not "is not None": connect() sets the platform up under
        # "if self._remote", so an empty --remote would otherwise report remote
        # while no platform exists -- the probes would find nothing to ask and
        # the local ones would be skipped.
        return bool(self._remote)

    # -- Pre-flight checks ---------------------------------------------------

    def _check_macos_sip(self) -> None:
        """Warn about SIP restrictions on macOS."""
        import platform as _plat
        if _plat.system() != "Darwin":
            return
        import subprocess
        try:
            result = subprocess.run(
                ["csrutil", "status"],
                capture_output=True, text=True, timeout=5,
            )
            if "enabled" in result.stdout.lower():
                self._log.warning(
                    "macOS System Integrity Protection (SIP) is enabled. "
                    "Attaching to Apple-signed or hardened-runtime processes "
                    "will fail. Only debug builds with "
                    "com.apple.security.get-task-allow entitlement can be "
                    "debugged. Disable SIP or use the Frida backend for "
                    "broader process access."
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def _check_ptrace_scope(self) -> None:
        """Warn about ptrace restrictions on Linux."""
        warn_ptrace_scope(self._log)

    def _probable_cause(self) -> str:
        """Preflight warnings that may explain an attach failure."""
        return self._preflight.probable_cause() if self._preflight else ""

    # -- DebuggerBridge interface -------------------------------------------

    def connect(self) -> None:
        """Create an LLDB debugger instance and attach to the target."""
        bindings_dir = _ensure_lldb_importable()
        try:
            import lldb as _lldb  # noqa: F811
        except ImportError as exc:
            raise ImportError(_lldb_import_message(bindings_dir, exc)) from exc

        self._lldb = _lldb

        debugger = _lldb.SBDebugger.Create()
        debugger.SetAsync(False)
        self._debugger = debugger

        self._check_macos_sip()
        self._check_ptrace_scope()
        self._preflight = enforce_attach_preflight(
            self._target if isinstance(self._target, int) else None,
            is_remote=self.is_remote,
            logger=self._log,
        )

        # Set up remote platform if specified.
        if self._remote:
            platform_name, connect_url = self._parse_remote_url(self._remote)
            platform = _lldb.SBPlatform(platform_name)
            connect_options = _lldb.SBPlatformConnectOptions(connect_url)
            error = platform.ConnectRemote(connect_options)
            if error.Fail():
                raise RuntimeError(
                    f"LLDB remote connect to {connect_url} failed: "
                    f"{error.GetCString()}"
                )
            debugger.SetSelectedPlatform(platform)
            self._platform = platform
            self._log.info(
                "Connected to remote platform '%s' at %s",
                platform_name, connect_url,
            )
            if platform_name == "remote-ios":
                self._log.warning(
                    "iOS remote debugging via LLDB requires a running "
                    "debugserver on the target device (jailbreak required). "
                    "Consider using the Frida backend (-b frida -U) for "
                    "more reliable iOS memory acquisition."
                )

        lldb_target = debugger.CreateTarget("")
        if not lldb_target.IsValid():
            raise RuntimeError("Failed to create LLDB target")
        self._lldb_target = lldb_target

        error = _lldb.SBError()
        if isinstance(self._target, int):
            self._log.info("Attaching to PID %d via LLDB...", self._target)
            process = lldb_target.AttachToProcessWithID(
                _lldb.SBListener(), self._target, error,
            )
        else:
            self._log.info(
                "Attaching to process '%s' via LLDB...", self._target,
            )
            process = lldb_target.AttachToProcessWithName(
                _lldb.SBListener(), self._target, False, error,
            )

        if not error.Success():
            raise AttachError(
                f"attach to {self._target} failed: {error.GetCString()}",
                probable_cause=self._probable_cause(),
            )
        self._process = process

        # Resolve platform info immediately so get_platform_info() is cheap.
        triple = lldb_target.GetTriple() or ""
        os_type, arch = parse_lldb_triple(triple)
        pid = process.GetProcessID()
        page_size = _default_page_size(arch, os_type)

        # Only the remote fallback below can set this. A local target is this
        # machine, and an Apple arm64 triple fixes the page size at 16 KiB, so
        # neither is a guess.
        page_size_assumed = False

        # Refine OS detection and page size from /proc. Both transports get
        # this; they differ only in how /proc is reached. Leaving the remote
        # case out is what made every remote target report 4096 and plain
        # Linux, regardless of the device.
        if os_type in (OSType.Linux, OSType.Android):
            refine = (
                self._refine_remote_linux_info if self.is_remote
                else self._refine_linux_info
            )
            os_type, page_size, page_size_assumed = refine(
                pid, os_type, page_size,
            )

        self._platform_info = PlatformInfo(
            arch=arch, os=os_type, pid=pid, page_size=page_size,
            page_size_assumed=page_size_assumed,
        )

        if os_type == OSType.Android:
            self._log.warning(
                "Android memory acquisition via LLDB is limited. "
                "SELinux policies may block process attachment and "
                "/proc access. ART managed heap data will be opaque. "
                "Consider using the Frida backend (-b frida -U) for "
                "more complete Android memory acquisition."
            )

        self._log.debug(
            "LLDB attached: triple=%s pid=%d page_size=%d",
            triple, pid, page_size,
        )

    def get_platform_info(self) -> PlatformInfo:
        """Return cached platform info collected during :meth:`connect`."""
        if self._platform_info is None:
            raise RuntimeError("LLDBBridge.connect() must be called first")
        return self._platform_info

    # Skip size when GetMemoryRegionInfo fails (1 MB).
    _REGION_SKIP: int = 0x100000
    # Give up after this many consecutive failures (64 MB gap).
    _MAX_CONSECUTIVE_SKIP: int = 64
    # Minimum LLDB region count before /proc/maps cross-check on Linux.
    _MIN_LLDB_REGION_COUNT: int = 5

    def enumerate_ranges(self) -> list[MemoryRange]:
        """Walk the process address space and collect all memory regions."""
        if self._process is None or self._lldb is None:
            raise RuntimeError("LLDBBridge.connect() must be called first")
        _lldb = self._lldb
        process = self._process
        ranges: list[MemoryRange] = []

        addr: int = 0
        consecutive_failures: int = 0
        region = _lldb.SBMemoryRegionInfo()
        while True:
            err = process.GetMemoryRegionInfo(addr, region)
            if err.Fail():
                consecutive_failures += 1
                if consecutive_failures > self._MAX_CONSECUTIVE_SKIP:
                    self._log.debug(
                        "Stopping region scan after %d consecutive failures "
                        "at 0x%x",
                        consecutive_failures, addr,
                    )
                    break
                self._log.debug(
                    "GetMemoryRegionInfo failed at 0x%x, skipping ahead by "
                    "0x%x (%s)",
                    addr, self._REGION_SKIP, err.GetCString(),
                )
                addr += self._REGION_SKIP
                continue

            # Successful query — reset the failure counter.
            consecutive_failures = 0

            base = region.GetRegionBase()
            end = region.GetRegionEnd()
            size = end - base

            if size > 0 and region.IsMapped():
                file_path = region.GetName() or ""
                ranges.append(MemoryRange(
                    base=base,
                    size=size,
                    protection=_protection_string(region),
                    file_path=file_path,
                ))

            # Advance past this region; guard against wrap-around.
            if end == 0 or end <= addr:
                break
            addr = end

        # On Linux, fall back to /proc/maps when LLDB returns too few
        # regions -- this catches both zero results and suspiciously
        # incomplete enumerations (e.g. sparse 64-bit address spaces).
        if (
            len(ranges) < self._MIN_LLDB_REGION_COUNT
            and self._platform_info
            and self._platform_info.os in (OSType.Linux, OSType.Android)
            and not self.is_remote
        ):
            proc_ranges = self._enumerate_from_proc_maps()
            if len(proc_ranges) > len(ranges):
                self._log.debug(
                    "LLDB returned only %d regions; using %d regions from "
                    "/proc/maps instead",
                    len(ranges), len(proc_ranges),
                )
                ranges = proc_ranges

        self._log.debug("Enumerated %d memory regions via LLDB", len(ranges))
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules reported by the LLDB target."""
        if self._lldb_target is None:
            raise RuntimeError("LLDBBridge.connect() must be called first")
        target = self._lldb_target
        modules: list[ModuleInfo] = []

        for i in range(target.GetNumModules()):
            mod = target.GetModuleAtIndex(i)
            fspec = mod.GetFileSpec()
            name = fspec.GetFilename() or ""
            path = str(fspec)

            # Determine load address from the object-file header.
            header_addr = mod.GetObjectFileHeaderAddress()
            base = header_addr.GetLoadAddress(target) if header_addr.IsValid() else 0

            # Estimate in-memory size from the address span of loaded sections.
            # Falls back to summing section byte sizes when load addresses
            # are unavailable.
            min_addr = 0xFFFFFFFFFFFFFFFF
            max_addr = 0
            sum_size = 0
            for s in range(mod.GetNumSections()):
                sec = mod.GetSectionAtIndex(s)
                sec_size = sec.GetByteSize()
                sum_size += sec_size
                sec_addr = sec.GetLoadAddress(target)
                if sec_addr != 0xFFFFFFFFFFFFFFFF and sec_size > 0:
                    min_addr = min(min_addr, sec_addr)
                    max_addr = max(max_addr, sec_addr + sec_size)
            total_size = (max_addr - min_addr) if max_addr > min_addr else sum_size

            modules.append(ModuleInfo(
                name=name, path=path, base=base, size=total_size,
            ))

        self._log.debug("Enumerated %d modules via LLDB", len(modules))
        return modules

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        """Read *size* bytes at *address*, reporting the fault on failure.

        ``SBProcess.ReadMemory`` can stop at the first unreadable cache line and
        hand back a short buffer without reporting an error, so the length is
        checked as well as the status. A short span is never returned as data:
        every backend answers all-or-nothing, so the caller can place what it
        receives without further checks.

        Args:
            address: Address to read from.
            size: Number of bytes to read.

        Returns:
            A :class:`ReadResult` holding the whole span, or no data plus the
            boundary where the read stopped.
        """
        if self._process is None or self._lldb is None:
            return ReadResult(None, error="LLDBBridge.connect() must be called first")

        error = self._lldb.SBError()
        data = self._process.ReadMemory(address, size, error)
        if error.Success() and data is not None and len(data) >= size:
            return ReadResult(bytes(data)[:size])

        detail = error.GetCString() or ""
        partial = len(data) if data else 0
        self._log.debug(
            "LLDB read at 0x%x size=%d returned %d bytes: %s",
            address, size, partial, detail,
        )
        return ReadResult(
            None,
            fault_addr=self._fault_boundary(address, size, partial, detail),
            error=detail or f"short read: {partial}/{size} bytes",
        )

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes starting at *address*. Return None on failure."""
        return self.read_memory_ex(address, size).data

    # -- Private helpers -----------------------------------------------------

    def _fault_boundary(
        self, address: int, size: int, partial: int, detail: str,
    ) -> int | None:
        """First address proven unreadable within ``[address, address+size)``.

        LLDB knows the map layout, so asking it where the region containing
        *address* ends beats guessing from the error text.

        Args:
            address: Start of the failed read.
            size: Length of the failed read.
            partial: Bytes LLDB did return, if any.
            detail: Error text from the failed read.

        Returns:
            The boundary, or ``None`` when none could be established -- which
            tells the caller to fall back to page-by-page reads rather than
            skip pages that may well be readable.
        """
        bounds = self._region_bounds_at(address)
        if bounds is not None:
            readable, _base, region_end = bounds
            if readable and address < region_end < address + size:
                return region_end
            # Either the region covers the whole span, or none of it is
            # readable. Neither leaves a readable prefix to salvage, and a
            # fault at the very start of a span is the one case where
            # reporting it backfires: the caller re-asks for the whole
            # shrinking remainder once per page instead of reading each page
            # once. Measured on a 2 MB unreadable span, that is 538 MB
            # requested against 4 MB. Say nothing and let it read page by page.
            return None

        return fault_addr_from_text(address, size, detail)

    def _region_bounds_at(self, address: int) -> tuple[bool, int, int] | None:
        """``(readable, base, end)`` for the region holding *address*.

        Each query is a round trip to the debug server, and a span that
        degrades to page-by-page reads asks about the same region thousands of
        times, so the last answer is kept. The target is stopped for the whole
        capture, so the map cannot change underneath the cache.

        Returns:
            The bounds, or ``None`` when the query failed.
        """
        cached = self._region_cache
        if cached is not None and cached[1] <= address < cached[2]:
            return cached

        region = self._lldb.SBMemoryRegionInfo()
        try:
            err = self._process.GetMemoryRegionInfo(address, region)
        except Exception:
            # This only ever informs a diagnostic, so a process that has died
            # underneath us must not turn a failed read into an exception.
            return None
        if err.Fail():
            return None

        base, end = region.GetRegionBase(), region.GetRegionEnd()
        if not base <= address < end:
            # A stub that answers with the next region, or with a degenerate
            # empty one, has told us nothing about this address. Treating it
            # as proof would claim an address is unreadable on the strength of
            # a region that does not contain it.
            return None

        bounds = (bool(region.IsMapped() and region.IsReadable()), base, end)
        self._region_cache = bounds
        return bounds

    @staticmethod
    def _parse_remote_url(remote: str) -> tuple[str, str]:
        """Parse a remote URL into (platform_name, connect_url).

        Accepted formats:
            ``"host:port"``             -> ``("remote-linux", "connect://host:port")``
            ``"ios://host:port"``       -> ``("remote-ios", "connect://host:port")``
            ``"android://host:port"``   -> ``("remote-linux", "connect://host:port")``

        Note:
            The ``ios://`` scheme maps to LLDB's ``remote-ios`` platform which
            requires a manually launched ``debugserver`` on the target device
            (typically jailbroken).  No usbmuxd / lockdownd integration is
            provided by this bridge.
        """
        if remote.startswith("ios://"):
            addr = remote[len("ios://"):]
            return "remote-ios", f"connect://{addr}"
        if remote.startswith("android://"):
            addr = remote[len("android://"):]
            return "remote-linux", f"connect://{addr}"
        return "remote-linux", f"connect://{remote}"

    def _refine_linux_info(
        self, pid: int, os_type: OSType, page_size: int,
    ) -> tuple[OSType, int, bool]:
        """Refine OS detection and page size from /proc on Linux.

        Returns:
            ``(os_type, page_size, page_size_assumed)``. The page size is never
            assumed here -- a local target is this machine, so ``sysconf``
            measures the right one.
        """
        # Prefer os.sysconf for accurate page size on the local machine.
        if hasattr(os, "sysconf"):
            try:
                local = os.sysconf("SC_PAGE_SIZE")
                # sysconf reports -1 for "indeterminate" rather than raising,
                # and that would only surface at the MSL writer, once the
                # capture had already run.
                if valid_page_size(local):
                    page_size = local
                else:
                    self._log.debug("sysconf page size not usable: %r", local)
            except (ValueError, OSError):
                pass

        # Check /proc maps for Android indicators.
        maps_path = f"/proc/{pid}/maps"
        if os_type == OSType.Linux and os.path.isfile(maps_path):
            try:
                with open(maps_path) as fh:
                    content = fh.read(_MAPS_SCAN_BYTES)
                refined = detect_os_from_maps(content)
                if refined == OSType.Android:
                    os_type = refined
                    self._log.info("Detected Android from /proc/maps")
            except (OSError, PermissionError):
                pass

        return os_type, page_size, False

    def _platform_shell(self, command: str) -> str | None:
        """Run *command* on the connected remote platform.

        lldb-server in platform mode serves these; debugserver (iOS) does not,
        so a ``None`` here is an ordinary outcome rather than an error.

        Args:
            command: Shell command to run on the target machine.

        Returns:
            The command's output, or ``None`` when there is no platform, the
            command failed, or it produced nothing.
        """
        if self._platform is None or self._lldb is None:
            return None
        try:
            shell = self._lldb.SBPlatformShellCommand(command)
            error = self._platform.Run(shell)
            if error is not None and error.Fail():
                self._log.debug(
                    "Remote shell %r failed: %s", command, error.GetCString(),
                )
                return None
            return shell.GetOutput()
        except Exception as exc:
            # Broad on purpose, and for the same reason disconnect() is: the
            # SWIG bindings raise types that are not part of any documented
            # contract. This is a best-effort probe with a caller that handles
            # None, so nothing it raises should be able to fail the attach.
            self._log.debug("Remote shell %r unavailable: %s", command, exc)
            return None

    def _remote_page_size(self) -> int | None:
        """Page size of the remote target, asked of the target itself.

        Returns:
            The page size, or ``None`` when the platform could not answer or
            answered something that is not a usable page size.
        """
        output = self._platform_shell("getconf PAGESIZE")
        if not output:
            return None
        try:
            value = int(output.strip())
        except ValueError:
            self._log.debug("Remote page size not a number: %r", output)
            return None
        return value if valid_page_size(value) else None

    def _refine_remote_linux_info(
        self, pid: int, os_type: OSType, page_size: int,
    ) -> tuple[OSType, int, bool]:
        """Refine OS detection and page size for a remote Linux target.

        The remote counterpart of :meth:`_refine_linux_info`: same two questions,
        asked over the platform's shell because this machine's ``/proc`` and
        ``sysconf`` describe the wrong computer.

        Returns:
            ``(os_type, page_size, page_size_assumed)``.
        """
        probed = self._remote_page_size()
        page_size_assumed = probed is None
        if probed is not None:
            page_size = probed
        else:
            self._log.warning(ASSUMED_PAGE_SIZE_WARNING, page_size)

        if os_type == OSType.Linux:
            # Bounded like the local read in _refine_linux_info: the Android
            # markers appear among the first mappings, and a browser or JVM
            # maps file runs to megabytes that would be buffered whole and
            # pulled across the connection during attach.
            maps = self._platform_shell(
                f"head -c {_MAPS_SCAN_BYTES} /proc/{pid}/maps"
            )
            if maps and detect_os_from_maps(maps) == OSType.Android:
                os_type = OSType.Android
                self._log.info("Detected Android from remote /proc/maps")

        return os_type, page_size, page_size_assumed

    def _enumerate_from_proc_maps(self) -> list[MemoryRange]:
        """Parse ``/proc/<pid>/maps`` as a fallback range source on Linux."""
        pid = self._platform_info.pid if self._platform_info else 0
        ranges = parse_proc_maps(pid, logger=self._log)
        self._log.debug("Fallback: read %d ranges from /proc/%d/maps", len(ranges), pid)
        return ranges

    def disconnect(self) -> None:
        """Detach from the process and destroy the debugger instance."""
        if self._process is not None:
            try:
                self._process.Detach()
            except Exception:
                pass
            self._process = None

        if self._debugger is not None:
            try:
                self._lldb.SBDebugger.Destroy(self._debugger)
            except Exception:
                pass
            self._debugger = None

        # The target belongs to the destroyed debugger, the platform's
        # connection went with it, and the cached region describes a process
        # this bridge is no longer attached to. Clearing them keeps the guards
        # honest: enumerate_modules would otherwise call into a dead target and
        # report "no modules" rather than refusing.
        self._lldb_target = None
        self._platform = None
        self._region_cache = None
