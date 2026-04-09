"""LLDB-based DebuggerBridge implementation."""
from __future__ import annotations

import logging
import os
from typing import Any

from memslicer.acquirer.bridge import (
    MemoryRange,
    ModuleInfo,
    PlatformInfo,
)
from memslicer.acquirer.platform_detect import (
    detect_os_from_maps,
    parse_lldb_triple,
    parse_proc_maps,
)
from memslicer.msl.constants import ArchType, OSType


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
        self._debugger: Any | None = None
        self._lldb_target: Any | None = None
        self._process: Any | None = None
        self._platform_info: PlatformInfo | None = None

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        return self._remote is not None

    # -- DebuggerBridge interface -------------------------------------------

    def connect(self) -> None:
        """Create an LLDB debugger instance and attach to the target."""
        try:
            import lldb as _lldb  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'lldb' Python module is not available. "
                "Ensure LLDB is installed and its Python bindings are on "
                "sys.path (e.g. via PYTHONPATH or the Xcode toolchain)."
            ) from exc

        self._lldb = _lldb

        debugger = _lldb.SBDebugger.Create()
        debugger.SetAsync(False)
        self._debugger = debugger

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
            self._log.info(
                "Connected to remote platform '%s' at %s",
                platform_name, connect_url,
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
            raise RuntimeError(f"LLDB attach failed: {error.GetCString()}")
        self._process = process

        # Resolve platform info immediately so get_platform_info() is cheap.
        triple = lldb_target.GetTriple() or ""
        os_type, arch = parse_lldb_triple(triple)
        pid = process.GetProcessID()
        page_size = _default_page_size(arch, os_type)

        # Refine OS detection and page size on Linux using /proc.
        if os_type in (OSType.Linux, OSType.Android) and self._remote is None:
            os_type, page_size = self._refine_linux_info(pid, os_type, page_size)

        self._platform_info = PlatformInfo(
            arch=arch, os=os_type, pid=pid, page_size=page_size,
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

    def enumerate_ranges(self) -> list[MemoryRange]:
        """Walk the process address space and collect all memory regions."""
        _lldb = self._lldb
        process = self._process
        ranges: list[MemoryRange] = []

        addr: int = 0
        region = _lldb.SBMemoryRegionInfo()
        while True:
            err = process.GetMemoryRegionInfo(addr, region)
            if err.Fail():
                break

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

        # On Linux, fall back to /proc/maps when LLDB returns no regions.
        if (
            not ranges
            and self._platform_info
            and self._platform_info.os in (OSType.Linux, OSType.Android)
            and self._remote is None
        ):
            ranges = self._enumerate_from_proc_maps()

        self._log.debug("Enumerated %d memory regions via LLDB", len(ranges))
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules reported by the LLDB target."""
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

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes starting at *address*. Return None on failure."""
        _lldb = self._lldb
        error = _lldb.SBError()
        data = self._process.ReadMemory(address, size, error)
        if error.Success() and data is not None:
            return bytes(data)
        self._log.debug(
            "LLDB read failed at 0x%x size=%d: %s",
            address, size, error.GetCString(),
        )
        return None

    # -- Private helpers -----------------------------------------------------

    @staticmethod
    def _parse_remote_url(remote: str) -> tuple[str, str]:
        """Parse a remote URL into (platform_name, connect_url).

        Accepted formats:
            ``"host:port"``             -> ``("remote-linux", "connect://host:port")``
            ``"ios://host:port"``       -> ``("remote-ios", "connect://host:port")``
            ``"android://host:port"``   -> ``("remote-linux", "connect://host:port")``
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
    ) -> tuple[OSType, int]:
        """Refine OS detection and page size from /proc on Linux.

        Returns ``(os_type, page_size)`` — both may be updated.
        """
        # Prefer os.sysconf for accurate page size on the local machine.
        if hasattr(os, "sysconf"):
            try:
                page_size = os.sysconf("SC_PAGE_SIZE")
            except (ValueError, OSError):
                pass

        # Check /proc maps for Android indicators.
        maps_path = f"/proc/{pid}/maps"
        if os_type == OSType.Linux and os.path.isfile(maps_path):
            try:
                with open(maps_path) as fh:
                    content = fh.read(32768)
                refined = detect_os_from_maps(content)
                if refined == OSType.Android:
                    os_type = refined
                    self._log.info("Detected Android from /proc/maps")
            except (OSError, PermissionError):
                pass

        return os_type, page_size

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
