"""OS and architecture detection via Frida script API."""
from __future__ import annotations

import logging
import os
import re

from memslicer.acquirer.bridge import MemoryRange
from memslicer.msl.constants import OSType, ArchType


_ARCH_MAP = {
    "ia32": ArchType.x86,
    "x64": ArchType.x86_64,
    "arm": ArchType.ARM32,
    "arm64": ArchType.ARM64,
}

_PLATFORM_MAP = {
    "windows": OSType.Windows,
    "linux": OSType.Linux,
    "darwin": OSType.macOS,
}


def detect_arch(frida_arch: str) -> ArchType:
    """Map Frida Process.arch string to ArchType."""
    arch = _ARCH_MAP.get(frida_arch)
    if arch is None:
        raise ValueError(f"Unknown Frida arch: {frida_arch!r}")
    return arch


def detect_os(
    frida_platform: str,
    modules: list[dict] | None = None,
    os_override: OSType | None = None,
) -> OSType:
    """Detect OS from Frida platform and module list.

    Args:
        frida_platform: From Process.platform ("windows", "linux", "darwin")
        modules: List of module dicts with 'name' and 'path' keys
        os_override: If provided, use this instead of auto-detection
    """
    if os_override is not None:
        return os_override

    base_os = _PLATFORM_MAP.get(frida_platform)
    if base_os is None:
        raise ValueError(f"Unknown Frida platform: {frida_platform!r}")

    if base_os == OSType.macOS and modules:
        # Distinguish iOS from macOS
        for mod in modules:
            path = mod.get("path", "")
            name = mod.get("name", "")
            if "UIKit" in name or "/System/Library/Frameworks/UIKit" in path:
                return OSType.iOS
            if "/usr/lib/system/libsystem_" in path and "/iPhoneOS" in path:
                return OSType.iOS
        return OSType.macOS

    if base_os == OSType.Linux and modules:
        # Distinguish Android from Linux
        for mod in modules:
            path = mod.get("path", "")
            name = mod.get("name", "")
            if name in ("linker", "linker64") and "/system/bin/" in path:
                return OSType.Android
            if "libandroid_runtime.so" in name:
                return OSType.Android
            if "libdvm.so" in name or "libart.so" in name:
                return OSType.Android
        return OSType.Linux

    return base_os


def detect_platform(
    frida_arch: str,
    frida_platform: str,
    modules: list[dict] | None = None,
    os_override: OSType | None = None,
) -> tuple[OSType, ArchType]:
    """Full platform detection. Returns (os_type, arch_type)."""
    return (
        detect_os(frida_platform, modules, os_override),
        detect_arch(frida_arch),
    )


# ---------------------------------------------------------------------------
# GDB / LLDB / proc-maps helpers
# ---------------------------------------------------------------------------

_GDB_ARCH_MAP = {
    "i386": ArchType.x86,
    "i386:x86-64": ArchType.x86_64,
    "aarch64": ArchType.ARM64,
    "arm": ArchType.ARM32,
}

_GDB_ARCH_RE = re.compile(
    r'The target architecture is set to "auto" \(currently "([^"]+)"\)'
    r'|'
    r'The target architecture is set to "([^"]+)"'
)


def parse_gdb_architecture(arch_output: str) -> ArchType:
    """Extract architecture from GDB ``show architecture`` output.

    Args:
        arch_output: Full output line from the GDB command.

    Returns:
        The matching :class:`ArchType`.

    Raises:
        ValueError: If the output cannot be parsed or the architecture is
            not recognised.
    """
    match = _GDB_ARCH_RE.search(arch_output)
    if match is None:
        raise ValueError(f"Cannot parse GDB architecture output: {arch_output!r}")

    # Group 1 is the "currently ..." variant, group 2 is the direct variant.
    arch_str = match.group(1) or match.group(2)

    arch = _GDB_ARCH_MAP.get(arch_str)
    if arch is None:
        raise ValueError(f"Unknown GDB architecture: {arch_str!r}")
    return arch


_LLDB_ARCH_MAP = {
    "x86_64": ArchType.x86_64,
    "aarch64": ArchType.ARM64,
    "arm64": ArchType.ARM64,
    "arm": ArchType.ARM32,
    "i386": ArchType.x86,
    "i686": ArchType.x86,
}

_LLDB_OS_PATTERNS: list[tuple[re.Pattern[str], OSType]] = [
    (re.compile(r"apple-(?:macosx|darwin)"), OSType.macOS),
    (re.compile(r"apple-ios"), OSType.iOS),
    (re.compile(r"android"), OSType.Android),
    (re.compile(r"linux"), OSType.Linux),
    (re.compile(r"windows"), OSType.Windows),
]


def parse_lldb_triple(triple: str) -> tuple[OSType, ArchType]:
    """Parse an LLDB target triple into OS and architecture.

    Args:
        triple: A target triple such as ``"x86_64-apple-macosx15.0.0"``
            or ``"aarch64-unknown-linux-gnu"``.

    Returns:
        A ``(OSType, ArchType)`` tuple.

    Raises:
        ValueError: If the architecture or OS portion is not recognised.
    """
    parts = triple.split("-", 1)
    if len(parts) < 2:
        raise ValueError(f"Invalid LLDB triple (expected at least arch-os): {triple!r}")

    arch_str = parts[0]
    rest = parts[1]

    arch = _LLDB_ARCH_MAP.get(arch_str)
    if arch is None:
        raise ValueError(f"Unknown LLDB architecture in triple: {arch_str!r}")

    for pattern, os_type in _LLDB_OS_PATTERNS:
        if pattern.search(rest):
            return os_type, arch

    raise ValueError(f"Unknown OS in LLDB triple: {triple!r}")


_ANDROID_INDICATORS = re.compile(
    r"/system/lib|/data/app|dalvik|libart\.so"
)


def detect_os_from_maps(maps_content: str) -> OSType:
    """Heuristically detect OS from ``/proc/<pid>/maps`` content.

    Looks for Android-specific paths and libraries. If none are found the
    target is assumed to be plain Linux.

    Args:
        maps_content: The text content of the maps file.

    Returns:
        :attr:`OSType.Android` or :attr:`OSType.Linux`.
    """
    if _ANDROID_INDICATORS.search(maps_content):
        return OSType.Android
    return OSType.Linux


def parse_proc_maps(
    pid: int,
    logger: logging.Logger | None = None,
) -> list[MemoryRange]:
    """Parse ``/proc/<pid>/maps`` into a list of :class:`MemoryRange`.

    Each line in the maps file has the form::

        addr_lo-addr_hi perms offset dev inode [path]

    The *perms* field (e.g. ``rwxp``) is normalised to three characters
    by replacing the private/shared flag (``p``/``s``) with ``-``.

    Args:
        pid: Process ID whose maps file to read.
        logger: Optional logger for warning on I/O errors.

    Returns:
        A list of :class:`MemoryRange` instances, or an empty list if the
        maps file cannot be read.
    """
    log = logger or logging.getLogger(__name__)
    maps_path = f"/proc/{pid}/maps"
    ranges: list[MemoryRange] = []

    try:
        with open(maps_path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr_lo, addr_hi = parts[0].split("-")
                base = int(addr_lo, 16)
                end = int(addr_hi, 16)
                prot = parts[1].replace("p", "-").replace("s", "-")[:3]
                path = parts[5] if len(parts) > 5 else ""
                ranges.append(MemoryRange(base, end - base, prot, path))
    except FileNotFoundError:
        log.warning("Maps file not found: %s", maps_path)
    except PermissionError:
        log.warning("Permission denied reading: %s", maps_path)

    return ranges
