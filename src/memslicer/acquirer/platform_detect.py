"""OS and architecture detection via Frida script API."""
from __future__ import annotations

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
