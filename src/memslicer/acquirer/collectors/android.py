"""Android-specific investigation collector.

Extends LinuxCollector with SELinux-aware fallbacks and Android
system property collection for OS detail enrichment.
"""
from __future__ import annotations

import logging
import subprocess

from memslicer.acquirer.collectors.linux import LinuxCollector
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo


# Android system properties used for OS detail
_ANDROID_PROPS = (
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.fingerprint",
    "ro.product.model",
    "ro.product.manufacturer",
)


class AndroidCollector(LinuxCollector):
    """Investigation collector for Android targets.

    Android is Linux-based but has SELinux restrictions on /proc
    and provides system properties for device/OS identification.
    """

    _is_memslicer_collector = True

    def __init__(
        self,
        proc_root: str = "/proc",
        is_remote: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        super().__init__(proc_root=proc_root, logger=logger)
        self._is_remote = is_remote

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity with SELinux-aware fallbacks."""
        info = super().collect_process_identity(pid)

        # On Android, /proc/<pid>/exe readlink often fails due to SELinux.
        # Fall back to argv[0] from cmdline.
        if not info.exe_path and info.cmd_line:
            parts = info.cmd_line.split()
            if parts:
                info.exe_path = parts[0]
                self._log.debug(
                    "exe_path fallback to cmdline argv[0]: %s", info.exe_path
                )

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info with Android system properties."""
        info = super().collect_system_info()

        # Override os_detail with rich Android info
        props = self._read_system_properties()
        if props:
            release = props.get("ro.build.version.release", "")
            sdk = props.get("ro.build.version.sdk", "")
            manufacturer = props.get("ro.product.manufacturer", "")
            model = props.get("ro.product.model", "")
            fingerprint = props.get("ro.build.fingerprint", "")

            parts = []
            if release:
                parts.append(f"Android {release}")
            if sdk:
                parts.append(f"(API {sdk})")
            if manufacturer:
                parts.append(manufacturer)
            if model:
                parts.append(model)
            if fingerprint:
                parts.append(f"[{fingerprint}]")

            if parts:
                info.os_detail = " ".join(parts)

        # Android hostname is often "localhost" — keep it but log
        if info.hostname == "localhost":
            self._log.debug("Android hostname is 'localhost' (typical)")

        return info

    def _read_system_properties(self) -> dict[str, str]:
        """Read Android system properties via single getprop call."""
        try:
            result = subprocess.run(
                ["getprop"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return {}
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self._log.debug("getprop failed: %s", exc)
            return {}

        # Parse "[key]: [value]" lines
        props: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if not line.startswith("["):
                continue
            bracket_end = line.find("]")
            if bracket_end == -1:
                continue
            key = line[1:bracket_end]
            if key not in _ANDROID_PROPS:
                continue
            val_start = line.find("[", bracket_end + 1)
            val_end = line.rfind("]")
            if val_start != -1 and val_end > val_start:
                props[key] = line[val_start + 1:val_end]

        return props
