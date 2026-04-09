"""iOS-specific investigation collector.

Extends DarwinCollector with sandbox-aware fallbacks and iOS
identification via SystemVersion.plist.
"""
from __future__ import annotations

import logging
import plistlib
import re

from memslicer.acquirer.collectors.darwin import DarwinCollector
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry


class IOSCollector(DarwinCollector):
    """Investigation collector for iOS targets.

    iOS is Darwin-based but has heavy sandboxing. Commands like
    ps, lsof, and sw_vers may not be available on stock iOS.
    Jailbroken devices have broader access.
    """

    _is_memslicer_collector = True

    _SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist"

    def __init__(self, logger: logging.Logger | None = None) -> None:
        super().__init__(logger=logger)

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity with sandbox-aware fallbacks.

        On stock iOS, ps may not be available. Falls back to
        sysctl where possible.
        """
        info = super().collect_process_identity(pid)

        # If ps failed (stock iOS), try sysctl for basic info
        if not info.exe_path:
            sysctl_out = self._run_cmd([
                "sysctl", "-n", f"kern.proc.pid.{pid}",
            ])
            if sysctl_out:
                self._log.debug("Using sysctl fallback for pid %d", pid)

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info with iOS-specific OS detail."""
        info = super().collect_system_info()

        # Override os_detail with iOS-specific info from SystemVersion.plist
        ios_detail = self._read_system_version_plist()
        if ios_detail:
            info.os_detail = ios_detail

        # Append device model from hw.machine
        model = self._read_device_model()
        if model and info.os_detail:
            info.os_detail = f"{info.os_detail} ({model})"
        elif model:
            info.os_detail = f"iOS ({model})"

        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate processes. May be limited by sandbox."""
        entries = super().collect_process_table(target_pid)
        if not entries:
            self._log.warning(
                "Process table empty on iOS — likely sandbox restriction. "
                "Jailbroken device required for full process list."
            )
        return entries

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate connections. May be limited by sandbox."""
        entries = super().collect_connection_table()
        if not entries:
            self._log.warning(
                "Connection table empty on iOS — lsof may not be available. "
                "Jailbroken device required for network enumeration."
            )
        return entries

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate handles. May be limited by sandbox."""
        entries = super().collect_handle_table(pid)
        if not entries:
            self._log.warning(
                "Handle table empty on iOS — lsof may not be available. "
                "Jailbroken device required for handle enumeration."
            )
        return entries

    # ------------------------------------------------------------------
    # Private: iOS-specific helpers
    # ------------------------------------------------------------------

    def _read_system_version_plist(self) -> str:
        """Read iOS version from SystemVersion.plist."""
        try:
            with open(self._SYSTEM_VERSION_PLIST, "rb") as fh:
                plist = plistlib.load(fh)

            product_name = plist.get("ProductName", "iOS")
            product_version = plist.get("ProductVersion", "")
            build_version = plist.get("ProductBuildVersion", "")

            parts = [product_name]
            if product_version:
                parts.append(product_version)
            if build_version:
                parts.append(f"({build_version})")

            return " ".join(parts)
        except (OSError, plistlib.InvalidFileException) as exc:
            self._log.debug(
                "Cannot read SystemVersion.plist: %s", exc
            )
            return ""

    def _read_device_model(self) -> str:
        """Read device model identifier via sysctl hw.machine."""
        out = self._run_cmd(["sysctl", "-n", "hw.machine"])
        return out.strip() if out else ""
