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
from memslicer.msl.types import (
    ConnectionEntry, HandleEntry, ProcessEntry, ConnectivityTable,
    KernelModuleList, PersistenceManifest,
)


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
        # Jailbreak detection markers: method -> tuple of filesystem paths
        # that, if present, indicate that method's installer has run.
        # Instance attribute so tests can redirect to a tmp_path fixture
        # without patching os.path.exists.
        self._jailbreak_markers: dict[str, tuple[str, ...]] = {
            # Rootless jailbreaks (iOS 15+). /var/jb/ is the canonical
            # marker used by Dopamine, palera1n, XinaA15.
            "dopamine":  ("/var/jb/",),
            "palera1n":  ("/binpack/", "/.bootstrapped_palera1n"),
            "serotonin": ("/var/jb/usr/lib/libellekit.dylib",),
            # Legacy rooted jailbreaks (pre-iOS 15).
            "substrate": ("/Library/MobileSubstrate/",),
            "checkra1n": ("/.checkra1n",),
        }
        # Roothide enumerates a glob pattern rather than a fixed path.
        self._roothide_glob: str = "/var/containers/Bundle/Application/.jbroot-*"

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        """Collect process identity with sandbox-aware fallbacks.

        On stock iOS, ps may not be available. Falls back to
        sysctl where possible. P1.6.3 kwargs are forwarded to the
        Darwin base class; that base ignores them.
        """
        info = super().collect_process_identity(
            pid,
            include_target_introspection=include_target_introspection,
            include_environ=include_environ,
        )

        # If ps failed (stock iOS), try sysctl for basic info
        if not info.exe_path:
            sysctl_out = self._run_cmd([
                "sysctl", "-n", f"kern.proc.pid.{pid}",
            ])
            if sysctl_out:
                self._log.debug("Using sysctl fallback for pid %d", pid)

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info with iOS-specific enrichment.

        Layered on Darwin's base collection:
          * Remap ``hw.machine`` (board ID on iOS) from arch -> hw_model.
          * Supplement distro from ``kern.osproductversion`` / ``kern.osversion``.
          * Populate ``boot_id`` from ``kern.bootsessionuuid``.
          * Prefer SystemVersion.plist when readable.
          * Probe for jailbreak markers to populate ``env`` / ``root_method``.
        """
        info = super().collect_system_info()

        # On iOS, hw.machine is a board ID like "iPhone16,2", not an arch.
        # Darwin's super() stored it in info.arch — remap to hw_model and
        # correct arch to "arm64" (all modern iOS devices are arm64).
        board_id = info.arch
        if board_id and board_id.startswith(
            ("iPhone", "iPad", "iPod", "Watch", "AppleTV")
        ):
            info.hw_model = board_id
            info.arch = "arm64"

        # Supplement with kern.osversion (build, e.g. "21E219") and
        # kern.osproductversion (semantic, e.g. "17.4"). These are the
        # same values SystemVersion.plist carries but readable without
        # the plist, so they give a fallback distro on sandboxed iOS.
        build_ver = self._read_sysctl("kern.osversion")
        prod_ver = self._read_sysctl("kern.osproductversion")

        # Boot session UUID: per-boot identifier that anchors the slice
        # even if two reboots happen to report the same wall-clock boot
        # time (rare, but observable on fast successive reboots).
        boot_session = self._read_sysctl("kern.bootsessionuuid")
        if boot_session:
            info.boot_id = boot_session

        # Compose a distro string from sysctl as a fallback. The plist
        # supplement below can override this with authoritative content.
        if prod_ver:
            info.distro = f"iOS {prod_ver}" + (
                f" ({build_ver})" if build_ver else ""
            )

        # Read the plist if accessible — it's authoritative when available.
        plist_detail = self._read_system_version_plist()
        if plist_detail:
            info.os_detail = plist_detail
        elif info.distro:
            info.os_detail = info.distro

        # Append the device model in parentheses (preserves existing
        # behavior tested by TestCollectSystemInfoIOS).
        if info.hw_model and info.os_detail and info.hw_model not in info.os_detail:
            info.os_detail = f"{info.os_detail} ({info.hw_model})"
        elif info.hw_model and not info.os_detail:
            info.os_detail = f"iOS ({info.hw_model})"

        # Jailbreak / environment detection (filesystem marker probe).
        jb = self._detect_jailbreak()
        if jb:
            info.env = "jailbroken"
            info.root_method = jb
        else:
            info.env = "stock"

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

    def collect_connectivity_table(self) -> ConnectivityTable:
        """Not implemented on iOS -- returns empty ConnectivityTable."""
        return ConnectivityTable()

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Not implemented on iOS -- returns empty KernelModuleList."""
        return KernelModuleList()

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Not implemented on iOS -- returns empty PersistenceManifest."""
        return PersistenceManifest()

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

    def _detect_jailbreak(self) -> str:
        """Probe filesystem for jailbreak markers.

        Returns a comma-separated list of detected methods (advisory),
        or an empty string when no markers are found. Uses instance
        attributes ``_jailbreak_markers`` and ``_roothide_glob`` so tests
        can redirect to tmp_path-based fixtures without patching globals.
        """
        import glob
        import os as _os

        detected: list[str] = []
        for method, paths in self._jailbreak_markers.items():
            for path in paths:
                try:
                    if _os.path.exists(path):
                        detected.append(method)
                        break
                except OSError:
                    continue

        # Roothide uses a per-install glob pattern rather than a fixed path.
        try:
            if glob.glob(self._roothide_glob):
                detected.append("roothide")
        except OSError:
            pass

        return ",".join(detected)
