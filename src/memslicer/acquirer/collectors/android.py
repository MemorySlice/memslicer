"""Android-specific investigation collector.

Extends :class:`LinuxCollector` with SELinux-aware fallbacks and
Android system property collection for OS detail enrichment.

P1.2 adds structured enrichment (patch level, verified boot state,
bootloader lock, dm-verity, build type, crypto type, environment and
advisory root detection) on top of the existing getprop collection.
"""
from __future__ import annotations

import glob
import hashlib
import logging
import os
import subprocess

from memslicer.acquirer.collectors.linux import LinuxCollector
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo


# Android system properties used for OS detail and enrichment.
# The filter in ``_read_system_properties`` uses this tuple as an
# allow-list so we never retain properties the collector does not know
# how to interpret.
_ANDROID_PROPS = (
    # Build / version
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.fingerprint",
    "ro.build.display.id",
    "ro.build.type",
    "ro.build.tags",
    # Product / hardware
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.cpu.abi",
    "ro.hardware",
    # Boot / verified boot
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.veritymode",
    "ro.boot.bootloader",
    # Crypto
    "ro.crypto.type",
    "ro.crypto.state",
    # Treble / misc
    "ro.treble.enabled",
    "persist.sys.timezone",
    # Emulator markers
    "ro.kernel.qemu",
    "ro.boot.qemu",
    # Serials (privacy-class)
    "ro.boot.serialno",
    "ro.serialno",
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
        # Root-detection probe paths. Exposed as an instance attribute so
        # tests can redirect to a tmp tree without monkey-patching module
        # globals.
        self._root_paths: dict[str, list[str]] = {
            "kernelsu": ["/data/adb/ksu", "/data/adb/ksud"],
            "apatch": ["/data/adb/ap"],
            "zygisk": ["/data/adb/modules/zygisk_*"],  # glob
            "magisk_hide": ["/debug_ramdisk/.magisk"],
            "magisk": [
                "/sbin/.magisk",
                "/system/bin/.magisk",
                "/data/adb/magisk",
            ],
        }
        # SELinux sysfs probe path (overridable for tests).
        self._selinux_enforce_path: str = "/sys/fs/selinux/enforce"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity with SELinux-aware fallbacks.

        On Android, ``/proc/<pid>/exe`` is frequently unreadable due to
        SELinux policy. Historical behavior stuffed ``argv[0]`` into
        ``exe_path`` — but on Android that is a **package process name**
        (e.g. ``com.whatsapp:pushservice``), not a filesystem path.

        This method now splits the two concerns: ``process_name`` and
        ``package`` carry the package identity, while ``exe_path`` is
        set to the canonical ``app_process64`` path so analysts always
        have a real binary to consult.
        """
        info = super().collect_process_identity(pid)

        if not info.exe_path and info.cmd_line:
            parts = info.cmd_line.split()
            if parts:
                argv0 = parts[0]
                info.process_name = argv0
                info.package = argv0.split(":", 1)[0]
                # On Android, app processes are all forked from
                # app_process64 (or app_process32 on legacy 32-bit
                # devices). Record the canonical 64-bit path so
                # downstream consumers always have a real binary path
                # even when /proc/<pid>/exe is SELinux-blocked.
                info.exe_path = "/system/bin/app_process64"
                self._log.debug(
                    "exe_path fallback: process_name=%s package=%s exe=%s",
                    info.process_name, info.package, info.exe_path,
                )

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info with Android system properties + enrichment."""
        info = super().collect_system_info()
        props = self._read_system_properties()

        # --- Build / version ---
        release = props.get("ro.build.version.release", "")
        sdk = props.get("ro.build.version.sdk", "")
        if release:
            info.distro = (
                f"Android {release}" + (f" (API {sdk})" if sdk else "")
            )
        if release and not info.kernel:
            info.kernel = release

        # --- Hardware identity ---
        manufacturer = props.get("ro.product.manufacturer", "")
        model = props.get("ro.product.model", "")
        abi = props.get("ro.product.cpu.abi", "")
        if manufacturer:
            info.hw_vendor = manufacturer
        if model:
            info.hw_model = model
        if abi:
            info.arch = abi

        # --- Fingerprint (privacy-gated at projection time) ---
        info.fingerprint = props.get("ro.build.fingerprint", "")

        # --- Android enrichment fields ---
        info.patch_level = props.get("ro.build.version.security_patch", "")
        info.verified_boot = props.get("ro.boot.verifiedbootstate", "")
        info.bootloader_locked = self._map_flash_locked(
            props.get("ro.boot.flash.locked", "")
        )
        info.dm_verity = props.get("ro.boot.veritymode", "")
        info.build_type = props.get("ro.build.type", "")
        info.crypto_type = props.get("ro.crypto.type", "")

        tz = props.get("persist.sys.timezone", "")
        if tz:
            info.timezone = tz

        # --- SELinux: primary sysfs, fallback getenforce ---
        info.selinux = self._read_selinux_mode()

        # --- Environment detection ---
        info.env = self._detect_android_env(props)

        # --- Root detection (advisory) ---
        info.root_method = self._detect_root_methods()

        # --- Machine ID: boot/serialno if present, weak hash otherwise ---
        info.machine_id = self._derive_machine_id(props, info.fingerprint, info.hw_model)

        # --- Compose human os_detail (projector composes the full
        # microformat at pack time). Only override the Linux-derived
        # os_detail when getprop actually yielded an Android distro
        # string — otherwise the parent's composition (from /etc/os-release
        # or kernel/arch) is a better fallback than raw_os.
        android_os_detail = self._compose_android_os_detail(props, info)
        if android_os_detail and info.distro:
            info.os_detail = android_os_detail

        if info.hostname == "localhost":
            self._log.debug("Android hostname is 'localhost' (typical)")

        return info

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_system_properties(self) -> dict[str, str]:
        """Read Android system properties via a single ``getprop`` call."""
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

    def _read_selinux_mode(self) -> str:
        """Return SELinux enforcement mode.

        Tries ``/sys/fs/selinux/enforce`` first (``"1"``→``"enforcing"``,
        ``"0"``→``"permissive"``). On ENOENT / read failure, falls back
        to ``getenforce``. Returns ``""`` if neither source is usable.
        """
        try:
            with open(self._selinux_enforce_path, "r", encoding="ascii") as fh:
                raw = fh.read().strip()
            if raw == "1":
                return "enforcing"
            if raw == "0":
                return "permissive"
        except FileNotFoundError:
            # Not mounted → SELinux not present at all.
            pass
        except OSError as exc:
            self._log.debug("selinux sysfs read failed: %s", exc)

        try:
            result = subprocess.run(
                ["getenforce"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return self._map_getenforce(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self._log.debug("getenforce failed: %s", exc)

        return ""

    @staticmethod
    def _map_getenforce(stdout: str) -> str:
        token = stdout.strip().lower()
        if token == "enforcing":
            return "enforcing"
        if token == "permissive":
            return "permissive"
        if token == "disabled":
            return "disabled"
        return ""

    @staticmethod
    def _detect_android_env(props: dict[str, str]) -> str:
        """Classify the Android environment from getprop hints.

        Priority:
          1. ``ro.kernel.qemu`` / ``ro.boot.qemu`` == ``"1"`` → emulator
          2. Cuttlefish model/hardware markers
          3. Android SDK / sdk_gphone markers → emulator
          4. VirtualBox hardware (Genymotion)
          5. Waydroid manufacturer
          6. Default: physical
        """
        if props.get("ro.kernel.qemu") == "1" or props.get("ro.boot.qemu") == "1":
            return "emulator"

        model = props.get("ro.product.model", "")
        hardware = props.get("ro.hardware", "")
        manufacturer = props.get("ro.product.manufacturer", "")

        if "Cuttlefish" in model or "cutf" in hardware:
            return "cuttlefish"
        if "sdk_gphone" in model or "Android SDK" in model:
            return "emulator"
        if "vbox" in hardware:
            return "genymotion"
        if "Waydroid" in manufacturer:
            return "waydroid"

        return "physical"

    def _detect_root_methods(self) -> str:
        """Probe well-known root indicator paths (advisory only).

        Returns a comma-separated list of detected markers (e.g.
        ``"kernelsu,zygisk"``) or ``""`` if nothing is found. This is
        advisory: the presence of any marker implies the operator
        should not trust runtime integrity.
        """
        found: list[str] = []
        for name, paths in self._root_paths.items():
            for path in paths:
                if "*" in path:
                    if glob.glob(path):
                        found.append(name)
                        break
                elif os.path.exists(path):
                    found.append(name)
                    break
        return ",".join(found)

    def _derive_machine_id(
        self, props: dict[str, str], fingerprint: str, hw_model: str,
    ) -> str:
        """Compute a best-effort stable machine ID.

        Prefers ``ro.boot.serialno`` → ``ro.serialno``. Falls back to a
        short SHA-256 of ``fingerprint + hw_model`` tagged ``weak:`` so
        downstream consumers can tell it is not an OEM identifier.
        Privacy-gating (``--include-serials``) is applied later at the
        projector stage.
        """
        for key, marker in (
            ("ro.boot.serialno", "boot_serialno"),
            ("ro.serialno", "serialno"),
        ):
            val = props.get(key, "")
            if val and val.lower() != "unknown":
                return f"{marker}:{val}"

        if fingerprint or hw_model:
            digest = hashlib.sha256(
                f"{fingerprint}|{hw_model}".encode("utf-8")
            ).hexdigest()[:16]
            return f"weak:{digest}"

        return ""

    @staticmethod
    def _map_flash_locked(value: str) -> str:
        if value == "1":
            return "1"
        if value == "0":
            return "0"
        return ""

    def _compose_android_os_detail(
        self, props: dict[str, str], info: TargetSystemInfo,
    ) -> str:
        """Compose a short human-readable os_detail string.

        Reuses Linux's ``_compose_os_detail`` when distro+kernel+arch
        are known; otherwise falls back to ``raw_os``. We deliberately
        do NOT stuff the fingerprint here — the projector handles
        ``include_fingerprint`` gating at pack time.
        """
        if info.distro:
            return self._compose_os_detail(info.distro, info.kernel, info.arch)
        return info.raw_os or ""
