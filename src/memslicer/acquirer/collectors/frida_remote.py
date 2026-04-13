"""Frida remote investigation collector.

Executes JavaScript on the target device via Frida RPC to collect
investigation data. Used for Android (USB/ADB) and iOS (USB) targets
where the host machine differs from the target device.
"""
from __future__ import annotations

import logging
from importlib import resources
from typing import Any

from memslicer.acquirer.collectors.addr_utils import (
    decode_network_order_addr,
    decode_proc_net_addr,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry


# The Frida JS script extension for investigation data collection.
# The JS source is split across resource files in the sibling ``js`` package
# (a refactor seam for P1.4b per-platform enrichment). The concatenation order
# matters: ``common.js`` defines the symbols the later files reference.
_JS_FILES: tuple[str, ...] = (
    "common.js",         # constants + W() + maybeLoadModule + native func loaders
    "darwin_sysctl.js",  # sysctlStr/sysctlU64/sysctlInt (depends on nothing)
    "darwin_native.js",  # darwinReadSockAddr etc. (uses common.js)
    "proc_helpers.js",   # readlinkStr, parseNetFile (uses common.js)
    "windows.js",        # winReg, winGetVersion, windowsGetSystemInfo
    "android.js",        # androidGetProp, androidGetSystemInfo
    "ios.js",            # iosGetSystemInfo (uses darwin_sysctl.js)
    "rpc_exports.js",    # dispatcher - must be last
)


def _load_investigation_script() -> str:
    """Concatenate the per-file JS resources into a single Frida script.

    Uses ``importlib.resources`` so the loader works for both editable and
    wheel installs without any extra package-data configuration (hatchling
    bundles all files under the package by default).
    """
    pkg = resources.files("memslicer.acquirer.collectors.js")
    parts: list[str] = []
    for name in _JS_FILES:
        parts.append(pkg.joinpath(name).read_text(encoding="utf-8"))
    return "\n".join(parts)


INVESTIGATION_SCRIPT = _load_investigation_script()


class FridaRemoteCollector:
    """Investigation collector using Frida RPC for remote targets.

    Executes JavaScript on the target device to collect system
    information that cannot be gathered from the host.
    """

    _is_memslicer_collector = True

    def __init__(
        self,
        session: Any,
        logger: logging.Logger | None = None,
    ) -> None:
        self._session = session
        self._log = logger or logging.getLogger("memslicer")
        self._api: Any | None = None

    def connect(self) -> None:
        """Load the investigation script and obtain RPC exports."""
        script = self._session.create_script(INVESTIGATION_SCRIPT)
        script.on("message", self._on_message)
        script.load()
        self._api = script.exports_sync
        self._log.info("Investigation script loaded on target")

    def _on_message(self, message: dict, data: Any) -> None:
        if message.get("type") == "error":
            self._log.warning("Investigation script error: %s", message.get("description"))

    def _unwrap(self, response: Any, op: str) -> tuple[Any, list[str]]:
        """Extract (data, warnings) from an RPC response.

        The P1.4b RPC contract wraps every export return value in
        ``{"data": <value>, "warnings": [<str>, ...]}``. This helper
        tolerates the legacy flat shape for backward compatibility with
        any in-flight agents - if the response lacks both keys, it
        treats the whole response as data and produces an empty
        warnings list.
        """
        if (
            isinstance(response, dict)
            and "data" in response
            and "warnings" in response
        ):
            warnings = response.get("warnings") or []
            return response["data"], list(warnings)
        return response, []

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity via Frida RPC on target."""
        if self._api is None:
            return TargetProcessInfo()

        try:
            raw = self._api.get_process_info(pid)
        except Exception as exc:
            self._log.warning("Frida getProcessInfo failed: %s", exc)
            return TargetProcessInfo()

        data, warnings = self._unwrap(raw, "getProcessInfo")
        if not isinstance(data, dict):
            return TargetProcessInfo()

        for w in warnings:
            self._log.warning("Frida getProcessInfo warning: %s", w)

        return TargetProcessInfo(
            ppid=data.get("ppid", 0),
            session_id=data.get("sessionId", 0),
            start_time_ns=data.get("startTimeNs", 0),
            exe_path=data.get("exePath", ""),
            cmd_line=data.get("cmdLine", ""),
            process_name=data.get("processName", ""),
            package=data.get("package", ""),
        )

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info via Frida RPC on target."""
        if self._api is None:
            return TargetSystemInfo()

        try:
            raw = self._api.get_system_info()
        except Exception as exc:
            self._log.warning("Frida getSystemInfo failed: %s", exc)
            return TargetSystemInfo()

        data, warnings = self._unwrap(raw, "getSystemInfo")
        if not isinstance(data, dict):
            return TargetSystemInfo()

        info = TargetSystemInfo(
            boot_time=data.get("bootTime", 0),
            hostname=data.get("hostname", ""),
            domain=data.get("domain", ""),
            os_detail=data.get("osDetail", ""),
            kernel=data.get("kernel", ""),
            arch=data.get("arch", ""),
            distro=data.get("distro", ""),
            machine_id=data.get("machineId", ""),
            hw_vendor=data.get("hwVendor", ""),
            hw_model=data.get("hwModel", ""),
            cpu_brand=data.get("cpuBrand", ""),
            ram_bytes=data.get("ramBytes", 0),
            fingerprint=data.get("fingerprint", ""),
            patch_level=data.get("patchLevel", ""),
            verified_boot=data.get("verifiedBoot", ""),
            bootloader_locked=data.get("bootloaderLocked", ""),
            dm_verity=data.get("dmVerity", ""),
            build_type=data.get("buildType", ""),
            crypto_type=data.get("cryptoType", ""),
            env=data.get("env", ""),
        )
        info.collector_warnings = list(warnings)
        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Collect process table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw = self._api.get_process_table(target_pid)
        except Exception as exc:
            self._log.warning("Frida getProcessTable failed: %s", exc)
            return []

        data, warnings = self._unwrap(raw, "getProcessTable")
        for w in warnings:
            self._log.warning("Frida getProcessTable warning: %s", w)
        if not isinstance(data, list):
            return []

        return [
            ProcessEntry(
                pid=e.get("pid", 0),
                ppid=e.get("ppid", 0),
                uid=e.get("uid", 0),
                is_target=e.get("isTarget", False),
                start_time=e.get("startTime", 0),
                rss=e.get("rss", 0),
                exe_name=e.get("exeName", ""),
                cmd_line=e.get("cmdLine", ""),
                user=e.get("user", ""),
            )
            for e in data
        ]

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Collect connection table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw = self._api.get_connection_table()
        except Exception as exc:
            self._log.warning("Frida getConnectionTable failed: %s", exc)
            return []

        data, warnings = self._unwrap(raw, "getConnectionTable")
        for w in warnings:
            self._log.warning("Frida getConnectionTable warning: %s", w)
        if not isinstance(data, list):
            return []

        return [self._parse_connection_entry(e) for e in data]

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Collect handle table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw = self._api.get_handle_table(pid)
        except Exception as exc:
            self._log.warning("Frida getHandleTable failed: %s", exc)
            return []

        data, warnings = self._unwrap(raw, "getHandleTable")
        for w in warnings:
            self._log.warning("Frida getHandleTable warning: %s", w)
        if not isinstance(data, list):
            return []

        return [
            HandleEntry(
                pid=e.get("pid", pid),
                fd=e.get("fd", 0),
                handle_type=e.get("handleType", 0),
                path=e.get("path", ""),
            )
            for e in data
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_connection_entry(self, e: dict) -> ConnectionEntry:
        """Parse a single JS connection entry dict into ConnectionEntry."""
        family = e.get("family", 0x02)
        is_ipv6 = family == 0x0A
        network_order = e.get("_networkOrder", False)
        decode = decode_network_order_addr if network_order else decode_proc_net_addr
        return ConnectionEntry(
            pid=e.get("pid", 0),
            family=family,
            protocol=e.get("protocol", 0x06),
            state=e.get("state", 0),
            local_addr=decode(e.get("localAddr", ""), is_ipv6),
            local_port=e.get("localPort", 0),
            remote_addr=decode(e.get("remoteAddr", ""), is_ipv6),
            remote_port=e.get("remotePort", 0),
        )

    # Legacy static method aliases for backward compatibility with tests
    _decode_darwin_addr = staticmethod(decode_network_order_addr)
    _decode_proc_net_addr = staticmethod(decode_proc_net_addr)
