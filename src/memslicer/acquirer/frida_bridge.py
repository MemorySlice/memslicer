"""Frida-based DebuggerBridge implementation."""
from __future__ import annotations

import bisect
import logging
from typing import Any

from memslicer.acquirer.attach_preflight import (
    PreflightResult, enforce_attach_preflight,
)
from memslicer.acquirer.bridge import (
    MemoryRange, ModuleInfo, PlatformInfo, ReadResult,
    parse_fault_addr,
)
from memslicer.acquirer.errors import AttachError
from memslicer.acquirer.platform_detect import detect_platform, parse_maps_text


# Frida JS script for RPC exports
_FRIDA_SCRIPT = """\
rpc.exports = {
    enumerateRanges: function(prot) {
        return Process.enumerateRanges(prot);
    },
    readMemory: function(addr, size) {
        try {
            return ptr(addr).readByteArray(size);
        } catch (e) {
            return {
                __error: true, addr: addr, size: size,
                message: e.message || String(e), stack: e.stack || ''
            };
        }
    },
    readProcMaps: function() {
        if (Process.platform !== 'linux') return '';
        try {
            return File.readAllText('/proc/self/maps');
        } catch (e) {}
        try {
            // /proc/*/maps is a seq_file: a single read() can short-return,
            // so loop until exhausted.
            var f = new File('/proc/self/maps', 'r'), out = '', chunk;
            while ((chunk = f.read(65536)) && chunk.length > 0) out += chunk;
            f.close();
            return out;
        } catch (e) {
            return '';
        }
    },
    getPageSize: function() {
        return Process.pageSize;
    },
    enumerateModules: function() {
        return Process.enumerateModules();
    },
    getPlatform: function() {
        return Process.platform;
    },
    getArch: function() {
        return Process.arch;
    },
    getPid: function() {
        return Process.id;
    },
    validateApi: function() {
        var p = ptr(0);
        return {
            ptrType: typeof ptr,
            readByteArrayType: typeof p.readByteArray,
            pageSize: Process.pageSize
        };
    }
};
"""


def _parse_frida_addr(value: str | int) -> int:
    """Convert a Frida address (hex string or int) to int."""
    return int(value, 16) if isinstance(value, str) else value


def _ensure_bytes(data: Any) -> bytes:
    """Ensure data from Frida RPC is a bytes object."""
    return data if isinstance(data, bytes) else bytes(data)


class FridaBridge:
    """DebuggerBridge implementation using Frida."""

    def __init__(
        self,
        target: int | str,
        device: Any | None = None,
        read_timeout: float = 10.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self._target = target
        self._device = device
        self._read_timeout = read_timeout
        self._log = logger or logging.getLogger("memslicer")
        self._session: Any | None = None
        self._api: Any | None = None
        self._platform_info: PlatformInfo | None = None
        self._modules_cache: list[dict] | None = None
        # Lazily fetched (start, end, name) spans from the target's own maps;
        # None until the first enumerate_ranges() call.
        self._map_spans: list[tuple[int, int, str]] | None = None
        self._preflight: PreflightResult | None = None

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        if self._device is None:
            return False
        device_type = getattr(self._device, 'type', 'local')
        return device_type != 'local'

    def _on_message(self, message: dict, data: bytes | None) -> None:
        """Handle messages from the Frida JS agent."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "read-error":
                self._log.warning(
                    "JS read-error at %s size=%s: %s",
                    payload.get("addr", "?"),
                    payload.get("size", "?"),
                    payload.get("error", "unknown"),
                )
                stack = payload.get("stack", "")
                if stack:
                    self._log.debug("  JS stack: %s", stack)
        elif message.get("type") == "error":
            self._log.error(
                "Frida script error: %s", message.get("description", message),
            )

    def connect(self) -> None:
        """Attach to target process and load the Frida agent script."""
        import frida as _frida

        if self._device is None:
            self._device = _frida.get_local_device()

        if isinstance(self._target, int):
            self._log.info("Attaching to PID %d...", self._target)
        else:
            self._log.info("Attaching to process '%s'...", self._target)

        self._preflight = enforce_attach_preflight(
            self._target if isinstance(self._target, int) else None,
            is_remote=self.is_remote,
            logger=self._log,
        )

        try:
            session = self._device.attach(self._target)
        except Exception as e:
            raise AttachError(
                f"attach to {self._target} failed: {e}",
                probable_cause=self._preflight.probable_cause(),
                cause=e,
            ) from e
        self._session = session

        self._log.info("Loading agent script...")
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", self._on_message)
        script.load()
        self._api = script.exports_sync

        # Validate API
        api_check = self._api.validate_api()
        self._log.debug(
            "API check: ptr=%s readByteArray=%s pageSize=%s",
            api_check.get("ptrType"),
            api_check.get("readByteArrayType"),
            api_check.get("pageSize"),
        )

        # Resolve PID if attached by name
        pid = self._target if isinstance(self._target, int) else self._api.get_pid()

        # Detect platform
        self._log.info("Querying platform info...")
        frida_arch = self._api.get_arch()
        frida_platform = self._api.get_platform()
        self._modules_cache = self._api.enumerate_modules()
        modules_dicts = [{"name": m["name"], "path": m["path"]} for m in self._modules_cache]

        os_type, arch_type = detect_platform(
            frida_arch, frida_platform, modules_dicts,
        )

        page_size = self._api.get_page_size()
        self._log.debug(
            "platform=%s arch=%s pid=%d page_size=%d",
            frida_platform, frida_arch, pid, page_size,
        )

        self._platform_info = PlatformInfo(
            arch=arch_type,
            os=os_type,
            pid=pid,
            page_size=page_size,
        )

    def get_platform_info(self) -> PlatformInfo:
        """Return cached platform info from connect()."""
        if self._platform_info is None:
            raise RuntimeError("FridaBridge.connect() must be called first")
        return self._platform_info

    def _fetch_target_map_spans(self) -> list[tuple[int, int, str]]:
        """Return sorted ``(start, end, name)`` spans from the target's maps.

        Frida only reports a path for file-backed ranges, so pseudo-mappings
        such as ``[vvar]``, ``[heap]`` and ``[stack]`` are invisible to
        :meth:`enumerate_ranges`. The agent runs inside the target, so reading
        ``/proc/self/maps`` there recovers those names for local *and* remote
        devices without needing any host privilege.

        Returns:
            Named spans sorted by start address, or ``[]`` when unavailable.
        """
        fetch = getattr(self._api, "read_proc_maps", None)
        if fetch is None:
            return []
        try:
            text = fetch()
        except Exception as e:
            self._log.debug("readProcMaps RPC failed: %s", e)
            return []
        if not isinstance(text, str) or not text:
            return []
        return sorted(
            (r.base, r.base + r.size, r.file_path)
            for r in parse_maps_text(text) if r.file_path
        )

    def _lookup_map_name(self, base: int) -> str:
        """Return the maps name of the span containing *base*, or ``""``."""
        spans = self._map_spans
        if not spans:
            return ""
        idx = bisect.bisect_right(spans, base, key=lambda span: span[0]) - 1
        if idx < 0:
            return ""
        start, end, name = spans[idx]
        return name if start <= base < end else ""

    def enumerate_ranges(self) -> list[MemoryRange]:
        """Enumerate all memory ranges via Frida RPC."""
        if self._map_spans is None:
            self._map_spans = self._fetch_target_map_spans()

        raw = self._api.enumerate_ranges("---")
        ranges: list[MemoryRange] = []
        named = 0
        for r in raw:
            file_info = r.get("file")
            file_path = file_info.get("path", "") if file_info else ""
            base = _parse_frida_addr(r["base"])
            if not file_path:
                file_path = self._lookup_map_name(base)
                if file_path:
                    named += 1
            ranges.append(MemoryRange(
                base=base,
                size=r["size"],
                protection=r["protection"],
                file_path=file_path,
            ))
        if named:
            self._log.debug(
                "maps enrichment: named %d/%d ranges", named, len(ranges),
            )
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """Return loaded modules (cached from connect() if available)."""
        raw = self._modules_cache if self._modules_cache is not None else self._api.enumerate_modules()
        return [
            ModuleInfo(
                name=m["name"],
                path=m["path"],
                base=_parse_frida_addr(m["base"]),
                size=m["size"],
            )
            for m in raw
        ]

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        """Read memory via Frida RPC, reporting the fault address on failure.

        The agent returns either an ArrayBuffer (marshalled as ``bytes``) or an
        error descriptor (marshalled as ``dict``), so the two cases are
        unambiguous without out-of-band messages.

        Args:
            address: Address to read from.
            size: Number of bytes to read.

        Returns:
            A :class:`ReadResult` carrying the data or the failure detail.
        """
        try:
            data = self._api.read_memory(hex(address), size)
        except Exception as e:
            self._log.debug(
                "Read exception at 0x%x size=%d: %s", address, size, e,
            )
            return ReadResult(data=None, error=str(e))

        if isinstance(data, dict) and data.get("__error"):
            message = str(data.get("message", "unknown"))
            self._log.debug(
                "Read failed at 0x%x size=%d: %s", address, size, message,
            )
            return ReadResult(
                data=None,
                # Frida reports a real CPU fault address, so it is trusted even
                # when it equals the address asked for: that means the first
                # page of the span is the dead one.
                fault_addr=parse_fault_addr(message),
                error=message,
            )
        if data is None:
            return ReadResult(data=None)
        return ReadResult(data=_ensure_bytes(data))

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory via Frida RPC. Returns None on failure."""
        return self.read_memory_ex(address, size).data

    def disconnect(self) -> None:
        """Detach the Frida session."""
        self._map_spans = None
        session = self._session
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
            self._session = None
