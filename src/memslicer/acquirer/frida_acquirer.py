"""Frida-based memory acquisition engine."""
from __future__ import annotations
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

import frida

from memslicer.acquirer.base import AcquireResult, BaseAcquirer
from memslicer.acquirer.platform_detect import detect_platform
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    CompAlgo, OSType, PageState, RegionType, CapBit,
    Endianness, VERSION, HASH_SIZE,
)
from memslicer.msl.types import FileHeader, MemoryRegion, ModuleEntry
from memslicer.msl.writer import MSLWriter
from memslicer.utils.protection import (
    PROT_R, PROT_W, PROT_X, format_protection, is_rwx, parse_protection,
)
from memslicer.utils.timestamps import now_ns


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
            send({type: 'read-error', addr: addr, size: size, error: e.message, stack: e.stack || ''});
            return null;
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

# Default max chunk size for splitting large regions (same as fridump)
_DEFAULT_MAX_CHUNK = 20971520  # 20 MB


def _parse_frida_addr(value: str | int) -> int:
    """Convert a Frida address (hex string or int) to int."""
    return int(value, 16) if isinstance(value, str) else value


def _ensure_bytes(data) -> bytes:
    """Ensure data from Frida RPC is a bytes object."""
    return data if isinstance(data, bytes) else bytes(data)


def _classify_region(file_info: dict | None) -> RegionType:
    """Classify a memory region based on Frida's file mapping info."""
    if file_info is None:
        return RegionType.Anon
    path = file_info.get("path", "")
    if not path:
        return RegionType.Anon
    if "[heap]" in path:
        return RegionType.Heap
    if "[stack]" in path:
        return RegionType.Stack
    if path.endswith((".so", ".dylib", ".dll", ".exe")):
        return RegionType.Image
    if "/" in path or "\\" in path:
        return RegionType.MappedFile
    return RegionType.Unknown


def _volatility_key(r: dict) -> tuple[int, int]:
    """Return sort key for volatility-first ordering.

    Priority (most volatile first):
      0 – rw- Anon/Heap/Stack (live runtime state)
      1 – rwx regions (JIT code, changes rapidly)
      2 – r-x Image (executable code, stable)
      3 – r-- MappedFile/Image (disk-backed, lowest priority)
      4 – everything else
    Secondary sort by base address for determinism.
    """
    prot = parse_protection(r["protection"])
    region_type = _classify_region(r.get("file"))
    base = _parse_frida_addr(r["base"])

    has_r = prot & PROT_R
    has_w = prot & PROT_W
    has_x = prot & PROT_X

    if has_r and has_w and not has_x:  # rw-
        if region_type in (RegionType.Anon, RegionType.Heap, RegionType.Stack):
            return (0, base)
    if is_rwx(prot):  # rwx
        return (1, base)
    if has_r and has_x and not has_w:  # r-x
        return (2, base)
    if has_r and not has_w and not has_x:  # r--
        return (3, base)
    return (4, base)


# Progress callback signature:
#   (regions_captured, total_ranges, bytes_captured, modules_captured, regions_processed)
ProgressCallback = Callable[[int, int, int, int, int], None]


class FridaAcquirer(BaseAcquirer):
    """Acquires process memory using Frida and writes MSL files.

    Memory reading strategy (matching fridump's proven approach):
    - Try full region read via direct Frida RPC call
    - If region is too large (> max_chunk_size), split into fixed-size chunks
    - On read failure for a chunk, skip it (mark pages FAILED)
    - All RPC calls happen on the main thread (Frida requirement)
    """

    def __init__(
        self,
        target: int | str,
        device: frida.core.Device | None = None,
        comp_algo: CompAlgo = CompAlgo.NONE,
        region_filter: RegionFilter | None = None,
        os_override: OSType | None = None,
        logger: logging.Logger | None = None,
        read_timeout: float = 10.0,
        max_chunk_size: int = _DEFAULT_MAX_CHUNK,
    ) -> None:
        self._target = target
        self._device = device or frida.get_local_device()
        self._comp_algo = comp_algo
        self._filter = region_filter or RegionFilter()
        self._os_override = os_override
        self._abort = threading.Event()
        self._session: frida.core.Session | None = None
        self._progress_callback: ProgressCallback | None = None
        self._log = logger or logging.getLogger("memslicer")
        self._read_timeout = read_timeout
        self._max_chunk_size = max_chunk_size

    def _on_message(self, message: dict, data: bytes | None) -> None:
        """Handle messages from the Frida JS agent (e.g. read-error diagnostics)."""
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
            self._log.error("Frida script error: %s", message.get("description", message))

    def request_abort(self) -> None:
        """Request graceful abort of the current acquisition."""
        self._abort.set()
        session = self._session
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback.

        Signature: callback(regions_captured, total_ranges, bytes_captured,
                           modules_captured, regions_processed)
        """
        self._progress_callback = callback

    def _emit_progress(
        self, region_count: int, total_ranges: int,
        bytes_captured: int, modules: int, regions_processed: int,
    ) -> None:
        """Emit progress if a callback is set."""
        if self._progress_callback:
            self._progress_callback(
                region_count, total_ranges, bytes_captured,
                modules, regions_processed,
            )

    def acquire(self, output_path: Path | str) -> AcquireResult:
        """Acquire process memory and write MSL file."""
        start = time.monotonic()
        self._abort.clear()
        output_path = Path(output_path)

        # Attach to process
        self._log.info("Connecting to device...")
        if isinstance(self._target, int):
            self._log.info("Attaching to PID %d...", self._target)
            pid = self._target
        else:
            self._log.info("Attaching to process '%s'...", self._target)
            pid = 0  # will be resolved via RPC

        session = self._device.attach(self._target)
        self._session = session

        region_count = 0
        total_ranges = 0
        bytes_captured = 0
        module_entries: list[ModuleEntry] = []
        regions_skipped = 0
        rwx_regions = 0
        bytes_attempted = 0
        pages_captured = 0
        pages_failed = 0
        skip_reasons: dict[str, int] = {}

        try:
            # Load RPC script
            self._log.info("Loading agent script...")
            script = session.create_script(_FRIDA_SCRIPT)
            script.on('message', self._on_message)
            script.load()
            api = script.exports_sync

            # Validate Frida API availability
            api_check = api.validate_api()
            self._log.debug(
                "API check: ptr=%s readByteArray=%s pageSize=%s",
                api_check.get("ptrType"),
                api_check.get("readByteArrayType"),
                api_check.get("pageSize"),
            )

            # Resolve PID via RPC if attached by name
            if pid == 0:
                pid = api.get_pid()

            # Detect platform
            self._log.info("Querying platform info...")
            frida_arch = api.get_arch()
            frida_platform = api.get_platform()
            modules_raw = api.enumerate_modules()
            modules_dicts = [{"name": m["name"], "path": m["path"]} for m in modules_raw]

            os_type, arch_type = detect_platform(
                frida_arch, frida_platform, modules_dicts, self._os_override
            )

            page_size = api.get_page_size()
            self._log.debug(
                "platform=%s arch=%s pid=%d page_size=%d",
                frida_platform, frida_arch, pid, page_size,
            )
            self._log.debug("modules: %d", len(modules_raw))

            # Build file header
            header = FileHeader(
                endianness=Endianness.LITTLE,
                version=VERSION,
                flags=0,
                cap_bitmap=(1 << CapBit.MemoryRegions) | (1 << CapBit.ModuleList),
                dump_uuid=uuid.uuid4().bytes,
                timestamp_ns=now_ns(),
                os_type=os_type,
                arch_type=arch_type,
                pid=pid,
            )

            # Open output and create writer
            with open(output_path, "wb") as f:
                writer = MSLWriter(f, header, self._comp_algo)

                try:
                    # Enumerate memory ranges — pass '---' to get ALL ranges
                    # (filtering is done on our side by RegionFilter)
                    self._log.info("Enumerating memory ranges...")
                    ranges = api.enumerate_ranges('---')
                    total_ranges = len(ranges)

                    # Sort by volatility — capture rw- regions first
                    ranges.sort(key=_volatility_key)
                    self._log.info(
                        "Reordered %d ranges by volatility (rw- first)",
                        total_ranges,
                    )

                    # Count readable ranges only when debug logging is active
                    if self._log.isEnabledFor(logging.DEBUG):
                        readable_count = sum(
                            1 for r in ranges
                            if parse_protection(r["protection"]) & 1
                        )
                        self._log.debug(
                            "ranges: %d total, %d readable", total_ranges, readable_count,
                        )

                    # Startup test read — pick a small readable region and
                    # attempt a single read for immediate feedback.
                    self._perform_startup_test_read(api, ranges, page_size)

                    for idx, r in enumerate(ranges):
                        if self._abort.is_set():
                            break

                        base_addr = _parse_frida_addr(r["base"])
                        base_hex = r["base"]  # keep original hex string for Frida RPC
                        size = r["size"]
                        prot = parse_protection(r["protection"])
                        file_info = r.get("file")
                        file_path = file_info.get("path", "") if file_info else ""

                        # Apply filter
                        reason = self._filter.skip_reason(base_addr, size, prot, file_path)
                        if reason is not None:
                            regions_skipped += 1
                            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                            self._emit_progress(
                                region_count, total_ranges,
                                bytes_captured, 0, idx + 1,
                            )
                            continue

                        bytes_attempted += size

                        region, data_size = self._read_region(
                            api, base_addr, base_hex, size, prot,
                            file_info, page_size,
                        )
                        writer.write_memory_region(region)
                        region_count += 1
                        bytes_captured += data_size
                        captured = region.page_states.count(PageState.CAPTURED)
                        pages_captured += captured
                        pages_failed += len(region.page_states) - captured
                        if is_rwx(prot):
                            rwx_regions += 1

                        self._emit_progress(
                            region_count, total_ranges,
                            bytes_captured, 0, idx + 1,
                        )

                    # Acquire modules
                    for m in modules_raw:
                        entry = ModuleEntry(
                            base_addr=_parse_frida_addr(m["base"]),
                            module_size=m["size"],
                            path=m["path"],
                            version="",
                            disk_hash=b'\x00' * HASH_SIZE,
                            native_blob=b"",
                        )
                        module_entries.append(entry)

                    if module_entries:
                        writer.write_module_list(module_entries)

                    self._emit_progress(
                        region_count, total_ranges,
                        bytes_captured, len(module_entries), total_ranges,
                    )

                finally:
                    # Always finalize the writer, even on abort
                    writer.finalize()

        except frida.InvalidOperationError:
            # Session was detached (e.g. via request_abort)
            self._log.debug("Session detached (abort or target exit)")
        finally:
            try:
                session.detach()
            except Exception:
                pass
            self._session = None

        duration = time.monotonic() - start
        return AcquireResult(
            regions_captured=region_count,
            regions_total=total_ranges,
            bytes_captured=bytes_captured,
            modules_captured=len(module_entries),
            aborted=self._abort.is_set(),
            duration_secs=duration,
            output_path=str(output_path),
            regions_skipped=regions_skipped,
            rwx_regions=rwx_regions,
            bytes_attempted=bytes_attempted,
            pages_captured=pages_captured,
            pages_failed=pages_failed,
            skip_reasons=skip_reasons,
        )

    def _read_region(
        self,
        api,
        base_addr: int,
        base_hex: str,
        size: int,
        protection: int,
        file_info: dict | None,
        page_size: int,
    ) -> tuple[MemoryRegion, int]:
        """Read a memory region using direct Frida RPC calls.

        Strategy (matching fridump):
        - If region fits in max_chunk_size, try a single read
        - If too large, split into max_chunk_size chunks
        - On failure for any chunk, mark those pages as FAILED
        """
        num_pages = (size + page_size - 1) // page_size
        page_states: list[PageState] = []
        page_data_chunks: list[bytes] = []
        data_size = 0
        region_type = _classify_region(file_info)

        self._log.debug(
            "Region 0x%x size=%d prot=%s type=%s",
            base_addr, size,
            format_protection(protection),
            region_type.name,
        )

        # Flag RWX regions at WARNING level (forensically significant)
        if is_rwx(protection):
            self._log.warning(
                "RWX region at 0x%x (%d bytes, %s) — potential JIT/injection",
                base_addr, size, region_type.name,
            )

        max_chunk = self._max_chunk_size

        if size <= max_chunk:
            # Small enough to try in one shot
            data = self._try_read(api, base_hex, size)
            if data is not None:
                data_bytes = _ensure_bytes(data)
                page_states = [PageState.CAPTURED] * num_pages
                page_data_chunks = [data_bytes]
                data_size = len(data_bytes)
                self._log.debug(
                    "Region 0x%x → read OK (%d bytes)", base_addr, data_size,
                )
            else:
                # Single read failed — try page-by-page fallback
                self._log.debug(
                    "Region 0x%x → full read FAILED, trying page-by-page fallback",
                    base_addr,
                )
                page_states, page_data_chunks, data_size = self._try_read_pages(
                    api, base_addr, size, page_size,
                )
        else:
            # Large region — split into chunks (fridump approach)
            self._log.debug(
                "Region 0x%x too big (%d), splitting into %d chunks",
                base_addr, size, (size + max_chunk - 1) // max_chunk,
            )
            page_states = [PageState.FAILED] * num_pages
            offset = 0

            while offset < size:
                if self._abort.is_set():
                    break
                chunk_size = min(max_chunk, size - offset)
                chunk_addr = base_addr + offset
                chunk_hex = hex(chunk_addr)

                data = self._try_read(api, chunk_hex, chunk_size)
                if data is not None:
                    data_bytes = _ensure_bytes(data)
                    page_data_chunks.append(data_bytes)
                    data_size += len(data_bytes)

                    # Mark pages as captured
                    first_page = offset // page_size
                    chunk_pages = (chunk_size + page_size - 1) // page_size
                    for pi in range(first_page, min(first_page + chunk_pages, num_pages)):
                        page_states[pi] = PageState.CAPTURED
                else:
                    # Chunk failed — try page-by-page fallback for this chunk
                    self._log.debug(
                        "Chunk 0x%x+%d failed, trying page-by-page fallback",
                        base_addr, offset,
                    )
                    fb_states, fb_chunks, fb_size = self._try_read_pages(
                        api, chunk_addr, chunk_size, page_size,
                    )
                    if fb_size > 0:
                        page_data_chunks.extend(fb_chunks)
                        data_size += fb_size
                        first_page = offset // page_size
                        for pi_off, st in enumerate(fb_states):
                            pi = first_page + pi_off
                            if pi < num_pages:
                                page_states[pi] = st

                offset += chunk_size

        region = MemoryRegion(
            base_addr=base_addr,
            region_size=size,
            protection=protection,
            region_type=region_type,
            page_size=page_size,
            timestamp_ns=now_ns(),
            page_states=page_states,
            page_data_chunks=page_data_chunks,
        )
        return region, data_size

    def _perform_startup_test_read(
        self, api, ranges: list[dict], page_size: int,
    ) -> None:
        """Pick a small readable region and attempt a single read for early feedback."""
        for r in ranges:
            prot = parse_protection(r["protection"])
            if not (prot & 1):  # not readable
                continue
            size = r["size"]
            if size > page_size * 4:
                continue  # skip large regions for the test
            addr = r["base"]
            # Normalize address
            if isinstance(addr, int):
                addr = hex(addr)
            test_size = min(size, page_size)
            data = self._try_read(api, addr, test_size)
            if data is not None:
                self._log.info(
                    "Startup test read OK: %s (%d bytes)", addr, len(_ensure_bytes(data)),
                )
            else:
                self._log.warning(
                    "Startup test read FAILED at %s size=%d — "
                    "reads may be blocked; check diagnostics",
                    addr, test_size,
                )
            return
        self._log.warning("No small readable region found for startup test read")

    def _try_read(self, api, addr, size: int) -> bytes | None:
        """Attempt a single Frida read_memory call. Returns None on failure."""
        # Normalize address to hex string for consistent Frida RPC calls
        if isinstance(addr, int):
            addr = hex(addr)
        try:
            return api.read_memory(addr, size)
        except Exception as e:
            self._log.debug("Read exception at %s size=%d: %s", addr, size, e)
            return None

    def _try_read_pages(
        self, api, base_addr: int, size: int, page_size: int,
    ) -> tuple[list[PageState], list[bytes], int]:
        """Retry a failed region read page-by-page (4KB at a time).

        Returns (page_states, page_data_chunks, data_size).
        Some pages may succeed even when the full-region read fails.
        """
        num_pages = (size + page_size - 1) // page_size
        page_states: list[PageState] = []
        page_data_chunks: list[bytes] = []
        data_size = 0
        pages_ok = 0

        for i in range(num_pages):
            if self._abort.is_set():
                # Fill remaining pages as FAILED
                page_states.extend([PageState.FAILED] * (num_pages - i))
                break
            page_addr = base_addr + i * page_size
            read_size = min(page_size, size - i * page_size)
            data = self._try_read(api, hex(page_addr), read_size)
            if data is not None:
                data_bytes = _ensure_bytes(data)
                page_states.append(PageState.CAPTURED)
                page_data_chunks.append(data_bytes)
                data_size += len(data_bytes)
                pages_ok += 1
            else:
                page_states.append(PageState.FAILED)

        self._log.debug(
            "Page-by-page fallback 0x%x: %d/%d pages captured (%d bytes)",
            base_addr, pages_ok, num_pages, data_size,
        )
        return page_states, page_data_chunks, data_size
