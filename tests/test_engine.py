"""Tests for AcquisitionEngine with a MockBridge."""
from __future__ import annotations

import struct
import threading
from pathlib import Path
from unittest.mock import patch


from memslicer.acquirer.base import UnreadableRange
from memslicer.acquirer.bridge import (
    MemoryRange, ModuleInfo, PlatformInfo, ReadResult,
)
from memslicer.acquirer.engine import (
    AcquisitionEngine, classify_region, coalesce_unreadable, volatility_key,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    ArchType, CapBit, HEADER_SIZE, OSType, PageState, RegionType,
    BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType,
)
from memslicer.msl.types import (
    MemoryRegion, ProcessEntry, ConnectionEntry, HandleEntry,
)


# ---------------------------------------------------------------------------
# Module-level function tests
# ---------------------------------------------------------------------------


class TestClassifyRegion:
    """Tests for classify_region covering all region type classifications."""

    def test_empty_path_returns_anon(self):
        assert classify_region("") == RegionType.Anon

    def test_heap_path(self):
        assert classify_region("[heap]") == RegionType.Heap

    def test_stack_path(self):
        assert classify_region("[stack]") == RegionType.Stack

    def test_shared_library_returns_image(self):
        assert classify_region("/usr/lib/libc.so") == RegionType.Image

    def test_dylib_returns_image(self):
        assert classify_region("/usr/lib/libSystem.dylib") == RegionType.Image

    def test_dll_returns_image(self):
        assert classify_region("C:\\Windows\\System32\\ntdll.dll") == RegionType.Image

    def test_exe_returns_image(self):
        assert classify_region("C:\\Program Files\\app.exe") == RegionType.Image

    def test_mapped_file_with_slash(self):
        assert classify_region("/path/to/file") == RegionType.MappedFile

    def test_unknown_path(self):
        assert classify_region("something") == RegionType.Unknown


class TestVolatilityKeyOrdering:
    """Tests for volatility_key ensuring correct priority ordering."""

    def test_rw_anon_comes_first(self):
        """rw- anonymous regions (priority 0) should sort before all others."""
        rw_anon = MemoryRange(base=0x1000, size=4096, protection="rw-", file_path="")
        rwx = MemoryRange(base=0x2000, size=4096, protection="rwx", file_path="")
        rx_image = MemoryRange(base=0x3000, size=4096, protection="r-x", file_path="/lib/libc.so")
        ro_mapped = MemoryRange(base=0x4000, size=4096, protection="r--", file_path="/data/file")
        no_prot = MemoryRange(base=0x5000, size=4096, protection="---", file_path="")

        keys = [
            volatility_key(rw_anon),
            volatility_key(rwx),
            volatility_key(rx_image),
            volatility_key(ro_mapped),
            volatility_key(no_prot),
        ]

        # Each priority bucket should be strictly less than the next
        assert keys[0] < keys[1] < keys[2] < keys[3] < keys[4]

    def test_rw_heap_also_priority_zero(self):
        rw_heap = MemoryRange(base=0x1000, size=4096, protection="rw-", file_path="[heap]")
        assert volatility_key(rw_heap)[0] == 0

    def test_rw_stack_also_priority_zero(self):
        rw_stack = MemoryRange(base=0x1000, size=4096, protection="rw-", file_path="[stack]")
        assert volatility_key(rw_stack)[0] == 0

    def test_secondary_sort_by_base_address(self):
        r1 = MemoryRange(base=0x1000, size=4096, protection="rw-", file_path="")
        r2 = MemoryRange(base=0x2000, size=4096, protection="rw-", file_path="")
        assert volatility_key(r1) < volatility_key(r2)


# ---------------------------------------------------------------------------
# MockBridge
# ---------------------------------------------------------------------------


class MockBridge:
    """A mock debugger bridge for testing AcquisitionEngine.

    Attributes:
        memory: dict mapping address -> bytes for read_memory lookups.
        ranges: list of MemoryRange to return from enumerate_ranges.
        modules: list of ModuleInfo to return from enumerate_modules.
        platform_info: PlatformInfo to return from get_platform_info.
        connected: tracks whether connect/disconnect were called.
        connect_count: number of connect() calls.
        disconnect_count: number of disconnect() calls.
    """

    def __init__(
        self,
        ranges: list[MemoryRange] | None = None,
        modules: list[ModuleInfo] | None = None,
        platform_info: PlatformInfo | None = None,
        memory: dict[int, bytes] | None = None,
    ) -> None:
        self.ranges = ranges or []
        self.modules = modules or []
        self.platform_info = platform_info or PlatformInfo(
            arch=ArchType.x86_64,
            os=OSType.Linux,
            pid=1234,
            page_size=4096,
        )
        self.memory: dict[int, bytes] = memory or {}
        self.connected = False
        self.connect_count = 0
        self.disconnect_count = 0

    def connect(self) -> None:
        self.connected = True
        self.connect_count += 1

    def get_platform_info(self) -> PlatformInfo:
        return self.platform_info

    def enumerate_ranges(self) -> list[MemoryRange]:
        return list(self.ranges)

    def enumerate_modules(self) -> list[ModuleInfo]:
        return list(self.modules)

    def read_memory(self, address: int, size: int) -> bytes | None:
        data = self.memory.get(address)
        if data is None:
            return None
        if len(data) < size:
            return None
        return data[:size]

    def disconnect(self) -> None:
        self.connected = False
        self.disconnect_count += 1


# ---------------------------------------------------------------------------
# Fault-injecting bridges
# ---------------------------------------------------------------------------


_NO_OVERRIDE = object()
"""Sentinel meaning "derive the fault address from the bad pages"."""


class FaultingBridge(MockBridge):
    """A MockBridge whose reads fail whenever they touch a "bad" page.

    Only :meth:`read_memory` is exposed, so the engine takes the path it takes
    for any backend that cannot localise a fault -- one read per page.

    Attributes:
        bad_pages: Page-aligned addresses that cannot be read.
        reads: Every ``(address, size)`` the engine asked for, in order.
    """

    def __init__(
        self,
        ranges: list[MemoryRange] | None = None,
        modules: list[ModuleInfo] | None = None,
        bad_pages: tuple[int, ...] = (),
        page_size: int = 4096,
        fill: bytes = b"\xa5",
        max_reads: int = 512,
    ) -> None:
        super().__init__(ranges=ranges, modules=modules)
        self.bad_pages = set(bad_pages)
        self.page_size = page_size
        self.fill = fill
        self.max_reads = max_reads
        self.reads: list[tuple[int, int]] = []

    def first_bad_in(self, address: int, size: int) -> int | None:
        """Return the first bad page touched by ``[address, address+size)``."""
        if size <= 0:
            return None
        first = address - (address % self.page_size)
        for page in range(first, address + size, self.page_size):
            if page in self.bad_pages:
                return page
        return None

    def read_memory(self, address: int, size: int) -> bytes | None:
        self.reads.append((address, size))
        if len(self.reads) > self.max_reads:
            raise RuntimeError(
                f"read budget of {self.max_reads} exhausted — "
                "the engine is not making forward progress"
            )
        if size <= 0 or self.first_bad_in(address, size) is not None:
            return None
        return self.fill * size


class FaultReportingBridge(FaultingBridge):
    """A :class:`FaultingBridge` that also implements ``read_memory_ex``.

    Defining the optional capability only on this subclass keeps both bridge
    shapes — with and without fault reporting — exercised by the suite.

    Attributes:
        fault_override: ``_NO_OVERRIDE`` to report the real faulting page;
            ``None`` to report a failure without an address (as a backend that
            cannot localise the fault would); an int to always report that
            address, however implausible.
    """

    def __init__(self, *args, fault_override=_NO_OVERRIDE, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fault_override = fault_override

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        data = self.read_memory(address, size)
        if data is not None:
            return ReadResult(data=data)
        if self.fault_override is _NO_OVERRIDE:
            fault = self.first_bad_in(address, size)
        else:
            fault = self.fault_override
        return ReadResult(
            data=None,
            fault_addr=fault,
            error=(
                f"access violation accessing 0x{fault:x}"
                if fault is not None else "read failed"
            ),
        )


def _read_span(bridge: FaultingBridge, base: int, size: int,
               page_size: int = 4096, file_path: str = ""):
    """Drive ``_read_region`` directly and return ``(region, data_size)``."""
    engine = AcquisitionEngine(bridge)
    return engine._read_region(base, size, 0x03, file_path, page_size)


def _states(*runs: tuple[PageState, int]) -> list[PageState]:
    """Build a page-state list from ``(state, count)`` runs."""
    out: list[PageState] = []
    for state, count in runs:
        out.extend([state] * count)
    return out


def _make_region(
    states: list[PageState], base: int = 0x10000, page_size: int = 4096,
) -> MemoryRegion:
    """Build a MemoryRegion carrying only the page states under test."""
    return MemoryRegion(
        base_addr=base,
        region_size=len(states) * page_size,
        protection=0x03,
        region_type=RegionType.Anon,
        page_size=page_size,
        timestamp_ns=0,
        page_states=list(states),
        page_data_chunks=[],
    )


# ---------------------------------------------------------------------------
# Engine integration tests
# ---------------------------------------------------------------------------


class TestBasicAcquire:
    """Test basic acquisition with a single readable region and module."""

    def test_basic_acquire(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
        modules = [ModuleInfo(name="libc.so", path="/usr/lib/libc.so", base=0x400000, size=0x10000)]

        bridge = MockBridge(
            ranges=ranges,
            modules=modules,
            memory={0x10000: data},
        )

        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"
        result = engine.acquire(output)

        assert result.regions_captured == 1
        assert result.modules_captured == 1
        assert result.bytes_captured == len(data)
        assert output.exists()
        assert output.stat().st_size > 0
        assert bridge.connect_count >= 1
        assert bridge.disconnect_count >= 1


class TestAcquireWithFilter:
    """Test that region filtering skips regions below min_prot."""

    def test_filter_skips_regions(self, tmp_path: Path):
        data_rw = b"\xbb" * 4096
        data_ro = b"\xcc" * 4096

        ranges = [
            MemoryRange(base=0x10000, size=4096, protection="rw-", file_path=""),
            MemoryRange(base=0x20000, size=4096, protection="r--", file_path=""),
        ]

        bridge = MockBridge(
            ranges=ranges,
            memory={0x10000: data_rw, 0x20000: data_ro},
        )

        # min_prot=3 requires both R and W bits, so r-- region gets skipped
        region_filter = RegionFilter(min_prot=3, skip_no_read=False)
        engine = AcquisitionEngine(bridge, region_filter=region_filter)
        output = tmp_path / "dump.msl"
        result = engine.acquire(output)

        assert result.regions_captured == 1
        assert result.regions_skipped == 1
        assert "min-prot" in result.skip_reasons
        assert result.skip_reasons["min-prot"] == 1


class TestAcquirePageFallback:
    """Test that page-by-page fallback works when full region read fails."""

    def test_page_fallback(self, tmp_path: Path):
        page_size = 4096
        region_size = page_size * 3

        ranges = [MemoryRange(base=0x10000, size=region_size, protection="rw-", file_path="")]

        # Full region read (address=0x10000, size=12288) returns None,
        # but individual page reads succeed.
        memory = {
            0x10000: b"\x01" * page_size,
            0x11000: b"\x02" * page_size,
            0x12000: b"\x03" * page_size,
        }

        bridge = MockBridge(ranges=ranges, memory=memory)
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"
        result = engine.acquire(output)

        assert result.regions_captured == 1
        assert result.pages_captured == 3
        assert result.bytes_captured == region_size


class TestAcquireAbort:
    """Test that request_abort() stops acquisition early."""

    def test_abort_stops_early(self, tmp_path: Path):
        page_size = 4096
        # Create many regions so there is time to abort
        ranges = [
            MemoryRange(base=0x10000 + i * page_size, size=page_size, protection="rw-", file_path="")
            for i in range(50)
        ]
        memory = {
            r.base: b"\xdd" * page_size for r in ranges
        }

        bridge = MockBridge(ranges=ranges, memory=memory)
        engine = AcquisitionEngine(bridge)

        captured_counts: list[int] = []

        def progress_cb(regions_captured, total_ranges, bytes_captured, modules, regions_processed):
            captured_counts.append(regions_captured)
            # Abort after 2 regions have been captured
            if regions_captured >= 2:
                engine.request_abort()

        engine.set_progress_callback(progress_cb)
        output = tmp_path / "dump.msl"
        result = engine.acquire(output)

        assert result.aborted is True
        # Should have captured some but not all regions
        assert result.regions_captured < 50


class TestProgressCallback:
    """Test that the progress callback is invoked during acquisition."""

    def test_callback_invoked(self, tmp_path: Path):
        data = b"\xee" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
        modules = [ModuleInfo(name="mod", path="/lib/mod.so", base=0x400000, size=0x1000)]

        bridge = MockBridge(ranges=ranges, modules=modules, memory={0x10000: data})
        engine = AcquisitionEngine(bridge)

        calls: list[tuple] = []

        def progress_cb(regions_captured, total_ranges, bytes_captured, modules_count, regions_processed):
            calls.append((regions_captured, total_ranges, bytes_captured, modules_count, regions_processed))

        engine.set_progress_callback(progress_cb)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        assert len(calls) >= 1
        # The final call should report all regions processed and modules counted
        last = calls[-1]
        assert last[0] == 1  # regions_captured
        assert last[1] == 1  # total_ranges
        assert last[3] == 1  # modules_captured in final progress


class TestAcquireEmptyRanges:
    """Test acquisition when no memory ranges are returned."""

    def test_empty_ranges(self, tmp_path: Path):
        bridge = MockBridge(ranges=[], modules=[])
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"
        result = engine.acquire(output)

        assert result.regions_captured == 0
        assert result.regions_total == 0
        assert result.bytes_captured == 0
        assert result.modules_captured == 0
        assert result.aborted is False
        assert output.exists()


class TestDynamicCapBitmap:
    """Test that CapBitmap is set dynamically based on enumerated data."""

    def _read_cap_bitmap(self, path: Path) -> int:
        """Read the cap_bitmap field from the MSL file header."""
        data = path.read_bytes()
        # cap_bitmap is at offset 8+1+1+2+4 = 16, as uint64 LE
        return struct.unpack_from("<Q", data, 16)[0]

    def test_cap_bitmap_includes_module_bit_when_modules_present(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
        modules = [ModuleInfo(name="libc.so", path="/usr/lib/libc.so", base=0x400000, size=0x10000)]

        bridge = MockBridge(ranges=ranges, modules=modules, memory={0x10000: data})
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        cap_bitmap = self._read_cap_bitmap(output)
        assert cap_bitmap & (1 << CapBit.MemoryRegions), "MemoryRegions bit should be set"
        assert cap_bitmap & (1 << CapBit.ProcessIdentity), "ProcessIdentity bit should be set"
        assert cap_bitmap & (1 << CapBit.ModuleList), "ModuleList bit should be set when modules exist"

    def test_cap_bitmap_excludes_module_bit_when_no_modules(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        cap_bitmap = self._read_cap_bitmap(output)
        assert cap_bitmap & (1 << CapBit.MemoryRegions), "MemoryRegions bit should be set"
        assert cap_bitmap & (1 << CapBit.ProcessIdentity), "ProcessIdentity bit should be set"
        assert not (cap_bitmap & (1 << CapBit.ModuleList)), "ModuleList bit should NOT be set when no modules"


# ---------------------------------------------------------------------------
# MockCollector
# ---------------------------------------------------------------------------


class MockCollector:
    """A mock investigation collector for testing collector integration."""

    def __init__(self):
        self.process_info = TargetProcessInfo(
            ppid=999, session_id=42, start_time_ns=1700000000_000000000,
            exe_path="/usr/bin/target", cmd_line="/usr/bin/target --flag",
        )
        self.system_info = TargetSystemInfo(
            boot_time=1699000000_000000000,
            hostname="target-host",
            domain="example.com",
            os_detail="Linux 6.1.0-generic x86_64",
        )

    def collect_process_identity(self, pid, **kwargs):
        return self.process_info

    def collect_system_info(self):
        return self.system_info

    def collect_process_table(self, target_pid):
        return [ProcessEntry(pid=target_pid, ppid=1, uid=1000, is_target=True,
                             start_time=0, rss=4096, exe_name="target", cmd_line="target", user="")]

    def collect_connection_table(self):
        return [ConnectionEntry(pid=1234, family=0x02, protocol=0x06, state=0x01,
                                local_addr=b'\x7f\x00\x00\x01' + b'\x00' * 12,
                                local_port=8080,
                                remote_addr=b'\x00' * 16, remote_port=0)]

    def collect_handle_table(self, pid):
        return [HandleEntry(pid=pid, fd=3, handle_type=0x01, path="/tmp/test.log")]

    def collect_persistence_manifest(self, **kwargs):
        # P1.6.4 stub — engine only calls this when the
        # ``--include-persistence-manifest`` flag is on.
        from memslicer.msl.types import PersistenceManifest
        return PersistenceManifest()

    def collect_connectivity_table(self, **kwargs):
        # P1.6.5 stub — returns an empty ConnectivityTable so the engine
        # treats it as "no rows" and skips writing the 0x0054 block.
        from memslicer.msl.types import ConnectivityTable
        return ConnectivityTable()

    def collect_kernel_module_list(self, **kwargs):
        # P1.6.2 stub — returns an empty KernelModuleList so the engine
        # skips writing the 0x0057 block.
        from memslicer.msl.types import KernelModuleList
        return KernelModuleList()


# ---------------------------------------------------------------------------
# Helpers for parsing MSL blocks
# ---------------------------------------------------------------------------


def _parse_blocks(raw: bytes) -> list[tuple[int, int, bytes]]:
    """Walk blocks from HEADER_SIZE, returning list of (block_type, flags, payload).

    Each block starts with a BLOCK_HEADER_SIZE-byte header:
      BLOCK_MAGIC(4) + BlockType(2) + Flags(2) + BlockLength(4) + ...
    Payload follows immediately after the header.
    """
    offset = HEADER_SIZE
    blocks: list[tuple[int, int, bytes]] = []
    while offset + BLOCK_HEADER_SIZE <= len(raw):
        magic = raw[offset:offset + 4]
        if magic != BLOCK_MAGIC:
            break
        block_type, flags, block_length = struct.unpack_from("<HHI", raw, offset + 4)
        payload_size = block_length - BLOCK_HEADER_SIZE
        payload_start = offset + BLOCK_HEADER_SIZE
        payload = raw[payload_start:payload_start + payload_size]
        blocks.append((block_type, flags, payload))
        offset += block_length
    return blocks


def _find_block(blocks: list[tuple[int, int, bytes]], block_type: int) -> bytes | None:
    """Find the first block matching a given type and return its payload."""
    for bt, _flags, payload in blocks:
        if bt == block_type:
            return payload
    return None


def _read_padded_string(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated, pad8 string from data at offset.

    Returns (string, new_offset_after_padding).
    """
    null_pos = data.index(b"\x00", offset)
    s = data[offset:null_pos].decode("utf-8")
    raw_len = null_pos - offset + 1  # include null byte
    padded_len = ((raw_len + 7) // 8) * 8
    return s, offset + padded_len


# ---------------------------------------------------------------------------
# Collector integration tests
# ---------------------------------------------------------------------------


class TestCollectorProcessIdentity:
    """Test that ProcessIdentity block contains data from the collector."""

    def test_process_identity_populated_from_collector(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        collector = MockCollector()
        engine = AcquisitionEngine(bridge, collector=collector)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        raw = output.read_bytes()
        blocks = _parse_blocks(raw)
        payload = _find_block(blocks, BlockType.ProcessIdentity)
        assert payload is not None, "ProcessIdentity block not found"

        # Fixed header: ppid(4) + session_id(4) + start_time_ns(8) + exe_path_len(2) + cmd_line_len(2) + reserved(4) = 24
        ppid, session_id, start_time_ns, exe_path_len, cmd_line_len, _reserved = struct.unpack_from(
            "<IIQHHI", payload, 0,
        )

        assert ppid == 999
        assert session_id == 42
        assert start_time_ns == 1700000000_000000000

        # Parse variable-length strings after fixed 24-byte header
        offset = 24
        exe_path, offset = _read_padded_string(payload, offset)
        assert exe_path == "/usr/bin/target"

        cmd_line, offset = _read_padded_string(payload, offset)
        assert cmd_line == "/usr/bin/target --flag"


class TestCollectorSystemContext:
    """Test that SystemContext uses collector data when investigation=True."""

    def test_system_context_populated_from_collector(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        collector = MockCollector()
        engine = AcquisitionEngine(bridge, investigation=True, collector=collector)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        raw = output.read_bytes()
        blocks = _parse_blocks(raw)
        payload = _find_block(blocks, BlockType.SystemContext)
        assert payload is not None, "SystemContext block not found"

        # Fixed 32-byte header:
        # boot_time(8) + target_count(1) + table_bitmap(4)
        # + acq_user_len(2) + hostname_len(2) + domain_len(2) + os_detail_len(2)
        # + case_ref_len(2) + reserved(6)
        boot_time, target_count, table_bitmap = struct.unpack_from("<QBI", payload, 0)
        acq_user_len, hostname_len, domain_len, os_detail_len, case_ref_len = struct.unpack_from(
            "<HHHHH", payload, 13,
        )

        assert boot_time == 1699000000_000000000

        # Parse variable strings after 32-byte fixed header
        offset = 32
        # acq_user (we don't control this value, just skip it)
        if acq_user_len > 0:
            _acq_user, offset = _read_padded_string(payload, offset)

        # hostname
        hostname, offset = _read_padded_string(payload, offset)
        assert hostname == "target-host"

        # domain
        if domain_len > 0:
            domain, offset = _read_padded_string(payload, offset)
            assert domain == "example.com"

        # os_detail — since P0.4 the engine packs collector output through
        # the msl.memslicer/1 microformat (see acquirer/os_detail.py). The
        # original raw string survives as the ``raw_os`` key and is also
        # used to build the human-readable prefix that leads the value, so
        # a naive consumer still sees a sensible OS description.
        os_detail, offset = _read_padded_string(payload, offset)
        assert os_detail.startswith("msl.memslicer/1 ")
        assert "Linux 6.1.0-generic x86_64" in os_detail
        # Parser round-trip: the packed raw_os must match the collector's
        # emission, proving no data was silently dropped in the refactor.
        from memslicer.acquirer.os_detail import parse_os_detail
        parsed = parse_os_detail(os_detail)
        assert parsed.get("raw_os") == "Linux 6.1.0-generic x86_64"


class TestCollectorSystemTables:
    """Test that system tables are written when collector provides data."""

    def _read_cap_bitmap(self, path: Path) -> int:
        """Read the cap_bitmap field from the MSL file header."""
        data = path.read_bytes()
        return struct.unpack_from("<Q", data, 16)[0]

    def test_system_tables_written(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        collector = MockCollector()
        engine = AcquisitionEngine(bridge, investigation=True, collector=collector)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        raw = output.read_bytes()
        blocks = _parse_blocks(raw)

        # Verify all three table blocks exist
        process_table = _find_block(blocks, BlockType.ProcessTable)
        assert process_table is not None, "ProcessTable block not found"

        connection_table = _find_block(blocks, BlockType.ConnectionTable)
        assert connection_table is not None, "ConnectionTable block not found"

        handle_table = _find_block(blocks, BlockType.HandleTable)
        assert handle_table is not None, "HandleTable block not found"

    def test_table_bitmap_has_all_table_bits(self, tmp_path: Path):
        """Verify SystemContext table_bitmap has bits for all three system tables."""
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        collector = MockCollector()
        engine = AcquisitionEngine(bridge, investigation=True, collector=collector)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        raw = output.read_bytes()
        blocks = _parse_blocks(raw)
        payload = _find_block(blocks, BlockType.SystemContext)
        assert payload is not None, "SystemContext block not found"

        # table_bitmap is at offset 9 in the 32-byte fixed header
        _boot_time, _target_count, table_bitmap = struct.unpack_from("<QBI", payload, 0)
        assert table_bitmap & 0x01, "ProcessTable bit (0x01) should be set in table_bitmap"
        assert table_bitmap & 0x02, "ConnectionTable bit (0x02) should be set in table_bitmap"
        assert table_bitmap & 0x04, "HandleTable bit (0x04) should be set in table_bitmap"


class TestCollectorFallback:
    """Test that without collector, ProcessIdentity is zeroed."""

    def test_process_identity_zeroed_without_collector(self, tmp_path: Path):
        data = b"\xaa" * 4096
        ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]

        bridge = MockBridge(ranges=ranges, modules=[], memory={0x10000: data})
        engine = AcquisitionEngine(bridge, collector=None)
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        raw = output.read_bytes()
        blocks = _parse_blocks(raw)
        payload = _find_block(blocks, BlockType.ProcessIdentity)
        assert payload is not None, "ProcessIdentity block not found"

        # Fixed header: ppid(4) + session_id(4) + start_time_ns(8) + exe_path_len(2) + cmd_line_len(2) + reserved(4)
        ppid, session_id, start_time_ns, exe_path_len, cmd_line_len, _reserved = struct.unpack_from(
            "<IIQHHI", payload, 0,
        )

        assert ppid == 0
        assert session_id == 0
        assert start_time_ns == 0

        # exe_path should be empty (just a null terminator)
        offset = 24
        exe_path, offset = _read_padded_string(payload, offset)
        assert exe_path == ""

        # cmd_line should be empty — either no data or empty string
        # When cmd_line is "", the writer may omit it entirely (cmd_line_len=0)
        if cmd_line_len > 0:
            cmd_line, offset = _read_padded_string(payload, offset)
            assert cmd_line == ""


# ---------------------------------------------------------------------------
# Engine fallback tests (connection table / handle table without collector)
# ---------------------------------------------------------------------------


class TestEngineConnectionTableFallback:
    """Tests for _collect_connection_table engine fallback to LinuxCollector."""

    def _make_engine(self):
        """Create an AcquisitionEngine with investigation=True, no collector."""
        bridge = MockBridge()
        engine = AcquisitionEngine(bridge, investigation=True, collector=None)
        return engine

    def test_connection_table_fallback_delegates_to_linux_collector(self):
        """When /proc/net exists, delegates to LinuxCollector."""
        engine = self._make_engine()
        sample = [ConnectionEntry(
            pid=100, family=0x02, protocol=0x06, state=0x01,
            local_addr=b'\x7f\x00\x00\x01' + b'\x00' * 12,
            local_port=80, remote_addr=b'\x00' * 16, remote_port=0,
        )]

        with patch("memslicer.acquirer.engine.os.path.isdir", return_value=True), \
             patch("memslicer.acquirer.collectors.linux.LinuxCollector.collect_connection_table",
                   return_value=sample):
            result = engine._collect_connection_table()

        assert len(result) == 1
        assert result[0].pid == 100
        assert result[0].local_port == 80

    def test_connection_table_fallback_empty_no_proc(self):
        """When /proc/net does not exist, returns empty list."""
        engine = self._make_engine()

        with patch("memslicer.acquirer.engine.os.path.isdir", return_value=False):
            result = engine._collect_connection_table()

        assert result == []


class TestEngineHandleTableFallback:
    """Tests for _collect_handle_table engine fallback to LinuxCollector."""

    def _make_engine(self):
        """Create an AcquisitionEngine with investigation=True, no collector."""
        bridge = MockBridge()
        engine = AcquisitionEngine(bridge, investigation=True, collector=None)
        return engine

    def test_handle_table_fallback_delegates_to_linux_collector(self):
        """When /proc/{pid}/fd exists, delegates to LinuxCollector."""
        engine = self._make_engine()
        sample = [HandleEntry(pid=1234, fd=3, handle_type=0x01, path="/tmp/test.log")]

        with patch("memslicer.acquirer.engine.os.path.isdir", return_value=True), \
             patch("memslicer.acquirer.collectors.linux.LinuxCollector.collect_handle_table",
                   return_value=sample):
            result = engine._collect_handle_table(1234)

        assert len(result) == 1
        assert result[0].pid == 1234
        assert result[0].fd == 3
        assert result[0].path == "/tmp/test.log"

    def test_handle_table_fallback_empty_no_proc(self):
        """When /proc/{pid}/fd does not exist, returns empty list."""
        engine = self._make_engine()

        with patch("memslicer.acquirer.engine.os.path.isdir", return_value=False):
            result = engine._collect_handle_table(1234)

        assert result == []


# ---------------------------------------------------------------------------
# Fault-boundary splitting
# ---------------------------------------------------------------------------


PAGE = 4096
BASE = 0x10000
REGION_PAGES = 16
REGION_SIZE = REGION_PAGES * PAGE


class TestSplitOnFault:
    """Reads split at the reported fault boundary instead of degrading to
    one read per page."""

    def test_single_fault_in_the_middle(self):
        bad = BASE + 7 * PAGE
        bridge = FaultReportingBridge(bad_pages=(bad,))

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.CAPTURED, 7), (PageState.FAILED, 1),
            (PageState.CAPTURED, 8),
        )
        assert data_size == 15 * PAGE
        # Full read, readable prefix, readable suffix — nothing per-page.
        assert len(bridge.reads) == 3
        assert len(bridge.reads) < REGION_PAGES + 1

    def test_fault_at_span_start_issues_no_zero_length_read(self):
        """With the very first page bad the good prefix is empty, so no read
        may be issued for it."""
        bridge = FaultReportingBridge(bad_pages=(BASE,))

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.FAILED, 1), (PageState.CAPTURED, 15),
        )
        assert data_size == 15 * PAGE
        assert all(size > 0 for _addr, size in bridge.reads)
        assert len(bridge.reads) == 2

    def test_fault_on_last_page(self):
        bad = BASE + 15 * PAGE
        bridge = FaultReportingBridge(bad_pages=(bad,))

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.CAPTURED, 15), (PageState.FAILED, 1),
        )
        assert data_size == 15 * PAGE
        assert len(bridge.reads) == 2

    def test_two_faults_in_one_region(self):
        bad = (BASE + 3 * PAGE, BASE + 10 * PAGE)
        bridge = FaultReportingBridge(bad_pages=bad)

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.CAPTURED, 3), (PageState.FAILED, 1),
            (PageState.CAPTURED, 6), (PageState.FAILED, 1),
            (PageState.CAPTURED, 5),
        )
        assert data_size == 14 * PAGE
        assert len(bridge.reads) < REGION_PAGES + 1

    def test_fault_outside_span_degrades_to_page_reads(self):
        """A nonsensical fault address must not be trusted; the result has to
        match what the plain page-by-page path produces."""
        bad = BASE + 7 * PAGE
        bogus = BASE - 0x100000
        reporting = FaultReportingBridge(bad_pages=(bad,), fault_override=bogus)
        plain = FaultingBridge(bad_pages=(bad,))

        region, data_size = _read_span(reporting, BASE, REGION_SIZE)
        plain_region, plain_size = _read_span(plain, BASE, REGION_SIZE)

        assert region.page_states == plain_region.page_states
        assert data_size == plain_size
        assert region.page_states == _states(
            (PageState.CAPTURED, 7), (PageState.FAILED, 1),
            (PageState.CAPTURED, 8),
        )

    def test_no_fault_address_matches_bridge_without_read_memory_ex(self):
        """Regression guard for the GDB/LLDB bridges, which never report a
        fault address."""
        bad = BASE + 7 * PAGE
        reporting = FaultReportingBridge(bad_pages=(bad,), fault_override=None)
        plain = FaultingBridge(bad_pages=(bad,))

        region, data_size = _read_span(reporting, BASE, REGION_SIZE)
        plain_region, plain_size = _read_span(plain, BASE, REGION_SIZE)

        assert region.page_states == plain_region.page_states
        assert data_size == plain_size
        assert reporting.reads == plain.reads

    def test_stale_fault_address_still_terminates(self):
        """A backend that keeps reporting the same address below ``pos`` must
        not be able to stall the split loop."""
        bad = BASE + 7 * PAGE
        bridge = FaultReportingBridge(
            bad_pages=(bad,), fault_override=BASE, max_reads=200,
        )
        outcome: list[object] = []

        def run() -> None:
            try:
                outcome.append(_read_span(bridge, BASE, REGION_SIZE))
            except BaseException as exc:  # noqa: BLE001 - reported below
                outcome.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=30)

        assert not worker.is_alive(), "_read_span_split did not terminate"
        assert outcome, "worker produced no outcome"
        assert not isinstance(outcome[0], BaseException), outcome[0]
        region, _data_size = outcome[0]
        assert len(region.page_states) == REGION_PAGES
        assert region.page_states.count(PageState.FAILED) >= 1


class TestCoalesceUnreadable:
    """Contiguous runs of lost pages are reported as address ranges."""

    def test_single_run_of_three_pages(self):
        region = _make_region(_states(
            (PageState.CAPTURED, 2), (PageState.FAILED, 3),
            (PageState.CAPTURED, 1),
        ))

        ranges = coalesce_unreadable(region)

        assert len(ranges) == 1
        assert isinstance(ranges[0], UnreadableRange)
        assert ranges[0].base == BASE + 2 * PAGE
        assert ranges[0].size == 3 * PAGE
        assert ranges[0].region_base == BASE
        assert ranges[0].expected is False

    def test_two_separate_runs(self):
        region = _make_region(_states(
            (PageState.FAILED, 1), (PageState.CAPTURED, 2),
            (PageState.FAILED, 2), (PageState.CAPTURED, 1),
        ))

        ranges = coalesce_unreadable(region)

        assert len(ranges) == 2
        assert (ranges[0].base, ranges[0].size) == (BASE, PAGE)
        assert (ranges[1].base, ranges[1].size) == (BASE + 3 * PAGE, 2 * PAGE)

    def test_run_reaching_the_end_of_the_region(self):
        region = _make_region(_states(
            (PageState.CAPTURED, 2), (PageState.FAILED, 2),
        ))

        ranges = coalesce_unreadable(region)

        assert len(ranges) == 1
        assert ranges[0].base == BASE + 2 * PAGE
        assert ranges[0].size == 2 * PAGE

    def test_all_captured_yields_no_ranges(self):
        region = _make_region([PageState.CAPTURED] * 4)

        assert coalesce_unreadable(region) == []

    def test_kernel_pseudo_region_marks_ranges_expected(self):
        region = _make_region(_states((PageState.UNMAPPED, 2)))

        ranges = coalesce_unreadable(region, "[vvar_vclock]")

        assert len(ranges) == 1
        assert ranges[0].expected is True
        assert ranges[0].file_path == "[vvar_vclock]"

    def test_ordinary_region_ranges_are_not_expected(self):
        region = _make_region(_states((PageState.FAILED, 2)))

        ranges = coalesce_unreadable(region, "/usr/lib/libc.so.6")

        assert ranges[0].expected is False

    def test_unmapped_and_failed_runs_both_counted(self):
        """Coalescing keys off "not captured", so a UNMAPPED page adjacent to
        a FAILED one forms a single run."""
        region = _make_region(_states(
            (PageState.CAPTURED, 1), (PageState.FAILED, 1),
            (PageState.UNMAPPED, 1), (PageState.CAPTURED, 1),
        ))

        ranges = coalesce_unreadable(region)

        assert len(ranges) == 1
        assert ranges[0].size == 2 * PAGE


class TestKernelPseudoRegionAccounting:
    """A kernel pseudo-mapping's failed reads are the kernel's answer, not
    data loss."""

    def _pseudo_bridge(self, file_path: str = "[vvar_vclock]", pages: int = 2):
        ranges = [MemoryRange(
            base=BASE, size=pages * PAGE, protection="r--", file_path=file_path,
        )]
        # No memory entries at all, so every read fails.
        return MockBridge(ranges=ranges, modules=[], memory={})

    def test_pages_recorded_as_unmapped_not_failed(self):
        bridge = self._pseudo_bridge()

        region, data_size = _read_span(
            bridge, BASE, 2 * PAGE, file_path="[vvar_vclock]",
        )

        assert region.page_states == [PageState.UNMAPPED] * 2
        assert PageState.FAILED not in region.page_states
        assert data_size == 0

    def test_ordinary_region_still_reports_failed(self):
        bridge = MockBridge(memory={})

        region, _data_size = _read_span(bridge, BASE, 2 * PAGE, file_path="")

        assert region.page_states == [PageState.FAILED] * 2

    def test_acquire_accounts_pseudo_pages_separately(self, tmp_path: Path):
        bridge = self._pseudo_bridge()
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"

        result = engine.acquire(output)

        assert result.pages_expected_unreadable == 2
        assert result.pages_failed == 0
        assert result.pages_captured == 0
        assert result.bytes_expected_unreadable == 2 * PAGE
        assert "[vvar_vclock]" in result.expected_unreadable_regions

    def test_acquire_still_writes_the_pseudo_region(self, tmp_path: Path):
        bridge = self._pseudo_bridge()
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "dump.msl"

        result = engine.acquire(output)

        assert result.regions_captured == 1
        assert result.regions_skipped == 0
        blocks = _parse_blocks(output.read_bytes())
        assert _find_block(blocks, BlockType.MemoryRegion) is not None

    def test_acquire_marks_pseudo_ranges_expected(self, tmp_path: Path):
        bridge = self._pseudo_bridge()
        engine = AcquisitionEngine(bridge)

        result = engine.acquire(tmp_path / "dump.msl")

        assert len(result.unreadable_ranges) == 1
        assert result.unreadable_ranges[0].expected is True
        assert result.unreadable_ranges[0].file_path == "[vvar_vclock]"

    def test_skip_kernel_pseudo_filter_skips_the_region(self, tmp_path: Path):
        data = b"\xaa" * PAGE
        ranges = [
            MemoryRange(base=BASE, size=PAGE, protection="r--",
                        file_path="[vvar_vclock]"),
            MemoryRange(base=0x20000, size=PAGE, protection="rw-",
                        file_path=""),
        ]
        bridge = MockBridge(ranges=ranges, modules=[], memory={0x20000: data})
        engine = AcquisitionEngine(
            bridge, region_filter=RegionFilter(skip_kernel_pseudo=True),
        )

        result = engine.acquire(tmp_path / "dump.msl")

        assert result.regions_skipped == 1
        assert result.skip_reasons["kernel-pseudo"] == 1
        assert result.regions_captured == 1
        assert result.pages_expected_unreadable == 0


class ShortReadBridge(MockBridge):
    """A MockBridge that answers every read with fewer bytes than requested.

    Real backends do this: GDB bisects around unreadable holes and LLDB's
    ``ReadMemory`` can stop at the first bad cache line, both without saying
    the read failed. The engine must record only the pages it actually got.

    Attributes:
        returned: Bytes handed back per read, however much was asked for.
    """

    def __init__(self, returned: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.returned = returned

    def read_memory(self, address: int, size: int) -> bytes | None:
        return b"\xa5" * min(self.returned, size)


class TestShortReadAccounting:
    """A backend returning fewer bytes than asked for is never recorded as a
    fully captured span."""

    def test_short_read_marks_only_the_returned_pages(self):
        bridge = ShortReadBridge(returned=3 * PAGE)

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.CAPTURED, 3), (PageState.FAILED, REGION_PAGES - 3),
        )
        assert data_size == 3 * PAGE

    def test_partial_page_still_claims_only_one_page(self):
        """A read stopping mid-page captures that page and nothing beyond."""
        bridge = ShortReadBridge(returned=PAGE + 100)

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        assert region.page_states == _states(
            (PageState.CAPTURED, 2), (PageState.FAILED, REGION_PAGES - 2),
        )
        assert data_size == PAGE + 100

    def test_short_read_in_a_chunked_region(self):
        """The same accounting applies to each chunk of an oversized region."""
        bridge = ShortReadBridge(returned=PAGE)
        engine = AcquisitionEngine(bridge, max_chunk_size=4 * PAGE)

        region, data_size = engine._read_region(
            BASE, REGION_SIZE, 0x03, "", PAGE,
        )

        # One captured page at the head of each of the four chunks.
        assert region.page_states == _states(
            (PageState.CAPTURED, 1), (PageState.FAILED, 3),
        ) * 4
        assert data_size == 4 * PAGE

    def test_captured_page_count_matches_the_data_written(self):
        """Page states and payload stay in step, so bytes are never placed at
        an offset the state map does not claim."""
        bridge = ShortReadBridge(returned=5 * PAGE)

        region, data_size = _read_span(bridge, BASE, REGION_SIZE)

        captured = region.page_states.count(PageState.CAPTURED)
        assert sum(len(c) for c in region.page_data_chunks) == data_size
        assert captured * PAGE >= data_size > (captured - 1) * PAGE


# ---------------------------------------------------------------------------
# Assumed page size provenance
# ---------------------------------------------------------------------------


def _system_context_os_detail(raw: bytes) -> str:
    """Return the packed ``OSDetail`` string from a capture's SystemContext."""
    blocks = _parse_blocks(raw)
    payload = _find_block(blocks, BlockType.SystemContext)
    assert payload is not None, "SystemContext block not found"

    # Fixed 32-byte header; the length fields start at offset 13.
    acq_user_len, hostname_len, domain_len, _os_detail_len, _case_ref_len = (
        struct.unpack_from("<HHHHH", payload, 13)
    )
    offset = 32
    for length in (acq_user_len, hostname_len, domain_len):
        if length > 0:
            _value, offset = _read_padded_string(payload, offset)
    os_detail, _offset = _read_padded_string(payload, offset)
    return os_detail


def _capture_collector_warnings(
    tmp_path: Path,
    *,
    page_size_assumed: bool,
    collector: MockCollector | None = None,
) -> list[str]:
    """Acquire an investigation-mode slice and return its collector warnings.

    The warnings are read back out of the finished file rather than off the
    engine, so the assertion covers everything between the bridge and the
    bytes an analyst opens.
    """
    from memslicer.acquirer.os_detail import parse_os_detail

    data = b"\xaa" * 4096
    ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
    bridge = MockBridge(
        ranges=ranges,
        modules=[],
        memory={0x10000: data},
        platform_info=PlatformInfo(
            arch=ArchType.x86_64,
            os=OSType.Linux,
            pid=1234,
            page_size=4096,
            page_size_assumed=page_size_assumed,
        ),
    )
    engine = AcquisitionEngine(
        bridge, investigation=True, collector=collector or MockCollector(),
    )
    output = tmp_path / "dump.msl"
    engine.acquire(output)

    os_detail = _system_context_os_detail(output.read_bytes())
    warning = parse_os_detail(os_detail).get("collector_warning", "")
    return [w for w in warning.split(",") if w]


class TestAssumedPageSizeWarning:
    """A capture whose page size was guessed must not read as one where the
    page size was known.

    Nothing else in the file can tell the two apart: ``PageSizeLog2`` and the
    page-state map agree with each other either way, so a 16K-page target
    recorded with a guessed 4K page size produces a self-consistent, wrong
    slice. The warning is the only surviving trace of the doubt.
    """

    def test_guessed_page_size_is_recorded_in_the_capture(self, tmp_path: Path):
        """A slice taken from a bridge that could not learn the page size
        arrives without any sign that the page size was a default."""
        warnings = _capture_collector_warnings(tmp_path, page_size_assumed=True)

        assert "page_size_assumed_4k" in warnings

    def test_known_page_size_is_not_flagged(self, tmp_path: Path):
        """A slice from a bridge that did learn the page size carries a doubt
        marker anyway, so analysts cannot trust the marker to mean anything."""
        warnings = _capture_collector_warnings(tmp_path, page_size_assumed=False)

        assert "page_size_assumed_4k" not in warnings

    def test_guessed_page_size_does_not_displace_collector_warnings(
        self, tmp_path: Path,
    ):
        """The page-size doubt overwrites what the collector had already
        reported, so an operator loses the host-side warnings."""
        collector = MockCollector()
        collector.system_info.collector_warnings = [
            "hidepid_active", "kallsyms_restricted",
        ]

        warnings = _capture_collector_warnings(
            tmp_path, page_size_assumed=True, collector=collector,
        )

        assert "hidepid_active" in warnings
        assert "kallsyms_restricted" in warnings
        assert "page_size_assumed_4k" in warnings
