"""Tests for AcquisitionEngine with a MockBridge."""
from __future__ import annotations

import struct
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from memslicer.acquirer.base import AcquireResult
from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.acquirer.engine import AcquisitionEngine, classify_region, volatility_key
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, HEADER_SIZE, OSType, RegionType,
    BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, FLAG_INVESTIGATION,
)
from memslicer.msl.types import ProcessEntry, ConnectionEntry, HandleEntry


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

    def collect_process_identity(self, pid):
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
        # boot_time(8) + target_count(4) + table_bitmap(4)
        # + acq_user_len(2) + hostname_len(2) + domain_len(2) + os_detail_len(2)
        # + case_ref_len(2) + reserved(6)
        boot_time, target_count, table_bitmap = struct.unpack_from("<QII", payload, 0)
        acq_user_len, hostname_len, domain_len, os_detail_len, case_ref_len = struct.unpack_from(
            "<HHHHH", payload, 16,
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

        # table_bitmap is at offset 12 in the 32-byte fixed header
        _boot_time, _target_count, table_bitmap = struct.unpack_from("<QII", payload, 0)
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
