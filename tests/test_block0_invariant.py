"""Block 0 must be Process Identity, and the header must tell the truth.

Spec Section 5.4 gives Block 0 to Process Identity (0x0040) and to nothing
else on a live acquisition. Three separate defects used to break that promise
or the header that describes it, and each one is pinned here:

* a collector that raised left ``finally: writer.finalize()`` to put
  EndOfCapture in Block 0;
* the CapBitmap bits for the system tables were OR-ed in after the header had
  already been written, so they never reached disk;
* an over-long command line raised ``struct.error`` out of the uint16 length
  field and aborted the capture at Block 0.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.acquirer.investigation import TargetProcessInfo
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE, BLOCK_MAGIC, HEADER_SIZE, BlockType, CapBit,
)

from test_engine import MockBridge, MockCollector


CAP_BITMAP_OFFSET = 16
"""Byte offset of the 8-byte CapBitmap in the file header."""


def _block_types(path: Path) -> list[int]:
    """Return every block type in *path*, in file order."""
    raw = path.read_bytes()
    offset = HEADER_SIZE
    types: list[int] = []
    while offset + BLOCK_HEADER_SIZE <= len(raw):
        if raw[offset:offset + 4] != BLOCK_MAGIC:
            break
        block_type, _flags, block_length = struct.unpack_from("<HHI", raw, offset + 4)
        types.append(block_type)
        offset += block_length
    return types


def _cap_bitmap(path: Path) -> int:
    """Read the CapBitmap the file header actually carries."""
    return struct.unpack_from("<Q", path.read_bytes(), CAP_BITMAP_OFFSET)[0]


def _one_page_bridge() -> MockBridge:
    """A bridge with exactly one readable page and one module."""
    return MockBridge(
        ranges=[MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")],
        modules=[ModuleInfo(name="libc.so", path="/usr/lib/libc.so",
                            base=0x400000, size=0x10000)],
        memory={0x10000: b"\xaa" * 4096},
    )


class TestProcessIdentityIsBlockZero:
    """Block 0 is 0x0040 whether or not the optional pieces are present."""

    def test_plain_capture(self, tmp_path: Path):
        output = tmp_path / "dump.msl"
        AcquisitionEngine(_one_page_bridge()).acquire(output)
        assert _block_types(output)[0] == BlockType.ProcessIdentity

    def test_capture_without_modules(self, tmp_path: Path):
        """No module list must not shift Process Identity out of Block 0."""
        bridge = _one_page_bridge()
        bridge.modules = []
        output = tmp_path / "dump.msl"
        AcquisitionEngine(bridge).acquire(output)
        assert _block_types(output)[0] == BlockType.ProcessIdentity

    def test_investigation_capture(self, tmp_path: Path):
        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(_one_page_bridge(), investigation=True,
                                   collector=MockCollector())
        engine.acquire(output)
        types = _block_types(output)
        assert types[0] == BlockType.ProcessIdentity
        assert types[-1] == BlockType.EndOfCapture


class TestCollectorFailureLeavesNoMalformedSlice:
    """A raising collector must not yield a slice whose Block 0 is EoC."""

    def test_raising_collector_does_not_produce_eoc_as_block_zero(self, tmp_path: Path):
        class ExplodingCollector(MockCollector):
            def collect_process_identity(self, pid, **kwargs):
                raise OSError("target vanished mid-collect")

        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(_one_page_bridge(), collector=ExplodingCollector())

        with pytest.raises(OSError):
            engine.acquire(output)

        # The failure must surface before the file exists at all. If a file
        # was created anyway, Block 0 still may not be EndOfCapture.
        if output.exists():
            types = _block_types(output)
            assert types and types[0] != BlockType.EndOfCapture


class TestCapBitmapReachesDisk:
    """The header's CapBitmap must describe what the file actually holds."""

    def test_system_table_bits_are_written(self, tmp_path: Path):
        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(_one_page_bridge(), investigation=True,
                                   collector=MockCollector())
        engine.acquire(output)

        cap_bitmap = _cap_bitmap(output)
        for bit in (CapBit.SystemProcessTable,
                    CapBit.SystemNetworkTable,
                    CapBit.SystemHandleTable):
            assert cap_bitmap & (1 << bit), f"{bit.name} bit missing from header"

    def test_table_bits_absent_without_investigation(self, tmp_path: Path):
        output = tmp_path / "dump.msl"
        AcquisitionEngine(_one_page_bridge(), collector=MockCollector()).acquire(output)

        cap_bitmap = _cap_bitmap(output)
        for bit in (CapBit.SystemProcessTable,
                    CapBit.SystemNetworkTable,
                    CapBit.SystemHandleTable):
            assert not cap_bitmap & (1 << bit), f"{bit.name} set without -I"


class TestOversizedCommandLine:
    """A command line larger than the uint16 length field must not abort."""

    def test_huge_cmdline_is_truncated_not_fatal(self, tmp_path: Path):
        class HugeCmdlineCollector(MockCollector):
            def collect_process_identity(self, pid, **kwargs):
                return TargetProcessInfo(
                    ppid=1, session_id=1, start_time_ns=1,
                    exe_path="/usr/bin/target",
                    cmd_line="a" * 200_000,
                )

        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(_one_page_bridge(), collector=HugeCmdlineCollector())
        engine.acquire(output)  # used to raise struct.error

        raw = output.read_bytes()
        payload = HEADER_SIZE + BLOCK_HEADER_SIZE
        exe_len, cmd_len = struct.unpack_from("<HH", raw, payload + 0x10)
        assert cmd_len <= 0xFFFF
        assert _block_types(output)[0] == BlockType.ProcessIdentity

        # The stored bytes must still be decodable as the UTF-8 the spec says.
        cmd_offset = payload + 0x18 + ((exe_len + 7) & ~7)
        raw[cmd_offset:cmd_offset + cmd_len - 1].decode("utf-8")


class TestTableCollectionIsNotFatal:
    """A failing system table must cost that table, not the capture."""

    def test_raising_table_collector_still_yields_a_slice(self, tmp_path: Path):
        class BadConnectionCollector(MockCollector):
            def collect_connection_table(self):
                raise OSError("/proc/net/tcp unreadable")

        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(_one_page_bridge(), investigation=True,
                                   collector=BadConnectionCollector())
        engine.acquire(output)

        types = _block_types(output)
        assert types[0] == BlockType.ProcessIdentity
        assert types[-1] == BlockType.EndOfCapture

        # The bit for the table that failed must stay clear -- the header
        # may never claim a table the file does not carry.
        cap_bitmap = _cap_bitmap(output)
        assert not cap_bitmap & (1 << CapBit.SystemNetworkTable)
        assert cap_bitmap & (1 << CapBit.SystemProcessTable)
        assert cap_bitmap & (1 << CapBit.SystemHandleTable)


class TestExtensionBlockCollectionIsNotFatal:
    """A failing extension-block collector must cost that block, not the
    capture. These run while the writer is open, so an unguarded raise
    used to leave a truncated slice with no EndOfCapture."""

    @staticmethod
    def _system_context_table_bitmap(path: Path) -> int:
        from test_engine import _find_block, _parse_blocks

        payload = _find_block(_parse_blocks(path.read_bytes()), BlockType.SystemContext)
        assert payload is not None, "SystemContext block not found"
        # boot_time(8) + target_count(1) precede the 4-byte table_bitmap.
        return struct.unpack_from("<I", payload, 9)[0]

    def _acquire(self, tmp_path: Path, collector, **attribution_kwargs) -> Path:
        from memslicer.acquirer.identity import AttributionConfig

        output = tmp_path / "dump.msl"
        engine = AcquisitionEngine(
            _one_page_bridge(), investigation=True, collector=collector,
            attribution=AttributionConfig(**attribution_kwargs),
        )
        engine.acquire(output)
        types = _block_types(output)
        assert types[0] == BlockType.ProcessIdentity
        assert types[-1] == BlockType.EndOfCapture
        return output

    def test_raising_connectivity_collector_leaves_bit_3_clear(self, tmp_path: Path):
        class BadConnectivityCollector(MockCollector):
            def collect_connectivity_table(self, **kwargs):
                raise OSError("/proc/net/snmp unreadable")

        output = self._acquire(tmp_path, BadConnectivityCollector())

        assert BlockType.ConnectivityTable not in _block_types(output)
        assert not self._system_context_table_bitmap(output) & 0x08

    def test_raising_persistence_collector_leaves_bit_6_clear(self, tmp_path: Path):
        class BadPersistenceCollector(MockCollector):
            def collect_persistence_manifest(self, **kwargs):
                raise PermissionError("/etc unreadable")

        output = self._acquire(
            tmp_path, BadPersistenceCollector(), include_persistence_manifest=True,
        )

        assert BlockType.PersistenceManifest not in _block_types(output)
        assert not self._system_context_table_bitmap(output) & 0x40

    def test_collected_empty_persistence_manifest_still_sets_bit_6(self, tmp_path: Path):
        """The opposite case pins the distinction: an empty manifest that was
        actually collected is a positive signal and keeps its block."""
        output = self._acquire(
            tmp_path, MockCollector(), include_persistence_manifest=True,
        )

        assert BlockType.PersistenceManifest in _block_types(output)
        assert self._system_context_table_bitmap(output) & 0x40

    def test_raising_system_info_collector_records_a_warning(self, tmp_path: Path):
        from memslicer.acquirer.os_detail import parse_os_detail
        from test_engine import _system_context_os_detail

        class BadSystemInfoCollector(MockCollector):
            def collect_system_info(self):
                raise OSError("uname failed")

        output = self._acquire(tmp_path, BadSystemInfoCollector())

        os_detail = parse_os_detail(_system_context_os_detail(output.read_bytes()))
        warnings = os_detail.get("collector_warning", "").split(",")
        assert "system_info_collection_failed" in warnings
