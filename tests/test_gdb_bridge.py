"""Tests for the GDBBridge debugger bridge."""
from __future__ import annotations

import queue
import re
import threading
from unittest.mock import MagicMock, mock_open, patch

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.gdb_bridge import GDBBridge
from memslicer.acquirer.platform_detect import parse_gdb_architecture as _parse_gdb_architecture
from memslicer.msl.constants import ArchType


# ---------------------------------------------------------------------------
# Tests -- construction
# ---------------------------------------------------------------------------

class TestGDBBridgeInit:
    """Tests for GDBBridge.__init__()."""

    def test_target_must_be_int(self):
        """Passing a string target raises TypeError."""
        with pytest.raises(TypeError, match="numeric PID"):
            GDBBridge(target="my_app")


# ---------------------------------------------------------------------------
# Tests -- read_memory
# ---------------------------------------------------------------------------

class TestGDBBridgeReadMemory:
    """Tests for GDBBridge.read_memory()."""

    def test_read_memory_parses_hex_response(self):
        """A successful MI response with contents=\"...\" is parsed to bytes."""
        bridge = GDBBridge(target=1234, logger=MagicMock())

        # Simulate the MI command returning hex content.
        mi_response = (
            '^done,addr="0x10000",nr-bytes="4",'
            'total-bytes="4",next-row="0x10004",'
            'prev-row="0x0fffc",next-page="0x10004",'
            'prev-page="0x0fffc",'
            'memory=[{begin="0x10000",offset="0x0",'
            'end="0x10004",contents="deadbeef"}]'
        )
        bridge._send_mi_command = MagicMock(return_value=mi_response)

        result = bridge.read_memory(0x10000, 4)

        assert result == bytes.fromhex("deadbeef")
        bridge._send_mi_command.assert_called_once_with(
            "-data-read-memory-bytes 0x10000 4"
        )

    def test_read_memory_returns_none_on_error(self):
        """When the MI command raises RuntimeError, None is returned."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock(
            side_effect=RuntimeError("GDB/MI error: Cannot access memory")
        )

        result = bridge.read_memory(0xDEAD, 8)

        assert result is None


# ---------------------------------------------------------------------------
# Tests -- enumerate_ranges
# ---------------------------------------------------------------------------

class TestGDBBridgeEnumerateRanges:
    """Tests for GDBBridge.enumerate_ranges()."""

    def test_enumerate_ranges_parses_proc_maps(self):
        """Ranges are correctly parsed from /proc/<pid>/maps content."""
        bridge = GDBBridge(target=42, logger=MagicMock())

        maps_content = (
            "00400000-00452000 r-xp 00000000 08:01 12345  /usr/bin/app\n"
            "7f000000-7f001000 rw-p 00000000 00:00 0      [heap]\n"
            "7ffff000-80000000 r--p 00000000 08:01 99999  /usr/lib/libc.so.6\n"
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=maps_content)):
            ranges = bridge.enumerate_ranges()

        assert len(ranges) == 3

        r0 = ranges[0]
        assert r0.base == 0x00400000
        assert r0.size == 0x00452000 - 0x00400000
        assert r0.protection == "r-x"
        assert r0.file_path == "/usr/bin/app"

        r1 = ranges[1]
        assert r1.base == 0x7F000000
        assert r1.size == 0x1000
        assert r1.protection == "rw-"
        assert r1.file_path == "[heap]"


# ---------------------------------------------------------------------------
# Tests -- _parse_gdb_architecture
# ---------------------------------------------------------------------------

class TestParseGdbArchitecture:
    """Tests for the module-level _parse_gdb_architecture helper."""

    @pytest.mark.parametrize(
        "text, expected",
        [
            ('The target architecture is set to "i386".', ArchType.x86),
            ('The target architecture is set to "auto" (currently "i386:x86-64").', ArchType.x86_64),
            ('The target architecture is set to "aarch64".', ArchType.ARM64),
            ('The target architecture is set to "arm".', ArchType.ARM32),
        ],
    )
    def test_platform_detect(self, text: str, expected: ArchType):
        """Various GDB architecture output strings are mapped correctly."""
        result = _parse_gdb_architecture(text)
        assert result == expected

    def test_unknown_architecture_raises(self):
        """An unrecognised architecture string raises ValueError."""
        with pytest.raises(ValueError, match="Cannot parse GDB architecture"):
            _parse_gdb_architecture("something totally unknown")


# ---------------------------------------------------------------------------
# Tests -- MI command timeout
# ---------------------------------------------------------------------------

class TestMICommandTimeout:
    """Tests for _send_mi_command timeout and process-death handling."""

    def test_mi_command_timeout(self):
        """TimeoutError raised when GDB never sends a result record."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=0.2)

        # Set up a mock process with stdin that accepts writes
        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        mock_proc.poll.return_value = None
        bridge._proc = mock_proc

        # Empty queue — no lines will ever arrive
        bridge._line_queue = queue.Queue()

        with pytest.raises(TimeoutError, match="did not respond"):
            bridge._send_mi_command("-some-command")

    def test_mi_command_process_died(self):
        """RuntimeError raised when GDB process exits mid-command."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=5.0)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc

        # Simulate reader thread signalling EOF (process died)
        bridge._line_queue = queue.Queue()
        bridge._line_queue.put(None)

        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            bridge._send_mi_command("-some-command")

    def test_mi_command_succeeds_with_queue(self):
        """Normal operation: result record arrives via queue."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=5.0)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc

        bridge._line_queue = queue.Queue()
        bridge._line_queue.put("~\"some console output\"")
        bridge._line_queue.put("^done")

        result = bridge._send_mi_command("-some-command")
        assert "^done" in result

    def test_read_memory_returns_none_on_timeout(self):
        """read_memory gracefully returns None when MI times out."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=0.1)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc
        bridge._line_queue = queue.Queue()

        result = bridge.read_memory(0x1000, 4096)
        assert result is None
