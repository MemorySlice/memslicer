"""Tests for Frida acquirer with mocked Frida session."""
import io
import logging
import logging.handlers
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import frida
import pytest

from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE,
    BlockType,
)
from memslicer.acquirer.frida_acquirer import (
    FridaAcquirer, _classify_region, _ensure_bytes, _volatility_key,
)
from memslicer.acquirer.base import AcquireResult
from memslicer.utils.protection import parse_protection as _parse_protection
from memslicer.msl.constants import RegionType


class TestParseProtection:
    def test_rwx(self):
        assert _parse_protection("rwx") == 7

    def test_read_only(self):
        assert _parse_protection("r--") == 1

    def test_read_write(self):
        assert _parse_protection("rw-") == 3

    def test_read_execute(self):
        assert _parse_protection("r-x") == 5

    def test_none(self):
        assert _parse_protection("---") == 0


class TestClassifyRegion:
    def test_none(self):
        assert _classify_region(None) == RegionType.Anon

    def test_empty_path(self):
        assert _classify_region({"path": ""}) == RegionType.Anon

    def test_heap(self):
        assert _classify_region({"path": "[heap]"}) == RegionType.Heap

    def test_stack(self):
        assert _classify_region({"path": "[stack]"}) == RegionType.Stack

    def test_shared_object(self):
        assert _classify_region({"path": "/usr/lib/libc.so"}) == RegionType.Image

    def test_dylib(self):
        assert _classify_region({"path": "/usr/lib/libSystem.dylib"}) == RegionType.Image

    def test_mapped_file(self):
        assert _classify_region({"path": "/tmp/data.bin"}) == RegionType.MappedFile


class TestFridaAcquirerIntegration:
    """Test FridaAcquirer with fully mocked Frida."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_acquire_produces_valid_msl(self, mock_frida, tmp_path):
        # Setup mock device and session
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        api.enumerate_ranges.return_value = [
            {
                "base": "0x10000",
                "size": 4096,
                "protection": "r--",
                "file": {"path": "/lib/libc.so"},
            },
        ]
        api.enumerate_modules.return_value = [
            {"name": "libc.so", "base": "0x10000", "size": 0x10000, "path": "/lib/libc.so"},
        ]
        api.read_memory.return_value = b'\xcc' * 4096

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert isinstance(result, AcquireResult)
        assert result.regions_captured >= 1
        assert not result.aborted

        data = output.read_bytes()

        # Verify basic structure
        assert data[:8] == FILE_MAGIC
        assert data[HEADER_SIZE:HEADER_SIZE + 4] == BLOCK_MAGIC

        # Should have blocks: MemoryRegion + ModuleListIndex + ModuleEntry + EoC
        blocks = []
        offset = HEADER_SIZE
        while offset < len(data):
            assert data[offset:offset + 4] == BLOCK_MAGIC
            block_type = struct.unpack_from("<H", data, offset + 4)[0]
            block_len = struct.unpack_from("<I", data, offset + 8)[0]
            blocks.append(block_type)
            offset += block_len

        assert BlockType.MemoryRegion in blocks
        assert BlockType.ModuleListIndex in blocks
        assert BlockType.ModuleEntry in blocks
        assert blocks[-1] == BlockType.EndOfCapture

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_progress_callback(self, mock_frida, tmp_path):
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "r--", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)

        progress_calls = []
        acquirer.set_progress_callback(
            lambda r, t, b, m, p: progress_calls.append((r, t, b, m, p))
        )
        acquirer.acquire(output)

        assert len(progress_calls) >= 1
        assert progress_calls[-1][0] >= 1  # at least 1 region

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_abort_mid_acquisition(self, mock_frida, tmp_path):
        """Test that aborting mid-acquisition produces a partial but valid MSL."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "r--", "file": None},
            {"base": "0x20000", "size": 4096, "protection": "rw-", "file": None},
            {"base": "0x30000", "size": 4096, "protection": "r-x", "file": None},
        ]
        api.enumerate_modules.return_value = []

        output = tmp_path / "aborted.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)

        call_count = 0

        def read_and_maybe_abort(addr, size):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                acquirer.request_abort()
            return b'\xaa' * size

        api.read_memory.side_effect = read_and_maybe_abort

        result = acquirer.acquire(output)

        assert result.aborted is True
        assert result.regions_captured < result.regions_total

        # Verify the output is still a valid MSL file (has FILE_MAGIC header)
        data = output.read_bytes()
        assert data[:8] == FILE_MAGIC


class TestChunkedReading:
    """Test chunked reading for large regions."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_large_region_split_into_chunks(self, mock_frida, tmp_path):
        """Regions larger than max_chunk_size get split into chunks."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        # Region of 256KB, but set max_chunk to 64KB → should split into 4 chunks
        region_size = 256 * 1024
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": region_size, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        # All reads succeed
        api.read_memory.side_effect = lambda addr, size: b'\xaa' * size

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(
            target=1234, device=mock_device, max_chunk_size=64 * 1024,
        )
        result = acquirer.acquire(output)

        assert result.regions_captured == 1
        assert result.bytes_captured == region_size
        # Should have been called 4 times (4 chunks of 64KB)
        assert api.read_memory.call_count == 4

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_partial_chunk_failures(self, mock_frida, tmp_path):
        """Some chunks succeed, some fail within a large region."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        # 2 pages, max_chunk=4096 so each page is a separate chunk
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 8192, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        # Call sequence:
        # 1: startup test read → succeed
        # 2: chunk 1 (0x10000) → succeed
        # 3: chunk 2 (0x11000) → fail
        # 4: page-by-page fallback for chunk 2 → fail
        call_count = 0

        def mock_read(addr, size):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return b'\xaa' * size
            return None
        api.read_memory.side_effect = mock_read

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(
            target=1234, device=mock_device, max_chunk_size=4096,
        )
        result = acquirer.acquire(output)

        assert result.regions_captured == 1
        assert result.bytes_captured == 4096  # only first chunk


class TestSignalHandling:
    """Test abort and session detach behavior."""

    def test_request_abort_detaches_session(self):
        """request_abort() should set abort event and detach session."""
        mock_device = MagicMock()
        acquirer = FridaAcquirer(target=1234, device=mock_device)

        mock_session = MagicMock()
        acquirer._session = mock_session

        acquirer.request_abort()

        assert acquirer._abort.is_set()
        mock_session.detach.assert_called_once()

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_invalid_operation_error_treated_as_abort(self, mock_frida, tmp_path):
        """frida.InvalidOperationError should be caught gracefully."""
        # Expose the real exception class on the mock so except clause works
        mock_frida.InvalidOperationError = frida.InvalidOperationError

        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        # Simulate InvalidOperationError during enumerate_ranges
        api.enumerate_ranges.side_effect = frida.InvalidOperationError("session detached")
        api.enumerate_modules.return_value = []

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)

        # Should not raise
        result = acquirer.acquire(output)
        assert result.regions_captured == 0


class TestLogging:
    """Test verbose logging output."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_debug_logging_during_acquire(self, mock_frida, tmp_path):
        """Logger.debug should be called during acquisition."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        logger = logging.getLogger("memslicer.test_debug")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer.acquire(output)

        # Logger should have received debug messages
        assert handler.buffer  # at least some log records


class TestReadFailureHandling:
    """Test that read failures are handled gracefully."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_read_exception_caught(self, mock_frida, tmp_path):
        """Exceptions from read_memory should be caught, not propagated."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        # Read raises an exception
        api.read_memory.side_effect = RuntimeError("access violation")

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        # Should complete, region counted but 0 bytes captured
        assert result.regions_captured == 1
        assert result.bytes_captured == 0

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_all_reads_return_none(self, mock_frida, tmp_path):
        """When all reads return None, regions are still tracked (page-by-page also fails)."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None},
            {"base": "0x20000", "size": 4096, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = None

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert result.regions_captured == 2
        assert result.bytes_captured == 0


class TestOnMessageDiagnostics:
    """Test JS agent error message handling (Change 1)."""

    def test_on_message_logs_read_error(self):
        """read-error messages from JS agent are logged at WARNING level."""
        mock_device = MagicMock()
        logger = logging.getLogger("memslicer.test_on_message")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer._on_message(
            {
                "type": "send",
                "payload": {
                    "type": "read-error",
                    "addr": "0x10000",
                    "size": 4096,
                    "error": "access violation reading 0x10000",
                    "stack": "Error\n    at readMemory (script.js:5)",
                },
            },
            None,
        )

        warning_records = [r for r in handler.buffer if r.levelno == logging.WARNING]
        assert len(warning_records) == 1
        assert "access violation" in warning_records[0].getMessage()

    def test_on_message_logs_script_error(self):
        """Script error messages are logged at ERROR level."""
        mock_device = MagicMock()
        logger = logging.getLogger("memslicer.test_on_message_err")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer._on_message(
            {"type": "error", "description": "ReferenceError: foo is not defined"},
            None,
        )

        error_records = [r for r in handler.buffer if r.levelno == logging.ERROR]
        assert len(error_records) == 1
        assert "ReferenceError" in error_records[0].getMessage()

    def test_on_message_ignores_unknown(self):
        """Unknown message types don't crash."""
        mock_device = MagicMock()
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        # Should not raise
        acquirer._on_message({"type": "unknown", "payload": "stuff"}, None)

    def test_on_message_logs_stack_trace_at_debug(self):
        """read-error messages with a stack field log the JS stack at DEBUG level."""
        mock_device = MagicMock()
        logger = logging.getLogger("memslicer.test_stack_trace")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer._on_message(
            {
                "type": "send",
                "payload": {
                    "type": "read-error",
                    "addr": "0x10000",
                    "size": 4096,
                    "error": "access violation reading 0x10000",
                    "stack": "Error\n    at readMemory (script.js:5)",
                },
            },
            None,
        )

        debug_records = [r for r in handler.buffer if r.levelno == logging.DEBUG]
        assert any("JS stack:" in r.getMessage() for r in debug_records)

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_script_on_message_registered(self, mock_frida, tmp_path):
        """script.on('message', ...) is called during acquire."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.enumerate_ranges.return_value = []
        api.enumerate_modules.return_value = []

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        acquirer.acquire(output)

        mock_script.on.assert_called_once_with('message', acquirer._on_message)


class TestStartupTestRead:
    """Test startup test read (Change 2)."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_startup_read_success_logged(self, mock_frida, tmp_path):
        """Successful startup test read is logged at INFO."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "r--", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\xaa' * 4096

        logger = logging.getLogger("memslicer.test_startup_ok")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer.acquire(output)

        info_msgs = [r.getMessage() for r in handler.buffer if r.levelno == logging.INFO]
        assert any("Startup test read OK" in m for m in info_msgs)

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_startup_read_failure_warned(self, mock_frida, tmp_path):
        """Failed startup test read is logged at WARNING."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "r--", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = None

        logger = logging.getLogger("memslicer.test_startup_fail")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer.acquire(output)

        warn_msgs = [r.getMessage() for r in handler.buffer if r.levelno == logging.WARNING]
        assert any("Startup test read FAILED" in m for m in warn_msgs)

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_startup_read_skips_large_regions(self, mock_frida, tmp_path):
        """Startup test read skips regions larger than 4 * page_size."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        # Only large regions — no small ones for test read
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 1024 * 1024, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * (1024 * 1024)

        logger = logging.getLogger("memslicer.test_startup_skip")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        acquirer.acquire(output)

        warn_msgs = [r.getMessage() for r in handler.buffer if r.levelno == logging.WARNING]
        assert any("No small readable region" in m for m in warn_msgs)


class TestPageByPageFallback:
    """Test page-by-page fallback read strategy (Change 3)."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_fallback_captures_partial_pages(self, mock_frida, tmp_path):
        """When full read fails, page-by-page fallback captures individual pages."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        # Region of 2 pages
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 8192, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        call_count = 0

        def mock_read(addr, size):
            nonlocal call_count
            call_count += 1
            # First call is the startup test read (0x10000, but region is
            # too large for startup test at 8192 > 4*4096=16384... actually
            # 8192 < 16384, so it WILL be used for startup test)
            # Call 1: startup test read (4096 bytes) — succeeds
            # Call 2: full region read (8192 bytes) — fails
            # Calls 3-4: page-by-page fallback — page 1 succeeds, page 2 fails
            if call_count == 1:
                return b'\xbb' * size  # startup test
            if call_count == 2:
                return None  # full region fails
            if call_count == 3:
                return b'\xaa' * size  # page 1 succeeds
            return None  # page 2 fails

        api.read_memory.side_effect = mock_read

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert result.regions_captured == 1
        assert result.bytes_captured == 4096  # only 1 of 2 pages

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_fallback_in_chunked_path(self, mock_frida, tmp_path):
        """Page-by-page fallback also works when a chunk fails in the chunked path."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}

        # 3 pages, max_chunk=8192 → chunk1 (2 pages), chunk2 (1 page)
        region_size = 3 * 4096
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": region_size, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        call_count = 0

        def mock_read(addr, size):
            nonlocal call_count
            call_count += 1
            # Call 1: startup test (region is 12288 > 16384? No, 12288 < 16384)
            # So startup test will try this region
            if call_count == 1:
                return b'\xbb' * size  # startup test succeeds
            # Call 2: chunk 1 (8192 bytes) — fails
            if call_count == 2:
                return None
            # Calls 3-4: page-by-page for chunk 1 — both succeed
            if call_count in (3, 4):
                return b'\xaa' * size
            # Call 5: chunk 2 (4096 bytes) — succeeds
            if call_count == 5:
                return b'\xcc' * size
            return None

        api.read_memory.side_effect = mock_read

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(
            target=1234, device=mock_device, max_chunk_size=8192,
        )
        result = acquirer.acquire(output)

        assert result.regions_captured == 1
        assert result.bytes_captured == region_size  # all 3 pages captured


class TestAddressNormalization:
    """Test address format normalization (Change 4)."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_int_address_normalized_to_hex(self, mock_frida, tmp_path):
        """Integer addresses are converted to hex strings for Frida RPC."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.enumerate_ranges.return_value = []
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        acquirer = FridaAcquirer(target=1234, device=mock_device)

        # Call _try_read with an int address — should normalize to hex
        result = acquirer._try_read(api, 0x10000, 4096)

        # Verify read_memory was called with a hex string, not an int
        api.read_memory.assert_called_once_with("0x10000", 4096)


class TestVolatilityOrdering:
    """Test volatility-first region sorting."""

    def test_rw_anon_first(self):
        """rw- anonymous regions should sort before r-- mapped files."""
        rw_anon = {"base": "0x20000", "size": 4096, "protection": "rw-", "file": None}
        ro_mapped = {"base": "0x10000", "size": 4096, "protection": "r--", "file": {"path": "/lib/libc.so"}}
        assert _volatility_key(rw_anon) < _volatility_key(ro_mapped)

    def test_rwx_before_rx(self):
        """rwx regions should sort before r-x regions."""
        rwx = {"base": "0x30000", "size": 4096, "protection": "rwx", "file": None}
        rx = {"base": "0x10000", "size": 4096, "protection": "r-x", "file": {"path": "/lib/libc.so"}}
        assert _volatility_key(rwx) < _volatility_key(rx)

    def test_rx_before_ro(self):
        """r-x regions should sort before r-- regions."""
        rx = {"base": "0x10000", "size": 4096, "protection": "r-x", "file": {"path": "/lib/libc.so"}}
        ro = {"base": "0x20000", "size": 4096, "protection": "r--", "file": {"path": "/tmp/data.bin"}}
        assert _volatility_key(rx) < _volatility_key(ro)

    def test_same_tier_sorted_by_address(self):
        """Within the same volatility tier, sort by base address."""
        r1 = {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None}
        r2 = {"base": "0x20000", "size": 4096, "protection": "rw-", "file": None}
        assert _volatility_key(r1) < _volatility_key(r2)

    def test_heap_is_tier_zero(self):
        """Heap regions (rw-) should be tier 0."""
        heap = {"base": "0x10000", "size": 4096, "protection": "rw-", "file": {"path": "[heap]"}}
        assert _volatility_key(heap)[0] == 0

    def test_stack_is_tier_zero(self):
        """Stack regions (rw-) should be tier 0."""
        stack = {"base": "0x10000", "size": 4096, "protection": "rw-", "file": {"path": "[stack]"}}
        assert _volatility_key(stack)[0] == 0


class TestRWXDetection:
    """Test RWX region detection and counting."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_rwx_warning_logged(self, mock_frida, tmp_path):
        """RWX regions should trigger a WARNING-level log."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rwx", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        logger = logging.getLogger("memslicer.test_rwx_warn")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=1000)
        logger.addHandler(handler)

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device, logger=logger)
        result = acquirer.acquire(output)

        warn_msgs = [r.getMessage() for r in handler.buffer if r.levelno == logging.WARNING]
        assert any("RWX region" in m for m in warn_msgs)
        assert result.rwx_regions == 1

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_no_rwx_when_not_present(self, mock_frida, tmp_path):
        """Non-RWX regions should not trigger warnings or count."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert result.rwx_regions == 0


class TestPageLevelMetrics:
    """Test that page-level and byte-level metrics are tracked in AcquireResult."""

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_successful_read_tracks_pages(self, mock_frida, tmp_path):
        """Successful region reads track pages_captured."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 8192, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 8192

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert result.pages_captured == 2
        assert result.pages_failed == 0
        assert result.bytes_attempted == 8192
        assert result.bytes_captured == 8192

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_partial_failure_tracks_both(self, mock_frida, tmp_path):
        """Partial page failures track both captured and failed pages."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 8192, "protection": "rw-", "file": None},
        ]
        api.enumerate_modules.return_value = []

        call_count = 0
        def mock_read(addr, size):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return b'\xbb' * size  # startup test
            if call_count == 2:
                return None  # full region fails
            if call_count == 3:
                return b'\xaa' * size  # page 1 succeeds
            return None  # page 2 fails
        api.read_memory.side_effect = mock_read

        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device)
        result = acquirer.acquire(output)

        assert result.pages_captured == 1
        assert result.pages_failed == 1
        assert result.bytes_attempted == 8192

    @patch("memslicer.acquirer.frida_acquirer.frida")
    def test_skip_reasons_tracked(self, mock_frida, tmp_path):
        """Skip reasons are tracked in the result."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()
        api = MagicMock()

        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_script.exports_sync = api

        api.get_arch.return_value = "x64"
        api.get_platform.return_value = "linux"
        api.get_page_size.return_value = 4096
        api.get_pid.return_value = 1234
        api.validate_api.return_value = {"ptrType": "function", "readByteArrayType": "function", "pageSize": 4096}
        api.enumerate_ranges.return_value = [
            {"base": "0x10000", "size": 4096, "protection": "rw-", "file": None},
            {"base": "0x20000", "size": 4096, "protection": "---", "file": None},
            {"base": "0x30000", "size": 4096, "protection": "---", "file": None},
        ]
        api.enumerate_modules.return_value = []
        api.read_memory.return_value = b'\x00' * 4096

        from memslicer.acquirer.region_filter import RegionFilter
        output = tmp_path / "test.msl"
        acquirer = FridaAcquirer(target=1234, device=mock_device,
                                  region_filter=RegionFilter())
        result = acquirer.acquire(output)

        assert result.regions_skipped == 2
        assert result.skip_reasons.get("no-read") == 2
        assert result.bytes_attempted == 4096  # only the rw- region
