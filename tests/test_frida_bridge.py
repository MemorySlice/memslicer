"""Tests for the FridaBridge debugger bridge."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.msl.constants import ArchType, OSType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bridge(target=1234, device=None):
    """Create a FridaBridge instance without importing frida at module level."""
    from memslicer.acquirer.frida_bridge import FridaBridge

    return FridaBridge(
        target=target,
        device=device,
        read_timeout=5.0,
        logger=MagicMock(),
    )


def _prepare_mock_frida_module():
    """Return a mock ``frida`` package suitable for ``sys.modules``."""
    mock_frida = MagicMock()
    mock_frida.get_local_device.return_value = MagicMock()
    return mock_frida


def _setup_device_and_api(bridge, device=None):
    """Wire up a mock device/session/api and run connect().

    Returns (device, api) so the caller can set up return values and assert.
    """
    mock_frida = _prepare_mock_frida_module()

    mock_device = device or MagicMock()
    mock_session = MagicMock()
    mock_script = MagicMock()
    mock_api = MagicMock()

    mock_device.attach.return_value = mock_session
    mock_session.create_script.return_value = mock_script
    mock_script.exports_sync = mock_api

    # Defaults for connect() calls
    mock_api.validate_api.return_value = {
        "ptrType": "function",
        "readByteArrayType": "function",
        "pageSize": 4096,
    }
    mock_api.get_arch.return_value = "x64"
    mock_api.get_platform.return_value = "linux"
    mock_api.enumerate_modules.return_value = [
        {"name": "libc.so.6", "path": "/usr/lib/libc.so.6"},
    ]
    mock_api.get_page_size.return_value = 4096
    mock_api.get_pid.return_value = 5678

    bridge._device = mock_device

    with patch.dict(sys.modules, {"frida": mock_frida}):
        bridge.connect()

    return mock_device, mock_api


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFridaBridgeConnect:
    """Tests for FridaBridge.connect()."""

    def test_connect_attaches_to_pid(self):
        """When target is an int, device.attach is called with that PID."""
        bridge = _make_bridge(target=1234)
        device, _api = _setup_device_and_api(bridge)

        device.attach.assert_called_once_with(1234)

    def test_connect_attaches_by_name(self):
        """When target is a string, device.attach is called with the name
        and get_pid is invoked to resolve the numeric PID."""
        bridge = _make_bridge(target="my_process")
        device, api = _setup_device_and_api(bridge)

        device.attach.assert_called_once_with("my_process")
        api.get_pid.assert_called_once()

    def test_get_platform_info(self):
        """After connect(), get_platform_info returns a valid PlatformInfo."""
        bridge = _make_bridge(target=1234)
        _device, _api = _setup_device_and_api(bridge)

        info = bridge.get_platform_info()

        assert isinstance(info, PlatformInfo)
        assert info.arch == ArchType.x86_64
        assert info.os == OSType.Linux
        assert info.pid == 1234
        assert info.page_size == 4096


class TestFridaBridgeEnumerateRanges:
    """Tests for FridaBridge.enumerate_ranges()."""

    def test_enumerate_ranges_converts_frida_dicts(self):
        """Frida-style range dicts (hex-string base, file dict) are converted
        into MemoryRange dataclasses."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        api.enumerate_ranges.return_value = [
            {
                "base": "0x10000",
                "size": 4096,
                "protection": "r--",
                "file": {"path": "/usr/lib/libc.so.6", "offset": 0, "size": 4096},
            },
            {
                "base": "0x20000",
                "size": 8192,
                "protection": "rw-",
                "file": None,
            },
        ]

        ranges = bridge.enumerate_ranges()

        assert len(ranges) == 2

        assert ranges[0].base == 0x10000
        assert ranges[0].size == 4096
        assert ranges[0].protection == "r--"
        assert ranges[0].file_path == "/usr/lib/libc.so.6"

        assert ranges[1].base == 0x20000
        assert ranges[1].size == 8192
        assert ranges[1].protection == "rw-"
        assert ranges[1].file_path == ""


class TestFridaBridgeEnumerateModules:
    """Tests for FridaBridge.enumerate_modules()."""

    def test_enumerate_modules_converts(self):
        """Module dicts are converted into ModuleInfo dataclasses."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        # Clear cache from connect() so we can test with custom data
        bridge._modules_cache = None
        api.enumerate_modules.return_value = [
            {
                "name": "libc.so.6",
                "base": "0x10000",
                "size": 0x10000,
                "path": "/usr/lib/libc.so.6",
            },
            {
                "name": "app",
                "base": "0x400000",
                "size": 0x1000,
                "path": "/home/user/app",
            },
        ]

        modules = bridge.enumerate_modules()

        assert len(modules) == 2

        assert modules[0].name == "libc.so.6"
        assert modules[0].base == 0x10000
        assert modules[0].size == 0x10000
        assert modules[0].path == "/usr/lib/libc.so.6"

        assert modules[1].name == "app"
        assert modules[1].base == 0x400000
        assert modules[1].size == 0x1000


class TestFridaBridgeReadMemory:
    """Tests for FridaBridge.read_memory()."""

    def test_read_memory_success(self):
        """Successful read returns the raw bytes from the API."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        expected = b"\xde\xad\xbe\xef"
        api.read_memory.return_value = expected

        result = bridge.read_memory(0x10000, 4)

        api.read_memory.assert_called_once_with("0x10000", 4)
        assert result == expected

    def test_read_memory_failure(self):
        """When the API returns None, read_memory returns None."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        api.read_memory.return_value = None

        result = bridge.read_memory(0x10000, 4)

        assert result is None

    def test_read_memory_exception(self):
        """When the API raises, read_memory catches it and returns None."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        api.read_memory.side_effect = RuntimeError("access violation")

        result = bridge.read_memory(0x10000, 4)

        assert result is None


class TestFridaBridgeDisconnect:
    """Tests for FridaBridge.disconnect()."""

    def test_disconnect(self):
        """Disconnect calls session.detach()."""
        bridge = _make_bridge(target=1234)
        _device, _api = _setup_device_and_api(bridge)

        session = bridge._session
        bridge.disconnect()

        session.detach.assert_called_once()
        assert bridge._session is None
