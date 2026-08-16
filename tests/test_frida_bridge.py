"""Tests for the FridaBridge debugger bridge."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from memslicer.acquirer.bridge import PlatformInfo
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


def _prepare_device_and_api(bridge, device=None):
    """Wire a mock device/session/script/api onto *bridge* without connecting.

    Returns (device, api) so the caller can stub RPCs before ``connect()``.
    """
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
    return mock_device, mock_api


def _setup_device_and_api(bridge, device=None):
    """Wire up a mock device/session/api and run connect().

    Returns (device, api) so the caller can set up return values and assert.
    """
    mock_frida = _prepare_mock_frida_module()
    mock_device, mock_api = _prepare_device_and_api(bridge, device)

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


class TestFridaBridgeReadMemoryEx:
    """Tests for FridaBridge.read_memory_ex() fault reporting."""

    def test_success_reports_ok_without_fault(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.return_value = b"\xde\xad\xbe\xef"

        result = bridge.read_memory_ex(0x10000, 4)

        assert result.ok is True
        assert result.data == b"\xde\xad\xbe\xef"
        assert result.fault_addr is None
        assert result.error == ""
        assert bridge.read_memory(0x10000, 4) == b"\xde\xad\xbe\xef"

    def test_error_descriptor_yields_fault_address(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.return_value = {
            "__error": True,
            "message": "access violation accessing 0x7d57c3f2d000",
        }

        result = bridge.read_memory_ex(0x7D57C3F2C000, 8192)

        assert result.ok is False
        assert result.data is None
        assert result.fault_addr == 0x7D57C3F2D000
        assert "access violation" in result.error
        assert bridge.read_memory(0x7D57C3F2C000, 8192) is None

    def test_unable_to_read_phrasing_also_parsed(self):
        """Frida words the failure differently across versions."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.return_value = {
            "__error": True,
            "message": "unable to read memory at 0x7ffd5b7f9000",
        }

        assert bridge.read_memory_ex(0x1000, 8).fault_addr == 0x7FFD5B7F9000

    def test_unparseable_message_leaves_fault_address_unset(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.return_value = {
            "__error": True, "message": "something went wrong",
        }

        result = bridge.read_memory_ex(0x10000, 4)

        assert result.data is None
        assert result.fault_addr is None
        assert result.error == "something went wrong"
        assert bridge.read_memory(0x10000, 4) is None

    def test_rpc_exception_reports_error_text(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.side_effect = RuntimeError("script destroyed")

        result = bridge.read_memory_ex(0x10000, 4)

        assert result.data is None
        assert result.ok is False
        assert result.error
        assert bridge.read_memory(0x10000, 4) is None

    def test_none_result_is_a_plain_failure(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_memory.return_value = None

        result = bridge.read_memory_ex(0x10000, 4)

        assert result.data is None
        assert result.fault_addr is None
        assert bridge.read_memory(0x10000, 4) is None


_MAPS_TEXT = """\
55d0aa000000-55d0aa021000 rw-p 00000000 00:00 0                          [heap]
7f8c00000000-7f8c00021000 r-xp 00000000 08:01 1234                       /usr/lib/libc.so.6
7ffd5b7f9000-7ffd5b7fd000 r--p 00000000 00:00 0                          [vvar_vclock]
7ffd5b7fd000-7ffd5b7fe000 r-xp 00000000 00:00 0                          [vdso]
"""


def _frida_ranges():
    """Frida-shaped range dicts covering the spans in ``_MAPS_TEXT``."""
    return [
        # Pseudo-mappings: Frida reports no file at all.
        {"base": "0x55d0aa000000", "size": 0x21000,
         "protection": "rw-", "file": None},
        {"base": "0x7ffd5b7f9000", "size": 0x4000,
         "protection": "r--", "file": None},
        # File-backed: Frida already knows the path, maps must not win.
        {"base": "0x7f8c00000000", "size": 0x21000, "protection": "r-x",
         "file": {"path": "/frida/supplied/libc.so.6", "offset": 0}},
        # Outside every named span in the maps text.
        {"base": "0x1000", "size": 0x1000, "protection": "rw-", "file": None},
    ]


class TestFridaBridgeMapsEnrichment:
    """Ranges Frida cannot name are recovered from the target's own maps."""

    def _ranges_by_base(self, bridge):
        return {r.base: r for r in bridge.enumerate_ranges()}

    def test_pseudo_mappings_get_their_maps_name(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = _MAPS_TEXT
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = self._ranges_by_base(bridge)

        assert ranges[0x55D0AA000000].file_path == "[heap]"
        assert ranges[0x7FFD5B7F9000].file_path == "[vvar_vclock]"

    def test_frida_supplied_path_is_not_overwritten(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = _MAPS_TEXT
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = self._ranges_by_base(bridge)

        assert ranges[0x7F8C00000000].file_path == "/frida/supplied/libc.so.6"

    def test_range_outside_every_span_stays_unnamed(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = _MAPS_TEXT
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = self._ranges_by_base(bridge)

        assert ranges[0x1000].file_path == ""

    def test_maps_are_fetched_once_per_session(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = _MAPS_TEXT
        api.enumerate_ranges.return_value = _frida_ranges()

        bridge.enumerate_ranges()
        bridge.enumerate_ranges()

        api.read_proc_maps.assert_called_once()


class TestFridaBridgeMapsEnrichmentDegradation:
    """Enrichment is best-effort: every failure mode leaves names empty."""

    def _unnamed_ranges(self, bridge):
        return [r for r in bridge.enumerate_ranges() if not r.file_path]

    def test_rpc_raising_is_swallowed(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.side_effect = RuntimeError("no such export")
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = bridge.enumerate_ranges()

        assert ranges[0].file_path == ""
        assert ranges[1].file_path == ""

    def test_empty_maps_text_leaves_names_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = ""
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = bridge.enumerate_ranges()

        assert ranges[0].file_path == ""
        assert ranges[1].file_path == ""

    def test_non_string_rpc_result_leaves_names_empty(self):
        """An unstubbed RPC on a MagicMock api returns a MagicMock, not a
        string — parsing it would break every other test in this file."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_ranges.return_value = _frida_ranges()

        ranges = bridge.enumerate_ranges()

        assert not isinstance(api.read_proc_maps(), str)
        assert ranges[0].file_path == ""
        assert ranges[1].file_path == ""
        assert ranges[3].file_path == ""

    def test_missing_export_leaves_names_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_ranges.return_value = _frida_ranges()
        del api.read_proc_maps

        ranges = bridge.enumerate_ranges()

        assert bridge._map_spans == []
        assert ranges[0].file_path == ""

    def test_disconnect_drops_the_cached_spans(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.read_proc_maps.return_value = _MAPS_TEXT
        api.enumerate_ranges.return_value = _frida_ranges()

        bridge.enumerate_ranges()
        assert bridge._map_spans

        bridge.disconnect()

        assert bridge._map_spans is None


def _preflight_result(warnings=()):
    """Build a PreflightResult carrying the given warning details."""
    from memslicer.acquirer.attach_preflight import (
        AttachEnvironment, PreflightFinding, PreflightResult, Severity,
    )

    return PreflightResult(
        env=AttachEnvironment(checked=True, target_pid=1234),
        findings=[
            PreflightFinding(
                code=f"warning-{i}", severity=Severity.WARNING, detail=detail,
            )
            for i, detail in enumerate(warnings)
        ],
    )


class TestFridaBridgePreflight:
    """connect() runs the shared attach preflight before touching the target."""

    def test_refusal_propagates_and_never_attaches(self):
        from memslicer.acquirer.errors import AttachPreflightError

        bridge = _make_bridge(target=1234)
        device, _api = _prepare_device_and_api(bridge)
        refusal = AttachPreflightError(
            "cannot attach to PID 1234: Yama ptrace_scope is 2",
            remediation=["run as root"],
        )

        with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}), \
             patch("memslicer.acquirer.frida_bridge.enforce_attach_preflight",
                   side_effect=refusal):
            with pytest.raises(AttachPreflightError) as excinfo:
                bridge.connect()

        assert excinfo.value is refusal
        device.attach.assert_not_called()
        assert bridge._session is None

    def test_clean_result_lets_the_attach_proceed(self):
        bridge = _make_bridge(target=1234)
        device, _api = _prepare_device_and_api(bridge)
        clean = _preflight_result()

        with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}), \
             patch("memslicer.acquirer.frida_bridge.enforce_attach_preflight",
                   return_value=clean) as preflight:
            bridge.connect()

        preflight.assert_called_once()
        device.attach.assert_called_once_with(1234)
        assert bridge._preflight is clean

    def test_attach_failure_reuses_warnings_as_probable_cause(self):
        from memslicer.acquirer.errors import AttachError, AttachPreflightError

        bridge = _make_bridge(target=1234)
        device, _api = _prepare_device_and_api(bridge)
        device.attach.side_effect = RuntimeError(
            "unable to access process with pid 1234"
        )
        warned = _preflight_result(warnings=["Yama ptrace_scope is 1"])

        with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}), \
             patch("memslicer.acquirer.frida_bridge.enforce_attach_preflight",
                   return_value=warned):
            with pytest.raises(AttachError) as excinfo:
                bridge.connect()

        error = excinfo.value
        assert not isinstance(error, AttachPreflightError)
        assert error.probable_cause == "Yama ptrace_scope is 1"
        assert isinstance(error.cause, RuntimeError)

    def test_name_target_passes_none_as_pid(self):
        bridge = _make_bridge(target="my_process")
        _device, _api = _prepare_device_and_api(bridge)

        with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}), \
             patch("memslicer.acquirer.frida_bridge.enforce_attach_preflight",
                   return_value=_preflight_result()) as preflight:
            bridge.connect()

        assert preflight.call_args[0][0] is None


class TestFridaBridgeFaultTextFalsePositives:
    """The shared fault parser must not read ordinary prose as a fault.

    Frida is the one backend that trusts a parsed address without an interior
    check -- its address is a real CPU fault address, so a fault at the span
    start legitimately means the first page is dead. That trust makes a false
    positive here cost a readable page.
    """

    @pytest.mark.parametrize("message", [
        "unable to allocate 0x1000 bytes for 0x7fff00000000",
        "Error: no data available for 0x41414141",
        "waiting for 0xdeadbeef",
        "bad format 0x1000",
        "repeat 0x2000",
        "abort_at 0x1000",
    ])
    def test_prose_is_not_a_fault_address(self, message: str):
        """None of these name a faulting address."""
        from memslicer.acquirer.bridge import parse_fault_addr

        assert parse_fault_addr(message) is None

    @pytest.mark.parametrize("message, expected", [
        ("access violation accessing 0x7d57c3f2d000", 0x7D57C3F2D000),
        ("unable to read memory at 0x7ffd5b7f9000", 0x7FFD5B7F9000),
        ("Cannot access memory at address 0x1000", 0x1000),
    ])
    def test_real_backend_phrasings_still_parse(self, message: str, expected: int):
        """The phrasings the backends actually emit must keep working."""
        from memslicer.acquirer.bridge import parse_fault_addr

        assert parse_fault_addr(message) == expected
