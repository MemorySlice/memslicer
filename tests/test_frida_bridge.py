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


# ---------------------------------------------------------------------------
# Remote investigation collector
# ---------------------------------------------------------------------------

def _connect_with_two_scripts(bridge, device=None, investigation_script=None):
    """Connect *bridge* so the bridge and investigation scripts are distinct.

    Returns ``(bridge_script, investigation_script)``; the second is what
    ``session.create_script`` hands out for the investigation agent.
    """
    mock_device = device or MagicMock(type="usb")
    mock_device_, api = _prepare_device_and_api(bridge, mock_device)
    session = mock_device_.attach.return_value
    bridge_script = session.create_script.return_value
    investigation_script = investigation_script or MagicMock()
    session.create_script.side_effect = [bridge_script, investigation_script]
    # Stub the preflight: on Linux it would check the fake PID in /proc.
    with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}), \
         patch("memslicer.acquirer.frida_bridge.enforce_attach_preflight",
               return_value=_preflight_result()):
        bridge.connect()
    return bridge_script, investigation_script


class TestFridaBridgeCreateRemoteCollector:
    """FridaBridge.create_remote_collector loads the agent on remote targets."""

    def test_remote_target_returns_connected_collector(self):
        from memslicer.acquirer.collectors.frida_remote import FridaRemoteCollector

        bridge = _make_bridge(target=1234)
        _bridge_script, investigation_script = _connect_with_two_scripts(bridge)

        collector = bridge.create_remote_collector()

        assert isinstance(collector, FridaRemoteCollector)
        assert bridge._session.create_script.call_count == 2
        assert collector._api is investigation_script.exports_sync
        investigation_script.load.assert_called_once()

    def test_local_device_returns_none(self):
        bridge = _make_bridge(target=1234)
        _connect_with_two_scripts(bridge, device=MagicMock(type="local"))

        assert bridge.create_remote_collector() is None
        assert bridge._session.create_script.call_count == 1

    def test_before_connect_returns_none(self):
        bridge = _make_bridge(target=1234, device=MagicMock(type="usb"))

        assert bridge.create_remote_collector() is None

    def test_script_load_failure_returns_none_and_warns(self):
        bridge = _make_bridge(target=1234)
        failing_script = MagicMock()
        failing_script.load.side_effect = RuntimeError("boom")
        _connect_with_two_scripts(bridge, investigation_script=failing_script)

        assert bridge.create_remote_collector() is None
        bridge._log.warning.assert_called_once()
        fmt, exc = bridge._log.warning.call_args.args
        assert "Investigation script could not be loaded" in fmt
        assert "boom" in str(exc)

    def test_create_script_failure_returns_none_and_warns(self):
        bridge = _make_bridge(target=1234)
        _connect_with_two_scripts(bridge)
        bridge._session.create_script.side_effect = RuntimeError("boom")

        assert bridge.create_remote_collector() is None
        bridge._log.warning.assert_called_once()

    def test_collector_uses_given_logger(self):
        bridge = _make_bridge(target=1234)
        _connect_with_two_scripts(bridge)
        logger = MagicMock()

        collector = bridge.create_remote_collector(logger=logger)

        assert collector._log is logger

    def test_bridge_satisfies_remote_collector_capable(self):
        from memslicer.acquirer.bridge import RemoteCollectorCapable

        bridge = _make_bridge(target=1234)

        assert isinstance(bridge, RemoteCollectorCapable)


class TestFridaScriptProcMapsFallback:
    """The agent's /proc/self/maps fallback must use the GumJS File API."""

    def test_fallback_reads_with_read_text_not_read(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "File.readAllText('/proc/self/maps')" in _FRIDA_SCRIPT
        assert "f.readText(65536)" in _FRIDA_SCRIPT
        assert "typeof f.readText !== 'function'" in _FRIDA_SCRIPT
        assert "f.read(" not in _FRIDA_SCRIPT


# ---------------------------------------------------------------------------
# Tests -- page residency and thread stack pointers
# ---------------------------------------------------------------------------

class TestFridaScriptResidencyExports:
    """The agent exposes the residency/thread exports and feature-detects
    every API they rely on: Frida 17 removed the static Module.* lookups and
    older GumJS File objects have no seek()/readBytes()."""

    @pytest.mark.parametrize("export", [
        "residencyMethod", "residencyDetail", "queryResidency",
        "enumerateStackPointers", "closeResidency",
    ])
    def test_export_is_defined(self, export):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert f"{export}: function" in _FRIDA_SCRIPT

    @pytest.mark.parametrize("guard", [
        "typeof Module.findGlobalExportByName === 'function'",
        "typeof Module.findExportByName === 'function'",
        "typeof File === 'undefined'",
        "typeof File.prototype.seek !== 'function'",
        "typeof File.prototype.readBytes !== 'function'",
        "typeof File.readAllText === 'function'",
        "typeof File.SEEK_SET === 'number'",
        "typeof Process.enumerateThreads !== 'function'",
    ])
    def test_api_is_feature_detected(self, guard):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert guard in _FRIDA_SCRIPT

    def test_pagemap_probe_and_decoding(self):
        """Opens pagemap binary, probes one entry, masks the top-byte bits."""
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "new File('/proc/self/pagemap', 'rb')" in _FRIDA_SCRIPT
        assert "f.readBytes(8)" in _FRIDA_SCRIPT
        assert "& 0xC0" in _FRIDA_SCRIPT
        assert "Process.platform !== 'linux'" in _FRIDA_SCRIPT

    def test_mincore_is_gated_on_empty_swap(self):
        """mincore() cannot see swapped pages, so VmSwap must be 0 kB."""
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "_findGlobalExport('mincore')" in _FRIDA_SCRIPT
        assert "/proc/self/status" in _FRIDA_SCRIPT
        assert "/^VmSwap:[ \\t]*([0-9]+)[ \\t]*kB/m" in _FRIDA_SCRIPT
        assert "['pointer', 'size_t', 'pointer']" in _FRIDA_SCRIPT
        assert "flags[i] & 1" in _FRIDA_SCRIPT

    def test_script_is_valid_javascript(self, tmp_path):
        """node --check on the agent, when node is installed."""
        import shutil
        import subprocess

        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        node = shutil.which("node")
        if node is None:
            pytest.skip("node not installed")
        script = tmp_path / "agent.js"
        script.write_text(_FRIDA_SCRIPT)

        result = subprocess.run(
            [node, "--check", str(script)], capture_output=True, text=True,
        )

        assert result.returncode == 0, result.stderr


class TestFridaScriptSwapTable:
    """mincore() is trusted per VMA: with VmSwap > 0 the agent builds a swap
    table from /proc/self/smaps and refuses to answer for VMAs holding swap,
    so pruning stays lossless on Android where pagemap is SELinux-denied."""

    def test_swap_table_is_built_from_smaps(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "function _loadSwapTable()" in _FRIDA_SCRIPT
        assert "_readTextFile('/proc/self/smaps')" in _FRIDA_SCRIPT
        assert "/^([0-9a-f]+)-([0-9a-f]+) /" in _FRIDA_SCRIPT
        assert "/^Swap:[ \\t]*([0-9]+)[ \\t]*kB/" in _FRIDA_SCRIPT
        assert "parseInt(h[1], 16), parseInt(h[2], 16)" in _FRIDA_SCRIPT

    def test_mincore_needs_the_table_only_while_swap_is_in_use(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "if (_vmSwapKb() !== 0) {" in _FRIDA_SCRIPT
        assert "_noteWhy('smaps unreadable')" in _FRIDA_SCRIPT
        assert "_noteWhy('mincore export missing')" in _FRIDA_SCRIPT

    def test_mask_refuses_vmas_with_swap(self):
        """Unknown VMA, swap inside it, or a span leaving it => null."""
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "function _findSwapEntry(addr)" in _FRIDA_SCRIPT
        assert (
            "if (vma === null || vma[2] > 0 || spanEnd > vma[1]) return null;"
            in _FRIDA_SCRIPT
        )

    def test_detail_export_explains_the_method(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "residencyDetail: function()" in _FRIDA_SCRIPT
        assert "'swap table: ' + _swapTable.length + ' VMAs, '" in _FRIDA_SCRIPT
        assert "'none: ' + (_residencyWhy === '' ? 'unknown' : _residencyWhy)" in _FRIDA_SCRIPT

    def test_close_forgets_the_table_and_the_reason(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        close_body = _FRIDA_SCRIPT.split("closeResidency: function() {", 1)[1]
        assert "_swapTable = null;" in close_body
        assert "_residencyWhy = '';" in close_body

    @pytest.mark.parametrize("scenario, method, detail, swapped_vma", [
        ("swap", "mincore", "mincore (swap table: 3 VMAs, 1 with swap)", None),
        ("noswap", "mincore", "mincore (VmSwap 0 kB, no swap table)", 2),
        ("nosmaps", "none", "none: pagemap: Permission denied; smaps unreadable", None),
        ("nomincore", "none", "none: pagemap: Permission denied; mincore export missing", None),
    ])
    def test_agent_logic_under_node(self, tmp_path, scenario, method, detail, swapped_vma):
        """Runs the agent in node with stubbed Frida globals: pagemap denied,
        a synthetic smaps with one swapped VMA, and the given status/exports."""
        import json
        import shutil
        import subprocess

        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        node = shutil.which("node")
        if node is None:
            pytest.skip("node not installed")
        (tmp_path / "agent.js").write_text(_FRIDA_SCRIPT)
        (tmp_path / "harness.js").write_text(_NODE_HARNESS)

        result = subprocess.run(
            [node, str(tmp_path / "harness.js"), str(tmp_path / "agent.js"), scenario],
            capture_output=True, text=True,
        )

        assert result.returncode == 0, result.stderr
        answer = json.loads(result.stdout)
        assert answer["method"] == method
        assert answer["detail"] == detail
        assert answer["swapped_vma"] == swapped_vma
        if method == "mincore":
            assert answer["clean_vma"] == 2
        else:
            assert answer["clean_vma"] is None
        if scenario == "swap":
            assert answer["crosses_end"] is None
            assert answer["no_vma"] is None


_NODE_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8'), scenario = process.argv[3];
const PAGE = 4096;
const smaps = [
  '10000-20000 rw-p 00000000 00:00 0', 'Size: 64 kB', 'Swap: 0 kB',
  '20000-30000 rw-p 00000000 00:00 0', 'Size: 64 kB', 'Swap: 8 kB',
  '40000-50000 r--p 00000000 00:00 0', 'Size: 64 kB', 'Swap:         0 kB',
].join('\n') + '\n';
const files = {
  '/proc/self/status': scenario === 'noswap' ? 'VmSwap:\t0 kB\n' : 'VmSwap:\t  244 kB\n',
  '/proc/self/smaps': scenario === 'nosmaps' ? '' : smaps,
};
function Ptr(n) { this.n = BigInt(n); }
Ptr.prototype.toString = function() { return this.n.toString(); };
Ptr.prototype.isNull = function() { return this.n === 0n; };
Ptr.prototype.and = function(o) { return new Ptr(this.n & o.n); };
Ptr.prototype.not = function() { return new Ptr(~this.n & 0xffffffffffffffffn); };
Ptr.prototype.readByteArray = function(n) { return new Uint8Array(n).fill(1).buffer; };
const sandbox = {
  Process: { platform: 'linux', pageSize: PAGE },
  Module: { findGlobalExportByName: () => (scenario === 'nomincore' ? null : new Ptr(0x1000)) },
  File: function() { throw new Error('Permission denied'); },
  Memory: { alloc: () => new Ptr(0x2000) },
  NativeFunction: function() { return () => 0; },
  ptr: v => new Ptr(typeof v === 'string' ? BigInt(v) : v),
  rpc: {},
};
sandbox.File.prototype.seek = function() {};
sandbox.File.prototype.readBytes = function() {};
sandbox.File.readAllText = p => files[p];
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const x = sandbox.rpc.exports;
const q = (a, n) => {
  const r = x.queryResidency('0x' + a.toString(16), n * PAGE);
  return r === null ? null : new Uint8Array(r).length;
};
console.log(JSON.stringify({
  method: x.residencyMethod(), detail: x.residencyDetail(),
  clean_vma: q(0x10000, 2), swapped_vma: q(0x20000, 2),
  crosses_end: q(0x1f000, 2), no_vma: q(0x30000, 1),
}));
x.closeResidency();
"""


class TestFridaBridgeResidencyMethod:
    """residency_method() reports the agent's answer and degrades to none."""

    def test_reports_agent_answer(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "pagemap"

        assert bridge.residency_method() == "pagemap"

    def test_answer_is_cached_per_connection(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "mincore"

        assert bridge.residency_method() == "mincore"
        assert bridge.residency_method() == "mincore"

        api.residency_method.assert_called_once()

    def test_rpc_raising_degrades_to_none(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.side_effect = RuntimeError("script unloaded")

        assert bridge.residency_method() == "none"

    def test_non_string_answer_degrades_to_none(self):
        """An unstubbed RPC on a MagicMock api answers a MagicMock."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        assert not isinstance(api.residency_method(), str)
        assert bridge.residency_method() == "none"

    def test_unknown_string_degrades_to_none(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "madvise"

        assert bridge.residency_method() == "none"

    def test_missing_export_degrades_to_none(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        del api.residency_method

        assert bridge.residency_method() == "none"

    def test_before_connect_is_none(self):
        bridge = _make_bridge(target=1234)

        assert bridge.residency_method() == "none"

    def test_disconnect_forgets_the_cached_answer(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "pagemap"
        bridge.residency_method()

        bridge.disconnect()

        assert bridge._residency_method is None

    def test_detail_is_logged_once_at_debug_when_resolved(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "mincore"
        api.residency_detail.return_value = "mincore (swap table: 3 VMAs, 1 with swap)"

        bridge.residency_method()
        bridge.residency_method()

        api.residency_detail.assert_called_once_with()
        logged = [
            call.args for call in bridge._log.debug.call_args_list
            if call.args and call.args[0] == "residency method %s (%s)"
        ]
        assert logged == [(
            "residency method %s (%s)", "mincore",
            "mincore (swap table: 3 VMAs, 1 with swap)",
        )]

    def test_bridge_satisfies_residency_capable(self):
        from memslicer.acquirer.bridge import ResidencyCapable

        assert isinstance(_make_bridge(target=1234), ResidencyCapable)

    def test_bridge_satisfies_thread_stack_capable(self):
        from memslicer.acquirer.bridge import ThreadStackCapable

        assert isinstance(_make_bridge(target=1234), ThreadStackCapable)


class TestFridaBridgeResidencyDetail:
    """residency_detail() is informational and degrades to an empty string."""

    def test_reports_agent_answer(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_detail.return_value = "none: pagemap: Permission denied"

        assert bridge.residency_detail() == "none: pagemap: Permission denied"
        api.residency_detail.assert_called_once_with()

    def test_rpc_raising_degrades_to_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_detail.side_effect = RuntimeError("script unloaded")

        assert bridge.residency_detail() == ""

    def test_non_string_answer_degrades_to_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_detail.return_value = {"method": "mincore"}

        assert bridge.residency_detail() == ""

    def test_missing_export_degrades_to_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        del api.residency_detail

        assert bridge.residency_detail() == ""

    def test_before_connect_is_empty(self):
        bridge = _make_bridge(target=1234)

        assert bridge.residency_detail() == ""

    def test_missing_detail_does_not_break_residency_method(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "pagemap"
        del api.residency_detail

        assert bridge.residency_method() == "pagemap"


class TestFridaBridgeQueryResidency:
    """query_residency() trusts the agent only for an exactly-sized mask."""

    def _pagemap_bridge(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "pagemap"
        return bridge, api

    def test_returns_one_byte_per_page(self):
        bridge, api = self._pagemap_bridge()
        api.query_residency.return_value = bytes([1, 0, 1])

        mask = bridge.query_residency(0x10000, 3 * 4096)

        assert mask == b"\x01\x00\x01"
        api.query_residency.assert_called_once_with("0x10000", 3 * 4096)

    def test_unaligned_span_is_counted_outwards(self):
        """Half a page at each end still means three pages, like page_count."""
        bridge, api = self._pagemap_bridge()
        api.query_residency.return_value = bytes([1, 1, 1])

        assert bridge.query_residency(0x10800, 2 * 4096) == b"\x01\x01\x01"

    def test_bytearray_answer_is_accepted(self):
        bridge, api = self._pagemap_bridge()
        api.query_residency.return_value = bytearray([0, 1])

        mask = bridge.query_residency(0x10000, 2 * 4096)

        assert mask == b"\x00\x01"
        assert isinstance(mask, bytes)

    def test_wrong_length_is_rejected(self):
        bridge, api = self._pagemap_bridge()
        api.query_residency.return_value = bytes([1, 0])

        assert bridge.query_residency(0x10000, 3 * 4096) is None

    def test_null_answer_returns_none(self):
        bridge, api = self._pagemap_bridge()
        api.query_residency.return_value = None

        assert bridge.query_residency(0x10000, 4096) is None

    def test_rpc_raising_returns_none(self):
        bridge, api = self._pagemap_bridge()
        api.query_residency.side_effect = RuntimeError("script unloaded")

        assert bridge.query_residency(0x10000, 4096) is None

    def test_non_bytes_answer_returns_none(self):
        bridge, api = self._pagemap_bridge()

        assert not isinstance(api.query_residency(), bytes)
        assert bridge.query_residency(0x10000, 4096) is None

    def test_missing_export_returns_none(self):
        bridge, api = self._pagemap_bridge()
        del api.query_residency

        assert bridge.query_residency(0x10000, 4096) is None

    def test_method_none_skips_the_rpc(self):
        """"none" promises that query_residency always answers None."""
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.residency_method.return_value = "none"
        api.query_residency.return_value = bytes([1])

        assert bridge.query_residency(0x10000, 4096) is None
        api.query_residency.assert_not_called()


class TestFridaBridgeEnumerateStackPointers:
    """enumerate_stack_pointers() parses what it can and never raises."""

    def test_parses_hex_strings_and_skips_junk(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_stack_pointers.return_value = ["0x7fff0000", "junk"]

        assert bridge.enumerate_stack_pointers() == [0x7fff0000]

    def test_ints_are_accepted_and_other_types_skipped(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_stack_pointers.return_value = [
            0x1000, "0x2000", None, 3.5, True, MagicMock(),
        ]

        assert bridge.enumerate_stack_pointers() == [0x1000, 0x2000]

    def test_rpc_raising_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_stack_pointers.side_effect = RuntimeError("no threads")

        assert bridge.enumerate_stack_pointers() == []

    def test_non_list_answer_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        assert not isinstance(api.enumerate_stack_pointers(), list)
        assert bridge.enumerate_stack_pointers() == []

    def test_missing_export_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        del api.enumerate_stack_pointers

        assert bridge.enumerate_stack_pointers() == []

    def test_before_connect_returns_empty(self):
        bridge = _make_bridge(target=1234)

        assert bridge.enumerate_stack_pointers() == []


class TestFridaBridgeEnumerateThreads:
    """enumerate_threads() turns the agent's sampled contexts into ThreadInfo
    entries and never raises."""

    X86_64_CONTEXT = {
        "rip": "0x401000", "rsp": "0x7ffd0000", "rbp": "0x7ffd0040",
        "rax": "0x2a", "pc": "0x401000", "sp": "0x7ffd0000",
    }
    ARM64_CONTEXT = {
        "pc": "0x7000", "sp": "0x7ff0000", "fp": "0x7ff0040",
        "lr": "0x7010", "x0": "0x1", "nzcv": "0x60000000",
    }

    @staticmethod
    def _connect_with_arch(bridge, frida_arch):
        """Run connect() with the agent reporting *frida_arch*."""
        _device, api = _prepare_device_and_api(bridge)
        api.get_arch.return_value = frida_arch
        with patch.dict(sys.modules, {"frida": _prepare_mock_frida_module()}):
            bridge.connect()
        return api

    @staticmethod
    def _by_name(info):
        return {r.name: r for r in info.registers}

    def test_x86_64_context_drops_generic_aliases(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 4321, "name": "worker", "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        threads = bridge.enumerate_threads()

        assert len(threads) == 1
        regs = self._by_name(threads[0])
        assert set(regs) == {"rip", "rsp", "rbp", "rax"}

    def test_x86_64_roles_and_little_endian_values(self):
        from memslicer.msl.constants import REG_ROLE_FP, REG_ROLE_PC, REG_ROLE_SP

        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        regs = self._by_name(bridge.enumerate_threads()[0])

        assert regs["rip"].role == REG_ROLE_PC
        assert regs["rsp"].role == REG_ROLE_SP
        assert regs["rbp"].role == REG_ROLE_FP
        assert regs["rax"].role == 0
        assert regs["rip"].width == 8
        assert regs["rip"].value == (0x401000).to_bytes(8, "little")
        assert regs["rax"].value == b"\x2a" + b"\x00" * 7

    def test_thread_metadata_is_carried(self):
        from memslicer.msl.constants import ThreadState

        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 4321, "name": "worker", "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        info = bridge.enumerate_threads()[0]

        assert info.tid == 4321
        assert info.name == "worker"
        assert info.state == ThreadState.RUNNING
        assert info.suspended is False
        assert info.partial is False

    @pytest.mark.parametrize("text, expected", [
        ("running", "RUNNING"), ("stopped", "STOPPED"), ("waiting", "WAITING"),
        ("uninterruptible", "UNINTERRUPTIBLE"), ("halted", "HALTED"),
        ("", "UNKNOWN"), ("something-new", "UNKNOWN"), (None, "UNKNOWN"),
    ])
    def test_frida_state_strings_map_to_spec_states(self, text, expected):
        from memslicer.msl.constants import ThreadState

        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": text,
             "context": dict(self.X86_64_CONTEXT)},
        ]

        assert bridge.enumerate_threads()[0].state == ThreadState[expected]

    def test_arm64_context_keeps_generic_names_with_roles(self):
        from memslicer.msl.constants import (
            REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP,
        )

        bridge = _make_bridge(target=1234)
        api = self._connect_with_arch(bridge, "arm64")
        api.enumerate_threads.return_value = [
            {"id": 7, "name": "main", "state": "waiting",
             "context": dict(self.ARM64_CONTEXT)},
        ]

        assert bridge.get_platform_info().arch == ArchType.ARM64
        regs = self._by_name(bridge.enumerate_threads()[0])

        assert set(regs) == {"pc", "sp", "fp", "lr", "x0", "nzcv"}
        assert regs["pc"].role == REG_ROLE_PC
        assert regs["sp"].role == REG_ROLE_SP
        assert regs["fp"].role == REG_ROLE_FP
        assert regs["lr"].role == REG_ROLE_LR
        assert regs["nzcv"].role == REG_ROLE_FLAGS
        assert regs["x0"].role == 0
        assert regs["sp"].value == (0x7ff0000).to_bytes(8, "little")

    def test_thread_without_sp_is_skipped(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {"rip": "0x401000", "rax": "0x1"}},
            {"id": 2, "name": "", "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        threads = bridge.enumerate_threads()

        assert [t.tid for t in threads] == [2]

    def test_thread_without_pc_is_skipped(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {"rsp": "0x7ffd0000", "rax": "0x1"}},
        ]

        assert bridge.enumerate_threads() == []

    def test_unparseable_register_is_skipped_and_marks_partial(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {**self.X86_64_CONTEXT, "rbx": "junk"}},
        ]

        info = bridge.enumerate_threads()[0]

        assert "rbx" not in self._by_name(info)
        assert info.partial is True

    @pytest.mark.parametrize("bad", [
        "-0x1", -1, 1 << 64, "0x10000000000000000", True, None, 3.5, [],
    ])
    def test_value_outside_register_width_marks_partial(self, bad):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {**self.X86_64_CONTEXT, "rbx": bad}},
        ]

        info = bridge.enumerate_threads()[0]

        assert "rbx" not in self._by_name(info)
        assert info.partial is True

    def test_plain_int_values_are_accepted(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {"rip": 0x401000, "rsp": 0x7ffd0000}},
        ]

        info = bridge.enumerate_threads()[0]

        assert info.partial is False
        assert self._by_name(info)["rip"].as_int == 0x401000

    def test_register_names_are_lowercased(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": 1, "name": "", "state": "running",
             "context": {"RIP": "0x401000", "RSP": "0x7ffd0000"}},
        ]

        assert set(self._by_name(bridge.enumerate_threads()[0])) == {"rip", "rsp"}

    def test_non_dict_items_and_bad_context_are_skipped(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            "junk", None, 42, ["rip"],
            {"id": 1, "name": "", "state": "running", "context": "nope"},
            {"id": 2, "name": "", "state": "running"},
            {"id": 3, "name": "", "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        assert [t.tid for t in bridge.enumerate_threads()] == [3]

    def test_bad_tid_and_name_fall_back_to_defaults(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.return_value = [
            {"id": "4321", "name": None, "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
            {"id": True, "name": 5, "state": "running",
             "context": dict(self.X86_64_CONTEXT)},
        ]

        threads = bridge.enumerate_threads()

        assert [t.tid for t in threads] == [0, 0]
        assert [t.name for t in threads] == ["", ""]

    def test_rpc_raising_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        api.enumerate_threads.side_effect = RuntimeError("no threads")

        assert bridge.enumerate_threads() == []

    def test_non_list_answer_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)

        assert not isinstance(api.enumerate_threads(), list)
        assert bridge.enumerate_threads() == []

    def test_missing_export_returns_empty(self):
        bridge = _make_bridge(target=1234)
        _device, api = _setup_device_and_api(bridge)
        del api.enumerate_threads

        assert bridge.enumerate_threads() == []

    def test_before_connect_returns_empty(self):
        bridge = _make_bridge(target=1234)

        assert bridge.enumerate_threads() == []

    def test_agent_export_is_defined_and_feature_detected(self):
        from memslicer.acquirer.frida_bridge import _FRIDA_SCRIPT

        assert "enumerateThreads: function" in _FRIDA_SCRIPT
        assert "typeof Process.enumerateThreads" in _FRIDA_SCRIPT
        assert "_hexContext(t.context || {})" in _FRIDA_SCRIPT

    def test_bridge_is_thread_registers_capable(self):
        from memslicer.acquirer.bridge import ThreadRegistersCapable

        assert isinstance(_make_bridge(target=1234), ThreadRegistersCapable)


class TestFridaBridgeDisconnectClosesResidency:
    """disconnect() releases the agent's pagemap handle, best-effort."""

    def test_disconnect_closes_residency_before_detaching(self):
        bridge = _make_bridge(target=1234)
        device, api = _setup_device_and_api(bridge)

        bridge.disconnect()

        api.close_residency.assert_called_once_with()
        device.attach.return_value.detach.assert_called_once()

    def test_missing_close_export_still_detaches(self):
        bridge = _make_bridge(target=1234)
        device, api = _setup_device_and_api(bridge)
        del api.close_residency

        bridge.disconnect()

        device.attach.return_value.detach.assert_called_once()

    def test_close_raising_still_detaches(self):
        bridge = _make_bridge(target=1234)
        device, api = _setup_device_and_api(bridge)
        api.close_residency.side_effect = RuntimeError("script unloaded")

        bridge.disconnect()

        device.attach.return_value.detach.assert_called_once()
        assert bridge._session is None
