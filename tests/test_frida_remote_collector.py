"""Tests for FridaRemoteCollector connection and handle table parsing."""
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.frida_remote import FridaRemoteCollector
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_collector(rpc_result=None, rpc_side_effect=None):
    """Create a FridaRemoteCollector with a mocked Frida session/API."""
    session = MagicMock()
    collector = FridaRemoteCollector(session=session)

    # Simulate connect() having been called
    api = MagicMock()
    collector._api = api

    if rpc_side_effect is not None:
        api.get_connection_table.side_effect = rpc_side_effect
        api.get_handle_table.side_effect = rpc_side_effect
    elif rpc_result is not None:
        api.get_connection_table.return_value = rpc_result
        api.get_handle_table.return_value = rpc_result

    return collector, api


# ===========================================================================
# Tests: _decode_proc_net_addr (static method)
# ===========================================================================

class TestDecodeProcNetAddr:
    """Unit tests for the /proc/net hex address decoder.

    The exact byte output depends on host byte order (the same algorithm
    as LinuxCollector._decode_ipv4_addr). Tests verify structural properties
    and consistency rather than hard-coded platform-specific byte sequences.
    """

    _decode = staticmethod(FridaRemoteCollector._decode_proc_net_addr)

    def test_ipv4_produces_16_bytes(self):
        for hex_addr in ("0100007F", "00000000", "FFFFFFFF", "C0A80164"):
            result = self._decode(hex_addr, False)
            assert len(result) == 16
            # Last 12 bytes are always zero-padded for IPv4
            assert result[4:] == b"\x00" * 12

    def test_ipv4_zeros(self):
        """00000000 = 0.0.0.0"""
        result = self._decode("00000000", False)
        assert result == b"\x00" * 16

    def test_ipv4_different_addrs_differ(self):
        """Different hex addresses produce different output."""
        a = self._decode("0100007F", False)
        b = self._decode("C0A80164", False)
        assert a != b

    def test_ipv4_matches_struct_chain(self):
        """Verify output matches the struct pack/unpack chain directly."""
        import struct
        hex_addr = "0100007F"
        host_int = int(hex_addr, 16)
        expected = struct.pack(
            "!I", struct.unpack("<I", struct.pack("=I", host_int))[0],
        ) + b"\x00" * 12
        assert self._decode(hex_addr, False) == expected

    def test_ipv6_produces_16_bytes(self):
        for hex_addr in [
            "00000000000000000000000001000000",
            "00000000000000000000000000000000",
            "0000000000000000FFFF00000100007F",
        ]:
            result = self._decode(hex_addr, True)
            assert len(result) == 16

    def test_ipv6_zeros(self):
        result = self._decode("00000000000000000000000000000000", True)
        assert result == b"\x00" * 16

    def test_ipv6_different_addrs_differ(self):
        a = self._decode("00000000000000000000000001000000", True)
        b = self._decode("000080FE000000000000000001000000", True)
        assert a != b

    def test_empty_string_returns_zeros(self):
        assert self._decode("", False) == b"\x00" * 16

    def test_empty_string_ipv6_returns_zeros(self):
        assert self._decode("", True) == b"\x00" * 16


# ===========================================================================
# Tests: collect_connection_table
# ===========================================================================

class TestCollectConnectionTable:
    """Tests for the Python-side connection table parsing."""

    def test_empty_when_no_api(self):
        """Returns [] when _api is None (not connected)."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        assert collector.collect_connection_table() == []

    def test_parses_ipv4_tcp_entry(self):
        """Parse a single IPv4 TCP connection from RPC result."""
        rpc_result = [{
            "pid": 1234,
            "family": 0x02,
            "protocol": 0x06,
            "state": 0x01,  # ESTABLISHED
            "localAddr": "0100007F",
            "localPort": 8080,
            "remoteAddr": "6401A8C0",
            "remotePort": 443,
        }]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        e = entries[0]
        assert isinstance(e, ConnectionEntry)
        assert e.pid == 1234
        assert e.family == 0x02
        assert e.protocol == 0x06
        assert e.state == 0x01
        # Address bytes match the decode method (platform-dependent byte order)
        assert e.local_addr == FridaRemoteCollector._decode_proc_net_addr("0100007F", False)
        assert e.local_port == 8080
        assert e.remote_addr == FridaRemoteCollector._decode_proc_net_addr("6401A8C0", False)
        assert e.remote_port == 443
        assert len(e.local_addr) == 16
        assert len(e.remote_addr) == 16

    def test_parses_ipv6_tcp_entry(self):
        """Parse an IPv6 TCP connection from RPC result."""
        ipv6_local = "00000000000000000000000001000000"
        ipv6_remote = "00000000000000000000000000000000"
        rpc_result = [{
            "pid": 5678,
            "family": 0x0A,
            "protocol": 0x06,
            "state": 0x0A,  # LISTEN
            "localAddr": ipv6_local,
            "localPort": 80,
            "remoteAddr": ipv6_remote,
            "remotePort": 0,
        }]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        e = entries[0]
        assert e.family == 0x0A
        assert e.local_addr == FridaRemoteCollector._decode_proc_net_addr(ipv6_local, True)
        assert e.remote_addr == b"\x00" * 16
        assert len(e.local_addr) == 16

    def test_parses_udp_entry(self):
        """Parse a UDP connection entry."""
        rpc_result = [{
            "pid": 99,
            "family": 0x02,
            "protocol": 0x11,
            "state": 0x00,
            "localAddr": "00000000",
            "localPort": 53,
            "remoteAddr": "00000000",
            "remotePort": 0,
        }]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        assert entries[0].protocol == 0x11

    def test_multiple_entries(self):
        """Multiple connection entries are all parsed."""
        rpc_result = [
            {"pid": 1, "family": 0x02, "protocol": 0x06, "state": 1,
             "localAddr": "0100007F", "localPort": 80,
             "remoteAddr": "0100007F", "remotePort": 9000},
            {"pid": 2, "family": 0x0A, "protocol": 0x11, "state": 0,
             "localAddr": "00000000000000000000000000000000", "localPort": 53,
             "remoteAddr": "00000000000000000000000000000000", "remotePort": 0},
        ]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()
        assert len(entries) == 2

    def test_rpc_exception_returns_empty(self):
        """RPC failure returns empty list."""
        collector, _ = _make_collector(rpc_side_effect=Exception("Frida died"))
        assert collector.collect_connection_table() == []

    def test_missing_fields_use_defaults(self):
        """Missing fields in JS dict fall back to defaults."""
        rpc_result = [{"pid": 10}]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        e = entries[0]
        assert e.pid == 10
        assert e.family == 0x02
        assert e.protocol == 0x06
        assert e.state == 0
        assert e.local_addr == b"\x00" * 16
        assert e.local_port == 0


# ===========================================================================
# Tests: collect_handle_table
# ===========================================================================

class TestCollectHandleTable:
    """Tests for the Python-side handle table parsing."""

    def test_empty_when_no_api(self):
        """Returns [] when _api is None."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        assert collector.collect_handle_table(1234) == []

    def test_parses_file_handle(self):
        rpc_result = [{"pid": 100, "fd": 3, "handleType": 1, "path": "/tmp/foo.txt"}]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(100)

        assert len(entries) == 1
        e = entries[0]
        assert isinstance(e, HandleEntry)
        assert e.pid == 100
        assert e.fd == 3
        assert e.handle_type == 1  # HT_FILE
        assert e.path == "/tmp/foo.txt"

    def test_parses_socket_handle(self):
        rpc_result = [{"pid": 100, "fd": 5, "handleType": 3, "path": "socket:[12345]"}]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(100)

        assert len(entries) == 1
        assert entries[0].handle_type == 3  # HT_SOCKET

    def test_parses_pipe_handle(self):
        rpc_result = [{"pid": 100, "fd": 7, "handleType": 4, "path": "pipe:[67890]"}]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(100)

        assert entries[0].handle_type == 4  # HT_PIPE

    def test_parses_device_handle(self):
        rpc_result = [{"pid": 100, "fd": 0, "handleType": 5, "path": "/dev/null"}]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(100)

        assert entries[0].handle_type == 5  # HT_DEVICE

    def test_multiple_handles(self):
        rpc_result = [
            {"pid": 100, "fd": 0, "handleType": 1, "path": "/dev/stdin"},
            {"pid": 100, "fd": 1, "handleType": 1, "path": "/dev/stdout"},
            {"pid": 100, "fd": 3, "handleType": 3, "path": "socket:[111]"},
        ]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(100)
        assert len(entries) == 3

    def test_rpc_exception_returns_empty(self):
        collector, _ = _make_collector(rpc_side_effect=Exception("timeout"))
        assert collector.collect_handle_table(100) == []

    def test_missing_fields_use_defaults(self):
        """Missing fields default to pid param, fd=0, type=0, path=''."""
        rpc_result = [{}]
        collector, api = _make_collector()
        api.get_handle_table.return_value = rpc_result
        entries = collector.collect_handle_table(42)

        assert len(entries) == 1
        e = entries[0]
        assert e.pid == 42  # falls back to the pid argument
        assert e.fd == 0
        assert e.handle_type == 0
        assert e.path == ""


# ===========================================================================
# Tests: _decode_darwin_addr (static method)
# ===========================================================================

class TestDecodeDarwinAddr:
    """Unit tests for the Darwin libproc address decoder.

    Darwin addresses are already in network byte order, so no byte swapping
    is performed.  IPv4 = 4 bytes + 12 zero pad.  IPv6 = 16 bytes.
    """

    _decode = staticmethod(FridaRemoteCollector._decode_darwin_addr)

    def test_ipv4_network_order(self):
        """'7f000001' (loopback, already network order) -> correct 16 bytes."""
        result = self._decode("7f000001", False)
        assert len(result) == 16
        assert result[:4] == b"\x7f\x00\x00\x01"
        assert result[4:] == b"\x00" * 12

    def test_ipv6_loopback(self):
        """32 hex chars for ::1 -> 15 zero bytes + 0x01."""
        result = self._decode("00000000000000000000000000000001", True)
        assert len(result) == 16
        assert result == b"\x00" * 15 + b"\x01"

    def test_empty_returns_zeros(self):
        """Empty string returns 16 zero bytes."""
        assert self._decode("", False) == b"\x00" * 16
        assert self._decode("", True) == b"\x00" * 16

    def test_ipv4_padding(self):
        """Short input like '0a00' is padded to 16 bytes."""
        result = self._decode("0a00", False)
        assert len(result) == 16
        assert result[:2] == b"\x0a\x00"
        assert result[2:] == b"\x00" * 14


# ===========================================================================
# Tests: Darwin connection table parsing
# ===========================================================================

class TestDarwinConnectionTable:
    """Tests for Darwin-specific connection table parsing."""

    def test_darwin_connection_entry(self):
        """Darwin entry with _networkOrder=True uses _decode_darwin_addr (no swap)."""
        rpc_result = [{
            "pid": 42,
            "family": 0x02,
            "protocol": 0x06,
            "state": 0x01,
            "localAddr": "7f000001",
            "localPort": 80,
            "remoteAddr": "c0a80101",
            "remotePort": 443,
            "_networkOrder": True,
        }]
        collector, _ = _make_collector(rpc_result=rpc_result)
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        e = entries[0]
        # Darwin addresses are already in network byte order — no swapping
        assert e.local_addr[:4] == b"\x7f\x00\x00\x01"
        assert e.local_addr[4:] == b"\x00" * 12
        assert e.remote_addr[:4] == b"\xc0\xa8\x01\x01"
        assert e.remote_addr[4:] == b"\x00" * 12

    def test_darwin_and_linux_entries_use_different_decoders(self):
        """One _networkOrder entry and one Linux entry parse with their own decoders."""
        darwin_entry = {
            "pid": 1,
            "family": 0x02,
            "protocol": 0x06,
            "state": 0x01,
            "localAddr": "7f000001",
            "localPort": 80,
            "remoteAddr": "00000000",
            "remotePort": 0,
            "_networkOrder": True,
        }
        linux_entry = {
            "pid": 2,
            "family": 0x02,
            "protocol": 0x06,
            "state": 0x01,
            "localAddr": "0100007F",
            "localPort": 80,
            "remoteAddr": "00000000",
            "remotePort": 0,
        }
        collector, _ = _make_collector(rpc_result=[darwin_entry, linux_entry])
        entries = collector.collect_connection_table()

        assert len(entries) == 2
        darwin_e = entries[0]
        linux_e = entries[1]

        # Darwin: network byte order, no swap — 7f000001 -> \x7f\x00\x00\x01
        assert darwin_e.local_addr[:4] == b"\x7f\x00\x00\x01"

        # Linux: uses proc_net decode (host byte order swap)
        expected_linux = FridaRemoteCollector._decode_proc_net_addr("0100007F", False)
        assert linux_e.local_addr == expected_linux


# ===========================================================================
# Tests: P1.4b RPC envelope {data, warnings} contract
# ===========================================================================

class TestFridaRPCEnvelope:
    """Tests for the new {data, warnings} RPC marshaling shape introduced
    in P1.4b. Verifies warning surfacing into TargetSystemInfo.collector_warnings,
    new field projection on TargetSystemInfo, and backward compatibility with
    the legacy flat-shape RPC response.
    """

    def test_system_info_unwraps_data_warnings(self):
        """{data: {...}, warnings: [...]} envelope is unwrapped correctly."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_system_info.return_value = {
            "data": {"hostname": "h", "osDetail": "X", "bootTime": 123},
            "warnings": ["w1", "w2"],
        }
        info = collector.collect_system_info()

        assert isinstance(info, TargetSystemInfo)
        assert info.hostname == "h"
        assert info.os_detail == "X"
        assert info.boot_time == 123
        assert "w1" in info.collector_warnings
        assert "w2" in info.collector_warnings

    def test_system_info_android_fields_projected(self):
        """Android enrichment fields land on TargetSystemInfo."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_system_info.return_value = {
            "data": {
                "osDetail": "Android 14",
                "fingerprint": "google/raven/raven:14/UQ1A.240205.004/...",
                "patchLevel": "2024-03-01",
                "bootloaderLocked": "1",
                "verifiedBoot": "green",
                "dmVerity": "enforcing",
                "buildType": "user",
                "cryptoType": "file",
                "env": "physical",
                "hwVendor": "Google",
                "hwModel": "Pixel 6",
                "distro": "Android 14 (API 34)",
            },
            "warnings": [],
        }
        info = collector.collect_system_info()

        assert info.os_detail == "Android 14"
        assert info.fingerprint == "google/raven/raven:14/UQ1A.240205.004/..."
        assert info.patch_level == "2024-03-01"
        assert info.bootloader_locked == "1"
        assert info.verified_boot == "green"
        assert info.dm_verity == "enforcing"
        assert info.build_type == "user"
        assert info.crypto_type == "file"
        assert info.env == "physical"
        assert info.hw_vendor == "Google"
        assert info.hw_model == "Pixel 6"
        assert info.distro == "Android 14 (API 34)"
        assert info.collector_warnings == []

    def test_system_info_windows_fields_projected(self):
        """Windows enrichment fields land on TargetSystemInfo."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_system_info.return_value = {
            "data": {
                "kernel": "10.0.22631",
                "distro": "Windows 11 Pro 23H2 (Build 22631)",
                "osDetail": "Windows 11 Pro 23H2 (Build 22631)",
                "hwModel": "OptiPlex 7090",
                "ramBytes": 17179869184,
                "machineId": "abc-123",
                "cpuBrand": "Intel(R) Core(TM) i7-11700",
            },
            "warnings": [],
        }
        info = collector.collect_system_info()

        assert info.kernel == "10.0.22631"
        assert info.distro == "Windows 11 Pro 23H2 (Build 22631)"
        assert info.os_detail == "Windows 11 Pro 23H2 (Build 22631)"
        assert info.hw_model == "OptiPlex 7090"
        assert info.ram_bytes == 17179869184
        assert info.machine_id == "abc-123"
        assert info.cpu_brand == "Intel(R) Core(TM) i7-11700"

    def test_connection_table_unwraps_envelope(self):
        """Envelope-wrapped connection table is unwrapped and parsed."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_connection_table.return_value = {
            "data": [{
                "pid": 4242,
                "family": 0x02,
                "protocol": 0x06,
                "state": 0x01,
                "localAddr": "0100007F",
                "localPort": 8080,
                "remoteAddr": "00000000",
                "remotePort": 0,
            }],
            "warnings": [],
        }
        entries = collector.collect_connection_table()
        assert len(entries) == 1
        assert entries[0].pid == 4242
        assert entries[0].local_port == 8080

    def test_legacy_flat_shape_still_works(self):
        """Legacy flat-list shape is still accepted (backward compat)."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_connection_table.return_value = [{
            "pid": 7,
            "family": 0x02,
            "protocol": 0x06,
            "state": 0x01,
            "localAddr": "0100007F",
            "localPort": 22,
            "remoteAddr": "00000000",
            "remotePort": 0,
        }]
        entries = collector.collect_connection_table()
        assert len(entries) == 1
        assert entries[0].pid == 7
        # Also verify legacy flat shape on system_info doesn't carry warnings.
        collector._api.get_system_info.return_value = {
            "hostname": "legacy",
            "osDetail": "Linux legacy",
            "bootTime": 0,
        }
        info = collector.collect_system_info()
        assert info.hostname == "legacy"
        assert info.os_detail == "Linux legacy"
        assert info.collector_warnings == []

    def test_process_identity_android_new_fields(self):
        """processName, package, exePath populated for Android process."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_process_info.return_value = {
            "data": {
                "ppid": 1,
                "sessionId": 0,
                "startTimeNs": 1000,
                "exePath": "/system/bin/app_process64",
                "cmdLine": "com.whatsapp:push",
                "processName": "com.whatsapp:push",
                "package": "com.whatsapp",
            },
            "warnings": [],
        }
        info = collector.collect_process_identity(1234)
        assert isinstance(info, TargetProcessInfo)
        assert info.process_name == "com.whatsapp:push"
        assert info.package == "com.whatsapp"
        assert info.exe_path == "/system/bin/app_process64"
        assert info.cmd_line == "com.whatsapp:push"

    def test_warnings_surface_in_collector_warnings(self):
        """JS-side warnings are surfaced into TargetSystemInfo.collector_warnings."""
        session = MagicMock()
        collector = FridaRemoteCollector(session=session)
        collector._api = MagicMock()
        collector._api.get_system_info.return_value = {
            "data": {},
            "warnings": ["linux_net_parse:ENOENT"],
        }
        info = collector.collect_system_info()
        assert "linux_net_parse:ENOENT" in info.collector_warnings
