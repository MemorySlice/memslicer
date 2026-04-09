"""Tests for WindowsCollector (Windows investigation data collection)."""
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
)
from memslicer.acquirer.collectors.windows import (
    WindowsCollector,
    _NETSTAT_STATES,
)


def _make_completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture
def collector():
    return WindowsCollector()


# ---------------------------------------------------------------------------
# collect_process_identity
# ---------------------------------------------------------------------------

class TestCollectProcessIdentity:

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_identity_from_wmic(self, mock_run, collector):
        """Parse wmic LIST format output correctly."""
        wmic_output = (
            "\r\n"
            "CommandLine=C:\\Python311\\python.exe script.py\r\n"
            "CreationDate=20240401120000.000000+000\r\n"
            "ExecutablePath=C:\\Python311\\python.exe\r\n"
            "ParentProcessId=1000\r\n"
            "SessionId=1\r\n"
            "\r\n"
        )
        mock_run.return_value = _make_completed(wmic_output)

        info = collector.collect_process_identity(5678)

        assert info.ppid == 1000
        assert info.session_id == 1
        assert info.exe_path == "C:\\Python311\\python.exe"
        assert info.cmd_line == "C:\\Python311\\python.exe script.py"
        assert info.start_time_ns > 0

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_identity_wmic_failure_falls_back(self, mock_run, collector):
        """When wmic fails, tries PowerShell; when both fail, returns defaults."""
        mock_run.return_value = _make_completed("", returncode=1)

        info = collector.collect_process_identity(999)

        assert info.ppid == 0
        assert info.session_id == 0
        assert info.exe_path == ""
        assert info.cmd_line == ""

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_identity_empty_fields(self, mock_run, collector):
        """Handle LIST format with empty values gracefully."""
        wmic_output = (
            "CommandLine=\r\n"
            "CreationDate=\r\n"
            "ExecutablePath=\r\n"
            "ParentProcessId=0\r\n"
            "SessionId=0\r\n"
        )
        mock_run.return_value = _make_completed(wmic_output)

        info = collector.collect_process_identity(1)
        assert info.ppid == 0
        assert info.exe_path == ""
        assert info.start_time_ns == 0


# ---------------------------------------------------------------------------
# collect_system_info
# ---------------------------------------------------------------------------

class TestCollectSystemInfo:

    @patch("memslicer.acquirer.collectors.windows.platform.platform", return_value="Windows-10-10.0.19045-SP0")
    @patch.dict("os.environ", {"COMPUTERNAME": "WORKSTATION01", "USERDOMAIN": "CORP"})
    def test_system_info_from_env(self, mock_platform, collector):
        """System info should use COMPUTERNAME and USERDOMAIN env vars."""
        with patch.object(collector, "_read_boot_time", return_value=1712345678_000_000_000):
            info = collector.collect_system_info()

        assert info.hostname == "WORKSTATION01"
        assert info.domain == "CORP"
        assert "Windows" in info.os_detail
        assert info.boot_time == 1712345678_000_000_000

    @patch("memslicer.acquirer.collectors.windows.platform.platform", return_value="Windows-11")
    @patch.dict("os.environ", {}, clear=True)
    def test_system_info_no_env(self, mock_platform, collector):
        """When env vars are missing, fall back to socket.gethostname."""
        with patch.object(collector, "_read_boot_time", return_value=0), \
             patch.object(WindowsCollector, "_get_hostname", return_value="FALLBACK"):
            info = collector.collect_system_info()

        assert info.hostname == "FALLBACK"
        assert info.domain == ""


# ---------------------------------------------------------------------------
# collect_process_table
# ---------------------------------------------------------------------------

class TestCollectProcessTable:

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_process_table_csv(self, mock_run, collector):
        """Parse tasklist /V /FO CSV output."""
        csv_output = (
            '"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"\r\n'
            '"System Idle Process","0","Services","0","8 K","Unknown","NT AUTHORITY\\SYSTEM","0:00:00","N/A"\r\n'
            '"python.exe","1234","Console","1","45,678 K","Running","USER\\admin","0:01:23","script"\r\n'
        )
        mock_run.return_value = _make_completed(csv_output)

        entries = collector.collect_process_table(target_pid=1234)

        assert len(entries) == 2
        target = [e for e in entries if e.is_target]
        assert len(target) == 1
        assert target[0].pid == 1234
        assert target[0].exe_name == "python.exe"
        assert target[0].rss == 45678 * 1024

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_process_table_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector.collect_process_table(1) == []

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_process_table_header_only(self, mock_run, collector):
        """CSV with header but no data rows."""
        csv_output = '"Image Name","PID","Session Name","Session#","Mem Usage"\r\n'
        mock_run.return_value = _make_completed(csv_output)
        assert collector.collect_process_table(1) == []


# ---------------------------------------------------------------------------
# collect_connection_table
# ---------------------------------------------------------------------------

class TestCollectConnectionTable:

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_connection_table_tcp_established(self, mock_run, collector):
        netstat_output = (
            "Active Connections\r\n"
            "\r\n"
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    127.0.0.1:8080         10.0.0.1:443           ESTABLISHED     1234\r\n"
        )
        mock_run.return_value = _make_completed(netstat_output)

        entries = collector.collect_connection_table()

        assert len(entries) == 1
        conn = entries[0]
        assert conn.pid == 1234
        assert conn.protocol == PROTO_TCP
        assert conn.state == _NETSTAT_STATES["ESTABLISHED"]
        assert conn.local_port == 8080
        assert conn.remote_port == 443
        assert conn.family == AF_INET

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_connection_table_udp(self, mock_run, collector):
        netstat_output = (
            "Active Connections\r\n"
            "\r\n"
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  UDP    0.0.0.0:53             *:*                                    5678\r\n"
        )
        mock_run.return_value = _make_completed(netstat_output)

        entries = collector.collect_connection_table()

        assert len(entries) == 1
        conn = entries[0]
        assert conn.pid == 5678
        assert conn.protocol == PROTO_UDP
        assert conn.state == 0x00
        assert conn.local_port == 53

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_connection_table_ipv6(self, mock_run, collector):
        netstat_output = (
            "Active Connections\r\n"
            "\r\n"
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    [::1]:445              [::1]:50000            ESTABLISHED     2000\r\n"
        )
        mock_run.return_value = _make_completed(netstat_output)

        entries = collector.collect_connection_table()

        assert len(entries) == 1
        conn = entries[0]
        assert conn.family == AF_INET6
        assert conn.local_port == 445
        assert conn.remote_port == 50000

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_connection_table_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector.collect_connection_table() == []

    @patch("memslicer.acquirer.collectors.windows.subprocess.run")
    def test_connection_table_listening(self, mock_run, collector):
        netstat_output = (
            "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4\r\n"
        )
        mock_run.return_value = _make_completed(netstat_output)

        entries = collector.collect_connection_table()

        assert len(entries) == 1
        assert entries[0].state == _NETSTAT_STATES["LISTENING"]


# ---------------------------------------------------------------------------
# collect_handle_table
# ---------------------------------------------------------------------------

class TestCollectHandleTable:

    def test_handle_table_returns_empty_on_non_windows(self, collector):
        """Handle table returns empty list silently on non-Windows platforms."""
        with patch("os.name", "posix"):
            entries = collector.collect_handle_table(1234)

        assert entries == []


# ---------------------------------------------------------------------------
# _parse_netstat_line
# ---------------------------------------------------------------------------

class TestParseNetstatLine:

    def test_tcp_established(self, collector):
        line = "  TCP    192.168.1.100:49152    93.184.216.34:80       ESTABLISHED     3456"
        entry = collector._parse_netstat_line(line)
        assert entry is not None
        assert entry.protocol == PROTO_TCP
        assert entry.state == _NETSTAT_STATES["ESTABLISHED"]
        assert entry.pid == 3456
        assert entry.local_port == 49152
        assert entry.remote_port == 80

    def test_udp_line(self, collector):
        line = "  UDP    0.0.0.0:5353           *:*                                    1000"
        entry = collector._parse_netstat_line(line)
        assert entry is not None
        assert entry.protocol == PROTO_UDP
        assert entry.state == 0x00
        assert entry.pid == 1000
        assert entry.local_port == 5353

    def test_ipv6_line(self, collector):
        line = "  TCP    [::1]:8080             [::1]:50000            ESTABLISHED     2000"
        entry = collector._parse_netstat_line(line)
        assert entry is not None
        assert entry.family == AF_INET6

    def test_header_line_skipped(self, collector):
        assert collector._parse_netstat_line("Active Connections") is None
        assert collector._parse_netstat_line("  Proto  Local Address") is None

    def test_empty_line_skipped(self, collector):
        assert collector._parse_netstat_line("") is None
        assert collector._parse_netstat_line("   ") is None

    def test_unknown_protocol_skipped(self, collector):
        line = "  ICMP   192.168.1.1:0          0.0.0.0:0              0"
        assert collector._parse_netstat_line(line) is None

    def test_close_wait(self, collector):
        line = "  TCP    10.0.0.1:443           10.0.0.2:12345         CLOSE_WAIT      999"
        entry = collector._parse_netstat_line(line)
        assert entry is not None
        assert entry.state == _NETSTAT_STATES["CLOSE_WAIT"]


# ---------------------------------------------------------------------------
# _parse_list_format
# ---------------------------------------------------------------------------

class TestParseListFormat:

    def test_basic_parsing(self):
        text = "Key1=Value1\nKey2=Value2\nKey3=\n"
        result = WindowsCollector._parse_list_format(text)
        assert result == {"Key1": "Value1", "Key2": "Value2", "Key3": ""}

    def test_value_with_equals(self):
        text = "CommandLine=python.exe -c x=1\n"
        result = WindowsCollector._parse_list_format(text)
        assert result["CommandLine"] == "python.exe -c x=1"

    def test_empty_input(self):
        assert WindowsCollector._parse_list_format("") == {}

    def test_lines_without_equals_skipped(self):
        text = "no equals here\nKey=Value\n"
        result = WindowsCollector._parse_list_format(text)
        assert result == {"Key": "Value"}


# ---------------------------------------------------------------------------
# _parse_wmi_datetime
# ---------------------------------------------------------------------------

class TestParseWmiDatetime:

    def test_valid_datetime(self):
        ns = WindowsCollector._parse_wmi_datetime("20240401120000.000000+000")
        assert ns > 0

    def test_invalid_datetime(self):
        assert WindowsCollector._parse_wmi_datetime("not-a-date") == 0

    def test_empty_string(self):
        assert WindowsCollector._parse_wmi_datetime("") == 0


# ---------------------------------------------------------------------------
# _classify_win_type
# ---------------------------------------------------------------------------

class TestWindowsHandleTableClassify:
    """Tests for the _classify_win_type helper function."""

    def test_classify_win_type_file(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_FILE
        assert _classify_win_type("File") == HT_FILE  # 0x01

    def test_classify_win_type_directory(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_DIR
        assert _classify_win_type("Directory") == HT_DIR  # 0x02

    def test_classify_win_type_key(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_REGISTRY
        assert _classify_win_type("Key") == HT_REGISTRY  # 0x06

    def test_classify_win_type_socket(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_SOCKET
        assert _classify_win_type("TcpEndpoint") == HT_SOCKET  # 0x03

    def test_classify_win_type_device(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_DEVICE
        assert _classify_win_type("Device") == HT_DEVICE  # 0x05

    def test_classify_win_type_unknown(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_UNKNOWN
        assert _classify_win_type("Mutant") == HT_UNKNOWN  # 0x00

    def test_classify_win_type_case_insensitive(self):
        from memslicer.acquirer.collectors.windows import _classify_win_type
        from memslicer.acquirer.collectors.constants import HT_FILE
        assert _classify_win_type("FILE") == HT_FILE


# ---------------------------------------------------------------------------
# Handle table on non-Windows
# ---------------------------------------------------------------------------

class TestWindowsHandleTableNonWindows:

    def test_handle_table_returns_empty_on_non_windows(self, collector):
        """collect_handle_table returns [] on non-Windows platforms."""
        with patch("memslicer.acquirer.collectors.windows.os") as mock_os:
            mock_os.name = "posix"
            entries = collector.collect_handle_table(1234)
        assert entries == []
