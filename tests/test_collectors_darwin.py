"""Tests for DarwinCollector (macOS investigation data collection)."""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.constants import (
    HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE, HT_UNKNOWN,
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
)
from memslicer.acquirer.collectors.darwin import DarwinCollector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return DarwinCollector()


def _make_completed(stdout="", returncode=0):
    """Helper to build a subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# collect_process_identity
# ---------------------------------------------------------------------------

class TestCollectProcessIdentity:
    """Tests for DarwinCollector.collect_process_identity."""

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_basic_identity(self, mock_run, collector):
        """Verify ppid, session_id, start_time, exe_path, cmd_line."""
        # Single combined ps call returns all fields
        ps_output = "   100  5000 Mon Jan  2 15:04:05 2023 /usr/bin/python3 /usr/bin/python3 script.py --verbose\n"
        mock_run.return_value = _make_completed(ps_output)

        info = collector.collect_process_identity(1234)

        assert info.ppid == 100
        assert info.session_id == 5000
        assert info.exe_path == "/usr/bin/python3"
        assert "/usr/bin/python3 script.py --verbose" in info.cmd_line
        assert info.start_time_ns > 0

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_identity_ps_failure(self, mock_run, collector):
        """When ps call fails, return default TargetProcessInfo."""
        mock_run.return_value = _make_completed("", returncode=1)
        info = collector.collect_process_identity(999)
        assert info.ppid == 0
        assert info.session_id == 0
        assert info.exe_path == ""
        assert info.cmd_line == ""
        assert info.start_time_ns == 0

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_identity_partial_ps_output(self, mock_run, collector):
        """When output has only one numeric field, parsing handles gracefully."""
        mock_run.return_value = _make_completed("   100\n")

        info = collector.collect_process_identity(42)
        # Only one field means split(None, 2) gives < 3 parts → defaults
        assert info.ppid == 0
        assert info.session_id == 0


# ---------------------------------------------------------------------------
# collect_system_info
# ---------------------------------------------------------------------------

class TestCollectSystemInfo:
    """Tests for DarwinCollector.collect_system_info."""

    @patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="myhost")
    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_system_info_full(self, mock_run, mock_hostname, collector):
        ioreg_output = (
            '+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice>\n'
            '    | {\n'
            '    |   "IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"\n'
            '    |   "IOPlatformSerialNumber" = "C02ZXYZABC123"\n'
            '    | }\n'
        )
        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed(
                "{ sec = 1712345678, usec = 0 } Mon Apr  1 00:00:00 2024\n"
            ),
            ("domainname",): _make_completed("example.com\n"),
            ("sw_vers",): _make_completed(
                "ProductName:\tmacOS\nProductVersion:\t14.4\nBuildVersion:\t23E214\n"
            ),
            ("uname", "-r"): _make_completed("23.4.0\n"),
            ("sysctl", "-n", "kern.osrelease"): _make_completed("23.4.0\n"),
            ("sysctl", "-n", "hw.machine"): _make_completed("arm64\n"),
            ("sysctl", "-n", "hw.model"): _make_completed("MacBookPro18,2\n"),
            ("sysctl", "-n", "machdep.cpu.brand_string"): _make_completed(
                "Apple M1 Max\n"
            ),
            ("sysctl", "-n", "hw.ncpu"): _make_completed("10\n"),
            ("sysctl", "-n", "hw.memsize"): _make_completed("34359738368\n"),
            ("sysctl", "-n", "kern.hv_vmm_present"): _make_completed("0\n"),
            ("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"): _make_completed(
                ioreg_output
            ),
        }

        def side_effect(cmd, **kwargs):
            return responses.get(tuple(cmd), _make_completed("", returncode=1))

        mock_run.side_effect = side_effect

        with patch(
            "memslicer.acquirer.collectors.darwin.read_symlink",
            return_value="/var/db/timezone/zoneinfo/Europe/Berlin",
        ):
            info = collector.collect_system_info()

        assert info.boot_time == 1712345678 * 1_000_000_000
        assert info.hostname == "myhost"
        assert info.domain == "example.com"
        assert "macOS" in info.os_detail
        assert "14.4" in info.os_detail
        assert "kernel 23.4.0" in info.os_detail
        # Darwin intentionally leaves raw_os empty — system_info_to_fields
        # falls back to os_detail when raw_os is empty, so the wire output
        # still carries the legacy string without duplicating it here.
        assert info.raw_os == ""
        assert info.kernel == "23.4.0"
        assert info.arch == "arm64"
        assert info.distro == "macOS 14.4 (23E214)"
        assert info.machine_id == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        assert info.hw_vendor == "Apple"
        assert info.hw_model == "MacBookPro18,2"
        assert info.hw_serial == "C02ZXYZABC123"
        assert info.bios_version == ""
        assert info.cpu_brand == "Apple M1 Max"
        assert info.cpu_count == 10
        assert info.ram_bytes == 34359738368
        assert info.virtualization == "none"
        assert info.timezone == "Europe/Berlin"

    @patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host")
    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_system_info_domain_none(self, mock_run, mock_hostname, collector):
        """Domain '(none)' should be normalized to empty string."""
        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed("", returncode=1),
            ("domainname",): _make_completed("(none)\n"),
            ("sw_vers",): _make_completed("", returncode=1),
            ("uname", "-r"): _make_completed("", returncode=1),
        }
        mock_run.side_effect = lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))

        info = collector.collect_system_info()
        assert info.domain == ""

    @patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host")
    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_boot_time_no_match(self, mock_run, mock_hostname, collector):
        """If sysctl output doesn't contain sec=, boot_time should be 0."""
        responses = {
            ("sysctl", "-n", "kern.boottime"): _make_completed("garbage\n"),
            ("domainname",): _make_completed("", returncode=1),
            ("sw_vers",): _make_completed("", returncode=1),
            ("uname", "-r"): _make_completed("", returncode=1),
        }
        mock_run.side_effect = lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))

        info = collector.collect_system_info()
        assert info.boot_time == 0

    @patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host")
    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_collect_system_info_populates_machine_id_from_ioreg_not_kern_uuid(
        self, mock_run, mock_hostname, collector
    ):
        """machine_id must come from IOPlatformUUID in ioreg, never from kern.uuid."""
        ioreg_output = (
            '    "IOPlatformUUID" = "11111111-2222-3333-4444-555555555555"\n'
            '    "IOPlatformSerialNumber" = "SERIAL42"\n'
        )
        responses = {
            ("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"): _make_completed(
                ioreg_output
            ),
        }

        observed_cmds: list[tuple[str, ...]] = []

        def side_effect(cmd, **kwargs):
            observed_cmds.append(tuple(cmd))
            return responses.get(tuple(cmd), _make_completed("", returncode=1))

        mock_run.side_effect = side_effect

        with patch(
            "memslicer.acquirer.collectors.darwin.read_symlink",
            return_value="",
        ):
            info = collector.collect_system_info()

        assert info.machine_id == "11111111-2222-3333-4444-555555555555"
        assert info.hw_serial == "SERIAL42"
        # Must never shell out to sysctl kern.uuid for the platform UUID.
        assert ("sysctl", "-n", "kern.uuid") not in observed_cmds

    @patch("memslicer.acquirer.collectors.darwin.socket.gethostname", return_value="host")
    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_collect_system_info_populates_hw_model_arch_ram_cpu(
        self, mock_run, mock_hostname, collector
    ):
        """hw.model, hw.machine, hw.memsize, hw.ncpu, cpu brand all land on info."""
        responses = {
            ("sysctl", "-n", "kern.osrelease"): _make_completed("22.6.0\n"),
            ("sysctl", "-n", "hw.machine"): _make_completed("x86_64\n"),
            ("sysctl", "-n", "hw.model"): _make_completed("MacBookPro16,1\n"),
            ("sysctl", "-n", "machdep.cpu.brand_string"): _make_completed(
                "Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz\n"
            ),
            ("sysctl", "-n", "hw.ncpu"): _make_completed("16\n"),
            ("sysctl", "-n", "hw.memsize"): _make_completed("17179869184\n"),
            ("sysctl", "-n", "kern.hv_vmm_present"): _make_completed("1\n"),
        }
        mock_run.side_effect = (
            lambda cmd, **kw: responses.get(tuple(cmd), _make_completed("", returncode=1))
        )

        with patch(
            "memslicer.acquirer.collectors.darwin.read_symlink",
            return_value="/usr/share/zoneinfo/America/Los_Angeles",
        ):
            info = collector.collect_system_info()

        assert info.kernel == "22.6.0"
        assert info.arch == "x86_64"
        assert info.hw_model == "MacBookPro16,1"
        assert info.cpu_brand == "Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz"
        assert info.cpu_count == 16
        assert info.ram_bytes == 17179869184
        assert info.virtualization == "hypervisor"
        assert info.timezone == "America/Los_Angeles"
        # Unreachable fields gracefully default.
        assert info.machine_id == ""
        assert info.hw_serial == ""
        assert info.bios_version == ""


# ---------------------------------------------------------------------------
# collect_process_table
# ---------------------------------------------------------------------------

class TestCollectProcessTable:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_process_table_parsing(self, mock_run, collector):
        ps_output = (
            "    1     0     0  1024 /sbin/launchd /sbin/launchd\n"
            "  100     1   501  2048 /usr/bin/python3 /usr/bin/python3 app.py\n"
            "  200     1   501  4096 /usr/bin/vim vim file.txt\n"
        )
        mock_run.return_value = _make_completed(ps_output)

        entries = collector.collect_process_table(target_pid=100)

        assert len(entries) == 3
        # Check target marking
        target = [e for e in entries if e.is_target]
        assert len(target) == 1
        assert target[0].pid == 100
        assert target[0].ppid == 1
        assert target[0].uid == 501
        assert target[0].rss == 2048 * 1024
        assert target[0].exe_name == "python3"

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_process_table_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector.collect_process_table(1) == []

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_process_table_malformed_line(self, mock_run, collector):
        """Lines with fewer than 5 fields should be skipped."""
        ps_output = "1 0 0\n100 1 501 2048 python3 python3 foo\n"
        mock_run.return_value = _make_completed(ps_output)
        entries = collector.collect_process_table(100)
        assert len(entries) == 1
        assert entries[0].pid == 100


# ---------------------------------------------------------------------------
# collect_connection_table
# ---------------------------------------------------------------------------

class TestCollectConnectionTable:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_connection_table_tcp(self, mock_run, collector):
        lsof_output = (
            "COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python3  1234   user   3u  IPv4 0x1234      0t0  TCP 127.0.0.1:8080->10.0.0.1:443 (ESTABLISHED)\n"
        )
        mock_run.return_value = _make_completed(lsof_output)

        entries = collector.collect_connection_table()

        assert len(entries) == 1
        conn = entries[0]
        assert conn.pid == 1234
        assert conn.protocol == PROTO_TCP
        assert conn.state == 0x01  # ESTABLISHED
        assert conn.local_port == 8080
        assert conn.remote_port == 443

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_connection_table_udp(self, mock_run, collector):
        lsof_output = (
            "COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "dns      5678   root   4u  IPv4 0x5678      0t0  UDP *:53\n"
        )
        mock_run.return_value = _make_completed(lsof_output)

        entries = collector.collect_connection_table()

        # The UDP line may or may not parse depending on field count
        # (lsof UDP lines have fewer fields). Verify graceful handling.
        # UDP lines have 9 fields, which is < 10, so they are skipped.
        assert len(entries) == 0

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_connection_table_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector.collect_connection_table() == []


# ---------------------------------------------------------------------------
# collect_handle_table
# ---------------------------------------------------------------------------

class TestCollectHandleTable:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_handle_table_parsing(self, mock_run, collector):
        lsof_output = (
            "COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python3  1234   user  cwd    DIR  1,18      640    2 /Users/user\n"
            "python3  1234   user    3r   REG  1,18      100  123 /tmp/data.txt\n"
            "python3  1234   user    4u  IPv4 0x1234      0t0  TCP 127.0.0.1:8080 (LISTEN)\n"
        )
        mock_run.return_value = _make_completed(lsof_output)

        entries = collector.collect_handle_table(1234)

        assert len(entries) == 3
        # cwd entry
        assert entries[0].fd == -1
        assert entries[0].handle_type == HT_DIR
        assert entries[0].path == "/Users/user"
        # REG entry
        assert entries[1].fd == 3
        assert entries[1].handle_type == HT_FILE
        # IPv4 entry
        assert entries[2].fd == 4
        assert entries[2].handle_type == HT_SOCKET

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_handle_table_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("", returncode=1)
        assert collector.collect_handle_table(1234) == []


# ---------------------------------------------------------------------------
# _classify_lsof_type
# ---------------------------------------------------------------------------

class TestClassifyLsofType:

    @pytest.mark.parametrize("fd_type,expected", [
        ("REG", HT_FILE),
        ("DIR", HT_DIR),
        ("IPv4", HT_SOCKET),
        ("IPv6", HT_SOCKET),
        ("sock", HT_SOCKET),
        ("unix", HT_SOCKET),
        ("FIFO", HT_PIPE),
        ("PIPE", HT_PIPE),
        ("CHR", HT_DEVICE),
        ("BLK", HT_DEVICE),
        ("UNKNOWN_TYPE", HT_UNKNOWN),
        ("", HT_UNKNOWN),
    ])
    def test_type_classification(self, fd_type, expected):
        assert DarwinCollector._classify_lsof_type(fd_type) == expected


# ---------------------------------------------------------------------------
# _parse_addr_port
# ---------------------------------------------------------------------------

class TestParseAddrPort:

    def setup_method(self):
        self.collector = DarwinCollector()

    def test_ipv4_address(self):
        addr, port, family = self.collector._parse_addr_port("192.168.1.1:8080")
        assert port == 8080
        assert family == AF_INET
        # First 4 bytes should be the IPv4 address, rest zero-padded
        assert addr[:4] == b"\xc0\xa8\x01\x01"
        assert addr[4:] == b"\x00" * 12

    def test_ipv6_address(self):
        addr, port, family = self.collector._parse_addr_port("[::1]:443")
        assert port == 443
        assert family == AF_INET6
        assert addr == b"\x00" * 15 + b"\x01"

    def test_wildcard(self):
        addr, port, family = self.collector._parse_addr_port("*:*")
        assert addr == b"\x00" * 16
        assert port == 0
        assert family == AF_INET

    def test_wildcard_with_port(self):
        addr, port, family = self.collector._parse_addr_port("*:53")
        assert port == 53
        assert addr == b"\x00" * 16

    def test_empty_string(self):
        addr, port, family = self.collector._parse_addr_port("")
        assert addr == b"\x00" * 16
        assert port == 0

    def test_no_colon(self):
        addr, port, family = self.collector._parse_addr_port("noport")
        assert addr == b"\x00" * 16
        assert port == 0


# ---------------------------------------------------------------------------
# _run_cmd error handling
# ---------------------------------------------------------------------------

class TestRunCmd:

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_timeout_returns_empty(self, mock_run, collector):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=10)
        assert collector._run_cmd(["test"]) == ""

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_file_not_found_returns_empty(self, mock_run, collector):
        mock_run.side_effect = FileNotFoundError("no such file")
        assert collector._run_cmd(["nonexistent"]) == ""

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_nonzero_returncode_returns_empty(self, mock_run, collector):
        mock_run.return_value = _make_completed("some output", returncode=1)
        assert collector._run_cmd(["failing_cmd"]) == ""

    @patch("memslicer.acquirer.collectors.darwin.subprocess.run")
    def test_success_returns_stdout(self, mock_run, collector):
        mock_run.return_value = _make_completed("hello world\n")
        assert collector._run_cmd(["echo"]) == "hello world\n"
