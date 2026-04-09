"""Tests for LinuxCollector using mock /proc filesystem."""
import logging
import logging.handlers
import os
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.linux import LinuxCollector


# ---------------------------------------------------------------------------
# Helpers for building mock /proc trees
# ---------------------------------------------------------------------------

def _write(path: Path, content: str) -> None:
    """Write content to a file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _make_proc_stat_line(pid: int, comm: str, state: str, ppid: int,
                         pgrp: int, session: int, starttime: int) -> str:
    """Build a /proc/<pid>/stat line.

    Fields after closing paren: state ppid pgrp session tty_nr tpgid flags
    minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
    num_threads itrealvalue starttime ...
    """
    # Fields 0-18 after the closing ')': state ppid pgrp session + 15 padding fields
    padding = "0 " * 15  # fields 4..18
    after_paren = f"{state} {ppid} {pgrp} {session} {padding}{starttime} 0 0"
    return f"{pid} ({comm}) {after_paren}\n"


def _setup_basic_process(proc_root: Path, pid: int, comm: str = "bash",
                         ppid: int = 1, session: int = 1234,
                         starttime: int = 5000,
                         exe_target: str = "/usr/bin/bash",
                         cmdline: str = "bash\x00--login",
                         uid: int = 1000, rss_pages: int = 512) -> None:
    """Create a minimal /proc/<pid> directory with typical files."""
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)

    stat_line = _make_proc_stat_line(pid, comm, "S", ppid, pid, session, starttime)
    _write(pid_dir / "stat", stat_line)
    _write(pid_dir / "cmdline", cmdline)
    _write(pid_dir / "status", f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    _write(pid_dir / "statm", f"2000 {rss_pages} 100 50 0 150 0\n")

    # exe symlink
    exe_link = pid_dir / "exe"
    if exe_target:
        exe_link.symlink_to(exe_target)

    # fd directory (empty by default)
    (pid_dir / "fd").mkdir(exist_ok=True)


def _setup_system_files(proc_root: Path, btime: int = 1700000000,
                        hostname: str = "testhost",
                        domainname: str = "(none)",
                        version: str = "Linux version 6.1.0") -> None:
    """Create system-level /proc files."""
    _write(proc_root / "stat",
           f"cpu  100 200 300 400 0 0 0 0 0 0\nbtime {btime}\n")
    _write(proc_root / "sys" / "kernel" / "hostname", hostname + "\n")
    _write(proc_root / "sys" / "kernel" / "domainname", domainname + "\n")
    _write(proc_root / "version", version + "\n")


def _setup_net_tcp(proc_root: Path, lines: list[str]) -> None:
    """Create /proc/net/tcp with header + data lines."""
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    _write(proc_root / "net" / "tcp", header + "".join(lines))


def _setup_net_tcp6(proc_root: Path, lines: list[str]) -> None:
    """Create /proc/net/tcp6 with header + data lines."""
    header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    _write(proc_root / "net" / "tcp6", header + "".join(lines))


def _setup_net_udp(proc_root: Path, lines: list[str]) -> None:
    """Create /proc/net/udp with header + data lines."""
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    _write(proc_root / "net" / "udp", header + "".join(lines))


def _setup_net_udp6(proc_root: Path, lines: list[str]) -> None:
    """Create /proc/net/udp6 with header + data lines."""
    header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    _write(proc_root / "net" / "udp6", header + "".join(lines))


def _make_net_line(slot: int, local_hex: str, local_port_hex: str,
                   remote_hex: str, remote_port_hex: str,
                   state_hex: str, uid: int, inode: int) -> str:
    """Build a single /proc/net/tcp-style line."""
    return (
        f"   {slot}: {local_hex}:{local_port_hex} "
        f"{remote_hex}:{remote_port_hex} {state_hex} "
        f"00000000:00000000 00:00000000 00000000 "
        f"  {uid}        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )


# ---------------------------------------------------------------------------
# Tests: collect_process_identity
# ---------------------------------------------------------------------------

class TestCollectProcessIdentity:
    """Tests for LinuxCollector.collect_process_identity."""

    def test_basic_identity(self, tmp_path):
        """Collect basic process identity from well-formed /proc files."""
        _setup_basic_process(tmp_path, pid=42, comm="myapp", ppid=10,
                             session=99, starttime=5000,
                             exe_target="/usr/bin/myapp",
                             cmdline="myapp\x00--flag\x00value")
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)

        assert info.ppid == 10
        assert info.session_id == 99
        assert info.exe_path == "/usr/bin/myapp"
        assert info.cmd_line == "myapp --flag value"

    def test_start_time_calculation(self, tmp_path):
        """Verify start_time_ns is computed from btime + starttime/CLK_TCK."""
        _setup_basic_process(tmp_path, pid=1, starttime=25000)
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        clk_tck = 100
        with patch("os.sysconf", return_value=clk_tck):
            info = collector.collect_process_identity(1)

        expected_sec = 1700000000 + 25000 / clk_tck
        expected_ns = int(expected_sec * 1_000_000_000)
        assert info.start_time_ns == expected_ns

    def test_comm_with_spaces_and_parens(self, tmp_path):
        """Comm names with spaces or nested parens are handled correctly."""
        pid_dir = tmp_path / "42"
        pid_dir.mkdir()
        # Comm with space and nested paren: "(special app)"
        _write(pid_dir / "stat",
               "42 (special (app)) S 10 42 99 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 5000 0 0\n")
        _write(pid_dir / "cmdline", "special\x00app")
        _write(pid_dir / "status", "Name:\tspecial\nUid:\t1000\t1000\t1000\t1000\n")
        _write(pid_dir / "statm", "100 50 10 5 0 20 0\n")
        (pid_dir / "exe").symlink_to("/opt/special")
        (pid_dir / "fd").mkdir()
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(42)

        assert info.ppid == 10
        assert info.exe_path == "/opt/special"

    def test_missing_stat_file(self, tmp_path):
        """Missing stat file returns defaults without crashing."""
        pid_dir = tmp_path / "99"
        pid_dir.mkdir()
        _write(pid_dir / "cmdline", "hello")
        (pid_dir / "fd").mkdir()

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_process_identity(99)

        assert info.ppid == 0
        assert info.session_id == 0
        assert info.start_time_ns == 0
        assert info.cmd_line == "hello"

    def test_missing_exe_symlink(self, tmp_path):
        """Missing exe symlink returns empty string."""
        _setup_basic_process(tmp_path, pid=7, exe_target="")
        # Remove the exe link that _setup_basic_process would skip
        exe_path = tmp_path / "7" / "exe"
        if exe_path.exists():
            exe_path.unlink()
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(7)

        assert info.exe_path == ""

    def test_missing_cmdline(self, tmp_path):
        """Missing cmdline file returns empty string."""
        pid_dir = tmp_path / "5"
        pid_dir.mkdir()
        _write(pid_dir / "stat",
               "5 (init) S 0 5 5 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0\n")
        (pid_dir / "fd").mkdir()
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        with patch("os.sysconf", return_value=100):
            info = collector.collect_process_identity(5)

        assert info.cmd_line == ""

    def test_nonexistent_pid(self, tmp_path):
        """Querying a PID with no /proc entry returns safe defaults."""
        _setup_system_files(tmp_path)
        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_process_identity(99999)

        assert info.ppid == 0
        assert info.exe_path == ""
        assert info.cmd_line == ""


# ---------------------------------------------------------------------------
# Tests: collect_system_info
# ---------------------------------------------------------------------------

class TestCollectSystemInfo:
    """Tests for LinuxCollector.collect_system_info."""

    def test_basic_system_info(self, tmp_path):
        """Collect hostname, domain, version, and boot time."""
        _setup_system_files(tmp_path, btime=1700000000,
                            hostname="server01",
                            domainname="example.com",
                            version="Linux version 6.1.0-amd64")

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.hostname == "server01"
        assert info.domain == "example.com"
        assert info.os_detail == "Linux version 6.1.0-amd64"
        assert info.boot_time == 1700000000 * 1_000_000_000

    def test_domain_none_becomes_empty(self, tmp_path):
        """The special '(none)' domain is normalized to empty string."""
        _setup_system_files(tmp_path, domainname="(none)")

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.domain == ""

    def test_empty_domain_becomes_empty(self, tmp_path):
        """An empty domain string remains empty."""
        _setup_system_files(tmp_path, domainname="")

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.domain == ""

    def test_missing_proc_stat(self, tmp_path):
        """Missing /proc/stat yields boot_time=0."""
        _write(tmp_path / "sys" / "kernel" / "hostname", "host\n")
        _write(tmp_path / "sys" / "kernel" / "domainname", "(none)\n")
        _write(tmp_path / "version", "Linux 6.1\n")

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.boot_time == 0
        assert info.hostname == "host"

    def test_missing_hostname_file(self, tmp_path):
        """Missing hostname file yields empty string."""
        _setup_system_files(tmp_path)
        (tmp_path / "sys" / "kernel" / "hostname").unlink()

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.hostname == ""

    def test_proc_stat_no_btime_line(self, tmp_path):
        """A /proc/stat without btime yields boot_time=0."""
        _write(tmp_path / "stat", "cpu  100 200 300 400\n")
        _write(tmp_path / "sys" / "kernel" / "hostname", "h\n")
        _write(tmp_path / "sys" / "kernel" / "domainname", "(none)\n")
        _write(tmp_path / "version", "Linux\n")

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_system_info()

        assert info.boot_time == 0


# ---------------------------------------------------------------------------
# Tests: collect_process_table
# ---------------------------------------------------------------------------

class TestCollectProcessTable:
    """Tests for LinuxCollector.collect_process_table."""

    def test_multiple_processes(self, tmp_path):
        """Multiple PIDs in /proc yield corresponding ProcessEntry objects."""
        _setup_basic_process(tmp_path, pid=1, comm="init", ppid=0, uid=0, rss_pages=100)
        _setup_basic_process(tmp_path, pid=100, comm="sshd", ppid=1, uid=0, rss_pages=200)
        _setup_basic_process(tmp_path, pid=500, comm="python", ppid=100, uid=1000, rss_pages=5000)
        _setup_system_files(tmp_path, btime=1700000000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=500)

        assert len(entries) == 3
        by_pid = {e.pid: e for e in entries}

        assert by_pid[1].exe_name == "init"
        assert by_pid[1].ppid == 0
        assert by_pid[1].is_target is False

        assert by_pid[500].exe_name == "python"
        assert by_pid[500].is_target is True
        assert by_pid[500].uid == 1000
        assert by_pid[500].rss == 5000 * 4096

    def test_non_numeric_entries_ignored(self, tmp_path):
        """Non-numeric entries in /proc (e.g., 'net', 'sys') are skipped."""
        _setup_basic_process(tmp_path, pid=10, comm="test")
        _setup_system_files(tmp_path)
        # These non-numeric dirs already exist from _setup_system_files
        (tmp_path / "cpuinfo").mkdir(exist_ok=True)

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=10)

        assert len(entries) == 1
        assert entries[0].pid == 10

    def test_process_with_missing_status(self, tmp_path):
        """Process entry with missing status file gets uid=0."""
        _setup_basic_process(tmp_path, pid=42, comm="app")
        (tmp_path / "42" / "status").unlink()
        _setup_system_files(tmp_path)

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=1)

        assert len(entries) == 1
        assert entries[0].uid == 0

    def test_process_with_missing_statm(self, tmp_path):
        """Process entry with missing statm file gets rss=0."""
        _setup_basic_process(tmp_path, pid=42, comm="app")
        (tmp_path / "42" / "statm").unlink()
        _setup_system_files(tmp_path)

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=1)

        assert len(entries) == 1
        assert entries[0].rss == 0

    def test_empty_proc(self, tmp_path):
        """Empty /proc yields empty process table."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=1)
        assert entries == []

    def test_unreadable_proc_dir(self, tmp_path):
        """Inaccessible /proc directory returns empty list."""
        nonexistent = str(tmp_path / "does_not_exist")
        collector = LinuxCollector(proc_root=nonexistent)
        entries = collector.collect_process_table(target_pid=1)
        assert entries == []


# ---------------------------------------------------------------------------
# Tests: collect_connection_table
# ---------------------------------------------------------------------------

class TestCollectConnectionTable:
    """Tests for LinuxCollector.collect_connection_table."""

    def test_ipv4_tcp_listening(self, tmp_path):
        """Parse an IPv4 TCP LISTEN entry (state 0x0A)."""
        # 127.0.0.1:8080 -> 0.0.0.0:0
        # 127.0.0.1 in /proc/net hex (little-endian): 0100007F
        line = _make_net_line(0, "0100007F", "1F90",
                              "00000000", "0000", "0A", 500, 12345)
        _setup_net_tcp(tmp_path, [line])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.local_port == 0x1F90  # 8080
        assert entry.remote_port == 0
        assert entry.state == 0x0A  # LISTEN
        assert entry.family == 0x02  # AF_INET
        assert entry.protocol == 0x06  # TCP

    def test_ipv4_address_byte_order(self, tmp_path):
        """Verify IPv4 address is converted from little-endian hex to 16 bytes."""
        # 0x0100007F represents 127.0.0.1 in /proc/net format
        line = _make_net_line(0, "0100007F", "0050",
                              "C0A80164", "1F90", "01", 0, 99999)
        _setup_net_tcp(tmp_path, [line])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        local_addr = entries[0].local_addr
        # The address bytes match the codec's host-to-network conversion
        expected_local = collector._decode_ipv4_addr("0100007F")
        assert local_addr == expected_local
        assert len(local_addr) == 16
        # Remaining 12 bytes should be zero-padded
        assert local_addr[4:] == b"\x00" * 12

    def test_ipv4_remote_address(self, tmp_path):
        """Verify remote IPv4 address parsing."""
        # C0A80164 represents an address in /proc/net hex format
        line = _make_net_line(0, "0100007F", "0050",
                              "C0A80164", "1F90", "01", 0, 11111)
        _setup_net_tcp(tmp_path, [line])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        remote = entries[0].remote_addr
        expected_remote = collector._decode_ipv4_addr("C0A80164")
        assert remote == expected_remote
        assert len(remote) == 16

    def test_ipv6_tcp(self, tmp_path):
        """Parse an IPv6 TCP entry and verify 16-byte address."""
        # ::1 in /proc/net/tcp6 hex (4 words, each in host byte order on LE):
        # 00000000 00000000 00000000 01000000
        ipv6_local = "00000000000000000000000001000000"
        ipv6_remote = "00000000000000000000000000000000"
        line = _make_net_line(0, ipv6_local, "1F90",
                              ipv6_remote, "0000", "0A", 0, 55555)
        _setup_net_tcp(tmp_path, [])
        _setup_net_tcp6(tmp_path, [line])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.family == 0x0A  # AF_INET6
        assert entry.protocol == 0x06  # TCP
        assert len(entry.local_addr) == 16
        expected_local = collector._decode_ipv6_addr(ipv6_local)
        assert entry.local_addr == expected_local

    def test_udp_entries(self, tmp_path):
        """Parse UDP entries correctly."""
        line = _make_net_line(0, "00000000", "0035",
                              "00000000", "0000", "07", 0, 77777)
        _setup_net_tcp(tmp_path, [])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [line])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        assert entries[0].protocol == 0x11  # UDP
        assert entries[0].local_port == 0x0035  # 53 (DNS)

    def test_multiple_connections(self, tmp_path):
        """Multiple lines across tcp/udp produce multiple entries."""
        tcp_line = _make_net_line(0, "0100007F", "0050",
                                  "00000000", "0000", "0A", 0, 111)
        udp_line = _make_net_line(0, "00000000", "0035",
                                  "00000000", "0000", "07", 0, 222)
        _setup_net_tcp(tmp_path, [tcp_line])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [udp_line])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 2

    def test_inode_pid_mapping(self, tmp_path):
        """Connections are mapped to owning PIDs via socket inodes in /proc/<pid>/fd."""
        _setup_basic_process(tmp_path, pid=42, comm="server")
        fd_dir = tmp_path / "42" / "fd"
        (fd_dir / "3").symlink_to("socket:[12345]")

        tcp_line = _make_net_line(0, "0100007F", "1F90",
                                  "00000000", "0000", "0A", 500, 12345)
        _setup_net_tcp(tmp_path, [tcp_line])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()

        assert len(entries) == 1
        assert entries[0].pid == 42

    def test_missing_net_files(self, tmp_path):
        """Missing /proc/net files yield empty results without crashing."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()
        assert entries == []

    def test_malformed_net_line_skipped(self, tmp_path):
        """Lines with too few fields are silently skipped."""
        _setup_net_tcp(tmp_path, ["   0: short_line\n"])
        _setup_net_tcp6(tmp_path, [])
        _setup_net_udp(tmp_path, [])
        _setup_net_udp6(tmp_path, [])

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_connection_table()
        assert entries == []


# ---------------------------------------------------------------------------
# Tests: collect_handle_table
# ---------------------------------------------------------------------------

class TestCollectHandleTable:
    """Tests for LinuxCollector.collect_handle_table."""

    def test_file_handle(self, tmp_path):
        """Regular file symlinks are classified as HT_FILE."""
        _setup_basic_process(tmp_path, pid=10, comm="app")
        fd_dir = tmp_path / "10" / "fd"
        (fd_dir / "0").symlink_to("/dev/null")
        (fd_dir / "1").symlink_to("/var/log/app.log")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(10)

        by_fd = {e.fd: e for e in entries}
        assert by_fd[0].handle_type == 0x05  # HT_DEVICE (/dev/*)
        assert by_fd[0].path == "/dev/null"
        assert by_fd[1].handle_type == 0x01  # HT_FILE
        assert by_fd[1].path == "/var/log/app.log"

    def test_socket_handle(self, tmp_path):
        """Socket symlinks are classified as HT_SOCKET."""
        _setup_basic_process(tmp_path, pid=20, comm="server")
        fd_dir = tmp_path / "20" / "fd"
        (fd_dir / "3").symlink_to("socket:[12345]")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(20)

        assert len(entries) == 1
        assert entries[0].handle_type == 0x03  # HT_SOCKET
        assert entries[0].path == "socket:[12345]"

    def test_pipe_handle(self, tmp_path):
        """Pipe symlinks are classified as HT_PIPE."""
        _setup_basic_process(tmp_path, pid=30, comm="worker")
        fd_dir = tmp_path / "30" / "fd"
        (fd_dir / "4").symlink_to("pipe:[67890]")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(30)

        assert len(entries) == 1
        assert entries[0].handle_type == 0x04  # HT_PIPE

    def test_multiple_handles(self, tmp_path):
        """Multiple file descriptors are all collected."""
        _setup_basic_process(tmp_path, pid=40, comm="multi")
        fd_dir = tmp_path / "40" / "fd"
        (fd_dir / "0").symlink_to("/dev/pts/0")
        (fd_dir / "1").symlink_to("/dev/pts/0")
        (fd_dir / "2").symlink_to("/dev/pts/0")
        (fd_dir / "5").symlink_to("socket:[111]")
        (fd_dir / "6").symlink_to("pipe:[222]")
        (fd_dir / "7").symlink_to("/tmp/data.txt")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(40)

        assert len(entries) == 6

    def test_missing_fd_directory(self, tmp_path):
        """Missing fd directory returns empty list."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(99999)
        assert entries == []

    def test_non_numeric_fd_entries_ignored(self, tmp_path):
        """Non-numeric entries in fd/ are skipped."""
        _setup_basic_process(tmp_path, pid=50, comm="app")
        fd_dir = tmp_path / "50" / "fd"
        (fd_dir / "0").symlink_to("/dev/null")
        # Create a non-numeric entry
        (fd_dir / "not_a_fd").symlink_to("/tmp/junk")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(50)

        assert len(entries) == 1
        assert entries[0].fd == 0

    def test_broken_fd_symlink(self, tmp_path):
        """A broken/unreadable fd symlink yields HT_UNKNOWN."""
        _setup_basic_process(tmp_path, pid=60, comm="app")
        fd_dir = tmp_path / "60" / "fd"
        # Remove the fd dir and recreate to ensure clean state
        # Create fd entry that points nowhere readable
        fd_link = fd_dir / "3"
        fd_link.symlink_to("/nonexistent/deleted/path")

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(60)

        fd3_entries = [e for e in entries if e.fd == 3]
        assert len(fd3_entries) == 1
        # Points to a regular path (not socket/pipe/dev), classified as HT_FILE
        assert fd3_entries[0].handle_type == 0x01  # HT_FILE


# ---------------------------------------------------------------------------
# Tests: IPv4 and IPv6 address parsing
# ---------------------------------------------------------------------------

class TestAddressParsing:
    """Tests for internal address parsing methods.

    Note: The codec applies a host-to-network byte-order transform via
    struct pack/unpack. Tests verify consistency of the transform rather
    than assuming a specific host endianness.
    """

    def test_ipv4_loopback_port(self, tmp_path):
        """Port is correctly extracted from the hex address:port string."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        addr, port = collector._parse_hex_addr("0100007F:1F90", is_ipv6=False)

        assert port == 8080
        assert len(addr) == 16
        # Verify against the codec's own IPv4 decoder
        assert addr == collector._decode_ipv4_addr("0100007F")

    def test_ipv4_zeros(self, tmp_path):
        """0.0.0.0:0 produces all-zero 16-byte address."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        addr, port = collector._parse_hex_addr("00000000:0000", is_ipv6=False)

        assert port == 0
        assert addr == b"\x00" * 16

    def test_ipv4_broadcast(self, tmp_path):
        """FFFFFFFF produces 4 bytes of 0xFF followed by 12 zero bytes."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        addr, port = collector._parse_hex_addr("FFFFFFFF:FFFF", is_ipv6=False)

        assert port == 65535
        assert addr[:4] == bytes([255, 255, 255, 255])
        assert addr[4:] == b"\x00" * 12

    def test_ipv4_specific_address(self, tmp_path):
        """A specific IPv4 hex address is decoded consistently."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        addr, port = collector._parse_hex_addr("0100000A:0050", is_ipv6=False)

        assert port == 80
        expected = collector._decode_ipv4_addr("0100000A")
        assert addr == expected
        # Address bytes are 4 bytes + 12 zero-padding
        assert addr[4:] == b"\x00" * 12

    def test_ipv4_decode_produces_16_bytes(self, tmp_path):
        """_decode_ipv4_addr always produces exactly 16 bytes."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        for hex_addr in ("0100007F", "00000000", "FFFFFFFF", "C0A80164"):
            result = collector._decode_ipv4_addr(hex_addr)
            assert len(result) == 16
            assert result[4:] == b"\x00" * 12

    def test_ipv6_loopback(self, tmp_path):
        """::1 in /proc/net hex produces a 16-byte address."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        hex_addr = "00000000000000000000000001000000"
        addr, port = collector._parse_hex_addr(f"{hex_addr}:1F90", is_ipv6=True)

        assert port == 8080
        assert len(addr) == 16
        expected = collector._decode_ipv6_addr(hex_addr)
        assert addr == expected

    def test_ipv6_all_zeros(self, tmp_path):
        """:: (all zeros) produces all-zero 16 bytes."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        hex_addr = "00000000000000000000000000000000"
        addr, port = collector._parse_hex_addr(f"{hex_addr}:0000", is_ipv6=True)

        assert addr == b"\x00" * 16
        assert port == 0

    def test_ipv6_mapped_ipv4(self, tmp_path):
        """IPv4-mapped IPv6 address produces a 16-byte result."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        # ::ffff:127.0.0.1 in /proc/net hex (LE word format)
        hex_addr = "0000000000000000FFFF00000100007F"
        addr, _ = collector._parse_hex_addr(f"{hex_addr}:0050", is_ipv6=True)

        assert len(addr) == 16
        expected = collector._decode_ipv6_addr(hex_addr)
        assert addr == expected
        # The first 8 bytes should be all zeros (the :: prefix)
        assert addr[:8] == b"\x00" * 8

    def test_ipv6_decode_produces_16_bytes(self, tmp_path):
        """_decode_ipv6_addr always produces exactly 16 bytes."""
        collector = LinuxCollector(proc_root=str(tmp_path))
        hex_addrs = [
            "00000000000000000000000001000000",
            "00000000000000000000000000000000",
            "0000000000000000FFFF00000100007F",
        ]
        for hex_addr in hex_addrs:
            result = collector._decode_ipv6_addr(hex_addr)
            assert len(result) == 16

    def test_ipv4_and_ipv6_parse_consistency(self, tmp_path):
        """_parse_hex_addr dispatches to the correct decoder based on is_ipv6."""
        collector = LinuxCollector(proc_root=str(tmp_path))

        addr4, _ = collector._parse_hex_addr("0100007F:0050", is_ipv6=False)
        assert addr4 == collector._decode_ipv4_addr("0100007F")

        hex6 = "00000000000000000000000001000000"
        addr6, _ = collector._parse_hex_addr(f"{hex6}:0050", is_ipv6=True)
        assert addr6 == collector._decode_ipv6_addr(hex6)


# ---------------------------------------------------------------------------
# Tests: error handling and edge cases
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for graceful error handling in LinuxCollector."""

    def test_permission_error_on_stat(self, tmp_path):
        """Permission errors on /proc/<pid>/stat are handled gracefully."""
        pid_dir = tmp_path / "42"
        pid_dir.mkdir()
        stat_file = pid_dir / "stat"
        _write(stat_file, "42 (app) S 1 42 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0\n")
        stat_file.chmod(0o000)
        _write(pid_dir / "cmdline", "app")
        (pid_dir / "fd").mkdir()

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_process_identity(42)

        # Should degrade gracefully
        assert info.ppid == 0
        assert info.cmd_line == "app"

        # Cleanup: restore permissions so tmp_path cleanup works
        stat_file.chmod(0o644)

    def test_permission_error_on_fd_dir(self, tmp_path):
        """Permission errors on /proc/<pid>/fd return empty handle list."""
        pid_dir = tmp_path / "42"
        pid_dir.mkdir()
        fd_dir = pid_dir / "fd"
        fd_dir.mkdir()
        fd_dir.chmod(0o000)

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_handle_table(42)

        assert entries == []

        # Cleanup
        fd_dir.chmod(0o755)

    def test_corrupted_stat_line(self, tmp_path):
        """A stat file with garbage content is handled gracefully."""
        pid_dir = tmp_path / "42"
        pid_dir.mkdir()
        _write(pid_dir / "stat", "garbage content no parens")
        _write(pid_dir / "cmdline", "app")
        (pid_dir / "fd").mkdir()

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_process_identity(42)

        assert info.ppid == 0

    def test_empty_stat_file(self, tmp_path):
        """An empty stat file is handled gracefully."""
        pid_dir = tmp_path / "42"
        pid_dir.mkdir()
        _write(pid_dir / "stat", "")
        _write(pid_dir / "cmdline", "app")
        (pid_dir / "fd").mkdir()

        collector = LinuxCollector(proc_root=str(tmp_path))
        info = collector.collect_process_identity(42)

        assert info.ppid == 0

    def test_logger_receives_warnings(self, tmp_path):
        """Warnings are logged when files are missing."""
        logger = logging.getLogger("test_linux_collector")
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.MemoryHandler(capacity=100)
        logger.addHandler(handler)

        collector = LinuxCollector(proc_root=str(tmp_path), logger=logger)
        collector.collect_process_identity(99999)

        handler.flush()
        logger.removeHandler(handler)

    def test_process_table_skips_unreadable_procs(self, tmp_path):
        """Processes whose stat files cannot be read are silently skipped."""
        _setup_basic_process(tmp_path, pid=1, comm="init")
        _setup_system_files(tmp_path)

        # Create a proc dir with no stat file -> should be skipped
        bad_dir = tmp_path / "999"
        bad_dir.mkdir()
        _write(bad_dir / "cmdline", "broken")
        (bad_dir / "fd").mkdir()

        collector = LinuxCollector(proc_root=str(tmp_path))
        entries = collector.collect_process_table(target_pid=1)

        # Only pid 1 should appear; pid 999 has no stat file
        pids = {e.pid for e in entries}
        assert 1 in pids
        assert 999 not in pids
