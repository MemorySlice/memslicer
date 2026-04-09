"""Linux-specific investigation collector using /proc filesystem."""
from __future__ import annotations

import logging
import os
import struct
from pathlib import Path

from memslicer.acquirer.collectors.addr_utils import (
    decode_proc_net_ipv4,
    decode_proc_net_ipv6,
)
from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
    HT_UNKNOWN, HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry


class LinuxCollector:
    """Collects investigation data from Linux /proc filesystem.

    All methods handle errors gracefully, logging warnings and
    returning partial or empty data on failure.
    """

    _is_memslicer_collector = True

    def __init__(
        self,
        proc_root: str = "/proc",
        logger: logging.Logger | None = None,
    ) -> None:
        self._proc = proc_root
        self._log = logger or logging.getLogger("memslicer")

    # ------------------------------------------------------------------
    # Public API (matches InvestigationCollector protocol)
    # ------------------------------------------------------------------

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect identity metadata for the target process."""
        info = TargetProcessInfo()
        try:
            stat_fields, _ = self._parse_proc_stat(pid)
            info.ppid = int(stat_fields[1])
            info.session_id = int(stat_fields[3])
            info.start_time_ns = self._calc_start_time_ns(int(stat_fields[19]))
        except (OSError, PermissionError, ValueError, IndexError) as exc:
            self._log.warning("Failed to read stat for pid %d: %s", pid, exc)

        info.exe_path = self._read_exe_path(pid)
        info.cmd_line = self._read_cmdline(pid)
        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system-wide context (hostname, OS detail, boot time)."""
        info = TargetSystemInfo()
        info.boot_time = self._read_boot_time_ns()
        info.hostname = self._read_sysctl("kernel/hostname")
        info.os_detail = self._read_file_text(f"{self._proc}/version")

        domain = self._read_sysctl("kernel/domainname")
        info.domain = "" if domain in ("(none)", "") else domain
        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate all running processes via /proc."""
        entries: list[ProcessEntry] = []
        try:
            for name in os.listdir(self._proc):
                if not name.isdigit():
                    continue
                entry = self._read_process_entry(int(name), target_pid)
                if entry is not None:
                    entries.append(entry)
        except (OSError, PermissionError) as exc:
            self._log.warning("Failed to list %s: %s", self._proc, exc)
            return []

        self._log.info("Collected %d process table entries", len(entries))
        return entries

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate network connections from /proc/net."""
        inode_pid = self._build_inode_pid_map()
        entries: list[ConnectionEntry] = []

        net_files = [
            ("tcp", AF_INET, PROTO_TCP),
            ("tcp6", AF_INET6, PROTO_TCP),
            ("udp", AF_INET, PROTO_UDP),
            ("udp6", AF_INET6, PROTO_UDP),
        ]
        for filename, family, protocol in net_files:
            path = f"{self._proc}/net/{filename}"
            entries.extend(self._parse_net_file(path, family, protocol, inode_pid))

        self._log.info("Collected %d connection table entries", len(entries))
        return entries

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate open file handles for a process."""
        fd_dir = f"{self._proc}/{pid}/fd"
        entries: list[HandleEntry] = []
        try:
            fd_names = os.listdir(fd_dir)
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot list %s: %s", fd_dir, exc)
            return []

        for fd_name in fd_names:
            if not fd_name.isdigit():
                continue
            fd_num = int(fd_name)
            entries.append(self._read_handle_entry(pid, fd_num, fd_dir))

        self._log.info("Collected %d handle entries for pid %d", len(entries), pid)
        return entries

    # ------------------------------------------------------------------
    # Private helpers: process identity
    # ------------------------------------------------------------------

    def _parse_proc_stat(self, pid: int) -> tuple[list[str], str]:
        """Parse /proc/<pid>/stat, returning fields after comm and the comm name.

        Returns (fields_after_comm, comm_name).
        Fields: index 0=state, 1=ppid, 3=session, 19=starttime.
        """
        with open(f"{self._proc}/{pid}/stat", "r") as fh:
            stat_line = fh.read()
        comm_start = stat_line.index("(") + 1
        comm_end = stat_line.rindex(")")
        comm_name = stat_line[comm_start:comm_end]
        return stat_line[comm_end + 2:].split(), comm_name

    def _calc_start_time_ns(self, starttime_ticks: int) -> int:
        """Convert starttime clock ticks to nanoseconds since epoch."""
        boot_time_sec = self._read_boot_time_sec()
        clk_tck = os.sysconf("SC_CLK_TCK")
        start_sec = boot_time_sec + starttime_ticks / clk_tck
        return int(start_sec * 1_000_000_000)

    def _read_exe_path(self, pid: int) -> str:
        """Read the executable path via /proc/<pid>/exe symlink."""
        try:
            return os.readlink(f"{self._proc}/{pid}/exe")
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read exe for pid %d: %s", pid, exc)
            return ""

    def _read_cmdline(self, pid: int) -> str:
        """Read the command line from /proc/<pid>/cmdline."""
        try:
            with open(f"{self._proc}/{pid}/cmdline", "r") as fh:
                return fh.read().replace("\x00", " ").strip()
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read cmdline for pid %d: %s", pid, exc)
            return ""

    # ------------------------------------------------------------------
    # Private helpers: system info
    # ------------------------------------------------------------------

    def _read_boot_time_sec(self) -> int:
        """Read boot time in seconds from /proc/stat btime line."""
        try:
            with open(f"{self._proc}/stat", "r") as fh:
                for line in fh:
                    if line.startswith("btime "):
                        return int(line.split()[1])
        except (OSError, PermissionError, ValueError) as exc:
            self._log.warning("Cannot read boot time: %s", exc)
        return 0

    def _read_boot_time_ns(self) -> int:
        """Read boot time in nanoseconds from /proc/stat btime line."""
        return self._read_boot_time_sec() * 1_000_000_000

    def _read_sysctl(self, key: str) -> str:
        """Read a value from /proc/sys/<key>."""
        return self._read_file_text(f"{self._proc}/sys/{key}")

    def _read_file_text(self, path: str) -> str:
        """Read and strip a single-line text file, returning '' on failure."""
        try:
            with open(path, "r") as fh:
                return fh.read().strip()
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read %s: %s", path, exc)
            return ""

    # ------------------------------------------------------------------
    # Private helpers: process table
    # ------------------------------------------------------------------

    def _read_process_entry(
        self, proc_pid: int, target_pid: int
    ) -> ProcessEntry | None:
        """Read a single process entry from /proc/<pid>. Returns None on failure."""
        proc_dir = f"{self._proc}/{proc_pid}"
        try:
            stat_fields, comm_name = self._parse_proc_stat(proc_pid)
            ppid = int(stat_fields[1])
            start_time = int(stat_fields[19])
        except (OSError, PermissionError, ValueError, IndexError):
            return None

        cmd_line = self._read_cmdline(proc_pid)
        uid = self._read_uid(proc_dir)
        rss = self._read_rss(proc_dir)

        return ProcessEntry(
            pid=proc_pid,
            ppid=ppid,
            uid=uid,
            is_target=(proc_pid == target_pid),
            start_time=start_time,
            rss=rss,
            exe_name=comm_name,
            cmd_line=cmd_line,
            user="",
        )

    def _read_uid(self, proc_dir: str) -> int:
        """Read the real UID from /proc/<pid>/status."""
        try:
            with open(f"{proc_dir}/status", "r") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        return int(line.split()[1])
        except (OSError, PermissionError, ValueError):
            pass
        return 0

    def _read_rss(self, proc_dir: str) -> int:
        """Read RSS in bytes from /proc/<pid>/statm (field 1, in pages)."""
        try:
            with open(f"{proc_dir}/statm", "r") as fh:
                rss_pages = int(fh.read().split()[1])
                return rss_pages * 4096
        except (OSError, PermissionError, ValueError, IndexError):
            pass
        return 0

    # ------------------------------------------------------------------
    # Private helpers: connection table
    # ------------------------------------------------------------------

    def _build_inode_pid_map(self) -> dict[int, int]:
        """Build a mapping from socket inode to owning PID.

        Scans /proc/*/fd/ for symlinks matching ``socket:[inode]``.
        """
        inode_pid: dict[int, int] = {}
        try:
            proc_entries = os.listdir(self._proc)
        except (OSError, PermissionError):
            return inode_pid

        for name in proc_entries:
            if not name.isdigit():
                continue
            pid = int(name)
            fd_dir = f"{self._proc}/{pid}/fd"
            try:
                fd_names = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            for fd_name in fd_names:
                self._try_map_socket_inode(fd_dir, fd_name, pid, inode_pid)

        return inode_pid

    def _try_map_socket_inode(
        self,
        fd_dir: str,
        fd_name: str,
        pid: int,
        inode_pid: dict[int, int],
    ) -> None:
        """Attempt to map a single fd symlink to a socket inode."""
        try:
            target = os.readlink(f"{fd_dir}/{fd_name}")
            if target.startswith("socket:[") and target.endswith("]"):
                inode = int(target[8:-1])
                inode_pid[inode] = pid
        except (OSError, PermissionError, ValueError):
            pass

    def _parse_net_file(
        self,
        path: str,
        family: int,
        protocol: int,
        inode_pid: dict[int, int],
    ) -> list[ConnectionEntry]:
        """Parse a /proc/net/{tcp,tcp6,udp,udp6} file."""
        entries: list[ConnectionEntry] = []
        is_ipv6 = (family == AF_INET6)
        try:
            with open(path, "r") as fh:
                next(fh, None)  # skip header
                for line in fh:
                    entry = self._parse_net_line(line, family, protocol, is_ipv6, inode_pid)
                    if entry is not None:
                        entries.append(entry)
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read %s: %s", path, exc)

        return entries

    def _parse_net_line(
        self,
        line: str,
        family: int,
        protocol: int,
        is_ipv6: bool,
        inode_pid: dict[int, int],
    ) -> ConnectionEntry | None:
        """Parse a single line from a /proc/net file."""
        fields = line.split()
        if len(fields) < 10:
            return None

        try:
            local_addr, local_port = self._parse_hex_addr(fields[1], is_ipv6)
            remote_addr, remote_port = self._parse_hex_addr(fields[2], is_ipv6)
            state = int(fields[3], 16)
            inode = int(fields[9])
        except (ValueError, IndexError):
            return None

        pid = inode_pid.get(inode, 0)
        return ConnectionEntry(
            pid=pid,
            family=family,
            protocol=protocol,
            state=state,
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
        )

    def _parse_hex_addr(
        self, addr_port: str, is_ipv6: bool
    ) -> tuple[bytes, int]:
        """Parse a hex address:port string from /proc/net.

        For IPv4: the hex address is a 32-bit host-byte-order integer.
        Convert to 4 bytes in network order, padded to 16 bytes.

        For IPv6: 32 hex chars as 4 groups of 32-bit words in host byte
        order. Each group is byte-reversed to network order.

        Returns (16-byte address, port number).
        """
        hex_addr, hex_port = addr_port.split(":")
        port = int(hex_port, 16)

        if is_ipv6:
            addr_bytes = self._decode_ipv6_addr(hex_addr)
        else:
            addr_bytes = self._decode_ipv4_addr(hex_addr)

        return addr_bytes, port

    def _decode_ipv4_addr(self, hex_addr: str) -> bytes:
        """Decode a /proc/net IPv4 hex address to 16-byte padded form."""
        return decode_proc_net_ipv4(hex_addr)

    def _decode_ipv6_addr(self, hex_addr: str) -> bytes:
        """Decode a /proc/net IPv6 hex address to 16-byte form."""
        return decode_proc_net_ipv6(hex_addr)

    # ------------------------------------------------------------------
    # Private helpers: handle table
    # ------------------------------------------------------------------

    def _read_handle_entry(self, pid: int, fd_num: int, fd_dir: str) -> HandleEntry:
        """Read a single handle entry for a file descriptor."""
        try:
            target = os.readlink(f"{fd_dir}/{fd_num}")
            handle_type = self._classify_handle(target)
        except (OSError, PermissionError):
            target = ""
            handle_type = HT_UNKNOWN

        return HandleEntry(pid=pid, fd=fd_num, handle_type=handle_type, path=target)

    @staticmethod
    def _classify_handle(target: str) -> int:
        """Classify a file descriptor target path into a handle type."""
        if target.startswith("socket:"):
            return HT_SOCKET
        if target.startswith("pipe:"):
            return HT_PIPE
        if target.startswith("/dev/"):
            return HT_DEVICE
        if os.path.isdir(target):
            return HT_DIR
        return HT_FILE
