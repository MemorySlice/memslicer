"""macOS (Darwin) investigation collector using sysctl, ps, and lsof."""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from datetime import datetime

from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry

from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
    HT_UNKNOWN, HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE,
)

# TCP state map for lsof
_TCP_STATES = {
    "ESTABLISHED": 0x01,
    "LISTEN": 0x0A,
    "SYN_SENT": 0x02,
    "SYN_RECV": 0x03,
    "FIN_WAIT1": 0x04,
    "FIN_WAIT2": 0x05,
    "TIME_WAIT": 0x06,
    "CLOSE": 0x07,
    "CLOSE_WAIT": 0x08,
    "LAST_ACK": 0x09,
    "CLOSING": 0x0B,
}


class DarwinCollector:
    """Collects investigation data on macOS via system commands.

    Uses ps, sysctl, sw_vers, and lsof for data collection.
    All methods handle errors gracefully.
    """

    _is_memslicer_collector = True

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or logging.getLogger("memslicer")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity via ps command."""
        info = TargetProcessInfo()

        # Single ps call for all fields; lstart has spaces so we use careful parsing
        ps_out = self._run_cmd([
            "ps", "-p", str(pid), "-o", "ppid=,sess=,lstart=,comm=,args=",
        ])
        if not ps_out:
            return info

        # Parse: "  999   42 Mon Jan  2 15:04:05 2006 /usr/bin/app /usr/bin/app --flag"
        # ppid and sess are numeric, followed by lstart (fixed 24-char format),
        # then comm and args
        line = ps_out.strip()
        parts = line.split(None, 2)  # split into [ppid, sess, rest]
        if len(parts) < 3:
            return info

        try:
            info.ppid = int(parts[0])
            info.session_id = int(parts[1])
        except ValueError:
            pass

        rest = parts[2]
        # lstart is a fixed-width date: "Day Mon DD HH:MM:SS YYYY" (24 chars)
        # Try to find the date pattern and split
        lstart_match = re.match(
            r"(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*(.*)",
            rest,
        )
        if lstart_match:
            info.start_time_ns = self._parse_lstart(lstart_match.group(1))
            remainder = lstart_match.group(2)
            # remainder is "comm args..." - comm is the first word
            if remainder:
                cmd_parts = remainder.split(None, 1)
                info.exe_path = cmd_parts[0] if cmd_parts else ""
                info.cmd_line = remainder
        else:
            # Fallback: no lstart parsed, try to get at least exe_path
            info.exe_path = rest.split()[0] if rest.split() else ""
            info.cmd_line = rest

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info via sysctl and sw_vers."""
        info = TargetSystemInfo()
        info.boot_time = self._read_boot_time()
        info.hostname = socket.gethostname()
        info.domain = self._read_domain()
        info.os_detail = self._read_os_detail()
        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate processes via ps."""
        ps_out = self._run_cmd([
            "ps", "-ax", "-o", "pid=,ppid=,uid=,rss=,comm=,args=",
        ])
        if not ps_out:
            return []

        entries: list[ProcessEntry] = []
        for line in ps_out.strip().splitlines():
            entry = self._parse_ps_line(line, target_pid)
            if entry is not None:
                entries.append(entry)

        self._log.info("Collected %d process table entries", len(entries))
        return entries

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate connections via lsof -i."""
        lsof_out = self._run_cmd(["lsof", "-i", "-n", "-P", "+c", "0"])
        if not lsof_out:
            return []

        entries: list[ConnectionEntry] = []
        for line in lsof_out.strip().splitlines()[1:]:  # skip header
            entry = self._parse_lsof_connection(line)
            if entry is not None:
                entries.append(entry)

        self._log.info("Collected %d connection entries", len(entries))
        return entries

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate file handles via lsof -p."""
        lsof_out = self._run_cmd(["lsof", "-p", str(pid)])
        if not lsof_out:
            return []

        entries: list[HandleEntry] = []
        for line in lsof_out.strip().splitlines()[1:]:  # skip header
            entry = self._parse_lsof_handle(line, pid)
            if entry is not None:
                entries.append(entry)

        self._log.info("Collected %d handle entries for pid %d", len(entries), pid)
        return entries

    # ------------------------------------------------------------------
    # Private: command execution
    # ------------------------------------------------------------------

    def _run_cmd(self, cmd: list[str], timeout: float = 10.0) -> str:
        """Run a command and return stdout. Returns '' on failure."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self._log.warning("Command %s failed: %s", cmd[0], exc)
        return ""

    # ------------------------------------------------------------------
    # Private: system info helpers
    # ------------------------------------------------------------------

    def _read_boot_time(self) -> int:
        """Read boot time via sysctl kern.boottime."""
        out = self._run_cmd(["sysctl", "-n", "kern.boottime"])
        if not out:
            return 0
        # Output: "{ sec = 1712345678, usec = 123456 } ..."
        match = re.search(r"sec\s*=\s*(\d+)", out)
        if match:
            return int(match.group(1)) * 1_000_000_000
        return 0

    def _read_domain(self) -> str:
        """Read domain name."""
        out = self._run_cmd(["domainname"])
        domain = out.strip() if out else ""
        return "" if domain in ("(none)", "") else domain

    def _read_os_detail(self) -> str:
        """Build OS detail string from sw_vers and uname."""
        parts: list[str] = []

        sw_vers = self._run_cmd(["sw_vers"])
        if sw_vers:
            for line in sw_vers.strip().splitlines():
                kv = line.split(":", 1)
                if len(kv) == 2:
                    parts.append(kv[1].strip())

        uname = self._run_cmd(["uname", "-r"])
        if uname:
            parts.append(f"kernel {uname.strip()}")

        return " ".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # Private: parsing helpers
    # ------------------------------------------------------------------

    def _parse_lstart(self, lstart: str) -> int:
        """Parse ps lstart output to nanoseconds since epoch."""
        # lstart format: "Mon Jan  2 15:04:05 2006" (locale-dependent)
        for fmt in ("%a %b %d %H:%M:%S %Y", "%c"):
            try:
                dt = datetime.strptime(lstart, fmt)
                return int(dt.timestamp() * 1_000_000_000)
            except ValueError:
                continue
        return 0

    def _parse_ps_line(self, line: str, target_pid: int) -> ProcessEntry | None:
        """Parse a single ps output line."""
        parts = line.split(None, 5)
        if len(parts) < 5:
            return None
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            uid = int(parts[2])
            rss = int(parts[3]) * 1024  # ps reports RSS in KB
            comm = parts[4] if len(parts) >= 5 else ""
            cmd_line = parts[5] if len(parts) >= 6 else ""
        except (ValueError, IndexError):
            return None

        exe_name = comm.rsplit("/", 1)[-1] if "/" in comm else comm
        return ProcessEntry(
            pid=pid, ppid=ppid, uid=uid,
            is_target=(pid == target_pid),
            start_time=0, rss=rss,
            exe_name=exe_name, cmd_line=cmd_line, user="",
        )

    def _parse_lsof_connection(self, line: str) -> ConnectionEntry | None:
        """Parse a single lsof -i output line."""
        # lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        fields = line.split()
        if len(fields) < 10:
            return None

        try:
            pid = int(fields[1])
        except ValueError:
            return None

        node = fields[7]  # TCP or UDP
        name = fields[8] if len(fields) >= 9 else ""
        state_str = fields[9] if len(fields) >= 10 else ""

        # Remove parentheses from state: "(ESTABLISHED)" -> "ESTABLISHED"
        state_str = state_str.strip("()")

        if node == "TCP":
            protocol = PROTO_TCP
            state = _TCP_STATES.get(state_str, 0x00)
        elif node == "UDP":
            protocol = PROTO_UDP
            state = 0x00
        else:
            return None

        # Parse NAME: "host:port->remote:port" or "*:port" or "host:port"
        local_addr, local_port, remote_addr, remote_port, family = (
            self._parse_lsof_name(name)
        )

        return ConnectionEntry(
            pid=pid, family=family, protocol=protocol, state=state,
            local_addr=local_addr, local_port=local_port,
            remote_addr=remote_addr, remote_port=remote_port,
        )

    def _parse_lsof_name(
        self, name: str
    ) -> tuple[bytes, int, bytes, int, int]:
        """Parse lsof NAME field like 'host:port->remote:port'."""
        zero_addr = b"\x00" * 16

        # Split on "->" for connection pairs
        if "->" in name:
            local_part, remote_part = name.split("->", 1)
        else:
            local_part = name
            remote_part = ""

        local_addr, local_port, family = self._parse_addr_port(local_part)
        if remote_part:
            remote_addr, remote_port, _ = self._parse_addr_port(remote_part)
        else:
            remote_addr = zero_addr
            remote_port = 0

        return local_addr, local_port, remote_addr, remote_port, family

    def _parse_addr_port(self, part: str) -> tuple[bytes, int, int]:
        """Parse 'addr:port' or '[addr]:port' into (16-byte addr, port, family)."""
        zero_addr = b"\x00" * 16

        if not part or part == "*:*":
            return zero_addr, 0, AF_INET

        # Handle IPv6 [addr]:port
        if part.startswith("["):
            bracket_end = part.index("]")
            addr_str = part[1:bracket_end]
            port_str = part[bracket_end + 2:] if bracket_end + 1 < len(part) else "0"
            family = AF_INET6
        else:
            # Last colon separates addr from port
            last_colon = part.rfind(":")
            if last_colon == -1:
                return zero_addr, 0, AF_INET
            addr_str = part[:last_colon]
            port_str = part[last_colon + 1:]
            family = AF_INET6 if ":" in addr_str else AF_INET

        # Parse port
        try:
            port = int(port_str) if port_str and port_str != "*" else 0
        except ValueError:
            port = 0

        # Parse address
        if addr_str in ("*", ""):
            return zero_addr, port, family

        try:
            addr_obj = ipaddress.ip_address(addr_str)
            addr_bytes = addr_obj.packed
            if len(addr_bytes) == 4:
                addr_bytes = addr_bytes + b"\x00" * 12
                family = AF_INET
            else:
                family = AF_INET6
        except ValueError:
            addr_bytes = zero_addr

        return addr_bytes, port, family

    def _parse_lsof_handle(self, line: str, pid: int) -> HandleEntry | None:
        """Parse a single lsof -p output line."""
        # lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        fields = line.split()
        if len(fields) < 9:
            return None

        fd_str = fields[3]
        fd_type = fields[4]
        name = " ".join(fields[8:])

        # Parse FD number (e.g., "3r", "4w", "5u", "txt", "cwd", "rtd")
        fd_num = 0
        fd_digits = re.match(r"(\d+)", fd_str)
        if fd_digits:
            fd_num = int(fd_digits.group(1))
        elif fd_str in ("cwd", "rtd", "txt", "mem"):
            fd_num = -1  # special descriptors

        handle_type = self._classify_lsof_type(fd_type)
        return HandleEntry(pid=pid, fd=fd_num, handle_type=handle_type, path=name)

    @staticmethod
    def _classify_lsof_type(fd_type: str) -> int:
        """Map lsof TYPE column to handle type constant."""
        type_map = {
            "REG": HT_FILE,
            "DIR": HT_DIR,
            "IPv4": HT_SOCKET,
            "IPv6": HT_SOCKET,
            "sock": HT_SOCKET,
            "unix": HT_SOCKET,
            "FIFO": HT_PIPE,
            "PIPE": HT_PIPE,
            "CHR": HT_DEVICE,
            "BLK": HT_DEVICE,
        }
        return type_map.get(fd_type, HT_UNKNOWN)
