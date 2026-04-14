"""macOS (Darwin) investigation collector using sysctl, ps, and lsof."""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from datetime import datetime

from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import (
    ConnectionEntry, HandleEntry, ProcessEntry, ConnectivityTable,
    KernelModuleList, PersistenceManifest,
)

from memslicer.acquirer.collectors._io import read_symlink
from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
    HT_UNKNOWN, HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE,
)

# Regexes for parsing ioreg output of IOPlatformExpertDevice.
_IOREG_UUID_RE = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')
_IOREG_SERIAL_RE = re.compile(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"')

# Timezone symlink prefixes to strip from /etc/localtime.
_TZ_PREFIXES = (
    "/var/db/timezone/zoneinfo/",
    "/usr/share/zoneinfo/",
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

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        """Collect process identity via ps command.

        The P1.6.3 ``include_target_introspection`` / ``include_environ``
        kwargs are accepted for protocol compatibility but currently
        ignored — macOS introspection harvest is not implemented in
        this sub-phase. Linux-only fields stay at their empty defaults.
        """
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
        """Collect system info via sysctl, sw_vers, and ioreg."""
        info = TargetSystemInfo()
        info.boot_time = self._read_boot_time()
        info.hostname = socket.gethostname()
        info.domain = self._read_domain()

        # sw_vers is expensive (subprocess) and used twice — cache once.
        sw_vers_fields = self._read_sw_vers_fields()

        # Enrichment: identity.
        info.kernel = self._read_sysctl("kern.osrelease")
        info.arch = self._read_sysctl("hw.machine")
        info.distro = self._compose_darwin_distro(sw_vers_fields)

        # Legacy os_detail string composed from the cached sw_vers +
        # the kernel value we already have. Leave ``raw_os`` empty so
        # the packer's ``raw_os or os_detail`` fallback in
        # ``system_info_to_fields`` uses this string, avoiding the
        # redundant duplicate assignment the earlier draft had.
        info.os_detail = self._compose_legacy_os_detail(sw_vers_fields, info.kernel)

        uuid, serial = self._read_ioreg_platform()
        info.machine_id = uuid
        info.hw_serial = serial
        info.hw_vendor = "Apple"
        info.hw_model = self._read_sysctl("hw.model")
        # bios_version intentionally left empty for P0.
        info.cpu_brand = self._read_sysctl("machdep.cpu.brand_string")
        info.cpu_count = self._read_sysctl_int("hw.ncpu")
        info.ram_bytes = self._read_sysctl_int("hw.memsize")

        # Enrichment: boot state / runtime posture.
        info.virtualization = self._read_virtualization()
        info.timezone = self._read_timezone()

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

    def collect_connectivity_table(self) -> ConnectivityTable:
        """Not implemented on Darwin -- returns empty ConnectivityTable."""
        return ConnectivityTable()

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Not implemented on Darwin -- returns empty KernelModuleList."""
        return KernelModuleList()

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Not implemented on Darwin -- returns empty PersistenceManifest."""
        return PersistenceManifest()

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

    def _read_sw_vers_fields(self) -> dict[str, str]:
        """Run ``sw_vers`` once and parse the ``Key: value`` output."""
        sw_vers = self._run_cmd(["sw_vers"])
        if not sw_vers:
            return {}
        fields: dict[str, str] = {}
        for line in sw_vers.strip().splitlines():
            kv = line.split(":", 1)
            if len(kv) == 2:
                fields[kv[0].strip()] = kv[1].strip()
        return fields

    @staticmethod
    def _compose_darwin_distro(sw_vers_fields: dict[str, str]) -> str:
        """Compose ``ProductName ProductVersion (BuildVersion)`` from sw_vers."""
        name = sw_vers_fields.get("ProductName", "")
        version = sw_vers_fields.get("ProductVersion", "")
        build = sw_vers_fields.get("BuildVersion", "")
        parts = [p for p in (name, version) if p]
        result = " ".join(parts)
        if build:
            return f"{result} ({build})" if result else f"({build})"
        return result

    @staticmethod
    def _compose_legacy_os_detail(
        sw_vers_fields: dict[str, str], kernel: str,
    ) -> str:
        """Join sw_vers values + ``kernel <release>`` (backwards compat)."""
        parts: list[str] = [v for v in sw_vers_fields.values() if v]
        if kernel:
            parts.append(f"kernel {kernel}")
        return " ".join(parts)

    def _read_sysctl(self, key: str) -> str:
        """Read a single sysctl value as trimmed string ('' on failure)."""
        out = self._run_cmd(["sysctl", "-n", key])
        return out.strip() if out else ""

    def _read_sysctl_int(self, key: str) -> int:
        """Read a single sysctl value as int (0 on failure)."""
        raw = self._read_sysctl(key)
        if not raw:
            return 0
        try:
            return int(raw)
        except ValueError:
            return 0

    def _read_ioreg_platform(self) -> tuple[str, str]:
        """Extract (IOPlatformUUID, IOPlatformSerialNumber) via a single ioreg call.

        CRITICAL: the platform UUID comes from IOPlatformExpertDevice, not from
        ``sysctl kern.uuid`` (which is the per-boot session UUID).
        """
        out = self._run_cmd(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        if not out:
            return "", ""
        uuid_match = _IOREG_UUID_RE.search(out)
        serial_match = _IOREG_SERIAL_RE.search(out)
        uuid = uuid_match.group(1) if uuid_match else ""
        serial = serial_match.group(1) if serial_match else ""
        return uuid, serial

    def _read_virtualization(self) -> str:
        """Return 'hypervisor' if kern.hv_vmm_present=1, 'none' if 0, '' otherwise."""
        raw = self._read_sysctl("kern.hv_vmm_present")
        if raw == "1":
            return "hypervisor"
        if raw == "0":
            return "none"
        return ""

    def _read_timezone(self) -> str:
        """Return IANA timezone via /etc/localtime symlink."""
        link = read_symlink("/etc/localtime", self._log)
        if not link:
            return ""
        for prefix in _TZ_PREFIXES:
            if link.startswith(prefix):
                return link[len(prefix):]
        return link

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
