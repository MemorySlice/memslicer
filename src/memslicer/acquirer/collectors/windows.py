"""Windows-specific investigation collector."""
from __future__ import annotations

import csv
import ipaddress
import io
import logging
import os
import platform
import re
import subprocess
import time

from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry

from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
    HT_UNKNOWN, HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE, HT_REGISTRY,
)

# netstat state mapping
_NETSTAT_STATES = {
    "ESTABLISHED": 0x01,
    "SYN_SENT": 0x02,
    "SYN_RECV": 0x03,
    "FIN_WAIT_1": 0x04,
    "FIN_WAIT_2": 0x05,
    "TIME_WAIT": 0x06,
    "CLOSE_WAIT": 0x08,
    "LAST_ACK": 0x09,
    "LISTENING": 0x0A,
    "CLOSING": 0x0B,
}


def _classify_win_type(type_name: str) -> int:
    """Map a Windows NT object type name to a handle type constant."""
    t = type_name.lower()
    if t == "file":
        return HT_FILE
    if t == "directory":
        return HT_DIR
    if t in ("tcpendpoint", "udpendpoint", "afdendpoint"):
        return HT_SOCKET
    if t == "key":
        return HT_REGISTRY
    if t in ("section", "event", "mutant", "semaphore", "timer",
             "thread", "process", "iocompletion", "job"):
        return HT_UNKNOWN  # kernel objects, not user-visible
    if t == "device":
        return HT_DEVICE
    return HT_UNKNOWN


class WindowsCollector:
    """Collects investigation data on Windows via system commands."""

    _is_memslicer_collector = True

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or logging.getLogger("memslicer")

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity via wmic/PowerShell."""
        info = TargetProcessInfo()

        # Try wmic first, then PowerShell
        wmic_out = self._run_cmd([
            "wmic", "process", "where", f"processid={pid}",
            "get", "ParentProcessId,SessionId,CreationDate,ExecutablePath,CommandLine",
            "/FORMAT:LIST",
        ])

        if not wmic_out:
            wmic_out = self._run_powershell(
                f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' | "
                "Select-Object ParentProcessId,SessionId,CreationDate,ExecutablePath,CommandLine | "
                "Format-List"
            )

        if wmic_out:
            props = self._parse_list_format(wmic_out)
            info.ppid = int(props.get("ParentProcessId", "0") or "0")
            info.session_id = int(props.get("SessionId", "0") or "0")
            info.exe_path = props.get("ExecutablePath", "")
            info.cmd_line = props.get("CommandLine", "")

            creation = props.get("CreationDate", "")
            if creation:
                info.start_time_ns = self._parse_wmi_datetime(creation)

        return info

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info via environment and ctypes/wmic."""
        info = TargetSystemInfo()
        info.hostname = os.environ.get("COMPUTERNAME", "") or self._get_hostname()
        info.domain = os.environ.get("USERDOMAIN", "")
        info.os_detail = platform.platform()
        info.boot_time = self._read_boot_time()
        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate processes via tasklist /V /FO CSV."""
        out = self._run_cmd(["tasklist", "/V", "/FO", "CSV"])
        if not out:
            return []

        entries: list[ProcessEntry] = []
        reader = csv.reader(io.StringIO(out))
        header = next(reader, None)
        if not header:
            return []

        for row in reader:
            entry = self._parse_tasklist_row(row, header, target_pid)
            if entry is not None:
                entries.append(entry)

        self._log.info("Collected %d process table entries", len(entries))
        return entries

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate connections via netstat -ano."""
        out = self._run_cmd(["netstat", "-ano"])
        if not out:
            return []

        entries: list[ConnectionEntry] = []
        for line in out.strip().splitlines():
            entry = self._parse_netstat_line(line)
            if entry is not None:
                entries.append(entry)

        self._log.info("Collected %d connection entries", len(entries))
        return entries

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Collect handle table via NtQuerySystemInformation.

        Falls back to empty list when not running with elevated privileges
        or on non-Windows platforms.
        """
        if os.name != "nt":
            return []

        try:
            return self._enumerate_handles_nt(pid)
        except Exception as exc:
            self._log.warning(
                "Handle table collection failed (may need elevated "
                "privileges): %s", exc,
            )
            return []

    def _enumerate_handles_nt(self, pid: int) -> list[HandleEntry]:
        """Use NtQuerySystemInformation to enumerate handles for *pid*."""
        import ctypes
        from ctypes import wintypes

        ntdll = ctypes.WinDLL("ntdll")
        NtQuerySystemInformation = ntdll.NtQuerySystemInformation
        NtQuerySystemInformation.restype = ctypes.c_long
        NtQuerySystemInformation.argtypes = [
            ctypes.c_ulong,        # SystemInformationClass
            ctypes.c_void_p,       # SystemInformation
            ctypes.c_ulong,        # SystemInformationLength
            ctypes.POINTER(ctypes.c_ulong),  # ReturnLength
        ]

        NtQueryObject = ntdll.NtQueryObject
        NtQueryObject.restype = ctypes.c_long
        NtQueryObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]

        SYSTEM_HANDLE_INFORMATION = 16
        STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

        # SYSTEM_HANDLE_TABLE_ENTRY_INFO layout (16 bytes on 32-bit, 24 on 64-bit)
        class SYSTEM_HANDLE_ENTRY(ctypes.Structure):
            _fields_ = [
                ("UniqueProcessId", ctypes.c_ushort),
                ("CreatorBackTraceIndex", ctypes.c_ushort),
                ("ObjectTypeIndex", ctypes.c_ubyte),
                ("HandleAttributes", ctypes.c_ubyte),
                ("HandleValue", ctypes.c_ushort),
                ("Object", ctypes.c_void_p),
                ("GrantedAccess", ctypes.c_ulong),
            ]

        # Grow buffer until NtQuerySystemInformation succeeds
        buf_size = 0x100000  # 1 MB initial
        for _ in range(10):
            buf = ctypes.create_string_buffer(buf_size)
            ret_len = ctypes.c_ulong(0)
            status = NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION,
                buf, buf_size, ctypes.byref(ret_len),
            )
            if (status & 0xFFFFFFFF) == STATUS_INFO_LENGTH_MISMATCH:
                buf_size = ret_len.value + 4096
                continue
            if status < 0:
                raise OSError(f"NtQuerySystemInformation failed: 0x{status & 0xFFFFFFFF:08X}")
            break
        else:
            raise OSError("NtQuerySystemInformation buffer too small")

        # Parse the SYSTEM_HANDLE_INFORMATION structure
        count = ctypes.c_ulong.from_buffer_copy(buf, 0).value
        entry_offset = ctypes.sizeof(ctypes.c_void_p)  # NumberOfHandles is pointer-sized
        entry_size = ctypes.sizeof(SYSTEM_HANDLE_ENTRY)

        # Set up DuplicateHandle for type resolution in a single pass
        kernel32 = ctypes.WinDLL("kernel32")
        OpenProcess = kernel32.OpenProcess
        DuplicateHandle = kernel32.DuplicateHandle
        CloseHandle = kernel32.CloseHandle
        GetCurrentProcess = kernel32.GetCurrentProcess

        PROCESS_DUP_HANDLE = 0x0040
        DUPLICATE_SAME_ACCESS = 0x0002
        ObjectTypeInformation = 2

        proc_handle = OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        can_resolve = bool(proc_handle)

        entries: list[HandleEntry] = []
        try:
            for i in range(min(count, 100000)):  # Safety cap
                offset = entry_offset + i * entry_size
                if offset + entry_size > buf_size:
                    break
                entry = SYSTEM_HANDLE_ENTRY.from_buffer_copy(buf, offset)
                if entry.UniqueProcessId != pid:
                    continue

                handle_type = HT_UNKNOWN

                # Resolve type via DuplicateHandle + NtQueryObject in same pass
                if can_resolve:
                    handle_type = self._resolve_handle_type(
                        proc_handle, entry.HandleValue,
                        DuplicateHandle, GetCurrentProcess, CloseHandle,
                        NtQueryObject, ObjectTypeInformation,
                        ctypes, wintypes,
                    )

                entries.append(HandleEntry(
                    pid=pid,
                    fd=entry.HandleValue,
                    handle_type=handle_type,
                    path="",
                ))
        finally:
            if proc_handle:
                CloseHandle(proc_handle)

        self._log.info("Collected %d handle entries", len(entries))
        return entries

    @staticmethod
    def _resolve_handle_type(
        proc_handle, handle_value,
        DuplicateHandle, GetCurrentProcess, CloseHandle,
        NtQueryObject, ObjectTypeInformation,
        ctypes, wintypes,
    ) -> int:
        """Attempt to resolve a single handle's type via DuplicateHandle."""
        dup = wintypes.HANDLE()
        DUPLICATE_SAME_ACCESS = 0x0002
        ok = DuplicateHandle(
            proc_handle, handle_value,
            GetCurrentProcess(), ctypes.byref(dup),
            0, False, DUPLICATE_SAME_ACCESS,
        )
        if not ok:
            return HT_UNKNOWN
        try:
            type_buf = ctypes.create_string_buffer(1024)
            type_len = ctypes.c_ulong(0)
            status = NtQueryObject(
                dup, ObjectTypeInformation,
                type_buf, 1024, ctypes.byref(type_len),
            )
            if status >= 0 and type_len.value > 4:
                name_len = ctypes.c_ushort.from_buffer_copy(type_buf, 0).value
                ptr_offset = ctypes.sizeof(ctypes.c_ushort) * 2 + (
                    8 - (ctypes.sizeof(ctypes.c_ushort) * 2) % 8
                ) % 8  # align to pointer
                if ptr_offset + ctypes.sizeof(ctypes.c_void_p) <= type_len.value:
                    name_start = max(ptr_offset + ctypes.sizeof(ctypes.c_void_p), 8)
                    if name_start + name_len <= type_len.value:
                        type_name = type_buf[name_start:name_start + name_len].decode(
                            "utf-16-le", errors="ignore",
                        )
                        return _classify_win_type(type_name)
        finally:
            CloseHandle(dup)
        return HT_UNKNOWN

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_cmd(self, cmd: list[str], timeout: float = 15.0) -> str:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self._log.debug("Command %s failed: %s", cmd[0], exc)
        return ""

    def _run_powershell(self, script: str) -> str:
        return self._run_cmd(["powershell", "-NoProfile", "-Command", script])

    @staticmethod
    def _get_hostname() -> str:
        import socket
        return socket.gethostname()

    def _read_boot_time(self) -> int:
        """Read boot time via GetTickCount64 or wmic."""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            uptime_ms = kernel32.GetTickCount64()
            boot_time_sec = int(time.time()) - (uptime_ms // 1000)
            return boot_time_sec * 1_000_000_000
        except (AttributeError, OSError):
            pass

        # Fallback: wmic
        out = self._run_cmd(["wmic", "os", "get", "LastBootUpTime", "/FORMAT:LIST"])
        if out:
            props = self._parse_list_format(out)
            dt_str = props.get("LastBootUpTime", "")
            if dt_str:
                return self._parse_wmi_datetime(dt_str)
        return 0

    @staticmethod
    def _parse_list_format(text: str) -> dict[str, str]:
        """Parse KEY=VALUE format from wmic/PowerShell LIST output."""
        props: dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                props[key.strip()] = value.strip()
        return props

    @staticmethod
    def _parse_wmi_datetime(dt_str: str) -> int:
        """Parse WMI datetime format (yyyymmddHHMMSS.ffffff+ZZZ) to ns."""
        match = re.match(r"(\d{14})", dt_str)
        if match:
            from datetime import datetime
            dt = datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
            return int(dt.timestamp() * 1_000_000_000)
        return 0

    def _parse_tasklist_row(
        self, row: list[str], header: list[str], target_pid: int,
    ) -> ProcessEntry | None:
        if len(row) < 2:
            return None
        try:
            # CSV columns: "Image Name","PID","Session Name","Session#","Mem Usage",...
            exe_name = row[0] if len(row) > 0 else ""
            pid = int(row[1]) if len(row) > 1 else 0
            session_id = int(row[3]) if len(row) > 3 else 0
            # Memory column has "K" suffix: "1,234 K"
            mem_str = row[4].replace(",", "").replace(" K", "").strip() if len(row) > 4 else "0"
            rss = int(mem_str) * 1024 if mem_str.isdigit() else 0
        except (ValueError, IndexError):
            return None

        return ProcessEntry(
            pid=pid, ppid=0, uid=0,
            is_target=(pid == target_pid),
            start_time=0, rss=rss,
            exe_name=exe_name, cmd_line="", user="",
        )

    def _parse_netstat_line(self, line: str) -> ConnectionEntry | None:
        """Parse a netstat -ano output line."""
        line = line.strip()
        # Skip headers and empty lines
        if not line or line.startswith("Active") or line.startswith("Proto"):
            return None

        fields = line.split()
        if len(fields) < 4:
            return None

        proto_str = fields[0].upper()
        if proto_str == "TCP":
            protocol = PROTO_TCP
            if len(fields) < 5:
                return None
            local = fields[1]
            remote = fields[2]
            state_str = fields[3]
            state = _NETSTAT_STATES.get(state_str, 0x00)
            try:
                pid = int(fields[4])
            except (ValueError, IndexError):
                pid = 0
        elif proto_str == "UDP":
            protocol = PROTO_UDP
            local = fields[1]
            remote = fields[2] if len(fields) > 2 else "*:*"
            state = 0x00
            try:
                pid = int(fields[3])
            except (ValueError, IndexError):
                pid = 0
        else:
            return None

        local_addr, local_port, family = self._parse_netstat_addr(local)
        remote_addr, remote_port, _ = self._parse_netstat_addr(remote)

        return ConnectionEntry(
            pid=pid, family=family, protocol=protocol, state=state,
            local_addr=local_addr, local_port=local_port,
            remote_addr=remote_addr, remote_port=remote_port,
        )

    @staticmethod
    def _parse_netstat_addr(addr_str: str) -> tuple[bytes, int, int]:
        """Parse netstat address like '127.0.0.1:8080' or '[::1]:443'."""
        zero_addr = b"\x00" * 16

        if addr_str in ("*:*", "0.0.0.0:0", "[::]:0"):
            return zero_addr, 0, AF_INET

        # IPv6: [addr]:port
        if addr_str.startswith("["):
            bracket_end = addr_str.index("]")
            addr_part = addr_str[1:bracket_end]
            port_part = addr_str[bracket_end + 2:]
            family = AF_INET6
        else:
            last_colon = addr_str.rfind(":")
            addr_part = addr_str[:last_colon]
            port_part = addr_str[last_colon + 1:]
            family = AF_INET6 if ":" in addr_part else AF_INET

        try:
            port = int(port_part) if port_part and port_part != "*" else 0
        except ValueError:
            port = 0

        try:
            ip = ipaddress.ip_address(addr_part)
            addr_bytes = ip.packed
            if len(addr_bytes) == 4:
                addr_bytes += b"\x00" * 12
        except ValueError:
            addr_bytes = zero_addr

        return addr_bytes, port, family
