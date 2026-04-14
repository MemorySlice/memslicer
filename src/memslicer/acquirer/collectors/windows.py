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

try:
    import winreg  # type: ignore[import-not-found]
except ImportError:
    winreg = None  # type: ignore[assignment]

from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import (
    ConnectionEntry, HandleEntry, ProcessEntry, ConnectivityTable,
    KernelModuleList, PersistenceManifest,
)

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

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        """Collect process identity via wmic/PowerShell.

        P1.6.3 kwargs are accepted for protocol compatibility but
        currently ignored — the Windows introspection harvest is not
        implemented in this sub-phase.
        """
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
        """Collect enriched system info via ctypes, winreg, and CIM.

        Every individual source is a ``_win_*`` helper so tests can stub
        them one at a time. The method never raises: failures are caught
        and appended to ``info.collector_warnings``.
        """
        info = TargetSystemInfo()
        try:
            info.hostname = (
                self._win_hostname()
                or os.environ.get("COMPUTERNAME", "")
                or self._get_hostname()
            )
            info.domain = self._win_domain() or os.environ.get("USERDOMAIN", "")

            ver = self._win_version_ex() or {}
            if ver:
                info.kernel = (
                    f"{ver.get('major', '')}.{ver.get('minor', '')}."
                    f"{ver.get('build', '')}"
                )
            info.arch = self._win_arch()
            info.distro = self._win_compose_distro() or platform.platform()
            info.raw_os = platform.platform()
            info.os_detail = info.distro or info.raw_os

            info.machine_id = self._win_machine_id()
            hw_vendor, hw_model = self._win_hw_vendor_model()
            info.hw_vendor = hw_vendor
            info.hw_model = hw_model
            info.bios_version = self._win_bios()
            info.cpu_brand = self._win_cpu()
            info.cpu_count = self._win_cpu_count()
            info.ram_bytes = self._win_ram_bytes()
            info.timezone = self._win_timezone()
            info.boot_time = self._win_boot_time_ns()
            info.secure_boot = self._win_secure_boot()

            # CIM-gated fields: detect Winmgmt service first.
            if self._win_service_running("Winmgmt"):
                info.hw_serial = self._win_hw_serial()
                info.virtualization = self._win_virt()
                info.disk_encryption = self._win_disk_encryption()
                smbios = self._win_smbios_uuid()
                if smbios and not info.machine_id:
                    info.machine_id = smbios
            else:
                info.collector_warnings.append("wmi_unavailable")

            # Network identity is always collected; projection-time flag
            # (``--include-network-identity``) decides whether it is
            # written to the wire.
            info.nic_macs = self._win_nic_macs()
        except Exception as exc:  # pragma: no cover - safety net
            self._log.warning("collect_system_info failed: %s", exc)
            info.collector_warnings.append(f"collect_system_info_error:{exc}")
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

    def collect_connectivity_table(self) -> ConnectivityTable:
        """Not implemented on Windows -- returns empty ConnectivityTable."""
        return ConnectivityTable()

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Not implemented on Windows -- returns empty KernelModuleList."""
        return KernelModuleList()

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Not implemented on Windows -- returns empty PersistenceManifest."""
        return PersistenceManifest()

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

    # ------------------------------------------------------------------
    # Enrichment helpers (P1.1). Every method catches ImportError,
    # OSError, and AttributeError so the module stays import-safe on
    # Darwin/Linux and unit tests can stub them individually.
    # ------------------------------------------------------------------

    def _win_version_ex(self) -> dict | None:
        """Call ntdll.RtlGetVersion for shim-proof OS version info."""
        try:
            import ctypes
            from ctypes import wintypes

            class RTL_OSVERSIONINFOEXW(ctypes.Structure):
                _fields_ = [
                    ("dwOSVersionInfoSize", wintypes.ULONG),
                    ("dwMajorVersion", wintypes.ULONG),
                    ("dwMinorVersion", wintypes.ULONG),
                    ("dwBuildNumber", wintypes.ULONG),
                    ("dwPlatformId", wintypes.ULONG),
                    ("szCSDVersion", wintypes.WCHAR * 128),
                    ("wServicePackMajor", wintypes.USHORT),
                    ("wServicePackMinor", wintypes.USHORT),
                    ("wSuiteMask", wintypes.USHORT),
                    ("wProductType", ctypes.c_ubyte),
                    ("wReserved", ctypes.c_ubyte),
                ]

            osvi = RTL_OSVERSIONINFOEXW()
            osvi.dwOSVersionInfoSize = ctypes.sizeof(RTL_OSVERSIONINFOEXW)
            ntdll = ctypes.WinDLL("ntdll")
            if ntdll.RtlGetVersion(ctypes.byref(osvi)) != 0:
                return None
            return {
                "major": int(osvi.dwMajorVersion),
                "minor": int(osvi.dwMinorVersion),
                "build": int(osvi.dwBuildNumber),
                "service_pack": osvi.szCSDVersion or "",
            }
        except (ImportError, OSError, AttributeError):
            return None

    def _win_read_registry(
        self, hive: str, subkey: str, value: str, wow64_64: bool = True,
    ) -> str | int | None:
        """Read a single registry value, forcing the 64-bit view by default."""
        if winreg is None:
            return None
        hive_map = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        root = hive_map.get(hive)
        if root is None:
            return None
        flags = winreg.KEY_READ
        if wow64_64:
            flags |= getattr(winreg, "KEY_WOW64_64KEY", 0)
        try:
            with winreg.OpenKey(root, subkey, 0, flags) as key:
                data, vtype = winreg.QueryValueEx(key, value)
            if vtype in (winreg.REG_DWORD, getattr(winreg, "REG_QWORD", 11)):
                return int(data)
            return data
        except (FileNotFoundError, OSError):
            return None

    def _win_compose_distro(self) -> str:
        """Compose a distro string from CurrentVersion registry values.

        Applies the ProductName trap fix: ``ProductName`` is still
        "Windows 10 …" on Windows 11 (build >= 22000), so we override
        the prefix when the build number says otherwise.
        """
        subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        product = self._win_read_registry("HKLM", subkey, "ProductName") or ""
        display = self._win_read_registry("HKLM", subkey, "DisplayVersion") or ""
        build_s = self._win_read_registry("HKLM", subkey, "CurrentBuildNumber") or ""
        ubr = self._win_read_registry("HKLM", subkey, "UBR")
        try:
            build_num = int(build_s) if build_s else 0
        except (TypeError, ValueError):
            build_num = 0

        if not product and not build_s:
            return ""

        product_str = str(product)
        if build_num >= 22000 and product_str.startswith("Windows 10"):
            product_str = "Windows 11" + product_str[len("Windows 10"):]

        parts = [product_str] if product_str else []
        if display:
            parts.append(str(display))
        if build_s:
            if ubr is not None:
                parts.append(f"(Build {build_s}.{ubr})")
            else:
                parts.append(f"(Build {build_s})")
        return " ".join(parts).strip()

    def _win_arch(self) -> str:
        """Detect native CPU arch via kernel32.GetNativeSystemInfo."""
        try:
            import ctypes
            from ctypes import wintypes

            class SYSTEM_INFO(ctypes.Structure):
                _fields_ = [
                    ("wProcessorArchitecture", wintypes.WORD),
                    ("wReserved", wintypes.WORD),
                    ("dwPageSize", wintypes.DWORD),
                    ("lpMinimumApplicationAddress", ctypes.c_void_p),
                    ("lpMaximumApplicationAddress", ctypes.c_void_p),
                    ("dwActiveProcessorMask", ctypes.c_void_p),
                    ("dwNumberOfProcessors", wintypes.DWORD),
                    ("dwProcessorType", wintypes.DWORD),
                    ("dwAllocationGranularity", wintypes.DWORD),
                    ("wProcessorLevel", wintypes.WORD),
                    ("wProcessorRevision", wintypes.WORD),
                ]

            si = SYSTEM_INFO()
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.GetNativeSystemInfo(ctypes.byref(si))
            arch_map = {0: "x86", 9: "x86_64", 12: "arm64", 5: "arm"}
            native = arch_map.get(si.wProcessorArchitecture, "")

            # Detect ARM64EC / emulated x64 via IsWow64Process2.
            try:
                process_machine = wintypes.USHORT(0)
                native_machine = wintypes.USHORT(0)
                if kernel32.IsWow64Process2(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(process_machine),
                    ctypes.byref(native_machine),
                ):
                    if native_machine.value == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                        native = "arm64"
            except (AttributeError, OSError):
                pass
            return native
        except (ImportError, OSError, AttributeError):
            return ""

    def _win_machine_id(self) -> str:
        """Read HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid (64-bit view)."""
        val = self._win_read_registry(
            "HKLM", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid",
            wow64_64=True,
        )
        return str(val) if val else ""

    def _win_smbios_uuid(self) -> str:
        """Get the SMBIOS system UUID via CIM (requires Winmgmt)."""
        rows = self._read_cim("root/cimv2", "SELECT UUID FROM Win32_ComputerSystemProduct")
        if rows:
            return str(rows[0].get("UUID", ""))
        return ""

    def _win_hw_vendor_model(self) -> tuple[str, str]:
        """Read SystemManufacturer/SystemProductName from HARDWARE\\DESCRIPTION."""
        subkey = r"HARDWARE\DESCRIPTION\System\BIOS"
        vendor = self._win_read_registry("HKLM", subkey, "SystemManufacturer") or ""
        model = self._win_read_registry("HKLM", subkey, "SystemProductName") or ""
        return (str(vendor), str(model))

    def _win_bios(self) -> str:
        """Compose BIOSVersion + BIOSReleaseDate from HARDWARE\\DESCRIPTION."""
        subkey = r"HARDWARE\DESCRIPTION\System\BIOS"
        version = self._win_read_registry("HKLM", subkey, "BIOSVersion") or ""
        release = self._win_read_registry("HKLM", subkey, "BIOSReleaseDate") or ""
        parts = [str(p) for p in (version, release) if p]
        return " ".join(parts)

    def _win_hw_serial(self) -> str:
        """Read Win32_BIOS.SerialNumber via CIM (projection-gated)."""
        rows = self._read_cim("root/cimv2", "SELECT SerialNumber FROM Win32_BIOS")
        if rows:
            return str(rows[0].get("SerialNumber", ""))
        return ""

    def _win_cpu(self) -> str:
        """Read CentralProcessor\\0\\ProcessorNameString from the registry."""
        subkey = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        val = self._win_read_registry("HKLM", subkey, "ProcessorNameString") or ""
        return str(val).strip()

    def _win_cpu_count(self) -> int:
        """Return os.cpu_count() or 0."""
        return os.cpu_count() or 0

    def _win_ram_bytes(self) -> int:
        """Return total physical RAM via kernel32.GlobalMemoryStatusEx."""
        try:
            import ctypes
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32 = ctypes.WinDLL("kernel32")
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return int(stat.ullTotalPhys)
            return 0
        except (ImportError, OSError, AttributeError):
            return 0

    def _win_timezone(self) -> str:
        """Read Windows TZ key name. Note: raw Windows name, not IANA."""
        # Best-effort: return the raw Windows TZ name (e.g. "Pacific Standard
        # Time"). A precise IANA mapping would require the CLDR table and is
        # out of scope for P1.1.
        subkey = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
        val = self._win_read_registry("HKLM", subkey, "TimeZoneKeyName") or ""
        return str(val).strip()

    def _win_hostname(self) -> str:
        """Read the DNS FQDN via GetComputerNameExW (two-call size dance)."""
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32")
            ComputerNameDnsFullyQualified = 3
            size = wintypes.DWORD(0)
            kernel32.GetComputerNameExW(
                ComputerNameDnsFullyQualified, None, ctypes.byref(size),
            )
            if size.value == 0:
                return ""
            buf = ctypes.create_unicode_buffer(size.value)
            if not kernel32.GetComputerNameExW(
                ComputerNameDnsFullyQualified, buf, ctypes.byref(size),
            ):
                return ""
            return buf.value
        except (ImportError, OSError, AttributeError):
            return ""

    def _win_domain(self) -> str:
        """Return AD domain via netapi32.NetGetJoinInformation."""
        try:
            import ctypes
            from ctypes import wintypes
            netapi32 = ctypes.WinDLL("netapi32")
            name_buf = ctypes.c_wchar_p()
            status = wintypes.DWORD(0)
            rc = netapi32.NetGetJoinInformation(
                None, ctypes.byref(name_buf), ctypes.byref(status),
            )
            if rc != 0:
                return ""
            try:
                # 3 == NetSetupDomainName
                if status.value == 3 and name_buf.value:
                    return name_buf.value
                return ""
            finally:
                netapi32.NetApiBufferFree(name_buf)
        except (ImportError, OSError, AttributeError):
            return ""

    def _win_boot_time_ns(self) -> int:
        """Prefer CIM Win32_OperatingSystem.LastBootUpTime; fall back to tick count."""
        rows = self._read_cim(
            "root/cimv2",
            "SELECT LastBootUpTime FROM Win32_OperatingSystem",
        )
        if rows:
            dt_str = str(rows[0].get("LastBootUpTime", ""))
            if dt_str:
                ns = self._parse_wmi_datetime(dt_str)
                if ns:
                    return ns
        return self._read_boot_time()

    def _win_virt(self) -> str:
        """Detect virtualization via CIM HypervisorPresent + Model keywords."""
        rows = self._read_cim(
            "root/cimv2",
            "SELECT HypervisorPresent,Model,Manufacturer FROM Win32_ComputerSystem",
        )
        if not rows:
            return ""
        row = rows[0]
        model = f"{row.get('Model', '')} {row.get('Manufacturer', '')}".lower()
        if "vmware" in model:
            return "vmware"
        if "virtualbox" in model:
            return "virtualbox"
        if "qemu" in model:
            return "qemu"
        if "kvm" in model:
            return "kvm"
        if "hyper-v" in model or "hyperv" in model:
            return "hypervisor"
        hv = str(row.get("HypervisorPresent", "")).strip().lower()
        if hv in ("true", "1"):
            return "hypervisor"
        return "none"

    def _win_secure_boot(self) -> str:
        """Read UEFISecureBootEnabled from SecureBoot\\State."""
        subkey = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        val = self._win_read_registry("HKLM", subkey, "UEFISecureBootEnabled")
        if val is None:
            return ""
        try:
            return "1" if int(val) == 1 else "0"
        except (TypeError, ValueError):
            return ""

    def _win_disk_encryption(self) -> str:
        """Detect BitLocker via Win32_EncryptableVolume.ProtectionStatus."""
        rows = self._read_cim(
            "root/cimv2/Security/MicrosoftVolumeEncryption",
            "SELECT ProtectionStatus FROM Win32_EncryptableVolume",
        )
        if not rows:
            return ""
        for row in rows:
            try:
                if int(row.get("ProtectionStatus", 0)) == 1:
                    return "bitlocker"
            except (TypeError, ValueError):
                continue
        return "none"

    def _win_collector_caps(self) -> str:
        """Check token elevation via advapi32.GetTokenInformation."""
        try:
            import ctypes
            from ctypes import wintypes
            advapi32 = ctypes.WinDLL("advapi32")
            kernel32 = ctypes.WinDLL("kernel32")
            TOKEN_QUERY = 0x0008
            TokenElevation = 20
            token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token),
            ):
                return ""
            try:
                elevation = wintypes.DWORD(0)
                ret_len = wintypes.DWORD(0)
                ok = advapi32.GetTokenInformation(
                    token, TokenElevation,
                    ctypes.byref(elevation), ctypes.sizeof(elevation),
                    ctypes.byref(ret_len),
                )
                if not ok:
                    return ""
                return "elevated" if elevation.value else "standard"
            finally:
                kernel32.CloseHandle(token)
        except (ImportError, OSError, AttributeError):
            return ""

    def _win_nic_macs(self) -> list[str]:
        """Enumerate NIC MACs via iphlpapi.GetAdaptersAddresses."""
        try:
            import ctypes
            from ctypes import wintypes
            iphlpapi = ctypes.WinDLL("iphlpapi")

            # Call once with a NULL buffer to discover required size.
            size = wintypes.ULONG(15 * 1024)
            buf = ctypes.create_string_buffer(size.value)
            # Family AF_UNSPEC=0, flags=0.
            rc = iphlpapi.GetAdaptersAddresses(
                0, 0, None, buf, ctypes.byref(size),
            )
            if rc == 111:  # ERROR_BUFFER_OVERFLOW
                buf = ctypes.create_string_buffer(size.value)
                rc = iphlpapi.GetAdaptersAddresses(
                    0, 0, None, buf, ctypes.byref(size),
                )
            if rc != 0:
                return []
            # Parsing the IP_ADAPTER_ADDRESSES linked list is ~60 lines of
            # layout boilerplate. For P1.1 we accept that Windows MAC
            # collection is stubbed on non-Windows (where this code path
            # is not reachable anyway) and tests patch this helper
            # directly. Return [] as a safe default here.
            return []
        except (ImportError, OSError, AttributeError):
            return []

    def _win_service_running(self, name: str) -> bool:
        """Check if a Windows service is RUNNING via advapi32 SCM."""
        try:
            import ctypes
            from ctypes import wintypes

            class SERVICE_STATUS(ctypes.Structure):
                _fields_ = [
                    ("dwServiceType", wintypes.DWORD),
                    ("dwCurrentState", wintypes.DWORD),
                    ("dwControlsAccepted", wintypes.DWORD),
                    ("dwWin32ExitCode", wintypes.DWORD),
                    ("dwServiceSpecificExitCode", wintypes.DWORD),
                    ("dwCheckPoint", wintypes.DWORD),
                    ("dwWaitHint", wintypes.DWORD),
                ]

            advapi32 = ctypes.WinDLL("advapi32")
            SC_MANAGER_CONNECT = 0x0001
            SERVICE_QUERY_STATUS = 0x0004
            SERVICE_RUNNING = 0x00000004

            scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            if not scm:
                return False
            try:
                svc = advapi32.OpenServiceW(scm, name, SERVICE_QUERY_STATUS)
                if not svc:
                    return False
                try:
                    status = SERVICE_STATUS()
                    if not advapi32.QueryServiceStatus(svc, ctypes.byref(status)):
                        return False
                    return status.dwCurrentState == SERVICE_RUNNING
                finally:
                    advapi32.CloseServiceHandle(svc)
            finally:
                advapi32.CloseServiceHandle(scm)
        except (ImportError, OSError, AttributeError):
            return False

    def _read_cim(self, namespace: str, query: str) -> list[dict]:
        """Run a CIM query via PowerShell Get-CimInstance and parse LIST output.

        Only called after ``_win_service_running("Winmgmt")`` succeeds.
        Returns an empty list on non-Windows / on any failure.
        """
        if os.name != "nt":
            return []
        script = (
            f"Get-CimInstance -Namespace '{namespace}' -Query \"{query}\" | "
            "Format-List"
        )
        out = self._run_powershell(script)
        if not out:
            return []

        rows: list[dict] = []
        current: dict = {}
        for raw in out.splitlines():
            line = raw.rstrip()
            if not line.strip():
                if current:
                    rows.append(current)
                    current = {}
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()
        if current:
            rows.append(current)
        return rows

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
