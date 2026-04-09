"""Protocol and data types for investigation-mode data collection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from memslicer.msl.types import ProcessEntry, ConnectionEntry, HandleEntry


@dataclass
class TargetProcessInfo:
    """Process identity metadata collected from the target system."""
    ppid: int = 0
    session_id: int = 0
    start_time_ns: int = 0
    exe_path: str = ""
    cmd_line: str = ""


@dataclass
class TargetSystemInfo:
    """System-level metadata collected from the target system."""
    boot_time: int = 0        # nanoseconds since epoch
    hostname: str = ""
    domain: str = ""
    os_detail: str = ""


@runtime_checkable
class InvestigationCollector(Protocol):
    """Protocol for collecting system-wide investigation data.

    Implementations are OS-specific, not debugger-specific.
    Each method returns best-effort data; empty/zero for
    fields that cannot be collected on the current platform.
    """

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect identity metadata for the target process."""
        ...

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system-wide context (hostname, OS detail, boot time)."""
        ...

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate all running processes. Returns empty list on failure."""
        ...

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate network connections. Returns empty list on failure."""
        ...

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate open file handles for a process. Returns empty list on failure."""
        ...
