"""Fallback collector returning safe defaults for unsupported platforms."""
from __future__ import annotations

import logging

from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import (
    ConnectionEntry, HandleEntry, ProcessEntry, ConnectivityTable,
    KernelModuleList, PersistenceManifest,
)


class NullCollector:
    """Returns zeroed/empty data for all investigation fields.

    Used when the target OS is unknown or unsupported.
    """

    _is_memslicer_collector = True

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or logging.getLogger("memslicer")
        self._log.warning("Using NullCollector: investigation data will be minimal")

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        return TargetProcessInfo()

    def collect_system_info(self) -> TargetSystemInfo:
        return TargetSystemInfo()

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        return []

    def collect_connection_table(self) -> list[ConnectionEntry]:
        return []

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        return []

    def collect_connectivity_table(self) -> ConnectivityTable:
        return ConnectivityTable()

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Not implemented on unsupported platforms — returns empty list."""
        return KernelModuleList()

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Not implemented on unsupported platforms — returns empty manifest."""
        return PersistenceManifest()
