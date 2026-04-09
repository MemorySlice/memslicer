"""Backward-compatible Frida acquirer wrapping FridaBridge + AcquisitionEngine."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from memslicer.acquirer.base import AcquireResult, BaseAcquirer
from memslicer.acquirer.engine import AcquisitionEngine, ProgressCallback, _DEFAULT_MAX_CHUNK
from memslicer.acquirer.frida_bridge import FridaBridge
from memslicer.acquirer.investigation import InvestigationCollector
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import CompAlgo, OSType


class FridaAcquirer(BaseAcquirer):
    """Acquires process memory using Frida and writes MSL files.

    This is a backward-compatible wrapper around FridaBridge + AcquisitionEngine.
    """

    def __init__(
        self,
        target: int | str,
        device: Any | None = None,
        comp_algo: CompAlgo = CompAlgo.NONE,
        region_filter: RegionFilter | None = None,
        os_override: OSType | None = None,
        logger: logging.Logger | None = None,
        read_timeout: float = 10.0,
        max_chunk_size: int = _DEFAULT_MAX_CHUNK,
        investigation: bool = False,
        collector: InvestigationCollector | None = None,
    ) -> None:
        bridge = FridaBridge(
            target=target,
            device=device,
            read_timeout=read_timeout,
            logger=logger,
        )
        self._engine = AcquisitionEngine(
            bridge=bridge,
            comp_algo=comp_algo,
            region_filter=region_filter,
            os_override=os_override,
            logger=logger,
            max_chunk_size=max_chunk_size,
            investigation=investigation,
            collector=collector,
        )

    def acquire(self, output_path: Path | str) -> AcquireResult:
        """Acquire process memory and write MSL file."""
        return self._engine.acquire(output_path)

    def request_abort(self) -> None:
        """Request graceful abort of the current acquisition."""
        self._engine.request_abort()

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback."""
        self._engine.set_progress_callback(callback)
