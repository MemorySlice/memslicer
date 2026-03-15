"""Abstract base class for memory acquirers."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AcquireResult:
    """Result of a memory acquisition operation."""

    regions_captured: int
    regions_total: int
    bytes_captured: int
    modules_captured: int
    aborted: bool
    duration_secs: float
    output_path: str
    regions_skipped: int = 0
    rwx_regions: int = 0
    bytes_attempted: int = 0
    pages_captured: int = 0
    pages_failed: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)


class BaseAcquirer(ABC):
    """Abstract interface for memory acquisition backends."""

    @abstractmethod
    def acquire(self, output_path: Path | str) -> AcquireResult:
        """Acquire process memory and write to output_path as MSL file."""
        ...
