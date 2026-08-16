"""Abstract base class for memory acquirers."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class UnreadableRange:
    """A contiguous run of pages that could not be captured.

    Recorded per region so the acquisition log documents *which* bytes are
    missing rather than only how many.

    Attributes:
        base: First address of the unreadable run.
        size: Length of the run in bytes.
        region_base: Base address of the region the run belongs to.
        file_path: Mapped name of the region (e.g. ``[vvar_vclock]``), or
            ``""`` when the backend could not supply one.
        expected: ``True`` when the region is a kernel pseudo-mapping that is
            unreadable by design, ``False`` for a genuine read failure.
    """

    base: int
    size: int
    region_base: int
    file_path: str = ""
    expected: bool = False


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
    # Kernel pseudo-mappings ([vvar] and friends) are mapped but unreadable by
    # design.  They are counted separately so they do not read as data loss.
    pages_expected_unreadable: int = 0
    bytes_expected_unreadable: int = 0
    expected_unreadable_regions: list[str] = field(default_factory=list)
    unreadable_ranges: list[UnreadableRange] = field(default_factory=list)
    unreadable_ranges_truncated: int = 0


class BaseAcquirer(ABC):
    """Abstract interface for memory acquisition backends."""

    @abstractmethod
    def acquire(self, output_path: Path | str) -> AcquireResult:
        """Acquire process memory and write to output_path as MSL file."""
        ...
