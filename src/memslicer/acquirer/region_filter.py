"""Memory region filtering for selective acquisition."""
from __future__ import annotations
import re
from dataclasses import dataclass, field


SKIP_REASON_LABELS = {
    "no-read": "no read permission (use --include-unreadable to include)",
    "max-size": "exceeded max region size",
    "min-prot": "below minimum protection filter",
    "addr-range": "outside address range filter",
    "path-include": "path did not match include filter",
    "path-exclude": "path matched exclude filter",
}


@dataclass
class RegionFilter:
    """Filter for memory regions based on address, protection, and path patterns.

    Attributes:
        addr_ranges: List of (start, end) tuples. If non-empty, only regions
                     overlapping these ranges are included.
        min_prot: Minimum protection bits required (bit0=R, bit1=W, bit2=X).
                  E.g., 1 = must be readable.
        include_paths: Regex patterns; if non-empty, region file path must match at least one.
        exclude_paths: Regex patterns; region file path must NOT match any.
    """
    addr_ranges: list[tuple[int, int]] = field(default_factory=list)
    min_prot: int = 0
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    skip_no_read: bool = True
    max_region_size: int = 0

    def __post_init__(self) -> None:
        self._compiled_includes = [re.compile(p) for p in self.include_paths]
        self._compiled_excludes = [re.compile(p) for p in self.exclude_paths]

    def matches(self, base_addr: int, size: int, protection: int, file_path: str = "") -> bool:
        """Check if a memory region passes this filter."""
        return self.skip_reason(base_addr, size, protection, file_path) is None

    def skip_reason(self, base_addr: int, size: int, protection: int, file_path: str = "") -> str | None:
        """Return the reason a region would be skipped, or None if it passes."""
        if self.skip_no_read and (protection & 1) == 0:
            return "no-read"
        if self.max_region_size > 0 and size > self.max_region_size:
            return "max-size"
        if self.min_prot and (protection & self.min_prot) != self.min_prot:
            return "min-prot"
        if self.addr_ranges:
            region_end = base_addr + size
            in_range = any(
                base_addr < range_end and region_end > range_start
                for range_start, range_end in self.addr_ranges
            )
            if not in_range:
                return "addr-range"
        if self._compiled_includes and file_path:
            if not any(pat.search(file_path) for pat in self._compiled_includes):
                return "path-include"
        elif self._compiled_includes and not file_path:
            return "path-include"
        if self._compiled_excludes and file_path:
            if any(pat.search(file_path) for pat in self._compiled_excludes):
                return "path-exclude"
        return None
