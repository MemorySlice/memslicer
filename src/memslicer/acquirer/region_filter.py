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
    "kernel-pseudo": "kernel pseudo-mapping, unreadable by design",
}


# Kernel-provided mappings that appear readable in /proc/<pid>/maps but fault
# on ptrace / process_vm_readv reads.  Linux 6.13 split [vvar] into [vvar] and
# [vvar_vclock], so both names occur in the wild.
#
# [vdso] is deliberately absent: it is genuinely readable and forensically
# relevant.
KERNEL_PSEUDO_NAMES = frozenset({"[vvar]", "[vvar_vclock]", "[vsyscall]"})


def is_kernel_pseudo_region(file_path: str) -> bool:
    """Whether *file_path* names a kernel mapping that cannot be read.

    Args:
        file_path: Region name from ``/proc/<pid>/maps``, e.g. ``[vvar]``.

    Returns:
        ``True`` for kernel pseudo-mappings, ``False`` otherwise.
    """
    return file_path.strip() in KERNEL_PSEUDO_NAMES


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
        skip_kernel_pseudo: Skip kernel pseudo-mappings outright instead of
                  attempting them. Off by default so the acquirer still tries
                  the read and records the kernel's answer.
    """
    addr_ranges: list[tuple[int, int]] = field(default_factory=list)
    min_prot: int = 0
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    skip_no_read: bool = True
    max_region_size: int = 0
    skip_kernel_pseudo: bool = False

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
        if self.skip_kernel_pseudo and is_kernel_pseudo_region(file_path):
            return "kernel-pseudo"
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
