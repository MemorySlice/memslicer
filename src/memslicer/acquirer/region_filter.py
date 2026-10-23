"""Memory region filtering for selective acquisition."""
from __future__ import annotations
import fnmatch
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from memslicer.acquirer.region_classify import (
    RegionCategory, RegionInfo, path_basename, strip_deleted,
)


SKIP_REASON_LABELS = {
    "no-read": "no read permission (use --include-unreadable to include)",
    "max-size": "exceeded max region size",
    "min-prot": "below minimum protection filter",
    "addr-range": "outside address range filter",
    "path-include": "path did not match include filter",
    "path-exclude": "path matched exclude filter",
    "kernel-pseudo": "kernel pseudo-mapping, unreadable by design",
    "module-exclude": "module matched --exclude-module",
    "scope": "outside selected --scope",
}


# ---------------------------------------------------------------------------
# Acquisition scope
# ---------------------------------------------------------------------------

SCOPE_TOKENS = ("full", "app", "heap", "stack")
SCOPE_ALIASES = {"heapstack": ("heap", "stack")}

FULL_SCOPE = frozenset({"full"})

# Shared-memory labels that back a heap (ashmem/dev-zero mappings used by
# allocators) and therefore belong to the ``heap`` scope when writable.
_HEAP_SHARED_MEM_PREFIXES = ("/dev/zero", "/dev/ashmem/")

# Flags used to compile ``--exclude-module`` globs.  Windows paths are
# case-insensitive, POSIX paths are not.  A module constant so tests can
# exercise both behaviours regardless of the host platform.
MODULE_PATTERN_FLAGS = re.IGNORECASE if sys.platform == "win32" else 0

_PATH_SEPARATORS = ("/", "\\")


def _expand_scope_token(token: str) -> tuple[str, ...]:
    """Expand one lower-cased scope token, resolving aliases.

    Raises:
        ValueError: If *token* is neither a scope token nor an alias.
    """
    if token in SCOPE_ALIASES:
        return SCOPE_ALIASES[token]
    if token in SCOPE_TOKENS:
        return (token,)
    expected = ", ".join((*SCOPE_TOKENS, *SCOPE_ALIASES))
    raise ValueError(f"unknown scope token '{token}' (expected one of: {expected})")


def parse_scope(text: str) -> frozenset[str]:
    """Parse a ``--scope`` value into a set of scope tokens.

    The value is a comma-separated, case-insensitive list; surrounding
    whitespace and empty items are ignored and aliases (``heapstack``) are
    expanded.  An empty value selects ``full``.

    Args:
        text: Raw option value, e.g. ``"heap, stack"``.

    Returns:
        The selected tokens, a subset of :data:`SCOPE_TOKENS`.

    Raises:
        ValueError: On an unknown token, or when ``full`` is combined with
            another token (``full`` already keeps everything).
    """
    tokens: set[str] = set()
    for item in text.split(","):
        token = item.strip().lower()
        if token:
            tokens.update(_expand_scope_token(token))
    if not tokens:
        return FULL_SCOPE
    if "full" in tokens and len(tokens) > 1:
        raise ValueError("scope 'full' cannot be combined with other tokens")
    return frozenset(tokens)


def scope_label(scope: frozenset[str]) -> str:
    """Return a stable, comma-joined label for *scope* in canonical order.

    Args:
        scope: Tokens as returned by :func:`parse_scope`.

    Returns:
        E.g. ``"heap,stack"`` regardless of the set's iteration order.
    """
    return ",".join(token for token in SCOPE_TOKENS if token in scope)


def skip_label(reason: str, scope: frozenset[str] | None = None) -> str:
    """Return the human-readable label for a skip *reason*.

    Args:
        reason: Reason code as returned by :meth:`RegionFilter.skip_reason`.
        scope: The active scope; appended to the ``scope`` label so the
            summary reads ``outside selected --scope (heap,stack)``.

    Returns:
        The label from :data:`SKIP_REASON_LABELS`, or *reason* itself when
        the code is unknown.
    """
    label = SKIP_REASON_LABELS.get(reason, reason)
    if reason == "scope" and scope:
        return f"{label} ({scope_label(scope)})"
    return label


def _normalise_scope(scope: str | Iterable[str]) -> frozenset[str]:
    """Coerce a str or iterable of tokens into a validated scope set."""
    if isinstance(scope, str):
        return parse_scope(scope)
    return parse_scope(",".join(scope))


def _is_writable(protection: int) -> bool:
    """True when the W bit (bit1) is set in *protection*."""
    return bool(protection & 2)


def _app_scope_keeps(protection: int, info: RegionInfo) -> bool:
    """``app`` keeps everything but clean system images and device maps.

    A read-only or executable mapping of a system-owned file is an
    unmodified copy of what is on disk and carries no app state.
    """
    if info.category == RegionCategory.DEVICE:
        return False
    clean_system_file = (
        info.is_file_backed and info.system_owned and not _is_writable(protection)
    )
    return not clean_system_file


def _heap_scope_keeps(protection: int, info: RegionInfo) -> bool:
    """``heap`` keeps allocator regions and writable unnamed/ashmem memory."""
    if info.category in (RegionCategory.HEAP_NATIVE, RegionCategory.HEAP_MANAGED):
        return True
    if not _is_writable(protection):
        return False
    if info.category == RegionCategory.ANON:
        return True
    return (
        info.category == RegionCategory.SHARED_MEM
        and info.label.startswith(_HEAP_SHARED_MEM_PREFIXES)
    )


def _stack_scope_keeps(protection: int, info: RegionInfo) -> bool:
    """``stack`` keeps regions classified as a thread stack."""
    return info.category == RegionCategory.STACK


_SCOPE_KEEP_RULES: dict[str, Callable[[int, RegionInfo], bool]] = {
    "app": _app_scope_keeps,
    "heap": _heap_scope_keeps,
    "stack": _stack_scope_keeps,
}


@dataclass(frozen=True)
class _ModulePattern:
    """A compiled ``--exclude-module`` glob.

    Attributes:
        regex: Full-match regex built with :func:`fnmatch.translate`.
        is_path: True when the glob contains a path separator and should
            therefore be matched against full paths as well as basenames.
    """

    regex: re.Pattern[str]
    is_path: bool

    @classmethod
    def compile(cls, pattern: str) -> _ModulePattern:
        """Compile *pattern* using :data:`MODULE_PATTERN_FLAGS`."""
        regex = re.compile(fnmatch.translate(pattern), MODULE_PATTERN_FLAGS)
        is_path = any(sep in pattern for sep in _PATH_SEPARATORS)
        return cls(regex, is_path)

    def matches(self, names: list[str], paths: list[str]) -> bool:
        """True when the glob fully matches a name, or a path if it is one."""
        candidates = names + paths if self.is_path else names
        return any(self.regex.fullmatch(c) for c in candidates if c)


def _module_candidates(file_path: str, info: RegionInfo | None) -> tuple[list[str], list[str]]:
    """Collect the (basenames, full paths) a module glob is matched against.

    With *info*: the backing file's basename and path for file-backed
    regions, the owning module's name/basename/path when attributed, and
    the label of every other region (e.g. ``dalvik-LinearAlloc``).
    Without *info*: the basename and full form of *file_path*.
    """
    if info is None:
        path = strip_deleted(file_path)
        return [path_basename(path)], [path]
    names: list[str] = []
    paths: list[str] = []
    if info.is_file_backed:
        names.append(path_basename(info.label))
        paths.append(info.label)
    else:
        names.append(info.label)
    if info.owner is not None:
        names.extend((info.owner.name, path_basename(info.owner.path)))
        paths.append(info.owner.path)
    return names, paths


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
        scope: Scope tokens (see :func:`parse_scope`); a str is parsed, any
                  iterable is normalised. ``{"full"}`` keeps every region.
                  Otherwise a region is kept when ANY selected token keeps it.
                  Regions without a :class:`RegionInfo` cannot be classified
                  and are skipped with reason ``scope``.
        exclude_modules: ``fnmatch`` globs; a region is skipped when one
                  fully matches its module basename, its anonymous label, its
                  owning module's name, or (for globs containing ``/`` or
                  ``\\``) its full path.
    """
    addr_ranges: list[tuple[int, int]] = field(default_factory=list)
    min_prot: int = 0
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    skip_no_read: bool = True
    max_region_size: int = 0
    skip_kernel_pseudo: bool = False
    scope: frozenset[str] = FULL_SCOPE
    exclude_modules: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._compiled_includes = [re.compile(p) for p in self.include_paths]
        self._compiled_excludes = [re.compile(p) for p in self.exclude_paths]
        self.scope = _normalise_scope(self.scope)
        self._compiled_modules = [_ModulePattern.compile(p) for p in self.exclude_modules]

    @property
    def is_full_scope(self) -> bool:
        """True when no scope narrowing is active."""
        return "full" in self.scope

    def matches(
        self, base_addr: int, size: int, protection: int, file_path: str = "",
        info: RegionInfo | None = None,
    ) -> bool:
        """Check if a memory region passes this filter."""
        return self.skip_reason(base_addr, size, protection, file_path, info) is None

    def _module_excluded(self, file_path: str, info: RegionInfo | None) -> bool:
        """True when any ``exclude_modules`` glob matches the region."""
        names, paths = _module_candidates(file_path, info)
        return any(pat.matches(names, paths) for pat in self._compiled_modules)

    def _kept_by_scope(self, protection: int, info: RegionInfo | None) -> bool:
        """True when at least one selected scope token keeps the region.

        An unclassified region (*info* is ``None``) is never kept, because
        none of the scope rules can be evaluated for it.
        """
        if info is None:
            return False
        return any(_SCOPE_KEEP_RULES[token](protection, info) for token in self.scope)

    def skip_reason(
        self, base_addr: int, size: int, protection: int, file_path: str = "",
        info: RegionInfo | None = None,
    ) -> str | None:
        """Return the reason a region would be skipped, or None if it passes.

        Args:
            base_addr: Start address of the region.
            size: Size of the region in bytes.
            protection: Protection bits (bit0=R, bit1=W, bit2=X).
            file_path: Mapping name as reported by the OS.
            info: Classification of the region; required for the ``scope``
                check and preferred by the ``module-exclude`` check.
        """
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
        if self._compiled_modules and self._module_excluded(file_path, info):
            return "module-exclude"
        if not self.is_full_scope and not self._kept_by_scope(protection, info):
            return "scope"
        return None
