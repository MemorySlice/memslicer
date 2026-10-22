"""Backend-independent classification of memory regions.

The debugger backends (Frida, GDB, LLDB, ``/proc/<pid>/maps``) all report a
region as a :class:`~memslicer.acquirer.bridge.MemoryRange` whose
``file_path`` is whatever name the OS attached to the mapping.  That name
is the only portable signal we have, so this module turns it into a
:class:`RegionCategory` using nothing but string rules plus, optionally,
the module list and thread stack pointers of the target.

Two entry points exist:

* :func:`classify_name` -- the pure, name-only rule set.  It needs no
  target state and is what :func:`memslicer.acquirer.engine.classify_region`
  builds on.
* :class:`RegionClassifier` -- wraps :func:`classify_name` and adds owner
  attribution, system/app ownership and stack-pointer detection.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.msl.constants import OSType, RegionType


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


class RegionCategory(Enum):
    """Fine-grained kind of a memory region, derived from its name."""

    ANON = auto()
    ANON_NAMED = auto()
    HEAP_NATIVE = auto()
    HEAP_MANAGED = auto()
    JIT_CODE = auto()
    STACK = auto()
    BSS = auto()
    IMAGE = auto()
    MAPPED_FILE = auto()
    SHARED_MEM = auto()
    DEVICE = auto()
    KERNEL = auto()


@dataclass(frozen=True)
class RegionInfo:
    """Result of classifying one :class:`MemoryRange`.

    Attributes:
        category: The :class:`RegionCategory` the region falls into.
        owner: The module that owns the region, if one could be attributed.
        label: The backing file path without a ``" (deleted)"`` suffix, the
            stripped anonymous label (``"scudo:primary"`` for
            ``"[anon:scudo:primary]"``), or ``""`` for an unnamed region.
        system_owned: True when the backing file lives in an OS-owned
            location (``/system/``, ``/usr/lib/``, ``C:\\Windows\\`` ...).
    """

    category: RegionCategory
    owner: ModuleInfo | None
    label: str
    system_owned: bool

    @property
    def is_file_backed(self) -> bool:
        """True for regions backed by a file on disk (image or mapped file)."""
        return self.category in (RegionCategory.IMAGE, RegionCategory.MAPPED_FILE)

    @property
    def is_anonymous(self) -> bool:
        """True for regions that are neither file-backed nor device/kernel."""
        return not self.is_file_backed and self.category not in (
            RegionCategory.DEVICE, RegionCategory.KERNEL,
        )


# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------

_DELETED_SUFFIX = " (deleted)"

_ANON_LABEL = re.compile(r"^\[anon(?:_shmem)?:(.*)\]$")

_KERNEL_NAMES = frozenset({
    "[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]", "[vectors]",
    "[sigpage]", "[uprobes]",
})

_STACK_NAME = re.compile(r"^\[stack(?::\d+)?\]$")

_NATIVE_HEAP_PREFIXES = ("scudo:", "GWP-ASan", "bionic_alloc", "jemalloc")

_STACK_LABEL_PREFIXES = (
    "stack_and_tls:", "thread signal stack", "bionic TLS", "thread stack",
)

_DALVIK_JIT_MARKERS = ("jit-code-cache", "data-code-cache")

_DALVIK_NON_HEAP = re.compile(r"bitmap|\bmap\b|\b(?:live|mark) stack\b")

_DALVIK_IMAGE = re.compile(r"^dalvik-/.*\.art$")

_JIT_MEMFD_PREFIXES = ("/memfd:jit-cache", "/memfd:jit-zygote-cache")

_SHARED_MEM_PREFIXES = ("/memfd:", "/dev/shm/", "/SYSV", "/dev/ashmem/")

_ASHMEM_DALVIK_SPACE = re.compile(r"^/dev/ashmem/dalvik-.* space")

_DEVICE_PREFIXES = ("/dev/", "/dmabuf", "anon_inode:")

_IMAGE_SUFFIX = re.compile(
    r"(?:\.so(?:\.\d+)*|\.dylib|\.dll|\.exe|\.oat|\.odex|\.vdex|\.dex|\.art)$",
    re.IGNORECASE,
)

_WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def strip_deleted(name: str) -> str:
    """Remove a trailing ``" (deleted)"`` marker from a mapping name.

    Args:
        name: Raw mapping name as reported by the OS.

    Returns:
        The name without the deleted suffix; unchanged if none is present.
    """
    if name.endswith(_DELETED_SUFFIX):
        return name[: -len(_DELETED_SUFFIX)]
    return name


def anon_label(name: str) -> str | None:
    """Extract ``X`` from ``"[anon:X]"`` or ``"[anon_shmem:X]"``.

    Args:
        name: Mapping name, already passed through :func:`strip_deleted`.

    Returns:
        The label text, or ``None`` if *name* is not an anonymous label.
    """
    match = _ANON_LABEL.match(name)
    return match.group(1) if match else None


def is_real_path(name: str) -> bool:
    """True when *name* looks like a filesystem path rather than a pseudo name.

    Accepts POSIX absolute paths, Windows drive paths (``C:\\`` / ``c:/``)
    and UNC paths (``\\\\server\\share``).

    Args:
        name: Mapping name, already passed through :func:`strip_deleted`.
    """
    return (
        name.startswith("/")
        or name.startswith("\\\\")
        or bool(_WINDOWS_DRIVE_PATH.match(name))
    )


def path_basename(path: str) -> str:
    """Return the last component of a POSIX or Windows path."""
    return re.split(r"[\\/]", path)[-1]


# ---------------------------------------------------------------------------
# Name-only classification
# ---------------------------------------------------------------------------


def _classify_dalvik(label: str) -> RegionCategory:
    """Classify an ART/Dalvik anonymous label (``dalvik-...``)."""
    if any(marker in label for marker in _DALVIK_JIT_MARKERS):
        return RegionCategory.JIT_CODE
    if " space" in label and not _DALVIK_NON_HEAP.search(label):
        return RegionCategory.HEAP_MANAGED
    if _DALVIK_IMAGE.match(label):
        return RegionCategory.HEAP_MANAGED
    return RegionCategory.ANON_NAMED


def _classify_anon_label(label: str) -> RegionCategory:
    """Classify the ``X`` of an ``[anon:X]`` / ``[anon_shmem:X]`` mapping."""
    if "malloc" in label or label.startswith(_NATIVE_HEAP_PREFIXES):
        return RegionCategory.HEAP_NATIVE
    if label.startswith("dalvik-"):
        return _classify_dalvik(label)
    if label.startswith(_STACK_LABEL_PREFIXES):
        return RegionCategory.STACK
    if label == ".bss":
        return RegionCategory.BSS
    return RegionCategory.ANON_NAMED


def _classify_pseudo_path(name: str) -> RegionCategory | None:
    """Classify memfd/ashmem/device pseudo paths, or None if *name* is none."""
    if name.startswith(_JIT_MEMFD_PREFIXES):
        return RegionCategory.JIT_CODE
    if _ASHMEM_DALVIK_SPACE.match(name):
        return RegionCategory.HEAP_MANAGED
    if name == "/dev/zero" or name.startswith(_SHARED_MEM_PREFIXES):
        return RegionCategory.SHARED_MEM
    if name.startswith(_DEVICE_PREFIXES):
        return RegionCategory.DEVICE
    return None


def _classify_real_path(name: str) -> RegionCategory:
    """Classify a filesystem path as IMAGE or MAPPED_FILE by its suffix."""
    if _IMAGE_SUFFIX.search(name):
        return RegionCategory.IMAGE
    return RegionCategory.MAPPED_FILE


def classify_name(file_path: str) -> RegionCategory:
    """Classify a mapping purely by its name.

    This is the backend-independent rule set shared by
    :class:`RegionClassifier` and
    :func:`memslicer.acquirer.engine.classify_region`.  It knows nothing
    about modules or threads, so stack-pointer detection and owner
    attribution are left to the classifier.

    Args:
        file_path: Raw mapping name (a ``" (deleted)"`` suffix is tolerated).

    Returns:
        The :class:`RegionCategory` the name implies.
    """
    name = strip_deleted(file_path)
    if not name:
        return RegionCategory.ANON
    if name in _KERNEL_NAMES:
        return RegionCategory.KERNEL
    if name == "[heap]":
        return RegionCategory.HEAP_NATIVE
    if _STACK_NAME.match(name):
        return RegionCategory.STACK
    label = anon_label(name)
    if label is not None:
        return _classify_anon_label(label)
    pseudo = _classify_pseudo_path(name)
    if pseudo is not None:
        return pseudo
    if is_real_path(name):
        return _classify_real_path(name)
    return RegionCategory.ANON_NAMED


# ---------------------------------------------------------------------------
# System path tables
# ---------------------------------------------------------------------------

_SYSTEM_PREFIXES: dict[OSType, tuple[str, ...]] = {
    OSType.Android: (
        "/system/", "/system_ext/", "/apex/", "/vendor/", "/odm/",
        "/product/", "/oem/", "/data/dalvik-cache/",
    ),
    OSType.Linux: (
        "/lib/", "/lib64/", "/lib32/", "/usr/lib/", "/usr/lib64/",
        "/usr/lib32/", "/usr/libexec/", "/usr/share/", "/usr/bin/",
        "/usr/sbin/", "/bin/", "/sbin/", "/etc/",
    ),
    OSType.macOS: (
        "/usr/lib/", "/usr/libexec/", "/usr/share/", "/System/",
        "/Library/Apple/", "/private/preboot/Cryptexes/",
        "/System/Cryptexes/", "/private/var/db/dyld/", "/usr/bin/",
        "/usr/sbin/",
    ),
    OSType.iOS: (
        "/usr/lib/", "/usr/libexec/", "/System/",
        "/private/preboot/Cryptexes/", "/usr/bin/", "/Developer/",
    ),
}

_WINDOWS_SYSTEM_PATH = re.compile(r"^[a-z]:\\windows\\")


def _normalize_windows_path(path: str) -> str:
    """Lower-case a Windows path and fold ``/`` separators into ``\\``."""
    return path.replace("/", "\\").lower()


# ---------------------------------------------------------------------------
# Context-aware classifier
# ---------------------------------------------------------------------------


class RegionClassifier:
    """Classify memory ranges using the target's module list and stacks.

    Builds on :func:`classify_name` and adds:

    * owner attribution by module address span (and ``.bss`` adjacency),
    * system-vs-app ownership from per-OS path tables,
    * stack detection for unnamed regions that contain a thread's stack
      pointer.

    Args:
        os_type: OS of the target; selects the system path table.
        modules: Loaded modules used for owner attribution.
        exe_path: Path of the main executable; never counted as system-owned
            and recognised as an image even without a known suffix.
        app_paths: Path prefixes whose files are always app-owned, even when
            they sit under a system prefix.
        stack_pointers: Current stack pointer of every thread; a region
            containing one of them is a stack.
    """

    def __init__(
        self,
        os_type: OSType,
        modules: Sequence[ModuleInfo],
        *,
        exe_path: str = "",
        app_paths: Sequence[str] = (),
        stack_pointers: Sequence[int] = (),
    ) -> None:
        self._os_type = os_type
        self._modules = sorted(modules, key=lambda m: m.base)
        self._module_bases = [m.base for m in self._modules]
        self._modules_by_end = {m.base + m.size: m for m in self._modules}
        self._modules_by_path = {m.path: m for m in self._modules}
        self._exe_path = exe_path
        self._exe_basename = path_basename(exe_path) if exe_path else ""
        self._app_paths = tuple(app_paths)
        self._stack_pointers = tuple(stack_pointers)

    # -- public API ---------------------------------------------------------

    def classify(self, r: MemoryRange) -> RegionInfo:
        """Classify *r* into a :class:`RegionInfo`.

        Args:
            r: The memory range to classify.
        """
        name = strip_deleted(r.file_path)
        category = classify_name(name)
        if category in (RegionCategory.ANON, RegionCategory.ANON_NAMED):
            if self._contains_stack_pointer(r):
                category = RegionCategory.STACK
        if category == RegionCategory.BSS:
            return RegionInfo(category, self._adjacent_module(r.base), ".bss", False)
        if category in (RegionCategory.IMAGE, RegionCategory.MAPPED_FILE):
            return self._classify_file_backed(r, name, category)
        return RegionInfo(category, None, _label_for(name), False)

    def owner_of(self, base: int) -> ModuleInfo | None:
        """Return the module whose address span contains *base*, if any.

        Args:
            base: Address to look up.
        """
        index = bisect_right(self._module_bases, base) - 1
        if index < 0:
            return None
        module = self._modules[index]
        if module.base <= base < module.base + module.size:
            return module
        return None

    def is_system_path(self, path: str) -> bool:
        """True when *path* lies in an OS-owned location for this target's OS.

        Windows paths are compared case-insensitively with either separator
        and any drive letter.  Paths on OSes without a table, and paths that
        match no prefix, are considered app-owned.

        Args:
            path: Backing file path, without a ``" (deleted)"`` suffix.
        """
        if self._os_type == OSType.Windows:
            return bool(_WINDOWS_SYSTEM_PATH.match(_normalize_windows_path(path)))
        prefixes = _SYSTEM_PREFIXES.get(self._os_type, ())
        return path.startswith(prefixes)

    # -- internals ----------------------------------------------------------

    def _classify_file_backed(
        self, r: MemoryRange, path: str, category: RegionCategory,
    ) -> RegionInfo:
        """Build the :class:`RegionInfo` for an image or mapped file."""
        if category == RegionCategory.MAPPED_FILE and self._is_executable(path):
            category = RegionCategory.IMAGE
        owner = self.owner_of(r.base) or self._modules_by_path.get(path)
        return RegionInfo(category, owner, path, self._is_system_owned(path))

    def _is_executable(self, path: str) -> bool:
        """True when *path* is the main executable or a known module path."""
        if self._exe_basename and path_basename(path) == self._exe_basename:
            return True
        return path in self._modules_by_path

    def _is_system_owned(self, path: str) -> bool:
        """Apply app-path and exe overrides on top of :meth:`is_system_path`."""
        if path == self._exe_path or path.startswith(self._app_paths):
            return False
        return self.is_system_path(path)

    def _contains_stack_pointer(self, r: MemoryRange) -> bool:
        """True when any known stack pointer lies within *r*."""
        end = r.base + r.size
        return any(r.base <= sp < end for sp in self._stack_pointers)

    def _adjacent_module(self, base: int) -> ModuleInfo | None:
        """Return the module that ends exactly at *base* (``.bss`` owner)."""
        return self._modules_by_end.get(base)


def _label_for(name: str) -> str:
    """Return the display label for a non-file-backed mapping name."""
    label = anon_label(name)
    return label if label is not None else name


# ---------------------------------------------------------------------------
# Mapping onto the MSL on-disk RegionType
# ---------------------------------------------------------------------------

_REGION_TYPE_BY_CATEGORY: dict[RegionCategory, RegionType] = {
    RegionCategory.HEAP_NATIVE: RegionType.Heap,
    RegionCategory.HEAP_MANAGED: RegionType.Heap,
    RegionCategory.STACK: RegionType.Stack,
    RegionCategory.IMAGE: RegionType.Image,
    RegionCategory.MAPPED_FILE: RegionType.MappedFile,
    RegionCategory.ANON: RegionType.Anon,
    RegionCategory.ANON_NAMED: RegionType.Anon,
    RegionCategory.BSS: RegionType.Anon,
    RegionCategory.JIT_CODE: RegionType.Anon,
    RegionCategory.SHARED_MEM: RegionType.SharedMem,
    RegionCategory.DEVICE: RegionType.Other,
    RegionCategory.KERNEL: RegionType.Other,
}


def region_type_for_category(category: RegionCategory) -> RegionType:
    """Map a :class:`RegionCategory` onto the coarse MSL :class:`RegionType`."""
    return _REGION_TYPE_BY_CATEGORY[category]


def region_type_for(info: RegionInfo) -> RegionType:
    """Map a classified region onto the coarse MSL :class:`RegionType`.

    Args:
        info: Result of :meth:`RegionClassifier.classify`.
    """
    return region_type_for_category(info.category)
