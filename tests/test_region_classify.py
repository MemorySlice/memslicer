"""Tests for backend-independent memory region classification."""
import pytest
from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.region_classify import (
    RegionCategory,
    RegionClassifier,
    RegionInfo,
    anon_label,
    classify_name,
    region_type_for,
    region_type_for_category,
    strip_deleted,
)
from memslicer.msl.constants import OSType, RegionType

C = RegionCategory

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LIBFOO_PATH = "/home/u/app/libfoo.so"
LIBC = ModuleInfo("libc.so", LIBC_PATH, 0x7F00_0000_0000, 0x200000)
LIBFOO = ModuleInfo("libfoo.so", LIBFOO_PATH, 0x7F10_0000_0000, 0x10000)


def _range(base: int, size: int = 0x1000, path: str = "", prot: str = "rw-") -> MemoryRange:
    return MemoryRange(base, size, prot, path)


class TestStripDeleted:
    """strip_deleted removes only a trailing ' (deleted)' marker."""

    def test_removes_deleted_suffix(self):
        assert strip_deleted("/x.so (deleted)") == "/x.so"

    def test_unchanged_without_suffix(self):
        assert strip_deleted("/x.so") == "/x.so"

    def test_empty_name(self):
        assert strip_deleted("") == ""

    def test_suffix_only_at_end(self):
        assert strip_deleted("/x (deleted).so") == "/x (deleted).so"


class TestAnonLabel:
    """anon_label extracts X from [anon:X] and [anon_shmem:X]."""

    def test_anon(self):
        assert anon_label("[anon:scudo:primary]") == "scudo:primary"

    def test_anon_shmem(self):
        assert anon_label("[anon_shmem:dalvik-jit-code-cache]") == "dalvik-jit-code-cache"

    def test_heap_is_not_anon_label(self):
        assert anon_label("[heap]") is None

    def test_path_is_not_anon_label(self):
        assert anon_label("/x.so") is None


class TestClassifyName:
    """classify_name applies the pure name-only rule set."""

    @pytest.mark.parametrize("name,expected", [
        ("", C.ANON),
        # kernel pseudo mappings
        ("[vdso]", C.KERNEL),
        ("[vvar]", C.KERNEL),
        ("[vvar_vclock]", C.KERNEL),
        ("[vsyscall]", C.KERNEL),
        ("[vectors]", C.KERNEL),
        ("[sigpage]", C.KERNEL),
        ("[uprobes]", C.KERNEL),
        # process heap / stack
        ("[heap]", C.HEAP_NATIVE),
        ("[stack]", C.STACK),
        ("[stack:1234]", C.STACK),
        # native allocators
        ("[anon:libc_malloc]", C.HEAP_NATIVE),
        ("[anon:glibc: malloc arena]", C.HEAP_NATIVE),
        ("[anon:scudo:primary]", C.HEAP_NATIVE),
        ("[anon:scudo:secondary]", C.HEAP_NATIVE),
        ("[anon:GWP-ASan Guard Page]", C.HEAP_NATIVE),
        ("[anon:bionic_alloc_small_objects]", C.HEAP_NATIVE),
        ("[anon:jemalloc]", C.HEAP_NATIVE),
        # ART JIT
        ("[anon:dalvik-jit-code-cache]", C.JIT_CODE),
        ("[anon:dalvik-data-code-cache]", C.JIT_CODE),
        ("[anon_shmem:dalvik-jit-code-cache]", C.JIT_CODE),
        # ART managed heap spaces and boot images
        ("[anon:dalvik-main space]", C.HEAP_MANAGED),
        ("[anon:dalvik-main space (region space)]", C.HEAP_MANAGED),
        ("[anon:dalvik-free list large object space]", C.HEAP_MANAGED),
        ("[anon:dalvik-non moving space]", C.HEAP_MANAGED),
        ("[anon:dalvik-zygote space]", C.HEAP_MANAGED),
        ("[anon:dalvik-alloc space]", C.HEAP_MANAGED),
        ("[anon:dalvik-bump-pointer space]", C.HEAP_MANAGED),
        ("[anon:dalvik-/system/framework/boot-framework.art]", C.HEAP_MANAGED),
        ("[anon:dalvik-/system/framework/boot.art]", C.HEAP_MANAGED),
        # ART bookkeeping that is not object storage
        ("[anon:dalvik-allocation info map]", C.ANON_NAMED),
        ("[anon:dalvik-page-status map]", C.ANON_NAMED),
        ("[anon:dalvik-main space live-bitmap 0]", C.ANON_NAMED),
        ("[anon:dalvik-region space mark-bitmap]", C.ANON_NAMED),
        ("[anon:dalvik-mark stack]", C.ANON_NAMED),
        ("[anon:dalvik-live stack]", C.ANON_NAMED),
        ("[anon:dalvik-LinearAlloc]", C.ANON_NAMED),
        ("[anon:dalvik-CompilerMetadata]", C.ANON_NAMED),
        ("[anon:dalvik-indirect ref table]", C.ANON_NAMED),
        ("[anon:dalvik-card table]", C.ANON_NAMED),
        # bionic thread stacks
        ("[anon:stack_and_tls:12345]", C.STACK),
        ("[anon:thread signal stack]", C.STACK),
        ("[anon:bionic TLS]", C.STACK),
        ("[anon:thread stack guard]", C.STACK),
        # .bss and other named anon
        ("[anon:.bss]", C.BSS),
        ("[anon:linker_alloc]", C.ANON_NAMED),
        ("[anon:System property context nodes]", C.ANON_NAMED),
        # memfd / shm / ashmem
        ("/memfd:jit-cache (deleted)", C.JIT_CODE),
        ("/memfd:jit-zygote-cache (deleted)", C.JIT_CODE),
        ("/memfd:foo (deleted)", C.SHARED_MEM),
        ("/dev/shm/x", C.SHARED_MEM),
        ("/dev/zero", C.SHARED_MEM),
        ("/SYSV00000000", C.SHARED_MEM),
        ("/dev/ashmem/foo (deleted)", C.SHARED_MEM),
        ("/dev/ashmem/dalvik-main space (deleted)", C.HEAP_MANAGED),
        # devices
        ("/dev/kgsl-3d0", C.DEVICE),
        ("/dev/binder", C.DEVICE),
        ("/dmabuf:foo", C.DEVICE),
        ("anon_inode:[eventfd]", C.DEVICE),
        # executable images
        ("/usr/lib/x86_64-linux-gnu/libc.so.6", C.IMAGE),
        ("/home/u/app/libfoo.so", C.IMAGE),
        ("/x.so (deleted)", C.IMAGE),
        ("/usr/lib/libfoo.so.1.2", C.IMAGE),
        ("/usr/lib/libSystem.B.dylib", C.IMAGE),
        ("C:\\Windows\\System32\\ntdll.dll", C.IMAGE),
        ("c:/users/x/app.exe", C.IMAGE),
        ("/data/app/x/base.odex", C.IMAGE),
        ("/data/app/x/base.vdex", C.IMAGE),
        ("/system/framework/boot.oat", C.IMAGE),
        ("/data/app/x/classes.dex", C.IMAGE),
        ("/system/framework/boot-framework.art", C.IMAGE),
        # plain mapped files
        ("/data/file", C.MAPPED_FILE),
        ("/Applications/Foo.app/Contents/MacOS/Foo", C.MAPPED_FILE),
        ("/usr/share/zoneinfo/UTC", C.MAPPED_FILE),
        ("\\\\server\\share\\file.txt", C.MAPPED_FILE),
        # anything else
        ("something", C.ANON_NAMED),
        ("[foo]", C.ANON_NAMED),
    ])
    def test_classify_name(self, name, expected):
        assert classify_name(name) == expected


class TestRegionClassifierOwner:
    """Owner attribution by module address span, path and .bss adjacency."""

    @pytest.fixture
    def classifier(self):
        # unsorted on purpose: the classifier must sort by base itself
        return RegionClassifier(OSType.Linux, [LIBFOO, LIBC])

    def test_owner_inside_libc(self, classifier):
        assert classifier.owner_of(LIBC.base + 0x1000) is LIBC

    def test_owner_at_libc_base(self, classifier):
        assert classifier.owner_of(LIBC.base) is LIBC

    def test_owner_just_past_libc_end(self, classifier):
        assert classifier.owner_of(LIBC.base + LIBC.size) is None

    def test_owner_below_all_modules(self, classifier):
        assert classifier.owner_of(0x1000) is None

    def test_owner_in_gap_between_modules(self, classifier):
        assert classifier.owner_of(LIBC.base + LIBC.size + 0x10000) is None

    def test_owner_inside_libfoo(self, classifier):
        assert classifier.owner_of(LIBFOO.base + 0x100) is LIBFOO

    def test_classify_libc_text(self, classifier):
        info = classifier.classify(_range(LIBC.base + 0x1000, 0x1000, LIBC_PATH, "r-x"))
        assert info.category == C.IMAGE
        assert info.owner is LIBC
        assert info.label == LIBC_PATH
        assert info.system_owned is True
        assert info.is_file_backed is True
        assert info.is_anonymous is False

    def test_owner_falls_back_to_module_path(self, classifier):
        info = classifier.classify(_range(0x5000_0000, 0x1000, LIBFOO_PATH))
        assert info.owner is LIBFOO

    def test_bss_adjacent_to_module(self, classifier):
        info = classifier.classify(_range(LIBFOO.base + LIBFOO.size, 0x1000, "[anon:.bss]"))
        assert info.category == C.BSS
        assert info.owner is LIBFOO
        assert info.label == ".bss"

    def test_bss_without_adjacent_module(self, classifier):
        info = classifier.classify(_range(0x1234_0000, 0x1000, "[anon:.bss]"))
        assert info.category == C.BSS
        assert info.owner is None
        assert info.label == ".bss"


class TestRegionClassifierOwnership:
    """system_owned derived from per-OS path tables and overrides."""

    @pytest.mark.parametrize("os_type,path,expected", [
        (OSType.Android, "/system/lib64/libc.so", True),
        (OSType.Android, "/apex/com.android.runtime/lib64/bionic/libc.so", True),
        (OSType.Android, "/data/app/~~x/com.foo/lib/arm64/libfoo.so", False),
        (OSType.Android, "/data/dalvik-cache/arm64/boot.oat", True),
        (OSType.Linux, LIBC_PATH, True),
        (OSType.Linux, LIBFOO_PATH, False),
        (OSType.macOS, "/usr/lib/libSystem.B.dylib", True),
        (OSType.macOS, "/System/Library/Frameworks/Foundation.framework/Foundation", True),
        (OSType.macOS, "/Applications/Foo.app/Contents/MacOS/Foo", False),
        (OSType.iOS, "/usr/lib/libSystem.B.dylib", True),
        (OSType.iOS, "/private/var/containers/Bundle/Application/X/Foo.app/Foo", False),
        (OSType.Windows, "C:\\Windows\\System32\\ntdll.dll", True),
        (OSType.Windows, "c:/windows/system32/kernel32.dll", True),
        (OSType.Windows, "D:\\Windows\\System32\\x.dll", True),
        (OSType.Windows, "c:/users/x/app.exe", False),
    ])
    def test_system_owned(self, os_type, path, expected):
        classifier = RegionClassifier(os_type, [])
        info = classifier.classify(_range(0x1000_0000, 0x1000, path, "r--"))
        assert info.system_owned is expected
        assert classifier.is_system_path(path) is expected

    def test_is_system_path_direct(self):
        linux = RegionClassifier(OSType.Linux, [])
        assert linux.is_system_path("/usr/lib/libz.so.1") is True
        assert linux.is_system_path("/opt/app/libz.so.1") is False
        windows = RegionClassifier(OSType.Windows, [])
        assert windows.is_system_path("c:/WINDOWS/system32/user32.dll") is True
        assert windows.is_system_path("C:\\Program Files\\Foo\\foo.dll") is False

    def test_app_paths_override_system_prefix(self):
        classifier = RegionClassifier(OSType.Android, [], app_paths=["/system/app/Foo/"])
        app_lib = classifier.classify(_range(0x1000, 0x1000, "/system/app/Foo/lib/libfoo.so"))
        libc = classifier.classify(_range(0x2000, 0x1000, "/system/lib64/libc.so"))
        assert app_lib.system_owned is False
        assert libc.system_owned is True

    def test_exe_path_linux_is_image_and_app_owned(self):
        classifier = RegionClassifier(OSType.Linux, [], exe_path="/usr/bin/target")
        info = classifier.classify(_range(0x40_0000, 0x1000, "/usr/bin/target", "r-x"))
        assert info.category == C.IMAGE
        assert info.system_owned is False

    def test_exe_path_macos_bundle_binary(self):
        exe = "/Applications/Foo.app/Contents/MacOS/Foo"
        classifier = RegionClassifier(OSType.macOS, [], exe_path=exe)
        info = classifier.classify(_range(0x1_0000_0000, 0x4000, exe, "r-x"))
        assert info.category == C.IMAGE
        assert info.system_owned is False

    def test_macos_bundle_binary_without_exe_path_is_mapped_file(self):
        exe = "/Applications/Foo.app/Contents/MacOS/Foo"
        classifier = RegionClassifier(OSType.macOS, [])
        info = classifier.classify(_range(0x1_0000_0000, 0x4000, exe, "r-x"))
        assert info.category == C.MAPPED_FILE

    def test_suffixless_module_path_is_image(self):
        path = "/System/Library/Frameworks/Foundation.framework/Foundation"
        foundation = ModuleInfo("Foundation", path, 0x1000, 0x1000)
        classifier = RegionClassifier(OSType.macOS, [foundation])
        info = classifier.classify(_range(0x9000_0000, 0x1000, path, "r-x"))
        assert info.category == C.IMAGE
        assert info.owner is foundation
        assert info.system_owned is True


class TestRegionClassifierStackPointers:
    """Stack-pointer detection, display labels and is_anonymous."""

    SP = 0x7FFD_1C01_0000

    @pytest.fixture
    def classifier(self):
        return RegionClassifier(OSType.Linux, [], stack_pointers=[self.SP])

    def test_unnamed_region_containing_sp_is_stack(self, classifier):
        info = classifier.classify(_range(0x7FFD_1C00_0000, 0x21000))
        assert info.category == C.STACK

    def test_unnamed_region_without_sp_is_anon(self, classifier):
        info = classifier.classify(_range(0x7FFD_0000_0000, 0x1000))
        assert info.category == C.ANON

    def test_named_anon_containing_sp_is_stack(self, classifier):
        info = classifier.classify(_range(0x7FFD_1C00_0000, 0x21000, "[anon:foo]"))
        assert info.category == C.STACK

    def test_named_anon_without_sp_keeps_label(self, classifier):
        info = classifier.classify(_range(0x7FFD_0000_0000, 0x1000, "[anon:foo]"))
        assert info.category == C.ANON_NAMED
        assert info.label == "foo"

    def test_sp_at_region_end_is_exclusive(self, classifier):
        info = classifier.classify(_range(self.SP - 0x1000, 0x1000))
        assert info.category == C.ANON

    def test_heap_containing_sp_stays_heap(self, classifier):
        info = classifier.classify(_range(0x7FFD_1C00_0000, 0x21000, "[heap]"))
        assert info.category == C.HEAP_NATIVE

    @pytest.mark.parametrize("name,label", [
        ("[anon:scudo:primary]", "scudo:primary"),
        ("[heap]", "[heap]"),
        ("", ""),
        ("/dev/kgsl-3d0", "/dev/kgsl-3d0"),
        ("/x.so (deleted)", "/x.so"),
    ])
    def test_labels(self, classifier, name, label):
        info = classifier.classify(_range(0x1000_0000, 0x1000, name))
        assert info.label == label

    @pytest.mark.parametrize("category", [
        C.ANON, C.ANON_NAMED, C.HEAP_NATIVE, C.HEAP_MANAGED,
        C.STACK, C.BSS, C.JIT_CODE, C.SHARED_MEM,
    ])
    def test_is_anonymous_true(self, category):
        assert RegionInfo(category, None, "", False).is_anonymous is True

    @pytest.mark.parametrize("category", [C.DEVICE, C.KERNEL, C.IMAGE, C.MAPPED_FILE])
    def test_is_anonymous_false(self, category):
        assert RegionInfo(category, None, "", False).is_anonymous is False


class TestRegionTypeFor:
    """Mapping of RegionCategory onto the coarse MSL RegionType."""

    @pytest.mark.parametrize("category,expected", [
        (C.HEAP_NATIVE, RegionType.Heap),
        (C.HEAP_MANAGED, RegionType.Heap),
        (C.STACK, RegionType.Stack),
        (C.IMAGE, RegionType.Image),
        (C.MAPPED_FILE, RegionType.MappedFile),
        (C.ANON, RegionType.Anon),
        (C.ANON_NAMED, RegionType.Anon),
        (C.BSS, RegionType.Anon),
        (C.JIT_CODE, RegionType.Anon),
        (C.SHARED_MEM, RegionType.SharedMem),
        (C.DEVICE, RegionType.Other),
        (C.KERNEL, RegionType.Other),
    ])
    def test_region_type(self, category, expected):
        assert region_type_for_category(category) == expected
        assert region_type_for(RegionInfo(category, None, "", False)) == expected

    def test_every_category_is_mapped(self):
        for category in RegionCategory:
            assert isinstance(region_type_for_category(category), RegionType)
