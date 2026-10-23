"""Tests for region filtering."""
import re
import sys

import pytest

from memslicer.acquirer import region_filter as region_filter_module
from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.region_classify import RegionClassifier
from memslicer.acquirer.region_filter import (
    FULL_SCOPE,
    KERNEL_PSEUDO_NAMES,
    MODULE_PATTERN_FLAGS,
    SCOPE_ALIASES,
    SCOPE_TOKENS,
    SKIP_REASON_LABELS,
    RegionFilter,
    is_kernel_pseudo_region,
    parse_scope,
    scope_label,
    skip_label,
)
from memslicer.msl.constants import OSType


class TestRegionFilter:
    def test_empty_filter_matches_all(self):
        f = RegionFilter()
        assert f.matches(0x1000, 0x1000, 0x07, "/some/path")

    def test_prot_filter_pass(self):
        f = RegionFilter(min_prot=1)  # require readable
        assert f.matches(0x1000, 0x1000, 0x05, "")  # r-x

    def test_prot_filter_fail(self):
        f = RegionFilter(min_prot=1)  # require readable
        assert not f.matches(0x1000, 0x1000, 0x00, "")  # ---

    def test_addr_range_pass(self):
        f = RegionFilter(addr_ranges=[(0x1000, 0x3000)])
        assert f.matches(0x2000, 0x1000, 0x07, "")

    def test_addr_range_fail(self):
        f = RegionFilter(addr_ranges=[(0x1000, 0x2000)])
        assert not f.matches(0x5000, 0x1000, 0x07, "")

    def test_addr_range_overlap(self):
        f = RegionFilter(addr_ranges=[(0x1000, 0x2000)])
        assert f.matches(0x1500, 0x1000, 0x07, "")  # overlaps

    def test_include_path_pass(self):
        f = RegionFilter(include_paths=[r"libc\.so"])
        assert f.matches(0x1000, 0x1000, 0x07, "/usr/lib/libc.so.6")

    def test_include_path_fail(self):
        f = RegionFilter(include_paths=[r"libc\.so"])
        assert not f.matches(0x1000, 0x1000, 0x07, "/usr/lib/libm.so")

    def test_include_path_no_path(self):
        f = RegionFilter(include_paths=[r"libc\.so"])
        assert not f.matches(0x1000, 0x1000, 0x07, "")

    def test_exclude_path(self):
        f = RegionFilter(exclude_paths=[r"\.so$"])
        assert not f.matches(0x1000, 0x1000, 0x07, "/lib/libfoo.so")

    def test_exclude_path_no_match(self):
        f = RegionFilter(exclude_paths=[r"\.so$"])
        assert f.matches(0x1000, 0x1000, 0x07, "/lib/libfoo.dylib")

    def test_combined_filters(self):
        f = RegionFilter(
            addr_ranges=[(0x1000, 0x5000)],
            min_prot=1,
            exclude_paths=[r"\[vdso\]"],
        )
        assert f.matches(0x2000, 0x1000, 0x05, "/lib/foo.so")
        assert not f.matches(0x2000, 0x1000, 0x00, "/lib/foo.so")  # no read
        assert not f.matches(0x8000, 0x1000, 0x05, "/lib/foo.so")  # out of range
        assert not f.matches(0x2000, 0x1000, 0x05, "[vdso]")  # excluded

    def test_skip_no_read_default(self):
        f = RegionFilter()
        assert not f.matches(0x1000, 0x1000, 0x00, "")  # --- has no read bit

    def test_skip_no_read_allows_readable(self):
        f = RegionFilter()
        assert f.matches(0x1000, 0x1000, 0x01, "")  # r-- has read bit

    def test_skip_no_read_disabled(self):
        f = RegionFilter(skip_no_read=False)
        assert f.matches(0x1000, 0x1000, 0x00, "")  # --- allowed when skip disabled

    def test_max_region_size_filters_large(self):
        f = RegionFilter(max_region_size=1048576)
        assert not f.matches(0x1000, 2 * 1048576, 0x07, "")  # too large

    def test_max_region_size_allows_small(self):
        f = RegionFilter(max_region_size=1048576)
        assert f.matches(0x1000, 4096, 0x07, "")  # within limit

    def test_max_region_size_zero_no_limit(self):
        f = RegionFilter(max_region_size=0)
        assert f.matches(0x1000, 0xFFFFFFFF, 0x07, "")  # any size allowed

    def test_skip_reason_no_read(self):
        f = RegionFilter()
        assert f.skip_reason(0x1000, 0x1000, 0x00, "") == "no-read"

    def test_skip_reason_max_size(self):
        f = RegionFilter(max_region_size=4096)
        assert f.skip_reason(0x1000, 8192, 0x07, "") == "max-size"

    def test_skip_reason_min_prot(self):
        f = RegionFilter(min_prot=3, skip_no_read=False)  # require rw
        assert f.skip_reason(0x1000, 0x1000, 0x01, "") == "min-prot"

    def test_skip_reason_addr_range(self):
        f = RegionFilter(addr_ranges=[(0x1000, 0x2000)])
        assert f.skip_reason(0x5000, 0x1000, 0x07, "") == "addr-range"

    def test_skip_reason_path_include(self):
        f = RegionFilter(include_paths=[r"libc\.so"])
        assert f.skip_reason(0x1000, 0x1000, 0x07, "/lib/libm.so") == "path-include"

    def test_skip_reason_path_exclude(self):
        f = RegionFilter(exclude_paths=[r"\.so$"])
        assert f.skip_reason(0x1000, 0x1000, 0x07, "/lib/libfoo.so") == "path-exclude"

    def test_skip_reason_none_when_passes(self):
        f = RegionFilter()
        assert f.skip_reason(0x1000, 0x1000, 0x07, "/some/path") is None


class TestKernelPseudoRegions:
    """Tests for kernel pseudo-mapping detection and the opt-in skip."""

    @pytest.mark.parametrize("name", ["[vvar]", "[vvar_vclock]", "[vsyscall]"])
    def test_known_pseudo_names_detected(self, name):
        assert is_kernel_pseudo_region(name) is True

    def test_vdso_is_not_pseudo(self):
        """[vdso] is genuinely readable and forensically relevant — it must
        never be classified as an unreadable kernel pseudo-mapping."""
        assert is_kernel_pseudo_region("[vdso]") is False
        assert "[vdso]" not in KERNEL_PSEUDO_NAMES

    @pytest.mark.parametrize(
        "name",
        ["[heap]", "[stack]", "", "/usr/lib/libc.so.6"],
    )
    def test_ordinary_names_are_not_pseudo(self, name):
        assert is_kernel_pseudo_region(name) is False

    @pytest.mark.parametrize(
        "name",
        ["  [vvar]", "[vvar]  ", "\t[vvar_vclock]\n", " [vsyscall] "],
    )
    def test_surrounding_whitespace_tolerated(self, name):
        assert is_kernel_pseudo_region(name) is True

    def test_default_filter_does_not_skip_pseudo(self):
        """Off by default: the acquirer still attempts the read and records
        the kernel's answer."""
        f = RegionFilter()
        assert f.skip_reason(0x1000, 0x1000, 0x01, "[vvar]") is None
        assert f.matches(0x1000, 0x1000, 0x01, "[vvar]")

    def test_skip_kernel_pseudo_reports_reason(self):
        f = RegionFilter(skip_kernel_pseudo=True)
        assert f.skip_reason(0x1000, 0x1000, 0x01, "[vvar]") == "kernel-pseudo"
        assert not f.matches(0x1000, 0x1000, 0x01, "[vvar]")

    def test_skip_kernel_pseudo_leaves_vdso_alone(self):
        f = RegionFilter(skip_kernel_pseudo=True)
        assert f.skip_reason(0x1000, 0x1000, 0x01, "[vdso]") is None

    def test_skip_kernel_pseudo_leaves_ordinary_regions_alone(self):
        f = RegionFilter(skip_kernel_pseudo=True)
        assert f.skip_reason(0x1000, 0x1000, 0x07, "/lib/libc.so.6") is None

    def test_no_read_still_wins_over_kernel_pseudo(self):
        """An unreadable pseudo-mapping is reported as no-read, matching the
        ordering of the checks in skip_reason."""
        f = RegionFilter(skip_kernel_pseudo=True)
        assert f.skip_reason(0x1000, 0x1000, 0x00, "[vvar]") == "no-read"

    def test_label_registered(self):
        assert "kernel-pseudo" in SKIP_REASON_LABELS
        assert SKIP_REASON_LABELS["kernel-pseudo"]


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------


class TestParseScope:
    @pytest.mark.parametrize("token", SCOPE_TOKENS)
    def test_single_token(self, token):
        assert parse_scope(token) == frozenset({token})

    def test_multiple_tokens(self):
        assert parse_scope("heap,stack") == frozenset({"heap", "stack"})

    def test_alias_expands(self):
        assert parse_scope("heapstack") == frozenset({"heap", "stack"})
        assert SCOPE_ALIASES["heapstack"] == ("heap", "stack")

    def test_whitespace_and_case_tolerated(self):
        assert parse_scope("  Heap , STACK\t") == frozenset({"heap", "stack"})

    def test_empty_items_ignored(self):
        assert parse_scope("heap,,stack,") == frozenset({"heap", "stack"})

    @pytest.mark.parametrize("text", ["", "   ", ","])
    def test_empty_is_full(self, text):
        assert parse_scope(text) == FULL_SCOPE == frozenset({"full"})

    def test_duplicate_tokens_collapse(self):
        assert parse_scope("heap,heap,heapstack") == frozenset({"heap", "stack"})

    def test_unknown_token_message(self):
        with pytest.raises(ValueError) as excinfo:
            parse_scope("heap,bogus")
        assert str(excinfo.value) == (
            "unknown scope token 'bogus' "
            "(expected one of: full, app, heap, stack, heapstack)"
        )

    def test_full_combined_rejected(self):
        with pytest.raises(ValueError, match="full"):
            parse_scope("full,heap")

    def test_full_repeated_is_fine(self):
        assert parse_scope("full,full") == FULL_SCOPE


class TestScopeLabel:
    def test_canonical_order(self):
        assert scope_label(frozenset({"stack", "heap"})) == "heap,stack"

    def test_single(self):
        assert scope_label(frozenset({"app"})) == "app"

    def test_full(self):
        assert scope_label(FULL_SCOPE) == "full"


class TestSkipLabel:
    def test_new_labels_registered(self):
        assert SKIP_REASON_LABELS["module-exclude"] == "module matched --exclude-module"
        assert SKIP_REASON_LABELS["scope"] == "outside selected --scope"

    def test_scope_label_appends_scope(self):
        assert skip_label("scope", frozenset({"stack", "heap"})) == (
            "outside selected --scope (heap,stack)"
        )

    def test_scope_label_without_scope(self):
        assert skip_label("scope") == "outside selected --scope"

    def test_other_reasons_unchanged_by_scope(self):
        assert skip_label("no-read", frozenset({"heap"})) == SKIP_REASON_LABELS["no-read"]

    def test_unknown_reason_passes_through(self):
        assert skip_label("mystery") == "mystery"


# ---------------------------------------------------------------------------
# Shared fixtures for classifier-backed tests
# ---------------------------------------------------------------------------

_LIBART = "/apex/com.android.art/lib64/libart.so"
_LIBFOO = "/data/app/~~x==/com.foo-y==/lib/arm64/libfoo.so"
_LIBART_BASE, _LIBART_SIZE = 0x7000_0000_0000, 0x400000
_LIBFOO_BASE, _LIBFOO_SIZE = 0x7100_0000_0000, 0x100000
_STACK_SP = 0x7F00_0000_0800

_MODULES = [
    ModuleInfo("libart.so", _LIBART, _LIBART_BASE, _LIBART_SIZE),
    ModuleInfo("libfoo.so", _LIBFOO, _LIBFOO_BASE, _LIBFOO_SIZE),
]

R, RW, RX = 0x1, 0x3, 0x5


def _classifier(**kwargs):
    return RegionClassifier(OSType.Android, _MODULES, **kwargs)


def _info(name, base=0x7FFF_0000_0000, classifier=None):
    """Classify a realistic Android range into a RegionInfo."""
    return (classifier or _classifier()).classify(MemoryRange(base, 0x1000, "rw-", name))


def _reason(f, prot, name, base=0x7FFF_0000_0000, classifier=None):
    return f.skip_reason(base, 0x1000, prot, name, info=_info(name, base, classifier))


# ---------------------------------------------------------------------------
# --exclude-module
# ---------------------------------------------------------------------------


class TestExcludeModules:
    def test_default_excludes_nothing(self):
        f = RegionFilter()
        assert _reason(f, RX, "/system/lib64/libhwui.so") is None

    def test_basename_glob(self):
        f = RegionFilter(exclude_modules=["libhwui*"])
        assert _reason(f, RX, "/system/lib64/libhwui.so") == "module-exclude"
        assert _reason(f, RX, "/system/lib64/libc.so") is None

    def test_basename_glob_must_fullmatch(self):
        f = RegionFilter(exclude_modules=["libhwui"])
        assert _reason(f, RX, "/system/lib64/libhwui.so") is None

    def test_full_path_glob(self):
        f = RegionFilter(exclude_modules=["/apex/*"])
        assert _reason(f, RX, _LIBART) == "module-exclude"
        assert _reason(f, RX, "/system/lib64/libc.so") is None

    def test_glob_without_separator_ignores_full_path(self):
        f = RegionFilter(exclude_modules=["apex*"])
        assert _reason(f, RX, _LIBART) is None

    def test_owner_name_match_for_attributed_region(self):
        """A .bss region adjacent to libfoo.so is owned by it."""
        f = RegionFilter(exclude_modules=["libfoo.so"])
        bss_base = _LIBFOO_BASE + _LIBFOO_SIZE
        assert _info("[anon:.bss]", bss_base).owner.name == "libfoo.so"
        assert _reason(f, RW, "[anon:.bss]", bss_base) == "module-exclude"

    def test_owner_path_glob_for_attributed_region(self):
        f = RegionFilter(exclude_modules=["/data/app/*"])
        bss_base = _LIBFOO_BASE + _LIBFOO_SIZE
        assert _reason(f, RW, "[anon:.bss]", bss_base) == "module-exclude"

    def test_unattributed_bss_not_excluded(self):
        f = RegionFilter(exclude_modules=["libfoo.so"])
        assert _reason(f, RW, "[anon:.bss]") is None

    def test_anon_label_match(self):
        f = RegionFilter(exclude_modules=["dalvik-LinearAlloc"])
        assert _reason(f, RW, "[anon:dalvik-LinearAlloc]") == "module-exclude"
        assert _reason(f, RW, "[anon:dalvik-main space]") is None

    def test_anon_label_glob(self):
        f = RegionFilter(exclude_modules=["dalvik-*"])
        assert _reason(f, RW, "[anon:dalvik-LinearAlloc]") == "module-exclude"

    def test_deleted_suffix_ignored(self):
        f = RegionFilter(exclude_modules=["libhwui.so"])
        assert _reason(f, RX, "/system/lib64/libhwui.so (deleted)") == "module-exclude"

    def test_fallback_without_info_basename(self):
        f = RegionFilter(exclude_modules=["libhwui*"])
        assert f.skip_reason(0x1000, 0x1000, RX, "/system/lib64/libhwui.so") == "module-exclude"
        assert f.skip_reason(0x1000, 0x1000, RX, "/system/lib64/libc.so") is None

    def test_fallback_without_info_full_path(self):
        f = RegionFilter(exclude_modules=["/system/*"])
        assert f.skip_reason(0x1000, 0x1000, RX, "/system/lib64/libhwui.so") == "module-exclude"
        assert f.skip_reason(0x1000, 0x1000, RX, "/vendor/lib64/libx.so") is None

    def test_fallback_without_info_empty_path(self):
        f = RegionFilter(exclude_modules=["*"])
        assert f.skip_reason(0x1000, 0x1000, RW, "") is None

    def test_matches_passthrough(self):
        f = RegionFilter(exclude_modules=["libhwui*"])
        name = "/system/lib64/libhwui.so"
        assert not f.matches(0x1000, 0x1000, RX, name, info=_info(name))
        assert f.matches(0x1000, 0x1000, RX, "/system/lib64/libc.so")

    def test_path_exclude_takes_precedence(self):
        f = RegionFilter(exclude_paths=[r"libhwui"], exclude_modules=["libhwui*"])
        assert _reason(f, RX, "/system/lib64/libhwui.so") == "path-exclude"

    def test_flags_follow_platform(self):
        expected = re.IGNORECASE if sys.platform == "win32" else 0
        assert MODULE_PATTERN_FLAGS == expected

    def test_case_sensitive_when_flags_cleared(self, monkeypatch):
        monkeypatch.setattr(region_filter_module, "MODULE_PATTERN_FLAGS", 0)
        f = RegionFilter(exclude_modules=["LIBHWUI*"])
        assert _reason(f, RX, "/system/lib64/libhwui.so") is None

    def test_case_insensitive_when_flag_set(self, monkeypatch):
        monkeypatch.setattr(region_filter_module, "MODULE_PATTERN_FLAGS", re.IGNORECASE)
        f = RegionFilter(exclude_modules=["LIBHWUI*"])
        assert _reason(f, RX, "/system/lib64/libhwui.so") == "module-exclude"


# ---------------------------------------------------------------------------
# --scope
# ---------------------------------------------------------------------------


class TestScopeField:
    def test_default_is_full(self):
        assert RegionFilter().scope == FULL_SCOPE
        assert RegionFilter().is_full_scope

    def test_str_is_parsed(self):
        f = RegionFilter(scope="heap, stack")
        assert f.scope == frozenset({"heap", "stack"})
        assert not f.is_full_scope

    def test_iterable_is_normalised(self):
        assert RegionFilter(scope=["heap"]).scope == frozenset({"heap"})
        assert RegionFilter(scope=("heapstack",)).scope == frozenset({"heap", "stack"})

    def test_empty_iterable_is_full(self):
        assert RegionFilter(scope=[]).scope == FULL_SCOPE

    def test_invalid_scope_rejected(self):
        with pytest.raises(ValueError):
            RegionFilter(scope="nope")


class TestScopeApp:
    f = RegionFilter(scope="app")

    def test_keeps_writable_system_image(self):
        assert _reason(self.f, RW, _LIBART) is None

    def test_drops_clean_system_image(self):
        assert _reason(self.f, RX, _LIBART) == "scope"
        assert _reason(self.f, R, _LIBART) == "scope"

    def test_drops_device_mapping(self):
        assert _reason(self.f, RW, "/dev/kgsl-3d0") == "scope"

    def test_keeps_named_anon(self):
        assert _reason(self.f, RW, "[anon:dalvik-LinearAlloc]") is None

    def test_keeps_app_image_even_clean(self):
        assert _reason(self.f, RX, _LIBFOO) is None

    def test_keeps_heap_and_stack(self):
        assert _reason(self.f, RW, "[heap]") is None
        assert _reason(self.f, RW, "[stack]") is None


class TestScopeHeap:
    f = RegionFilter(scope="heap")

    @pytest.mark.parametrize("name", [
        "[heap]",
        "[anon:scudo:primary]",
        "[anon:bionic_alloc_small_objects]",
        "[anon:dalvik-main space]",
        "[anon:dalvik-free list large object space]",
        "[anon:dalvik-/system/framework/boot.art]",
        "/dev/ashmem/dalvik-main space (deleted)",
        "",
    ])
    def test_keeps(self, name):
        assert _reason(self.f, RW, name) is None

    @pytest.mark.parametrize("name", [
        "[anon:stack_and_tls:123]",
        "[anon:dalvik-LinearAlloc]",
        "/memfd:jit-cache (deleted)",
        _LIBART,
        _LIBFOO,
        "/system/framework/framework.jar",
    ])
    def test_drops_writable(self, name):
        assert _reason(self.f, RW, name) == "scope"

    def test_drops_readonly_unnamed_anon(self):
        assert _reason(self.f, R, "") == "scope"

    def test_keeps_readonly_native_heap(self):
        """Allocator regions are kept regardless of protection."""
        assert _reason(self.f, R, "[anon:scudo:primary]") is None

    def test_keeps_writable_ashmem_and_dev_zero(self):
        assert _reason(self.f, RW, "/dev/ashmem/foo (deleted)") is None
        assert _reason(self.f, RW, "/dev/zero (deleted)") is None

    def test_drops_readonly_ashmem(self):
        assert _reason(self.f, R, "/dev/ashmem/foo (deleted)") == "scope"

    def test_drops_other_shared_mem(self):
        assert _reason(self.f, RW, "/dev/shm/foo") == "scope"
        assert _reason(self.f, RW, "/memfd:foo (deleted)") == "scope"


class TestScopeStack:
    f = RegionFilter(scope="stack")

    @pytest.mark.parametrize("name", [
        "[stack]",
        "[anon:stack_and_tls:1]",
        "[anon:thread signal stack]",
    ])
    def test_keeps(self, name):
        assert _reason(self.f, RW, name) is None

    def test_keeps_unnamed_region_holding_stack_pointer(self):
        classifier = _classifier(stack_pointers=[_STACK_SP])
        base = _STACK_SP & ~0xFFF
        assert _reason(self.f, RW, "", base, classifier) is None
        assert _reason(self.f, RW, "", 0x7FFF_0000_0000, classifier) == "scope"

    @pytest.mark.parametrize("name", ["[heap]", "", "[anon:dalvik-main space]", _LIBFOO])
    def test_drops(self, name):
        assert _reason(self.f, RW, name) == "scope"


class TestScopeCombinations:
    @pytest.mark.parametrize("scope", ["heap,stack", "heapstack", ["stack", "heap"]])
    def test_union_keeps_both(self, scope):
        f = RegionFilter(scope=scope)
        assert _reason(f, RW, "[heap]") is None
        assert _reason(f, RW, "[stack]") is None
        assert _reason(f, RW, "[anon:dalvik-LinearAlloc]") == "scope"

    @pytest.mark.parametrize("name", [_LIBART, "/dev/kgsl-3d0", "[heap]", "[stack]", ""])
    def test_full_keeps_everything(self, name):
        assert _reason(RegionFilter(scope="full"), RX, name) is None
        assert _reason(RegionFilter(), RX, name) is None

    def test_info_none_with_narrow_scope_is_skipped(self):
        f = RegionFilter(scope="heap")
        assert f.skip_reason(0x1000, 0x1000, RW, "[heap]") == "scope"
        assert not f.matches(0x1000, 0x1000, RW, "[heap]")

    def test_info_none_with_full_scope_passes(self):
        assert RegionFilter().skip_reason(0x1000, 0x1000, RW, "[heap]") is None

    def test_no_read_wins_over_scope(self):
        f = RegionFilter(scope="heap")
        assert _reason(f, 0x0, "[heap]") == "no-read"

    def test_path_exclude_wins_over_scope(self):
        f = RegionFilter(scope="heap", exclude_paths=[r"\[heap\]"])
        assert _reason(f, RW, "[heap]") == "path-exclude"

    def test_module_exclude_wins_over_scope(self):
        f = RegionFilter(scope="app", exclude_modules=["dalvik-LinearAlloc"])
        assert _reason(f, RW, "[anon:dalvik-LinearAlloc]") == "module-exclude"

    def test_addr_range_wins_over_scope(self):
        f = RegionFilter(scope="heap", addr_ranges=[(0x1000, 0x2000)])
        assert _reason(f, RW, "[heap]") == "addr-range"
