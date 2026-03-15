"""Tests for region filtering."""
from memslicer.acquirer.region_filter import RegionFilter


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
