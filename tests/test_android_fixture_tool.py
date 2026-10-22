"""Tests for ``tests/tools/make_android_fixture.py``."""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

from memslicer.msl.constants import HEADER_SIZE, BlockType, OSType, RegionType
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.writer import parse_vas_map

_TOOL = Path(__file__).resolve().parent / "tools" / "make_android_fixture.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("make_android_fixture", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module here
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load_tool()


@pytest.fixture
def built(tool, tmp_path: Path):
    out = tmp_path / "sub" / "android.msl"
    return tool, out, tool.build_android_fixture(out)


def _blocks(path: Path):
    with path.open("rb") as f:
        return list(iterate_blocks(f))


class TestMakeAndroidFixture:
    def test_key_is_deterministic_random_32_bytes(self, tool):
        assert len(tool.KEY) == 32
        assert len(set(tool.KEY)) > 16
        assert _load_tool().KEY == tool.KEY

    def test_header_is_android(self, built):
        _, out, _ = built
        os_type = struct.unpack_from("<H", out.read_bytes()[:HEADER_SIZE], 0x30)[0]
        assert os_type == OSType.Android

    def test_vas_map_lists_every_range_sorted(self, built):
        tool, out, summary = built
        vas_blocks = [b for b in _blocks(out) if b.block_type == BlockType.VASMap]
        assert len(vas_blocks) == 1
        entries = parse_vas_map(vas_blocks[0].payload)
        assert entries == tool.vas_entries()
        assert len(entries) == summary["vas_entries"] == len(tool.RANGES)
        names = {e.mapped_path for e in entries}
        for required in ("[anon:dalvik-zygote space]", "[anon:dalvik-card table]",
                         "[anon:dalvik-/system/framework/boot.art]",
                         "[anon:scudo:primary]", "[anon:libc_malloc]",
                         "[anon:stack_and_tls:4243]", "[anon:cfi shadow]",
                         "[vdso]", "[stack]", tool.APP_LIB):
            assert required in names
        assert [e.base_addr for e in entries] == sorted(e.base_addr for e in entries)

    def test_uncaptured_ranges_have_no_region_block(self, built):
        tool, out, summary = built
        bases = {struct.unpack_from("<Q", b.payload, 0)[0]
                 for b in _blocks(out) if b.block_type == BlockType.MemoryRegion}
        assert len(bases) == summary["regions_captured"]
        assert bases == {r.base for r in tool.RANGES if r.captured}

    def test_key_planted_in_scudo_region(self, built):
        tool, out, summary = built
        data = out.read_bytes()
        assert data.count(tool.KEY) == 1
        entries = {e.base_addr: e for e in tool.vas_entries()}
        key_base = summary["key_address"] - tool.KEY_OFFSET
        assert entries[key_base].mapped_path.startswith("[anon:scudo:")
        assert entries[key_base].region_type == RegionType.Heap
        assert summary["key_hex"] == tool.KEY.hex()

    def test_main_writes_given_path(self, tool, tmp_path: Path, capsys):
        out = tmp_path / "cli.msl"
        assert tool.main([str(out)]) == 0
        assert out.exists()
        assert "key_address: 0x" in capsys.readouterr().out

    def test_memdiver_reader_opens_fixture(self, built):
        reader_mod = pytest.importorskip("memdiver.msl.reader")
        tool, out, _ = built
        reader = reader_mod.MslReader(out)
        reader.open()
        try:
            names = [e.mapped_path for v in reader.collect_vas_map() for e in v.entries]
            assert names == [e.mapped_path for e in tool.vas_entries()]
            assert reader.file_header.os_type == int(OSType.Android)
        finally:
            close = getattr(reader, "close", None)
            if close:
                close()
