"""Tests for the VAS Map block (0x1001): writer, parser and engine build.

The payload layout must match MemDiver's ``msl.decoders.decode_vas_map``
byte for byte; the cross-check test runs only when ``memdiver`` imports.
"""
from __future__ import annotations

import io
import struct
import uuid

import pytest

from memslicer.acquirer.bridge import MemoryRange
from memslicer.acquirer.engine import build_vas_entries
from memslicer.msl.constants import (
    COMPRESSED, ArchType, BlockType, CompAlgo, OSType, RegionType, VasNameSource,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import FileHeader, ProcessIdentity, VasEntry
from memslicer.msl.writer import (
    MSLWriter, _pack_vas_entry, _read_vas_entry, _vas_path_bytes, parse_vas_map,
)
from memslicer.utils.timestamps import now_ns

SAMPLE_ENTRIES = [
    VasEntry(0x12c00000, 0x2000000, 3, RegionType.Heap,
             "[anon:dalvik-main space (region space)]", VasNameSource.LIVE),
    VasEntry(0x70000000, 0x1000, 3, RegionType.Anon, "[anon:dalvik-zygote space]",
             name_source=VasNameSource.SYNTHESIZED),
    VasEntry(0x7f0000000000, 0x21000, 3, RegionType.Heap, "[anon:scudo:primary]"),
    VasEntry(0x7f1000000000, 0x1000, 5, RegionType.Image,
             "/apex/com.android.runtime/lib64/bionic/libc.so"),
    VasEntry(0x7ffff000, 0x1000, 0, RegionType.Anon, ""),
    VasEntry(0x7fff00000000, 0x21000, 3, RegionType.Stack, "[stack]"),
    VasEntry(0x7fff10000000, 0x1000, 3, RegionType.Unknown, "x" * 7),  # pad edge
    VasEntry(0x7fff20000000, 0x1000, 3, RegionType.Unknown, "y" * 8),
]


def _header() -> FileHeader:
    return FileHeader(
        endianness=1, version=(1, 0), flags=0, cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes, timestamp_ns=now_ns(),
        os_type=OSType.Android, arch_type=ArchType.ARM64, pid=4242,
    )


def _write(entries: list[VasEntry], comp: CompAlgo = CompAlgo.NONE) -> bytes:
    buf = io.BytesIO()
    writer = MSLWriter(buf, _header(), comp)
    writer.write_process_identity(ProcessIdentity(exe_path="/system/bin/app_process64"))
    writer.write_vas_map(entries)
    writer.finalize()
    return buf.getvalue()


def _vas_blocks(data: bytes):
    return [b for b in iterate_blocks(io.BytesIO(data)) if b.block_type == BlockType.VASMap]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


class TestVasPathBytes:
    def test_nul_terminated(self):
        assert _vas_path_bytes("[stack]") == b"[stack]\x00"

    def test_empty_is_absent(self):
        assert _vas_path_bytes("") == b""

    def test_nul_containing_name_dropped(self):
        assert _vas_path_bytes("a\x00b") == b""

    def test_unencodable_name_dropped(self):
        assert _vas_path_bytes("bad\udcff") == b""

    def test_limit_includes_terminator(self):
        assert len(_vas_path_bytes("a" * 0xFFFE)) == 0xFFFF
        assert _vas_path_bytes("a" * 0xFFFF) == b""

    def test_multibyte_counted_in_bytes(self):
        assert _vas_path_bytes("ä" * 0x7FFF) == ("ä" * 0x7FFF).encode() + b"\x00"
        assert _vas_path_bytes("ä" * 0x8000) == b""


class TestPackVasEntry:
    def test_exact_layout(self):
        e = VasEntry(0x1122334455667788, 0x2000, 5, RegionType.Image, "/lib/a.so",
                     VasNameSource.LIVE)
        raw = _pack_vas_entry(e)
        assert raw[:24] == struct.pack("<QQBBHB3x", 0x1122334455667788, 0x2000, 5, 3, 10, 1)
        assert raw[24:] == b"/lib/a.so\x00" + b"\x00" * 6
        assert len(raw) % 8 == 0

    def test_name_source_at_offset_0x14(self):
        """NameSource occupies the first former reserved byte (spec Section 5.8)."""
        for source in VasNameSource:
            raw = _pack_vas_entry(VasEntry(0x1000, 0x1000, 3, RegionType.Anon, "", source))
            assert raw[0x14] == int(source)
            assert raw[0x15:0x18] == b"\x00" * 3

    def test_default_name_source_is_unspecified(self):
        """Positional 5-argument construction still works and writes 0."""
        raw = _pack_vas_entry(VasEntry(0x1000, 0x1000, 3, RegionType.Anon, ""))
        assert raw[0x14] == 0
        assert raw == struct.pack("<QQBBH4x", 0x1000, 0x1000, 3, 5, 0)  # 1.0 bytes

    def test_no_path_has_zero_len_and_no_tail(self):
        raw = _pack_vas_entry(VasEntry(0x1000, 0x1000, 3, RegionType.Anon, ""))
        assert raw == struct.pack("<QQBBHB3x", 0x1000, 0x1000, 3, 5, 0, 0)

    def test_exact_multiple_of_eight_gets_full_pad_word(self):
        raw = _pack_vas_entry(VasEntry(0, 0, 0, RegionType.Unknown, "y" * 8))
        assert len(raw) == 24 + 16  # 8 chars + NUL -> pad8(9) = 16

    def test_unpackable_address_returns_none(self):
        assert _pack_vas_entry(VasEntry(1 << 64, 0, 0, RegionType.Unknown, "")) is None

    def test_read_inverts_pack(self):
        e = SAMPLE_ENTRIES[0]
        raw = _pack_vas_entry(e)
        got, consumed = _read_vas_entry(raw, 0)
        assert got == e
        assert got.name_source is VasNameSource.LIVE
        assert consumed == len(raw)

    def test_read_unknown_name_source_kept_as_int(self):
        raw = struct.pack("<QQBBHB3x", 0x1000, 0x1000, 3, 5, 0, 0x7E)
        assert _read_vas_entry(raw, 0)[0].name_source == 0x7E

    def test_read_truncated_raises(self):
        with pytest.raises(ValueError):
            _read_vas_entry(b"\x00" * 10, 0)
        raw = _pack_vas_entry(SAMPLE_ENTRIES[0])
        with pytest.raises(ValueError):
            _read_vas_entry(raw[:30], 0)


class TestParseVasMap:
    def test_truncated_header_raises(self):
        with pytest.raises(ValueError):
            parse_vas_map(b"\x00" * 4)

    def test_fixed_entry_size_honoured(self):
        e = VasEntry(0x1000, 0x1000, 3, RegionType.Anon, "")
        payload = struct.pack("<II", 2, 32) + (_pack_vas_entry(e) + b"\x00" * 8) * 2
        assert parse_vas_map(payload) == [e, e]

    def test_unknown_region_type_kept_as_int(self):
        payload = struct.pack("<II", 1, 0) + struct.pack("<QQBBHB3x", 0, 0, 0, 0x42, 0, 0)
        assert parse_vas_map(payload)[0].region_type == 0x42


# ---------------------------------------------------------------------------
# Writer round-trip through memslicer's own iterator
# ---------------------------------------------------------------------------


class TestWriteVasMapRoundTrip:
    @pytest.mark.parametrize("comp", [CompAlgo.NONE, CompAlgo.ZSTD])
    def test_round_trip(self, comp: CompAlgo):
        blocks = _vas_blocks(_write(SAMPLE_ENTRIES, comp))
        assert len(blocks) == 1
        assert bool(blocks[0].flags & COMPRESSED) == (comp != CompAlgo.NONE)
        assert parse_vas_map(blocks[0].payload) == SAMPLE_ENTRIES

    def test_bad_names_dropped_entries_kept(self):
        entries = [
            VasEntry(0x1000, 0x1000, 3, RegionType.Anon, "a\x00b"),
            VasEntry(0x2000, 0x1000, 3, RegionType.Anon, "z" * 0x10000),
        ]
        parsed = parse_vas_map(_vas_blocks(_write(entries))[0].payload)
        assert [e.mapped_path for e in parsed] == ["", ""]
        assert [e.base_addr for e in parsed] == [0x1000, 0x2000]

    def test_unpackable_entry_not_counted(self):
        entries = [VasEntry(1 << 64, 0, 0, RegionType.Unknown, ""), SAMPLE_ENTRIES[0]]
        parsed = parse_vas_map(_vas_blocks(_write(entries))[0].payload)
        assert parsed == [SAMPLE_ENTRIES[0]]

    def test_empty_map(self):
        payload = _vas_blocks(_write([]))[0].payload
        assert payload[:8] == struct.pack("<II", 0, 0)
        assert parse_vas_map(payload) == []


# ---------------------------------------------------------------------------
# Cross-check with MemDiver's decoder (only when memdiver is importable)
# ---------------------------------------------------------------------------


class TestMemDiverDecoderCompat:
    @pytest.mark.parametrize("comp", [CompAlgo.NONE, CompAlgo.ZSTD])
    def test_decoder_parses_identically(self, comp: CompAlgo):
        decoders = pytest.importorskip("memdiver.msl.decoders")
        payload = _vas_blocks(_write(SAMPLE_ENTRIES, comp))[0].payload
        vas = decoders.decode_vas_map(None, payload, "<")
        assert vas.entry_count == len(SAMPLE_ENTRIES)
        got = [(e.base_addr, e.region_size, e.protection, e.region_type, e.mapped_path,
                e.name_source)
               for e in vas.entries]
        want = [(e.base_addr, e.region_size, e.protection, int(e.region_type), e.mapped_path,
                 int(e.name_source))
                for e in SAMPLE_ENTRIES]
        assert got == want

    def test_payload_byte_identical_to_memdiver_writer(self):
        mdwriter = pytest.importorskip("memdiver.msl.writer")
        mdtypes = pytest.importorskip("memdiver.msl.types")
        md_entries = [
            mdtypes.MslVasEntry(e.base_addr, e.region_size, e.protection,
                                int(e.region_type), e.mapped_path,
                                name_source=int(e.name_source))
            for e in SAMPLE_ENTRIES
        ]
        theirs = mdwriter._build_vas_map_payload(md_entries)
        ours = _vas_blocks(_write(SAMPLE_ENTRIES))[0].payload
        assert ours == theirs


# ---------------------------------------------------------------------------
# Engine helper
# ---------------------------------------------------------------------------


class TestBuildVasEntries:
    def test_sorted_by_base_and_classified(self):
        ranges = [
            MemoryRange(base=0x9000, size=10, protection="rw-",
                        file_path="[anon:dalvik-main space (region space)]"),
            MemoryRange(base=0x1000, size=0x1000, protection="r-x",
                        file_path="/system/lib64/libc.so"),
            MemoryRange(base=0x5000, size=0x1000, protection="---", file_path=""),
        ]
        got = build_vas_entries(ranges, 4096)
        assert [e.base_addr for e in got] == [0x1000, 0x5000, 0x9000]
        # Names enumerated from the running target are LIVE (spec Section 5.8).
        assert got[0] == VasEntry(0x1000, 0x1000, 5, RegionType.Image,
                                  "/system/lib64/libc.so", VasNameSource.LIVE)
        assert got[1] == VasEntry(0x5000, 0x1000, 0, RegionType.Anon, "",
                                  VasNameSource.LIVE)
        assert got[2].region_size == 4096  # page-rounded like region blocks
        assert got[2].region_type == RegionType.Heap
        assert got[2].mapped_path == "[anon:dalvik-main space (region space)]"

    def test_empty(self):
        assert build_vas_entries([], 4096) == []

    def test_name_source_defaults_to_live_and_can_be_overridden(self):
        ranges = [MemoryRange(base=0x1000, size=0x1000, protection="r--", file_path="")]
        assert build_vas_entries(ranges, 4096)[0].name_source is VasNameSource.LIVE
        got = build_vas_entries(ranges, 4096, name_source=VasNameSource.SYNTHESIZED)
        assert got[0].name_source is VasNameSource.SYNTHESIZED
