"""Tests for the Thread Context block (0x0011): writer, packer and parser.

The payload layout must match spec Tables 19a (32-byte head + optional
thread name) and 19b (one entry per register) byte for byte.
"""
from __future__ import annotations

import io
import logging
import struct
import uuid

import pytest

from memslicer.msl.constants import (
    REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_TLS,
    TC_FLAG_CRASHED, TC_FLAG_CURRENT, TC_FLAG_PARTIAL, TC_FLAG_SUSPENDED,
    ArchType, BlockType, CompAlgo, OSType, ThreadState,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import FileHeader, ProcessIdentity, ThreadContext, ThreadRegister
from memslicer.msl.writer import (
    _TC_HEAD, _TC_REG_HEAD, MSLWriter, _pack_thread_register, parse_thread_context,
)
from memslicer.utils.padding import pad8
from memslicer.utils.timestamps import now_ns

PC_VALUE = bytes(range(0x10, 0x18))
SP_VALUE = bytes(range(0x20, 0x28))

MAIN_THREAD = ThreadContext(
    thread_id=0x1122334455667788, start_time_ns=1_700_000_000_000_000_000,
    flags=TC_FLAG_CURRENT, state=ThreadState.RUNNING, arch=0, name="main",
    registers=[
        ThreadRegister("pc", 8, REG_ROLE_PC, PC_VALUE),
        ThreadRegister("sp", 8, REG_ROLE_SP, SP_VALUE),
    ],
)


def _header() -> FileHeader:
    return FileHeader(
        endianness=1, version=(1, 0), flags=0, cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes, timestamp_ns=now_ns(),
        os_type=OSType.Android, arch_type=ArchType.ARM64, pid=4242,
    )


def _write(
    contexts: list[ThreadContext], parent_uuid: bytes | None = None,
    comp: CompAlgo = CompAlgo.NONE,
) -> tuple[bytes, list[bytes]]:
    """Write *contexts* into one file; return ``(file_bytes, block_uuids)``."""
    buf = io.BytesIO()
    writer = MSLWriter(buf, _header(), comp)
    writer.write_process_identity(ProcessIdentity(exe_path="/system/bin/app_process64"))
    uuids = [writer.write_thread_context(tc, parent_uuid=parent_uuid) for tc in contexts]
    writer.finalize()
    return buf.getvalue(), uuids


def _tc_blocks(data: bytes):
    return [
        b for b in iterate_blocks(io.BytesIO(data))
        if b.block_type == BlockType.ThreadContext
    ]


def _payload(tc: ThreadContext) -> bytes:
    """Payload of a single thread context as the writer lays it out."""
    data, _ = _write([tc])
    return _tc_blocks(data)[0].payload


def _round_trip(tc: ThreadContext) -> ThreadContext:
    return parse_thread_context(_payload(tc))


# ---------------------------------------------------------------------------
# Exact layout (Tables 19a / 19b)
# ---------------------------------------------------------------------------


class TestPayloadLayout:
    """Every field sits at the offset the spec gives it."""

    def test_struct_sizes(self):
        assert _TC_HEAD.size == 32
        assert _TC_REG_HEAD.size == 8

    def test_head_fields_at_spec_offsets(self):
        raw = _payload(MAIN_THREAD)
        assert struct.unpack_from("<Q", raw, 0x00)[0] == 0x1122334455667788
        assert struct.unpack_from("<Q", raw, 0x08)[0] == 1_700_000_000_000_000_000
        assert struct.unpack_from("<H", raw, 0x10)[0] == TC_FLAG_CURRENT
        assert struct.unpack_from("<B", raw, 0x12)[0] == ThreadState.RUNNING
        assert struct.unpack_from("<B", raw, 0x13)[0] == 0
        assert struct.unpack_from("<I", raw, 0x14)[0] == 2
        assert struct.unpack_from("<H", raw, 0x18)[0] == 5  # "main" + NUL
        assert raw[0x1A:0x20] == b"\x00" * 6

    def test_thread_name_nul_terminated_and_padded(self):
        raw = _payload(MAIN_THREAD)
        assert raw[0x20:0x28] == b"main\x00" + b"\x00" * 3

    def test_first_register_entry(self):
        raw = _payload(MAIN_THREAD)
        name_len, width, flags = struct.unpack_from("<BBH", raw, 0x28)
        assert (name_len, width, flags) == (3, 8, REG_ROLE_PC)
        assert raw[0x2C:0x30] == b"\x00" * 4
        assert raw[0x30:0x38] == b"pc\x00" + b"\x00" * 5
        assert raw[0x38:0x40] == PC_VALUE  # exactly 8 bytes, no pad

    def test_second_register_follows_immediately(self):
        raw = _payload(MAIN_THREAD)
        name_len, width, flags = struct.unpack_from("<BBH", raw, 0x40)
        assert (name_len, width, flags) == (3, 8, REG_ROLE_SP)
        assert raw[0x48:0x50] == b"sp\x00" + b"\x00" * 5
        assert raw[0x50:0x58] == SP_VALUE
        assert len(raw) == 0x58

    def test_no_name_omits_name_field(self):
        tc = ThreadContext(thread_id=7, registers=MAIN_THREAD.registers)
        raw = _payload(tc)
        assert struct.unpack_from("<H", raw, 0x18)[0] == 0
        assert struct.unpack_from("<BBH", raw, 0x20) == (3, 8, REG_ROLE_PC)
        assert len(raw) == 32 + sum(len(_pack_thread_register(r)) for r in tc.registers)

    def test_no_name_no_registers_is_bare_head(self):
        raw = _payload(ThreadContext(thread_id=1))
        assert len(raw) == 32
        assert raw == _TC_HEAD.pack(1, 0, 0, 0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Register packer
# ---------------------------------------------------------------------------


class TestPackThreadRegister:
    """One Table 19b entry: 8-byte head, name pad8, value pad8."""

    @pytest.mark.parametrize("name,width", [
        ("pc", 8), ("x0", 1), ("eflags", 4), ("v0", 16), ("a" * 7, 3), ("b" * 8, 9),
    ])
    def test_size_is_head_plus_padded_name_plus_padded_value(self, name: str, width: int):
        raw = _pack_thread_register(ThreadRegister(name, width, 0, bytes(width)))
        assert len(raw) == 8 + pad8(len(name) + 1) + pad8(width)

    def test_odd_width_value_padded_to_eight(self):
        raw = _pack_thread_register(ThreadRegister("eflags", 4, REG_ROLE_FLAGS, b"\x01\x02\x03\x04"))
        assert raw[:8] == struct.pack("<BBH4x", 7, 4, REG_ROLE_FLAGS)
        assert raw[8:16] == b"eflags\x00\x00"
        assert raw[16:24] == b"\x01\x02\x03\x04" + b"\x00" * 4

    def test_uppercase_name_written_lowercase(self):
        raw = _pack_thread_register(ThreadRegister("PC", 8, REG_ROLE_PC, PC_VALUE))
        assert raw[8:16] == b"pc\x00" + b"\x00" * 5

    def test_name_limit_includes_terminator(self):
        ok = _pack_thread_register(ThreadRegister("a" * 254, 1, 0, b"\x00"))
        assert ok[0] == 255
        with pytest.raises(ValueError):
            _pack_thread_register(ThreadRegister("a" * 255, 1, 0, b"\x00"))

    def test_empty_name_raises(self):
        with pytest.raises(ValueError):
            _pack_thread_register(ThreadRegister("", 8, 0, bytes(8)))

    @pytest.mark.parametrize("width", [0, 256])
    def test_width_out_of_range_raises(self, width: int):
        with pytest.raises(ValueError):
            _pack_thread_register(ThreadRegister("x0", width, 0, bytes(width)))

    @pytest.mark.parametrize("value", [bytes(7), bytes(9)])
    def test_value_length_mismatch_raises(self, value: bytes):
        with pytest.raises(ValueError):
            _pack_thread_register(ThreadRegister("x0", 8, 0, value))

    def test_writer_propagates_register_error(self):
        bad = ThreadContext(thread_id=1, registers=[ThreadRegister("", 8, 0, bytes(8))])
        writer = MSLWriter(io.BytesIO(), _header(), CompAlgo.NONE)
        with pytest.raises(ValueError):
            writer.write_thread_context(bad)


# ---------------------------------------------------------------------------
# Field round trips
# ---------------------------------------------------------------------------


class TestFieldRoundTrips:
    """Enum, flag and width values survive write + parse unchanged."""

    def test_register_widths_byte_exact(self):
        tc = ThreadContext(thread_id=3, registers=[
            ThreadRegister("v0", 16, 0, bytes(range(16))),
            ThreadRegister("eflags", 4, REG_ROLE_FLAGS, b"\x46\x02\x00\x00"),
            ThreadRegister("cpsr_bit", 1, 0, b"\xa5"),
        ])
        assert _round_trip(tc) == tc

    def test_thread_flags_combination(self):
        flags = TC_FLAG_CURRENT | TC_FLAG_CRASHED | TC_FLAG_SUSPENDED | TC_FLAG_PARTIAL
        assert _round_trip(ThreadContext(thread_id=1, flags=flags)).flags == flags

    def test_register_role_combinations(self):
        tc = ThreadContext(thread_id=1, registers=[
            ThreadRegister("pc", 8, REG_ROLE_PC | REG_ROLE_FLAGS, bytes(8)),
            ThreadRegister("x29", 8, REG_ROLE_FP | REG_ROLE_SP, bytes(8)),
            ThreadRegister("tpidr_el0", 8, REG_ROLE_TLS, bytes(8)),
            ThreadRegister("x30", 8, REG_ROLE_LR, bytes(8)),
        ])
        got = _round_trip(tc)
        assert [r.flags for r in got.registers] == [
            REG_ROLE_PC | REG_ROLE_FLAGS, REG_ROLE_FP | REG_ROLE_SP, REG_ROLE_TLS, REG_ROLE_LR,
        ]

    @pytest.mark.parametrize("state", list(ThreadState))
    def test_every_thread_state(self, state: ThreadState):
        got = _round_trip(ThreadContext(thread_id=1, state=state))
        assert got.state == state
        assert isinstance(got.state, ThreadState)

    def test_unknown_state_kept_as_int(self):
        payload = _TC_HEAD.pack(1, 0, 0, 0x7E, 0, 0, 0)
        got = parse_thread_context(payload)
        assert got.state == 0x7E
        assert not isinstance(got.state, ThreadState)

    def test_nonzero_arch_for_mixed_mode_thread(self):
        got = _round_trip(ThreadContext(thread_id=1, arch=ArchType.ARM32))
        assert got.arch == ArchType.ARM32

    def test_uppercase_register_name_parsed_lowercase(self):
        tc = ThreadContext(thread_id=1, registers=[ThreadRegister("PC", 8, REG_ROLE_PC, PC_VALUE)])
        assert _round_trip(tc).registers[0].name == "pc"

    def test_utf8_thread_name(self):
        name = "Thread-Ärger-✓"
        got = _round_trip(ThreadContext(thread_id=1, name=name))
        assert got.name == name

    def test_overlong_thread_name_truncated_with_warning(self, caplog):
        tc = ThreadContext(thread_id=1, name="n" * 0x10000)
        with caplog.at_level(logging.WARNING, logger="memslicer"):
            raw = _payload(tc)
        assert struct.unpack_from("<H", raw, 0x18)[0] == 0xFFFF
        assert parse_thread_context(raw).name == "n" * 0xFFFE
        assert any("ThreadName truncated" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Writer round-trip through memslicer's own iterator
# ---------------------------------------------------------------------------


class TestWriteThreadContextRoundTrip:
    @pytest.mark.parametrize("comp", [CompAlgo.NONE, CompAlgo.ZSTD])
    def test_round_trip(self, comp: CompAlgo):
        data, uuids = _write([MAIN_THREAD], comp=comp)
        blocks = _tc_blocks(data)
        assert len(blocks) == 1
        assert blocks[0].block_type == 0x0011
        assert blocks[0].block_uuid == uuids[0]
        assert blocks[0].parent_uuid == b"\x00" * 16
        assert parse_thread_context(blocks[0].payload) == MAIN_THREAD

    def test_parent_uuid_recorded(self):
        parent = uuid.uuid4().bytes
        data, uuids = _write([MAIN_THREAD], parent_uuid=parent)
        block = _tc_blocks(data)[0]
        assert block.parent_uuid == parent
        assert block.block_uuid == uuids[0]

    def test_several_contexts_in_one_file(self):
        contexts = [
            MAIN_THREAD,
            ThreadContext(thread_id=2, state=ThreadState.SLEEPING, name="worker"),
            ThreadContext(thread_id=3, flags=TC_FLAG_CRASHED, registers=[
                ThreadRegister("x30", 8, REG_ROLE_LR, bytes(8)),
            ]),
        ]
        data, uuids = _write(contexts)
        blocks = _tc_blocks(data)
        assert [b.block_uuid for b in blocks] == uuids
        assert len(set(uuids)) == 3
        assert [parse_thread_context(b.payload) for b in blocks] == contexts


# ---------------------------------------------------------------------------
# Parser truncation
# ---------------------------------------------------------------------------


class TestParseThreadContextTruncated:
    """A payload cut anywhere raises ValueError instead of mis-reading."""

    def test_truncated_in_head(self):
        with pytest.raises(ValueError):
            parse_thread_context(_payload(MAIN_THREAD)[:31])

    def test_truncated_in_name(self):
        with pytest.raises(ValueError):
            parse_thread_context(_payload(MAIN_THREAD)[:0x23])

    def test_truncated_in_register_head(self):
        with pytest.raises(ValueError):
            parse_thread_context(_payload(MAIN_THREAD)[:0x2C])

    def test_truncated_in_register_name(self):
        with pytest.raises(ValueError):
            parse_thread_context(_payload(MAIN_THREAD)[:0x31])

    def test_truncated_in_register_value(self):
        with pytest.raises(ValueError):
            parse_thread_context(_payload(MAIN_THREAD)[:0x3C])

    def test_declared_reg_count_beyond_payload(self):
        payload = _TC_HEAD.pack(1, 0, 0, 0, 0, 1, 0)
        with pytest.raises(ValueError):
            parse_thread_context(payload)


class TestArchAndStateBounds:
    """Arch and ThreadState are u8 fields; out-of-range values are refused, not masked."""

    def test_arch_unknown_is_refused(self):
        buf = io.BytesIO()
        writer = MSLWriter(buf, _header())
        with pytest.raises(ValueError, match="u8"):
            writer.write_thread_context(ThreadContext(1, arch=int(ArchType.Unknown)))

    def test_state_out_of_range_is_refused(self):
        buf = io.BytesIO()
        writer = MSLWriter(buf, _header())
        with pytest.raises(ValueError, match="u8"):
            writer.write_thread_context(ThreadContext(1, state=0x100))
