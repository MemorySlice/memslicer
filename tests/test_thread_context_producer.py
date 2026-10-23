"""Thread Context producer: bridge ThreadInfo -> engine blocks (spec 5.7).

The format layer (writer/parser layout) is covered by
``test_thread_context.py``; this file covers the acquisition side: the
register role tables, ``_build_thread_contexts`` and the engine writing the
blocks between Block 1 and the first Memory Region.
"""
from __future__ import annotations

import logging
import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import (
    RegisterValue, ThreadInfo, ThreadRegistersCapable, register_role,
    register_width_bytes, stack_pointers_of,
)
from memslicer.acquirer.engine import AcquisitionEngine, _build_thread_contexts
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.msl.constants import (
    REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP,
    REG_ROLE_TLS, TC_FLAG_CURRENT, TC_FLAG_PARTIAL, TC_FLAG_SUSPENDED,
    ArchType, BlockType, CapBit, OSType, ThreadState,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.writer import parse_thread_context
from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo

from tests.test_engine import MockBridge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

X64 = ArchType.x86_64
A64 = ArchType.ARM64


def _x64_thread(tid: int, *, pc=0x401000, sp=0x7fff0000, name="",
                suspended=False, partial=False,
                state=ThreadState.STOPPED) -> ThreadInfo:
    return ThreadInfo(
        tid=tid, name=name, state=state, suspended=suspended, partial=partial,
        registers=[
            RegisterValue.from_int("rip", pc, 8, X64),
            RegisterValue.from_int("rsp", sp, 8, X64),
            RegisterValue.from_int("rbp", 0x7fff0100, 8, X64),
            RegisterValue.from_int("rax", 0x2a, 8, X64),
        ],
    )


class ThreadBridge(MockBridge):
    """A MockBridge that also implements ``enumerate_threads``."""

    def __init__(self, threads: list[ThreadInfo], *, fail: bool = False,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.threads = threads
        self.fail = fail
        self.thread_calls = 0
        self.sp_calls = 0

    def enumerate_threads(self) -> list[ThreadInfo]:
        self.thread_calls += 1
        if self.fail:
            raise RuntimeError("no thread access")
        return list(self.threads)

    def enumerate_stack_pointers(self) -> list[int]:
        self.sp_calls += 1
        return [0x7fff0000]


_RANGES = [
    MemoryRange(base=0x400000, size=4096, protection="r-x", file_path="/bin/app"),
    MemoryRange(base=0x7ffe0000, size=0x20000, protection="rw-", file_path=""),
]
_MODULES = [ModuleInfo(name="app", path="/bin/app", base=0x400000, size=4096)]


def _bridge(threads: list[ThreadInfo], cls=ThreadBridge, **extra) -> MockBridge:
    return cls(
        threads,
        ranges=list(_RANGES), modules=list(_MODULES),
        platform_info=PlatformInfo(arch=X64, os=OSType.Linux, pid=1234, page_size=4096),
        memory={r.base: b"\x5a" * r.size for r in _RANGES},
        **extra,
    )


def _acquire(bridge, tmp_path: Path, **engine_kwargs):
    engine = AcquisitionEngine(bridge, **engine_kwargs)
    output = tmp_path / "out.msl"
    result = engine.acquire(output)
    with output.open("rb") as f:
        blocks = list(iterate_blocks(f))
    return result, blocks


def _types(blocks) -> list[int]:
    return [b.block_type for b in blocks]


def _cap_bitmap(path: Path) -> int:
    """CapBitmap of the file header: uint64 LE at offset 16."""
    return struct.unpack_from("<Q", path.read_bytes(), 16)[0]


# ---------------------------------------------------------------------------
# register_role / register_width_bytes / RegisterValue
# ---------------------------------------------------------------------------

class TestRegisterRole:
    @pytest.mark.parametrize("name, arch, role", [
        ("rip", X64, REG_ROLE_PC), ("RIP", X64, REG_ROLE_PC),
        ("rsp", X64, REG_ROLE_SP), ("rbp", X64, REG_ROLE_FP),
        ("rflags", X64, REG_ROLE_FLAGS), ("eflags", X64, REG_ROLE_FLAGS),
        ("fs_base", X64, REG_ROLE_TLS), ("gs_base", X64, REG_ROLE_TLS),
        ("eip", ArchType.x86, REG_ROLE_PC), ("esp", ArchType.x86, REG_ROLE_SP),
        ("ebp", ArchType.x86, REG_ROLE_FP), ("eflags", ArchType.x86, REG_ROLE_FLAGS),
        ("pc", A64, REG_ROLE_PC), ("sp", A64, REG_ROLE_SP),
        ("fp", A64, REG_ROLE_FP), ("x29", A64, REG_ROLE_FP),
        ("lr", A64, REG_ROLE_LR), ("x30", A64, REG_ROLE_LR),
        ("pstate", A64, REG_ROLE_FLAGS), ("cpsr", A64, REG_ROLE_FLAGS),
        ("nzcv", A64, REG_ROLE_FLAGS), ("tpidr_el0", A64, REG_ROLE_TLS),
        ("pc", ArchType.ARM32, REG_ROLE_PC), ("sp", ArchType.ARM32, REG_ROLE_SP),
        ("lr", ArchType.ARM32, REG_ROLE_LR), ("cpsr", ArchType.ARM32, REG_ROLE_FLAGS),
        ("r15", ArchType.ARM32, REG_ROLE_PC), ("r13", ArchType.ARM32, REG_ROLE_SP),
    ])
    def test_known_mnemonics(self, name, arch, role):
        assert register_role(name, arch) == role

    @pytest.mark.parametrize("name, arch", [
        ("rax", X64), ("x0", A64), ("r0", ArchType.ARM32), ("xmm0", X64),
        ("rip", A64), ("x29", X64),
    ])
    def test_general_and_foreign_registers_have_no_role(self, name, arch):
        assert register_role(name, arch) == 0

    def test_unknown_arch_accepts_every_mnemonic(self):
        assert register_role("rip", None) == REG_ROLE_PC
        assert register_role("pc", ArchType.MIPS64) == REG_ROLE_PC
        assert register_role("x30", ArchType.Unknown) == REG_ROLE_LR


class TestRegisterWidth:
    @pytest.mark.parametrize("arch, width", [
        (X64, 8), (A64, 8), (ArchType.MIPS64, 8), (None, 8),
        (ArchType.x86, 4), (ArchType.ARM32, 4), (ArchType.MIPS32, 4),
        (ArchType.RISC_V_RV32, 4), (ArchType.PPC32, 4),
    ])
    def test_width(self, arch, width):
        assert register_width_bytes(arch) == width


class TestRegisterValue:
    def test_from_int_lowercases_masks_and_encodes_little_endian(self):
        rv = RegisterValue.from_int("RSP", 0x1_0000_0000_7fff_0000, 8, X64)
        assert rv == RegisterValue("rsp", 8, (0x7fff0000).to_bytes(8, "little"), REG_ROLE_SP)
        assert rv.as_int == 0x7fff0000

    def test_from_int_honours_width(self):
        rv = RegisterValue.from_int("eip", 0x08048000, 4, ArchType.x86)
        assert rv.width == 4 and len(rv.value) == 4
        assert rv.role == REG_ROLE_PC

    def test_thread_info_pc_sp_and_stack_pointer(self):
        t = _x64_thread(1, sp=0x7fff1234)
        assert t.has_pc_and_sp
        assert t.stack_pointer == 0x7fff1234
        bare = ThreadInfo(tid=2, registers=[RegisterValue.from_int("rip", 1, 8, X64)])
        assert not bare.has_pc_and_sp
        assert bare.stack_pointer is None

    def test_stack_pointers_of_dedups_and_drops_zero(self):
        threads = [_x64_thread(1, sp=0x10), _x64_thread(2, sp=0x20),
                   _x64_thread(3, sp=0x10), _x64_thread(4, sp=0)]
        assert stack_pointers_of(threads) == (0x10, 0x20)


# ---------------------------------------------------------------------------
# _build_thread_contexts
# ---------------------------------------------------------------------------

class TestBuildThreadContexts:
    def test_one_block_per_thread_with_registers_in_file_form(self):
        ctxs = _build_thread_contexts([_x64_thread(1234, name="main", pc=0xabc)], X64)
        assert len(ctxs) == 1
        tc = ctxs[0]
        assert tc.thread_id == 1234 and tc.name == "main"
        assert tc.state is ThreadState.STOPPED
        assert tc.arch == 0  # inherits the header ArchType
        names = [r.name for r in tc.registers]
        assert names == ["rip", "rsp", "rbp", "rax"]
        assert tc.registers[0].value == (0xabc).to_bytes(8, "little")
        assert tc.registers[0].flags == REG_ROLE_PC
        assert tc.registers[1].flags == REG_ROLE_SP
        assert tc.registers[2].flags == REG_ROLE_FP
        assert tc.registers[3].flags == 0

    def test_names_are_lowercased_and_roles_filled_from_arch(self):
        t = ThreadInfo(tid=1, registers=[
            RegisterValue("RIP", 8, bytes(8), 0), RegisterValue("RSP", 8, bytes(8), 0),
        ])
        [tc] = _build_thread_contexts([t], X64)
        assert [(r.name, r.flags) for r in tc.registers] == [
            ("rip", REG_ROLE_PC), ("rsp", REG_ROLE_SP),
        ]

    def test_current_goes_to_main_thread_by_pid(self):
        ctxs = _build_thread_contexts(
            [_x64_thread(5679), _x64_thread(5678), _x64_thread(5680)], X64, pid=5678,
        )
        assert [bool(c.flags & TC_FLAG_CURRENT) for c in ctxs] == [False, True, False]

    def test_current_falls_back_to_first_thread(self):
        ctxs = _build_thread_contexts([_x64_thread(10), _x64_thread(11)], X64, pid=99)
        assert [bool(c.flags & TC_FLAG_CURRENT) for c in ctxs] == [True, False]
        ctxs = _build_thread_contexts([_x64_thread(10), _x64_thread(11)], X64)
        assert [bool(c.flags & TC_FLAG_CURRENT) for c in ctxs] == [True, False]

    def test_exactly_one_current_even_when_main_thread_dropped(self):
        no_sp = ThreadInfo(tid=5678, registers=[RegisterValue.from_int("rip", 1, 8, X64)])
        ctxs = _build_thread_contexts([no_sp, _x64_thread(5679)], X64, pid=5678)
        assert [c.thread_id for c in ctxs] == [5679]
        assert sum(bool(c.flags & TC_FLAG_CURRENT) for c in ctxs) == 1

    def test_suspended_and_partial_flags_follow_the_bridge(self):
        ctxs = _build_thread_contexts([
            _x64_thread(1, suspended=True, partial=False),
            _x64_thread(2, suspended=False, partial=True),
            _x64_thread(3, suspended=True, partial=True),
        ], X64)
        assert ctxs[0].flags & TC_FLAG_SUSPENDED and not ctxs[0].flags & TC_FLAG_PARTIAL
        assert ctxs[1].flags & TC_FLAG_PARTIAL and not ctxs[1].flags & TC_FLAG_SUSPENDED
        assert ctxs[2].flags & (TC_FLAG_SUSPENDED | TC_FLAG_PARTIAL) == (
            TC_FLAG_SUSPENDED | TC_FLAG_PARTIAL
        )

    def test_threads_without_pc_or_sp_are_dropped(self, caplog):
        only_pc = ThreadInfo(tid=1, registers=[RegisterValue.from_int("rip", 1, 8, X64)])
        only_sp = ThreadInfo(tid=2, registers=[RegisterValue.from_int("rsp", 1, 8, X64)])
        empty = ThreadInfo(tid=3)
        with caplog.at_level(logging.DEBUG, logger="memslicer"):
            assert _build_thread_contexts([only_pc, only_sp, empty], X64) == []
        assert "dropped" in caplog.text

    def test_empty_input(self):
        assert _build_thread_contexts([], X64, pid=1) == []

    def test_arm64_generic_names_are_canonical(self):
        t = ThreadInfo(tid=7, state=ThreadState.RUNNING, registers=[
            RegisterValue.from_int("pc", 0x1000, 8, A64),
            RegisterValue.from_int("sp", 0x2000, 8, A64),
            RegisterValue.from_int("x29", 0x3000, 8, A64),
            RegisterValue.from_int("lr", 0x4000, 8, A64),
            RegisterValue.from_int("nzcv", 0x6000_0000, 8, A64),
        ])
        [tc] = _build_thread_contexts([t], A64)
        assert [r.flags for r in tc.registers] == [
            REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_FLAGS,
        ]
        assert tc.state is ThreadState.RUNNING and tc.arch == 0


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------

class TestEngineThreadContexts:
    def test_blocks_land_between_block_1_and_the_first_region(self, tmp_path):
        threads = [_x64_thread(5679, name="worker", suspended=True),
                   _x64_thread(1234, name="main", suspended=True)]
        result, blocks = _acquire(_bridge(threads), tmp_path)

        types = _types(blocks)
        assert types[0] == BlockType.ProcessIdentity
        assert types[1] == BlockType.ModuleListIndex
        assert types[2:4] == [BlockType.ThreadContext, BlockType.ThreadContext]
        first_region = types.index(BlockType.MemoryRegion)
        assert first_region == 4
        assert result.thread_contexts == 2

    def test_blocks_parse_with_current_on_the_main_thread_and_pi_parent(self, tmp_path):
        threads = [_x64_thread(5679, name="worker", suspended=True),
                   _x64_thread(1234, name="main", suspended=True, pc=0x401234)]
        _result, blocks = _acquire(_bridge(threads), tmp_path)

        tcs = [parse_thread_context(b.payload)
               for b in blocks if b.block_type == BlockType.ThreadContext]
        assert [tc.thread_id for tc in tcs] == [5679, 1234]
        assert [bool(tc.flags & TC_FLAG_CURRENT) for tc in tcs] == [False, True]
        assert all(tc.flags & TC_FLAG_SUSPENDED for tc in tcs)
        assert tcs[1].name == "main" and tcs[1].arch == 0
        pc = next(r for r in tcs[1].registers if r.flags & REG_ROLE_PC)
        assert pc.name == "rip" and pc.value == (0x401234).to_bytes(8, "little")
        pi_uuid = blocks[0].block_uuid
        assert all(b.parent_uuid == pi_uuid
                   for b in blocks if b.block_type == BlockType.ThreadContext)

    def test_cap_bit_set_only_when_blocks_are_written(self, tmp_path):
        _result, _blocks = _acquire(_bridge([_x64_thread(1234)]), tmp_path)
        assert _cap_bitmap(tmp_path / "out.msl") & (1 << CapBit.ThreadContexts)

        result, blocks = _acquire(_bridge([]), tmp_path)
        assert not _cap_bitmap(tmp_path / "out.msl") & (1 << CapBit.ThreadContexts)
        assert BlockType.ThreadContext not in _types(blocks)
        assert result.thread_contexts == 0

    def test_no_registers_skips_the_rpc_and_clears_the_bit(self, tmp_path):
        bridge = _bridge([_x64_thread(1234)])
        result, blocks = _acquire(bridge, tmp_path, capture_registers=False)

        assert bridge.thread_calls == 0
        assert BlockType.ThreadContext not in _types(blocks)
        assert result.thread_contexts == 0
        assert not _cap_bitmap(tmp_path / "out.msl") & (1 << CapBit.ThreadContexts)

    def test_bridge_without_capability_writes_none(self, tmp_path):
        bridge = MockBridge(
            ranges=list(_RANGES), modules=list(_MODULES),
            memory={r.base: b"\x5a" * r.size for r in _RANGES},
        )
        assert not isinstance(bridge, ThreadRegistersCapable)
        result, blocks = _acquire(bridge, tmp_path)
        assert BlockType.ThreadContext not in _types(blocks)
        assert result.thread_contexts == 0

    def test_empty_answer_is_logged_once_at_info(self, tmp_path, caplog):
        with caplog.at_level(logging.INFO, logger="memslicer"):
            _acquire(_bridge([]), tmp_path)
        notes = [r for r in caplog.records
                 if "no thread contexts available from this backend" in r.getMessage()]
        assert len(notes) == 1 and notes[0].levelno == logging.INFO

    def test_failing_enumeration_degrades_to_no_blocks(self, tmp_path):
        result, blocks = _acquire(_bridge([_x64_thread(1)], fail=True), tmp_path)
        assert BlockType.ThreadContext not in _types(blocks)
        assert result.thread_contexts == 0
        assert result.regions_captured == 2

    def test_thread_enumeration_feeds_the_stack_classifier_once(self, tmp_path):
        """One RPC: the SPs come from the thread list, not a second query."""
        bridge = _bridge([_x64_thread(1234, sp=0x7ffe8000)])
        engine = AcquisitionEngine(bridge, region_filter=RegionFilter(scope={"stack"}))
        engine.acquire(tmp_path / "out.msl")

        assert bridge.thread_calls == 1
        assert bridge.sp_calls == 0
        assert engine._classifier._stack_pointers == (0x7ffe8000,)

    def test_no_registers_falls_back_to_the_stack_pointer_rpc(self, tmp_path):
        bridge = _bridge([_x64_thread(1234)])
        engine = AcquisitionEngine(
            bridge, region_filter=RegionFilter(scope={"stack"}), capture_registers=False,
        )
        engine.acquire(tmp_path / "out.msl")

        assert bridge.thread_calls == 0
        assert bridge.sp_calls == 1

    def test_survey_does_not_enumerate_threads(self):
        bridge = _bridge([_x64_thread(1234)])
        AcquisitionEngine(bridge).survey_regions()
        assert bridge.thread_calls == 0
