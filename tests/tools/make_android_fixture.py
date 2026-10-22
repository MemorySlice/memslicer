"""Generate a small Android-looking ``.msl`` fixture with a VAS Map.

The file mimics what the acquisition engine writes for an Android app
process: ProcessIdentity, ModuleListIndex + entries, one-page MemoryRegion
blocks for a subset of the ranges, a VAS Map (0x1001) listing every range
with its full mapping name, and EndOfCapture. One scudo heap region carries
a planted 32-byte key at a fixed offset so downstream key-search tests have
ground truth.

Usage::

    python tests/tools/make_android_fixture.py OUTPUT.msl

The default output is MemDiver's ``tests/fixtures/android/memslicer_android.msl``
when the two repositories are checked out side by side.
"""
from __future__ import annotations

import argparse
import random
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from memslicer.acquirer.engine import classify_region
from memslicer.msl.constants import (
    VERSION, ArchType, CapBit, CompAlgo, Endianness, OSType, PageState,
)
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity, VasEntry,
)
from memslicer.msl.writer import MSLWriter

PAGE_SIZE = 4096
PID = 4242
EXE_PATH = "/system/bin/app_process64"
CMD_LINE = "com.example.keyholder"
KEY_SEED = 0x4B455931
KEY = random.Random(KEY_SEED).randbytes(32)
KEY_REGION_NAME = "[anon:scudo:primary]"
KEY_OFFSET = 0x340
APP_LIB = "/data/app/~~Q1w2e3==/com.example.keyholder-AbC==/lib/arm64/libkeyholder.so"
LIBC = "/apex/com.android.runtime/lib64/bionic/libc.so"


@dataclass(frozen=True)
class FixtureRange:
    """One mapping of the synthetic process; ``captured`` writes its bytes."""
    base: int
    size: int
    protection: int
    name: str
    captured: bool = True


RANGES: tuple[FixtureRange, ...] = (
    FixtureRange(0x12C00000, 0x1000, 3, "[anon:dalvik-main space (region space)]"),
    FixtureRange(0x6F000000, 0x1000, 3, "[anon:dalvik-zygote space]"),
    FixtureRange(0x6F100000, 0x1000, 3, "[anon:dalvik-/system/framework/boot.art]"),
    FixtureRange(0x6F200000, 0x1000, 3, "[anon:dalvik-card table]", captured=False),
    FixtureRange(0x6F300000, 0x1000, 3,
                 "[anon:dalvik-large object space allocation]"),
    FixtureRange(0x7A00000000, 0x1000, 3, KEY_REGION_NAME),
    FixtureRange(0x7A00100000, 0x1000, 3, "[anon:scudo:secondary]"),
    FixtureRange(0x7A10000000, 0x1000, 3, "[anon:libc_malloc]"),
    FixtureRange(0x7A20000000, 0x1000, 3, "[anon:stack_and_tls:4243]"),
    FixtureRange(0x7A30000000, 0x1000, 1, "[anon:cfi shadow]", captured=False),
    FixtureRange(0x7A40000000, 0x1000, 5, APP_LIB),
    FixtureRange(0x7A40001000, 0x1000, 3, "[anon:.bss]"),
    FixtureRange(0x7A50000000, 0x1000, 5, LIBC),
    FixtureRange(0x7A60000000, 0x1000, 3, "/dev/__properties__/u:object_r:properties_serial:s0",
                 captured=False),
    FixtureRange(0x7A70000000, 0x1000, 5, "[vdso]"),
    FixtureRange(0x7FF0000000, 0x1000, 3, "[stack]"),
)


def _page_bytes(r: FixtureRange) -> bytes:
    """Deterministic, mostly-zero page content; the key region holds KEY."""
    page = bytearray(PAGE_SIZE)
    tag = r.name.encode("utf-8")[:64]
    page[: len(tag)] = tag
    if r.name == KEY_REGION_NAME:
        page[KEY_OFFSET:KEY_OFFSET + len(KEY)] = KEY
    return bytes(page)


def _memory_region(r: FixtureRange) -> MemoryRegion:
    return MemoryRegion(
        base_addr=r.base, region_size=r.size, protection=r.protection,
        region_type=classify_region(r.name), page_size=PAGE_SIZE,
        timestamp_ns=1_700_000_000_000_000_000,
        page_states=[PageState.CAPTURED],
        page_data_chunks=[_page_bytes(r)],
    )


def vas_entries() -> list[VasEntry]:
    """VAS Map rows for every fixture range, sorted by base address."""
    return sorted(
        (VasEntry(r.base, r.size, r.protection, classify_region(r.name), r.name)
         for r in RANGES),
        key=lambda e: e.base_addr,
    )


def _modules() -> list[ModuleEntry]:
    return [
        ModuleEntry(base_addr=0x7A40000000, module_size=0x2000, path=APP_LIB),
        ModuleEntry(base_addr=0x7A50000000, module_size=0x1000, path=LIBC),
    ]


def _header() -> FileHeader:
    return FileHeader(
        endianness=Endianness.LITTLE, version=VERSION, flags=0,
        cap_bitmap=(1 << CapBit.MemoryRegions) | (1 << CapBit.ModuleList)
        | (1 << CapBit.ProcessIdentity),
        dump_uuid=uuid.UUID("a17d0000-0000-4000-8000-000000004242").bytes,
        timestamp_ns=1_700_000_000_000_000_000,
        os_type=OSType.Android, arch_type=ArchType.ARM64, pid=PID,
    )


def build_android_fixture(output: Path) -> dict:
    """Write the fixture to *output*; return a summary with the key location."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as f:
        # Uncompressed on purpose: MemDiver's reader does not yet strip the
        # spec's 8-byte UncompressedSize prefix memslicer writes before
        # compressed payloads, and the fixture must open there.
        writer = MSLWriter(f, _header(), CompAlgo.NONE)
        writer.write_process_identity(
            ProcessIdentity(ppid=1, exe_path=EXE_PATH, cmd_line=CMD_LINE),
        )
        writer.write_module_list(_modules())
        for r in RANGES:
            if r.captured:
                writer.write_memory_region(_memory_region(r))
        writer.write_vas_map(vas_entries())
        writer.finalize()
    key_base = next(r.base for r in RANGES if r.name == KEY_REGION_NAME)
    return {
        "path": str(output),
        "regions_captured": sum(r.captured for r in RANGES),
        "vas_entries": len(RANGES),
        "key_hex": KEY.hex(),
        "key_address": key_base + KEY_OFFSET,
    }


def _default_output() -> Path:
    repo = Path(__file__).resolve().parents[2]
    return repo.parent / "MemDiver" / "tests" / "fixtures" / "android" / "memslicer_android.msl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", nargs="?", type=Path, default=_default_output())
    args = parser.parse_args(argv)
    summary = build_android_fixture(args.output)
    for key, value in summary.items():
        print(f"{key}: {hex(value) if key == 'key_address' else value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
