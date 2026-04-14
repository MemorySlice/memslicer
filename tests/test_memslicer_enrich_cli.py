"""Tests for the ``memslicer-enrich`` CLI (P1.7).

P1.6.2 shipped a stub that raised :class:`NotImplementedError`; P1.7
activates the real CLI on top of :mod:`memslicer.msl.iterator`. The
stub test has been replaced with real end-to-end tests; the
``test_enrich_cli_registered_in_pyproject`` and
``test_enrich_cli_help_works`` tests from the stub suite are retained.
"""
from __future__ import annotations

import io
import struct
import sys
import warnings
from pathlib import Path

import pytest
from click.testing import CliRunner

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.elf_notes import ELF_MAGIC
from memslicer.cli_enrich import main as enrich_main
from memslicer.msl.constants import (
    BlockType,
    CompAlgo,
    PageState,
    RegionType,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ModuleEntry,
)
from memslicer.msl.writer import MSLWriter


# ---------------------------------------------------------------------------
# Synthetic ELF builder (matches test_elf_notes helpers)
# ---------------------------------------------------------------------------


def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data + (b"\x00" * (4 - rem) if rem else b"")


def _build_gnu_note(build_id: bytes) -> bytes:
    name = b"GNU\x00"
    header = struct.pack("<III", len(name), len(build_id), 3)
    return header + _pad4(name) + _pad4(build_id)


def _make_elf64_with_build_id(build_id: bytes) -> bytes:
    """Minimal valid ELF64 LE file carrying a single NT_GNU_BUILD_ID note."""
    note_payload = _build_gnu_note(build_id)
    eh_size = 64
    ph_size = 56
    ph_offset = eh_size
    note_offset = ph_offset + ph_size

    e_ident = (
        ELF_MAGIC
        + bytes([2])  # EI_CLASS = ELFCLASS64
        + bytes([1])  # EI_DATA = little-endian
        + bytes([1])  # EI_VERSION
        + bytes([0]) * 9
    )
    header_tail = struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0, ph_offset, 0, 0, eh_size, ph_size, 1, 0, 0, 0,
    )
    elf_header = e_ident + header_tail
    ph_note = struct.pack(
        "<IIQQQQQQ",
        4, 4, note_offset, 0, 0, len(note_payload), len(note_payload), 1,
    )
    return elf_header + ph_note + note_payload


def _elf_page(build_id: bytes) -> bytes:
    """Produce a 4 KiB page whose first bytes are a synthetic ELF with
    the supplied build-id. Padded with zeros."""
    elf = _make_elf64_with_build_id(build_id)
    assert len(elf) <= 4096
    return elf + b"\x00" * (4096 - len(elf))


# ---------------------------------------------------------------------------
# Slice builder
# ---------------------------------------------------------------------------


def _synthesize_slice(
    path: Path,
    modules_with_pages: list[tuple[ModuleEntry, bytes]],
) -> None:
    """Write an .msl file containing matching MemoryRegions + ModuleEntries."""
    with open(path, "wb") as f:
        header = FileHeader()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer = MSLWriter(f, header, CompAlgo.NONE)
            for mod, page in modules_with_pages:
                region = MemoryRegion(
                    base_addr=mod.base_addr,
                    region_size=4096,
                    page_size=4096,
                    region_type=RegionType.Image,
                    page_states=[PageState.CAPTURED],
                    page_data_chunks=[page],
                )
                writer.write_memory_region(region)
            writer.write_module_list([m for m, _ in modules_with_pages])
            writer.finalize()


# ---------------------------------------------------------------------------
# Existing stub tests (retained surface)
# ---------------------------------------------------------------------------


def test_enrich_cli_registered_in_pyproject():
    """``memslicer-enrich`` is wired as a console script."""
    pyproject = PROJECT_ROOT / "pyproject.toml"
    text = pyproject.read_text()
    assert 'memslicer-enrich = "memslicer.cli_enrich:main"' in text


def test_enrich_cli_help_works():
    """``--help`` prints usage without invoking the enrichment logic."""
    runner = CliRunner()
    result = runner.invoke(enrich_main, ["--help"])
    assert result.exit_code == 0
    assert "slice" in result.output.lower()


# ---------------------------------------------------------------------------
# Real P1.7 end-to-end tests
# ---------------------------------------------------------------------------


class TestEnrichCLI:
    def test_enriches_unpopulated_modules(self, tmp_path):
        build_id = b"\xaa" * 20
        page = _elf_page(build_id)
        mod = ModuleEntry(base_addr=0x100000, module_size=4096, path="/bin/a")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])

        runner = CliRunner()
        output_path = tmp_path / "slice.enriched"
        result = runner.invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        assert result.exit_code == 0, result.output
        assert output_path.exists()

        # Verify the output has a ModuleBuildIdManifest block.
        with open(output_path, "rb") as f:
            block_types = [b.block_type for b in iterate_blocks(f)]
        assert BlockType.ModuleBuildIdManifest in block_types

    def test_in_place_replacement(self, tmp_path):
        build_id = b"\xbb" * 20
        page = _elf_page(build_id)
        mod = ModuleEntry(base_addr=0x200000, module_size=4096, path="/bin/b")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])
        original_size = slice_path.stat().st_size

        runner = CliRunner()
        result = runner.invoke(enrich_main, [str(slice_path), "--in-place"])
        assert result.exit_code == 0, result.output

        # File should have grown due to the appended manifest + new EoC.
        assert slice_path.stat().st_size > original_size

        # tmp path should no longer exist (replaced atomically).
        tmp_output = slice_path.with_suffix(slice_path.suffix + ".tmp")
        assert not tmp_output.exists()

        # The in-place file still iterates cleanly and carries the manifest.
        with open(slice_path, "rb") as f:
            block_types = [b.block_type for b in iterate_blocks(f)]
        assert BlockType.ModuleBuildIdManifest in block_types

    def test_nothing_to_enrich_when_blobs_populated(self, tmp_path):
        # Construct a module whose native_blob is already set.
        mod = ModuleEntry(
            base_addr=0x300000,
            module_size=4096,
            path="/bin/c",
            native_blob=bytes([20, 1, 0, 0]) + b"\xcc" * 20,
        )
        page = _elf_page(b"\xdd" * 20)
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])

        runner = CliRunner()
        output_path = tmp_path / "slice.enriched"
        result = runner.invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        assert result.exit_code == 0, result.output
        assert "nothing to enrich" in result.output

    def test_unresolvable_build_id_graceful(self, tmp_path):
        # Region contents are not a valid ELF; Path B extracts nothing.
        garbage = b"\xde\xad\xbe\xef" + b"\x00" * 4092
        mod = ModuleEntry(base_addr=0x400000, module_size=4096, path="/bin/d")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, garbage)])

        runner = CliRunner()
        output_path = tmp_path / "slice.enriched"
        result = runner.invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        # Exit cleanly with a diagnostic message — no crash.
        assert result.exit_code == 0, result.output
        combined = result.output + (result.stderr_bytes or b"").decode()
        assert "could not recover" in combined or "nothing" in combined

    def test_missing_slice_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            enrich_main, [str(tmp_path / "does_not_exist.msl")]
        )
        assert result.exit_code != 0

    def test_output_defaults_to_enriched_suffix(self, tmp_path):
        build_id = b"\xdd" * 20
        page = _elf_page(build_id)
        mod = ModuleEntry(base_addr=0x500000, module_size=4096, path="/bin/e")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])

        runner = CliRunner()
        result = runner.invoke(enrich_main, [str(slice_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "slice.msl.enriched").exists()

    def test_manifest_row_carries_build_id(self, tmp_path):
        """Verify the manifest block's payload actually contains the
        recovered build-id bytes (end-to-end sanity)."""
        build_id = b"\x11" * 20
        page = _elf_page(build_id)
        mod = ModuleEntry(base_addr=0x600000, module_size=4096, path="/bin/f")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])

        runner = CliRunner()
        output_path = tmp_path / "slice.enriched"
        result = runner.invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        assert result.exit_code == 0, result.output

        with open(output_path, "rb") as f:
            manifest_payloads = [
                b.payload
                for b in iterate_blocks(f)
                if b.block_type == BlockType.ModuleBuildIdManifest
            ]
        assert len(manifest_payloads) == 1
        assert build_id in manifest_payloads[0]
