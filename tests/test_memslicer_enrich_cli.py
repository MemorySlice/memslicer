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
from memslicer.cli_enrich import PRODUCER, main as enrich_main
from memslicer.msl.constants import (
    BLOCK_MAGIC,
    BlockType,
    CompAlgo,
    HashAlgo,
    PageState,
    RegionType,
)
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.iterator import iterate_blocks, read_hash_algo
from memslicer.msl.types import (
    FileHeader,
    MemoryRegion,
    ModuleBuildIdManifest,
    ModuleBuildIdRow,
    ModuleEntry,
)
from memslicer.msl.verify import VerifyReport, verify_slice
from memslicer.msl.writer import MSLWriter, parse_module_build_id_manifest


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


def _manifest_for(mod: ModuleEntry, build_id: bytes) -> ModuleBuildIdManifest:
    """A one-row manifest claiming *build_id* for *mod*."""
    return ModuleBuildIdManifest(rows=[ModuleBuildIdRow(
        base_addr=mod.base_addr, build_id_len=len(build_id), build_id_source=1,
        flags=0, build_id=build_id, disk_hash=b"\x00" * 32,
    )])


def _synthesize_slice(
    path: Path,
    modules_with_pages: list[tuple[ModuleEntry, bytes]],
    hash_algo: HashAlgo = HashAlgo.BLAKE3,
    comp_algo: CompAlgo = CompAlgo.NONE,
    capture_manifest: ModuleBuildIdManifest | None = None,
    segment_manifest: ModuleBuildIdManifest | None = None,
) -> None:
    """Write an .msl file containing matching MemoryRegions + ModuleEntries.

    ``capture_manifest`` is written before the EoC, the way a pre-1.1
    ``memslicer-enrich`` left it; ``segment_manifest`` goes into an
    extension segment after the EoC with producer ``other/1``.
    """
    with open(path, "wb") as f:
        header = FileHeader(hash_algo=hash_algo)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            writer = MSLWriter(f, header, comp_algo)
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
            if capture_manifest is not None:
                writer.write_module_build_id_manifest(capture_manifest)
            writer.finalize()
            if segment_manifest is not None:
                writer.begin_extension()
                writer.write_module_build_id_manifest(segment_manifest)
                writer.finalize_extension("other/1")


def _verify(path: Path) -> VerifyReport:
    with open(path, "rb") as f:
        return verify_slice(f)


def _records(path: Path) -> list:
    with open(path, "rb") as f:
        return list(iterate_blocks(f))


def _manifests(path: Path) -> list[tuple[int, ModuleBuildIdManifest]]:
    """``(segment, manifest)`` for every ModuleBuildIdManifest block."""
    return [
        (b.segment, parse_module_build_id_manifest(b.payload))
        for b in _records(path) if b.block_type == BlockType.ModuleBuildIdManifest
    ]


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

        # The manifest lands in extension segment 1, right after the
        # original EoC, closed by an EndOfExtension block.
        records = _records(output_path)
        types = [b.block_type for b in records]
        eoc = types.index(BlockType.EndOfCapture)
        assert records[eoc].segment == 0
        assert types[eoc + 1:] == [
            BlockType.ModuleBuildIdManifest, BlockType.EndOfExtension,
        ]
        assert [b.segment for b in records[eoc + 1:]] == [1, 1]

        report = _verify(output_path)
        assert report.valid, report.errors
        assert len(report.segments) == 1 and report.segments[0].verified
        assert report.segments[0].producer == PRODUCER
        assert report.segments[0].block_count == 2

    def test_in_place_replacement(self, tmp_path):
        build_id = b"\xbb" * 20
        page = _elf_page(build_id)
        mod = ModuleEntry(base_addr=0x200000, module_size=4096, path="/bin/b")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, page)])
        original = slice_path.read_bytes()

        runner = CliRunner()
        result = runner.invoke(enrich_main, [str(slice_path), "--in-place"])
        assert result.exit_code == 0, result.output

        # File should have grown due to the appended extension segment,
        # and the whole original file is its prefix.
        enriched = slice_path.read_bytes()
        assert len(enriched) > len(original)
        assert enriched[:len(original)] == original

        # tmp path should no longer exist (replaced atomically).
        tmp_output = slice_path.with_suffix(slice_path.suffix + ".tmp")
        assert not tmp_output.exists()

        # The in-place file still iterates cleanly and carries the manifest.
        with open(slice_path, "rb") as f:
            block_types = [b.block_type for b in iterate_blocks(f)]
        assert BlockType.ModuleBuildIdManifest in block_types
        report = _verify(slice_path)
        assert report.valid, report.errors
        assert len(report.segments) == 1 and report.segments[0].verified

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
        assert not output_path.exists()

    def test_old_style_enriched_file_is_recognised(self, tmp_path):
        """A pre-1.1 enriched file carries its manifest before a replaced
        EoC (segment 0); its rows still count as enriched."""
        mod = ModuleEntry(base_addr=0x310000, module_size=4096, path="/bin/c2")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(
            slice_path, [(mod, _elf_page(b"\xdd" * 20))],
            capture_manifest=_manifest_for(mod, b"\x55" * 20),
        )
        assert _manifests(slice_path)[0][0] == 0  # sanity: in the capture segment

        output_path = tmp_path / "slice.enriched"
        result = CliRunner().invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        assert result.exit_code == 0, result.output
        assert "nothing to enrich" in result.output
        assert not output_path.exists()

    def test_trailing_bytes_are_refused(self, tmp_path):
        mod = ModuleEntry(base_addr=0x320000, module_size=4096, path="/bin/c3")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, _elf_page(b"\xee" * 20))])
        with open(slice_path, "ab") as f:
            f.write(b"\x00" * 64)

        output_path = tmp_path / "slice.enriched"
        result = CliRunner().invoke(
            enrich_main, [str(slice_path), "-o", str(output_path)]
        )
        assert result.exit_code == 1
        combined = result.output + (result.stderr_bytes or b"").decode()
        assert "trailing" in combined
        assert not output_path.exists()

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

    def test_existing_segment_is_kept_and_a_second_appended(self, tmp_path):
        """Module A is covered by an existing segment; only B is enriched,
        into a second segment appended after the first."""
        mod_a = ModuleEntry(base_addr=0x610000, module_size=4096, path="/bin/fa")
        mod_b = ModuleEntry(base_addr=0x620000, module_size=4096, path="/bin/fb")
        build_id_b = b"\x66" * 20
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(
            slice_path,
            [(mod_a, _elf_page(b"\x65" * 20)), (mod_b, _elf_page(build_id_b))],
            segment_manifest=_manifest_for(mod_a, b"\x65" * 20),
        )
        original = slice_path.read_bytes()

        output_path = tmp_path / "slice.enriched"
        _enrich(slice_path, output_path)

        enriched = output_path.read_bytes()
        assert enriched[:len(original)] == original
        report = _verify(output_path)
        assert report.valid, report.errors
        assert [s.producer for s in report.segments] == ["other/1", PRODUCER]
        assert all(s.verified for s in report.segments)
        manifests = _manifests(output_path)
        assert [segment for segment, _ in manifests] == [1, 2]
        rows = manifests[1][1].rows
        assert [r.base_addr for r in rows] == [mod_b.base_addr]
        assert rows[0].build_id == build_id_b


# ---------------------------------------------------------------------------
# Integrity chain continuity (spec Sections 4.4 and 4.6)
# ---------------------------------------------------------------------------


def _assert_chain_valid(path: Path) -> None:
    """The file verifies end to end: chain, FileHash, every segment, no trailing data."""
    report = _verify(path)
    assert report.valid, report.errors
    assert report.trailing_bytes == 0
    assert all(segment.verified for segment in report.segments)


def _enrich(slice_path: Path, output_path: Path) -> None:
    result = CliRunner().invoke(
        enrich_main, [str(slice_path), "-o", str(output_path)]
    )
    assert result.exit_code == 0, result.output


class TestEnrichChainContinuity:
    @pytest.mark.parametrize(
        "hash_algo,comp_algo",
        [
            (HashAlgo.BLAKE3, CompAlgo.NONE),
            (HashAlgo.SHA256, CompAlgo.NONE),
            (HashAlgo.SHA512_256, CompAlgo.NONE),
            (HashAlgo.BLAKE3, CompAlgo.LZ4),
            (HashAlgo.SHA256, CompAlgo.ZSTD),
        ],
    )
    def test_enriched_chain_and_file_hash_valid(self, tmp_path, hash_algo, comp_algo):
        mod = ModuleEntry(base_addr=0x700000, module_size=4096, path="/bin/g")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(
            slice_path, [(mod, _elf_page(b"\x22" * 20))],
            hash_algo=hash_algo, comp_algo=comp_algo,
        )
        _assert_chain_valid(slice_path)  # sanity: input is valid

        output_path = tmp_path / "slice.enriched"
        _enrich(slice_path, output_path)

        raw = output_path.read_bytes()
        assert read_hash_algo(io.BytesIO(raw)) == hash_algo
        _assert_chain_valid(output_path)

    def test_enriched_preamble_is_byte_identical(self, tmp_path):
        mod = ModuleEntry(base_addr=0x710000, module_size=4096, path="/bin/h")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(slice_path, [(mod, _elf_page(b"\x33" * 20))])
        output_path = tmp_path / "slice.enriched"
        _enrich(slice_path, output_path)

        original = slice_path.read_bytes()
        with open(slice_path, "rb") as f:
            eoc_end = [
                b.end_offset for b in iterate_blocks(f)
                if b.block_type == BlockType.EndOfCapture
            ][0]
        # The original EoC is preserved, not replaced.
        assert output_path.read_bytes()[:eoc_end] == original[:eoc_end]
        assert _verify(output_path).eoc_block_count == _verify(slice_path).eoc_block_count

    def test_second_run_has_nothing_to_enrich(self, tmp_path):
        """The manifest written by the first run covers the module, so a
        second run finds nothing to do and writes no file."""
        mod = ModuleEntry(base_addr=0x720000, module_size=4096, path="/bin/i")
        slice_path = tmp_path / "slice.msl"
        _synthesize_slice(
            slice_path, [(mod, _elf_page(b"\x44" * 20))],
            hash_algo=HashAlgo.SHA256,
        )
        once = tmp_path / "once.msl"
        twice = tmp_path / "twice.msl"
        _enrich(slice_path, once)
        once_bytes = once.read_bytes()

        result = CliRunner().invoke(enrich_main, [str(once), "-o", str(twice)])
        assert result.exit_code == 0, result.output
        assert "nothing to enrich" in result.output
        assert not twice.exists()
        assert once.read_bytes() == once_bytes

        types = [b.block_type for b in _records(once)]
        assert types.count(BlockType.ModuleBuildIdManifest) == 1
        assert types.count(BlockType.EndOfCapture) == 1
        _assert_chain_valid(once)


class TestWriterResume:
    def test_resume_writes_no_header_and_continues_chain(self):
        original = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # no ProcessIdentity in this fixture
            writer = MSLWriter(original, FileHeader(hash_algo=HashAlgo.SHA256))
            writer.write_module_list([ModuleEntry(base_addr=0x1000, path="/x")])
        prefix = original.getvalue()

        chain = IntegrityChain(hash_algo=HashAlgo.SHA256)
        chain.feed_header(prefix[:64])
        offset = 64
        block_count = 0
        while offset < len(prefix):
            length = struct.unpack_from("<I", prefix, offset + 8)[0]
            chain.feed_block(prefix[offset:offset + length])
            offset += length
            block_count += 1
        expected_prev = chain.prev_hash

        tail = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # no Block-0 warning on resume
            resumed = MSLWriter.resume(
                tail, FileHeader(hash_algo=HashAlgo.SHA256), chain,
                block_index=block_count,
            )
            resumed.finalize()
        tail_bytes = tail.getvalue()

        assert tail_bytes[:4] == BLOCK_MAGIC
        assert tail_bytes[0x30:0x50] == expected_prev
        report = verify_slice(io.BytesIO(prefix + tail_bytes))
        assert report.valid, report.errors
        assert report.file_hash_ok is True


# ---------------------------------------------------------------------------
# Encrypted slices: sealed extension segments (spec Section 10.8)
# ---------------------------------------------------------------------------

_PASSPHRASE = "correct horse"


class _NonSeekable(io.RawIOBase):
    """Write-only stream that, like a pipe, cannot seek (keeps CipherLen 0)."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b) -> int:
        self.data += bytes(b)
        return len(b)


def _encryption_params():
    from memslicer.msl.encryption import EncryptionParams
    return EncryptionParams(kdf_time=1, kdf_memory=8, kdf_lanes=1)


def _write_encrypted(output, modules_with_pages) -> None:
    """Write an encrypted capture holding a region + module per pair."""
    from memslicer.msl.constants import FLAG_ENCRYPTED
    from memslicer.msl.encryption import derive_key
    params = _encryption_params()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        writer = MSLWriter(
            output, FileHeader(pid=4242, flags=FLAG_ENCRYPTED),
            encryption_key=derive_key(_PASSPHRASE, params),
            encryption_params=params,
        )
        for mod, page in modules_with_pages:
            writer.write_memory_region(MemoryRegion(
                base_addr=mod.base_addr, region_size=4096, page_size=4096,
                region_type=RegionType.Image, page_states=[PageState.CAPTURED],
                page_data_chunks=[page],
            ))
        writer.write_module_list([m for m, _ in modules_with_pages])
        writer.finalize()


def _encrypted_slice_file(path: Path, modules_with_pages, seekable: bool = True) -> bytes:
    """Write an encrypted slice to *path*; non-seekable leaves CipherLen 0."""
    if seekable:
        with open(path, "wb") as f:
            _write_encrypted(f, modules_with_pages)
    else:
        stream = _NonSeekable()
        _write_encrypted(stream, modules_with_pages)
        path.write_bytes(bytes(stream.data))
    return path.read_bytes()


def _seal_manifest(path: Path, manifest: ModuleBuildIdManifest, producer: str) -> None:
    """Append *manifest* as the next sealed segment, independent of the CLI."""
    from memslicer.msl.constants import ENCRYPTED_HEADER_SIZE
    from memslicer.msl.iterator import decrypt_container
    from memslicer.msl.sealed import seal_segment
    with open(path, "rb") as f:
        c = decrypt_container(f, ENCRYPTED_HEADER_SIZE, _PASSPHRASE)
    buf = io.BytesIO()
    writer = MSLWriter.for_sealed_segment(buf, FileHeader(hash_algo=HashAlgo(c.header[0x3D])))
    writer.begin_extension()
    writer.write_module_build_id_manifest(manifest)
    writer.finalize_extension(producer)
    unit = seal_segment(c.cek, c.header, c.kem_ciphertext, c.last_tag,
                        len(c.sealed_segments) + 1, buf.getvalue())
    with open(path, "ab") as f:
        f.write(unit)


def _enrich_encrypted(args, passphrase: str = _PASSPHRASE):
    return CliRunner().invoke(enrich_main, [*args, "--passphrase", passphrase])


def _verify_encrypted(path: Path) -> VerifyReport:
    with open(path, "rb") as f:
        return verify_slice(f, _PASSPHRASE)


def _encrypted_manifests(path: Path) -> list[tuple[int, ModuleBuildIdManifest]]:
    """``(seal_index, manifest)`` for every ModuleBuildIdManifest block."""
    with open(path, "rb") as f:
        records = list(iterate_blocks(f, _PASSPHRASE))
    return [
        (b.seal_index, parse_module_build_id_manifest(b.payload))
        for b in records if b.block_type == BlockType.ModuleBuildIdManifest
    ]


def _combined_output(result) -> str:
    return result.output + (result.stderr_bytes or b"").decode()


class TestEnrichEncrypted:
    def _slice(self, tmp_path, *pairs, seekable=True):
        path = tmp_path / "enc.msl"
        original = _encrypted_slice_file(path, list(pairs), seekable)
        return path, original

    def test_appends_a_sealed_segment(self, tmp_path):
        build_id = b"\x71" * 20
        mod = ModuleEntry(base_addr=0x710000, module_size=4096, path="/bin/e1")
        path, original = self._slice(tmp_path, (mod, _elf_page(build_id)))
        output = tmp_path / "enc.enriched"

        result = _enrich_encrypted([str(path), "-o", str(output)])

        assert result.exit_code == 0, _combined_output(result)
        assert path.read_bytes() == original
        enriched = output.read_bytes()
        assert enriched[:len(original)] == original
        report = _verify_encrypted(output)
        assert report.valid, report.errors
        assert len(report.sealed_segments) == 1
        assert report.sealed_segments[0].producer == PRODUCER
        assert report.sealed_trailing_bytes == 0
        manifests = _encrypted_manifests(output)
        assert [index for index, _ in manifests] == [1]
        assert manifests[0][1].rows[0].build_id == build_id
        assert manifests[0][1].rows[0].base_addr == mod.base_addr

    def test_in_place_appends_to_the_original(self, tmp_path):
        mod = ModuleEntry(base_addr=0x720000, module_size=4096, path="/bin/e2")
        path, original = self._slice(tmp_path, (mod, _elf_page(b"\x72" * 20)))

        result = _enrich_encrypted([str(path), "--in-place"])

        assert result.exit_code == 0, _combined_output(result)
        assert path.read_bytes()[:len(original)] == original
        assert not path.with_suffix(".msl.tmp").exists()
        report = _verify_encrypted(path)
        assert report.valid and len(report.sealed_segments) == 1

    def test_second_enrichment_sees_the_first(self, tmp_path):
        """A is covered by sealed segment 1; only B lands in sealed segment 2,
        and a further run finds nothing left to enrich."""
        mod_a = ModuleEntry(base_addr=0x730000, module_size=4096, path="/bin/ea")
        mod_b = ModuleEntry(base_addr=0x740000, module_size=4096, path="/bin/eb")
        build_id_b = b"\x74" * 20
        path, _ = self._slice(
            tmp_path, (mod_a, _elf_page(b"\x73" * 20)), (mod_b, _elf_page(build_id_b)),
        )
        _seal_manifest(path, _manifest_for(mod_a, b"\x73" * 20), "other/1")

        first = _enrich_encrypted([str(path), "--in-place"])
        assert first.exit_code == 0, _combined_output(first)
        after_first = path.read_bytes()
        second = _enrich_encrypted([str(path), "--in-place"])

        assert second.exit_code == 0, _combined_output(second)
        assert "nothing to enrich" in second.output
        assert path.read_bytes() == after_first
        report = _verify_encrypted(path)
        assert report.valid, report.errors
        assert [s.producer for s in report.sealed_segments] == ["other/1", PRODUCER]
        manifests = _encrypted_manifests(path)
        assert [index for index, _ in manifests] == [1, 2]
        assert [r.base_addr for r in manifests[1][1].rows] == [mod_b.base_addr]
        assert manifests[1][1].rows[0].build_id == build_id_b

    def test_wrong_passphrase_is_refused(self, tmp_path):
        mod = ModuleEntry(base_addr=0x750000, module_size=4096, path="/bin/e5")
        path, original = self._slice(tmp_path, (mod, _elf_page(b"\x75" * 20)))

        result = _enrich_encrypted([str(path), "--in-place"], passphrase="wrong")

        assert result.exit_code != 0
        assert "could not decrypt" in _combined_output(result)
        assert path.read_bytes() == original

    def test_cipher_len_zero_is_refused(self, tmp_path):
        mod = ModuleEntry(base_addr=0x760000, module_size=4096, path="/bin/e6")
        path, original = self._slice(tmp_path, (mod, _elf_page(b"\x76" * 20)), seekable=False)
        output = tmp_path / "enc.enriched"

        in_place = _enrich_encrypted([str(path), "--in-place"])
        to_output = _enrich_encrypted([str(path), "-o", str(output)])

        for result in (in_place, to_output):
            assert result.exit_code == 1
            assert "sealed without CipherLen" in _combined_output(result)
        assert path.read_bytes() == original
        assert not output.exists()

    def test_trailing_data_is_refused(self, tmp_path):
        mod = ModuleEntry(base_addr=0x770000, module_size=4096, path="/bin/e7")
        path, _ = self._slice(tmp_path, (mod, _elf_page(b"\x77" * 20)))
        with open(path, "ab") as f:
            f.write(b"\x00" * 64)
        original = path.read_bytes()
        output = tmp_path / "enc.enriched"

        in_place = _enrich_encrypted([str(path), "--in-place"])
        to_output = _enrich_encrypted([str(path), "-o", str(output)])

        for result in (in_place, to_output):
            assert result.exit_code == 1
            assert "trailing" in _combined_output(result)
        assert path.read_bytes() == original
        assert not output.exists()

    def test_passphrase_is_prompted_when_missing(self, tmp_path):
        mod = ModuleEntry(base_addr=0x780000, module_size=4096, path="/bin/e8")
        path, _ = self._slice(tmp_path, (mod, _elf_page(b"\x78" * 20)))

        result = CliRunner().invoke(
            enrich_main, [str(path), "--in-place"], input=f"{_PASSPHRASE}\n",
        )

        assert result.exit_code == 0, _combined_output(result)
        assert "Passphrase" in result.output
        assert _PASSPHRASE not in result.output
        assert len(_verify_encrypted(path).sealed_segments) == 1


def test_append_refuses_a_file_that_changed_size(tmp_path):
    """The single append only happens when the file still ends at sealed_end."""
    from memslicer.cli_enrich import _append_sealed_segment
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="changed since it was read"):
        _append_sealed_segment(target, 9, b"unit")
    assert target.read_bytes() == b"x" * 10
    _append_sealed_segment(target, 10, b"unit")
    assert target.read_bytes() == b"x" * 10 + b"unit"
