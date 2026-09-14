"""All four acquisition modes, and the block positions spec Section 2.1 fixes.

Table 1 of the spec crosses the Investigation flag with the Encrypted flag:

    Investigation  Encrypted  HeaderSize  Block 2
    0              0          64          Memory Region or other capture-time
    0              1          128         Memory Region or other (encrypted)
    1              0          64          System Context (0x0050, REQUIRED)
    1              1          128         System Context (0x0050, REQUIRED)

The REQUIRED rows are the reason ModuleEntry children are emitted after the
memory regions rather than straight after their index: written eagerly they
occupied Blocks 2..N+1 and pushed System Context out of the slot the spec
reserves for it.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.msl.constants import (
    ENCRYPTED_HEADER_SIZE, FLAG_ENCRYPTED, FLAG_INVESTIGATION, HEADER_SIZE,
    BlockType,
)
from memslicer.msl.encryption import (
    StreamingDecryptor, derive_key, unpack_encryption_extension,
)

from test_engine import MockBridge, MockCollector


PASSPHRASE = "correct horse battery staple"


def _bridge(modules: list[ModuleInfo] | None = None) -> MockBridge:
    mods = [ModuleInfo(name="libc.so", path="/usr/lib/libc.so",
                       base=0x400000, size=0x1000)] if modules is None else modules
    return MockBridge(
        ranges=[MemoryRange(base=0x10000, size=4096, protection="rw-", file_path=""),
                MemoryRange(base=0x20000, size=4096, protection="rw-", file_path="")],
        modules=mods,
        memory={0x10000: b"\xaa" * 4096, 0x20000: b"\xbb" * 4096},
    )


def _capture(tmp_path: Path, *, investigation: bool, encrypted: bool,
             modules: list[ModuleInfo] | None = None) -> Path:
    out = tmp_path / f"i{int(investigation)}e{int(encrypted)}.msl"
    AcquisitionEngine(
        _bridge(modules),
        investigation=investigation,
        collector=MockCollector() if investigation else None,
        passphrase=PASSPHRASE if encrypted else None,
    ).acquire(out)
    return out


def _block_types(stream: bytes, start: int) -> list[str]:
    off, names = start, []
    while off + 80 <= len(stream) and stream[off:off + 4] == b"MSLC":
        block_type, _flags, length = struct.unpack_from("<HHI", stream, off + 4)
        names.append(BlockType(block_type).name)
        off += length
    return names


def _plaintext_blocks(path: Path) -> list[str]:
    """Block types of *path*, decrypting first when the slice is encrypted."""
    raw = path.read_bytes()
    flags = struct.unpack_from("<I", raw, 0x0C)[0]
    if not flags & FLAG_ENCRYPTED:
        return _block_types(raw, raw[9])

    header = raw[:ENCRYPTED_HEADER_SIZE]
    params = unpack_encryption_extension(header[HEADER_SIZE:])
    decryptor = StreamingDecryptor(
        key=derive_key(PASSPHRASE, params), nonce=params.nonce, aad=header,
    )
    decryptor.update(raw[ENCRYPTED_HEADER_SIZE:-16])
    return _block_types(decryptor.finalize(raw[-16:]), 0)


ALL_MODES = [
    pytest.param(False, False, id="analysis-plain"),
    pytest.param(False, True, id="analysis-encrypted"),
    pytest.param(True, False, id="investigation-plain"),
    pytest.param(True, True, id="investigation-encrypted"),
]


@pytest.mark.parametrize("investigation,encrypted", ALL_MODES)
class TestTableOne:
    """Every row of spec Table 1 must be producible and correctly marked."""

    def test_flags_match_the_mode(self, tmp_path, investigation, encrypted):
        raw = _capture(tmp_path, investigation=investigation,
                       encrypted=encrypted).read_bytes()
        flags = struct.unpack_from("<I", raw, 0x0C)[0]
        assert bool(flags & FLAG_INVESTIGATION) is investigation
        assert bool(flags & FLAG_ENCRYPTED) is encrypted

    def test_header_size_matches_the_mode(self, tmp_path, investigation, encrypted):
        raw = _capture(tmp_path, investigation=investigation,
                       encrypted=encrypted).read_bytes()
        expected = ENCRYPTED_HEADER_SIZE if encrypted else HEADER_SIZE
        assert raw[9] == expected, "HeaderSize byte at 0x09"

    def test_block_zero_and_one(self, tmp_path, investigation, encrypted):
        names = _plaintext_blocks(
            _capture(tmp_path, investigation=investigation, encrypted=encrypted))
        assert names[0] == "ProcessIdentity"
        assert names[1] == "ModuleListIndex"

    def test_last_block_is_end_of_capture(self, tmp_path, investigation, encrypted):
        names = _plaintext_blocks(
            _capture(tmp_path, investigation=investigation, encrypted=encrypted))
        assert names[-1] == "EndOfCapture"


class TestBlockTwo:
    """Block 2 per Table 1, in both investigation modes and both module cases."""

    @pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
    @pytest.mark.parametrize("modules", [None, []], ids=["with-modules", "no-modules"])
    def test_investigation_block_two_is_system_context(self, tmp_path, encrypted, modules):
        names = _plaintext_blocks(
            _capture(tmp_path, investigation=True, encrypted=encrypted, modules=modules))
        assert names[2] == "SystemContext", f"got {names[:4]}"

    @pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
    def test_analysis_block_two_is_a_capture_time_block(self, tmp_path, encrypted):
        names = _plaintext_blocks(
            _capture(tmp_path, investigation=False, encrypted=encrypted))
        assert names[2] == "MemoryRegion", f"got {names[:4]}"


class TestModuleEntriesComeLate:
    """The children must trail the memory regions, as Figures 2 and 3 draw them."""

    def test_entries_follow_the_regions(self, tmp_path):
        names = _plaintext_blocks(_capture(tmp_path, investigation=True, encrypted=False))
        assert names.index("MemoryRegion") < names.index("ModuleEntry")

    def test_index_is_still_block_one(self, tmp_path):
        names = _plaintext_blocks(_capture(tmp_path, investigation=True, encrypted=False))
        assert names[1] == "ModuleListIndex"

    def test_index_written_even_with_no_modules(self, tmp_path):
        names = _plaintext_blocks(
            _capture(tmp_path, investigation=False, encrypted=False, modules=[]))
        assert names[1] == "ModuleListIndex"
        assert "ModuleEntry" not in names


class TestEncryptedReadBack:
    """Every mode the tool can write, it must also be able to read."""

    def _slice(self, tmp_path, *, investigation, encrypted):
        return _capture(tmp_path, investigation=investigation, encrypted=encrypted)

    @pytest.mark.parametrize("investigation,encrypted", ALL_MODES)
    def test_every_mode_round_trips(self, tmp_path, investigation, encrypted):
        from memslicer.msl.iterator import iterate_blocks
        path = self._slice(tmp_path, investigation=investigation, encrypted=encrypted)
        with open(path, "rb") as f:
            blocks = list(iterate_blocks(f, passphrase=PASSPHRASE if encrypted else None))
        assert blocks, "no blocks read back"
        assert blocks[0].block_type == BlockType.ProcessIdentity
        assert blocks[-1].block_type == BlockType.EndOfCapture

    def test_investigation_encrypted_block_two_survives_round_trip(self, tmp_path):
        from memslicer.msl.iterator import iterate_blocks
        path = self._slice(tmp_path, investigation=True, encrypted=True)
        with open(path, "rb") as f:
            blocks = list(iterate_blocks(f, passphrase=PASSPHRASE))
        assert blocks[2].block_type == BlockType.SystemContext

    def test_encrypted_slice_without_passphrase_is_refused(self, tmp_path):
        from memslicer.msl.iterator import iterate_blocks
        path = self._slice(tmp_path, investigation=False, encrypted=True)
        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="without a passphrase"):
                list(iterate_blocks(f))

    def test_wrong_passphrase_is_refused(self, tmp_path):
        from memslicer.msl.iterator import iterate_blocks
        path = self._slice(tmp_path, investigation=False, encrypted=True)
        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="could not decrypt"):
                list(iterate_blocks(f, passphrase="wrong"))

    def test_tampered_ciphertext_is_refused(self, tmp_path):
        """The AEAD tag must catch modification after capture."""
        from memslicer.msl.iterator import iterate_blocks
        path = self._slice(tmp_path, investigation=False, encrypted=True)
        raw = bytearray(path.read_bytes())
        raw[ENCRYPTED_HEADER_SIZE + 10] ^= 0xFF
        path.write_bytes(bytes(raw))
        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="could not decrypt"):
                list(iterate_blocks(f, passphrase=PASSPHRASE))

    def test_header_size_is_read_from_the_file(self, tmp_path):
        """A 128-byte header must be located from offset 0x09, not assumed."""
        from memslicer.msl.iterator import is_encrypted
        enc = self._slice(tmp_path, investigation=False, encrypted=True)
        plain = self._slice(tmp_path, investigation=False, encrypted=False)
        with open(enc, "rb") as f:
            assert is_encrypted(f) is True
        with open(plain, "rb") as f:
            assert is_encrypted(f) is False

    def test_enrich_refuses_encrypted_with_a_reason(self, tmp_path):
        from memslicer.cli_enrich import _load_slice
        path = self._slice(tmp_path, investigation=False, encrypted=True)
        with pytest.raises(ValueError, match="re-seal the container"):
            _load_slice(path)


class TestUnrepresentableProcessTableRows:
    """A single odd row in the system process table must not end a capture.

    macOS `ps` prints uids signed, so a process running as `nobody` reports
    -2. UID is a uint32 in the block, so packing that row raised struct.error
    and aborted the whole investigation capture at the process table.
    """

    def _writer(self):
        import io
        from memslicer.msl.constants import CompAlgo
        from memslicer.msl.types import FileHeader, ProcessIdentity, SystemContext
        from memslicer.msl.writer import MSLWriter
        writer = MSLWriter(io.BytesIO(), FileHeader(pid=1), CompAlgo.NONE)
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.write_module_list_index([])
        return writer, writer.write_system_context(SystemContext())

    def _row(self, pid, uid):
        from memslicer.msl.types import ProcessEntry
        return ProcessEntry(pid=pid, ppid=1, uid=uid, start_time=0, rss=4096,
                            exe_name=f"p{pid}", cmd_line="", user="")

    def test_negative_uid_row_is_dropped_not_fatal(self):
        writer, parent = self._writer()
        rows = [self._row(1, 0), self._row(1146, -2), self._row(2, 501)]
        writer.write_process_table(rows, parent_uuid=parent)  # used to raise

    def test_entry_count_matches_rows_actually_written(self):
        """EntryCount must not promise a row that was dropped."""
        import io
        import struct as _s
        from memslicer.msl.constants import (
            BLOCK_HEADER_SIZE, CompAlgo, HEADER_SIZE,
        )
        from memslicer.msl.types import FileHeader, ProcessIdentity, SystemContext
        from memslicer.msl.writer import MSLWriter

        buf = io.BytesIO()
        writer = MSLWriter(buf, FileHeader(pid=1), CompAlgo.NONE)
        writer.write_process_identity(ProcessIdentity(exe_path="/x"))
        writer.write_module_list_index([])
        parent = writer.write_system_context(SystemContext())
        writer.write_process_table(
            [self._row(1, 0), self._row(1146, -2), self._row(2, 501)],
            parent_uuid=parent,
        )
        raw = buf.getvalue()
        off = HEADER_SIZE
        while off + BLOCK_HEADER_SIZE <= len(raw):
            block_type, _flags, length = _s.unpack_from("<HHI", raw, off + 4)
            if block_type == BlockType.ProcessTable:
                count = _s.unpack_from("<I", raw, off + BLOCK_HEADER_SIZE)[0]
                assert count == 2, "dropped row must not be counted"
                return
            off += length
        pytest.fail("no ProcessTable block written")

    def test_valid_rows_are_all_kept(self):
        writer, parent = self._writer()
        writer.write_process_table([self._row(i, 501) for i in range(5)],
                                   parent_uuid=parent)


class TestDarwinUidNormalisation:
    """The collector should not hand the writer a value it cannot pack."""

    def test_negative_uid_becomes_its_unsigned_form(self):
        from memslicer.acquirer.collectors.darwin import DarwinCollector
        entry = DarwinCollector()._parse_ps_line("1146 1 -2 100 dhcp6d /usr/libexec/dhcp6d", 1)
        assert entry is not None
        assert entry.uid == 0xFFFFFFFE, "nobody is 4294967294 unsigned"

    def test_ordinary_uid_is_untouched(self):
        from memslicer.acquirer.collectors.darwin import DarwinCollector
        entry = DarwinCollector()._parse_ps_line("500 1 501 100 bash /bin/bash", 1)
        assert entry is not None
        assert entry.uid == 501
