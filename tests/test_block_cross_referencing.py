"""Verify block cross-referencing (ParentUUID) in MSL output.

Spec Section 8 requirements:
- Layer 1: ParentUUID establishes "belongs-to" hierarchy
  - ModuleEntry -> ModuleListIndex (ParentUUID points to MLI's BlockUUID)
  - ProcessIdentity, ModuleListIndex, MemoryRegion, EndOfCapture: ParentUUID = zeros
- Layer 2: Payload-embedded UUIDs for non parent-child relationships
  - ModuleListIndex manifest ModuleUUIDs must match ModuleEntry BlockUUIDs
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    BlockType,
    HEADER_SIZE,
    FILE_MAGIC,
)

ZERO_UUID = b"\x00" * 16


# ---------------------------------------------------------------------------
# MockBridge (self-contained for this test module)
# ---------------------------------------------------------------------------

class _MockBridge:
    """Minimal mock bridge that provides 2 ranges + 3 modules."""

    def __init__(self) -> None:
        self._page_size = 4096
        self._ranges = [
            MemoryRange(base=0x10000, size=4096, protection="rw-", file_path=""),
            MemoryRange(base=0x20000, size=4096, protection="r-x", file_path="/lib/libc.so"),
        ]
        self._modules = [
            ModuleInfo(name="libc.so", path="/usr/lib/libc.so", base=0x400000, size=0x10000),
            ModuleInfo(name="libm.so", path="/usr/lib/libm.so", base=0x500000, size=0x8000),
            ModuleInfo(name="app", path="/usr/bin/app", base=0x600000, size=0x4000),
        ]
        self._memory = {
            0x10000: b"\xaa" * 4096,
            0x20000: b"\xbb" * 4096,
        }

    def connect(self) -> None:
        pass

    def get_platform_info(self) -> PlatformInfo:
        from memslicer.msl.constants import ArchType, OSType
        return PlatformInfo(arch=ArchType.x86_64, os=OSType.Linux, pid=9999, page_size=self._page_size)

    def enumerate_ranges(self) -> list[MemoryRange]:
        return list(self._ranges)

    def enumerate_modules(self) -> list[ModuleInfo]:
        return list(self._modules)

    def read_memory(self, address: int, size: int) -> bytes | None:
        data = self._memory.get(address)
        if data is None:
            return None
        return data[:size]

    def disconnect(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Block parser
# ---------------------------------------------------------------------------

def _parse_blocks(data: bytes) -> list[dict]:
    """Parse all blocks from an MSL file, returning a list of block info dicts."""
    assert data[:8] == FILE_MAGIC, "Not a valid MSL file"
    offset = HEADER_SIZE
    blocks = []
    while offset + BLOCK_HEADER_SIZE <= len(data):
        magic = data[offset:offset + 4]
        if magic != BLOCK_MAGIC:
            break
        block_type_raw, flags, block_length, payload_version, reserved = struct.unpack_from(
            "<HHIHH", data, offset + 4,
        )
        block_uuid = data[offset + 16:offset + 32]
        parent_uuid = data[offset + 32:offset + 48]

        blocks.append({
            "offset": offset,
            "block_type": block_type_raw,
            "block_type_name": _block_type_name(block_type_raw),
            "flags": flags,
            "block_length": block_length,
            "block_uuid": block_uuid,
            "parent_uuid": parent_uuid,
            "payload": data[offset + BLOCK_HEADER_SIZE:offset + block_length],
        })
        offset += block_length
    return blocks


def _block_type_name(bt: int) -> str:
    try:
        return BlockType(bt).name
    except ValueError:
        return f"Unknown(0x{bt:04x})"


def _parse_module_list_manifest(payload: bytes) -> list[bytes]:
    """Extract ModuleUUIDs from the ModuleListIndex manifest payload.

    Layout: count(4) + reserved(4) + per-entry records.
    Each entry starts with a 16-byte ModuleUUID, followed by
    BaseAddr(8) + ModuleSize(8) + PathLen(2) + Reserved(2) + Reserved2(4) + Path(var, pad8).
    """
    count = struct.unpack_from("<I", payload, 0)[0]
    uuids: list[bytes] = []
    offset = 8  # skip count + reserved

    for _ in range(count):
        mod_uuid = payload[offset:offset + 16]
        uuids.append(mod_uuid)
        # BaseAddr(8) + ModuleSize(8) + PathLen(2) + Reserved(2) + Reserved2(4)
        _, _, path_len, _, _ = struct.unpack_from("<QQHHI", payload, offset + 16)
        padded_path_len = (path_len + 7) & ~7
        offset += 16 + 8 + 8 + 2 + 2 + 4 + padded_path_len

    return uuids


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBlockCrossReferencing:
    """Verify ParentUUID cross-referencing in MSL output per Spec Section 8."""

    @pytest.fixture()
    def msl_blocks(self, tmp_path: Path) -> list[dict]:
        bridge = _MockBridge()
        engine = AcquisitionEngine(bridge)
        output = tmp_path / "cross_ref_test.msl"
        result = engine.acquire(output)
        assert result.regions_captured == 2
        assert result.modules_captured == 3
        raw = output.read_bytes()
        blocks = _parse_blocks(raw)
        assert len(blocks) > 0, "No blocks found in MSL file"
        return blocks

    def _blocks_by_type(self, blocks: list[dict], bt: BlockType) -> list[dict]:
        return [b for b in blocks if b["block_type"] == bt]

    def _all_block_uuids(self, blocks: list[dict]) -> set[bytes]:
        return {b["block_uuid"] for b in blocks}

    # --- ProcessIdentity ---

    def test_process_identity_has_zero_parent(self, msl_blocks: list[dict]):
        pi_blocks = self._blocks_by_type(msl_blocks, BlockType.ProcessIdentity)
        assert len(pi_blocks) == 1, "Expected exactly one ProcessIdentity block"
        assert pi_blocks[0]["parent_uuid"] == ZERO_UUID, (
            f"ProcessIdentity ParentUUID should be zeros, got {pi_blocks[0]['parent_uuid'].hex()}"
        )

    # --- ModuleListIndex ---

    def test_module_list_index_has_zero_parent(self, msl_blocks: list[dict]):
        mli_blocks = self._blocks_by_type(msl_blocks, BlockType.ModuleListIndex)
        assert len(mli_blocks) == 1, "Expected exactly one ModuleListIndex block"
        assert mli_blocks[0]["parent_uuid"] == ZERO_UUID, (
            f"ModuleListIndex ParentUUID should be zeros, got {mli_blocks[0]['parent_uuid'].hex()}"
        )

    # --- ModuleEntry blocks: ParentUUID == ModuleListIndex's BlockUUID ---

    def test_module_entries_parent_is_mli(self, msl_blocks: list[dict]):
        mli_blocks = self._blocks_by_type(msl_blocks, BlockType.ModuleListIndex)
        assert len(mli_blocks) == 1
        mli_uuid = mli_blocks[0]["block_uuid"]

        me_blocks = self._blocks_by_type(msl_blocks, BlockType.ModuleEntry)
        assert len(me_blocks) == 3, f"Expected 3 ModuleEntry blocks, got {len(me_blocks)}"

        for i, me in enumerate(me_blocks):
            assert me["parent_uuid"] == mli_uuid, (
                f"ModuleEntry[{i}] ParentUUID ({me['parent_uuid'].hex()}) "
                f"does not match ModuleListIndex BlockUUID ({mli_uuid.hex()})"
            )

    # --- MemoryRegion blocks: ParentUUID = zeros (non-investigation mode) ---

    def test_memory_regions_have_zero_parent(self, msl_blocks: list[dict]):
        mr_blocks = self._blocks_by_type(msl_blocks, BlockType.MemoryRegion)
        assert len(mr_blocks) == 2, f"Expected 2 MemoryRegion blocks, got {len(mr_blocks)}"

        for i, mr in enumerate(mr_blocks):
            assert mr["parent_uuid"] == ZERO_UUID, (
                f"MemoryRegion[{i}] ParentUUID should be zeros, got {mr['parent_uuid'].hex()}"
            )

    # --- EndOfCapture: ParentUUID = zeros ---

    def test_end_of_capture_has_zero_parent(self, msl_blocks: list[dict]):
        eoc_blocks = self._blocks_by_type(msl_blocks, BlockType.EndOfCapture)
        assert len(eoc_blocks) == 1, "Expected exactly one EndOfCapture block"
        assert eoc_blocks[0]["parent_uuid"] == ZERO_UUID, (
            f"EndOfCapture ParentUUID should be zeros, got {eoc_blocks[0]['parent_uuid'].hex()}"
        )

    # --- No block references a non-existent parent ---

    def test_no_dangling_parent_references(self, msl_blocks: list[dict]):
        all_uuids = self._all_block_uuids(msl_blocks)
        for block in msl_blocks:
            parent = block["parent_uuid"]
            if parent == ZERO_UUID:
                continue
            assert parent in all_uuids, (
                f"Block {block['block_type_name']} at offset {block['offset']} "
                f"references non-existent parent {parent.hex()}"
            )

    # --- ModuleListIndex manifest UUIDs match ModuleEntry BlockUUIDs ---

    def test_manifest_uuids_match_module_entries(self, msl_blocks: list[dict]):
        mli_blocks = self._blocks_by_type(msl_blocks, BlockType.ModuleListIndex)
        assert len(mli_blocks) == 1
        manifest_uuids = _parse_module_list_manifest(mli_blocks[0]["payload"])

        me_blocks = self._blocks_by_type(msl_blocks, BlockType.ModuleEntry)
        me_uuids = [b["block_uuid"] for b in me_blocks]

        assert len(manifest_uuids) == len(me_uuids), (
            f"Manifest has {len(manifest_uuids)} UUIDs but there are {len(me_uuids)} ModuleEntry blocks"
        )

        for i, (manifest_uuid, entry_uuid) in enumerate(zip(manifest_uuids, me_uuids)):
            assert manifest_uuid == entry_uuid, (
                f"Manifest UUID[{i}] ({manifest_uuid.hex()}) does not match "
                f"ModuleEntry[{i}] BlockUUID ({entry_uuid.hex()})"
            )

    # --- Summary: block type counts ---

    def test_expected_block_count(self, msl_blocks: list[dict]):
        """Verify the total number of blocks: 1 PI + 1 MLI + 3 ME + 2 MR + 1 EoC = 8."""
        assert len(msl_blocks) == 8, (
            f"Expected 8 blocks total, got {len(msl_blocks)}: "
            + ", ".join(b["block_type_name"] for b in msl_blocks)
        )
