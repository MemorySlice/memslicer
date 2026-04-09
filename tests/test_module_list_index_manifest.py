"""Verification script for ModuleListIndex manifest structure (Table 13, Figure 7).

Checks:
1. EntryCount in manifest matches number of modules
2. Per-entry fields: ModuleUUID(16) + BaseAddr(8) + ModuleSize(8) + PathLen(2) + Reserved(2) + Reserved2(4) + Path(var, pad8)
3. ModuleEntry block UUIDs match ModuleUUIDs in manifest
4. BaseAddr and ModuleSize match between manifest and ModuleEntry
5. PathLen is pre-padding length (not padded length)
"""
from __future__ import annotations

import io
import struct
import uuid

from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    BlockType,
    CompAlgo,
    HEADER_SIZE,
    HAS_CHILDREN,
)
from memslicer.msl.types import FileHeader, ModuleEntry
from memslicer.msl.writer import MSLWriter
from memslicer.utils.padding import pad8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_all_blocks(data: bytes) -> list[dict]:
    """Parse all blocks from raw MSL data (after the 64-byte file header)."""
    offset = HEADER_SIZE
    blocks: list[dict] = []
    while offset + BLOCK_HEADER_SIZE <= len(data):
        magic = data[offset : offset + 4]
        if magic != BLOCK_MAGIC:
            break
        (
            _magic,
            block_type,
            flags,
            block_length,
            payload_version,
            reserved,
        ) = struct.unpack_from("<4sHHIHH", data, offset)
        # Layout: magic(4) + type(2) + flags(2) + length(4) + payloadVer(2) + reserved(2)
        #         + blockUUID(16) + parentUUID(16) + prevHash(32) = 80
        block_uuid = data[offset + 16 : offset + 32]
        parent_uuid = data[offset + 32 : offset + 48]

        payload_start = offset + BLOCK_HEADER_SIZE
        payload_end = offset + block_length
        payload = data[payload_start:payload_end]

        blocks.append(
            {
                "type": block_type,
                "flags": flags,
                "block_length": block_length,
                "block_uuid": block_uuid,
                "parent_uuid": parent_uuid,
                "payload": payload,
                "offset": offset,
            }
        )
        offset += block_length
    return blocks


def _parse_manifest_entries(payload: bytes) -> tuple[int, list[dict]]:
    """Parse the ModuleListIndex payload into entry count and entry list."""
    entry_count, _reserved = struct.unpack_from("<II", payload, 0)
    offset = 8
    entries = []
    for _ in range(entry_count):
        mod_uuid = payload[offset : offset + 16]
        offset += 16
        base_addr, mod_size, path_len, reserved, reserved2 = struct.unpack_from(
            "<QQHHI", payload, offset
        )
        offset += 8 + 8 + 2 + 2 + 4  # = 24
        path_raw = payload[offset : offset + path_len]
        padded_path_len = pad8(path_len)
        offset += padded_path_len
        entries.append(
            {
                "module_uuid": mod_uuid,
                "base_addr": base_addr,
                "module_size": mod_size,
                "path_len": path_len,
                "path_raw": path_raw,
                "reserved": reserved,
                "reserved2": reserved2,
            }
        )
    return entry_count, entries


def _parse_module_entry_payload(payload: bytes) -> dict:
    """Parse a ModuleEntry block's payload."""
    base_addr, mod_size, path_len, version_len, reserved = struct.unpack_from(
        "<QQHHI", payload, 0
    )
    offset = 8 + 8 + 2 + 2 + 4  # 24
    padded_path_len = pad8(path_len)
    path_raw = payload[offset : offset + path_len]
    offset += padded_path_len
    padded_version_len = pad8(version_len)
    version_raw = payload[offset : offset + version_len]
    offset += padded_version_len
    return {
        "base_addr": base_addr,
        "module_size": mod_size,
        "path_len": path_len,
        "path_raw": path_raw,
        "version_len": version_len,
        "version_raw": version_raw,
    }


# ---------------------------------------------------------------------------
# Test modules
# ---------------------------------------------------------------------------

MODULE_A = ModuleEntry(
    base_addr=0x00007FFF_DDA00000,
    module_size=0x001A3000,
    path="/usr/lib/libc.so.6",
    version="2.38",
    disk_hash=b"\xAA" * 32,
    native_blob=b"",
)

MODULE_B = ModuleEntry(
    base_addr=0x00007FFF_DD000000,
    module_size=0x00050000,
    path="/usr/lib/libpthread.so.0",
    version="2.38",
    disk_hash=b"\xBB" * 32,
    native_blob=b"",
)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_module_list_index_manifest():
    """Full verification of ModuleListIndex manifest structure."""
    # --- Step 1: Create MSL with 2 modules ---
    buf = io.BytesIO()
    header = FileHeader(timestamp_ns=1_000_000_000)
    writer = MSLWriter(buf, header, CompAlgo.NONE)
    writer.write_module_list([MODULE_A, MODULE_B])
    writer.finalize()

    raw = buf.getvalue()
    blocks = _parse_all_blocks(raw)

    # --- Step 2: Find ModuleListIndex ---
    idx_blocks = [b for b in blocks if b["type"] == BlockType.ModuleListIndex]
    assert len(idx_blocks) == 1, "Expected exactly one ModuleListIndex block"
    idx_block = idx_blocks[0]

    # --- Step 3: Parse manifest payload ---
    entry_count, manifest_entries = _parse_manifest_entries(idx_block["payload"])

    results: list[tuple[str, bool, str]] = []

    # CHECK 1: EntryCount == 2
    ok = entry_count == 2
    results.append(("EntryCount == 2", ok, f"got {entry_count}"))

    # CHECK 2: HAS_CHILDREN flag set on index block
    ok = bool(idx_block["flags"] & HAS_CHILDREN)
    results.append(("HAS_CHILDREN flag set", ok, f"flags=0x{idx_block['flags']:04X}"))

    # --- Step 4: Find ModuleEntry blocks ---
    mod_blocks = [b for b in blocks if b["type"] == BlockType.ModuleEntry]
    ok = len(mod_blocks) == 2
    results.append(("Found 2 ModuleEntry blocks", ok, f"got {len(mod_blocks)}"))

    # --- Step 5: Verify each entry ---
    expected_modules = [MODULE_A, MODULE_B]
    for i, (manifest_entry, expected_mod) in enumerate(
        zip(manifest_entries, expected_modules)
    ):
        prefix = f"Module[{i}]"

        # CHECK 3: ModuleEntry BlockUUID matches manifest ModuleUUID
        matching_block = None
        for mb in mod_blocks:
            if mb["block_uuid"] == manifest_entry["module_uuid"]:
                matching_block = mb
                break
        ok = matching_block is not None
        results.append(
            (
                f"{prefix} BlockUUID matches manifest ModuleUUID",
                ok,
                f"manifest_uuid={manifest_entry['module_uuid'].hex()}"
                + (
                    f", found block_uuid={matching_block['block_uuid'].hex()}"
                    if matching_block
                    else ", NO MATCHING BLOCK"
                ),
            )
        )

        if matching_block is None:
            results.append((f"{prefix} (skipping remaining checks - no block)", False, ""))
            continue

        # CHECK 4: ModuleEntry parent_uuid == index block UUID
        ok = matching_block["parent_uuid"] == idx_block["block_uuid"]
        results.append(
            (
                f"{prefix} parent_uuid matches index block",
                ok,
                f"parent={matching_block['parent_uuid'].hex()}, index={idx_block['block_uuid'].hex()}",
            )
        )

        # Parse the ModuleEntry payload
        mod_payload = _parse_module_entry_payload(matching_block["payload"])

        # CHECK 5: BaseAddr matches
        ok = manifest_entry["base_addr"] == mod_payload["base_addr"] == expected_mod.base_addr
        results.append(
            (
                f"{prefix} BaseAddr matches (manifest==block==expected)",
                ok,
                f"manifest=0x{manifest_entry['base_addr']:016X}, "
                f"block=0x{mod_payload['base_addr']:016X}, "
                f"expected=0x{expected_mod.base_addr:016X}",
            )
        )

        # CHECK 6: ModuleSize matches
        ok = manifest_entry["module_size"] == mod_payload["module_size"] == expected_mod.module_size
        results.append(
            (
                f"{prefix} ModuleSize matches (manifest==block==expected)",
                ok,
                f"manifest=0x{manifest_entry['module_size']:08X}, "
                f"block=0x{mod_payload['module_size']:08X}, "
                f"expected=0x{expected_mod.module_size:08X}",
            )
        )

        # CHECK 7: PathLen is pre-padding length (raw UTF-8 + null, NOT padded)
        expected_path_raw = expected_mod.path.encode("utf-8") + b"\x00"
        expected_path_len = len(expected_path_raw)
        padded_len = pad8(expected_path_len)

        ok_manifest = manifest_entry["path_len"] == expected_path_len
        ok_block = mod_payload["path_len"] == expected_path_len
        is_not_padded_manifest = manifest_entry["path_len"] != padded_len or expected_path_len == padded_len
        is_not_padded_block = mod_payload["path_len"] != padded_len or expected_path_len == padded_len

        results.append(
            (
                f"{prefix} Manifest PathLen is pre-padding ({expected_path_len})",
                ok_manifest,
                f"manifest_path_len={manifest_entry['path_len']}, "
                f"expected_pre_pad={expected_path_len}, padded={padded_len}",
            )
        )
        results.append(
            (
                f"{prefix} Block PathLen is pre-padding ({expected_path_len})",
                ok_block,
                f"block_path_len={mod_payload['path_len']}, "
                f"expected_pre_pad={expected_path_len}, padded={padded_len}",
            )
        )

        # CHECK 8: Path content matches
        ok = manifest_entry["path_raw"] == expected_path_raw
        results.append(
            (
                f"{prefix} Manifest path content matches",
                ok,
                f"got={manifest_entry['path_raw']!r}, expected={expected_path_raw!r}",
            )
        )

        # CHECK 9: Reserved fields are zero
        ok = manifest_entry["reserved"] == 0 and manifest_entry["reserved2"] == 0
        results.append(
            (
                f"{prefix} Manifest reserved fields are zero",
                ok,
                f"reserved={manifest_entry['reserved']}, reserved2={manifest_entry['reserved2']}",
            )
        )

    # --- Print results ---
    print("\n" + "=" * 70)
    print("ModuleListIndex Manifest Verification")
    print("=" * 70)
    all_pass = True
    for name, passed, detail in results:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  [{status}] {name}")
        if detail:
            print(f"         {detail}")
    print("=" * 70)
    if all_pass:
        print("ALL CHECKS PASSED")
    else:
        print("SOME CHECKS FAILED")
    print("=" * 70 + "\n")

    # Assert all passed for pytest
    failures = [(name, detail) for name, passed, detail in results if not passed]
    assert not failures, f"Failed checks: {failures}"


if __name__ == "__main__":
    test_module_list_index_manifest()
