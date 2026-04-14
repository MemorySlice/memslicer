"""End-to-end verification of Investigation Mode in memslicer.

Produces an MSL file via AcquisitionEngine with investigation=True,
then parses the binary and checks every structural invariant.
"""
from __future__ import annotations

import getpass
import socket
import struct
import sys
from pathlib import Path

import blake3

# ---------------------------------------------------------------------------
# Ensure the src directory is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo, PlatformInfo
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    BlockType,
    CapBit,
    FILE_MAGIC,
    FLAG_INVESTIGATION,
    HASH_SIZE,
    HEADER_SIZE,
    ArchType,
    OSType,
)

# ---------------------------------------------------------------------------
# Constants for parsing
# ---------------------------------------------------------------------------
SYSCTX_FIXED_HEADER_SIZE = 32  # 8+1+4+2+2+2+2+2+9


# ---------------------------------------------------------------------------
# MockBridge (same as test_engine.py)
# ---------------------------------------------------------------------------
class MockBridge:
    def __init__(
        self,
        ranges: list[MemoryRange] | None = None,
        modules: list[ModuleInfo] | None = None,
        platform_info: PlatformInfo | None = None,
        memory: dict[int, bytes] | None = None,
    ) -> None:
        self.ranges = ranges or []
        self.modules = modules or []
        self.platform_info = platform_info or PlatformInfo(
            arch=ArchType.x86_64, os=OSType.Linux, pid=1234, page_size=4096,
        )
        self.memory: dict[int, bytes] = memory or {}
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def get_platform_info(self) -> PlatformInfo:
        return self.platform_info

    def enumerate_ranges(self) -> list[MemoryRange]:
        return list(self.ranges)

    def enumerate_modules(self) -> list[ModuleInfo]:
        return list(self.modules)

    def read_memory(self, address: int, size: int) -> bytes | None:
        data = self.memory.get(address)
        if data is None:
            return None
        return data[:size] if len(data) >= size else None

    def disconnect(self) -> None:
        self.connected = False


# ---------------------------------------------------------------------------
# MockCollector for PART 3
# ---------------------------------------------------------------------------
class MockCollector:
    def collect_process_identity(self, pid, **kwargs):
        from memslicer.acquirer.investigation import TargetProcessInfo
        return TargetProcessInfo(ppid=500, session_id=7, start_time_ns=1700000000_000000000,
                                exe_path="/opt/app/server", cmd_line="/opt/app/server --port 8080")

    def collect_system_info(self):
        from memslicer.acquirer.investigation import TargetSystemInfo
        return TargetSystemInfo(boot_time=1699000000_000000000, hostname="forensic-target",
                                domain="lab.local", os_detail="Ubuntu 22.04 LTS 6.1.0")

    def collect_process_table(self, target_pid):
        return []

    def collect_connection_table(self):
        return []

    def collect_handle_table(self, pid):
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _parse_blocks(data: bytes) -> list[dict]:
    """Walk raw MSL bytes and return a list of block dicts."""
    blocks: list[dict] = []
    offset = HEADER_SIZE
    while offset + BLOCK_HEADER_SIZE <= len(data):
        magic = data[offset : offset + 4]
        if magic != BLOCK_MAGIC:
            break
        btype, bflags, blength = struct.unpack_from("<HHI", data, offset + 4)
        _payload_ver, _reserved = struct.unpack_from("<HH", data, offset + 12)
        block_uuid = data[offset + 16 : offset + 32]
        parent_uuid = data[offset + 32 : offset + 48]
        prev_hash = data[offset + 48 : offset + 80]
        payload = data[offset + BLOCK_HEADER_SIZE : offset + blength]
        blocks.append({
            "type": btype,
            "flags": bflags,
            "length": blength,
            "block_uuid": block_uuid,
            "parent_uuid": parent_uuid,
            "prev_hash": prev_hash,
            "payload": payload,
            "offset": offset,
            "raw": data[offset : offset + blength],
        })
        offset += blength
    return blocks


def _check(label: str, condition: bool, detail: str = "") -> bool:
    tag = "PASS" if condition else "FAIL"
    msg = f"[{tag}] {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    return condition


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------
def main() -> int:
    import tempfile

    all_pass = True

    # Build mock data
    page_data = b"\xAA" * 4096
    ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
    modules = [
        ModuleInfo(name="libc.so", path="/usr/lib/libc.so", base=0x400000, size=0x10000),
    ]
    bridge = MockBridge(
        ranges=ranges,
        modules=modules,
        memory={0x10000: page_data},
    )

    # -----------------------------------------------------------------------
    # PART 1: Investigation mode ON
    # -----------------------------------------------------------------------
    print("=" * 70)
    print("PART 1: Investigation Mode = True")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = Path(tmpdir) / "investigation.msl"
        engine = AcquisitionEngine(bridge, investigation=True)
        result = engine.acquire(outpath)

        all_pass &= _check("Acquisition succeeded", result.regions_captured == 1,
                           f"regions={result.regions_captured}")
        all_pass &= _check("MSL file exists", outpath.exists())

        raw = outpath.read_bytes()

        # -- File Header --
        all_pass &= _check("Magic", raw[:8] == FILE_MAGIC, repr(raw[:8]))

        flags = struct.unpack_from("<I", raw, 0x0C)[0]
        all_pass &= _check("Flags: Investigation bit set",
                           (flags & FLAG_INVESTIGATION) != 0,
                           f"flags=0x{flags:04X}")

        cap_bitmap = struct.unpack_from("<Q", raw, 0x10)[0]
        all_pass &= _check("CapBitmap: SystemContext bit (11) set",
                           (cap_bitmap & (1 << CapBit.SystemContext)) != 0,
                           f"cap_bitmap=0x{cap_bitmap:016X}")
        all_pass &= _check("CapBitmap: ProcessIdentity bit (8) set",
                           (cap_bitmap & (1 << CapBit.ProcessIdentity)) != 0)
        all_pass &= _check("CapBitmap: MemoryRegions bit (0) set",
                           (cap_bitmap & (1 << CapBit.MemoryRegions)) != 0)
        all_pass &= _check("CapBitmap: ModuleList bit (1) set",
                           (cap_bitmap & (1 << CapBit.ModuleList)) != 0)

        # -- Parse blocks --
        blocks = _parse_blocks(raw)
        all_pass &= _check("At least 4 blocks parsed", len(blocks) >= 4,
                           f"count={len(blocks)}")

        # Block 0: ProcessIdentity
        b0 = blocks[0]
        all_pass &= _check("Block 0: ProcessIdentity (0x0040)",
                           b0["type"] == BlockType.ProcessIdentity,
                           f"type=0x{b0['type']:04X}")

        # Block 1: ModuleListIndex
        b1 = blocks[1]
        all_pass &= _check("Block 1: ModuleListIndex (0x0010)",
                           b1["type"] == BlockType.ModuleListIndex,
                           f"type=0x{b1['type']:04X}")

        # Find SystemContext block — spec requires it at a fixed position
        # After Block 0 (ProcessIdentity) + Block 1 (ModuleListIndex) + ModuleEntry children
        sys_ctx_blocks = [b for b in blocks if b["type"] == BlockType.SystemContext]
        all_pass &= _check("SystemContext block exists", len(sys_ctx_blocks) == 1,
                           f"count={len(sys_ctx_blocks)}")

        # Verify SystemContext appears after module entries (spec Section 6.1)
        if sys_ctx_blocks:
            sc_idx = next(i for i, b in enumerate(blocks)
                          if b["type"] == BlockType.SystemContext)
            all_pass &= _check("SystemContext after ModuleListIndex",
                               sc_idx >= 2,
                               f"position={sc_idx}")

        if sys_ctx_blocks:
            sc = sys_ctx_blocks[0]
            sc_payload = sc["payload"]

            # Parse the fixed 32-byte header
            all_pass &= _check("SystemContext payload >= 32 bytes",
                               len(sc_payload) >= SYSCTX_FIXED_HEADER_SIZE,
                               f"len={len(sc_payload)}")

            if len(sc_payload) >= SYSCTX_FIXED_HEADER_SIZE:
                (boot_time, target_count, table_bitmap,
                 acq_user_len, hostname_len, domain_len,
                 os_detail_len, case_ref_len, _reserved6) = struct.unpack_from(
                    "<QBIHHHHH9s", sc_payload, 0,
                )
                # skip 2 more bytes (CaseRefLen) + 6 reserved = already parsed

                all_pass &= _check("SystemContext target_count >= 1",
                                   target_count >= 1,
                                   f"target_count={target_count}")
                all_pass &= _check("SystemContext acq_user_len > 0",
                                   acq_user_len > 0,
                                   f"acq_user_len={acq_user_len}")
                all_pass &= _check("SystemContext hostname_len > 0",
                                   hostname_len > 0,
                                   f"hostname_len={hostname_len}")

                # Extract variable-length strings
                str_offset = SYSCTX_FIXED_HEADER_SIZE
                acq_user_raw = sc_payload[str_offset : str_offset + acq_user_len]
                acq_user = acq_user_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
                str_offset += _pad8(acq_user_len)

                hostname_raw = sc_payload[str_offset : str_offset + hostname_len]
                hostname = hostname_raw.rstrip(b"\x00").decode("utf-8", errors="replace")

                expected_user = getpass.getuser()
                expected_host = socket.gethostname()

                all_pass &= _check("SystemContext acq_user matches real user",
                                   acq_user == expected_user,
                                   f"got={acq_user!r} expected={expected_user!r}")
                all_pass &= _check("SystemContext hostname matches real hostname",
                                   hostname == expected_host,
                                   f"got={hostname!r} expected={expected_host!r}")

        # MemoryRegion blocks
        mem_blocks = [b for b in blocks if b["type"] == BlockType.MemoryRegion]
        all_pass &= _check("MemoryRegion blocks present", len(mem_blocks) >= 1,
                           f"count={len(mem_blocks)}")

        # ModuleEntry blocks
        mod_blocks = [b for b in blocks if b["type"] == BlockType.ModuleEntry]
        all_pass &= _check("ModuleEntry blocks present", len(mod_blocks) >= 1,
                           f"count={len(mod_blocks)}")

        # Last block: EndOfCapture
        last = blocks[-1]
        all_pass &= _check("Last block: EndOfCapture (0x0FFF)",
                           last["type"] == BlockType.EndOfCapture,
                           f"type=0x{last['type']:04X}")

        # -- BLAKE3 integrity chain --
        print()
        print("--- BLAKE3 Integrity Chain ---")
        header_bytes = raw[:HEADER_SIZE]
        expected_prev = blake3.blake3(header_bytes).digest()

        chain_ok = True
        file_hasher = blake3.blake3()
        file_hasher.update(header_bytes)

        for i, blk in enumerate(blocks):
            blk_raw = blk["raw"]
            prev_in_block = blk["prev_hash"]

            match = prev_in_block == expected_prev
            if not match:
                chain_ok = False
                print(f"  [FAIL] Block {i} (0x{blk['type']:04X}): PrevHash mismatch")
            file_hasher.update(blk_raw)
            expected_prev = blake3.blake3(blk_raw).digest()

        all_pass &= _check("BLAKE3 chain valid across all blocks", chain_ok)

        # Verify EoC FileHash matches running hash (excluding EoC itself)
        # The file hash in the EoC should be the hash of everything up to (but not including) the EoC block
        eoc_payload = last["payload"]
        if len(eoc_payload) >= HASH_SIZE:
            eoc_file_hash = eoc_payload[:HASH_SIZE]
            # Recompute: hash of header + all blocks except last (EoC)
            recompute_hasher = blake3.blake3()
            recompute_hasher.update(header_bytes)
            for blk in blocks[:-1]:
                recompute_hasher.update(blk["raw"])
            expected_file_hash = recompute_hasher.digest()
            all_pass &= _check("EoC FileHash matches running BLAKE3",
                               eoc_file_hash == expected_file_hash,
                               f"eoc={eoc_file_hash[:8].hex()}... expected={expected_file_hash[:8].hex()}...")

    # -----------------------------------------------------------------------
    # PART 2: Investigation mode OFF (no SystemContext)
    # -----------------------------------------------------------------------
    print()
    print("=" * 70)
    print("PART 2: Investigation Mode = False (default)")
    print("=" * 70)

    bridge2 = MockBridge(
        ranges=ranges,
        modules=modules,
        memory={0x10000: page_data},
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        outpath2 = Path(tmpdir) / "normal.msl"
        engine2 = AcquisitionEngine(bridge2, investigation=False)
        result2 = engine2.acquire(outpath2)

        raw2 = outpath2.read_bytes()

        flags2 = struct.unpack_from("<I", raw2, 0x0C)[0]
        all_pass &= _check("Flags: Investigation bit NOT set",
                           (flags2 & FLAG_INVESTIGATION) == 0,
                           f"flags=0x{flags2:04X}")

        cap_bitmap2 = struct.unpack_from("<Q", raw2, 0x10)[0]
        all_pass &= _check("CapBitmap: SystemContext bit NOT set",
                           (cap_bitmap2 & (1 << CapBit.SystemContext)) == 0,
                           f"cap_bitmap=0x{cap_bitmap2:016X}")

        blocks2 = _parse_blocks(raw2)
        sys_ctx_blocks2 = [b for b in blocks2 if b["type"] == BlockType.SystemContext]
        all_pass &= _check("No SystemContext block when investigation=False",
                           len(sys_ctx_blocks2) == 0,
                           f"count={len(sys_ctx_blocks2)}")

        last2 = blocks2[-1]
        all_pass &= _check("Last block still EndOfCapture",
                           last2["type"] == BlockType.EndOfCapture)

    # -----------------------------------------------------------------------
    # PART 3: Investigation mode WITH MockCollector
    # -----------------------------------------------------------------------
    print()
    print("=" * 70)
    print("PART 3: Investigation Mode = True WITH MockCollector")
    print("=" * 70)

    bridge3 = MockBridge(
        ranges=ranges,
        modules=modules,
        memory={0x10000: page_data},
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        outpath3 = Path(tmpdir) / "investigation_collector.msl"
        engine3 = AcquisitionEngine(bridge3, investigation=True, collector=MockCollector())
        result3 = engine3.acquire(outpath3)

        all_pass &= _check("PART3: Acquisition succeeded", result3.regions_captured == 1,
                           f"regions={result3.regions_captured}")

        raw3 = outpath3.read_bytes()
        blocks3 = _parse_blocks(raw3)

        # --- ProcessIdentity block ---
        pi_blocks = [b for b in blocks3 if b["type"] == BlockType.ProcessIdentity]
        all_pass &= _check("PART3: ProcessIdentity block exists",
                           len(pi_blocks) == 1, f"count={len(pi_blocks)}")

        if pi_blocks:
            pi_payload = pi_blocks[0]["payload"]
            # Parse: ppid(4B LE) + session_id(4B LE) + start_time_ns(8B LE)
            all_pass &= _check("PART3: ProcessIdentity payload >= 16 bytes",
                               len(pi_payload) >= 16, f"len={len(pi_payload)}")
            if len(pi_payload) >= 16:
                ppid, session_id, start_time_ns = struct.unpack_from("<IIQ", pi_payload, 0)
                all_pass &= _check("PART3: ppid is non-zero (500)",
                                   ppid != 0, f"ppid={ppid}")
                all_pass &= _check("PART3: ppid == 500",
                                   ppid == 500, f"ppid={ppid}")

                # Variable-length strings follow the fixed header
                str_data = pi_payload[16:]
                # exe_path and cmd_line are null-terminated strings
                parts = str_data.split(b"\x00")
                # Filter out empty parts from padding
                string_parts = [p.decode("utf-8", errors="replace") for p in parts if p]
                exe_found = any("server" in s for s in string_parts)
                all_pass &= _check("PART3: exe_path contains 'server'",
                                   exe_found,
                                   f"strings={string_parts!r}")

        # --- SystemContext block ---
        sc_blocks3 = [b for b in blocks3 if b["type"] == BlockType.SystemContext]
        all_pass &= _check("PART3: SystemContext block exists",
                           len(sc_blocks3) == 1, f"count={len(sc_blocks3)}")

        if sc_blocks3:
            sc_payload3 = sc_blocks3[0]["payload"]
            all_pass &= _check("PART3: SystemContext payload >= 32 bytes",
                               len(sc_payload3) >= SYSCTX_FIXED_HEADER_SIZE,
                               f"len={len(sc_payload3)}")

            if len(sc_payload3) >= SYSCTX_FIXED_HEADER_SIZE:
                (boot_time3, target_count3, table_bitmap3,
                 acq_user_len3, hostname_len3, domain_len3,
                 os_detail_len3, case_ref_len3, _reserved6_3) = struct.unpack_from(
                    "<QBIHHHHH9s", sc_payload3, 0,
                )

                all_pass &= _check("PART3: boot_time is non-zero",
                                   boot_time3 != 0,
                                   f"boot_time={boot_time3}")

                # Parse variable-length strings
                str_offset3 = SYSCTX_FIXED_HEADER_SIZE

                # acq_user
                acq_user_raw3 = sc_payload3[str_offset3 : str_offset3 + acq_user_len3]
                str_offset3 += _pad8(acq_user_len3)

                # hostname
                hostname_raw3 = sc_payload3[str_offset3 : str_offset3 + hostname_len3]
                hostname3 = hostname_raw3.rstrip(b"\x00").decode("utf-8", errors="replace")
                str_offset3 += _pad8(hostname_len3)

                all_pass &= _check("PART3: hostname is 'forensic-target'",
                                   hostname3 == "forensic-target",
                                   f"hostname={hostname3!r}")

                # domain
                domain_raw3 = sc_payload3[str_offset3 : str_offset3 + domain_len3]
                str_offset3 += _pad8(domain_len3)

                # os_detail
                if os_detail_len3 > 0:
                    os_detail_raw3 = sc_payload3[str_offset3 : str_offset3 + os_detail_len3]
                    os_detail3 = os_detail_raw3.rstrip(b"\x00").decode("utf-8", errors="replace")
                    all_pass &= _check("PART3: os_detail contains 'Ubuntu'",
                                       "Ubuntu" in os_detail3,
                                       f"os_detail={os_detail3!r}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print()
    print("=" * 70)
    if all_pass:
        print("ALL CHECKS PASSED")
    else:
        print("SOME CHECKS FAILED -- see above")
    print("=" * 70)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
