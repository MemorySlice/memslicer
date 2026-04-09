"""Verify Process Identity block binary layout against spec (Table 14, Figure 8)."""
import io
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import FileHeader, ProcessIdentity
from memslicer.msl.constants import (
    HEADER_SIZE, BLOCK_HEADER_SIZE, BlockType, CompAlgo,
)
from memslicer.utils.padding import pad8


def main():
    results = []

    def check(name: str, actual, expected):
        ok = actual == expected
        status = "PASS" if ok else "FAIL"
        results.append((name, ok))
        print(f"  [{status}] {name}: got {actual!r}, expected {expected!r}")

    # 1. Create MSL with ProcessIdentity
    buf = io.BytesIO()
    header = FileHeader(pid=9999, timestamp_ns=42)
    writer = MSLWriter(buf, header, CompAlgo.NONE)

    proc_id = ProcessIdentity(
        ppid=1234,
        session_id=5,
        start_time_ns=1000000,
        exe_path="/usr/bin/test",
        cmd_line="test --flag",
    )
    writer.write_process_identity(proc_id)

    # 2. Parse the ProcessIdentity block
    data = buf.getvalue()

    # Block starts right after the 64-byte file header
    block_start = HEADER_SIZE
    block_header = data[block_start : block_start + BLOCK_HEADER_SIZE]

    # Parse block header fields
    (
        magic, block_type, flags, block_length,
        payload_ver, reserved,
        block_uuid, parent_uuid, prev_hash,
    ) = struct.unpack("<4sHHIHH16s16s32s", block_header)

    payload_start = block_start + BLOCK_HEADER_SIZE
    payload = data[payload_start:]

    print("Block header:")
    check("Block magic", magic, b"MSLC")
    check("Block type == 0x0040 (ProcessIdentity)", block_type, 0x0040)

    print("\nPayload fixed fields (24 bytes):")
    ppid = struct.unpack_from("<I", payload, 0x00)[0]
    check("+0x00 PPID", ppid, 1234)

    session_id = struct.unpack_from("<I", payload, 0x04)[0]
    check("+0x04 SessionID", session_id, 5)

    start_time = struct.unpack_from("<Q", payload, 0x08)[0]
    check("+0x08 StartTime", start_time, 1000000)

    exe_path_len = struct.unpack_from("<H", payload, 0x10)[0]
    # "/usr/bin/test" = 13 chars + 1 null = 14
    check("+0x10 ExePathLen (pre-padding, incl null)", exe_path_len, 14)

    cmd_line_len = struct.unpack_from("<H", payload, 0x12)[0]
    # "test --flag" = 11 chars + 1 null = 12
    check("+0x12 CmdLineLen (pre-padding, incl null)", cmd_line_len, 12)

    reserved_field = struct.unpack_from("<I", payload, 0x14)[0]
    check("+0x14 Reserved", reserved_field, 0)

    print("\nVariable-length fields:")
    # ExePath starts at +0x18
    exe_path_bytes = payload[0x18 : 0x18 + 14]
    check("+0x18 ExePath content", exe_path_bytes, b"/usr/bin/test\x00")

    # ExePath is padded to 8-byte boundary: 14 -> pad8(14) = 16
    exe_padded_len = pad8(14)
    check("ExePath padded length", exe_padded_len, 16)

    # Check padding bytes are zero
    exe_padding = payload[0x18 + 14 : 0x18 + exe_padded_len]
    check("ExePath padding zeros", exe_padding, b"\x00" * (exe_padded_len - 14))

    # CmdLine starts after padded ExePath
    cmd_offset = 0x18 + exe_padded_len
    cmd_line_bytes = payload[cmd_offset : cmd_offset + 12]
    check(f"+0x{cmd_offset:02X} CmdLine content", cmd_line_bytes, b"test --flag\x00")

    # CmdLine is padded to 8-byte boundary: 12 -> pad8(12) = 16
    cmd_padded_len = pad8(12)
    check("CmdLine padded length", cmd_padded_len, 16)

    cmd_padding = payload[cmd_offset + 12 : cmd_offset + cmd_padded_len]
    check("CmdLine padding zeros", cmd_padding, b"\x00" * (cmd_padded_len - 12))

    # Verify total payload size
    expected_payload_size = 24 + exe_padded_len + cmd_padded_len
    # The _write_block pads the whole payload too, so check block_length
    expected_block_length = BLOCK_HEADER_SIZE + pad8(expected_payload_size)
    check("Block length", block_length, expected_block_length)

    print("\n" + "=" * 60)
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    print(f"Results: {passed} passed, {failed} failed out of {len(results)} checks")

    if failed:
        print("\nFAILED checks:")
        for name, ok in results:
            if not ok:
                print(f"  - {name}")
        sys.exit(1)
    else:
        print("\nAll checks PASSED.")


if __name__ == "__main__":
    main()
