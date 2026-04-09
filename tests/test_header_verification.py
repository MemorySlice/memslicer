"""Verify every byte of the 64-byte MSL file header against spec v1.1.0 (Table 2).

Offsets:
  0x00 (8B): Magic = "MEMSLICE"
  0x08 (1B): Endianness = 0x01 (LE)
  0x09 (1B): HeaderSize = 0x40 (64)
  0x0A (2B): Version = uint16 LE, major<<8|minor. v1.0 => value 0x0100
  0x0C (4B): Flags = uint32
  0x10 (8B): CapBitmap = uint64
  0x18 (16B): DumpUUID = UUIDv4 RFC 4122
  0x28 (8B): Timestamp = uint64 ns
  0x30 (2B): OSType = uint16
  0x32 (2B): ArchType = uint16
  0x34 (4B): PID = uint32
  0x38 (1B): ClockSource = uint8
  0x39 (7B): Reserved = zeros
"""
from __future__ import annotations

import io
import struct
import sys

# Ensure the project source is importable
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import FileHeader
from memslicer.msl.constants import (
    CompAlgo, Endianness, OSType, ArchType, ClockSource,
)


def main() -> int:
    # ---- Known test values ------------------------------------------------
    known_uuid = bytes(range(0x10, 0x20))  # 16 deterministic bytes
    header = FileHeader(
        endianness=Endianness.LITTLE,       # 1
        version=(1, 0),
        flags=0,
        cap_bitmap=0x107,
        dump_uuid=known_uuid,
        timestamp_ns=123456789,
        os_type=OSType.Linux,               # 1
        arch_type=ArchType.x86_64,          # 1
        pid=42,
        clock_source=ClockSource.Unknown,   # 0
    )

    buf = io.BytesIO()
    writer = MSLWriter(buf, header, CompAlgo.NONE)
    writer.finalize()                       # writes EoC so file is valid

    raw = buf.getvalue()
    hdr = raw[:64]

    if len(hdr) < 64:
        print(f"FAIL: header only {len(hdr)} bytes, expected 64")
        return 1

    # ---- Field-by-field verification --------------------------------------
    passed = 0
    failed = 0

    def check(name: str, actual, expected):
        nonlocal passed, failed
        ok = actual == expected
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name}: got {actual!r}, expected {expected!r}")
        if ok:
            passed += 1
        else:
            failed += 1

    # 0x00  Magic (8B)
    magic = hdr[0x00:0x08]
    check("0x00 Magic", magic, b"MEMSLICE")

    # 0x08  Endianness (1B)
    endianness = hdr[0x08]
    check("0x08 Endianness", endianness, 0x01)

    # 0x09  HeaderSize (1B)
    header_size = hdr[0x09]
    check("0x09 HeaderSize", header_size, 0x40)

    # 0x0A  Version (2B LE uint16)  value = major<<8 | minor = 0x0100
    version_val = struct.unpack_from("<H", hdr, 0x0A)[0]
    check("0x0A Version (uint16 LE value)", version_val, 0x0100)
    # Also verify the raw bytes
    check("0x0A Version raw bytes", hdr[0x0A:0x0C], b"\x00\x01")

    # 0x0C  Flags (4B LE uint32)
    flags = struct.unpack_from("<I", hdr, 0x0C)[0]
    check("0x0C Flags", flags, 0)

    # 0x10  CapBitmap (8B LE uint64)
    cap_bitmap = struct.unpack_from("<Q", hdr, 0x10)[0]
    check("0x10 CapBitmap", cap_bitmap, 0x107)

    # 0x18  DumpUUID (16B)
    dump_uuid = hdr[0x18:0x28]
    check("0x18 DumpUUID", dump_uuid, known_uuid)

    # 0x28  Timestamp (8B LE uint64)
    ts = struct.unpack_from("<Q", hdr, 0x28)[0]
    check("0x28 Timestamp", ts, 123456789)

    # 0x30  OSType (2B LE uint16)
    os_type = struct.unpack_from("<H", hdr, 0x30)[0]
    check("0x30 OSType", os_type, 1)  # Linux

    # 0x32  ArchType (2B LE uint16)
    arch_type = struct.unpack_from("<H", hdr, 0x32)[0]
    check("0x32 ArchType", arch_type, 1)  # x86_64

    # 0x34  PID (4B LE uint32)
    pid = struct.unpack_from("<I", hdr, 0x34)[0]
    check("0x34 PID", pid, 42)

    # 0x38  ClockSource (1B)
    clock_src = hdr[0x38]
    check("0x38 ClockSource", clock_src, 0x00)

    # 0x39  Reserved (7B) - must be all zeros
    reserved = hdr[0x39:0x40]
    check("0x39-0x3F Reserved", reserved, b"\x00" * 7)

    # ---- Hex dump for visual inspection -----------------------------------
    print("\n  Header hex dump (64 bytes):")
    for offset in range(0, 64, 16):
        hex_part = " ".join(f"{b:02x}" for b in hdr[offset:offset + 16])
        ascii_part = "".join(
            chr(b) if 0x20 <= b < 0x7F else "." for b in hdr[offset:offset + 16]
        )
        print(f"    {offset:04x}  {hex_part:<48s}  {ascii_part}")

    # ---- Summary ----------------------------------------------------------
    print(f"\n  Summary: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
