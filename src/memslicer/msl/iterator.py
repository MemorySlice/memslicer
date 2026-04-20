"""Minimal MSL block iterator.

P1.7 deliverable — the first read path in memslicer. Used by
``memslicer-enrich`` (P1.6.2 / P1.7 activation) to walk an existing
``.msl`` file's blocks and extract ``ModuleEntry`` + ``MemoryRegion``
data for retroactive build-id enrichment.

This is NOT a full MSL reader. It yields :class:`BlockRecord` objects
with the decompressed payload bytes; callers parse type-specific
payloads on demand. A full type-dispatch reader (for a Volatility3
plugin, for a ``memslicer-inspect`` CLI) is future work.

Intentionally out of scope:

* Encrypted slices (refuses with a clear error)
* Integrity chain verification (callers can verify ``file_hash`` if
  they want; the iterator does not check ``prev_hash`` continuity)
* Continuation blocks (``CONTINUATION`` flag) — raises
  :class:`NotImplementedError` if encountered; the writer only uses
  them for >4 GiB blocks which memslicer does not currently produce.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from memslicer.msl.compression import decompress
from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    COMPALGO_MASK,
    COMPRESSED,
    CONTINUATION,
    FILE_MAGIC,
    FLAG_ENCRYPTED,
    HEADER_SIZE,
    BlockType,
    CompAlgo,
    HashAlgo,
)


@dataclass
class BlockRecord:
    """A single block yielded by :func:`iterate_blocks`.

    ``payload`` is the DECOMPRESSED payload bytes (writer-side
    compression, if any, has been undone and the 8-byte
    ``UncompressedSize`` prefix has been stripped). ``start_offset`` is
    the byte offset of the block header in the source file;
    ``end_offset`` is the offset immediately after the block's last
    on-disk byte (so ``end_offset - start_offset == length``).
    """

    block_type: int
    flags: int
    length: int  # full on-disk block length including header
    payload_version: int
    block_uuid: bytes
    parent_uuid: bytes
    prev_hash: bytes
    payload: bytes  # decompressed
    start_offset: int
    end_offset: int


def _read_file_header_info(f: BinaryIO) -> tuple[int, HashAlgo]:
    """Validate the file magic/flags and return (header_size, hash_algo).

    Returns ``(HEADER_SIZE, hash_algo)`` for unencrypted slices. Raises
    :class:`ValueError` on bad magic or when the ``FLAG_ENCRYPTED`` bit
    is set (encrypted-read support is P1.8 scope).
    """
    pos = f.tell()
    f.seek(0)
    magic = f.read(8)
    if magic != FILE_MAGIC:
        f.seek(pos)
        raise ValueError(
            f"bad MSL file magic: expected {FILE_MAGIC!r}, got {magic!r}"
        )
    # flags is the 4-byte field at offset 0x0C
    f.seek(0x0C)
    flags = struct.unpack("<I", f.read(4))[0]
    if flags & FLAG_ENCRYPTED:
        f.seek(pos)
        raise ValueError(
            "encrypted slices are not yet supported for read — P1.8 scope"
        )
    # HashAlgo is the 1-byte field at offset 0x3D (spec Table 3)
    f.seek(0x3D)
    hash_algo_byte = struct.unpack("B", f.read(1))[0]
    try:
        hash_algo = HashAlgo(hash_algo_byte)
    except ValueError:
        f.seek(pos)
        raise ValueError(
            f"unsupported HashAlgo code 0x{hash_algo_byte:02X} at offset 0x3D; "
            f"supported: {', '.join(f'0x{a.value:02X}={a.name}' for a in HashAlgo)}"
        )
    f.seek(pos)
    return HEADER_SIZE, hash_algo


def read_hash_algo(f: BinaryIO) -> HashAlgo:
    """Read and return the ``HashAlgo`` from an open MSL file.

    The file position is restored after reading. Raises
    :class:`ValueError` for invalid magic or unsupported algorithm codes.
    """
    _, hash_algo = _read_file_header_info(f)
    return hash_algo


def iterate_blocks(f: BinaryIO) -> Iterator[BlockRecord]:
    """Yield :class:`BlockRecord` entries from an open MSL file.

    The file must be opened in ``"rb"`` mode. This function seeks to
    the start of the first block (past the file header). Iteration
    stops when an :data:`BlockType.EndOfCapture` block is yielded or
    when EOF is reached; structural errors raise :class:`ValueError`.
    """
    header_size, _hash_algo = _read_file_header_info(f)
    f.seek(header_size)

    while True:
        start = f.tell()
        block_header = f.read(BLOCK_HEADER_SIZE)
        if len(block_header) == 0:
            return
        if len(block_header) < BLOCK_HEADER_SIZE:
            raise ValueError(
                f"truncated block header at offset {start}: "
                f"got {len(block_header)} bytes, expected {BLOCK_HEADER_SIZE}"
            )

        (
            magic,
            block_type,
            flags,
            length,
            payload_version,
            _reserved,
            block_uuid,
            parent_uuid,
            prev_hash,
        ) = struct.unpack("<4sHHIHH16s16s32s", block_header)

        if magic != BLOCK_MAGIC:
            raise ValueError(
                f"bad block magic at offset {start}: "
                f"expected {BLOCK_MAGIC!r}, got {magic!r}"
            )

        if flags & CONTINUATION:
            raise NotImplementedError(
                f"block at offset {start} has CONTINUATION flag set — "
                f"multi-block payloads are not supported by the P1.7 iterator"
            )

        payload_len = length - BLOCK_HEADER_SIZE
        if payload_len < 0:
            raise ValueError(
                f"block at offset {start} has length {length} < "
                f"BLOCK_HEADER_SIZE ({BLOCK_HEADER_SIZE})"
            )

        on_disk_payload = f.read(payload_len)
        if len(on_disk_payload) < payload_len:
            raise ValueError(
                f"truncated payload at offset {start}: "
                f"got {len(on_disk_payload)} bytes, expected {payload_len}"
            )

        if flags & COMPRESSED:
            if payload_len < 8:
                raise ValueError(
                    f"compressed block at offset {start} too small to "
                    f"contain UncompressedSize prefix"
                )
            uncompressed_size = struct.unpack("<Q", on_disk_payload[:8])[0]
            comp_algo = CompAlgo((flags & COMPALGO_MASK) >> 1)
            # The writer packs UncompressedSize(8B) + CompressedData and
            # pads the tuple to 8B; zstd/lz4 both tolerate trailing
            # padding on decompress.
            compressed_data = on_disk_payload[8:]
            try:
                payload = decompress(compressed_data, comp_algo)
            except Exception as exc:
                raise ValueError(
                    f"decompression failed at offset {start}: {exc}"
                ) from exc
            if len(payload) != uncompressed_size:
                raise ValueError(
                    f"decompressed size mismatch at offset {start}: "
                    f"expected {uncompressed_size}, got {len(payload)}"
                )
        else:
            payload = on_disk_payload

        end_offset = f.tell()
        yield BlockRecord(
            block_type=block_type,
            flags=flags,
            length=length,
            payload_version=payload_version,
            block_uuid=block_uuid,
            parent_uuid=parent_uuid,
            prev_hash=prev_hash,
            payload=payload,
            start_offset=start,
            end_offset=end_offset,
        )

        if block_type == BlockType.EndOfCapture:
            return
