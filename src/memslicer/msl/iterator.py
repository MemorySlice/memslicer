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

* Integrity chain verification of encrypted slices beyond the AEAD tag
  (the tag authenticates the whole container; ``prev_hash`` is zero by
  spec when ``Encrypted`` is set, so there is no chain to walk)
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
    ENCRYPTED_HEADER_SIZE,
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


def _read_file_header_info(f: BinaryIO) -> tuple[int, HashAlgo, int]:
    """Validate the file magic/flags and return (header_size, hash_algo).

    Returns ``(header_size, hash_algo, flags)``. ``header_size`` comes
    from the HeaderSize byte at offset 0x09 rather than a constant, so a
    128-byte encrypted header is located correctly; every field this
    function reads lives in the cleartext header, which is readable even
    when the block stream is encrypted. Deciding what to do about
    :data:`FLAG_ENCRYPTED` is left to the caller.

    Raises :class:`ValueError` on bad magic, an implausible HeaderSize,
    or an unsupported hash algorithm.
    """
    pos = f.tell()
    f.seek(0)
    magic = f.read(8)
    if magic != FILE_MAGIC:
        f.seek(pos)
        raise ValueError(
            f"bad MSL file magic: expected {FILE_MAGIC!r}, got {magic!r}"
        )
    # HeaderSize is the 1-byte field at offset 0x09: 64, or 128 when the
    # 64-byte encryption extension is present.
    f.seek(0x09)
    header_size = struct.unpack("B", f.read(1))[0]
    if header_size not in (HEADER_SIZE, ENCRYPTED_HEADER_SIZE):
        f.seek(pos)
        raise ValueError(
            f"unsupported HeaderSize {header_size} at offset 0x09; "
            f"expected {HEADER_SIZE} or {ENCRYPTED_HEADER_SIZE}"
        )
    # flags is the 4-byte field at offset 0x0C
    f.seek(0x0C)
    flags = struct.unpack("<I", f.read(4))[0]
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
    return header_size, hash_algo, flags


def read_hash_algo(f: BinaryIO) -> HashAlgo:
    """Read and return the ``HashAlgo`` from an open MSL file.

    The file position is restored after reading. Raises
    :class:`ValueError` for invalid magic or unsupported algorithm codes.
    """
    _, hash_algo, _flags = _read_file_header_info(f)
    return hash_algo


AEAD_TAG_SIZE = 16
"""Length of the AES-GCM authentication tag appended after the ciphertext."""


def _decrypt_stream(f: BinaryIO, header_size: int, passphrase: str) -> BinaryIO:
    """Return the plaintext block stream of an encrypted slice.

    The whole container is read and authenticated in one pass: AES-GCM
    offers no verdict on a fragment, so there is no way to stream blocks
    out while the tag is still unverified. A reader that yielded blocks
    before the tag checked out would be handing callers data it could not
    yet vouch for -- the wrong trade for a forensic format.

    Args:
        f: Open MSL file, positioned anywhere.
        header_size: Size of the cleartext header, from offset 0x09.
        passphrase: Passphrase the slice was sealed with.

    Returns:
        A binary stream over the decrypted blocks, positioned at 0.

    Raises:
        ValueError: If the container is truncated, or if the tag does not
            verify -- a wrong passphrase and a tampered file are the same
            answer here, by design of the AEAD.
    """
    from io import BytesIO

    from memslicer.msl.encryption import (
        StreamingDecryptor, derive_key, unpack_encryption_extension,
    )

    f.seek(0)
    raw = f.read()
    if len(raw) < header_size + AEAD_TAG_SIZE:
        raise ValueError(
            f"truncated encrypted slice: {len(raw)} bytes, need at least "
            f"{header_size + AEAD_TAG_SIZE}"
        )
    header = raw[:header_size]
    ciphertext = raw[header_size:-AEAD_TAG_SIZE]
    tag = raw[-AEAD_TAG_SIZE:]

    params = unpack_encryption_extension(header[HEADER_SIZE:header_size])
    decryptor = StreamingDecryptor(
        key=derive_key(passphrase, params), nonce=params.nonce, aad=header,
    )
    decryptor.update(ciphertext)
    try:
        plaintext = decryptor.finalize(tag)
    except Exception as exc:  # cryptography raises InvalidTag
        raise ValueError(
            "could not decrypt slice: wrong passphrase, or the file has been "
            "modified since capture (the authentication tag does not verify)"
        ) from exc
    return BytesIO(plaintext)


def is_encrypted(f: BinaryIO) -> bool:
    """Whether the slice's block stream is AEAD-encrypted.

    Reads the cleartext header only, and restores the file position, so it
    is safe to call before deciding how to open a slice.

    Args:
        f: Open MSL file.

    Returns:
        ``True`` when the ``Encrypted`` flag is set in the file header.
    """
    _header_size, _hash_algo, flags = _read_file_header_info(f)
    return bool(flags & FLAG_ENCRYPTED)


def iterate_blocks(
    f: BinaryIO, passphrase: str | None = None,
) -> Iterator[BlockRecord]:
    """Yield :class:`BlockRecord` entries from an open MSL file.

    The file must be opened in ``"rb"`` mode. This function seeks to
    the start of the first block (past the file header). Iteration
    stops when an :data:`BlockType.EndOfCapture` block is yielded or
    when EOF is reached; structural errors raise :class:`ValueError`.

    Args:
        f: Open MSL file.
        passphrase: Required to read a slice with :data:`FLAG_ENCRYPTED`
            set; ignored for an unencrypted one. Without it an encrypted
            slice is refused rather than partially read.

    Note:
        For an encrypted slice, ``start_offset`` and ``end_offset`` are
        positions in the decrypted block stream, not in the file on disk.
        Nothing in the file maps to a plaintext block boundary, so there
        is no file offset to report.
    """
    header_size, _hash_algo, flags = _read_file_header_info(f)
    if flags & FLAG_ENCRYPTED:
        if passphrase is None:
            raise ValueError(
                "encrypted slices cannot be read without a passphrase; "
                "pass one to read this file"
            )
        f = _decrypt_stream(f, header_size, passphrase)
        header_size = 0  # the decrypted stream starts at the first block
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
