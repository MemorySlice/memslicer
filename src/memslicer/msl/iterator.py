"""Minimal MSL block iterator.

P1.7 deliverable — the first read path in memslicer. Used by
``memslicer-enrich`` (P1.6.2 / P1.7 activation) to walk an existing
``.msl`` file's blocks and extract ``ModuleEntry`` + ``MemoryRegion``
data for retroactive build-id enrichment.

This is NOT a full MSL reader. It yields :class:`BlockRecord` objects
with the decompressed payload bytes; callers parse type-specific
payloads on demand. A full type-dispatch reader (for a Volatility3
plugin, for a ``memslicer-inspect`` CLI) is future work.

Extension segments (spec Section 4.6): after the ``EndOfCapture`` block
the iterator looks for runs of blocks each closed by an
``EndOfExtension`` block. A run is yielded only when it is terminated and
its terminator's ``BlockCount`` matches the number of blocks parsed;
anything else after the EoC is trailing data and never yielded. Records
carry a ``segment`` index (0 = capture segment) so callers can tell
evidence from appended views.

Intentionally out of scope:

* Integrity chain verification of encrypted slices beyond the AEAD tag
  (the tag authenticates the whole container; ``prev_hash`` is zero by
  spec when ``Encrypted`` is set, so there is no chain to walk)
* Integrity chain verification -- the iterator does not check
  ``prev_hash`` continuity or an extension segment's ``SegmentHash``;
  that lives in :mod:`memslicer.msl.verify`
* Continuation blocks (``CONTINUATION`` flag) — raises
  :class:`NotImplementedError` if encountered; the writer only uses
  them for >4 GiB blocks which memslicer does not currently produce.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from memslicer.msl.compression import decompress_tolerating_padding
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
    ``segment`` is 0 for a capture-segment block and *n* for a block of
    the *n*-th extension segment (spec Section 4.6).
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
    segment: int = 0


@dataclass
class RawBlock:
    """A block exactly as stored, yielded by :func:`_iter_raw_blocks`.

    Unlike :class:`BlockRecord`, nothing is decompressed: ``header_bytes``
    is the raw 80-byte block header and ``on_disk_payload`` the bytes that
    follow it, so hash-chain checks can run over the stored bytes.
    ``segment`` has the same meaning as on :class:`BlockRecord`; the
    caller that knows which segment it is walking sets it.
    """

    block_type: int
    flags: int
    length: int  # full on-disk block length including header
    payload_version: int
    block_uuid: bytes
    parent_uuid: bytes
    prev_hash: bytes
    header_bytes: bytes  # raw 80-byte block header
    on_disk_payload: bytes  # possibly compressed, as stored
    start_offset: int
    end_offset: int
    segment: int = 0


@dataclass
class SegmentSpan:
    """Byte extent of one extension segment found by :func:`scan_extension_segments`.

    ``index`` is 1-based (segment 0 is the capture segment). ``start`` is
    the offset of the segment's first block header and ``end`` the offset
    just after its last framed block. ``block_count`` is the number of
    blocks framed, including the terminator when ``terminated`` is set;
    ``terminator_offset`` is the ``EndOfExtension`` block's offset, or
    ``None`` for a run that ended at EOF, bad magic or a truncated block.
    Offsets are stream offsets (plaintext offsets for an encrypted slice).
    """

    index: int
    start: int
    end: int
    block_count: int
    terminator_offset: int | None
    terminated: bool


def read_file_header_info(f: BinaryIO) -> tuple[int, HashAlgo, int]:
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


_read_file_header_info = read_file_header_info
"""Backward-compatible private alias of :func:`read_file_header_info`."""


def read_hash_algo(f: BinaryIO) -> HashAlgo:
    """Read and return the ``HashAlgo`` from an open MSL file.

    The file position is restored after reading. Raises
    :class:`ValueError` for invalid magic or unsupported algorithm codes.
    """
    _, hash_algo, _flags = read_file_header_info(f)
    return hash_algo


AEAD_TAG_SIZE = 16
"""Length of the AES-GCM authentication tag appended after the ciphertext."""


def decrypt_stream(f: BinaryIO, header_size: int, passphrase: str) -> BinaryIO:
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


_decrypt_stream = decrypt_stream
"""Backward-compatible private alias of :func:`decrypt_stream`."""


def is_encrypted(f: BinaryIO) -> bool:
    """Whether the slice's block stream is AEAD-encrypted.

    Reads the cleartext header only, and restores the file position, so it
    is safe to call before deciding how to open a slice.

    Args:
        f: Open MSL file.

    Returns:
        ``True`` when the ``Encrypted`` flag is set in the file header.
    """
    _header_size, _hash_algo, flags = read_file_header_info(f)
    return bool(flags & FLAG_ENCRYPTED)


def iterate_blocks(
    f: BinaryIO, passphrase: str | None = None, *, extensions: bool = True,
) -> Iterator[BlockRecord]:
    """Yield :class:`BlockRecord` entries from an open MSL file.

    The file must be opened in ``"rb"`` mode. This function seeks to
    the start of the first block (past the file header). The capture
    segment is yielded through its :data:`BlockType.EndOfCapture` block
    (or to EOF when there is none); structural errors raise
    :class:`ValueError`.

    After the EoC, when ``extensions`` is set, extension segments (spec
    Section 4.6) are yielded with ``segment`` = 1, 2, ... Only a run that
    is closed by an ``EndOfExtension`` block whose ``BlockCount`` equals
    the number of blocks framed is yielded; the first run that is
    unterminated or miscounted ends iteration, and nothing after it is
    read. ``SegmentHash`` and PrevHash continuity are NOT checked here
    (see :mod:`memslicer.msl.verify`).

    Args:
        f: Open MSL file.
        passphrase: Required to read a slice with :data:`FLAG_ENCRYPTED`
            set; ignored for an unencrypted one. Without it an encrypted
            slice is refused rather than partially read.
        extensions: Stop at the EoC when ``False`` (pre-1.1 behaviour).

    Note:
        For an encrypted slice, ``start_offset`` and ``end_offset`` are
        positions in the decrypted block stream, not in the file on disk.
        Nothing in the file maps to a plaintext block boundary, so there
        is no file offset to report. Extension segments of an encrypted
        slice lie inside the AEAD stream and are handled the same way.
    """
    header_size, _hash_algo, flags = read_file_header_info(f)
    if flags & FLAG_ENCRYPTED:
        if passphrase is None:
            raise ValueError(
                "encrypted slices cannot be read without a passphrase; "
                "pass one to read this file"
            )
        f = decrypt_stream(f, header_size, passphrase)
        header_size = 0  # the decrypted stream starts at the first block
    f.seek(header_size)

    eoc_end: int | None = None
    for raw in _iter_raw_blocks(f):
        yield _to_record(raw)
        if raw.block_type == BlockType.EndOfCapture:
            eoc_end = raw.end_offset
            break

    if extensions and eoc_end is not None:
        yield from _iterate_extension_segments(f, eoc_end)


def _iterate_extension_segments(f: BinaryIO, start: int) -> Iterator[BlockRecord]:
    """Yield the blocks of every valid extension segment after ``start``.

    Stops at the first run that is unterminated or whose terminator's
    ``BlockCount`` disagrees with the blocks framed (spec Section 4.6:
    everything from there to EOF is trailing data).
    """
    spans, _trailing_start = scan_extension_segments(f, start)
    for span in spans:
        if not span_count_valid(f, span):
            return
        f.seek(span.start)
        for raw in _iter_raw_blocks(f, end=span.end):
            raw.segment = span.index
            yield _to_record(raw)


def _to_record(raw: RawBlock) -> BlockRecord:
    """Decompress a stored block into the :class:`BlockRecord` callers see."""
    if raw.flags & COMPRESSED:
        payload = _decompress_block_payload(raw)
    else:
        payload = raw.on_disk_payload
    return BlockRecord(
        block_type=raw.block_type,
        flags=raw.flags,
        length=raw.length,
        payload_version=raw.payload_version,
        block_uuid=raw.block_uuid,
        parent_uuid=raw.parent_uuid,
        prev_hash=raw.prev_hash,
        payload=payload,
        start_offset=raw.start_offset,
        end_offset=raw.end_offset,
        segment=raw.segment,
    )


def scan_extension_segments(
    f: BinaryIO, start: int,
) -> tuple[list[SegmentSpan], int]:
    """Locate extension segments after the EoC without reading payloads.

    Walks 80-byte block headers from ``start``, seeking over each payload.
    A run of blocks ends at an :data:`BlockType.EndOfExtension` block,
    which closes a terminated :class:`SegmentSpan`. The scan stops at
    EOF, at bytes that are not a block header (bad magic, length below
    the header size) or at a block that runs past EOF; blocks framed
    before that point form a final unterminated span. The terminator's
    payload is not inspected -- see :func:`span_count_valid`.

    Args:
        f: Block stream (plaintext for an encrypted slice).
        start: Offset just after the EndOfCapture block.

    Returns:
        ``(spans, trailing_start)`` where ``trailing_start`` is the end of
        the last terminated segment, or the start of an unterminated run
        when there is one. Bytes from ``trailing_start`` to EOF are
        trailing data. The file position afterwards is unspecified.
    """
    f.seek(0, 2)
    size = f.tell()
    spans: list[SegmentSpan] = []
    offset = start
    run_start, run_blocks = start, 0
    while True:
        header = _framed_header_at(f, offset, size)
        if header is None:
            break
        block_type, length = header
        offset += length
        run_blocks += 1
        if block_type == BlockType.EndOfExtension:
            spans.append(SegmentSpan(
                index=len(spans) + 1, start=run_start, end=offset,
                block_count=run_blocks, terminator_offset=offset - length,
                terminated=True,
            ))
            run_start, run_blocks = offset, 0
    if run_blocks:
        spans.append(SegmentSpan(
            index=len(spans) + 1, start=run_start, end=offset,
            block_count=run_blocks, terminator_offset=None, terminated=False,
        ))
    return spans, run_start


def _framed_header_at(f: BinaryIO, offset: int, size: int) -> tuple[int, int] | None:
    """Return ``(block_type, length)`` of a well-framed block at ``offset``.

    ``None`` when fewer than 80 bytes remain, the magic is wrong, the
    length is below the header size, or the block runs past ``size``.
    """
    if offset + BLOCK_HEADER_SIZE > size:
        return None
    f.seek(offset)
    header = f.read(BLOCK_HEADER_SIZE)
    if len(header) < BLOCK_HEADER_SIZE or header[:4] != BLOCK_MAGIC:
        return None
    block_type, length = struct.unpack_from("<HxxI", header, 4)
    if length < BLOCK_HEADER_SIZE or offset + length > size:
        return None
    return block_type, length


def span_count_valid(f: BinaryIO, span: SegmentSpan) -> bool:
    """Whether a terminated span's ``EndOfExtension`` counts its blocks exactly.

    Reads just the terminator block and compares its ``BlockCount`` with
    ``span.block_count``. ``False`` for an unterminated span or an
    unparsable terminator. The file position afterwards is unspecified.
    """
    from memslicer.msl.writer import parse_end_of_extension

    if not span.terminated or span.terminator_offset is None:
        return False
    f.seek(span.terminator_offset)
    try:
        terminator = _to_record(next(_iter_raw_blocks(f, end=span.end)))
        declared = parse_end_of_extension(terminator.payload).block_count
    except (ValueError, NotImplementedError, StopIteration):
        return False
    return declared == span.block_count


def _decompress_block_payload(raw: RawBlock) -> bytes:
    """Undo writer-side compression of a block and strip the size prefix.

    Raises :class:`ValueError` when the payload is too small, fails to
    decompress, or decompresses to a size other than ``UncompressedSize``.
    """
    start = raw.start_offset
    on_disk_payload = raw.on_disk_payload
    if len(on_disk_payload) < 8:
        raise ValueError(
            f"compressed block at offset {start} too small to "
            f"contain UncompressedSize prefix"
        )
    uncompressed_size = struct.unpack("<Q", on_disk_payload[:8])[0]
    comp_algo = CompAlgo((raw.flags & COMPALGO_MASK) >> 1)
    # Spec Section 4.2.1 (Table 9) stores UncompressedSize(8B) +
    # CompressedData with no padding. Older memslicer releases padded
    # that tuple to 8B; zstd ignores the trailing zeros but lz4 rejects
    # them, so on failure up to 7 trailing zero bytes are trimmed. The
    # UncompressedSize check below guards against a false success.
    compressed_data = on_disk_payload[8:]
    try:
        payload = decompress_tolerating_padding(compressed_data, comp_algo)
    except Exception as exc:
        raise ValueError(
            f"decompression failed at offset {start}: {exc}"
        ) from exc
    if len(payload) != uncompressed_size:
        raise ValueError(
            f"decompressed size mismatch at offset {start}: "
            f"expected {uncompressed_size}, got {len(payload)}"
        )
    return payload


def _iter_raw_blocks(f: BinaryIO, *, end: int | None = None) -> Iterator[RawBlock]:
    """Yield blocks as stored, starting at the current file position.

    Each block header is read and validated (magic, ``CONTINUATION``,
    length) and its on-disk payload read, without decompression.
    Iteration stops at EOF, or at ``end`` (a stream offset no block may
    start at or cross) when one is given; it does NOT stop at
    :data:`BlockType.EndOfCapture` -- callers decide whether trailing
    data after it matters. Structural errors raise :class:`ValueError`.
    """
    while True:
        start = f.tell()
        if end is not None and start >= end:
            return
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
        if end is not None and start + length > end:
            raise ValueError(
                f"block at offset {start} with length {length} crosses the "
                f"segment end at offset {end}"
            )

        on_disk_payload = f.read(payload_len)
        if len(on_disk_payload) < payload_len:
            raise ValueError(
                f"truncated payload at offset {start}: "
                f"got {len(on_disk_payload)} bytes, expected {payload_len}"
            )

        yield RawBlock(
            block_type=block_type,
            flags=flags,
            length=length,
            payload_version=payload_version,
            block_uuid=block_uuid,
            parent_uuid=parent_uuid,
            prev_hash=prev_hash,
            header_bytes=block_header,
            on_disk_payload=on_disk_payload,
            start_offset=start,
            end_offset=f.tell(),
        )
