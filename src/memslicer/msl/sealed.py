"""MSL spec Section 10.8 – sealed extension segments.

An encrypted container (header ``CipherLen`` non-zero) can be enriched
after its primary AEAD tag has been written by appending sealed segments::

    … | primary tag | SealHeader 1 | ciphertext 1 | tag 1 | … | [trailing data]

Each sealed segment is a separate AES-256-GCM message under
``SegKey_i`` = HKDF-BLAKE3(CEK, DumpUUID, "MSL-SEG-v1" ‖ LE16(i)), with a
fresh nonce in its cleartext 64-byte :class:`SealHeader` (Table 27a). Its
associated data chains it to the file and to the preceding tag::

    AAD_i = header (CipherLen zeroed) ‖ KEM ciphertext ‖ SealHeader_i ‖ Tag_{i-1}

with ``Tag_0`` the primary tag. The plaintext is exactly one extension
segment (spec Section 4.6) whose ``PrevHash`` fields are zero.

:func:`seal_segment` is the write primitive; :func:`open_sealed_segments`
verifies the segments after a primary tag and returns only those whose
tag and plaintext both verify. The ``Magic`` is stored as the ASCII bytes
``b"MSLS"`` (see :data:`memslicer.msl.constants.SEAL_MAGIC`).
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, replace
from io import BytesIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memslicer.msl.constants import (
    EXTENSION_FORBIDDEN_TYPES,
    SEAL_HEADER_SIZE,
    SEAL_MAGIC,
    HashAlgo,
)
from memslicer.msl.encryption import (
    AES_GCM_NONCE_LEN,
    AES_GCM_TAG_LEN,
    CIPHER_LEN_OFFSET,
    MAX_SEGMENT_INDEX,
    NONCE_FIELD_LEN,
    aad_from_header,
    derive_segment_key,
)
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.iterator import _iter_raw_blocks, scan_extension_segments
from memslicer.msl.verify import SegmentReport, VerifyReport, _verify_segment

_SEAL_HEADER = struct.Struct("<4sHHQ24s24s")
_DUMP_UUID_SLICE = slice(0x18, 0x28)
"""``DumpUUID`` in the file header (spec Table 3), the HKDF salt."""
_HASH_ALGO_OFFSET = 0x3D
_RESERVED = b"\x00" * 24


# ---------------------------------------------------------------------------
# SealHeader (Table 27a)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SealHeader:
    """The 64-byte cleartext header in front of each sealed segment.

    ``nonce`` holds the 12 AES-GCM nonce bytes; on disk they are padded
    with zeros to the 24-byte field, like the file header ``Nonce``.
    """

    seg_index: int
    seg_cipher_len: int
    nonce: bytes
    magic: bytes = SEAL_MAGIC
    seal_hdr_size: int = SEAL_HEADER_SIZE

    def pack(self) -> bytes:
        """Serialize to the 64-byte on-disk form."""
        nonce_field = self.nonce.ljust(NONCE_FIELD_LEN, b"\x00")
        return _SEAL_HEADER.pack(
            self.magic, self.seal_hdr_size, self.seg_index,
            self.seg_cipher_len, nonce_field, _RESERVED,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "SealHeader":
        """Parse 64 bytes; field values are not validated here.

        Raises:
            ValueError: if ``raw`` is not exactly 64 bytes.
        """
        if len(raw) != SEAL_HEADER_SIZE:
            raise ValueError(f"SealHeader must be {SEAL_HEADER_SIZE} bytes, got {len(raw)}")
        magic, size, index, cipher_len, nonce_field, _reserved = _SEAL_HEADER.unpack(raw)
        return cls(
            seg_index=index, seg_cipher_len=cipher_len,
            nonce=nonce_field[:AES_GCM_NONCE_LEN], magic=magic, seal_hdr_size=size,
        )


@dataclass(frozen=True)
class SealedSegment:
    """A sealed segment whose tag and plaintext segment both verified.

    ``offset`` is the file offset of its :class:`SealHeader` and ``end``
    the offset just after its tag. ``plaintext`` is the decrypted
    extension segment (blocks through the End-of-Extension block), and
    ``tag`` its AEAD tag -- the ``prev_tag`` of the next segment.
    ``report`` is the segment verification outcome (block count, producer).
    """

    index: int
    plaintext: bytes
    offset: int
    end: int
    tag: bytes
    report: SegmentReport


# ---------------------------------------------------------------------------
# Write primitive
# ---------------------------------------------------------------------------
def segment_aad(header: bytes, kem_ct: bytes, seal_header: bytes, prev_tag: bytes) -> bytes:
    """``AAD_i`` = header (CipherLen zeroed) ‖ KEM ct ‖ SealHeader_i ‖ Tag_{i-1}."""
    return aad_from_header(header, kem_ct) + bytes(seal_header) + bytes(prev_tag)


def seal_segment(
    cek: bytes, header_bytes: bytes, kem_ct: bytes, prev_tag: bytes,
    index: int, plaintext: bytes,
) -> bytes:
    """Encrypt one extension segment as sealed segment ``index``.

    Returns ``SealHeader ‖ ciphertext ‖ tag``, to be written as one unit
    right after the primary tag (``index`` 1) or the previous sealed
    segment. The caller must already have verified the container and
    every earlier sealed segment (spec Section 10.8, producer rules).

    Args:
        cek: Content-encryption key of the container.
        header_bytes: The file header exactly as on disk.
        kem_ct: KEM ciphertext after the header (``b""`` when none).
        prev_tag: Tag of segment ``index - 1``; the primary tag for 1.
        index: 1-based ``SegIndex``.
        plaintext: One extension segment with zero ``PrevHash`` fields,
            e.g. built with :meth:`MSLWriter.for_sealed_segment`.

    Raises:
        ValueError: if the header ``CipherLen`` is 0, ``plaintext`` is
            empty, ``prev_tag`` is not 16 bytes or ``index`` is out of range.
    """
    _require_sealable(header_bytes, prev_tag, plaintext)
    nonce = os.urandom(AES_GCM_NONCE_LEN)
    seal_header = SealHeader(index, len(plaintext), nonce).pack()
    key = derive_segment_key(cek, bytes(header_bytes[_DUMP_UUID_SLICE]), index)
    aad = segment_aad(header_bytes, kem_ct, seal_header, prev_tag)
    return seal_header + AESGCM(key).encrypt(nonce, bytes(plaintext), aad)


def _require_sealable(header_bytes: bytes, prev_tag: bytes, plaintext: bytes) -> None:
    """Refuse inputs spec Section 10.8 does not admit."""
    if _cipher_len(header_bytes) == 0:
        raise ValueError("sealed segments require a non-zero header CipherLen (spec Section 10.8)")
    if len(prev_tag) != AES_GCM_TAG_LEN:
        raise ValueError(f"prev_tag must be {AES_GCM_TAG_LEN} bytes, got {len(prev_tag)}")
    if not plaintext:
        raise ValueError("sealed segment plaintext is empty")


def _cipher_len(header_bytes: bytes) -> int:
    """The header ``CipherLen`` (0 when the header is too short to hold it)."""
    if len(header_bytes) < CIPHER_LEN_OFFSET + 8:
        return 0
    return struct.unpack_from("<Q", header_bytes, CIPHER_LEN_OFFSET)[0]


# ---------------------------------------------------------------------------
# Read path
# ---------------------------------------------------------------------------
def open_sealed_segments(
    cek: bytes, header_bytes: bytes, kem_ct: bytes, primary_tag: bytes,
    data: bytes | memoryview, start: int,
) -> tuple[list[SealedSegment], int]:
    """Verify the sealed segments in ``data`` from offset ``start``.

    Segments are parsed in order, i = 1, 2, …; the first that fails (short
    read, bad ``Magic``/``SealHdrSize``, ``SegIndex`` ≠ i, ``SegCipherLen``
    zero or too large, tag failure, malformed plaintext segment) ends the
    walk, and everything from its first byte is trailing data. Plaintext
    of a segment whose tag failed is never returned. With a header
    ``CipherLen`` of 0 nothing is parsed.

    Args:
        cek: Content-encryption key of the container.
        header_bytes: The file header exactly as on disk.
        kem_ct: KEM ciphertext after the header (``b""`` when none).
        primary_tag: The verified primary AEAD tag (``Tag_0``).
        data: The whole file (offsets in the result are into it).
        start: Offset just after the primary tag.

    Returns:
        ``(segments, trailing_offset)``: the verified segments and the
        offset where trailing data begins (``len(data)`` when none).
    """
    segments: list[SealedSegment] = []
    offset, prev_tag = start, bytes(primary_tag)
    if _cipher_len(header_bytes) == 0:
        return segments, offset
    while len(segments) < MAX_SEGMENT_INDEX:
        segment = _open_one(
            cek, header_bytes, kem_ct, prev_tag, data, offset, len(segments) + 1,
        )
        if segment is None:
            break
        segments.append(segment)
        offset, prev_tag = segment.end, segment.tag
    return segments, offset


def _open_one(
    cek: bytes, header_bytes: bytes, kem_ct: bytes, prev_tag: bytes,
    data: bytes | memoryview, offset: int, index: int,
) -> SealedSegment | None:
    """Verify sealed segment ``index`` at ``offset``; ``None`` on any failure."""
    raw_header = bytes(data[offset:offset + SEAL_HEADER_SIZE])
    seal_header = _check_seal_header(raw_header, len(data) - offset, index)
    if seal_header is None:
        return None
    body_start = offset + SEAL_HEADER_SIZE
    end = body_start + seal_header.seg_cipher_len + AES_GCM_TAG_LEN
    sealed = bytes(data[body_start:end])
    aad = segment_aad(header_bytes, kem_ct, raw_header, prev_tag)
    plaintext = _decrypt(cek, header_bytes, seal_header, sealed, aad)
    if plaintext is None:
        return None
    report = verify_segment_plaintext(plaintext, _hash_algo(header_bytes), index)
    if report is None:
        return None
    report.start_offset = offset
    return SealedSegment(
        index=index, plaintext=plaintext, offset=offset, end=end,
        tag=sealed[-AES_GCM_TAG_LEN:], report=report,
    )


def _check_seal_header(raw: bytes, remaining: int, index: int) -> SealHeader | None:
    """Parse and check a ``SealHeader``; ``None`` if segment ``index`` cannot start here.

    ``remaining`` counts the bytes from the header's first byte to EOF.
    """
    if len(raw) < SEAL_HEADER_SIZE:
        return None
    seal_header = SealHeader.unpack(raw)
    room = remaining - SEAL_HEADER_SIZE - AES_GCM_TAG_LEN
    if (
        seal_header.magic != SEAL_MAGIC
        or seal_header.seal_hdr_size != SEAL_HEADER_SIZE
        or seal_header.seg_index != index
        or not 0 < seal_header.seg_cipher_len <= room
    ):
        return None
    return seal_header


def _decrypt(
    cek: bytes, header_bytes: bytes, seal_header: SealHeader, sealed: bytes, aad: bytes,
) -> bytes | None:
    """Authenticate and decrypt ``ciphertext ‖ tag``; ``None`` if the tag fails.

    ``aad`` contains the on-disk ``SealHeader`` bytes, so any change to
    them -- reserved bytes and nonce padding included -- fails the tag.
    """
    key = derive_segment_key(cek, bytes(header_bytes[_DUMP_UUID_SLICE]), seal_header.seg_index)
    try:
        return AESGCM(key).decrypt(seal_header.nonce, sealed, aad)
    except InvalidTag:
        return None


def _hash_algo(header_bytes: bytes) -> HashAlgo:
    """The file's integrity ``HashAlgo`` (spec Table 3, offset 0x3D)."""
    return HashAlgo(header_bytes[_HASH_ALGO_OFFSET])


def verify_segment_plaintext(
    plaintext: bytes, hash_algo: HashAlgo, index: int,
) -> SegmentReport | None:
    """Check that ``plaintext`` is exactly one valid extension segment.

    Reuses the plaintext extension-segment checks of
    :mod:`memslicer.msl.verify` (zero ``PrevHash``, ``SegmentHash``,
    ``BlockCount``) and additionally requires the End-of-Extension block
    to end exactly at the end of ``plaintext`` and no evidence block type
    (spec Section 4.6, "Permitted block types").

    Returns:
        The :class:`SegmentReport` when every check passed, else ``None``.
    """
    stream = BytesIO(plaintext)
    spans, _trailing = scan_extension_segments(stream, 0)
    if len(spans) != 1 or not spans[0].terminated or spans[0].end != len(plaintext):
        return None
    span = replace(spans[0], index=index)
    scratch = VerifyReport(hash_algo=hash_algo, encrypted=True, header_block_count=0)
    report = _verify_segment(stream, span, 0, IntegrityChain(hash_algo), scratch)
    if not report.verified or scratch.errors or _has_forbidden_block(stream, span.end):
        return None
    return report


def _has_forbidden_block(stream: BytesIO, end: int) -> bool:
    """Whether any block before ``end`` is an evidence type (spec Section 4.6)."""
    stream.seek(0)
    return any(
        raw.block_type in EXTENSION_FORBIDDEN_TYPES
        for raw in _iter_raw_blocks(stream, end=end)
    )

