"""Standalone integrity verifier for MSL slices.

Recomputes the PrevHash chain (spec Section 4.4) and the End-of-Capture
FileHash (Section 4.5) exactly the way :class:`MSLWriter` produces them,
by feeding the same :class:`IntegrityChain` with the header and the
on-disk (possibly compressed) block bytes.

The capture segment's block count is cross-checked against every
non-zero declaration (header ``BlockCount``, EoC ``BlockCount``); a
mismatch means the file is truncated or corrupt (consumer rule 13).

Extension segments (Section 4.6) are verified after the EoC: the chain
continues through the EoC block, each segment's ``EndOfExtension`` must
carry the digest of the segment's preceding bytes and its exact block
count. The first segment that fails, or is not terminated, turns the rest
of the file into trailing data.

For an encrypted slice the AEAD tag is the integrity mechanism: every
PrevHash MUST be zero, and the FileHash is checked over the decrypted
plaintext stream; extension segments live inside that stream.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from memslicer.msl.constants import COMPRESSED, FLAG_ENCRYPTED, BlockType, HashAlgo
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.iterator import (
    RawBlock,
    SegmentSpan,
    _decompress_block_payload,
    _iter_raw_blocks,
    decrypt_stream,
    read_file_header_info,
    scan_extension_segments,
)
from memslicer.msl.writer import parse_end_of_capture, parse_end_of_extension

_ZERO_HASH = b"\x00" * 32
_FILE_HASH_SIZE = 32
_BLOCK_COUNT_OFFSET = 0x39
"""Offset of the 4-byte BlockCount field in the file header (spec Table 3)."""


@dataclass
class SegmentReport:
    """Outcome of verifying one extension segment (spec Section 4.6).

    ``block_count`` is the number of blocks framed in the segment,
    including the terminator; ``declared_block_count`` is the terminator's
    ``BlockCount`` (0 when the segment is unterminated). ``chain_ok`` and
    ``segment_hash_ok`` are ``None`` when the check could not be run,
    which only happens for an unterminated segment.
    """

    index: int
    start_offset: int
    block_count: int
    declared_block_count: int
    terminated: bool
    chain_ok: bool | None
    segment_hash_ok: bool | None
    producer: str = ""
    written_at_ns: int = 0

    @property
    def verified(self) -> bool:
        """Whether the segment passed termination, chain, hash and count checks."""
        return (
            self.terminated
            and self.chain_ok is True
            and self.segment_hash_ok is True
            and self.block_count == self.declared_block_count
        )


@dataclass
class VerifyReport:
    """Outcome of :func:`verify_slice`.

    ``broken_at`` is the index of the first block whose PrevHash did not
    verify; blocks are numbered continuously from Block 0 through every
    extension segment. ``file_hash_ok`` is ``None`` when no EndOfCapture
    block was reached. ``block_count`` is the number of capture-segment
    blocks including the EoC; ``eoc_block_count`` is the count the EoC
    declares (0 = unknown, legacy 40-byte payload) and ``block_count_ok``
    whether every non-zero declaration matched (``None`` without an EoC).
    ``trailing_bytes`` counts the bytes after the last verified segment
    (or after the EoC). A slice is valid when no errors were recorded;
    warnings (legacy layouts, missing EoC, trailing data) do not
    invalidate it.
    """

    hash_algo: HashAlgo
    encrypted: bool
    header_block_count: int
    block_count: int = 0
    eoc_present: bool = False
    file_hash_ok: bool | None = None
    broken_at: int | None = None
    eoc_block_count: int = 0
    block_count_ok: bool | None = None
    segments: list[SegmentReport] = field(default_factory=list)
    trailing_bytes: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Whether the slice passed every integrity check."""
        return not self.errors

    @property
    def chain_ok(self) -> bool:
        """Whether every PrevHash verified (all-zero when encrypted)."""
        return self.broken_at is None

    @property
    def capture_ok(self) -> bool:
        """Whether the capture segment alone verified, whatever follows it.

        True when the EoC was reached, its FileHash matched, no block
        count disagreed and no capture-segment PrevHash was broken.
        """
        return (
            self.eoc_present
            and self.file_hash_ok is True
            and self.block_count_ok is not False
            and (self.broken_at is None or self.broken_at >= self.block_count)
        )


def verify_slice(f: BinaryIO, passphrase: str | None = None) -> VerifyReport:
    """Verify the hash chain, EoC FileHash and extension segments of an MSL file.

    Args:
        f: MSL file opened in ``"rb"`` mode.
        passphrase: Required when the slice is encrypted.

    Returns:
        A :class:`VerifyReport`. Integrity failures, a failed decryption
        and structural errors are reported in it, not raised.

    Raises:
        ValueError: If the file header is unreadable, or the slice is
            encrypted and no passphrase was given.
    """
    header_size, hash_algo, flags = read_file_header_info(f)
    f.seek(0)
    header_bytes = f.read(header_size)
    report = VerifyReport(
        hash_algo=hash_algo,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        header_block_count=struct.unpack_from("<I", header_bytes, _BLOCK_COUNT_OFFSET)[0],
    )
    stream = _open_block_stream(f, header_size, report, passphrase)
    if stream is None:
        return report
    chain = IntegrityChain(hash_algo)
    chain.feed_header(header_bytes)
    _walk_blocks(stream, chain, report)
    return report


def _open_block_stream(
    f: BinaryIO, header_size: int, report: VerifyReport, passphrase: str | None,
) -> BinaryIO | None:
    """Return a stream positioned at Block 0, or ``None`` if decryption failed."""
    if not report.encrypted:
        f.seek(header_size)
        return f
    if passphrase is None:
        raise ValueError("slice is encrypted; a passphrase is required to verify it")
    try:
        return decrypt_stream(f, header_size, passphrase)
    except ValueError as exc:
        report.errors.append(str(exc))
        return None


def _walk_blocks(stream: BinaryIO, chain: IntegrityChain, report: VerifyReport) -> None:
    """Check every capture-segment block, then hand over to the extension walk."""
    try:
        for raw in _iter_raw_blocks(stream):
            index = report.block_count
            report.block_count += 1
            _check_prev_hash(raw, index, chain, report)
            if raw.block_type == BlockType.EndOfCapture:
                _check_file_hash(raw, index, chain, report)
                _check_block_count(report)
                # The chain continues through the EoC: the first extension
                # block's PrevHash is H(EoC bytes) (spec Section 4.6).
                chain.feed_block_parts(raw.header_bytes, raw.on_disk_payload)
                _walk_extensions(stream, raw.end_offset, chain, report)
                return
            chain.feed_block_parts(raw.header_bytes, raw.on_disk_payload)
    except (ValueError, NotImplementedError) as exc:
        report.errors.append(f"block {report.block_count}: structural error: {exc}")
        return
    report.warnings.append("no EndOfCapture block; FileHash not verified (truncated?)")


def _check_prev_hash(
    raw: RawBlock, index: int, chain: IntegrityChain, report: VerifyReport,
) -> bool:
    """Compare one block's PrevHash against the recomputed chain.

    Returns ``True`` when the PrevHash is acceptable (verified, zero in an
    encrypted slice, or the tolerated legacy zero on Block 0).
    """
    if report.encrypted:
        if raw.prev_hash != _ZERO_HASH:
            _chain_error(report, raw, index, "non-zero PrevHash in encrypted slice")
            return False
        return True
    if raw.prev_hash == chain.prev_hash:
        return True
    if index == 0 and raw.prev_hash == _ZERO_HASH:
        report.warnings.append("block 0: all-zero PrevHash (legacy unchained header)")
        return True
    _chain_error(report, raw, index, "PrevHash mismatch")
    return False


def _chain_error(report: VerifyReport, raw: RawBlock, index: int, what: str) -> None:
    """Record a chain failure, remembering the first broken block."""
    report.errors.append(f"block {index} @0x{raw.start_offset:X}: {what}")
    if report.broken_at is None:
        report.broken_at = index


def _check_file_hash(
    raw: RawBlock, index: int, chain: IntegrityChain, report: VerifyReport,
) -> None:
    """Compare the EoC FileHash with the digest of everything before it.

    Also records the EoC's declared ``BlockCount`` (0 for a legacy
    40-byte payload).
    """
    report.eoc_present = True
    payload = _block_payload(raw)
    stored = payload[:_FILE_HASH_SIZE]
    report.file_hash_ok = (
        len(stored) == _FILE_HASH_SIZE and stored == chain.finalize()
    )
    if not report.file_hash_ok:
        report.errors.append(f"block {index} @0x{raw.start_offset:X}: EoC FileHash mismatch")
    try:
        report.eoc_block_count = parse_end_of_capture(payload).block_count
    except ValueError as exc:
        report.errors.append(f"block {index} @0x{raw.start_offset:X}: {exc}")


def _block_payload(raw: RawBlock) -> bytes:
    """Return a block's payload as the writer saw it (decompressed if needed)."""
    if raw.flags & COMPRESSED:
        return _decompress_block_payload(raw)
    return raw.on_disk_payload


def _check_block_count(report: VerifyReport) -> None:
    """Fail when a non-zero header or EoC BlockCount disagrees with the walk.

    ``report.block_count`` must already include the EoC block. Consumer
    rule 13: a disagreeing count means the file is truncated or corrupt.
    """
    parsed = report.block_count
    report.block_count_ok = True
    for label, declared in (
        ("header", report.header_block_count), ("EoC", report.eoc_block_count),
    ):
        if declared and declared != parsed:
            report.errors.append(f"{label} BlockCount {declared} != {parsed} blocks")
            report.block_count_ok = False


def _walk_extensions(
    stream: BinaryIO, start: int, chain: IntegrityChain, report: VerifyReport,
) -> None:
    """Verify every extension segment after the EoC; the rest is trailing data.

    ``chain`` must have been fed the EoC block already. Stops at the first
    segment that is unterminated or fails verification (spec Section 4.6).
    """
    spans, trailing_start = scan_extension_segments(stream, start)
    next_index = report.block_count
    for span in spans:
        segment = _verify_segment(stream, span, next_index, chain, report)
        report.segments.append(segment)
        if not segment.verified:
            trailing_start = span.start
            break
        next_index += segment.block_count
    _note_trailing_bytes(stream, trailing_start, report)


def _verify_segment(
    stream: BinaryIO, span: SegmentSpan, first_index: int,
    chain: IntegrityChain, report: VerifyReport,
) -> SegmentReport:
    """Check one span's chain continuity, SegmentHash and BlockCount."""
    segment = SegmentReport(
        index=span.index, start_offset=span.start, block_count=span.block_count,
        declared_block_count=0, terminated=span.terminated,
        chain_ok=None, segment_hash_ok=None,
    )
    if not span.terminated:
        _note_unterminated(stream, span, report)
        return segment
    chain.start_segment()
    stream.seek(span.start)
    try:
        _check_segment_blocks(stream, span, first_index, chain, report, segment)
    except (ValueError, NotImplementedError) as exc:
        report.errors.append(f"segment {span.index}: structural error: {exc}")
        segment.chain_ok = False
    finally:
        if chain.in_segment:
            chain.end_segment()
    return segment


def _check_segment_blocks(
    stream: BinaryIO, span: SegmentSpan, first_index: int,
    chain: IntegrityChain, report: VerifyReport, segment: SegmentReport,
) -> None:
    """Feed a terminated span through the chain, checking its terminator last."""
    segment.chain_ok = True
    parsed = 0
    for raw in _iter_raw_blocks(stream, end=span.end):
        raw.segment = span.index
        if not _check_prev_hash(raw, first_index + parsed, chain, report):
            segment.chain_ok = False
        parsed += 1
        if raw.block_type == BlockType.EndOfExtension:
            # The SegmentHash covers the bytes before the terminator, so
            # take the digest before the terminator itself is fed.
            _check_terminator(raw, chain.segment_digest(), parsed, report, segment)
        chain.feed_block_parts(raw.header_bytes, raw.on_disk_payload)
    segment.block_count = parsed


def _check_terminator(
    raw: RawBlock, digest: bytes, parsed: int,
    report: VerifyReport, segment: SegmentReport,
) -> None:
    """Compare an EndOfExtension's SegmentHash and BlockCount with the walk."""
    terminator = parse_end_of_extension(_block_payload(raw))
    segment.declared_block_count = terminator.block_count
    segment.producer = terminator.producer
    segment.written_at_ns = terminator.written_at_ns
    segment.segment_hash_ok = terminator.segment_hash == digest
    if not segment.segment_hash_ok:
        report.errors.append(
            f"segment {segment.index} @0x{raw.start_offset:X}: SegmentHash mismatch"
        )
    if terminator.block_count != parsed:
        report.errors.append(
            f"segment {segment.index}: EndOfExtension BlockCount "
            f"{terminator.block_count} != {parsed} blocks"
        )


def _note_unterminated(stream: BinaryIO, span: SegmentSpan, report: VerifyReport) -> None:
    """Warn about a run of blocks after the EoC that no EndOfExtension closes."""
    stream.seek(0, 2)
    report.warnings.append(
        f"extension segment {span.index} unterminated; "
        f"{stream.tell() - span.start} byte(s) treated as trailing"
    )


def _note_trailing_bytes(stream: BinaryIO, trailing_start: int, report: VerifyReport) -> None:
    """Record bytes after the last verified segment (non-MSL trailing data, spec Section 4.5)."""
    stream.seek(0, 2)
    report.trailing_bytes = max(0, stream.tell() - trailing_start)
    if report.trailing_bytes > 0:
        report.warnings.append(
            f"{report.trailing_bytes} trailing byte(s) after EndOfCapture ignored"
        )
