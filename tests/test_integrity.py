"""Tests for BLAKE3 integrity chain."""
import blake3
import pytest
from memslicer.msl.integrity import IntegrityChain


def test_initial_prev_hash():
    chain = IntegrityChain()
    assert chain.prev_hash == b'\x00' * 32


def test_feed_header():
    chain = IntegrityChain()
    header_bytes = b'\x01' * 64
    result = chain.feed_header(header_bytes)
    expected = blake3.blake3(header_bytes).digest()
    assert result == expected
    assert chain.prev_hash == expected


def test_chain_sequence():
    chain = IntegrityChain()
    header = b'\xaa' * 64

    # Feed header
    h_hash = chain.feed_header(header)
    assert h_hash == blake3.blake3(header).digest()

    # Feed block 0
    block0 = b'\xbb' * 100
    b0_hash = chain.feed_block(block0)
    assert b0_hash == blake3.blake3(block0).digest()
    assert chain.prev_hash == b0_hash

    # Feed block 1
    block1 = b'\xcc' * 200
    b1_hash = chain.feed_block(block1)
    assert b1_hash == blake3.blake3(block1).digest()
    assert chain.prev_hash == b1_hash


def test_finalize():
    chain = IntegrityChain()
    header = b'\x01' * 64
    block = b'\x02' * 100

    chain.feed_header(header)
    chain.feed_block(block)

    # finalize should hash entire file content
    expected_hasher = blake3.blake3()
    expected_hasher.update(header)
    expected_hasher.update(block)

    assert chain.finalize() == expected_hasher.digest()


def test_prev_hash_updates():
    """Verify each block's prev_hash reflects the previous item in the chain."""
    chain = IntegrityChain()

    header = b'\x01' * 64
    chain.feed_header(header)
    prev_after_header = chain.prev_hash

    block0 = b'\x02' * 80
    chain.feed_block(block0)
    prev_after_block0 = chain.prev_hash

    # prev_hash should have changed
    assert prev_after_header != prev_after_block0
    assert prev_after_block0 == blake3.blake3(block0).digest()


# ---------------------------------------------------------------------------
# Extension segment hasher (spec Section 4.6)
# ---------------------------------------------------------------------------

def test_segment_digest_covers_only_segment_blocks():
    """Header and pre-segment blocks are excluded; both feed methods count."""
    chain = IntegrityChain()
    header = b'\x01' * 64
    before = b'\x02' * 90
    seg_a = b'\x03' * 100
    seg_b_head, seg_b_body = b'\x04' * 80, b'\x05' * 24

    chain.feed_header(header)
    chain.feed_block(before)
    chain.start_segment()
    chain.feed_block(seg_a)
    chain.feed_block_parts(seg_b_head, seg_b_body)

    expected = blake3.blake3(seg_a + seg_b_head + seg_b_body).digest()
    assert chain.segment_digest() == expected
    assert chain.segment_digest() != blake3.blake3(header + before + seg_a + seg_b_head + seg_b_body).digest()


def test_segment_digest_without_segment_raises():
    chain = IntegrityChain()
    with pytest.raises(ValueError, match="no segment"):
        chain.segment_digest()


def test_end_segment_without_segment_raises():
    chain = IntegrityChain()
    with pytest.raises(ValueError, match="no segment"):
        chain.end_segment()


def test_start_segment_twice_raises():
    chain = IntegrityChain()
    chain.start_segment()
    with pytest.raises(ValueError, match="already started"):
        chain.start_segment()


def test_blocks_after_end_segment_not_in_next_segment():
    """A closed segment's blocks never leak into a later segment's digest."""
    chain = IntegrityChain()
    chain.feed_header(b'\x01' * 64)
    chain.start_segment()
    chain.feed_block(b'\x02' * 100)
    chain.end_segment()
    chain.feed_block(b'\x03' * 100)  # between segments
    chain.start_segment()
    second = b'\x04' * 100
    chain.feed_block(second)
    assert chain.segment_digest() == blake3.blake3(second).digest()


def test_segment_digest_is_reset_by_new_segment():
    chain = IntegrityChain()
    chain.start_segment()
    chain.feed_block(b'\x02' * 100)
    first = chain.segment_digest()
    chain.end_segment()
    chain.start_segment()
    chain.feed_block(b'\x02' * 100)
    assert chain.segment_digest() == first  # same bytes, fresh hasher


def test_segment_does_not_affect_file_digest_or_prev_hash():
    """The file hash and PrevHash chain are the same with or without segments."""
    header = b'\x01' * 64
    blocks = [b'\x02' * 100, b'\x03' * 120, b'\x04' * 80]

    plain = IntegrityChain()
    plain.feed_header(header)
    for block in blocks:
        plain.feed_block(block)

    segmented = IntegrityChain()
    segmented.feed_header(header)
    segmented.feed_block(blocks[0])
    segmented.start_segment()
    segmented.feed_block(blocks[1])
    segmented.feed_block(blocks[2])
    segmented.end_segment()

    assert segmented.finalize() == plain.finalize()
    assert segmented.prev_hash == plain.prev_hash


def test_in_segment_property():
    chain = IntegrityChain()
    assert chain.in_segment is False
    chain.start_segment()
    assert chain.in_segment is True
    chain.end_segment()
    assert chain.in_segment is False
