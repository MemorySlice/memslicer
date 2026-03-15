"""Tests for BLAKE3 integrity chain."""
import blake3
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
