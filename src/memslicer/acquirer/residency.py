"""Page-residency helpers shared by the debugger bridges.

A memory region can be far larger than the part of it the target has ever
touched: a thread stack is reserved at 8 MiB and used for a few pages, a heap
arena is mapped whole and filled lazily. Reading those untouched pages costs
transport time and yields nothing but zeros. ``/proc/<pid>/pagemap`` says,
per page, whether the kernel has backed it -- present in RAM or written out to
swap -- so a bridge that can reach it reads only the pages that hold data.

The host-side reader here serves the GDB and LLDB bridges, which run on the
same machine as a local target. The Frida bridge does the same from inside the
target and only shares the pure helpers.

Mask convention used throughout: one byte per page, ``1`` meaning the page
must be read (present or swapped), ``0`` meaning it was never touched.
"""
from __future__ import annotations

import re

# Bit layout of a /proc/<pid>/pagemap entry (Documentation/admin-guide/mm/pagemap.rst).
PAGEMAP_PRESENT = 1 << 63
PAGEMAP_SWAPPED = 1 << 62

# Each pagemap entry is a 64-bit little-endian word.
_ENTRY_SIZE = 8

# Both residency bits live in the top byte of the entry.
_TOP_BYTE_MASK = 0xC0

_VM_SWAP_RE = re.compile(r"^VmSwap:\s*(\d+)\s*kB", re.MULTILINE)


def _pagemap_path(pid: int) -> str:
    """Path of the pagemap file for *pid*; a function so tests can redirect it."""
    return f"/proc/{pid}/pagemap"


def page_count(base: int, size: int, page_size: int) -> int:
    """Number of pages that ``[base, base + size)`` touches.

    A span that is not page-aligned, or whose size is not a page multiple,
    is rounded outwards so that every byte of it is covered.

    Returns:
        The page count, ``0`` for an empty span.
    """
    if size <= 0 or page_size <= 0:
        return 0
    first = base // page_size
    last = (base + size - 1) // page_size
    return last - first + 1


def decode_pagemap(raw: bytes) -> bytes:
    """Turn raw pagemap entries into a residency mask.

    Args:
        raw: Concatenated 8-byte little-endian pagemap entries. A trailing
            partial entry is ignored.

    Returns:
        One byte per entry, ``1`` when the page is present or swapped.
    """
    top_bytes = raw[_ENTRY_SIZE - 1::_ENTRY_SIZE]
    return bytes(1 if b & _TOP_BYTE_MASK else 0 for b in top_bytes)


def pagemap_readable(pid: int) -> bool:
    """Whether ``/proc/<pid>/pagemap`` can be opened for reading.

    Since Linux 4.2 the residency bits are readable without privilege (only
    the frame numbers are hidden), so being able to open the file is the whole
    test.
    """
    try:
        with open(_pagemap_path(pid), "rb", buffering=0):
            return True
    except OSError:
        return False


def read_pagemap(pid: int, base: int, size: int, page_size: int) -> bytes | None:
    """Residency mask for ``[base, base + size)`` of a local process.

    Args:
        pid: PID of the process on this host.
        base: Start address of the span.
        size: Length of the span in bytes; rounded up to whole pages.
        page_size: The target's page size.

    Returns:
        The mask as :func:`decode_pagemap` builds it, or ``None`` when the
        file cannot be read or returns fewer entries than asked for (the
        span runs past the end of the address space, or the process died).
    """
    pages = page_count(base, size, page_size)
    if pages == 0:
        return b""
    wanted = pages * _ENTRY_SIZE
    try:
        with open(_pagemap_path(pid), "rb", buffering=0) as fh:
            fh.seek((base // page_size) * _ENTRY_SIZE)
            raw = _read_exact(fh, wanted)
    except OSError:
        return None
    if raw is None:
        return None
    return decode_pagemap(raw)


def _read_exact(fh, wanted: int) -> bytes | None:
    """Read exactly *wanted* bytes from *fh*, or ``None`` if the file ends first."""
    chunks: list[bytes] = []
    got = 0
    while got < wanted:
        chunk = fh.read(wanted - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def resident_runs(mask: bytes, max_gap_pages: int = 0) -> list[tuple[int, int]]:
    """Runs of pages to read, as ``(first_page_index, page_count)`` pairs.

    Consecutive resident pages form one run. With *max_gap_pages* greater than
    zero, two runs separated by that many non-resident pages or fewer are
    merged into one -- the gap is read as if it were resident, because one
    larger read is cheaper than two reads plus a seek.

    Args:
        mask: Residency mask, one byte per page.
        max_gap_pages: Largest gap of untouched pages to bridge.

    Returns:
        The runs in ascending order; ``[]`` for an empty or all-zero mask.
    """
    runs = _raw_runs(mask)
    if max_gap_pages <= 0 or len(runs) < 2:
        return runs
    return _merge_gaps(runs, max_gap_pages)


def _raw_runs(mask: bytes) -> list[tuple[int, int]]:
    """Maximal runs of ``1`` bytes in *mask*."""
    runs: list[tuple[int, int]] = []
    start: int | None = None
    for index, resident in enumerate(mask):
        if resident and start is None:
            start = index
        elif not resident and start is not None:
            runs.append((start, index - start))
            start = None
    if start is not None:
        runs.append((start, len(mask) - start))
    return runs


def _merge_gaps(
    runs: list[tuple[int, int]], max_gap_pages: int,
) -> list[tuple[int, int]]:
    """Join neighbouring runs whose separating gap is at most *max_gap_pages*."""
    merged = [runs[0]]
    for start, count in runs[1:]:
        prev_start, prev_count = merged[-1]
        gap = start - (prev_start + prev_count)
        if gap <= max_gap_pages:
            merged[-1] = (prev_start, start + count - prev_start)
        else:
            merged.append((start, count))
    return merged


def count_nonresident(mask: bytes, runs: list[tuple[int, int]]) -> int:
    """Pages of *mask* that no run in *runs* covers.

    With gap merging, bridged pages count as covered even though their mask
    byte is ``0``: they are read, so they are not skipped.
    """
    covered = sum(count for _, count in runs)
    return max(len(mask) - covered, 0)


def vm_swap_kb(status_text: str) -> int | None:
    """``VmSwap`` of a ``/proc/<pid>/status`` text in kB, ``None`` if absent."""
    match = _VM_SWAP_RE.search(status_text)
    return int(match.group(1)) if match else None
