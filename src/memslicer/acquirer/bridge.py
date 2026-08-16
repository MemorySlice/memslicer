"""Backend-agnostic protocol and data types for debugger bridges."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from memslicer.msl.constants import ArchType, OSType


@dataclass
class PlatformInfo:
    """Platform information returned by a debugger bridge.

    Attributes:
        arch: Target architecture.
        os: Target operating system.
        pid: PID of the process on the target.
        page_size: Target page size in bytes.
        page_size_assumed: ``True`` when *page_size* is a default rather than
            an answer from the target. The finished file cannot express this
            on its own -- a region stores only ``PageSizeLog2`` and its
            page-state map is sized to match, so a wrong page size produces a
            capture that is self-consistent and wrong. Carrying the flag lets
            the acquisition record the uncertainty next to the data.
    """

    arch: ArchType
    os: OSType
    pid: int
    page_size: int
    page_size_assumed: bool = False


# Used when the target's page size cannot be established. 4 KiB is the most
# common page size and the safest guess: too small only costs granularity,
# whereas guessing too large would place page states for pages that do not
# exist.
FALLBACK_PAGE_SIZE = 4096

# Both bridges reach this state and should describe it identically. Takes the
# assumed size as its one argument.
ASSUMED_PAGE_SIZE_WARNING = (
    "Could not determine the target's page size; assuming %d. A 16K or 64K "
    "page target will be recorded with a page-state map that is too fine. "
    "The capture records this as the 'page_size_assumed_4k' warning."
)


@dataclass
class MemoryRange:
    """A memory range as reported by the debugger."""

    base: int
    size: int
    protection: str  # "rwx" / "r--" / etc.
    file_path: str = ""


@dataclass
class ModuleInfo:
    """A loaded module/shared library."""

    name: str
    path: str
    base: int
    size: int


@dataclass(frozen=True)
class ReadResult:
    """Outcome of a single memory read, with fault detail when available.

    Attributes:
        data: The bytes read, or ``None`` if the read failed.
        fault_addr: The first address the backend *proved* it could not read,
            when it could be determined. Lets the caller split a failed read at
            the real boundary instead of degrading to page-by-page reads. A
            guess is worse than ``None``: the caller skips a page for every
            fault it is told about, so a wrong address loses readable pages
            that the page-by-page fallback would have captured.
        error: Backend error text, empty on success.
    """

    data: bytes | None
    fault_addr: int | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        """Whether the read returned data."""
        return self.data is not None


# Backends phrase inaccessible-memory errors differently: Frida says "access
# violation accessing 0x..." or "unable to read memory at 0x...", GDB says
# "Cannot access memory at address 0x...".  The leading \b keeps the lead-in
# words whole, so text such as "bad format 0x1000" or "repeat 0x2000" is not
# mistaken for a fault.
#
# "for" is deliberately absent. Its only known producer is LLDB's "memory read
# failed for 0x...", which echoes the address it was asked about and is
# discarded by interior_fault anyway -- so recognising it buys nothing, while
# "waiting for 0x..." or "no data available for 0x..." in any backend's text
# would be read as a proven fault and cost that page.
_FAULT_ADDR_RE = re.compile(r"\b(?:accessing|at address|at)\s+(0x[0-9a-fA-F]+)")


def parse_fault_addr(message: str) -> int | None:
    """Extract a faulting address from a backend error message.

    This is a purely lexical read of the text. Whether the address it finds is
    trustworthy depends on the backend: some name the boundary they stopped at,
    others merely echo the address they were asked about. See
    :func:`interior_fault`.

    Args:
        message: Error text reported by the backend.

    Returns:
        The address named in the message, or ``None`` if it names none.
    """
    match = _FAULT_ADDR_RE.search(message or "")
    return int(match.group(1), 16) if match else None


def interior_fault(address: int, size: int, candidate: int | None) -> int | None:
    """Keep *candidate* only when it names a boundary strictly inside a request.

    A backend that echoes the address it was asked about reports no new
    information, and passing that on makes the caller mark every page of the
    span failed one page at a time instead of falling back to page-by-page
    reads that would have captured the readable ones.

    Use this for addresses scraped from error text. Addresses derived from
    structured evidence -- a returned block list, a region-info query -- are
    authoritative even at the start of the span and must not be filtered.

    Args:
        address: Start of the requested span.
        size: Length of the requested span in bytes.
        candidate: Address parsed from backend error text, if any.

    Returns:
        ``candidate`` when it lies strictly inside the span, else ``None``.
    """
    if candidate is None:
        return None
    return candidate if address < candidate < address + size else None


def fault_addr_from_text(address: int, size: int, message: str) -> int | None:
    """Fault address named by *message*, kept only if strictly inside the span.

    The last resort for backends whose error text is the only clue. Combines
    :func:`parse_fault_addr` with the :func:`interior_fault` trust filter,
    which is the only correct way to use a scraped address.

    Args:
        address: Start of the requested span.
        size: Length of the requested span in bytes.
        message: Backend error text.

    Returns:
        The address, or ``None`` when the message named none or merely echoed
        the address it was asked about.
    """
    return interior_fault(address, size, parse_fault_addr(message))


@runtime_checkable
class ReadMemoryExCapable(Protocol):
    """Optional bridge capability: reads that report *why* they failed.

    Bridges are not required to implement this. Callers should probe for the
    method and fall back to :meth:`DebuggerBridge.read_memory`.
    """

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        """Read *size* bytes from *address*, reporting the fault on failure.

        Implementations owe the caller two things:

        * All-or-nothing. ``data`` is exactly *size* bytes or ``None``; a
          partial span is never returned as data, so the caller can place what
          it receives without further checks.
        * An honest ``fault_addr``. It must be an address the backend *proved*
          it could not read, and must lie within ``[address, address + size)``.
          Report ``None`` rather than guess -- the caller skips a page for
          every fault it is told about, so a wrong address silently loses
          readable pages. Addresses scraped from error text usually just echo
          the argument; pass those through :func:`fault_addr_from_text`.

        Reads never raise: a failure is a ``ReadResult`` with no data.
        """
        ...


@runtime_checkable
class DebuggerBridge(Protocol):
    """Protocol for debugger backends.

    Each backend implements only these methods.
    Everything else (read strategy, MSL writing, progress,
    volatility sorting) lives in AcquisitionEngine.
    """

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        return False

    def connect(self) -> None:
        """Attach to the target process."""
        ...

    def get_platform_info(self) -> PlatformInfo:
        """Return arch, OS, PID, and page size."""
        ...

    def enumerate_ranges(self) -> list[MemoryRange]:
        """List all memory regions in the target process."""
        ...

    def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules/libraries."""
        ...

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read *size* bytes from *address*. Return ``None`` on failure.

        All-or-nothing: a returned buffer is exactly *size* bytes. A backend
        that can only read part of the span reports failure, because the caller
        places the bytes at *address* and has no way to learn that a shorter
        answer stopped early.

        Bridges may additionally implement the optional
        :class:`ReadMemoryExCapable` protocol to report fault addresses.
        """
        ...

    def disconnect(self) -> None:
        """Detach from the target process and clean up."""
        ...
