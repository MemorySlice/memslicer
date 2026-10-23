"""Backend-agnostic protocol and data types for debugger bridges."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

from memslicer.msl.constants import (
    REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC, REG_ROLE_SP,
    REG_ROLE_TLS, ArchType, OSType, ThreadState,
)

if TYPE_CHECKING:
    import logging

    from memslicer.acquirer.investigation import InvestigationCollector


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


# Register roles (spec Table 19b) by lowercase canonical mnemonic, per
# architecture. The generic aliases ``pc``/``sp``/``fp``/``lr`` are listed for
# every architecture: a backend that only knows the generic name still gets
# the role, and on AArch64 they *are* the canonical names.
_GENERIC_ROLES: dict[str, int] = {
    "pc": REG_ROLE_PC, "sp": REG_ROLE_SP, "fp": REG_ROLE_FP, "lr": REG_ROLE_LR,
}
_X86_ROLES: dict[str, int] = {
    "eip": REG_ROLE_PC, "esp": REG_ROLE_SP, "ebp": REG_ROLE_FP,
    "eflags": REG_ROLE_FLAGS, "fs_base": REG_ROLE_TLS, "gs_base": REG_ROLE_TLS,
}
_X86_64_ROLES: dict[str, int] = {
    "rip": REG_ROLE_PC, "rsp": REG_ROLE_SP, "rbp": REG_ROLE_FP,
    # GDB prints the 64-bit flags register as ``eflags`` even on x86_64.
    "rflags": REG_ROLE_FLAGS, "eflags": REG_ROLE_FLAGS,
    "fs_base": REG_ROLE_TLS, "gs_base": REG_ROLE_TLS,
}
_ARM32_ROLES: dict[str, int] = {
    "r15": REG_ROLE_PC, "r13": REG_ROLE_SP, "r11": REG_ROLE_FP, "r14": REG_ROLE_LR,
    "cpsr": REG_ROLE_FLAGS, "tpidruro": REG_ROLE_TLS, "tpidrurw": REG_ROLE_TLS,
}
_ARM64_ROLES: dict[str, int] = {
    "x29": REG_ROLE_FP, "x30": REG_ROLE_LR,
    "pstate": REG_ROLE_FLAGS, "cpsr": REG_ROLE_FLAGS, "nzcv": REG_ROLE_FLAGS,
    "tpidr_el0": REG_ROLE_TLS, "tpidr": REG_ROLE_TLS,
}
_ROLES_BY_ARCH: dict[ArchType, dict[str, int]] = {
    ArchType.x86: _X86_ROLES,
    ArchType.x86_64: _X86_64_ROLES,
    ArchType.ARM32: _ARM32_ROLES,
    ArchType.ARM64: _ARM64_ROLES,
}
# For an unknown architecture any known mnemonic is accepted.
_ALL_ROLES: dict[str, int] = {
    **_X86_ROLES, **_X86_64_ROLES, **_ARM32_ROLES, **_ARM64_ROLES,
}


def register_role(name: str, arch: ArchType | None = None) -> int:
    """``REG_ROLE_*`` bits of register *name* on *arch*; 0 for a general register.

    *name* is matched case-insensitively against the lowercase canonical
    mnemonics of spec Section 5.7 (``rip``/``eip``/``pc``, ``rsp``/``esp``/
    ``sp``, ``rbp``/``ebp``/``fp``/``x29``, ``rflags``/``eflags``/``pstate``/
    ``cpsr``/``nzcv``, ``fs_base``/``gs_base``/``tpidr_el0``, ``lr``/``x30``).
    With *arch* ``None`` every known mnemonic is accepted.
    """
    key = name.lower()
    table = _ALL_ROLES if arch is None else _ROLES_BY_ARCH.get(arch, _ALL_ROLES)
    return table.get(key, _GENERIC_ROLES.get(key, 0))


# Integer register width in bytes per architecture (GPRs); 8 otherwise.
_REG_WIDTH: dict[ArchType, int] = {
    ArchType.x86: 4, ArchType.ARM32: 4, ArchType.MIPS32: 4,
    ArchType.RISC_V_RV32: 4, ArchType.PPC32: 4,
}


def register_width_bytes(arch: ArchType | None) -> int:
    """Integer register width in bytes for *arch* (8 when unknown)."""
    if arch is None:
        return 8
    return _REG_WIDTH.get(arch, 8)


@dataclass(frozen=True)
class RegisterValue:
    """One CPU register as a debugger bridge reports it (spec Table 19b).

    Attributes:
        name: Lowercase canonical mnemonic, e.g. ``"rip"`` or ``"x0"``.
        width: Value width in bytes.
        value: Exactly *width* bytes, little-endian.
        role: ``REG_ROLE_*`` bits; 0 for a general register.
    """

    name: str
    width: int
    value: bytes
    role: int = 0

    @classmethod
    def from_int(
        cls, name: str, value: int, width: int, arch: ArchType | None = None,
    ) -> RegisterValue:
        """Build an entry from an unsigned integer *value*.

        The name is lowercased, the value masked to *width* bytes and
        encoded little-endian, and the role looked up with
        :func:`register_role`.
        """
        masked = int(value) & ((1 << (width * 8)) - 1)
        return cls(
            name=name.lower(), width=width,
            value=masked.to_bytes(width, "little"),
            role=register_role(name, arch),
        )

    @property
    def as_int(self) -> int:
        """The value decoded as an unsigned little-endian integer."""
        return int.from_bytes(self.value, "little")


@dataclass
class ThreadInfo:
    """Execution state of one thread as a debugger bridge reports it.

    Attributes:
        tid: OS thread identifier; 0 when unknown.
        name: Thread name; empty when the target reports none.
        state: Scheduler state (spec Table 19a).
        registers: The register file read from the thread.
        suspended: ``True`` only when the thread was stopped while its
            registers were read (ptrace-stopped, debugger-halted), so the
            values form a consistent snapshot. A bridge that samples a
            running thread leaves this ``False``.
        partial: ``True`` when the bridge could not read every register it
            would normally record.
    """

    tid: int
    name: str = ""
    state: ThreadState = ThreadState.UNKNOWN
    registers: list[RegisterValue] = field(default_factory=list)
    suspended: bool = False
    partial: bool = False

    def _with_role(self, role: int) -> RegisterValue | None:
        return next((r for r in self.registers if r.role & role), None)

    @property
    def has_pc_and_sp(self) -> bool:
        """Whether the register file carries both a program counter and a
        stack pointer -- the minimum spec Section 5.7 lets a producer emit."""
        return (
            self._with_role(REG_ROLE_PC) is not None
            and self._with_role(REG_ROLE_SP) is not None
        )

    @property
    def stack_pointer(self) -> int | None:
        """The stack pointer value, ``None`` when no SP register was read."""
        sp = self._with_role(REG_ROLE_SP)
        return sp.as_int if sp is not None else None


def stack_pointers_of(threads: Iterable[ThreadInfo]) -> tuple[int, ...]:
    """Distinct non-zero stack pointers of *threads*, in thread order.

    Lets the engine feed the SP-based stack classifier from the thread
    enumeration it already performed for the Thread Context blocks, instead
    of asking the bridge a second time.
    """
    pointers = (t.stack_pointer for t in threads)
    return tuple(dict.fromkeys(sp for sp in pointers if sp))


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
class RemoteCollectorCapable(Protocol):
    """Optional bridge capability: bridges that can run investigation
    collection on the target itself.

    Bridges are not required to implement this. Callers should probe for the
    method with ``getattr`` and fall back to
    :class:`~memslicer.acquirer.collectors.fallback.NullCollector`.
    """

    def create_remote_collector(
        self, logger: logging.Logger | None = None,
    ) -> InvestigationCollector | None:
        """Return a collector that gathers investigation data on the target.

        Returns ``None`` when the bridge is not attached to a remote target,
        is not connected yet, or the on-target agent could not be loaded.
        Implementations log the reason and never raise for those cases.
        """
        ...


@runtime_checkable
class ResidencyCapable(Protocol):
    """Optional bridge capability: which pages of a span the target has touched.

    Bridges are not required to implement this. Callers should probe for the
    methods with ``isinstance`` and treat an absent capability exactly like
    :meth:`residency_method` answering ``"none"``: read everything.
    """

    def query_residency(self, address: int, size: int) -> bytes | None:
        """Residency mask for ``[address, address + size)``.

        Returns:
            One byte per target page covering the span: ``1`` when the page is
            present in RAM or swapped out (either way it holds data that must
            be read), ``0`` when the page was never touched and reading it
            would only produce zeros. ``None`` when the answer is unknown or
            the method is unsupported, in which case the caller must read the
            whole span. Implementations never raise.
        """
        ...

    def residency_method(self) -> str:
        """How residency is determined: ``"pagemap"``, ``"mincore"`` or ``"none"``.

        ``"mincore"`` cannot see swapped pages, so bridges only report it when
        the target has nothing in swap; ``"none"`` means
        :meth:`query_residency` always answers ``None``.
        """
        ...


@runtime_checkable
class ThreadStackCapable(Protocol):
    """Optional bridge capability: the current stack pointer of every thread.

    Lets the caller rank the live part of each stack above the rest. Bridges
    are not required to implement this.
    """

    def enumerate_stack_pointers(self) -> list[int]:
        """Current SP of every thread in the target, ``[]`` when unavailable.

        Implementations never raise; a thread whose SP cannot be read is left
        out rather than reported as zero.
        """
        ...


@runtime_checkable
class ThreadRegistersCapable(Protocol):
    """Optional bridge capability: every thread with its register file.

    Feeds the Thread Context blocks (spec Section 5.7). Bridges are not
    required to implement this; the engine probes for the method and emits
    no Thread Context block when it is absent.
    """

    def enumerate_threads(self) -> list[ThreadInfo]:
        """Every thread the backend can see, with its registers.

        Implementations never raise. A thread whose program counter or
        stack pointer could not be read is left out (the spec requires both
        in every block); one whose other registers were only partly read is
        reported with ``partial`` set. ``[]`` when the backend cannot
        enumerate threads at all -- the engine then logs that no thread
        contexts are available and writes none.
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
