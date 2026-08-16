"""Exception taxonomy for memslicer.

Acquisition failures that are *predictable* — a blocked ``ptrace``, a
zombie target, an already-traced process — deserve one actionable line
instead of a raw backend string. This module holds the exception types
that carry that information from the bridges up to the CLI.

It deliberately contains **no** platform logic and imports nothing from
the acquirer package, so ``cli.py`` (and any other consumer) can import
it without pulling in the Linux-``/proc``-specific preflight module.

Exit codes
----------
``EXIT_PREFLIGHT_REFUSED`` (3) is reserved for "we refused to attach
before touching the target". It is distinct from the generic failure
exit code 1 so that scripted callers can tell "the environment forbids
this capture" from "the capture went wrong".
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only
    from memslicer.acquirer.attach_preflight import PreflightResult


EXIT_PREFLIGHT_REFUSED = 3
"""Process exit code used when an attach is refused by the preflight."""


class MemslicerError(Exception):
    """Base class for every memslicer-specific error."""


class AttachError(MemslicerError):
    """A debugger backend could not attach to the target.

    Attributes:
        summary: One-line, human-readable statement of what failed. This
            is what ``str(error)`` returns and what the CLI renders after
            ``Error:``.
        remediation: Concrete next steps, one per line. Always a list,
            even when constructed from a single string.
        probable_cause: Free-form contributing-cause text (for example an
            AppArmor profile name) shown below the remediation. Empty
            when nothing suspicious was observed.
        cause: The originating exception, if any. Also chained onto
            ``__cause__`` so tracebacks stay informative.
    """

    def __init__(
        self,
        summary: str,
        *,
        remediation: str | Sequence[str] | None = None,
        probable_cause: str = "",
        cause: BaseException | None = None,
    ) -> None:
        """Initialise the error.

        Args:
            summary: One-line statement of the failure.
            remediation: A single remediation line or a sequence of them.
            probable_cause: Optional contributing-cause description.
            cause: Optional originating exception to chain.
        """
        super().__init__(summary)
        self.summary = summary
        self.remediation: list[str] = _as_lines(remediation)
        self.probable_cause = probable_cause
        self.cause = cause
        if cause is not None:
            self.__cause__ = cause

    def __str__(self) -> str:
        """Return the summary only — never the remediation block."""
        return self.summary


class AttachPreflightError(AttachError):
    """Raised before any attach is attempted; carries the full result.

    The presence of this type (rather than its base class) is what tells
    the CLI that nothing was touched on the target and that exit code
    :data:`EXIT_PREFLIGHT_REFUSED` applies.

    Attributes:
        result: The ``PreflightResult`` that produced the refusal, or
            ``None`` when the error was synthesised without one.
    """

    def __init__(
        self,
        summary: str,
        *,
        result: PreflightResult | None = None,
        remediation: str | Sequence[str] | None = None,
        probable_cause: str = "",
        cause: BaseException | None = None,
    ) -> None:
        """Initialise the error.

        Args:
            summary: One-line statement of the refusal.
            result: The preflight result that justified the refusal.
            remediation: A single remediation line or a sequence of them.
            probable_cause: Optional contributing-cause description.
            cause: Optional originating exception to chain.
        """
        super().__init__(
            summary,
            remediation=remediation,
            probable_cause=probable_cause,
            cause=cause,
        )
        self.result = result


def _as_lines(value: Any) -> list[str]:
    """Normalise ``None`` / ``str`` / sequence-of-str into a list of lines."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in value if str(item)]
