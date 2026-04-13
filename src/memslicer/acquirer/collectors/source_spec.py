"""Declarative data-source specification for per-platform enrichment.

Background: each investigation collector needs to read ~20 platform-specific
fields (distro, machine_id, hw_vendor, bios, cpu, ram, timezone, etc.).
Writing 20 try/except methods per platform across five platforms produces
~100 nearly-identical error-handling blocks. This module replaces the
pattern with a **declarative list of** :class:`SourceSpec` **objects and a
single runner** that applies timeout, privacy gating, and exception
containment uniformly.

Usage pattern (per-collector):

    SPECS = [
        SourceSpec("distro", lambda: read_proc_file("/etc/os-release")),
        SourceSpec("machine_id", _read_machine_id, privacy="serial"),
        SourceSpec("hw_serial", _read_dmi_serial, privacy="serial"),
        SourceSpec("nic_macs", _read_nic_macs, privacy="netid"),
    ]

    values, warnings = run_specs(
        SPECS,
        include_serials=cli_flags.include_serials,
        include_network_identity=cli_flags.include_network_identity,
    )
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Literal, Union

FieldValue = Union[str, int]
Privacy = Literal["public", "serial", "netid"]


@dataclass
class SourceSpec:
    """One declarative source for one field.

    Attributes:
        field: Output key (e.g. ``"distro"``, ``"hw_serial"``). The runner
            returns a mapping keyed by this name.
        fn: Zero-argument callable returning the value. Should return an
            empty string / ``0`` on "not available" and raise on "broken";
            the runner converts raised exceptions to debug-logged empty
            values so the collection stays fail-soft.
        privacy: Gating class. ``"public"`` fields run unconditionally.
            ``"serial"`` fields run only when ``include_serials=True``.
            ``"netid"`` fields run only when ``include_network_identity=True``.
        timeout_ms: Per-spec deadline. Sources that block longer than this
            are aborted and their value is dropped. Applied via wall-clock
            checking after the fn returns (not preemptive signal-based,
            which would break on non-main threads).
        optional: If ``False``, an empty/missing value emits a
            ``collector_warning_<field>_unreadable`` entry in the warnings
            list. Defaults to ``True`` (most fields are best-effort).
    """

    field: str
    fn: Callable[[], FieldValue]
    privacy: Privacy = "public"
    timeout_ms: int = 1500
    optional: bool = True


@dataclass
class RunResult:
    """Structured output of :func:`run_specs`.

    Kept as a dataclass (rather than a bare tuple) so callers can add
    future provenance fields — e.g. per-field ``source=`` labels or a
    ``mode`` stamp — without breaking callers.
    """

    values: dict[str, FieldValue] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def run_specs(
    specs: list[SourceSpec],
    *,
    include_serials: bool = False,
    include_network_identity: bool = False,
    global_budget_ms: int = 2000,
    logger: logging.Logger | None = None,
) -> RunResult:
    """Execute ``specs`` under a global wall-clock budget.

    Behavior:

    - Specs whose ``privacy`` gate is closed are **skipped** (not run, not
      warned, not in the output). The analyst opts in explicitly via CLI
      flags; a closed gate is not a failure.

    - Specs that **raise** are caught, debug-logged, and omitted. A
      non-optional spec that raises or produces an empty value emits a
      ``<field>_unreadable`` entry in :attr:`RunResult.warnings` so the
      analyst can distinguish "not collected by policy" from "collection
      failed".

    - Specs that produce an **empty string / ``0``** are omitted from
      ``values`` so the packer never emits keyless ``key=`` entries. An
      empty value from a non-optional spec emits a warning, same as a raise.

    - The **global budget** bounds total wall-clock time across all specs.
      Once exceeded, subsequent specs are skipped with a
      ``global_budget_exceeded`` warning. This defends against one slow
      subprocess blocking the whole collection — critical on remote Frida
      targets where observer effect matters.

    - **Per-spec timeout** is advisory: we measure after each call and
      drop values whose call exceeded ``timeout_ms``, charging the spent
      time to the global budget. We do not preempt — Python signal-based
      alarms are main-thread-only and would break CLI usage.
    """
    log = logger or logging.getLogger("memslicer")
    result = RunResult()

    budget_ns = global_budget_ms * 1_000_000
    deadline = time.monotonic_ns() + budget_ns

    for spec in specs:
        # Privacy gating.
        if spec.privacy == "serial" and not include_serials:
            result.skipped.append(spec.field)
            continue
        if spec.privacy == "netid" and not include_network_identity:
            result.skipped.append(spec.field)
            continue

        # Global budget exhaustion.
        if time.monotonic_ns() >= deadline:
            result.warnings.append("global_budget_exceeded")
            result.skipped.append(spec.field)
            continue

        # Run the source.
        call_start = time.monotonic_ns()
        try:
            value: FieldValue = spec.fn()
        except Exception as exc:  # noqa: BLE001 — runner is fail-soft on purpose
            log.debug("SourceSpec %s raised: %s", spec.field, exc)
            if not spec.optional:
                result.warnings.append(f"{spec.field}_unreadable")
            continue
        call_elapsed_ms = (time.monotonic_ns() - call_start) // 1_000_000

        # Per-spec timeout: drop late values; charge time to budget.
        if call_elapsed_ms > spec.timeout_ms:
            log.debug(
                "SourceSpec %s exceeded %d ms (took %d ms), dropping",
                spec.field, spec.timeout_ms, call_elapsed_ms,
            )
            if not spec.optional:
                result.warnings.append(f"{spec.field}_timeout")
            continue

        # Empty value handling: omit key entirely; warn if non-optional.
        if value == "" or value == 0:
            if not spec.optional:
                result.warnings.append(f"{spec.field}_unreadable")
            continue

        result.values[spec.field] = value

    return result


__all__ = (
    "FieldValue",
    "Privacy",
    "RunResult",
    "SourceSpec",
    "run_specs",
)
