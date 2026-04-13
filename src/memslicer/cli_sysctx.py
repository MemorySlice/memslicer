"""``memslicer-sysctx`` — read-only inspector for MSL Section 6 data.

Standalone click command: runs the same per-platform collectors and
the same ``system_info_to_fields`` → ``pack_os_detail`` pipeline the
acquire command uses, but writes **no MSL file**. Output is a rich /
plain table (or JSON) on stdout.

Exit codes: ``0`` on complete collection, ``2`` on partial, ``1`` on
hard failure. ``--strict`` upgrades ``2`` → ``1``.
"""
from __future__ import annotations

import json
import logging
import signal
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

import click

from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, PROTO_TCP, PROTO_UDP,
)
from memslicer.acquirer.identity import (
    AttributionConfig,
    ForensicStringError,
    attribution_options,
    infer_os_type,
    resolve_target_identity,
    validate_attribution,
)
from memslicer.acquirer.investigation import (
    InvestigationCollector,
    TargetProcessInfo,
    TargetSystemInfo,
)
from memslicer.acquirer.os_detail import (
    pack_os_detail,
    parse_os_detail,
    system_info_to_fields,
)
from memslicer.msl.constants import OSType
from memslicer.msl.types import (
    ConnectionEntry,
    HandleEntry,
    ProcessEntry,
)


# JSON schema tag — bump on breaking schema changes so downstream
# pipelines can detect + route.
JSON_SCHEMA = "memslicer.system-context/v1"

# Minimum set of fields that must be non-empty for the command to
# consider its output "complete." Partial collection → exit 2.
_MINIMUM_SET = ("hostname", "os_detail")

# Exit codes (reexported as module constants so the test suite can
# assert against symbolic names rather than magic numbers).
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_PARTIAL = 2


# ---------------------------------------------------------------------------
# Platform / collector selection
# ---------------------------------------------------------------------------

def _make_collector(
    os_override: str | None,
    is_remote: bool,
    logger: logging.Logger,
) -> InvestigationCollector:
    """Build the right collector for the target platform.

    Isolated in a helper so tests can monkeypatch it.
    """
    from memslicer.acquirer.collectors import create_collector

    return create_collector(
        infer_os_type(os_override),
        is_remote=is_remote,
        logger=logger,
    )


# ---------------------------------------------------------------------------
# Collection orchestration
# ---------------------------------------------------------------------------

def _collect_all(
    collector: InvestigationCollector,
    *,
    target_pid: int | None,
    want_process_table: bool,
    want_connection_table: bool,
    want_handle_table: bool,
    attribution: AttributionConfig,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Run ``collector`` for every requested section and return a plain dict.

    Keeps the collection fail-soft: any section that raises is logged
    and replaced with an empty structure. The return dict mirrors the
    JSON output schema 1:1 so formatting is pure transformation.
    """
    # ----- System info -----
    try:
        sys_info = collector.collect_system_info()
    except Exception as exc:  # noqa: BLE001
        logger.warning("collect_system_info raised: %s", exc)
        sys_info = TargetSystemInfo()

    identity = resolve_target_identity(
        collector_hostname=sys_info.hostname,
        collector_domain=sys_info.domain,
        is_remote=attribution.is_remote,
        hostname_override=attribution.hostname_override,
        domain_override=attribution.domain_override,
        logger=logger,
    )

    fields = system_info_to_fields(
        sys_info,
        include_serials=attribution.include_serials,
        include_network_identity=attribution.include_network_identity,
    )
    collector_warnings = list(sys_info.collector_warnings)
    collector_warnings.extend(identity.warnings)
    if collector_warnings:
        fields["collector_warning"] = ",".join(collector_warnings)

    os_detail_packed = pack_os_detail(fields)

    import getpass
    acq_user = attribution.examiner or getpass.getuser()

    system_context = {
        "boot_time_ns": sys_info.boot_time,
        "boot_time_iso": (
            datetime.fromtimestamp(sys_info.boot_time / 1e9, tz=timezone.utc).isoformat()
            if sys_info.boot_time else ""
        ),
        "acq_user": acq_user,
        "hostname": identity.hostname,
        "domain": identity.domain,
        "case_ref": attribution.case_ref,
        "os_detail": os_detail_packed,
        "os_detail_parsed": parse_os_detail(os_detail_packed),
        "collector_warnings": collector_warnings,
    }

    # ----- Per-target process identity & handle table -----
    process_identity: dict[str, Any] | None = None
    handle_table: list[dict[str, Any]] = []
    if target_pid is not None:
        try:
            pi = collector.collect_process_identity(target_pid)
            process_identity = asdict(pi) if is_dataclass(pi) else dict(pi)
        except Exception as exc:  # noqa: BLE001
            logger.warning("collect_process_identity raised: %s", exc)
            process_identity = asdict(TargetProcessInfo())

        if want_handle_table:
            try:
                raw_handles = collector.collect_handle_table(target_pid)
            except Exception as exc:  # noqa: BLE001
                logger.warning("collect_handle_table raised: %s", exc)
                raw_handles = []
            handle_table = [asdict(h) for h in raw_handles]

    # ----- System-wide tables (not target-scoped) -----
    process_table: list[dict[str, Any]] = []
    if want_process_table:
        try:
            raw_procs = collector.collect_process_table(target_pid or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("collect_process_table raised: %s", exc)
            raw_procs = []
        process_table = [asdict(p) for p in raw_procs]

    connection_table: list[dict[str, Any]] = []
    if want_connection_table:
        try:
            raw_conns = collector.collect_connection_table()
        except Exception as exc:  # noqa: BLE001
            logger.warning("collect_connection_table raised: %s", exc)
            raw_conns = []
        connection_table = [_connection_to_dict(c) for c in raw_conns]

    return {
        "schema": JSON_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system_context": system_context,
        "process_identity": process_identity,
        "process_table": process_table,
        "connection_table": connection_table,
        "handle_table": handle_table,
    }


_PROTO_NAMES = {PROTO_TCP: "TCP", PROTO_UDP: "UDP"}
_FAMILY_NAMES = {AF_INET: "IPv4", AF_INET6: "IPv6"}


def _connection_to_dict(c: ConnectionEntry) -> dict[str, Any]:
    """Render a :class:`ConnectionEntry` with printable address strings."""
    import ipaddress

    def _addr_str(raw: bytes, family: int) -> str:
        try:
            if family == AF_INET:
                return str(ipaddress.IPv4Address(raw[:4]))
            if family == AF_INET6:
                return str(ipaddress.IPv6Address(raw[:16]))
        except Exception:  # noqa: BLE001
            return raw.hex()
        return raw.hex()

    return {
        "pid": c.pid,
        "family": _FAMILY_NAMES.get(c.family, str(c.family)),
        "protocol": _PROTO_NAMES.get(c.protocol, str(c.protocol)),
        "state": c.state,
        "local_addr": _addr_str(c.local_addr, c.family),
        "local_port": c.local_port,
        "remote_addr": _addr_str(c.remote_addr, c.family),
        "remote_port": c.remote_port,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _format_plain(data: dict[str, Any]) -> str:
    """Zero-dependency aligned-column output.

    Intentionally simple (~30 LOC). Rich styling via the ``rich`` extra
    is opt-in; the default path must work on any Python install with no
    transitive dependencies on a possibly-compromised acquisition host.
    """
    out: list[str] = []
    sc = data["system_context"]

    out.append("=" * 72)
    out.append("System Context (MSL Section 6)")
    out.append("=" * 72)

    def _row(label: str, value: Any) -> None:
        out.append(f"  {label:<22} {value}")

    _row("acq_user", sc["acq_user"])
    _row("hostname", sc["hostname"] or "(empty)")
    _row("domain", sc["domain"] or "(empty)")
    _row("case_ref", sc["case_ref"] or "(empty)")
    _row("boot_time", sc["boot_time_iso"] or "(unknown)")

    if sc["collector_warnings"]:
        out.append("")
        out.append("  WARNINGS:")
        for w in sc["collector_warnings"]:
            out.append(f"    - {w}")

    out.append("")
    out.append("-" * 72)
    out.append("Enriched os_detail")
    out.append("-" * 72)
    parsed = sc["os_detail_parsed"]
    if parsed:
        for key in sorted(parsed.keys()):
            _row(key, parsed[key])
    else:
        out.append("  (no structured fields)")

    out.append("")
    out.append(f"Raw os_detail: {sc['os_detail']}")

    pi = data.get("process_identity")
    if pi:
        out.append("")
        out.append("-" * 72)
        out.append("Target process identity")
        out.append("-" * 72)
        for key, value in pi.items():
            _row(key, value)

    if data["process_table"]:
        out.append("")
        out.append("-" * 72)
        out.append(f"Process table ({len(data['process_table'])} entries)")
        out.append("-" * 72)
        out.append(f"  {'PID':<8}{'PPID':<8}{'UID':<8}{'RSS':<14}{'EXE':<40}")
        for p in data["process_table"][:50]:
            out.append(
                f"  {p['pid']:<8}{p['ppid']:<8}{p['uid']:<8}"
                f"{p['rss']:<14}{(p.get('exe_name') or '')[:40]:<40}"
            )
        if len(data["process_table"]) > 50:
            out.append(f"  ... ({len(data['process_table']) - 50} more)")

    if data["connection_table"]:
        out.append("")
        out.append("-" * 72)
        out.append(f"Connection table ({len(data['connection_table'])} entries)")
        out.append("-" * 72)
        out.append(
            f"  {'PID':<8}{'PROTO':<6}{'LOCAL':<24}{'REMOTE':<24}"
        )
        for c in data["connection_table"][:50]:
            local = f"{c['local_addr']}:{c['local_port']}"
            remote = f"{c['remote_addr']}:{c['remote_port']}"
            out.append(f"  {c['pid']:<8}{c['protocol']:<6}{local[:23]:<24}{remote[:23]:<24}")
        if len(data["connection_table"]) > 50:
            out.append(f"  ... ({len(data['connection_table']) - 50} more)")

    if data["handle_table"]:
        out.append("")
        out.append("-" * 72)
        out.append(f"Handle table ({len(data['handle_table'])} entries)")
        out.append("-" * 72)
        for h in data["handle_table"][:50]:
            out.append(f"  fd={h['fd']:<6}type={h['handle_type']:<4}{(h.get('path') or '')[:50]}")
        if len(data["handle_table"]) > 50:
            out.append(f"  ... ({len(data['handle_table']) - 50} more)")

    return "\n".join(out)


def _format_rich(data: dict[str, Any]) -> str:
    """Rich output — opt-in via ``memslicer[pretty]``.

    Degrades silently to plain output when ``rich`` is not installed.
    Returns a string rather than printing directly so tests can assert
    against its content; rich's own ``Console.render`` API handles the
    terminal escape sequences when it is available.
    """
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _format_plain(data)

    console = Console(record=True, width=100)
    sc = data["system_context"]

    tbl = Table(title="System Context (MSL Section 6)", show_lines=False)
    tbl.add_column("Field", style="bold")
    tbl.add_column("Value")

    tbl.add_row("acq_user", sc["acq_user"])
    tbl.add_row("hostname", sc["hostname"] or "[dim](empty)[/dim]")
    tbl.add_row("domain", sc["domain"] or "[dim](empty)[/dim]")
    tbl.add_row("case_ref", sc["case_ref"] or "[dim](empty)[/dim]")
    tbl.add_row("boot_time", sc["boot_time_iso"] or "[dim](unknown)[/dim]")

    for key, value in sorted(sc["os_detail_parsed"].items()):
        tbl.add_row(f"os_detail.{key}", str(value))

    console.print(tbl)

    if sc["collector_warnings"]:
        console.print("[yellow]Warnings:[/yellow]")
        for w in sc["collector_warnings"]:
            console.print(f"  • {w}")

    return console.export_text()


def _format_json(data: dict[str, Any]) -> str:
    """Stable, schema-versioned JSON for downstream pipelines.

    We strip the nested ``os_detail_parsed`` under system_context before
    emitting because it's redundant with the packed string — callers
    who want structured values can call ``parse_os_detail`` themselves.
    (The plain formatter keeps it for human convenience.)
    """
    out = dict(data)
    out["system_context"] = dict(out["system_context"])
    out["system_context"].pop("os_detail_parsed", None)
    return json.dumps(out, indent=2, default=str)


# ---------------------------------------------------------------------------
# Completeness check / exit code
# ---------------------------------------------------------------------------

def _minimum_set_complete(data: dict[str, Any]) -> bool:
    """Return True when the minimum-set fields are populated enough to
    claim "complete collection."

    The hostname check rejects the synthetic ``socket.gethostname()``
    fallback when it produced the only signal — we want an empty hostname
    AND empty enrichment to register as a partial collection. The
    os_detail check rejects a parsed dict that contains only the synthetic
    ``_human`` prefix key, since that's derived from the raw collector
    string and does not prove anything was enriched.
    """
    sc = data["system_context"]
    if not sc.get("hostname"):
        return False
    parsed = sc.get("os_detail_parsed") or {}
    enriched_keys = set(parsed.keys()) - {"_human"}
    if not enriched_keys:
        return False
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command(name="memslicer-sysctx")
@click.argument("target", required=False)
@click.option(
    "--os", "os_override",
    type=click.Choice(["windows", "linux", "macos", "android", "ios"]),
    default=None,
    help="Force target OS type (auto-detected from sys.platform otherwise)",
)
@click.option("-U", "--usb", is_flag=True, help="Connect to USB device (Frida)")
@click.option(
    "-R", "--remote", "remote_addr", default=None,
    help="Remote server host:port (not implemented for sysctx yet)",
)
@click.option(
    "--tables", "tables_opt", default="process,connection,handle",
    help="Comma-separated: which tables to collect (default: all)",
)
@click.option(
    "--skip-tables", "skip_tables_opt", default="",
    help="Comma-separated table names to skip (overrides --tables)",
)
@attribution_options
@click.option(
    "--format", "output_format",
    type=click.Choice(["plain", "rich", "json"]),
    default=None,
    help="Output format (default: plain on non-TTY, rich on TTY if installed)",
)
@click.option("--mode", type=click.Choice(["safe", "deep"]), default="safe")
@click.option(
    "--strict", is_flag=True,
    help="Upgrade partial collection (exit 2) to hard failure (exit 1)",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging to stderr")
def main(
    target: str | None,
    os_override: str | None,
    usb: bool,
    remote_addr: str | None,
    tables_opt: str,
    skip_tables_opt: str,
    examiner: str,
    case_ref: str,
    hostname_override: str,
    domain_override: str,
    include_serials: bool,
    include_network_identity: bool,
    output_format: str | None,
    mode: str,
    strict: bool,
    verbose: bool,
) -> None:
    """Inspect MSL Section 6 (SystemContext) data for the live system.

    Runs the same per-platform investigation collectors as ``memslicer
    <pid> -I`` but writes no MSL file — instead prints the resulting
    SystemContext block plus the ProcessTable / ConnectionTable /
    HandleTable as a table or JSON document.

    TARGET (optional) is a PID or process name. When omitted, only the
    system-wide data is collected (Process Table + Connection Table);
    per-target Process Identity and Handle Table are skipped.

    Exit codes:
      0 - all minimum-set fields populated
      2 - partial collection (one or more minimum fields empty)
      1 - hard failure
    """
    # ----- Logging to stderr so --format json is clean on stdout -----
    logger = logging.getLogger("memslicer.sysctx")
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)

    is_remote = bool(usb or remote_addr)

    try:
        attribution = validate_attribution(
            examiner=examiner,
            case_ref=case_ref,
            hostname_override=hostname_override,
            domain_override=domain_override,
            is_remote=is_remote,
            include_serials=include_serials,
            include_network_identity=include_network_identity,
        )
    except ForensicStringError as exc:
        raise click.BadParameter(str(exc))

    # ----- Parse --tables / --skip-tables -----
    wanted = {s.strip() for s in tables_opt.split(",") if s.strip()}
    skipped = {s.strip() for s in skip_tables_opt.split(",") if s.strip()}
    wanted -= skipped
    valid = {"process", "connection", "handle"}
    unknown = (wanted - valid) | (skipped - valid)
    if unknown:
        raise click.BadParameter(
            f"unknown table name(s): {', '.join(sorted(unknown))}; "
            f"valid: {', '.join(sorted(valid))}"
        )
    want_process_table = "process" in wanted
    want_connection_table = "connection" in wanted
    want_handle_table = "handle" in wanted

    # ----- Parse TARGET -----
    target_pid: int | None = None
    if target is not None:
        try:
            target_pid = int(target)
        except ValueError:
            # Name → resolve via psutil if available; else warn and continue
            # without a target pid so system-wide tables still flow.
            try:
                import psutil  # type: ignore
                for proc in psutil.process_iter(["pid", "name"]):
                    if proc.info["name"] == target:
                        target_pid = proc.info["pid"]
                        break
            except ImportError:
                pass
            if target_pid is None:
                logger.warning(
                    "could not resolve target %r to a PID; collecting "
                    "system-wide data only", target,
                )

    # ----- Graceful abort on Ctrl+C (slow remote Frida paths) -----
    signal.signal(signal.SIGINT, lambda *_: sys.exit(EXIT_FAILURE))

    # ----- Build collector and run -----
    try:
        collector = _make_collector(os_override, is_remote=is_remote, logger=logger)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: could not create collector: {exc}", err=True)
        sys.exit(EXIT_FAILURE)

    try:
        data = _collect_all(
            collector,
            target_pid=target_pid,
            want_process_table=want_process_table,
            want_connection_table=want_connection_table,
            want_handle_table=want_handle_table,
            attribution=attribution,
            logger=logger,
        )
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error during collection: {exc}", err=True)
        sys.exit(EXIT_FAILURE)

    # Stash mode in the system context for provenance; the plan's P0.8
    # requires this for safe/deep bookkeeping.
    data["system_context"]["mode"] = mode

    # ----- Choose format -----
    if output_format is None:
        output_format = "rich" if sys.stdout.isatty() else "plain"

    if output_format == "json":
        click.echo(_format_json(data))
    elif output_format == "rich":
        click.echo(_format_rich(data))
    else:
        click.echo(_format_plain(data))

    # ----- Exit code -----
    if not _minimum_set_complete(data):
        sys.exit(EXIT_FAILURE if strict else EXIT_PARTIAL)
    sys.exit(EXIT_OK)


if __name__ == "__main__":  # pragma: no cover
    main()
