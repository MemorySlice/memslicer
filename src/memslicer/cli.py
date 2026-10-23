"""MemSlicer CLI - MSL memory dump tool with pluggable debugger backends."""
from __future__ import annotations
import logging
import signal
import sys
import time
from collections import deque
from pathlib import Path

import click

from memslicer.acquirer.base import AcquireResult
from memslicer.acquirer.errors import (
    EXIT_PREFLIGHT_REFUSED,
    AttachError,
    AttachPreflightError,
)
from memslicer.acquirer.identity import (
    ForensicStringError,
    attribution_options,
    validate_attribution,
)
from memslicer.acquirer.region_classify import RegionCategory
from memslicer.acquirer.region_filter import (
    SKIP_REASON_LABELS,  # noqa: F401  (kept for importers; skip_label wraps it)
    RegionFilter,
    parse_scope,
    scope_label,
    skip_label,
)
from memslicer.cli_verify import verify
from memslicer.msl.constants import CompAlgo, HashAlgo, OSType
from memslicer.utils.protection import parse_protection

# How many unreadable ranges to name on the console before deferring to the log.
_MAX_SHOWN_UNREADABLE = 5


def _render_attach_error(error: AttachError, log_file_path: str | None = None) -> None:
    """Print an attach failure as one actionable block.

    Args:
        error: The attach error to render.
        log_file_path: Path of the ``.msl.log`` holding the full record, or
            ``None`` when no log was written (a ``--dry-run``).
    """
    click.echo(f"\nError: {error}", err=True)
    for line in error.remediation:
        click.echo(f"  → {line}", err=True)
    if error.probable_cause:
        click.echo(f"  Probable cause: {error.probable_cause}", err=True)
    if log_file_path is not None:
        click.echo(f"  Full environment record: {log_file_path}", err=True)


def _fmt_size(n: int) -> str:
    """Format a byte count as B/KiB/MiB/GiB with one decimal."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{n} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _parse_scope_option(text: str) -> frozenset[str]:
    """Parse ``--scope``, turning a bad value into a click usage error."""
    try:
        return parse_scope(text)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--scope")


def _device_label(remote_addr: str | None, device_id: str | None, usb: bool) -> str:
    """Describe where the target lives, for the console banner."""
    if remote_addr:
        return remote_addr
    if device_id:
        return f"{device_id} (USB)"
    if usb:
        return "USB"
    return "local"


def _category_label(category: RegionCategory) -> str:
    """Render a RegionCategory as a lower-case, hyphenated word."""
    return category.name.lower().replace("_", "-")


def _echo_scope_summary(result: AcquireResult, region_filter: RegionFilter,
                        resident_only: bool) -> None:
    """Report scope, exclusions, omissions and residency pruning.

    Only lines that carry information are printed, so a plain full capture
    reads exactly as before.

    Args:
        result: The acquisition result to report on.
        region_filter: The filter the capture ran with.
        resident_only: Whether ``--resident-only`` was requested.
    """
    if result.scope != "full" or region_filter.exclude_modules:
        click.echo(f"  Scope   : {result.scope}")
        click.echo(f"  Exclude : {', '.join(region_filter.exclude_modules) or 'none'}")
    if result.regions_omitted:
        click.echo(f"  Omitted : {result.regions_omitted} regions recorded in"
                   f" RegionOmissionManifest (0x005B)")
    if result.pages_nonresident:
        click.echo(f"  Resident: {result.pages_nonresident:,} pages"
                   f" ({_fmt_size(result.bytes_nonresident)}) skipped as"
                   f" never-touched (method: {result.residency_method})")
    if resident_only and result.residency_method == "none":
        click.echo("  Note    : --resident-only was requested but residency"
                   " information was unavailable; every page was read")


# Skip reasons whose regions could not have been read anyway, so a dry run
# does not count them as readable bytes the operator chose to leave out.
_UNREADABLE_SKIP_REASONS = frozenset({"no-read", "kernel-pseudo"})


def _render_category_table(survey) -> None:
    """Print one row per RegionCategory, largest total first."""
    rows = sorted(survey.bytes_by_category().items(),
                  key=lambda item: -(item[1][1] + item[1][3]))
    click.echo(f"  {'category':<14} {'regions kept':>12} {'bytes kept':>12}"
               f" {'regions skipped':>15} {'bytes skipped':>13}")
    for category, (kept_n, kept_b, skipped_n, skipped_b) in rows:
        click.echo(f"  {_category_label(category):<14} {kept_n:>12,}"
                   f" {_fmt_size(kept_b):>12} {skipped_n:>15,}"
                   f" {_fmt_size(skipped_b):>13}")


def _render_owner_table(survey, limit: int = 15) -> None:
    """Print the largest owners (modules or region labels)."""
    rows = survey.bytes_by_owner(limit)
    if not rows:
        return
    width = max(len("owner"), *(len(label) for label, _, _ in rows))
    click.echo("  Top owners:")
    click.echo(f"  {'owner':<{width}} {'bytes kept':>12} {'bytes skipped':>13}")
    for label, kept_b, skipped_b in rows:
        click.echo(f"  {label:<{width}} {_fmt_size(kept_b):>12}"
                   f" {_fmt_size(skipped_b):>13}")


def _render_survey_totals(survey) -> None:
    """Print the one-line verdict: what would be captured out of what."""
    kept = survey.kept()
    kept_bytes = sum(d.range.size for d in kept)
    readable = kept_bytes + sum(
        d.range.size for d in survey.skipped()
        if d.skip_reason not in _UNREADABLE_SKIP_REASONS
    )
    click.echo(f"  Would capture {_fmt_size(kept_bytes)} of {_fmt_size(readable)}"
               f" readable bytes across {len(kept)} of"
               f" {len(survey.decisions)} regions")


def _render_survey_skip_reasons(survey, scope: frozenset[str]) -> None:
    """Print why regions would be skipped, most frequent first."""
    counts = survey.skip_reason_counts()
    if not counts:
        return
    click.echo("  Skipped :")
    for reason, count in sorted(counts.items(), key=lambda x: -x[1]):
        click.echo(f"            {count} {skip_label(reason, scope)}")


def _render_survey(survey, region_filter: RegionFilter, *, target: str,
                   backend: str, device_str: str) -> None:
    """Print a dry-run report of what an acquisition would capture.

    Args:
        survey: The :class:`RegionSurvey` the engine produced.
        region_filter: The filter the survey was planned with.
        target: The target as the operator typed it.
        backend: Debugger backend name.
        device_str: Device description from :func:`_device_label`.
    """
    exclude = ", ".join(region_filter.exclude_modules) or "none"
    click.echo(f"MemSlicer - Dry run for {target} (nothing is written)")
    click.echo(f"Backend: {backend} | Device: {device_str} | OS: {survey.os_type.name}"
               f" | Scope: {scope_label(region_filter.scope)} | Exclude: {exclude}")
    click.echo(f"  Regions : {len(survey.decisions)} enumerated,"
               f" page size {survey.page_size:,}")
    _render_category_table(survey)
    _render_owner_table(survey)
    _render_survey_totals(survey)
    _render_survey_skip_reasons(survey, region_filter.scope)


def _run_dry_run(acquirer_kwargs: dict, region_filter: RegionFilter, *,
                 target: str, backend: str, device_str: str,
                 logger: logging.Logger) -> None:
    """Survey the target and print the report; never writes a file.

    Attach failures use the same rendering as a real capture, minus the
    log-file pointer, since no ``.msl.log`` exists for a dry run.
    """
    acquirer = _create_acquirer(**acquirer_kwargs)
    try:
        survey = acquirer.survey_regions()
    except KeyboardInterrupt:
        click.echo("\nForce quit.")
        raise SystemExit(1)
    except AttachPreflightError as e:
        _render_attach_error(e)
        raise SystemExit(EXIT_PREFLIGHT_REFUSED)
    except AttachError as e:
        _render_attach_error(e)
        raise SystemExit(1)
    except Exception as e:
        logger.debug("Dry run failed", exc_info=True)
        click.echo(f"\nError: {e}", err=True)
        raise SystemExit(1)
    _render_survey(survey, region_filter, target=target, backend=backend,
                   device_str=device_str)


def _echo_unreadable_ranges(result: AcquireResult) -> None:
    """Name the address ranges that could not be captured.

    Only genuinely failed ranges are listed; expected-unreadable kernel
    mappings are already summarised on the ``Excluded:`` line.

    Args:
        result: The acquisition result to report on.
    """
    failed = [r for r in result.unreadable_ranges if not r.expected]
    if not failed:
        return
    click.echo(f"  Missing : {len(failed)} unreadable range(s)")
    for r in failed[:_MAX_SHOWN_UNREADABLE]:
        name = f" {r.file_path}" if r.file_path else ""
        click.echo(f"            0x{r.base:x}-0x{r.base + r.size:x}"
                   f" ({r.size:,} bytes){name}")
    hidden = (max(0, len(failed) - _MAX_SHOWN_UNREADABLE)
              + result.unreadable_ranges_truncated)
    if hidden > 0:
        click.echo(f"            and {hidden} more — see the log")


def _parse_target(target: str) -> int | str:
    """Parse target as PID (int) or process name (str)."""
    try:
        return int(target)
    except ValueError:
        return target


def _parse_addr_range(value: str) -> tuple[int, int]:
    """Parse address range like '0x1000-0x2000'."""
    parts = value.split("-", 1)
    if len(parts) != 2:
        raise click.BadParameter(f"Invalid address range: {value}. Use format: 0x1000-0x2000")
    return int(parts[0], 16), int(parts[1], 16)


def _progress_bar(processed: int, total: int, bar_width: int = 50) -> str:
    """Render a progress bar string like fridump: [####----] XX.XX% Complete."""
    if total <= 0:
        return ""
    pct = processed / total
    filled = int(round(bar_width * pct))
    bar = "#" * filled + "-" * (bar_width - filled)
    return f"Progress: [{bar}] {pct * 100:.2f}% Complete"


class ProgressDisplay:
    """Pinned progress bar with scrolling debug output below."""

    def __init__(self, debug_lines: int = 4, is_tty: bool | None = None) -> None:
        self._is_tty = sys.stdout.isatty() if is_tty is None else is_tty
        self._bar_text: str = ""
        self._debug_lines: deque[str] = deque(maxlen=debug_lines)
        self._rendered_lines: int = 0  # how many lines we last rendered
        self._last_render: float = 0.0

    def update_progress(self, bar_text: str) -> None:
        self._bar_text = bar_text
        self._render()

    def add_line(self, text: str) -> None:
        self._debug_lines.append(text.rstrip())
        now = time.monotonic()
        if now - self._last_render >= 0.05:
            self._render()

    def _render(self) -> None:
        if not self._is_tty:
            # Non-TTY fallback: simple carriage return for progress bar
            if self._bar_text:
                sys.stdout.write(f"\r{self._bar_text}")
                sys.stdout.flush()
            return

        # Move cursor up to overwrite previous output
        if self._rendered_lines > 0:
            sys.stdout.write(f"\033[{self._rendered_lines}A")

        # Draw progress bar
        sys.stdout.write(f"\033[K{self._bar_text}\n")
        lines_written = 1

        # Draw debug lines
        for line in self._debug_lines:
            sys.stdout.write(f"\033[K{line}\n")
            lines_written += 1

        # Clear any leftover lines from previous render
        for _ in range(self._rendered_lines - lines_written):
            sys.stdout.write("\033[K\n")
            lines_written += 1

        self._rendered_lines = lines_written
        self._last_render = time.monotonic()
        sys.stdout.flush()

    def finalize(self) -> None:
        """Clear debug area and print final bar with newline."""
        if not self._is_tty:
            sys.stdout.write(f"\r{self._bar_text}\n")
            sys.stdout.flush()
            return

        # Move up and clear everything
        if self._rendered_lines > 0:
            sys.stdout.write(f"\033[{self._rendered_lines}A")
        sys.stdout.write(f"\033[K{self._bar_text}\n")
        # Clear remaining debug lines
        for _ in range(self._rendered_lines - 1):
            sys.stdout.write("\033[K\n")
        # Move back up to just after the bar
        if self._rendered_lines > 1:
            sys.stdout.write(f"\033[{self._rendered_lines - 1}A")
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._rendered_lines = 0


class ProgressAwareHandler(logging.Handler):
    """Logging handler that routes output through ProgressDisplay."""

    def __init__(self, display: ProgressDisplay) -> None:
        super().__init__()
        self._display = display

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._display.add_line(msg)
        except Exception:
            self.handleError(record)


# Seconds to wait for a device named by -D to show up before giving up.
_FRIDA_DEVICE_LOOKUP_TIMEOUT = 5.0


def _get_frida_device(usb: bool, remote_addr: str | None, device_id: str | None = None):
    """Create a Frida device based on connection options.

    ``device_id`` (``-D``) wins over ``usb``: ``-U`` alone takes the first
    USB device Frida enumerates, which is the wrong one as soon as a second
    phone or emulator is attached, so ``-D <id>`` names the device explicitly
    (ids as printed by ``frida-ls-devices``).
    """
    import frida

    if device_id:
        try:
            return frida.get_device(device_id, timeout=_FRIDA_DEVICE_LOOKUP_TIMEOUT)
        except Exception as exc:
            raise click.UsageError(
                f"Frida device '{device_id}' not found; run frida-ls-devices"
            ) from exc
    if usb:
        return frida.get_usb_device()
    elif remote_addr:
        host, _, port = remote_addr.partition(":")
        port_num = int(port) if port else 27042
        manager = frida.get_device_manager()
        return manager.add_remote_device(f"{host}:{port_num}")
    else:
        return frida.get_local_device()


def _create_investigation_collector(
    investigation: bool,
    usb: bool,
    remote_addr: str | None,
    os_override: OSType | None,
    logger: logging.Logger,
    device_id: str | None = None,
):
    """Pick the host-side investigation collector, or defer to the engine.

    Args:
        investigation: Whether investigation mode (``-I``) is enabled.
        usb: Whether the target is a USB device.
        remote_addr: Remote server address, if any.
        os_override: Target OS forced via ``--os`` (already an ``OSType``).
        logger: Logger shared with the acquisition engine.
        device_id: Frida device selected via ``-D``, if any (a remote target).

    Returns:
        A collector for a local target, or ``None`` when investigation is
        off or the target is remote. For a remote target the engine picks
        the collector after attach (``FridaRemoteCollector`` through the
        bridge, or ``NullCollector`` for gdb/lldb) — host collectors would
        read the host's ``/proc`` for the device's PID.
    """
    if not investigation:
        return None
    # Truthiness, matching the bridges' is_remote and the attribution
    # below. An empty --remote attaches locally, so treating it as remote
    # here would pick a remote collector for a local capture.
    is_remote = bool(usb or remote_addr or device_id)
    if is_remote:
        logger.info(
            "Remote target: investigation collector is chosen after attach, "
            "from the target's platform"
        )
        return None

    from memslicer.acquirer.collectors import create_collector
    from memslicer.acquirer.identity import infer_os_type

    # infer_os_type(None) walks the host sys.platform ladder; the real
    # target OS is only known after the bridge connects.
    target_os = os_override if os_override is not None else infer_os_type(None)
    return create_collector(target_os, is_remote=False, logger=logger)


def _create_acquirer(
    backend: str,
    target,
    comp_algo,
    region_filter,
    os_override,
    logger,
    read_timeout,
    usb,
    remote_addr,
    max_chunk_size=20971520,
    investigation: bool = False,
    passphrase: str | None = None,
    attribution=None,
    hash_algo: HashAlgo = HashAlgo.BLAKE3,
    device_id: str | None = None,
    app_paths: tuple[str, ...] = (),
    resident_only: bool = False,
    capture_registers: bool = True,
):
    """Factory to create the appropriate acquirer for the selected backend."""
    from memslicer.acquirer.engine import AcquisitionEngine

    if backend == "frida":
        try:
            from memslicer.acquirer.frida_bridge import FridaBridge
        except ImportError:
            raise click.UsageError(
                "Frida is not installed. Install with: pip install memslicer[frida]"
            )
        device = _get_frida_device(usb, remote_addr, device_id)
        bridge = FridaBridge(
            target=target,
            device=device,
            read_timeout=read_timeout,
            logger=logger,
        )
    elif backend == "gdb":
        try:
            from memslicer.acquirer.gdb_bridge import GDBBridge
        except ImportError:
            raise click.UsageError(
                "GDB bridge dependencies not available. Ensure GDB is installed."
            )
        bridge = GDBBridge(target=target, remote=remote_addr, logger=logger)
    elif backend == "lldb":
        try:
            from memslicer.acquirer.lldb_bridge import LLDBBridge
        except ImportError:
            raise click.UsageError(
                "LLDB Python module not found. Ensure LLDB is installed "
                "and its Python bindings are on PYTHONPATH."
            )
        bridge = LLDBBridge(target=target, remote=remote_addr, logger=logger)
    else:
        raise click.UsageError(f"Unknown backend: {backend}")

    collector = _create_investigation_collector(
        investigation=investigation,
        usb=usb,
        remote_addr=remote_addr,
        os_override=os_override,
        logger=logger,
        device_id=device_id,
    )

    return AcquisitionEngine(
        bridge=bridge,
        comp_algo=comp_algo,
        region_filter=region_filter,
        os_override=os_override,
        logger=logger,
        max_chunk_size=max_chunk_size,
        investigation=investigation,
        passphrase=passphrase,
        collector=collector,
        attribution=attribution,
        hash_algo=hash_algo,
        app_paths=app_paths,
        resident_only=resident_only,
        capture_registers=capture_registers,
    )


@click.command()
@click.argument("target")
@click.option("-b", "--backend", type=click.Choice(["frida", "gdb", "lldb"]), default="frida", help="Debugger backend to use")
@click.option("-o", "--output", "output_path", default=None, help="Output .msl file path")
@click.option("-c", "--compress", "comp", type=click.Choice(["none", "zstd", "lz4"]), default="none", help="Compression algorithm")
@click.option("-U", "--usb", is_flag=True, help="Connect to USB device (Frida backend only)")
@click.option("-D", "--device", "device_id", default=None, help="Frida device ID as shown by `frida-ls-devices` (Frida backend only; use when several USB devices are attached)")
@click.option("-R", "--remote", "remote_addr", default=None, help="Remote server host:port (Frida: frida-server, GDB: gdbserver, LLDB: lldb-server)")
@click.option("--os", "os_override", type=click.Choice(["windows", "linux", "macos", "android", "ios"]), default=None, help="Override OS detection")
@click.option("--filter-prot", default=None, help="Protection filter (e.g., 'r--', 'rw-')")
@click.option("--filter-addr", default=None, help="Address range filter (e.g., '0x1000-0x2000')")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug output")
@click.option("--read-timeout", type=float, default=10.0, help="Per-read timeout in seconds (default: 10)")
@click.option("--include-unreadable", is_flag=True, help="Include regions with no read permission")
@click.option("--skip-kernel-pseudo", is_flag=True, help="Skip kernel pseudo-mappings ([vvar], [vsyscall]) instead of attempting them")
@click.option("--max-region-size", type=int, default=0, help="Skip regions larger than this size (0 = no limit)")
@click.option("--scope", default="full", help="Which memory to capture: full (default), app (drop clean read-only mappings of system libraries and device memory), heap (every native and managed heap), stack (thread stacks). Combine with commas, e.g. heap,stack (alias: heapstack).")
@click.option("--exclude-module", "exclude_module", metavar="PATTERN", multiple=True, help="Skip regions belonging to modules matching this glob (basename, e.g. 'libhwui*'; full path when the pattern contains '/'). Repeatable.")
@click.option("--app-path", "app_path", metavar="PREFIX", multiple=True, help="Treat files under this path prefix as app-owned for --scope app. Repeatable.")
@click.option("--resident-only", is_flag=True, help="Skip anonymous pages that were never touched (not resident, not swapped); they read as zero. Needs /proc/<pid>/pagemap or mincore in the target; falls back to full reads with a warning.")
@click.option("--no-registers", is_flag=True, default=False, help="Do not capture thread register state (no Thread Context blocks). Thread stack pointers are then only queried for --scope heap/stack.")
@click.option("--dry-run", is_flag=True, help="Enumerate and classify regions, print what would be captured under the current options, and exit without writing a file. On the Frida backend this still injects the agent into the target.")
@click.option("--investigation", "-I", is_flag=True, help="Investigation mode: capture system-wide context (encrypted by default)")
@click.option("--encrypt", "-E", is_flag=True, default=False, help="Enable AEAD encryption")
@click.option("--no-encrypt", is_flag=True, default=False, help="Disable encryption (overrides investigation default)")
@click.option("--passphrase", default=None, help="Encryption passphrase (prompted if --encrypt and not provided)")
@click.option("--hash-algo", "hash_algo_str", type=click.Choice(["blake3", "sha256", "sha512-256"]), default="blake3", help="Integrity hash algorithm (default: blake3)")
@attribution_options
def acquire(target, backend, output_path, comp, usb, device_id, remote_addr, os_override, filter_prot, filter_addr,
        verbose, read_timeout, include_unreadable, skip_kernel_pseudo,
        max_region_size, scope, exclude_module, app_path, resident_only,
        no_registers, dry_run, investigation,
        encrypt, no_encrypt, passphrase, hash_algo_str,
        examiner, case_ref, hostname_override, domain_override,
        include_serials, include_network_identity, include_fingerprint,
        include_kernel_symbols, include_kernel_modules,
        include_module_build_ids,
        include_target_introspection, include_environ,
        include_persistence_manifest):
    """Dump process memory to MSL format.

    TARGET is a PID (integer) or process name (string).

    Supports 4 acquisition modes:
      Analysis unencrypted (default), Analysis encrypted (-E),
      Investigation encrypted (-I, default), Investigation unencrypted (-I --no-encrypt).
    """
    # Validate backend-specific options
    if usb and backend != "frida":
        raise click.UsageError("--usb / -U is only supported with --backend frida")
    if device_id and backend != "frida":
        raise click.UsageError("--device / -D is only supported with --backend frida")
    if device_id and remote_addr:
        raise click.UsageError("--device / -D and --remote / -R select different transports; use one")

    # Validate + bundle operator attribution at the CLI boundary.
    # Any ForensicStringError becomes a clean BadParameter message
    # rather than propagating into the engine.
    try:
        attribution = validate_attribution(
            examiner=examiner,
            case_ref=case_ref,
            hostname_override=hostname_override,
            domain_override=domain_override,
            is_remote=bool(usb or remote_addr or device_id),
            include_serials=include_serials,
            include_network_identity=include_network_identity,
            include_fingerprint=include_fingerprint,
            include_kernel_symbols=include_kernel_symbols,
            include_kernel_modules=include_kernel_modules,
            include_module_build_ids=include_module_build_ids,
            include_target_introspection=include_target_introspection,
            include_environ=include_environ,
            include_persistence_manifest=include_persistence_manifest,
        )
    except ForensicStringError as exc:
        raise click.BadParameter(str(exc))

    # Determine encryption: investigation defaults to encrypted unless
    # --no-encrypt. Contradictions are refused rather than silently resolved:
    # a capture that is not encrypted when the examiner asked for encryption
    # is a confidentiality failure that no later step can undo.
    if encrypt and no_encrypt:
        raise click.UsageError(
            "--encrypt and --no-encrypt contradict each other; pass only one"
        )
    use_encryption = encrypt or (investigation and not no_encrypt)
    if passphrase is not None and not use_encryption:
        raise click.UsageError(
            "--passphrase was given but encryption is off; add --encrypt / -E "
            "(or drop --no-encrypt) to encrypt this capture"
        )
    if passphrase is not None and not passphrase.strip():
        raise click.UsageError("--passphrase must not be empty")
    if use_encryption and passphrase is None:
        passphrase = click.prompt("Encryption passphrase", hide_input=True, confirmation_prompt=True)

    # Configure logging
    logger = logging.getLogger("memslicer")
    handler = logging.StreamHandler()
    if verbose:
        fmt = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setLevel(logging.DEBUG)
    else:
        fmt = logging.Formatter("%(message)s")
        handler.setLevel(logging.WARNING)
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # Remap INFO level name for display
    logging.addLevelName(logging.INFO, "*")
    logging.addLevelName(logging.DEBUG, "debug")

    # Parse target
    parsed_target = _parse_target(target)

    # Parse compression
    comp_map = {"none": CompAlgo.NONE, "zstd": CompAlgo.ZSTD, "lz4": CompAlgo.LZ4}
    comp_algo = comp_map[comp]

    # Parse hash algorithm
    hash_algo_map = {"blake3": HashAlgo.BLAKE3, "sha256": HashAlgo.SHA256, "sha512-256": HashAlgo.SHA512_256}
    hash_algo = hash_algo_map[hash_algo_str]

    # Parse OS override
    os_map = {"windows": OSType.Windows, "linux": OSType.Linux, "macos": OSType.macOS, "android": OSType.Android, "ios": OSType.iOS}
    os_ovr = os_map.get(os_override) if os_override else None

    # Build region filter
    region_filter = RegionFilter(
        skip_no_read=not include_unreadable,
        skip_kernel_pseudo=skip_kernel_pseudo,
        max_region_size=max_region_size,
        scope=_parse_scope_option(scope),
        exclude_modules=list(exclude_module),
    )
    if filter_prot:
        region_filter.min_prot = parse_protection(filter_prot)
    if filter_addr:
        region_filter.addr_ranges.append(_parse_addr_range(filter_addr))

    # Everything the factory needs, shared by the dry run and the capture.
    acquirer_kwargs = dict(
        backend=backend,
        target=parsed_target,
        comp_algo=comp_algo,
        region_filter=region_filter,
        os_override=os_ovr,
        logger=logger,
        read_timeout=read_timeout,
        usb=usb,
        remote_addr=remote_addr,
        investigation=investigation,
        passphrase=passphrase if use_encryption else None,
        device_id=device_id,
        attribution=attribution,
        hash_algo=hash_algo,
        app_paths=tuple(app_path),
        resident_only=resident_only,
        capture_registers=not no_registers,
    )
    device_str = _device_label(remote_addr, device_id, usb)

    # A dry run plans the capture and reports it; no output file, no log file.
    if dry_run:
        try:
            _run_dry_run(acquirer_kwargs, region_filter, target=target,
                         backend=backend, device_str=device_str, logger=logger)
        finally:
            logger.removeHandler(handler)
        return

    # Default output path
    if output_path is None:
        pid_str = str(parsed_target) if isinstance(parsed_target, int) else parsed_target
        timestamp = int(time.time())
        output_path = f"{pid_str}_{timestamp}.msl"

    # Set up companion log file (captures ALL messages regardless of --verbose)
    log_file_path = f"{output_path}.log"
    file_handler = logging.FileHandler(log_file_path, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.setLevel(logging.DEBUG)  # Logger must accept DEBUG for file handler
    logger.addHandler(file_handler)

    click.echo(f"MemSlicer - Dumping {target} -> {output_path}")
    click.echo(f"Backend: {backend} | Compression: {comp} | Device: {device_str}")

    # Progress display — pinned bar with scrolling debug output
    display = ProgressDisplay()
    last_progress_ts = 0.0

    def progress(regions_captured, total_ranges, bytes_cap, modules, regions_processed):
        nonlocal last_progress_ts
        now = time.monotonic()
        if now - last_progress_ts < 0.1 and regions_processed < total_ranges:
            return
        last_progress_ts = now
        bar = _progress_bar(regions_processed, total_ranges)
        display.update_progress(bar)

    # Route log output through the progress display when verbose
    progress_handler: ProgressAwareHandler | None = None
    if verbose:
        progress_handler = ProgressAwareHandler(display)
        progress_handler.setFormatter(fmt)
        logger.removeHandler(handler)
        logger.addHandler(progress_handler)

    # Create acquirer via factory
    acquirer = _create_acquirer(**acquirer_kwargs)
    acquirer.set_progress_callback(progress)

    try:
        old_handler = signal.signal(signal.SIGINT, lambda sig, frame: acquirer.request_abort())
        result = acquirer.acquire(output_path)
        signal.signal(signal.SIGINT, old_handler)

        display.finalize()
        # Restore normal logging handler
        if progress_handler is not None:
            logger.removeHandler(progress_handler)
            logger.addHandler(handler)
        if result.aborted:
            click.echo("Aborted by user. Partial dump saved.")
        try:
            file_size = Path(result.output_path).stat().st_size
        except OSError:
            file_size = 0
        click.echo(f"  Regions : {result.regions_captured}/{result.regions_total}"
                    f" ({result.regions_skipped} filtered out)")
        if result.skip_reasons:
            for reason, count in sorted(result.skip_reasons.items(),
                                        key=lambda x: -x[1]):
                label = skip_label(reason, region_filter.scope)
                click.echo(f"            {count} {label}")
        _echo_scope_summary(result, region_filter, resident_only)
        total_pages = result.pages_captured + result.pages_failed
        if total_pages > 0:
            page_pct = result.pages_captured / total_pages * 100
            click.echo(f"  Pages   : {result.pages_captured:,}/{total_pages:,}"
                       f" captured ({page_pct:.1f}%)")
        # Kernel pseudo-mappings are mapped but unreadable by design, so they
        # are named explicitly rather than folded into the loss figures.
        if result.pages_expected_unreadable > 0:
            names = ", ".join(sorted(set(result.expected_unreadable_regions)))
            click.echo(f"  Excluded: {result.pages_expected_unreadable:,} pages in"
                       f" kernel pseudo-mappings ({names or 'unnamed'}) —"
                       f" unreadable by design, not counted as data loss")
        # Page-aligned exclusion against a raw attempted total, so clamp: an
        # unaligned trailing region could otherwise push this below zero.
        readable = max(0, result.bytes_attempted - result.bytes_expected_unreadable)
        if readable > 0:
            byte_pct = result.bytes_captured / readable * 100
            click.echo(f"  Bytes   : {result.bytes_captured:,}"
                       f" / {readable:,}"
                       f" readable ({byte_pct:.1f}%)")
        else:
            click.echo(f"  Bytes   : {result.bytes_captured:,}")
        _echo_unreadable_ranges(result)
        click.echo(f"  Modules : {result.modules_captured}")
        if result.thread_contexts > 0:
            click.echo(f"  Threads : {result.thread_contexts}")
        if result.rwx_regions > 0:
            click.echo(f"  RWX     : {result.rwx_regions} (forensic attention recommended)")
        click.echo(f"  Duration: {result.duration_secs:.2f}s")
        click.echo(f"  File    : {result.output_path} ({file_size:,} bytes)")
        click.echo(f"  Log     : {log_file_path}")

        # Multi-level quality assessment
        # Use page-level quality if available, fall back to region-level
        if total_pages > 0:
            if result.pages_failed == 0:
                quality = "EXCELLENT"
            elif page_pct >= 95:
                quality = "GOOD"
            elif page_pct >= 80:
                quality = "FAIR — some pages unreadable"
            else:
                quality = "POOR — significant data loss, consider re-acquisition"
            click.echo(f"  Quality : {quality} (page-level: {page_pct:.1f}%)")
        else:
            attempted = result.regions_total - result.regions_skipped
            if attempted > 0:
                rate = result.regions_captured / attempted * 100
                if rate >= 90:
                    quality = "GOOD"
                elif rate >= 70:
                    quality = "FAIR — some regions unreadable"
                else:
                    quality = "POOR — significant data loss, consider re-acquisition"
                click.echo(f"  Quality : {rate:.1f}% of attempted regions captured ({quality})")
    except KeyboardInterrupt:
        click.echo("\nForce quit.")
        raise SystemExit(1)
    except AttachPreflightError as e:
        _render_attach_error(e, log_file_path)
        raise SystemExit(EXIT_PREFLIGHT_REFUSED)
    except AttachError as e:
        _render_attach_error(e, log_file_path)
        raise SystemExit(1)
    except Exception as e:
        # Restore the console handler first so the traceback reaches the
        # terminal with -v; the file handler is DEBUG, so it always lands
        # in the .msl.log.
        if progress_handler is not None:
            logger.removeHandler(progress_handler)
            logger.addHandler(handler)
        logger.debug("Acquisition failed", exc_info=True)
        click.echo(f"\nError: {e}", err=True)
        click.echo(f"  Log     : {log_file_path}", err=True)
        raise SystemExit(1)
    finally:
        logger.removeHandler(file_handler)
        file_handler.close()
        # The "memslicer" logger outlives this command: detach the console
        # handlers too, or a later run in the same process inherits them.
        if progress_handler is not None:
            logger.removeHandler(progress_handler)
        logger.removeHandler(handler)


class _DefaultCommandGroup(click.Group):
    """Command group that falls back to ``acquire`` for unknown first args.

    Keeps the historic ``memslicer <target> [options]`` invocation working
    alongside named subcommands such as ``memslicer verify <file>``.
    """

    default_command = "acquire"

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if not args or (args[0] not in self.commands and args[0] not in ("--help", "-h")):
            args = [self.default_command, *args]
        return super().parse_args(ctx, args)


@click.group(cls=_DefaultCommandGroup, context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """memslicer: acquire process memory into MSL slices and verify them.

    Without a subcommand, arguments are passed to ``acquire``
    (``memslicer <target> [options]``).
    """


cli.add_command(acquire)
cli.add_command(verify)
