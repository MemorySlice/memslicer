"""MemSlicer CLI - Frida-based MSL memory dump tool."""
from __future__ import annotations
import logging
import signal
import sys
import time
from collections import deque
from pathlib import Path

import click
import frida

from memslicer.msl.constants import CompAlgo, OSType
from memslicer.acquirer.frida_acquirer import FridaAcquirer
from memslicer.acquirer.region_filter import RegionFilter, SKIP_REASON_LABELS
from memslicer.utils.protection import parse_protection


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


@click.command()
@click.argument("target")
@click.option("-o", "--output", "output_path", default=None, help="Output .msl file path")
@click.option("-c", "--compress", "comp", type=click.Choice(["none", "zstd", "lz4"]), default="none", help="Compression algorithm")
@click.option("-U", "--usb", is_flag=True, help="Connect to USB device (iOS/Android)")
@click.option("-R", "--remote", "remote_addr", default=None, help="Remote Frida server (host:port)")
@click.option("--os", "os_override", type=click.Choice(["windows", "linux", "macos", "android", "ios"]), default=None, help="Override OS detection")
@click.option("--filter-prot", default=None, help="Protection filter (e.g., 'r--', 'rw-')")
@click.option("--filter-addr", default=None, help="Address range filter (e.g., '0x1000-0x2000')")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug output")
@click.option("--read-timeout", type=float, default=10.0, help="Per-read timeout in seconds (default: 10)")
@click.option("--include-unreadable", is_flag=True, help="Include regions with no read permission")
@click.option("--max-region-size", type=int, default=0, help="Skip regions larger than this size (0 = no limit)")
def cli(target, output_path, comp, usb, remote_addr, os_override, filter_prot, filter_addr,
        verbose, read_timeout, include_unreadable, max_region_size):
    """Dump process memory to MSL format.

    TARGET is a PID (integer) or process name (string).
    """
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

    # Determine device
    if usb:
        device = frida.get_usb_device()
    elif remote_addr:
        host, _, port = remote_addr.partition(":")
        port_num = int(port) if port else 27042
        manager = frida.get_device_manager()
        device = manager.add_remote_device(f"{host}:{port_num}")
    else:
        device = frida.get_local_device()

    # Parse compression
    comp_map = {"none": CompAlgo.NONE, "zstd": CompAlgo.ZSTD, "lz4": CompAlgo.LZ4}
    comp_algo = comp_map[comp]

    # Parse OS override
    os_map = {"windows": OSType.Windows, "linux": OSType.Linux, "macos": OSType.macOS, "android": OSType.Android, "ios": OSType.iOS}
    os_ovr = os_map.get(os_override) if os_override else None

    # Build region filter
    region_filter = RegionFilter(
        skip_no_read=not include_unreadable,
        max_region_size=max_region_size,
    )
    if filter_prot:
        region_filter.min_prot = parse_protection(filter_prot)
    if filter_addr:
        region_filter.addr_ranges.append(_parse_addr_range(filter_addr))

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
    click.echo(f"Compression: {comp} | Device: {'USB' if usb else remote_addr or 'local'}")

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

    # Acquire
    acquirer = FridaAcquirer(
        target=parsed_target,
        device=device,
        comp_algo=comp_algo,
        region_filter=region_filter,
        os_override=os_ovr,
        logger=logger,
        read_timeout=read_timeout,
    )
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
                label = SKIP_REASON_LABELS.get(reason, reason)
                click.echo(f"            {count} {label}")
        total_pages = result.pages_captured + result.pages_failed
        if total_pages > 0:
            page_pct = result.pages_captured / total_pages * 100
            click.echo(f"  Pages   : {result.pages_captured:,}/{total_pages:,}"
                       f" captured ({page_pct:.1f}%)")
        if result.bytes_attempted > 0:
            byte_pct = result.bytes_captured / result.bytes_attempted * 100
            click.echo(f"  Bytes   : {result.bytes_captured:,}"
                       f" / {result.bytes_attempted:,}"
                       f" readable ({byte_pct:.1f}%)")
        else:
            click.echo(f"  Bytes   : {result.bytes_captured:,}")
        click.echo(f"  Modules : {result.modules_captured}")
        if result.rwx_regions > 0:
            click.echo(f"  RWX     : {result.rwx_regions} (forensic attention recommended)")
        click.echo(f"  Duration: {result.duration_secs:.2f}s")
        click.echo(f"  File    : {result.output_path} ({file_size:,} bytes)")
        click.echo(f"  Log     : {log_file_path}")

        # Multi-level quality assessment
        # Use page-level quality if available, fall back to region-level
        if total_pages > 0:
            if page_pct >= 95:
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
    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        raise SystemExit(1)
    finally:
        logger.removeHandler(file_handler)
        file_handler.close()
