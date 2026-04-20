"""MemSlicer CLI - MSL memory dump tool with pluggable debugger backends."""
from __future__ import annotations
import logging
import signal
import sys
import time
from collections import deque
from pathlib import Path

import click

from memslicer.acquirer.identity import (
    ForensicStringError,
    attribution_options,
    validate_attribution,
)
from memslicer.acquirer.region_filter import RegionFilter, SKIP_REASON_LABELS
from memslicer.msl.constants import CompAlgo, HashAlgo, OSType
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


def _get_frida_device(usb: bool, remote_addr: str | None):
    """Create a Frida device based on connection options."""
    import frida

    if usb:
        return frida.get_usb_device()
    elif remote_addr:
        host, _, port = remote_addr.partition(":")
        port_num = int(port) if port else 27042
        manager = frida.get_device_manager()
        return manager.add_remote_device(f"{host}:{port_num}")
    else:
        return frida.get_local_device()


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
        device = _get_frida_device(usb, remote_addr)
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

    # Create investigation collector if investigation mode is enabled
    collector = None
    if investigation:
        from memslicer.acquirer.collectors import create_collector
        is_remote = usb or (remote_addr is not None)

        # For remote Frida targets, use FridaRemoteCollector which runs
        # JS on the target device. Note: FridaRemoteCollector needs
        # the Frida session, which is only available after bridge.connect().
        # We store the bridge reference so the engine can set up the
        # remote collector during acquisition. For local targets, we
        # create a platform-local collector immediately.
        if backend == "frida" and is_remote:
            # Remote Frida: store bridge ref for deferred collector setup.
            # The local collector serves as fallback if remote setup fails.
            logger.info(
                "Remote Frida target detected; investigation data will be "
                "collected from target device when possible"
            )

        # Determine target OS for collector selection
        target_os = os_override if os_override is not None else None
        if target_os is not None:
            collector = create_collector(target_os, is_remote=is_remote, logger=logger)
        else:
            # OS detected after bridge connects; use host platform as fallback
            import sys as _sys
            if _sys.platform == "linux":
                collector = create_collector(OSType.Linux, is_remote=is_remote, logger=logger)
            elif _sys.platform == "darwin":
                collector = create_collector(OSType.macOS, is_remote=is_remote, logger=logger)
            elif _sys.platform == "win32":
                collector = create_collector(OSType.Windows, is_remote=is_remote, logger=logger)
            else:
                collector = create_collector(OSType.Unknown, is_remote=is_remote, logger=logger)

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
    )


@click.command()
@click.argument("target")
@click.option("-b", "--backend", type=click.Choice(["frida", "gdb", "lldb"]), default="frida", help="Debugger backend to use")
@click.option("-o", "--output", "output_path", default=None, help="Output .msl file path")
@click.option("-c", "--compress", "comp", type=click.Choice(["none", "zstd", "lz4"]), default="none", help="Compression algorithm")
@click.option("-U", "--usb", is_flag=True, help="Connect to USB device (Frida backend only)")
@click.option("-R", "--remote", "remote_addr", default=None, help="Remote server host:port (Frida: frida-server, GDB: gdbserver, LLDB: lldb-server)")
@click.option("--os", "os_override", type=click.Choice(["windows", "linux", "macos", "android", "ios"]), default=None, help="Override OS detection")
@click.option("--filter-prot", default=None, help="Protection filter (e.g., 'r--', 'rw-')")
@click.option("--filter-addr", default=None, help="Address range filter (e.g., '0x1000-0x2000')")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug output")
@click.option("--read-timeout", type=float, default=10.0, help="Per-read timeout in seconds (default: 10)")
@click.option("--include-unreadable", is_flag=True, help="Include regions with no read permission")
@click.option("--max-region-size", type=int, default=0, help="Skip regions larger than this size (0 = no limit)")
@click.option("--investigation", "-I", is_flag=True, help="Investigation mode: capture system-wide context (encrypted by default)")
@click.option("--encrypt", "-E", is_flag=True, default=False, help="Enable AEAD encryption")
@click.option("--no-encrypt", is_flag=True, default=False, help="Disable encryption (overrides investigation default)")
@click.option("--passphrase", default=None, help="Encryption passphrase (prompted if --encrypt and not provided)")
@click.option("--hash-algo", "hash_algo_str", type=click.Choice(["blake3", "sha256", "sha512-256"]), default="blake3", help="Integrity hash algorithm (default: blake3)")
@attribution_options
def cli(target, backend, output_path, comp, usb, remote_addr, os_override, filter_prot, filter_addr,
        verbose, read_timeout, include_unreadable, max_region_size, investigation,
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

    # Validate + bundle operator attribution at the CLI boundary.
    # Any ForensicStringError becomes a clean BadParameter message
    # rather than propagating into the engine.
    try:
        attribution = validate_attribution(
            examiner=examiner,
            case_ref=case_ref,
            hostname_override=hostname_override,
            domain_override=domain_override,
            is_remote=bool(usb or remote_addr),
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

    # Determine encryption: investigation defaults to encrypted unless --no-encrypt
    use_encryption = encrypt or (investigation and not no_encrypt)
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

    # Determine device display string
    if remote_addr:
        device_str = remote_addr
    elif usb:
        device_str = "USB"
    else:
        device_str = "local"

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
    acquirer = _create_acquirer(
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
        attribution=attribution,
        hash_algo=hash_algo,
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
