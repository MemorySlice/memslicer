"""``memslicer verify`` — check an MSL slice's hash chain, FileHash and extension segments.

Exit codes: ``0`` when the slice verifies, ``1`` when it does not.
"""
from __future__ import annotations

import click

from memslicer.msl.iterator import is_encrypted
from memslicer.msl.verify import SegmentReport, VerifyReport, verify_slice


def _summary_line(report: VerifyReport) -> str:
    """Describe algorithm, encryption and the three block counts in one line.

    Encrypted slices also show how many sealed segments verified.
    """
    sealed = f" sealed={len(report.sealed_segments)}" if report.encrypted else ""
    return (
        f"hash={report.hash_algo.name} encrypted={'yes' if report.encrypted else 'no'}"
        f"{sealed} "
        f"blocks={report.block_count} (header BlockCount={report.header_block_count}, "
        f"EoC BlockCount={report.eoc_block_count})"
    )


def _chain_line(report: VerifyReport) -> str:
    """Describe the PrevHash chain outcome in one line."""
    if report.broken_at is not None:
        return f"chain: BROKEN at block {report.broken_at}"
    if report.encrypted:
        if report.block_count == 0 and report.errors:
            return "chain: n/a (encrypted; decryption failed)"
        return "chain: n/a (encrypted; AEAD tag verified)"
    return "chain: OK"


def _file_hash_line(report: VerifyReport) -> str:
    """Describe the EndOfCapture FileHash outcome in one line."""
    if report.file_hash_ok is None:
        return "FileHash: absent"
    return "FileHash: OK" if report.file_hash_ok else "FileHash: MISMATCH"


def _segment_failure(segment: SegmentReport) -> str:
    """Name the first check an extension segment failed."""
    if not segment.terminated:
        return "unterminated"
    if segment.chain_ok is not True:
        return "PrevHash mismatch"
    if segment.segment_hash_ok is not True:
        return "SegmentHash mismatch"
    return f"BlockCount {segment.declared_block_count} != {segment.block_count}"


def _segment_line(segment: SegmentReport) -> str:
    """Describe one extension segment's outcome in one line."""
    if not segment.verified:
        return f"segment {segment.index}: BROKEN ({_segment_failure(segment)})"
    producer = segment.producer or "unknown"
    return (
        f"segment {segment.index}: OK ({segment.block_count} blocks, "
        f"producer={producer})"
    )


def _render_extensions(report: VerifyReport) -> None:
    """Print the extension-segment lines and the trailing-data line, if any."""
    if report.eoc_present:
        click.echo(f"extensions: {len(report.segments)} segment(s)")
    for segment in report.segments:
        click.echo(_segment_line(segment))
    if report.trailing_bytes:
        click.echo(f"trailing: {report.trailing_bytes} byte(s)")


def _render_report(report: VerifyReport) -> None:
    """Print the summary, errors (stderr), warnings and the final verdict."""
    click.echo(_summary_line(report))
    click.echo(_chain_line(report))
    click.echo(_file_hash_line(report))
    _render_extensions(report)
    for error in report.errors:
        click.echo(f"error: {error}", err=True)
    for warning in report.warnings:
        click.echo(f"warning: {warning}")
    click.echo("VALID" if report.valid else "INVALID")


@click.command("verify")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--passphrase", default=None, help="Decryption passphrase (prompted if the slice is encrypted and not provided)")
@click.pass_context
def verify(ctx, file, passphrase):
    """Verify an MSL slice's PrevHash chain, EoC FileHash and extension segments.

    FILE is the .msl slice to check. Exits 0 when valid, 1 otherwise.
    """
    with open(file, "rb") as f:
        try:
            if passphrase is None and is_encrypted(f):
                passphrase = click.prompt("Passphrase", hide_input=True)
            report = verify_slice(f, passphrase)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    _render_report(report)
    ctx.exit(0 if report.valid else 1)
