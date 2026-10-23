"""Tests for CLI interface."""
import logging
import struct
from pathlib import Path as _Path
from unittest.mock import patch, MagicMock, ANY

import pytest
from click.testing import CliRunner
from memslicer.cli import cli, _create_acquirer
from memslicer.acquirer.region_filter import RegionFilter as _RegionFilter
from memslicer.msl.constants import CompAlgo as _CompAlgo, OSType as _OSType
from memslicer.acquirer.base import AcquireResult, UnreadableRange
from memslicer.acquirer.errors import (
    EXIT_PREFLIGHT_REFUSED, AttachError, AttachPreflightError,
)


def _mock_acquire_result(**overrides):
    """Create a default AcquireResult for tests."""
    defaults = dict(
        regions_captured=1, regions_total=1, bytes_captured=4096,
        modules_captured=1, aborted=False, duration_secs=0.1, output_path="test.msl",
        regions_skipped=0, bytes_attempted=4096, pages_captured=1, pages_failed=0,
        skip_reasons={},
    )
    defaults.update(overrides)
    return AcquireResult(**defaults)


def _make_mock_acquirer(**result_overrides):
    """Create a mock acquirer with standard methods and acquire result."""
    mock_acq = MagicMock()
    mock_acq.acquire.return_value = _mock_acquire_result(**result_overrides)
    mock_acq.set_progress_callback = MagicMock()
    mock_acq.request_abort = MagicMock()
    return mock_acq


@patch("memslicer.cli._create_acquirer")
def test_basic_dump(mock_factory):
    """Test basic CLI dump command."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    mock_acquirer.acquire.assert_called_once_with("test.msl")


@patch("memslicer.cli._create_acquirer")
def test_compression_option(mock_factory):
    """Test compression option."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["myapp", "-o", "test.msl", "-c", "zstd"])

    assert result.exit_code == 0
    # Check that ZSTD was passed to the factory
    call_kwargs = mock_factory.call_args[1]
    from memslicer.msl.constants import CompAlgo
    assert call_kwargs["comp_algo"] == CompAlgo.ZSTD


@patch("memslicer.cli._get_frida_device")
@patch("memslicer.cli._create_acquirer")
def test_usb_device(mock_factory, mock_get_device):
    """Test USB device option."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-U"])

    assert result.exit_code == 0
    # Verify usb=True was passed to the factory
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["usb"] is True


@patch("memslicer.cli._create_acquirer")
def test_filter_options(mock_factory):
    """Test filter options."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, [
        "1234", "-o", "test.msl",
        "--filter-prot", "r--",
        "--filter-addr", "0x1000-0x2000",
    ])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.min_prot == 1  # readable
    assert rf.addr_ranges == [(0x1000, 0x2000)]


@patch("memslicer.cli._create_acquirer")
def test_os_override(mock_factory):
    """Test OS override option."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--os", "ios"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    from memslicer.msl.constants import OSType
    assert call_kwargs["os_override"] == OSType.iOS


@patch("memslicer.cli._create_acquirer")
def test_error_handling(mock_factory):
    """Test error handling in CLI."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.acquire.side_effect = RuntimeError("Process not found")
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "-o", "test.msl"])

    assert result.exit_code == 1


@patch("memslicer.cli._create_acquirer")
def test_verbose_flag(mock_factory):
    """Test that -v flag is accepted and doesn't error."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-v"])

    assert result.exit_code == 0
    mock_acquirer.acquire.assert_called_once_with("test.msl")


@patch("memslicer.cli._create_acquirer")
def test_read_timeout_option(mock_factory):
    """Test that --read-timeout passes read_timeout to _create_acquirer."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--read-timeout", "5"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["read_timeout"] == 5.0


@patch("memslicer.cli._create_acquirer")
def test_include_unreadable_flag(mock_factory):
    """Test that --include-unreadable sets skip_no_read=False on the region_filter."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--include-unreadable"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.skip_no_read is False


@patch("memslicer.cli._create_acquirer")
def test_max_region_size_option(mock_factory):
    """Test that --max-region-size sets max_region_size on region_filter."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--max-region-size", "1048576"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.max_region_size == 1048576


@patch("memslicer.cli._create_acquirer")
def test_rwx_summary_shown(mock_factory):
    """RWX summary line appears when rwx_regions > 0."""
    mock_acquirer = _make_mock_acquirer(rwx_regions=3)
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "RWX" in result.output
    assert "forensic attention" in result.output


@patch("memslicer.cli._create_acquirer")
def test_rwx_summary_hidden_when_zero(mock_factory):
    """RWX summary line is hidden when rwx_regions == 0."""
    mock_acquirer = _make_mock_acquirer(rwx_regions=0)
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "RWX" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_capture_quality_excellent(mock_factory):
    """Quality shows EXCELLENT when no page failed."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=9, regions_total=10, regions_skipped=0,
        pages_captured=100, pages_failed=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "EXCELLENT" in result.output
    assert "Quality" in result.output


@patch("memslicer.cli._create_acquirer")
def test_capture_quality_good(mock_factory):
    """Quality shows GOOD when capture rate >= 95% but pages were lost."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=9, regions_total=10, regions_skipped=0,
        pages_captured=96, pages_failed=4,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "GOOD" in result.output
    assert "Quality" in result.output


@patch("memslicer.cli._create_acquirer")
def test_capture_quality_fair(mock_factory):
    """Quality shows FAIR when capture rate is 70-89%."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=7, regions_total=10, regions_skipped=0,
        pages_captured=0, pages_failed=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "FAIR" in result.output


@patch("memslicer.cli._create_acquirer")
def test_capture_quality_poor(mock_factory):
    """Quality shows POOR when capture rate < 70% (region-level fallback)."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=5, regions_total=10, regions_skipped=0,
        pages_captured=0, pages_failed=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "POOR" in result.output


from memslicer.cli import ProgressDisplay


def test_progress_display_non_tty(capsys):
    """ProgressDisplay non-TTY mode writes simple carriage return output."""
    display = ProgressDisplay(is_tty=False)
    display.update_progress("Progress: [###] 50%")
    captured = capsys.readouterr()
    assert "Progress:" in captured.out
    assert "50%" in captured.out


@patch("memslicer.cli._create_acquirer")
def test_page_level_quality_good(mock_factory):
    """Quality shows GOOD when page capture rate >= 95%."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=950, pages_failed=10,
        bytes_captured=3891200, bytes_attempted=3932160,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "GOOD" in result.output
    assert "page-level" in result.output


@patch("memslicer.cli._create_acquirer")
def test_page_level_quality_fair(mock_factory):
    """Quality shows FAIR when page capture rate is 80-94%."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=85, pages_failed=15,
        bytes_captured=348160, bytes_attempted=409600,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "FAIR" in result.output


@patch("memslicer.cli._create_acquirer")
def test_page_level_quality_poor(mock_factory):
    """Quality shows POOR when page capture rate < 80%."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=50, pages_failed=50,
        bytes_captured=204800, bytes_attempted=409600,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "POOR" in result.output


@patch("memslicer.cli._create_acquirer")
def test_skip_reasons_displayed(mock_factory):
    """Skip reason breakdown is shown in output."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=100, regions_total=200, regions_skipped=100,
        skip_reasons={"no-read": 90, "max-size": 10},
        pages_captured=100, pages_failed=0,
        bytes_captured=409600, bytes_attempted=409600,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "90 no read permission" in result.output
    assert "10 exceeded max region size" in result.output


@patch("memslicer.cli._create_acquirer")
def test_bytes_attempted_displayed(mock_factory):
    """Bytes attempted vs captured is shown when bytes_attempted > 0."""
    mock_acquirer = _make_mock_acquirer(
        bytes_captured=3000, bytes_attempted=4096,
        pages_captured=1, pages_failed=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "4,096" in result.output
    assert "readable" in result.output


# ---------- New backend tests ----------


@patch("memslicer.cli._create_acquirer")
def test_backend_gdb(mock_factory):
    """Verify --backend gdb works and passes backend='gdb' to factory."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "gdb"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["backend"] == "gdb"
    mock_acquirer.acquire.assert_called_once_with("test.msl")


@patch("memslicer.cli._create_acquirer")
def test_backend_lldb(mock_factory):
    """Verify --backend lldb works and passes backend='lldb' to factory."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "lldb"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["backend"] == "lldb"
    mock_acquirer.acquire.assert_called_once_with("test.msl")


def test_usb_rejected_for_gdb():
    """--backend gdb -U should fail with UsageError."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "gdb", "-U"])

    assert result.exit_code != 0
    assert "--usb" in result.output or "-U" in result.output


def test_usb_rejected_for_lldb():
    """--backend lldb -U should fail with UsageError."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "lldb", "-U"])

    assert result.exit_code != 0
    assert "--usb" in result.output or "-U" in result.output


@patch("memslicer.cli._create_acquirer")
def test_remote_accepted_for_gdb(mock_factory):
    """--backend gdb -R host:1234 is now accepted (GDB supports remote)."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "gdb", "-R", "host:1234"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["remote_addr"] == "host:1234"


@patch("memslicer.cli._create_acquirer")
def test_remote_accepted_for_lldb(mock_factory):
    """--backend lldb -R host:5678 is accepted (LLDB supports remote)."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "lldb", "-R", "host:5678"])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["remote_addr"] == "host:5678"


@patch("memslicer.cli._create_acquirer")
def test_remote_device_string(mock_factory):
    """Remote address appears in device display string."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-R", "192.168.1.1:27042"])

    assert result.exit_code == 0
    assert "192.168.1.1:27042" in result.output


@patch("memslicer.cli._create_acquirer")
def test_backend_shown_in_output(mock_factory):
    """Verify 'Backend: frida' appears in output."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "Backend: frida" in result.output


# ---------- Kernel pseudo-mapping reporting ----------


@patch("memslicer.cli._create_acquirer")
def test_expected_unreadable_does_not_spoil_quality(mock_factory):
    """Pages the kernel refuses by design are excluded, not counted as loss:
    the capture still reads 100% complete and EXCELLENT."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=120, regions_total=120, regions_skipped=0,
        pages_captured=3245, pages_failed=0,
        pages_expected_unreadable=3,
        bytes_expected_unreadable=3 * 4096,
        expected_unreadable_regions=["[vvar_vclock]"],
        bytes_captured=3245 * 4096, bytes_attempted=3248 * 4096,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "100.0%" in result.output
    assert "Excluded:" in result.output
    assert "[vvar_vclock]" in result.output
    assert "not counted as data loss" in result.output
    assert "EXCELLENT" in result.output


@patch("memslicer.cli._create_acquirer")
def test_excluded_line_hidden_when_nothing_expected(mock_factory):
    """No kernel pseudo-mapping was attempted, so no Excluded: line."""
    mock_acquirer = _make_mock_acquirer(
        pages_captured=10, pages_failed=0, pages_expected_unreadable=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "Excluded:" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_byte_percentage_excludes_expected_unreadable_bytes(mock_factory):
    """The denominator is bytes_attempted - bytes_expected_unreadable."""
    mock_acquirer = _make_mock_acquirer(
        pages_captured=8, pages_failed=0,
        pages_expected_unreadable=2,
        bytes_captured=24576, bytes_attempted=40960,
        bytes_expected_unreadable=8192,
        expected_unreadable_regions=["[vvar]"],
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    # 24,576 / (40,960 - 8,192) = 75.0%, not 24,576 / 40,960 = 60.0%
    assert "24,576 / 32,768 readable (75.0%)" in result.output
    assert "60.0%" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_kernel_pseudo_skip_reason_label(mock_factory):
    """The kernel-pseudo skip reason renders its human-readable label."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=8, regions_total=10, regions_skipped=2,
        skip_reasons={"kernel-pseudo": 2},
        pages_captured=100, pages_failed=0,
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "2 kernel pseudo-mapping, unreadable by design" in result.output


@patch("memslicer.cli._create_acquirer")
def test_skip_kernel_pseudo_flag(mock_factory):
    """--skip-kernel-pseudo sets skip_kernel_pseudo on the region filter."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--skip-kernel-pseudo"])

    assert result.exit_code == 0
    rf = mock_factory.call_args[1]["region_filter"]
    assert rf.skip_kernel_pseudo is True


@patch("memslicer.cli._create_acquirer")
def test_skip_kernel_pseudo_off_by_default(mock_factory):
    """Without the flag the acquirer still attempts the pseudo-mappings."""
    mock_acquirer = _make_mock_acquirer()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    rf = mock_factory.call_args[1]["region_filter"]
    assert rf.skip_kernel_pseudo is False


# ---------- Attach failure rendering ----------


@patch("memslicer.cli._create_acquirer")
def test_preflight_refusal_uses_dedicated_exit_code(mock_factory):
    """A refusal before the attach exits 3 so scripts can tell it apart."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.acquire.side_effect = AttachPreflightError(
        "cannot attach to PID 9999: Yama ptrace_scope is 2",
        remediation=["Run as root, or document the sysctl change"],
        probable_cause="apparmor profile snap.foo",
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "-o", "test.msl"])

    assert result.exit_code == EXIT_PREFLIGHT_REFUSED == 3
    assert "Error:" in result.output
    assert "Yama ptrace_scope is 2" in result.output
    assert "→ Run as root" in result.output
    assert "Probable cause: apparmor profile snap.foo" in result.output
    assert "test.msl.log" in result.output


@patch("memslicer.cli._create_acquirer")
def test_attach_error_exits_one_with_the_same_rendering(mock_factory):
    """A failed attach is a generic failure (exit 1) but reads identically."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.acquire.side_effect = AttachError(
        "attach to 9999 failed: unable to access process",
        remediation=["Check that the process still exists"],
        probable_cause="Yama ptrace_scope is 1",
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "-o", "test.msl"])

    assert result.exit_code == 1
    assert "Error: attach to 9999 failed" in result.output
    assert "→ Check that the process still exists" in result.output
    assert "Probable cause: Yama ptrace_scope is 1" in result.output
    assert "test.msl.log" in result.output


@patch("memslicer.cli._create_acquirer")
def test_generic_exception_rendering_unchanged(mock_factory):
    """Errors without remediation keep the plain one-line rendering."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.acquire.side_effect = RuntimeError("Process not found")
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "-o", "test.msl"])

    assert result.exit_code == 1
    assert "Error: Process not found" in result.output
    assert "→" not in result.output
    assert "Probable cause" not in result.output


# ---------- Unreadable range reporting ----------


from memslicer.cli import _echo_unreadable_ranges


def _range(index, *, expected=False, size=4096):
    """Build an UnreadableRange at a predictable address."""
    return UnreadableRange(
        base=0x10000 + index * 0x10000,
        size=size,
        region_base=0x10000 + index * 0x10000,
        file_path="[vvar]" if expected else "",
        expected=expected,
    )


def test_echo_unreadable_lists_failed_ranges(capsys):
    result = _mock_acquire_result(unreadable_ranges=[_range(0), _range(1)])

    _echo_unreadable_ranges(result)

    out = capsys.readouterr().out
    assert "Missing : 2 unreadable range(s)" in out
    assert "0x10000-0x11000" in out
    assert "0x20000-0x21000" in out
    assert "more" not in out


def test_echo_unreadable_omits_expected_ranges(capsys):
    """Kernel pseudo-mappings are summarised on the Excluded: line instead."""
    result = _mock_acquire_result(unreadable_ranges=[
        _range(0), _range(1, expected=True), _range(2, expected=True),
    ])

    _echo_unreadable_ranges(result)

    out = capsys.readouterr().out
    assert "Missing : 1 unreadable range(s)" in out
    assert "[vvar]" not in out


def test_echo_unreadable_silent_when_all_expected(capsys):
    result = _mock_acquire_result(unreadable_ranges=[
        _range(0, expected=True), _range(1, expected=True),
    ])

    _echo_unreadable_ranges(result)

    assert capsys.readouterr().out == ""


def test_echo_unreadable_collapses_beyond_five(capsys):
    result = _mock_acquire_result(
        unreadable_ranges=[_range(i) for i in range(8)],
    )

    _echo_unreadable_ranges(result)

    out = capsys.readouterr().out
    assert "Missing : 8 unreadable range(s)" in out
    assert out.count("0x") == 10  # five listed ranges, two addresses each
    assert "and 3 more — see the log" in out


def test_echo_unreadable_counts_truncated_ranges(capsys):
    """Ranges dropped by the engine's cap are added to the hidden count."""
    result = _mock_acquire_result(
        unreadable_ranges=[_range(i) for i in range(6)],
        unreadable_ranges_truncated=4,
    )

    _echo_unreadable_ranges(result)

    assert "and 5 more — see the log" in capsys.readouterr().out


def test_echo_unreadable_shows_region_name(capsys):
    result = _mock_acquire_result(unreadable_ranges=[UnreadableRange(
        base=0x7F00, size=8192, region_base=0x7F00,
        file_path="/usr/lib/libc.so.6",
    )])

    _echo_unreadable_ranges(result)

    out = capsys.readouterr().out
    assert "/usr/lib/libc.so.6" in out
    assert "(8,192 bytes)" in out


@patch("memslicer.cli._create_acquirer")
def test_unreadable_ranges_shown_in_summary(mock_factory):
    """The summary names the ranges that were genuinely lost."""
    mock_acquirer = _make_mock_acquirer(
        pages_captured=9, pages_failed=1,
        unreadable_ranges=[_range(0), _range(1, expected=True)],
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "Missing : 1 unreadable range(s)" in result.output
    assert "0x10000-0x11000" in result.output


class TestAcquisitionModeFlags:
    """The four spec Table 1 modes, and the flag conflicts around them.

    Encryption is the one option where silently doing less than asked is a
    confidentiality failure, so every contradiction is refused rather than
    resolved by precedence.
    """

    def _invoke(self, args):
        """Run the CLI with the acquirer mocked out; return (result, kwargs)."""
        with patch("memslicer.cli._create_acquirer") as factory:
            factory.return_value = _make_mock_acquirer()
            result = CliRunner().invoke(cli, args)
        kwargs = factory.call_args[1] if factory.call_args else None
        return result, kwargs

    # -- the four modes -------------------------------------------------

    def test_analysis_unencrypted_is_the_default(self):
        _, kw = self._invoke(["123"])
        assert kw["investigation"] is False
        assert kw["passphrase"] is None

    def test_analysis_encrypted_via_encrypt_flag(self):
        _, kw = self._invoke(["123", "-E", "--passphrase", "secret"])
        assert kw["investigation"] is False
        assert kw["passphrase"] == "secret"

    def test_investigation_defaults_to_encrypted(self):
        _, kw = self._invoke(["123", "-I", "--passphrase", "secret"])
        assert kw["investigation"] is True
        assert kw["passphrase"] == "secret"

    def test_investigation_unencrypted_via_no_encrypt(self):
        _, kw = self._invoke(["123", "-I", "--no-encrypt"])
        assert kw["investigation"] is True
        assert kw["passphrase"] is None

    # -- contradictions are refused, not silently resolved ---------------

    def test_passphrase_without_encryption_is_refused(self):
        """Silently writing plaintext here would betray the examiner's intent."""
        result, kw = self._invoke(["123", "--passphrase", "secret"])
        assert result.exit_code == 2
        assert "encryption is off" in result.output
        assert kw is None, "must not reach the acquirer"

    def test_passphrase_with_no_encrypt_is_refused(self):
        result, _ = self._invoke(["123", "-I", "--no-encrypt", "--passphrase", "s"])
        assert result.exit_code == 2
        assert "encryption is off" in result.output

    def test_encrypt_and_no_encrypt_together_are_refused(self):
        result, kw = self._invoke(["123", "-E", "--no-encrypt"])
        assert result.exit_code == 2
        assert "contradict" in result.output
        assert kw is None

    def test_empty_passphrase_is_refused(self):
        result, kw = self._invoke(["123", "-E", "--passphrase", ""])
        assert result.exit_code == 2
        assert "must not be empty" in result.output
        assert kw is None

    def test_whitespace_only_passphrase_is_refused(self):
        result, _ = self._invoke(["123", "-E", "--passphrase", "   "])
        assert result.exit_code == 2
        assert "must not be empty" in result.output


# ---------- Investigation collector selection (issue #3) ----------


def _build_engine(*, usb=False, remote_addr=None, investigation=True, os_override=None):
    """Call the real factory with a frida backend and a mocked device."""
    return _create_acquirer(
        backend="frida",
        target=1234,
        comp_algo=_CompAlgo.NONE,
        region_filter=_RegionFilter(),
        os_override=os_override,
        logger=logging.getLogger("memslicer.test_cli"),
        read_timeout=1.0,
        usb=usb,
        remote_addr=remote_addr,
        investigation=investigation,
    )


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_remote_usb_investigation_defers_collector_to_engine(mock_device, mock_factory):
    """-I -U leaves the collector to the engine; no host collector is built."""
    mock_device.return_value = MagicMock(type="usb")

    engine = _build_engine(usb=True, investigation=True)

    assert engine._collector is None
    mock_factory.assert_not_called()


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_remote_addr_investigation_defers_collector_to_engine(mock_device, mock_factory):
    """-I -R behaves like -U: collector chosen after attach."""
    mock_device.return_value = MagicMock(type="remote")

    engine = _build_engine(remote_addr="192.168.1.5:27042", investigation=True)

    assert engine._collector is None
    mock_factory.assert_not_called()


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_local_investigation_uses_host_collector(mock_device, mock_factory):
    """Local -I builds a host collector from the host platform, never remote."""
    mock_device.return_value = MagicMock(type="local")
    sentinel = MagicMock(name="host_collector")
    mock_factory.return_value = sentinel

    engine = _build_engine(usb=False, remote_addr=None, investigation=True)

    assert engine._collector is sentinel
    mock_factory.assert_called_once()
    assert mock_factory.call_args.kwargs["is_remote"] is False


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_local_investigation_honours_os_override(mock_device, mock_factory):
    """--os android on a local target is forwarded to the factory."""
    mock_device.return_value = MagicMock(type="local")

    _build_engine(investigation=True, os_override=_OSType.Android)

    os_arg = mock_factory.call_args.args[0]
    assert os_arg == _OSType.Android
    assert mock_factory.call_args.kwargs["is_remote"] is False


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_no_investigation_builds_no_collector(mock_device, mock_factory):
    """Without -I there is nothing to collect, so no collector is built."""
    mock_device.return_value = MagicMock(type="usb")

    engine = _build_engine(usb=True, investigation=False)

    assert engine._collector is None
    mock_factory.assert_not_called()


# ---------- Traceback diagnostics on failure (Step 7) ----------


_STRUCT_ERROR_TEXT = "'Q' format requires 0 <= number <= 18446744073709551615"


def _invoke_failing_acquire(mock_factory, args):
    """Run the CLI with an acquirer that raises the issue #3 struct.error."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.acquire.side_effect = struct.error(_STRUCT_ERROR_TEXT)
    mock_factory.return_value = mock_acquirer
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, args)
        log_text = _Path("test.msl.log").read_text(encoding="utf-8")
    return result, log_text


@patch("memslicer.cli._create_acquirer")
def test_failure_traceback_lands_in_log_file(mock_factory):
    """A failed capture writes the traceback to the .msl.log and names it."""
    result, log_text = _invoke_failing_acquire(mock_factory, ["1234", "-o", "test.msl"])

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert _STRUCT_ERROR_TEXT in result.output
    assert "test.msl.log" in result.output
    assert "Traceback" in log_text
    assert "Acquisition failed" in log_text


@patch("memslicer.cli._create_acquirer")
def test_failure_traceback_hidden_from_console_without_verbose(mock_factory):
    """Without -v the console shows only the one-line error."""
    result, _ = _invoke_failing_acquire(mock_factory, ["1234", "-o", "test.msl"])

    assert result.exit_code == 1
    assert "Traceback" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_failure_traceback_shown_on_console_with_verbose(mock_factory):
    """With -v the traceback also reaches the console."""
    result, log_text = _invoke_failing_acquire(mock_factory, ["1234", "-o", "test.msl", "-v"])

    assert result.exit_code == 1
    assert "Traceback" in result.output
    assert "Traceback" in log_text


@patch("memslicer.cli._create_acquirer")
def test_console_handlers_detached_after_run(mock_factory):
    """Each run detaches its console handlers from the shared logger.

    Otherwise a later run in the same process (or test) inherits a DEBUG
    handler from an earlier ``-v`` run and prints debug output unasked.
    """
    mock_factory.return_value = _make_mock_acquirer()
    shared = logging.getLogger("memslicer")
    before = list(shared.handlers)

    runner = CliRunner()
    with runner.isolated_filesystem():
        assert runner.invoke(cli, ["1234", "-o", "test.msl", "-v"]).exit_code == 0
        mock_factory.return_value.acquire.side_effect = RuntimeError("boom")
        assert runner.invoke(cli, ["1234", "-o", "test.msl", "-v"]).exit_code == 1

    assert shared.handlers == before


# ---------- -D/--device: explicit Frida device selection ----------


@patch("memslicer.cli._create_acquirer")
def test_device_id_passed_to_factory(mock_factory):
    """-D emu hands device_id="emu" to _create_acquirer."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-D", "emu"])

    assert result.exit_code == 0
    assert mock_factory.call_args.kwargs["device_id"] == "emu"


@patch("memslicer.cli._create_acquirer")
def test_device_id_defaults_to_none(mock_factory):
    """Without -D the factory receives device_id=None, so -U/-R behave as before."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-U"])

    assert result.exit_code == 0
    assert mock_factory.call_args.kwargs["device_id"] is None
    assert mock_factory.call_args.kwargs["usb"] is True


@patch("memslicer.cli._create_acquirer")
def test_device_id_with_usb_is_allowed(mock_factory):
    """-U -D <id> is the issue-#3 invocation plus a selector; both are forwarded."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-U", "-D", "emulator-5556"])

    assert result.exit_code == 0
    assert mock_factory.call_args.kwargs["usb"] is True
    assert mock_factory.call_args.kwargs["device_id"] == "emulator-5556"


@patch("memslicer.cli._create_acquirer")
def test_device_id_shown_in_banner(mock_factory):
    """The startup banner names the selected device."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-D", "emulator-5556"])

    assert result.exit_code == 0
    assert "Device: emulator-5556 (USB)" in result.output


@patch("memslicer.cli._create_acquirer")
def test_device_id_rejected_with_remote(mock_factory):
    """-D and -R name two different transports: UsageError, exit 2."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-D", "emu", "-R", "host:27042"])

    assert result.exit_code == 2
    assert "--device" in result.output or "-D" in result.output
    mock_factory.assert_not_called()


def test_device_id_rejected_for_gdb():
    """--backend gdb -D should fail with UsageError, like -U does."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "gdb", "-D", "emu"])

    assert result.exit_code == 2
    assert "--device" in result.output or "-D" in result.output


def test_device_id_rejected_for_lldb():
    """--backend lldb -D should fail with UsageError, like -U does."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--backend", "lldb", "-D", "emu"])

    assert result.exit_code == 2
    assert "--device" in result.output or "-D" in result.output


def _patched_frida():
    """Patch the lazily imported ``frida`` module seen by _get_frida_device."""
    return patch.dict("sys.modules", {"frida": MagicMock()})


def test_get_frida_device_uses_get_device_for_device_id():
    """_get_frida_device(False, None, "emu") resolves the id via frida.get_device."""
    from memslicer.cli import _get_frida_device

    with _patched_frida():
        import sys
        fake_frida = sys.modules["frida"]
        sentinel = MagicMock(name="device")
        fake_frida.get_device.return_value = sentinel

        device = _get_frida_device(False, None, "emu")

    assert device is sentinel
    fake_frida.get_device.assert_called_once_with("emu", timeout=ANY)
    assert fake_frida.get_device.call_args.kwargs["timeout"] > 0
    fake_frida.get_usb_device.assert_not_called()
    fake_frida.get_local_device.assert_not_called()


def test_get_frida_device_id_wins_over_usb():
    """-U -D <id>: the explicit id is used, not the first USB device."""
    from memslicer.cli import _get_frida_device

    with _patched_frida():
        import sys
        fake_frida = sys.modules["frida"]

        _get_frida_device(True, None, "emu")

    fake_frida.get_device.assert_called_once()
    fake_frida.get_usb_device.assert_not_called()


def test_get_frida_device_lookup_failure_is_usage_error():
    """An unknown id becomes a UsageError pointing at frida-ls-devices."""
    import click
    from memslicer.cli import _get_frida_device

    with _patched_frida():
        import sys
        sys.modules["frida"].get_device.side_effect = RuntimeError("timeout")

        with pytest.raises(click.UsageError) as excinfo:
            _get_frida_device(False, None, "nope")

    assert "nope" in str(excinfo.value)
    assert "frida-ls-devices" in str(excinfo.value)


def test_get_frida_device_without_device_id_is_unchanged():
    """No -D: -U still takes the first USB device and no id lookup happens."""
    from memslicer.cli import _get_frida_device

    with _patched_frida():
        import sys
        fake_frida = sys.modules["frida"]

        _get_frida_device(True, None)

    fake_frida.get_usb_device.assert_called_once_with()
    fake_frida.get_device.assert_not_called()


@patch("memslicer.acquirer.collectors.create_collector")
@patch("memslicer.cli._get_frida_device")
def test_device_id_investigation_defers_collector_to_engine(mock_device, mock_factory):
    """-I -D <id> is a remote target: no host collector is built."""
    mock_device.return_value = MagicMock(type="usb")

    engine = _create_acquirer(
        backend="frida",
        target=1234,
        comp_algo=_CompAlgo.NONE,
        region_filter=_RegionFilter(),
        os_override=None,
        logger=logging.getLogger("memslicer.test_cli"),
        read_timeout=1.0,
        usb=False,
        remote_addr=None,
        investigation=True,
        device_id="emulator-5556",
    )

    assert engine._collector is None
    mock_factory.assert_not_called()
    mock_device.assert_called_once_with(False, None, "emulator-5556")


@patch("memslicer.cli.validate_attribution")
@patch("memslicer.cli._create_acquirer")
def test_device_id_marks_attribution_remote(mock_factory, mock_validate):
    """-D alone makes the attribution is_remote=True."""
    mock_factory.return_value = _make_mock_acquirer()
    mock_validate.return_value = MagicMock(name="attribution")

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-D", "emu"])

    assert result.exit_code == 0, result.output
    assert mock_validate.call_args.kwargs["is_remote"] is True


# ---------- --scope / --exclude-module / --app-path / --resident-only ----------


def _survey():
    """A small RegionSurvey: two heap regions kept, libc and a no-read skipped."""
    from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
    from memslicer.acquirer.engine import RegionDecision, RegionSurvey
    from memslicer.acquirer.region_classify import RegionCategory, RegionInfo

    libc = ModuleInfo(name="libc.so", path="/system/lib64/libc.so", base=0x40000, size=0x2000)

    def decision(base, size, prot, category, label, skip=None, owner=None):
        return RegionDecision(
            range=MemoryRange(base=base, size=size, protection=prot, file_path=label),
            protection=6 if prot == "rw-" else 5,
            info=RegionInfo(category=category, owner=owner, label=label, system_owned=owner is not None),
            skip_reason=skip,
        )

    decisions = [
        decision(0x10000, 8192, "rw-", RegionCategory.HEAP_NATIVE, "scudo:primary"),
        decision(0x20000, 16384, "rw-", RegionCategory.HEAP_MANAGED, "dalvik-main space"),
        decision(0x40000, 8192, "r-x", RegionCategory.IMAGE, "/system/lib64/libc.so", "scope", libc),
        decision(0x80000, 4096, "---", RegionCategory.ANON, "", "no-read"),
    ]
    return RegionSurvey(_OSType.Android, 4096, [libc], decisions)


@patch("memslicer.cli._create_acquirer")
def test_scope_option_parsed_into_region_filter(mock_factory):
    """--scope heap,stack lands on the RegionFilter as a token set."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--scope", "heap,stack"])

    assert result.exit_code == 0
    assert mock_factory.call_args[1]["region_filter"].scope == {"heap", "stack"}


@patch("memslicer.cli._create_acquirer")
def test_scope_alias_heapstack(mock_factory):
    """The heapstack alias expands to heap and stack."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--scope", "heapstack"])

    assert result.exit_code == 0
    assert mock_factory.call_args[1]["region_filter"].scope == {"heap", "stack"}


@patch("memslicer.cli._create_acquirer")
def test_scope_defaults_to_full(mock_factory):
    """Without --scope the filter keeps everything."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    rf = mock_factory.call_args[1]["region_filter"]
    assert rf.scope == {"full"}
    assert rf.exclude_modules == []


@patch("memslicer.cli._create_acquirer")
def test_scope_unknown_token_is_a_usage_error(mock_factory):
    """An unknown scope token is refused before anything is attached."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--scope", "bogus"])

    assert result.exit_code == 2
    assert "unknown scope token" in result.output
    mock_factory.assert_not_called()


@patch("memslicer.cli._create_acquirer")
def test_scope_full_cannot_be_combined(mock_factory):
    """full already keeps everything, so full,heap is refused."""
    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--scope", "full,heap"])

    assert result.exit_code == 2
    assert "cannot be combined" in result.output
    mock_factory.assert_not_called()


@patch("memslicer.cli._create_acquirer")
def test_exclude_module_order_preserved(mock_factory):
    """Repeated --exclude-module patterns reach the filter in the given order."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, [
        "1234", "-o", "test.msl",
        "--exclude-module", "libhwui*", "--exclude-module", "/apex/*",
    ])

    assert result.exit_code == 0
    rf = mock_factory.call_args[1]["region_filter"]
    assert rf.exclude_modules == ["libhwui*", "/apex/*"]


@patch("memslicer.cli._create_acquirer")
def test_app_path_and_resident_only_reach_factory(mock_factory):
    """--app-path and --resident-only are handed to _create_acquirer."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, [
        "1234", "-o", "test.msl", "--app-path", "/opt/foo", "--resident-only",
    ])

    assert result.exit_code == 0
    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["app_paths"] == ("/opt/foo",)
    assert call_kwargs["resident_only"] is True


@patch("memslicer.cli._create_acquirer")
def test_app_path_and_resident_only_default_off(mock_factory):
    """Without the options the engine gets no app paths and no pruning."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    assert runner.invoke(cli, ["1234", "-o", "test.msl"]).exit_code == 0

    call_kwargs = mock_factory.call_args[1]
    assert call_kwargs["app_paths"] == ()
    assert call_kwargs["resident_only"] is False


def test_create_acquirer_forwards_app_paths_and_resident_only():
    """The factory passes app_paths and resident_only to AcquisitionEngine."""
    with patch("memslicer.acquirer.engine.AcquisitionEngine") as mock_engine, \
         patch("memslicer.acquirer.gdb_bridge.GDBBridge"):
        _create_acquirer(
            backend="gdb", target=1234, comp_algo=_CompAlgo.NONE,
            region_filter=_RegionFilter(), os_override=None,
            logger=logging.getLogger("memslicer"), read_timeout=10.0,
            usb=False, remote_addr=None,
            app_paths=("/opt/foo",), resident_only=True,
        )
    kwargs = mock_engine.call_args[1]
    assert kwargs["app_paths"] == ("/opt/foo",)
    assert kwargs["resident_only"] is True


# ---------- --dry-run ----------


@patch("memslicer.cli._create_acquirer")
def test_dry_run_surveys_without_writing_anything(mock_factory):
    """--dry-run surveys, prints the plan and leaves no .msl or .msl.log."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.survey_regions.return_value = _survey()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, [
            "1234", "-o", "test.msl", "--dry-run",
            "--scope", "heap", "--exclude-module", "libhwui*",
        ])
        leftovers = sorted(p.name for p in _Path(".").iterdir())

    assert result.exit_code == 0, result.output
    assert leftovers == []
    mock_acquirer.survey_regions.assert_called_once_with()
    mock_acquirer.acquire.assert_not_called()
    assert "Dry run for 1234" in result.output
    assert "Dumping" not in result.output
    assert "Scope: heap | Exclude: libhwui*" in result.output
    assert "regions kept" in result.output and "bytes skipped" in result.output
    assert "heap-managed" in result.output
    assert "Top owners:" in result.output
    assert "libc.so" in result.output
    assert "Would capture 24.0 KiB of 32.0 KiB readable bytes across 2 of 4 regions" in result.output
    assert "1 outside selected --scope (heap)" in result.output
    assert "1 no read permission" in result.output


@patch("memslicer.cli._create_acquirer")
def test_dry_run_ignores_encryption_and_output_options(mock_factory):
    """--dry-run with -E/--passphrase/-o is accepted and still writes nothing."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.survey_regions.return_value = _survey()
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, [
            "1234", "-o", "out.msl", "-E", "--passphrase", "pw", "--dry-run",
        ])
        leftovers = sorted(p.name for p in _Path(".").iterdir())

    assert result.exit_code == 0, result.output
    assert leftovers == []
    mock_acquirer.acquire.assert_not_called()


@patch("memslicer.cli._create_acquirer")
def test_dry_run_attach_error_has_no_log_pointer(mock_factory):
    """An attach failure during a dry run renders without a .msl.log line."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.survey_regions.side_effect = AttachError(
        "attach to 9999 failed", remediation=["Check the PID"],
    )
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "--dry-run"])

    assert result.exit_code == 1
    assert "Error: attach to 9999 failed" in result.output
    assert "→ Check the PID" in result.output
    assert "Full environment record" not in result.output
    assert ".msl.log" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_dry_run_preflight_refusal_keeps_exit_code(mock_factory):
    """A preflight refusal during a dry run still exits 3."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.survey_regions.side_effect = AttachPreflightError("refused")
    mock_factory.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "--dry-run"])

    assert result.exit_code == EXIT_PREFLIGHT_REFUSED


@patch("memslicer.cli._create_acquirer")
def test_dry_run_detaches_console_handler(mock_factory):
    """A dry run leaves the shared logger as it found it."""
    mock_acquirer = _make_mock_acquirer()
    mock_acquirer.survey_regions.return_value = _survey()
    mock_factory.return_value = mock_acquirer
    shared = logging.getLogger("memslicer")
    before = list(shared.handlers)

    runner = CliRunner()
    assert runner.invoke(cli, ["1234", "--dry-run", "-v"]).exit_code == 0

    assert shared.handlers == before


# ---------- Summary lines for scope, omissions and residency ----------


@patch("memslicer.cli._create_acquirer")
def test_summary_shows_scope_omitted_and_resident_lines(mock_factory):
    """A scoped, pruned capture reports scope, exclusions, omissions and residency."""
    mock_factory.return_value = _make_mock_acquirer(
        scope="heap", regions_omitted=3, pages_nonresident=10,
        bytes_nonresident=40960, residency_method="pagemap",
        skip_reasons={"scope": 6},
    )

    runner = CliRunner()
    result = runner.invoke(cli, [
        "1234", "-o", "test.msl", "--scope", "heap",
        "--exclude-module", "libhwui*", "--exclude-module", "/apex/*",
        "--resident-only",
    ])

    assert result.exit_code == 0, result.output
    assert "6 outside selected --scope (heap)" in result.output
    assert "  Scope   : heap" in result.output
    assert "  Exclude : libhwui*, /apex/*" in result.output
    assert "  Omitted : 3 regions recorded in RegionOmissionManifest (0x005B)" in result.output
    assert ("  Resident: 10 pages (40.0 KiB) skipped as never-touched"
            " (method: pagemap)") in result.output
    assert "Note    :" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_summary_notes_when_residency_pruning_unavailable(mock_factory):
    """--resident-only without residency support says so in one line."""
    mock_factory.return_value = _make_mock_acquirer(residency_method="none")

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--resident-only"])

    assert result.exit_code == 0
    assert "--resident-only was requested but residency information was unavailable" in result.output
    assert "Resident:" not in result.output


@patch("memslicer.cli._create_acquirer")
def test_summary_unchanged_for_plain_full_capture(mock_factory):
    """A full capture without exclusions prints none of the new lines."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    for marker in ("Scope   :", "Exclude :", "Omitted :", "Resident:", "Note    :"):
        assert marker not in result.output


@patch("memslicer.cli._create_acquirer")
def test_summary_shows_exclude_line_for_full_scope_with_patterns(mock_factory):
    """--exclude-module alone is enough to print the Scope and Exclude lines."""
    mock_factory.return_value = _make_mock_acquirer()

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--exclude-module", "libfoo*"])

    assert result.exit_code == 0
    assert "  Scope   : full" in result.output
    assert "  Exclude : libfoo*" in result.output


@pytest.mark.parametrize("n, expected", [
    (0, "0 B"), (512, "512 B"), (1024, "1.0 KiB"), (40960, "40.0 KiB"),
    (1536 * 1024, "1.5 MiB"), (3 * 1024 ** 3, "3.0 GiB"), (5 * 1024 ** 4, "5120.0 GiB"),
])
def test_fmt_size(n, expected):
    from memslicer.cli import _fmt_size
    assert _fmt_size(n) == expected


# ---------- --no-registers (Thread Context blocks) ----------

@patch("memslicer.cli._create_acquirer")
def test_no_registers_reaches_factory(mock_factory):
    """--no-registers turns register capture off at the factory boundary."""
    mock_factory.return_value = _make_mock_acquirer()

    result = CliRunner().invoke(cli, ["1234", "-o", "test.msl", "--no-registers"])

    assert result.exit_code == 0
    assert mock_factory.call_args[1]["capture_registers"] is False


@patch("memslicer.cli._create_acquirer")
def test_registers_captured_by_default(mock_factory):
    mock_factory.return_value = _make_mock_acquirer()

    result = CliRunner().invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert mock_factory.call_args[1]["capture_registers"] is True


def test_create_acquirer_forwards_capture_registers():
    """The factory passes capture_registers to AcquisitionEngine."""
    with patch("memslicer.acquirer.engine.AcquisitionEngine") as mock_engine, \
         patch("memslicer.acquirer.gdb_bridge.GDBBridge"):
        _create_acquirer(
            backend="gdb", target=1234, comp_algo=_CompAlgo.NONE,
            region_filter=_RegionFilter(), os_override=None,
            logger=logging.getLogger("memslicer"), read_timeout=10.0,
            usb=False, remote_addr=None, capture_registers=False,
        )
    assert mock_engine.call_args[1]["capture_registers"] is False


@patch("memslicer.cli._create_acquirer")
def test_threads_summary_line_shown_when_contexts_written(mock_factory):
    mock_factory.return_value = _make_mock_acquirer(thread_contexts=7)

    result = CliRunner().invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "  Threads : 7" in result.output


@patch("memslicer.cli._create_acquirer")
def test_threads_summary_line_hidden_without_contexts(mock_factory):
    """A backend that reports no threads leaves the summary as it was."""
    mock_factory.return_value = _make_mock_acquirer(thread_contexts=0)

    result = CliRunner().invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "Threads :" not in result.output
