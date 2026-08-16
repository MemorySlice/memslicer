"""Tests for CLI interface."""
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from memslicer.cli import cli
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
