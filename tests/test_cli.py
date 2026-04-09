"""Tests for CLI interface."""
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from memslicer.cli import cli
from memslicer.acquirer.base import AcquireResult


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
def test_capture_quality_good(mock_factory):
    """Quality shows GOOD when capture rate >= 90%."""
    mock_acquirer = _make_mock_acquirer(
        regions_captured=9, regions_total=10, regions_skipped=0,
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
