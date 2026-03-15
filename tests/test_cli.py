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


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_basic_dump(mock_frida, mock_acquirer_class):
    """Test basic CLI dump command."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    mock_acquirer.acquire.assert_called_once_with("test.msl")


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_compression_option(mock_frida, mock_acquirer_class):
    """Test compression option."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["myapp", "-o", "test.msl", "-c", "zstd"])

    assert result.exit_code == 0
    # Check that ZSTD was passed
    call_kwargs = mock_acquirer_class.call_args[1]
    from memslicer.msl.constants import CompAlgo
    assert call_kwargs["comp_algo"] == CompAlgo.ZSTD


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_usb_device(mock_frida, mock_acquirer_class):
    """Test USB device option."""
    mock_frida.get_usb_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-U"])

    assert result.exit_code == 0
    mock_frida.get_usb_device.assert_called_once()


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_filter_options(mock_frida, mock_acquirer_class):
    """Test filter options."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, [
        "1234", "-o", "test.msl",
        "--filter-prot", "r--",
        "--filter-addr", "0x1000-0x2000",
    ])

    assert result.exit_code == 0
    call_kwargs = mock_acquirer_class.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.min_prot == 1  # readable
    assert rf.addr_ranges == [(0x1000, 0x2000)]


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_os_override(mock_frida, mock_acquirer_class):
    """Test OS override option."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--os", "ios"])

    assert result.exit_code == 0
    call_kwargs = mock_acquirer_class.call_args[1]
    from memslicer.msl.constants import OSType
    assert call_kwargs["os_override"] == OSType.iOS


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_error_handling(mock_frida, mock_acquirer_class):
    """Test error handling in CLI."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.side_effect = RuntimeError("Process not found")
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["9999", "-o", "test.msl"])

    assert result.exit_code == 1


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_verbose_flag(mock_frida, mock_acquirer_class):
    """Test that -v flag is accepted and doesn't error."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "-v"])

    assert result.exit_code == 0
    mock_acquirer.acquire.assert_called_once_with("test.msl")


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_read_timeout_option(mock_frida, mock_acquirer_class):
    """Test that --read-timeout passes read_timeout to FridaAcquirer."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--read-timeout", "5"])

    assert result.exit_code == 0
    call_kwargs = mock_acquirer_class.call_args[1]
    assert call_kwargs["read_timeout"] == 5.0


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_include_unreadable_flag(mock_frida, mock_acquirer_class):
    """Test that --include-unreadable sets skip_no_read=False on the region_filter."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--include-unreadable"])

    assert result.exit_code == 0
    call_kwargs = mock_acquirer_class.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.skip_no_read is False


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_max_region_size_option(mock_frida, mock_acquirer_class):
    """Test that --max-region-size sets max_region_size on region_filter."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result()
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl", "--max-region-size", "1048576"])

    assert result.exit_code == 0
    call_kwargs = mock_acquirer_class.call_args[1]
    rf = call_kwargs["region_filter"]
    assert rf.max_region_size == 1048576


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_rwx_summary_shown(mock_frida, mock_acquirer_class):
    """RWX summary line appears when rwx_regions > 0."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(rwx_regions=3)
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "RWX" in result.output
    assert "forensic attention" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_rwx_summary_hidden_when_zero(mock_frida, mock_acquirer_class):
    """RWX summary line is hidden when rwx_regions == 0."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(rwx_regions=0)
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "RWX" not in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_capture_quality_good(mock_frida, mock_acquirer_class):
    """Quality shows GOOD when capture rate >= 90%."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=9, regions_total=10, regions_skipped=0,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "GOOD" in result.output
    assert "Quality" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_capture_quality_fair(mock_frida, mock_acquirer_class):
    """Quality shows FAIR when capture rate is 70-89%."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=7, regions_total=10, regions_skipped=0,
        pages_captured=0, pages_failed=0,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "FAIR" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_capture_quality_poor(mock_frida, mock_acquirer_class):
    """Quality shows POOR when capture rate < 70% (region-level fallback)."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=5, regions_total=10, regions_skipped=0,
        pages_captured=0, pages_failed=0,
    )
    mock_acquirer_class.return_value = mock_acquirer

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


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_page_level_quality_good(mock_frida, mock_acquirer_class):
    """Quality shows GOOD when page capture rate >= 95%."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=950, pages_failed=10,
        bytes_captured=3891200, bytes_attempted=3932160,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "GOOD" in result.output
    assert "page-level" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_page_level_quality_fair(mock_frida, mock_acquirer_class):
    """Quality shows FAIR when page capture rate is 80-94%."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=85, pages_failed=15,
        bytes_captured=348160, bytes_attempted=409600,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "FAIR" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_page_level_quality_poor(mock_frida, mock_acquirer_class):
    """Quality shows POOR when page capture rate < 80%."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=10, regions_total=15, regions_skipped=5,
        pages_captured=50, pages_failed=50,
        bytes_captured=204800, bytes_attempted=409600,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "POOR" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_skip_reasons_displayed(mock_frida, mock_acquirer_class):
    """Skip reason breakdown is shown in output."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        regions_captured=100, regions_total=200, regions_skipped=100,
        skip_reasons={"no-read": 90, "max-size": 10},
        pages_captured=100, pages_failed=0,
        bytes_captured=409600, bytes_attempted=409600,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "90 no read permission" in result.output
    assert "10 exceeded max region size" in result.output


@patch("memslicer.cli.FridaAcquirer")
@patch("memslicer.cli.frida")
def test_bytes_attempted_displayed(mock_frida, mock_acquirer_class):
    """Bytes attempted vs captured is shown when bytes_attempted > 0."""
    mock_frida.get_local_device.return_value = MagicMock()
    mock_acquirer = MagicMock()
    mock_acquirer.acquire.return_value = _mock_acquire_result(
        bytes_captured=3000, bytes_attempted=4096,
        pages_captured=1, pages_failed=0,
    )
    mock_acquirer_class.return_value = mock_acquirer

    runner = CliRunner()
    result = runner.invoke(cli, ["1234", "-o", "test.msl"])

    assert result.exit_code == 0
    assert "4,096" in result.output
    assert "readable" in result.output
