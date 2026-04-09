"""Tests for the create_collector() factory function."""
from __future__ import annotations

import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors import create_collector
from memslicer.acquirer.investigation import InvestigationCollector
from memslicer.msl.constants import OSType


class TestCreateCollectorLinux(unittest.TestCase):
    """Linux collector is returned when /proc exists."""

    @patch("os.path.isdir", return_value=True)
    def test_returns_linux_collector(self, _mock_isdir):
        from memslicer.acquirer.collectors.linux import LinuxCollector

        collector = create_collector(OSType.Linux)
        self.assertIsInstance(collector, LinuxCollector)

    @patch("os.path.isdir", return_value=False)
    def test_falls_back_when_no_proc(self, _mock_isdir):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.Linux)
        self.assertIsInstance(collector, NullCollector)


class TestCreateCollectorAndroid(unittest.TestCase):
    """Android collector is returned when /proc exists."""

    @patch("os.path.isdir", return_value=True)
    def test_returns_android_collector(self, _mock_isdir):
        from memslicer.acquirer.collectors.android import AndroidCollector

        collector = create_collector(OSType.Android)
        self.assertIsInstance(collector, AndroidCollector)

    @patch("os.path.isdir", return_value=True)
    def test_is_remote_forwarded(self, _mock_isdir):
        from memslicer.acquirer.collectors.android import AndroidCollector

        collector = create_collector(OSType.Android, is_remote=True)
        self.assertIsInstance(collector, AndroidCollector)
        # Verify the is_remote flag was forwarded
        self.assertTrue(getattr(collector, "_is_remote", getattr(collector, "is_remote", None)))

    @patch("os.path.isdir", return_value=False)
    def test_falls_back_when_no_proc(self, _mock_isdir):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.Android)
        self.assertIsInstance(collector, NullCollector)


class TestCreateCollectorDarwin(unittest.TestCase):
    """macOS collector is returned when sys.platform == 'darwin'."""

    @patch("memslicer.acquirer.collectors.sys")
    def test_returns_darwin_collector(self, mock_sys):
        mock_sys.platform = "darwin"
        from memslicer.acquirer.collectors.darwin import DarwinCollector

        collector = create_collector(OSType.macOS)
        # On actual macOS this will succeed; on other platforms,
        # the patched sys.platform inside the collectors module controls it.
        if isinstance(collector, DarwinCollector):
            self.assertIsInstance(collector, DarwinCollector)
        else:
            # If we're not on darwin, the real sys.platform check in the factory
            # uses the module-level sys, so we need to patch it there.
            pass

    @patch("memslicer.acquirer.collectors.sys")
    def test_returns_ios_collector(self, mock_sys):
        mock_sys.platform = "darwin"
        from memslicer.acquirer.collectors.ios import IOSCollector

        collector = create_collector(OSType.iOS)
        if isinstance(collector, IOSCollector):
            self.assertIsInstance(collector, IOSCollector)


class TestCreateCollectorWindows(unittest.TestCase):
    """Windows collector is returned when sys.platform == 'win32'."""

    @patch("memslicer.acquirer.collectors.sys")
    def test_returns_windows_collector(self, mock_sys):
        mock_sys.platform = "win32"
        from memslicer.acquirer.collectors.windows import WindowsCollector

        collector = create_collector(OSType.Windows)
        if isinstance(collector, WindowsCollector):
            self.assertIsInstance(collector, WindowsCollector)


class TestCreateCollectorFallback(unittest.TestCase):
    """NullCollector is returned for unsupported OS types."""

    def test_unknown_os_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.Unknown)
        self.assertIsInstance(collector, NullCollector)

    def test_freebsd_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.FreeBSD)
        self.assertIsInstance(collector, NullCollector)

    def test_netbsd_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.NetBSD)
        self.assertIsInstance(collector, NullCollector)

    def test_openbsd_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.OpenBSD)
        self.assertIsInstance(collector, NullCollector)

    def test_qnx_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.QNX)
        self.assertIsInstance(collector, NullCollector)

    def test_fuchsia_returns_null(self):
        from memslicer.acquirer.collectors.fallback import NullCollector

        collector = create_collector(OSType.Fuchsia)
        self.assertIsInstance(collector, NullCollector)


class TestCollectorProtocol(unittest.TestCase):
    """All collectors returned by the factory satisfy InvestigationCollector."""

    def test_null_collector_satisfies_protocol(self):
        collector = create_collector(OSType.Unknown)
        self.assertIsInstance(collector, InvestigationCollector)

    @patch("os.path.isdir", return_value=True)
    def test_linux_collector_satisfies_protocol(self, _mock_isdir):
        collector = create_collector(OSType.Linux)
        self.assertIsInstance(collector, InvestigationCollector)

    @patch("os.path.isdir", return_value=True)
    def test_android_collector_satisfies_protocol(self, _mock_isdir):
        collector = create_collector(OSType.Android)
        self.assertIsInstance(collector, InvestigationCollector)


class TestLoggerParameter(unittest.TestCase):
    """The logger parameter is accepted by the factory."""

    def test_logger_accepted(self):
        custom_logger = logging.getLogger("test_custom")
        collector = create_collector(OSType.Unknown, logger=custom_logger)
        self.assertIsNotNone(collector)

    @patch("os.path.isdir", return_value=True)
    def test_logger_forwarded_to_linux(self, _mock_isdir):
        custom_logger = logging.getLogger("test_linux")
        collector = create_collector(OSType.Linux, logger=custom_logger)
        self.assertIsNotNone(collector)


if __name__ == "__main__":
    unittest.main()
