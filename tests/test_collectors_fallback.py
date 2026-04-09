"""Tests for NullCollector (fallback for unsupported platforms)."""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors.fallback import NullCollector
from memslicer.acquirer.investigation import (
    InvestigationCollector,
    TargetProcessInfo,
    TargetSystemInfo,
)
from memslicer.msl.types import ProcessEntry, ConnectionEntry, HandleEntry


@pytest.fixture
def collector():
    return NullCollector()


# ---------------------------------------------------------------------------
# All methods return empty/default values
# ---------------------------------------------------------------------------

class TestNullCollectorDefaults:
    """Verify every method returns zeroed/empty defaults."""

    def test_collect_process_identity_returns_defaults(self, collector):
        info = collector.collect_process_identity(1234)
        assert isinstance(info, TargetProcessInfo)
        assert info.ppid == 0
        assert info.session_id == 0
        assert info.start_time_ns == 0
        assert info.exe_path == ""
        assert info.cmd_line == ""

    def test_collect_system_info_returns_defaults(self, collector):
        info = collector.collect_system_info()
        assert isinstance(info, TargetSystemInfo)
        assert info.boot_time == 0
        assert info.hostname == ""
        assert info.domain == ""
        assert info.os_detail == ""

    def test_collect_process_table_returns_empty(self, collector):
        result = collector.collect_process_table(42)
        assert result == []
        assert isinstance(result, list)

    def test_collect_connection_table_returns_empty(self, collector):
        result = collector.collect_connection_table()
        assert result == []
        assert isinstance(result, list)

    def test_collect_handle_table_returns_empty(self, collector):
        result = collector.collect_handle_table(42)
        assert result == []
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# No exceptions raised
# ---------------------------------------------------------------------------

class TestNullCollectorNoExceptions:
    """Verify no method raises, even with unusual inputs."""

    def test_process_identity_zero_pid(self, collector):
        info = collector.collect_process_identity(0)
        assert isinstance(info, TargetProcessInfo)

    def test_process_identity_negative_pid(self, collector):
        info = collector.collect_process_identity(-1)
        assert isinstance(info, TargetProcessInfo)

    def test_process_identity_large_pid(self, collector):
        info = collector.collect_process_identity(2**31)
        assert isinstance(info, TargetProcessInfo)

    def test_process_table_zero_pid(self, collector):
        assert collector.collect_process_table(0) == []

    def test_handle_table_zero_pid(self, collector):
        assert collector.collect_handle_table(0) == []

    def test_multiple_calls_stable(self, collector):
        """Multiple calls should consistently return empty defaults."""
        for _ in range(10):
            assert collector.collect_process_identity(1).ppid == 0
            assert collector.collect_system_info().hostname == ""
            assert collector.collect_process_table(1) == []
            assert collector.collect_connection_table() == []
            assert collector.collect_handle_table(1) == []


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------

class TestNullCollectorProtocol:
    """Verify NullCollector satisfies the InvestigationCollector protocol."""

    def test_isinstance_check(self, collector):
        """NullCollector must pass isinstance check with InvestigationCollector."""
        assert isinstance(collector, InvestigationCollector)

    def test_has_all_protocol_methods(self, collector):
        """Verify all protocol methods are present and callable."""
        assert callable(getattr(collector, "collect_process_identity", None))
        assert callable(getattr(collector, "collect_system_info", None))
        assert callable(getattr(collector, "collect_process_table", None))
        assert callable(getattr(collector, "collect_connection_table", None))
        assert callable(getattr(collector, "collect_handle_table", None))

    def test_return_types_match_protocol(self, collector):
        """Verify return types match the protocol signatures."""
        assert isinstance(collector.collect_process_identity(1), TargetProcessInfo)
        assert isinstance(collector.collect_system_info(), TargetSystemInfo)

        proc_table = collector.collect_process_table(1)
        assert isinstance(proc_table, list)

        conn_table = collector.collect_connection_table()
        assert isinstance(conn_table, list)

        handle_table = collector.collect_handle_table(1)
        assert isinstance(handle_table, list)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class TestNullCollectorInit:

    def test_default_logger(self):
        """NullCollector can be created without explicit logger."""
        c = NullCollector()
        assert c is not None

    def test_custom_logger(self):
        """NullCollector accepts a custom logger."""
        import logging
        logger = logging.getLogger("test_null")
        c = NullCollector(logger=logger)
        assert c._log is logger

    def test_init_logs_warning(self):
        """Constructor should log a warning about minimal data."""
        import logging
        from unittest.mock import patch

        with patch.object(logging.getLogger("memslicer"), "warning") as mock_warn:
            NullCollector()
            mock_warn.assert_called_once()
            assert "NullCollector" in mock_warn.call_args[0][0]
