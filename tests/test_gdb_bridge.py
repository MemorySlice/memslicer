"""Tests for the GDBBridge debugger bridge."""
from __future__ import annotations

import queue
import re
import subprocess
import threading
from unittest.mock import MagicMock, mock_open, patch

import pytest

from memslicer.acquirer.bridge import MemoryRange, ModuleInfo
from memslicer.acquirer.engine import parse_protection
from memslicer.acquirer.gdb_bridge import (
    _MI_MAX_READ, GDBBridge, MIError, _unescape_mi,
)
from memslicer.acquirer.region_filter import RegionFilter
from memslicer.acquirer.platform_detect import parse_gdb_architecture as _parse_gdb_architecture
from memslicer.msl.constants import ArchType, OSType


# ---------------------------------------------------------------------------
# Tests -- construction
# ---------------------------------------------------------------------------

class TestGDBBridgeInit:
    """Tests for GDBBridge.__init__()."""

    def test_target_accepts_int(self):
        """Passing an int target sets _pid directly."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        assert bridge._pid == 1234

    def test_target_resolves_name_via_proc(self):
        """Passing a string target resolves to PID via /proc."""
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["1", "42", "abc", "100"]), \
             patch("builtins.open", mock_open(read_data="my_app\n")):
            bridge = GDBBridge(target="my_app", logger=MagicMock())
        # Should resolve to the first matching PID
        assert bridge._pid == 1

    def test_target_resolves_name_via_pidof(self):
        """Falls back to pidof when /proc doesn't find the process."""
        with patch("os.path.isdir", return_value=False), \
             patch("shutil.which", return_value="/usr/bin/pidof"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="42\n")
            bridge = GDBBridge(target="my_app", logger=MagicMock())
        assert bridge._pid == 42

    def test_target_name_not_found_raises(self):
        """ValueError raised when process name cannot be resolved."""
        with patch("os.path.isdir", return_value=False), \
             patch("shutil.which", return_value=None):
            with pytest.raises(ValueError, match="Could not resolve"):
                GDBBridge(target="nonexistent_app", logger=MagicMock())


# ---------------------------------------------------------------------------
# Tests -- _check_ptrace_scope
# ---------------------------------------------------------------------------

class TestGDBBridgePtraceCheck:
    """Tests for _check_ptrace_scope pre-flight check."""

    def test_ptrace_scope_warning_on_high_scope(self):
        """Warning logged when ptrace_scope >= 2."""
        logger = MagicMock()
        bridge = GDBBridge(target=1234, logger=logger)
        with patch("builtins.open", mock_open(read_data="2\n")):
            bridge._check_ptrace_scope()
        logger.warning.assert_called_once()
        assert "ptrace_scope" in logger.warning.call_args[0][0]

    def test_ptrace_scope_info_on_default(self):
        """Info logged when ptrace_scope is 1 (default)."""
        logger = MagicMock()
        bridge = GDBBridge(target=1234, logger=logger)
        with patch("builtins.open", mock_open(read_data="1\n")):
            bridge._check_ptrace_scope()
        logger.info.assert_called()

    def test_ptrace_scope_silent_when_not_linux(self):
        """No warnings when /proc/sys/kernel/yama/ptrace_scope doesn't exist."""
        logger = MagicMock()
        bridge = GDBBridge(target=1234, logger=logger)
        with patch("builtins.open", side_effect=FileNotFoundError):
            bridge._check_ptrace_scope()
        logger.warning.assert_not_called()


# ---------------------------------------------------------------------------
# Tests -- read_memory
# ---------------------------------------------------------------------------

class TestGDBBridgeReadMemory:
    """Tests for GDBBridge.read_memory()."""

    def test_read_memory_parses_hex_response(self):
        """A successful MI response with contents=\"...\" is parsed to bytes."""
        bridge = GDBBridge(target=1234, logger=MagicMock())

        # Simulate the MI command returning hex content.
        mi_response = (
            '^done,addr="0x10000",nr-bytes="4",'
            'total-bytes="4",next-row="0x10004",'
            'prev-row="0x0fffc",next-page="0x10004",'
            'prev-page="0x0fffc",'
            'memory=[{begin="0x10000",offset="0x0",'
            'end="0x10004",contents="deadbeef"}]'
        )
        bridge._send_mi_command = MagicMock(return_value=mi_response)

        result = bridge.read_memory(0x10000, 4)

        assert result == bytes.fromhex("deadbeef")
        bridge._send_mi_command.assert_called_once_with(
            "-data-read-memory-bytes 0x10000 4"
        )

    def test_read_memory_returns_none_on_error(self):
        """When the MI command raises RuntimeError, None is returned."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock(
            side_effect=RuntimeError("GDB/MI error: Cannot access memory")
        )

        result = bridge.read_memory(0xDEAD, 8)

        assert result is None


# ---------------------------------------------------------------------------
# Tests -- enumerate_ranges
# ---------------------------------------------------------------------------

class TestGDBBridgeEnumerateRanges:
    """Tests for GDBBridge.enumerate_ranges()."""

    def test_enumerate_ranges_parses_proc_maps(self):
        """Ranges are correctly parsed from /proc/<pid>/maps content."""
        bridge = GDBBridge(target=42, logger=MagicMock())

        maps_content = (
            "00400000-00452000 r-xp 00000000 08:01 12345  /usr/bin/app\n"
            "7f000000-7f001000 rw-p 00000000 00:00 0      [heap]\n"
            "7ffff000-80000000 r--p 00000000 08:01 99999  /usr/lib/libc.so.6\n"
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=maps_content)):
            ranges = bridge.enumerate_ranges()

        assert len(ranges) == 3

        r0 = ranges[0]
        assert r0.base == 0x00400000
        assert r0.size == 0x00452000 - 0x00400000
        assert r0.protection == "r-x"
        assert r0.file_path == "/usr/bin/app"

        r1 = ranges[1]
        assert r1.base == 0x7F000000
        assert r1.size == 0x1000
        assert r1.protection == "rw-"
        assert r1.file_path == "[heap]"


# ---------------------------------------------------------------------------
# Tests -- _parse_gdb_architecture
# ---------------------------------------------------------------------------

class TestParseGdbArchitecture:
    """Tests for the module-level _parse_gdb_architecture helper."""

    @pytest.mark.parametrize(
        "text, expected",
        [
            ('The target architecture is set to "i386".', ArchType.x86),
            ('The target architecture is set to "auto" (currently "i386:x86-64").', ArchType.x86_64),
            ('The target architecture is set to "aarch64".', ArchType.ARM64),
            ('The target architecture is set to "arm".', ArchType.ARM32),
        ],
    )
    def test_platform_detect(self, text: str, expected: ArchType):
        """Various GDB architecture output strings are mapped correctly."""
        result = _parse_gdb_architecture(text)
        assert result == expected

    def test_unknown_architecture_raises(self):
        """An unrecognised architecture string raises ValueError."""
        with pytest.raises(ValueError, match="Cannot parse GDB architecture"):
            _parse_gdb_architecture("something totally unknown")


# ---------------------------------------------------------------------------
# Tests -- MI command timeout
# ---------------------------------------------------------------------------

class TestMICommandTimeout:
    """Tests for _send_mi_command timeout and process-death handling."""

    def test_mi_command_timeout(self):
        """TimeoutError raised when GDB never sends a result record."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=0.2)

        # Set up a mock process with stdin that accepts writes
        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        mock_proc.poll.return_value = None
        bridge._proc = mock_proc

        # Empty queue — no lines will ever arrive
        bridge._line_queue = queue.Queue()

        with pytest.raises(TimeoutError, match="did not respond"):
            bridge._send_mi_command("-some-command")

    def test_mi_command_process_died(self):
        """RuntimeError raised when GDB process exits mid-command."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=5.0)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc

        # Simulate reader thread signalling EOF (process died)
        bridge._line_queue = queue.Queue()
        bridge._line_queue.put(None)

        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            bridge._send_mi_command("-some-command")

    def test_mi_command_succeeds_with_queue(self):
        """Normal operation: result record arrives via queue."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=5.0)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc

        bridge._line_queue = queue.Queue()
        bridge._line_queue.put("~\"some console output\"")
        bridge._line_queue.put("^done")

        result = bridge._send_mi_command("-some-command")
        assert "^done" in result

    def test_read_memory_returns_none_on_timeout(self):
        """read_memory gracefully returns None when MI times out."""
        bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=0.1)

        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        bridge._proc = mock_proc
        bridge._line_queue = queue.Queue()

        result = bridge.read_memory(0x1000, 4096)
        assert result is None


# ---------------------------------------------------------------------------
# Helpers -- MI reply construction
# ---------------------------------------------------------------------------

def _queued_bridge(*lines: str) -> GDBBridge:
    """Build a bridge whose reader queue already holds *lines*."""
    bridge = GDBBridge(target=1234, logger=MagicMock(), mi_timeout=5.0)
    mock_proc = MagicMock()
    mock_proc.stdin = MagicMock()
    bridge._proc = mock_proc
    bridge._line_queue = queue.Queue()
    for line in lines:
        bridge._line_queue.put(line)
    return bridge


def _mi_memory_reply(*blocks: tuple[int, str]) -> str:
    """Build a ``^done`` read reply listing the given ``(begin, hex)`` blocks."""
    listed = ",".join(
        f'{{begin="{begin:#x}",offset="0x0",'
        f'end="{begin + len(contents) // 2:#x}",contents="{contents}"}}'
        for begin, contents in blocks
    )
    return (
        '^done,addr="0x1000",nr-bytes="0",total-bytes="0",'
        f"memory=[{listed}]"
    )


def _read_bridge(reply, remote: str | None = None) -> GDBBridge:
    """Build a bridge whose _send_mi_command is stubbed with *reply*."""
    bridge = GDBBridge(target=1234, remote=remote, logger=MagicMock())
    if isinstance(reply, str):
        bridge._send_mi_command = MagicMock(return_value=reply)
    else:
        bridge._send_mi_command = MagicMock(side_effect=reply)
    return bridge


def _console_bridge(*replies: str, remote: str | None = None) -> GDBBridge:
    """Build a bridge whose console commands answer with *replies* in order.

    The text is handed over already unescaped, as _send_console_command would
    return it, so the caller writes the console output GDB prints rather than
    its MI transport form.
    """
    bridge = GDBBridge(target=1234, remote=remote, logger=MagicMock())
    bridge._send_console_command = MagicMock(side_effect=list(replies))
    return bridge


# ---------------------------------------------------------------------------
# Tests -- _send_mi_command record detection
# ---------------------------------------------------------------------------

class TestMICommandRecordDetection:
    """The stale "(gdb) " prompt must never displace the result record."""

    def test_stale_prompt_before_error_still_raises(self):
        """A queued "(gdb) " ahead of ^error does not mask the MIError."""
        bridge = _queued_bridge(
            "(gdb) ",
            '^error,msg="Cannot access memory at address 0x1000"',
        )

        with pytest.raises(MIError) as excinfo:
            bridge._send_mi_command("-data-read-memory-bytes 0x1000 4")

        assert excinfo.value.detail == "Cannot access memory at address 0x1000"

    def test_mi_error_is_a_runtime_error(self):
        """MIError subclasses RuntimeError so existing handlers still catch it."""
        assert issubclass(MIError, RuntimeError)
        assert isinstance(MIError("boom"), RuntimeError)

    def test_stale_prompt_is_dropped_from_the_result(self):
        """The prompt is stripped while console output is kept."""
        bridge = _queued_bridge("(gdb) ", '~"console output"', "^done")

        result = bridge._send_mi_command("-some-command")

        assert '~"console output"' in result
        assert "(gdb)" not in result


# ---------------------------------------------------------------------------
# Tests -- read_memory_ex block parsing
# ---------------------------------------------------------------------------

class TestGDBBridgeReadMemoryExBlocks:
    """Tests for how read_memory_ex interprets the MI memory=[..] listing."""

    def test_single_block_covers_the_request(self):
        """One block spanning the whole request yields the bytes and no fault."""
        bridge = _read_bridge(_mi_memory_reply((0x1000, "deadbeef")))

        res = bridge.read_memory_ex(0x1000, 4)

        assert res.data == bytes.fromhex("deadbeef")
        assert res.fault_addr is None
        assert bridge.read_memory(0x1000, 4) == res.data

    def test_gap_between_blocks_faults_at_the_prefix_end(self):
        """A hole between two blocks reports the end of the readable prefix."""
        bridge = _read_bridge(
            _mi_memory_reply((0x1000, "aabbccdd"), (0x1008, "11223344"))
        )

        res = bridge.read_memory_ex(0x1000, 12)

        assert res.data is None
        assert res.fault_addr == 0x1004

    def test_first_block_after_the_request_faults_at_the_request(self):
        """A listing that starts past the requested address proves it unreadable."""
        bridge = _read_bridge(_mi_memory_reply((0x1004, "aabbccdd")))

        res = bridge.read_memory_ex(0x1000, 8)

        assert res.data is None
        assert res.fault_addr == 0x1000

    def test_empty_memory_list_faults_at_the_request(self):
        """An empty memory=[] means GDB answered and nothing was readable."""
        bridge = _read_bridge(_mi_memory_reply())

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr == 0x1000

    def test_reply_without_memory_listing_reports_no_fault(self):
        """An unparseable reply must not be mistaken for a proven fault."""
        bridge = _read_bridge('^done,addr="0x1000",nr-bytes="0"')

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error

    def test_adjacent_blocks_are_merged(self):
        """Two touching blocks are joined into one contiguous span."""
        bridge = _read_bridge(
            _mi_memory_reply((0x1000, "aabbccdd"), (0x1004, "11223344"))
        )

        res = bridge.read_memory_ex(0x1000, 8)

        assert res.data == bytes.fromhex("aabbccdd11223344")
        assert res.fault_addr is None

    def test_undecodable_contents_block_reports_no_fault(self):
        """A block that will not decode makes the whole reply untrusted.

        Dropping just that block would shorten the readable run and report a
        parse failure as a proven unreadable address, costing a page that reads
        perfectly well. No fault address sends the caller to page-by-page reads
        instead.
        """
        bridge = _read_bridge(
            _mi_memory_reply((0x1000, "aabbccdd"), (0x1004, "abc"))
        )

        res = bridge.read_memory_ex(0x1000, 8)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error


# ---------------------------------------------------------------------------
# Tests -- fault address parsed from ^error text
# ---------------------------------------------------------------------------

class TestGDBBridgeReadMemoryExFaultText:
    """Only an interior address scraped from ^error text may be trusted."""

    def test_echoed_request_address_is_not_reported(self):
        """GDB naming the requested address adds nothing, so no fault is kept."""
        detail = "Cannot access memory at address 0x1000"
        bridge = _read_bridge(MIError(detail))

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error == detail

    def test_interior_address_is_reported(self):
        """An address strictly inside the span is a real boundary."""
        bridge = _read_bridge(
            MIError("Cannot access memory at address 0x1800")
        )

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr == 0x1800

    def test_error_without_an_address_reports_no_fault(self):
        """GDB's addressless total-failure text yields no fault address."""
        bridge = _read_bridge(MIError("Unable to read memory."))

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error == "Unable to read memory."


# ---------------------------------------------------------------------------
# Tests -- transport failures
# ---------------------------------------------------------------------------

class TestGDBBridgeReadMemoryExTransport:
    """A dead transport is not evidence about the memory being read."""

    @pytest.mark.parametrize("failure", [
        TimeoutError("GDB did not respond within 30.0s"),
        RuntimeError("GDB process exited unexpectedly"),
    ], ids=["timeout", "process-death"])
    def test_transport_failure_reports_no_fault(self, failure):
        """A dead transport yields no data and no fault address."""
        bridge = _read_bridge(failure)

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error


# ---------------------------------------------------------------------------
# Tests -- MI read cap
# ---------------------------------------------------------------------------

class TestGDBBridgeMIReadCap:
    """Spans larger than _MI_MAX_READ are split across several MI commands."""

    @staticmethod
    def _recording_reader(issued: list[tuple[int, int]]):
        """Return a _send_mi_command stub that synthesises matching replies."""
        def reply(cmd: str) -> str:
            match = re.match(
                r"-data-read-memory-bytes (0x[0-9a-fA-F]+) (\d+)", cmd,
            )
            assert match is not None, cmd
            begin, count = int(match.group(1), 16), int(match.group(2))
            issued.append((begin, count))
            return _mi_memory_reply((begin, (bytes([len(issued)]) * count).hex()))

        return reply

    def test_oversized_request_is_split_and_rejoined(self):
        """Sub-read sizes sum to the request and the data is concatenated in order."""
        size = _MI_MAX_READ + 4096
        issued: list[tuple[int, int]] = []
        bridge = _read_bridge(self._recording_reader(issued))

        res = bridge.read_memory_ex(0x1000, size)

        assert sum(count for _begin, count in issued) == size
        assert [begin for begin, _count in issued] == [
            0x1000, 0x1000 + _MI_MAX_READ,
        ]
        assert res.data == bytes([1]) * _MI_MAX_READ + bytes([2]) * 4096

    def test_failing_sub_read_discards_the_whole_span(self):
        """A later sub-read failing yields no data and that sub-read's fault."""
        issued: list[tuple[int, int]] = []
        good = self._recording_reader(issued)
        fault = 0x1000 + _MI_MAX_READ + 0x800

        def reply(cmd: str) -> str:
            if issued:
                raise MIError(f"Cannot access memory at address {fault:#x}")
            return good(cmd)

        bridge = _read_bridge(reply)

        res = bridge.read_memory_ex(0x1000, _MI_MAX_READ + 4096)

        assert res.data is None
        assert res.fault_addr == fault


# ---------------------------------------------------------------------------
# Tests -- _target_pid and remote gating
# ---------------------------------------------------------------------------

class TestGDBBridgeTargetPid:
    """A remote inferior's PID is GDB's to report, not the constructor's."""

    def test_local_target_pid_needs_no_mi_command(self):
        """A local bridge answers from the constructor PID."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock()

        assert bridge._target_pid() == 1234
        bridge._send_mi_command.assert_not_called()

    def test_remote_target_pid_comes_from_thread_groups(self):
        """A remote bridge parses pid=".." out of -list-thread-groups."""
        bridge = _read_bridge(
            '^done,groups=[{id="i1",type="process",pid="777",'
            'executable="/usr/bin/app"}]',
            remote="host:1234",
        )

        assert bridge._target_pid() == 777
        bridge._send_mi_command.assert_called_once_with("-list-thread-groups")

    def test_remote_enumerate_ranges_skips_proc_maps(self):
        """A remote bridge must not describe a local PID's /proc/<pid>/maps."""
        bridge = _read_bridge(
            "~\"          Start Addr           End Addr       Size"
            "     Offset  objfile\\n\"\n"
            "~\"            0x400000           0x452000    0x52000"
            "        0x0  /usr/bin/app\\n\"\n"
            "^done",
            remote="host:1234",
        )

        with patch(
            "memslicer.acquirer.gdb_bridge.parse_proc_maps"
        ) as mock_maps:
            ranges = bridge.enumerate_ranges()

        mock_maps.assert_not_called()
        assert len(ranges) == 1
        assert isinstance(ranges[0], MemoryRange)
        assert ranges[0].base == 0x400000
        assert ranges[0].size == 0x52000
        assert ranges[0].protection == "---"
        assert ranges[0].file_path == "/usr/bin/app"


# ---------------------------------------------------------------------------
# Tests -- attach preflight
# ---------------------------------------------------------------------------

class TestGDBBridgePreflight:
    """connect() runs the shared attach preflight before spawning GDB."""

    def test_refusal_propagates_and_never_spawns_gdb(self):
        """A refused preflight aborts connect() before subprocess.Popen runs."""
        from memslicer.acquirer.errors import AttachPreflightError

        bridge = GDBBridge(target=1234, logger=MagicMock())
        refusal = AttachPreflightError(
            "cannot attach to PID 1234: Yama ptrace_scope is 2",
            remediation=["run as root"],
        )

        with patch("shutil.which", return_value="/usr/bin/gdb"), \
             patch("subprocess.Popen") as mock_popen, \
             patch("memslicer.acquirer.gdb_bridge.enforce_attach_preflight",
                   side_effect=refusal):
            with pytest.raises(AttachPreflightError) as excinfo:
                bridge.connect()

        assert excinfo.value is refusal
        mock_popen.assert_not_called()
        assert bridge._proc is None


class TestGDBBridgeConsoleUnescaping:
    """Console stream records are unescaped before anything is parsed out."""

    def test_mapping_path_loses_the_record_escape(self):
        """A trailing \\n from the MI record must not land in file_path."""
        bridge = _read_bridge(
            r'~"    0x400000  0x452000  0x52000  0x0  /usr/bin/app\n"' "\n^done",
            remote="host:1234",
        )

        with patch(
            "memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[],
        ):
            ranges = bridge.enumerate_ranges()

        assert [r.file_path for r in ranges] == ["/usr/bin/app"]

    def test_module_path_loses_the_record_escape(self):
        """The same applies to shared-library paths."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes  /lib/libc.so.6\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/lib/libc.so.6"]
        assert [m.name for m in modules] == ["libc.so.6"]

    def test_reply_without_stream_records_is_passed_through(self):
        """Plain text carries no records to unescape and must survive intact."""
        bridge = _read_bridge("0x1000  0x2000  0x1000  0x0  /usr/bin/app")

        with patch(
            "memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[],
        ):
            ranges = bridge.enumerate_ranges()

        assert [r.file_path for r in ranges] == ["/usr/bin/app"]

    def test_escaped_quotes_are_decoded(self):
        """GDB escapes the quotes the architecture line is built around, so
        without unescaping the architecture cannot be read at all."""
        reply = (
            r'~"The target architecture is set to \"auto\" '
            r'(currently \"i386:x86-64\").\n"'
        )
        bridge = _read_bridge(reply)

        assert bridge.get_platform_info().arch == ArchType.x86_64

        with pytest.raises(ValueError):
            _parse_gdb_architecture(reply)


class TestGDBBridgeErrorRecordUnescaping:
    """``^error`` text is unescaped like console output is."""

    def test_mi_error_detail_is_unescaped(self):
        """MIError.detail reaches ReadResult.error, so it must be readable."""
        bridge = _queued_bridge(
            r'^error,msg="Cannot access memory at address 0x1000\nTry again."'
        )

        with pytest.raises(MIError) as excinfo:
            bridge._send_mi_command("-data-read-memory-bytes 0x1000 4096")

        assert excinfo.value.detail == (
            "Cannot access memory at address 0x1000\nTry again."
        )

    def test_read_error_text_carries_no_escapes(self):
        """The unescaped text is what the acquisition report shows."""
        bridge = _read_bridge(MIError("Cannot access memory\nat address 0x1800"))

        res = bridge.read_memory_ex(0x1000, 4096)

        assert "\\n" not in res.error
        assert res.fault_addr == 0x1800


class TestGDBBridgeReplyLogging:
    """Read replies are not written to the companion log in full."""

    def test_long_reply_line_is_truncated_in_the_log(self):
        """A 1 MiB read yields 2 MiB of hex; logging it whole would make the
        log larger than the dump it documents."""
        logger = MagicMock()
        logger.isEnabledFor.return_value = True
        bridge = GDBBridge(target=1234, logger=logger, mi_timeout=5.0)
        bridge._proc = MagicMock()
        bridge._line_queue = queue.Queue()
        huge = '^done,memory=[{begin="0x1000",contents="' + "ab" * 100_000 + '"}]'
        bridge._line_queue.put(huge)

        bridge._send_mi_command("-data-read-memory-bytes 0x1000 100000")

        logged = [
            call.args[1] for call in logger.debug.call_args_list
            if call.args and call.args[0] == "MI <<< %s"
        ]
        assert len(logged) == 1
        assert len(logged[0]) < 300
        assert str(len(huge)) in logged[0]


class TestGDBBridgeProcMappingsFallback:
    """The GDB-side mapping list is the only source for a remote target."""

    _MODERN = (
        r'~"          Start Addr           End Addr       Size     Offset  Perms  objfile\n"'
        "\n"
        r'~"      0x555555554000     0x555555555000     0x1000        0x0  r--p   /usr/bin/cat\n"'
        "\n"
        r'~"      0x555555555000     0x555555559000     0x4000     0x1000  r-xp   /usr/bin/cat\n"'
        "\n"
        r'~"      0x7ffff7ff9000     0x7ffff7ffd000     0x4000        0x0  r--p   [vvar]\n"'
        "\n^done"
    )
    _LEGACY = (
        r'~"      0x400000           0x452000           0x52000        0x0 /usr/bin/app\n"'
        "\n^done"
    )

    def test_perms_column_is_parsed(self):
        """Without real permissions every region is skipped as unreadable, so a
        remote capture would silently contain nothing."""
        bridge = _read_bridge(self._MODERN, remote="host:1234")

        with patch("memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[]):
            ranges = bridge.enumerate_ranges()

        assert [r.protection for r in ranges] == ["r--", "r-x", "r--"]

    def test_perms_column_is_not_glued_onto_the_path(self):
        """file_path drives region classification and kernel-pseudo detection."""
        bridge = _read_bridge(self._MODERN, remote="host:1234")

        with patch("memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[]):
            ranges = bridge.enumerate_ranges()

        assert [r.file_path for r in ranges] == [
            "/usr/bin/cat", "/usr/bin/cat", "[vvar]",
        ]

    def test_regions_survive_the_default_filter(self):
        """The end-to-end symptom: a remote capture must not come back empty."""
        bridge = _read_bridge(self._MODERN, remote="host:1234")

        with patch("memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[]):
            ranges = bridge.enumerate_ranges()

        kept = [
            r for r in ranges
            if RegionFilter().skip_reason(
                r.base, r.size, parse_protection(r.protection), r.file_path,
            ) is None
        ]
        assert len(kept) == 3

    def test_older_gdb_without_perms_still_parses(self):
        """Pre-8.1 GDB prints no Perms column; the path must still be clean."""
        bridge = _read_bridge(self._LEGACY, remote="host:1234")

        with patch("memslicer.acquirer.gdb_bridge.parse_proc_maps", return_value=[]):
            ranges = bridge.enumerate_ranges()

        assert len(ranges) == 1
        assert ranges[0].file_path == "/usr/bin/app"
        assert ranges[0].protection == "---"


class TestGDBBridgeSharedLibraryParsing:
    """Symbol-status markers are not part of the library path."""

    def test_partial_symbols_marker_is_not_the_path(self):
        """GDB writes "Yes (*)" for a library whose symbols are partly read."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes (*)     /lib/libc.so.6\n"'
            "\n"
            r'~"0x00007ffff7dd0000  0x00007ffff7df6000  Yes         /lib64/ld.so\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/lib/libc.so.6", "/lib64/ld.so"]
        assert [m.name for m in modules] == ["libc.so.6", "ld.so"]


class TestGDBBridgeDeadTransport:
    """Reads never raise, however the transport failed."""

    @pytest.mark.parametrize("failure", [
        BrokenPipeError(32, "Broken pipe"),
        ValueError("I/O operation on closed file"),
    ], ids=["broken-pipe", "closed-pipe"])
    def test_writing_to_a_dead_gdb_does_not_escape(self, failure):
        """A GDB that exited mid-capture must degrade to failed pages, not
        abort the run with a traceback."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        proc = MagicMock()
        proc.stdin.write.side_effect = failure
        bridge._proc = proc

        res = bridge.read_memory_ex(0x1000, 4096)

        assert res.data is None
        assert res.fault_addr is None
        assert res.error
        assert bridge.read_memory(0x1000, 4096) is None


class TestGDBBridgeOctalEscapes:
    """MI escapes every non-ASCII byte, including those in file names."""

    def test_utf8_path_survives_unescaping(self):
        r"""GDB emits UTF-8 as per-byte octal (\303\251 for e-acute)."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes  /opt/caf\303\251/lib.so\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/opt/café/lib.so"]

    def test_control_byte_escape_is_decoded(self):
        """A bare octal escape must not leak its digits into the text."""
        assert _unescape_mi(r"a\007b") == "a\x07b"
        assert _unescape_mi(r"tab\there") == "tab\there"
        assert _unescape_mi(r"back\\slash") == "back\\slash"


# ---------------------------------------------------------------------------
# Tests -- remote OS detection
# ---------------------------------------------------------------------------

_ARCH_LINE = 'The target architecture is set to "i386:x86-64".\n'
_AUXV_4K = (
    "0   AT_NULL              End of auxv                    0x0\n"
    "6   AT_PAGESZ            System page size               4096\n"
)


class TestGDBBridgeRemoteOSDetection:
    """A remote capture must record the target's OS, not this laptop's.

    The OS lands in the file header and decides how a reader interprets every
    structure in the dump, and nothing in the finished file says which machine
    the answer came from.
    """

    def test_darwin_osabi_wins_over_the_host(self):
        """Dumping a macOS target from a Linux box must record macOS."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "Darwin").\n',
            _AUXV_4K,
            remote="host:1234",
        )
        bridge._target_pid = MagicMock(return_value=777)

        with patch("platform.system") as mock_system:
            info = bridge.get_platform_info()

        assert info.os == OSType.macOS
        assert info.pid == 777
        mock_system.assert_not_called()

    def test_windows_osabi_wins_over_the_host(self):
        """The same holds for a Windows target reached over gdbserver."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "Windows").\n',
            _AUXV_4K,
            remote="host:1234",
        )
        bridge._target_pid = MagicMock(return_value=777)

        with patch("platform.system") as mock_system:
            info = bridge.get_platform_info()

        assert info.os == OSType.Windows
        mock_system.assert_not_called()

    def test_unpinned_osabi_falls_back_to_the_host_with_a_warning(self):
        """GDB routinely answers "none"; the guess that follows must be flagged.

        The host's OS is the wrong machine's answer for a remote target, so the
        one case where it is used is the one case that has to be visible in the
        log.
        """
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "none").\n',
            _AUXV_4K,
            remote="host:1234",
        )
        bridge._target_pid = MagicMock(return_value=777)

        with patch("platform.system", return_value="Darwin"):
            info = bridge.get_platform_info()

        assert info.os == OSType.macOS
        assert bridge._log.warning.called
        assert any(
            "did not report the target OS" in call.args[0]
            for call in bridge._log.warning.call_args_list
        )

    def test_remote_android_is_not_recorded_as_plain_linux(self):
        """"show osabi" says GNU/Linux for Android too, and a remote target has
        no local maps file to tell them apart."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "GNU/Linux").\n',
            "      0x7000000000  0x7000001000  0x1000  0x0  r--p  "
            "/system/lib64/libart.so\n",
            _AUXV_4K,
            remote="host:1234",
        )
        bridge._target_pid = MagicMock(return_value=777)

        info = bridge.get_platform_info()

        assert info.os == OSType.Android
        assert bridge._send_console_command.call_args_list[2].args[0] == (
            "info proc mappings"
        )

    def test_remote_linux_without_android_markers_stays_linux(self):
        """An ordinary remote Linux target must not be mislabelled Android."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "GNU/Linux").\n',
            "      0x400000  0x452000  0x52000  0x0  r-xp  /usr/bin/app\n",
            _AUXV_4K,
            remote="host:1234",
        )
        bridge._target_pid = MagicMock(return_value=777)

        info = bridge.get_platform_info()

        assert info.os == OSType.Linux


# ---------------------------------------------------------------------------
# Tests -- page size detection
# ---------------------------------------------------------------------------

class TestGDBBridgePageSizeDetection:
    """The page size describes the target, and is unrecoverable once written.

    Only PageSizeLog2 is stored and the page-state map is sized to match, so a
    host-derived 4K on a 16K or 64K target yields a self-consistent capture
    that no reader can tell is wrong.
    """

    def test_remote_page_size_comes_from_auxv(self):
        """A 64K-page target reached from a 4K host must record 65536."""
        bridge = _console_bridge(
            "0   AT_NULL              End of auxv                    0x0\n"
            "6   AT_PAGESZ            System page size               65536\n",
            remote="host:1234",
        )

        with patch("os.sysconf") as mock_sysconf:
            assert bridge._detect_page_size() == (65536, False)

        mock_sysconf.assert_not_called()
        bridge._send_console_command.assert_called_once_with("info auxv")

    def test_unreadable_remote_auxv_warns_about_the_assumption(self):
        """A target that will not serve auxv leaves an assumption in the file.

        The value has to be flagged as assumed, not just logged: the capture is
        self-consistent either way, so a reader cannot otherwise tell.
        """
        bridge = _console_bridge(
            "warning: Remote target does not support qXfer:auxv:read\n",
            remote="host:1234",
        )

        with patch("os.sysconf"):
            assert bridge._detect_page_size() == (4096, True)

        assert bridge._log.warning.called
        assert any(
            "page size" in call.args[0]
            for call in bridge._log.warning.call_args_list
        )

    def test_local_page_size_comes_from_sysconf_without_a_warning(self):
        """A local capture asks the right machine, so nothing is assumed."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_console_command = MagicMock()

        with patch("os.sysconf", return_value=16384) as mock_sysconf:
            assert bridge._detect_page_size() == (16384, False)

        mock_sysconf.assert_called_once_with("SC_PAGE_SIZE")
        bridge._send_console_command.assert_not_called()
        bridge._log.warning.assert_not_called()


# ---------------------------------------------------------------------------
# Tests -- shared-library paths containing spaces
# ---------------------------------------------------------------------------

class TestGDBBridgeSpacedModulePaths:
    """A space in a library path must not truncate the module record.

    A truncated path keeps a base and size that still look valid, so the
    module list names a file that does not exist and nothing reports an error.
    """

    def test_spaced_path_survives_intact(self):
        """"/usr/lib/My App/libfoo.so" must not be cut at the first space."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes  '
            r'/usr/lib/My App/libfoo.so\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/usr/lib/My App/libfoo.so"]
        assert [m.name for m in modules] == ["libfoo.so"]
        assert isinstance(modules[0], ModuleInfo)
        assert modules[0].base == 0x00007FFFF7C00000
        assert modules[0].size == 0x00007FFFF7D8B000 - 0x00007FFFF7C00000

    def test_unspaced_path_is_unaffected(self):
        """The ordinary case must keep working alongside the spaced one."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes  /lib/libc.so.6\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/lib/libc.so.6"]
        assert [m.name for m in modules] == ["libc.so.6"]

    def test_partial_symbols_marker_precedes_a_spaced_path(self):
        """"Yes (*)" is still a marker, not the start of the path."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes (*)  '
            r'/Applications/My App.app/Contents/libbar.dylib\n"'
            "\n"
            r'~"0x00007ffff7dd0000  0x00007ffff7df6000  Yes      /lib64/ld.so\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == [
            "/Applications/My App.app/Contents/libbar.dylib",
            "/lib64/ld.so",
        ]
        assert [m.name for m in modules] == ["libbar.dylib", "ld.so"]


# ---------------------------------------------------------------------------
# Tests -- console command quoting
# ---------------------------------------------------------------------------

class TestGDBBridgeConsoleCommandEscaping:
    """A quote in a console command must not end the MI string early.

    MI takes the wrapped command as a quoted string, so an unescaped quote
    would leave the remainder read as further arguments -- GDB then runs
    something other than what was asked, or refuses the command outright.
    """

    def test_quote_and_backslash_are_escaped(self):
        """The exact MI line GDB receives for a command carrying both."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock(return_value="^done")

        bridge._send_console_command(r'set x = "a\b"')

        bridge._send_mi_command.assert_called_once_with(
            r'-interpreter-exec console "set x = \"a\\b\""'
        )

    def test_backslash_is_escaped_before_the_quote(self):
        """Escaping the quote first would put a backslash through a second pass
        and double the one that was just introduced."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock(return_value="^done")

        bridge._send_console_command('say "hi"')

        sent = bridge._send_mi_command.call_args.args[0]
        assert sent == r'-interpreter-exec console "say \"hi\""'
        assert r"\\" not in sent

    def test_ordinary_command_is_passed_through_unchanged(self):
        """Commands without quoting stay readable in the log and on the wire."""
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_mi_command = MagicMock(
            return_value=r'~"    0x400000  0x452000  0x52000  0x0  /usr/bin/app\n"'
        )

        out = bridge._send_console_command("info proc mappings")

        bridge._send_mi_command.assert_called_once_with(
            '-interpreter-exec console "info proc mappings"'
        )
        assert out == "    0x400000  0x452000  0x52000  0x0  /usr/bin/app\n"


# ---------------------------------------------------------------------------
# Tests -- disconnect cleanup
# ---------------------------------------------------------------------------

class TestGDBBridgeDisconnect:
    """A finished capture must leave no pipe, thread, or stale line behind.

    A CLI run that dumps several processes in one process would otherwise
    accumulate a reader thread and an open pipe per target, and the sentinel
    the reader leaves behind would make the next connect()'s first command
    look like a GDB that had already exited.
    """

    @staticmethod
    def _disconnectable_bridge() -> GDBBridge:
        """A bridge whose detach is answered and whose queue holds a stale line."""
        bridge = _queued_bridge("^done", "=thread-group-exited,id=\"i1\"")
        bridge._reader_thread = MagicMock(spec=threading.Thread)
        bridge._reader_thread.is_alive.return_value = False
        return bridge

    def test_disconnect_releases_pipes_thread_and_queue(self):
        """Every resource the connection took is handed back."""
        bridge = self._disconnectable_bridge()
        proc = bridge._proc
        reader = bridge._reader_thread
        assert not bridge._line_queue.empty()

        bridge.disconnect()

        proc.stdin.close.assert_called_once()
        proc.stdout.close.assert_called_once()
        reader.join.assert_called_once()
        assert bridge._reader_thread is None
        assert bridge._line_queue.empty()
        assert bridge._proc is None
        assert bridge._shutting_down is False

    def test_second_disconnect_is_a_no_op(self):
        """A bridge disconnected twice must not fault on the missing process."""
        bridge = self._disconnectable_bridge()
        bridge.disconnect()

        bridge.disconnect()

        assert bridge._proc is None

    def test_a_gdb_that_ignores_terminate_is_killed_and_reaped(self):
        """kill() only sends the signal; without a second wait the child is
        left a zombie until memslicer itself exits."""
        bridge = self._disconnectable_bridge()
        proc = bridge._proc
        proc.wait.side_effect = [subprocess.TimeoutExpired("gdb", 5), None]

        bridge.disconnect()

        assert proc.kill.called
        assert proc.wait.call_count == 2
        assert [
            name for name, _args, _kwargs in proc.mock_calls
            if name in ("terminate", "kill", "wait")
        ] == ["terminate", "wait", "kill", "wait"]


class TestGDBBridgeDisconnectUnkillableGDB:
    """disconnect() must return even when the process refuses to die.

    It is called from the caller's finally block, so anything raised here
    replaces the acquisition error that sent us there with an unrelated one,
    and the bridge is left holding a process it can never release.
    """

    def test_terminate_and_kill_both_failing_does_not_raise(self):
        """A GDB this user may no longer signal must not abort the teardown."""
        bridge = _queued_bridge("^done")
        bridge._reader_thread = MagicMock(spec=threading.Thread)
        bridge._reader_thread.is_alive.return_value = False
        proc = bridge._proc
        proc.terminate.side_effect = OSError(1, "Operation not permitted")
        proc.kill.side_effect = PermissionError(1, "Operation not permitted")

        bridge.disconnect()

        assert proc.kill.called
        assert bridge._proc is None
        assert bridge._reader_thread is None
        assert bridge._shutting_down is False

    def test_a_gdb_that_cannot_be_killed_is_reported(self):
        """The log is the only place a leaked GDB process can be noticed."""
        bridge = _queued_bridge("^done")
        bridge._reader_thread = MagicMock(spec=threading.Thread)
        bridge._reader_thread.is_alive.return_value = False
        bridge._proc.terminate.side_effect = OSError(1, "Operation not permitted")
        bridge._proc.kill.side_effect = PermissionError(1, "Operation not permitted")

        bridge.disconnect()

        assert any(
            "kill" in call.args[0]
            for call in bridge._log.warning.call_args_list
        )


class _BlockingStdout:
    """A GDB stdout pipe that yields nothing until it is released.

    Stands in for the real pipe in the window disconnect() has to survive:
    the reader thread is still blocked on a read when the join times out.
    """

    def __init__(self) -> None:
        self.reading = threading.Event()
        self.release = threading.Event()

    def __iter__(self):
        # Set only once _stdout_reader has bound its queue and reached the
        # read, so the test never races the thread's start-up.
        self.reading.set()
        assert self.release.wait(timeout=5.0), "reader thread was never released"
        return iter(())

    def close(self) -> None:
        """Closing does not release the reader.

        disconnect() closes the pipes before it joins, and the whole point of
        the test is the case where that is not enough to stop the thread in
        time.
        """


class TestGDBBridgeDisconnectReaderQueue:
    """A reader thread that outlives disconnect() must not poison the bridge.

    ``disconnect()`` swaps in a fresh queue precisely so the reader's
    end-of-stream sentinel is discarded. A reader that re-reads the attribute
    puts that sentinel into the *new* queue instead, and the next connect()
    reads it on its first command as a GDB that had already exited -- so the
    reconnect fails with "GDB process exited unexpectedly" against a GDB that
    is running perfectly well.
    """

    def test_late_sentinel_lands_in_the_old_queue(self):
        """A reader released after the join timed out leaves the queue empty."""
        bridge = _queued_bridge("^done")
        # Small enough that the join gives up while the reader is still blocked.
        bridge._READER_JOIN_TIMEOUT = 0.01
        stdout = _BlockingStdout()
        bridge._proc.stdout = stdout
        old_queue = bridge._line_queue

        reader = threading.Thread(target=bridge._stdout_reader, daemon=True)
        reader.start()
        try:
            assert stdout.reading.wait(timeout=5.0)
            bridge._reader_thread = reader

            bridge.disconnect()

            assert bridge._line_queue is not old_queue
        finally:
            # Always release, so a failed assertion cannot hang the suite.
            stdout.release.set()
            reader.join(timeout=5.0)

        assert not reader.is_alive()
        assert bridge._line_queue.empty()
        assert old_queue.get_nowait() is None

    def test_a_reader_that_outlives_the_join_is_reported(self):
        """A thread still running after disconnect() has to be visible."""
        bridge = _queued_bridge("^done")
        bridge._READER_JOIN_TIMEOUT = 0.01
        stdout = _BlockingStdout()
        bridge._proc.stdout = stdout

        reader = threading.Thread(target=bridge._stdout_reader, daemon=True)
        reader.start()
        try:
            assert stdout.reading.wait(timeout=5.0)
            bridge._reader_thread = reader

            bridge.disconnect()

            assert any(
                "reader did not stop" in call.args[0]
                for call in bridge._log.warning.call_args_list
            )
        finally:
            stdout.release.set()
            reader.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Tests -- local /proc/<pid>/maps OS detection
# ---------------------------------------------------------------------------

_ANDROID_MAPS = (
    "7f0000000000-7f0000001000 r--p 00000000 fd:00 1234 "
    "/system/lib64/libart.so\n"
    "7f0000001000-7f0000002000 rw-p 00000000 00:00 0    [anon:dalvik-main]\n"
)
_LINUX_MAPS = (
    "00400000-00452000 r-xp 00000000 08:01 12345 /usr/bin/app\n"
    "7ffff7c00000-7ffff7d8b000 r--p 00000000 08:01 99999 /usr/lib/libc.so.6\n"
)


class TestGDBBridgeLocalMapsOSDetection:
    """A local maps file is the only source that tells Android from Linux.

    ``show osabi`` answers "GNU/Linux" for both, and the OS recorded in the
    header decides how a reader interprets every structure in the dump.
    """

    def test_android_markers_in_the_maps_file_win(self):
        """A local Android target must not be recorded as plain Linux."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "GNU/Linux").\n',
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=_ANDROID_MAPS)), \
             patch("os.sysconf", return_value=4096):
            info = bridge.get_platform_info()

        assert info.os == OSType.Android

    def test_plain_linux_maps_file_stays_linux(self):
        """An ordinary local Linux target must not be mislabelled Android."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "GNU/Linux").\n',
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=_LINUX_MAPS)), \
             patch("os.sysconf", return_value=4096):
            info = bridge.get_platform_info()

        assert info.os == OSType.Linux

    def test_a_readable_maps_file_settles_it_without_asking_gdb(self):
        """"show osabi" cannot improve on the maps file, so it is not issued."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "GNU/Linux").\n',
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", mock_open(read_data=_ANDROID_MAPS)), \
             patch("os.sysconf", return_value=4096):
            bridge.get_platform_info()

        assert [
            call.args[0] for call in bridge._send_console_command.call_args_list
        ] == ["show architecture"]


class TestGDBBridgeUnreadableLocalMaps:
    """An unreadable local maps file must not abort the capture.

    ``os.path.isfile("/proc/<pid>/maps")`` is true for every live PID,
    including ones this user cannot read, so the check says nothing about
    whether the read will work. There are two more OS sources below it.
    """

    @pytest.mark.parametrize("failure", [
        PermissionError(13, "Permission denied"),
        FileNotFoundError(2, "No such file or directory"),
    ], ids=["unreadable", "process-exited"])
    def test_maps_read_failure_falls_through_to_osabi(self, failure):
        """A maps file that will not open must not raise out of the probe."""
        bridge = _console_bridge(
            _ARCH_LINE,
            'The current OS ABI is "auto" (currently "Darwin").\n',
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", side_effect=failure), \
             patch("os.sysconf", return_value=4096):
            info = bridge.get_platform_info()

        assert info.os == OSType.macOS
        assert bridge._send_console_command.call_args_list[1].args[0] == (
            "show osabi"
        )


# ---------------------------------------------------------------------------
# Tests -- implausible local page size
# ---------------------------------------------------------------------------

class TestGDBBridgeLocalPageSizeSanity:
    """A page size the writer would reject must never leave the probe.

    ``sysconf`` answers -1 for "indeterminate" rather than raising, and -1
    would only be caught by the MSL writer once the whole capture had run.
    """

    @pytest.mark.parametrize("answer", [0, -1, 3000, 1 << 41], ids=[
        "zero", "indeterminate", "not-a-power-of-two", "too-large",
    ])
    def test_every_implausible_answer_is_replaced(self, answer):
        """Anything the writer would refuse falls back to the default.

        Not flagged as assumed: a local target is this machine, so 4096 is the
        right answer for it even when sysconf declined to say so.
        """
        bridge = GDBBridge(target=1234, logger=MagicMock())
        bridge._send_console_command = MagicMock()

        with patch("os.sysconf", return_value=answer):
            assert bridge._detect_page_size() == (4096, False)

        bridge._send_console_command.assert_not_called()


# ---------------------------------------------------------------------------
# Tests -- shared-library rows carrying no path
# ---------------------------------------------------------------------------

class TestGDBBridgePathlessSharedLibraryRow:
    """A row with no path must not adopt the text of the following line.

    The captured line arrives with the previous row's base and size, so the
    module list names something that was never mapped and nothing reports an
    error.
    """

    def test_a_pathless_row_does_not_swallow_the_next_row(self):
        """The next library's own line must not become the pathless row's path."""
        bridge = _read_bridge(
            r'~"0x0000000000000001  0x0000000000000002  Yes\n"'
            "\n"
            r'~"0x0000000000000003  0x0000000000000004  Yes  /lib/b.so\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/lib/b.so"]
        assert [m.base for m in modules] == [0x3]
        assert [m.size for m in modules] == [0x1]

    def test_the_missing_symbols_footnote_is_not_a_path(self):
        """GDB's own "(*): ..." footnote must not be recorded as a library."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes (*)\n"'
            "\n"
            r'~"(*): Shared library is missing debugging information.\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert not any(
            "missing debugging information" in m.path for m in modules
        )
        assert not any("Shared library" in m.name for m in modules)

    def test_the_footnote_after_a_normal_row_is_ignored(self):
        """The real listing ends with that footnote, and it names no library."""
        bridge = _read_bridge(
            r'~"0x00007ffff7c00000  0x00007ffff7d8b000  Yes (*)     '
            r'/lib/x86_64-linux-gnu/libc.so.6\n"'
            "\n"
            r'~"(*): Shared library is missing debugging information.\n"'
            "\n^done"
        )

        modules = bridge.enumerate_modules()

        assert [m.path for m in modules] == ["/lib/x86_64-linux-gnu/libc.so.6"]


# ---------------------------------------------------------------------------
# Tests -- empty --remote string
# ---------------------------------------------------------------------------

class TestGDBBridgeEmptyRemoteTarget:
    """An empty --remote is not a remote target.

    connect() selects the remote target under "if self._remote", so an empty
    string attaches locally while every probe takes the remote path -- the
    capture then records a PID, an OS, and a page size for a target GDB is
    not connected to.
    """

    def test_empty_remote_string_is_not_remote(self):
        """GDBBridge(remote="") attaches locally, so it must report local."""
        bridge = GDBBridge(target=1234, remote="", logger=MagicMock())

        assert bridge.is_remote is False

    def test_an_empty_remote_keeps_the_local_probes(self):
        """The PID probe must not ask GDB about an inferior it never selected."""
        bridge = GDBBridge(target=1234, remote="", logger=MagicMock())
        bridge._send_mi_command = MagicMock()

        assert bridge._target_pid() == 1234
        bridge._send_mi_command.assert_not_called()

    def test_a_real_remote_string_is_still_remote(self):
        """The ordinary case must keep working alongside the empty one."""
        assert GDBBridge(
            target=1234, remote="host:1234", logger=MagicMock(),
        ).is_remote is True
