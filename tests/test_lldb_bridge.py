"""Tests for the LLDBBridge debugger bridge."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from memslicer.acquirer.bridge import PlatformInfo
from memslicer.acquirer.platform_detect import parse_lldb_triple
from memslicer.msl.constants import ArchType, OSType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_lldb():
    """Build a mock ``lldb`` module with the types LLDBBridge expects."""
    mock_lldb = MagicMock()

    # SBDebugger
    mock_debugger = MagicMock()
    mock_lldb.SBDebugger.Create.return_value = mock_debugger

    # SBTarget
    mock_target = MagicMock()
    mock_target.IsValid.return_value = True
    mock_target.GetTriple.return_value = "x86_64-apple-macosx15.0.0"
    mock_debugger.CreateTarget.return_value = mock_target

    # SBError
    mock_error = MagicMock()
    mock_error.Success.return_value = True
    mock_lldb.SBError.return_value = mock_error

    # SBListener
    mock_lldb.SBListener.return_value = MagicMock()

    # SBProcess
    mock_process = MagicMock()
    mock_process.GetProcessID.return_value = 9999
    mock_target.AttachToProcessWithID.return_value = mock_process
    mock_target.AttachToProcessWithName.return_value = mock_process

    return mock_lldb, mock_debugger, mock_target, mock_process


def _skipped_preflight():
    """Build a real, skipped-and-ok PreflightResult for a mocked attach.

    A genuine :class:`PreflightResult` rather than a MagicMock, so
    ``probable_cause()`` still returns a plain string when ``connect()``
    consults it.
    """
    from memslicer.acquirer.attach_preflight import (
        AttachEnvironment, PreflightResult,
    )

    return PreflightResult(env=AttachEnvironment(skip_reason="not-linux"))


@pytest.fixture(autouse=True)
def _neutralise_attach_preflight():
    """Keep the shared attach preflight out of every mocked connect().

    The tests attach to PID 1234, which does not exist. On macOS the cheap
    gate in ``attach_preflight`` short-circuits on ``not-linux``, but on a
    Linux runner the real preflight would inspect ``/proc/1234`` and refuse.
    Individual tests may still patch the same name to assert on refusals.
    """
    with patch(
        "memslicer.acquirer.lldb_bridge.enforce_attach_preflight",
        return_value=_skipped_preflight(),
    ):
        yield


def _create_and_connect(target=1234):
    """Create an LLDBBridge instance, mock lldb, and call connect().

    Returns (bridge, mock_lldb, mock_debugger, mock_target, mock_process).
    """
    mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

    # The preflight is already neutralised module-wide by the autouse fixture.
    with patch.dict(sys.modules, {"lldb": mock_lldb}):
        from memslicer.acquirer.lldb_bridge import LLDBBridge

        bridge = LLDBBridge(target=target, logger=MagicMock())
        bridge.connect()

    return bridge, mock_lldb, mock_debugger, mock_target, mock_process


# ---------------------------------------------------------------------------
# Tests -- connect
# ---------------------------------------------------------------------------

class TestLLDBBridgeConnect:
    """Tests for LLDBBridge.connect()."""

    def test_connect_by_pid(self):
        """When target is an int, AttachToProcessWithID is called."""
        bridge, mock_lldb, _dbg, mock_target, _proc = _create_and_connect(
            target=1234,
        )

        mock_target.AttachToProcessWithID.assert_called_once()
        args = mock_target.AttachToProcessWithID.call_args
        # Second positional arg is the PID
        assert args[0][1] == 1234

    def test_connect_by_name(self):
        """When target is a string, AttachToProcessWithName is called."""
        bridge, mock_lldb, _dbg, mock_target, _proc = _create_and_connect(
            target="my_app",
        )

        mock_target.AttachToProcessWithName.assert_called_once()
        args = mock_target.AttachToProcessWithName.call_args
        # Second positional arg is the process name
        assert args[0][1] == "my_app"


# ---------------------------------------------------------------------------
# Tests -- read_memory
# ---------------------------------------------------------------------------

class TestLLDBBridgeReadMemory:
    """Tests for LLDBBridge.read_memory()."""

    def test_read_memory_success(self):
        """Successful ReadMemory returns the data as bytes."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        expected = b"\xca\xfe\xba\xbe"
        mock_error = MagicMock()
        mock_error.Success.return_value = True
        mock_lldb.SBError.return_value = mock_error
        mock_process.ReadMemory.return_value = expected

        result = bridge.read_memory(0x10000, 4)

        mock_process.ReadMemory.assert_called_once_with(0x10000, 4, mock_error)
        assert result == expected

    def test_read_memory_failure(self):
        """When ReadMemory reports an error, None is returned."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        mock_error = MagicMock()
        mock_error.Success.return_value = False
        mock_error.GetCString.return_value = "bad access"
        mock_lldb.SBError.return_value = mock_error
        mock_process.ReadMemory.return_value = None

        result = bridge.read_memory(0xDEAD, 8)

        assert result is None


# ---------------------------------------------------------------------------
# Tests -- disconnect
# ---------------------------------------------------------------------------

class TestLLDBBridgeDisconnect:
    """Tests for LLDBBridge.disconnect()."""

    def test_disconnect(self):
        """Disconnect calls process.Detach() and SBDebugger.Destroy()."""
        bridge, mock_lldb, mock_debugger, _tgt, mock_process = (
            _create_and_connect()
        )

        bridge.disconnect()

        mock_process.Detach.assert_called_once()
        mock_lldb.SBDebugger.Destroy.assert_called_once_with(mock_debugger)
        assert bridge._process is None
        assert bridge._debugger is None


# ---------------------------------------------------------------------------
# Tests -- parse_lldb_triple (from platform_detect)
# ---------------------------------------------------------------------------

class TestParseLldbTriple:
    """Tests for the parse_lldb_triple helper."""

    def test_parse_lldb_triple_macos(self):
        """macOS triple is correctly parsed."""
        os_type, arch = parse_lldb_triple("x86_64-apple-macosx")

        assert os_type == OSType.macOS
        assert arch == ArchType.x86_64

    def test_parse_lldb_triple_linux(self):
        """Linux triple with 'unknown' vendor is correctly parsed."""
        os_type, arch = parse_lldb_triple("aarch64-unknown-linux-gnu")

        assert os_type == OSType.Linux
        assert arch == ArchType.ARM64

    def test_parse_lldb_triple_ios(self):
        """iOS triple (arm64-apple-ios) is correctly parsed."""
        os_type, arch = parse_lldb_triple("arm64-apple-ios17.0.0")

        assert os_type == OSType.iOS
        assert arch == ArchType.ARM64

    def test_parse_lldb_triple_unknown_raises(self):
        """A completely unknown triple raises ValueError."""
        with pytest.raises(ValueError, match="Unknown"):
            parse_lldb_triple("unknown-unknown-unknown")


# ---------------------------------------------------------------------------
# Tests -- enumerate_ranges Linux fallback
# ---------------------------------------------------------------------------

class TestLLDBBridgeEnumerateRangesLinux:
    """Tests for /proc/maps fallback in enumerate_ranges()."""

    def test_fallback_to_proc_maps_when_lldb_empty(self):
        """When LLDB returns no regions, fall back to /proc/maps on Linux."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        # Make GetMemoryRegionInfo fail immediately (no LLDB regions).
        fail_err = MagicMock()
        fail_err.Fail.return_value = True
        mock_process.GetMemoryRegionInfo.return_value = fail_err

        # Set platform to Linux so the fallback is attempted.
        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.Linux, pid=9999, page_size=4096,
        )
        bridge._remote = None

        sample_maps = (
            "00400000-00401000 r-xp 00000000 08:01 1234 /bin/test\n"
            "7f000000-7f001000 rw-p 00000000 00:00 0 [heap]\n"
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(
                 return_value=MagicMock(
                     __enter__=lambda s: s,
                     __exit__=MagicMock(return_value=False),
                     __iter__=lambda s: iter(sample_maps.splitlines(True)),
                     read=lambda: sample_maps,
                 ),
             )):
            ranges = bridge.enumerate_ranges()

        assert len(ranges) == 2
        assert ranges[0].base == 0x00400000
        assert ranges[0].size == 0x1000
        assert ranges[0].protection == "r-x"
        assert ranges[0].file_path == "/bin/test"
        assert ranges[1].base == 0x7F000000
        assert ranges[1].protection == "rw-"

    def test_no_fallback_when_lldb_has_enough_ranges(self):
        """When LLDB returns >= 5 regions, /proc/maps is not read."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.Linux, pid=9999, page_size=4096,
        )
        bridge._remote = None

        # Configure mock to return 6 valid regions then fail.
        mock_region = MagicMock()
        mock_region.IsMapped.return_value = True
        mock_region.IsReadable.return_value = True
        mock_region.IsWritable.return_value = False
        mock_region.IsExecutable.return_value = False
        mock_region.GetName.return_value = "/lib/test.so"
        mock_lldb.SBMemoryRegionInfo.return_value = mock_region

        success_err = MagicMock()
        success_err.Fail.return_value = False
        fail_err = MagicMock()
        fail_err.Fail.return_value = True

        # 6 regions: base 0x1000, 0x2000, ..., 0x6000, then end increases each time
        bases = [0x1000 * (i + 1) for i in range(6)]
        ends = [b + 0x1000 for b in bases]

        call_count = [0]
        def mock_get_region_info(addr, region):
            if call_count[0] < 6:
                region.GetRegionBase.return_value = bases[call_count[0]]
                region.GetRegionEnd.return_value = ends[call_count[0]]
                call_count[0] += 1
                return success_err
            return fail_err

        mock_process.GetMemoryRegionInfo.side_effect = mock_get_region_info

        with patch("builtins.open") as mock_open:
            ranges = bridge.enumerate_ranges()

        mock_open.assert_not_called()
        assert len(ranges) == 6

    def test_fallback_when_lldb_has_few_ranges(self):
        """When LLDB returns < 5 regions on Linux, /proc/maps cross-check is used."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.Linux, pid=9999, page_size=4096,
        )
        bridge._remote = None

        # LLDB returns 2 regions
        mock_region = MagicMock()
        mock_region.IsMapped.return_value = True
        mock_region.IsReadable.return_value = True
        mock_region.IsWritable.return_value = False
        mock_region.IsExecutable.return_value = False
        mock_region.GetName.return_value = ""
        mock_lldb.SBMemoryRegionInfo.return_value = mock_region

        success_err = MagicMock()
        success_err.Fail.return_value = False
        fail_err = MagicMock()
        fail_err.Fail.return_value = True

        call_count = [0]
        bases = [0x1000, 0x2000]
        ends = [0x2000, 0x3000]
        def mock_get_region_info(addr, region):
            if call_count[0] < 2:
                region.GetRegionBase.return_value = bases[call_count[0]]
                region.GetRegionEnd.return_value = ends[call_count[0]]
                call_count[0] += 1
                return success_err
            return fail_err

        mock_process.GetMemoryRegionInfo.side_effect = mock_get_region_info

        # /proc/maps returns more (10 ranges)
        sample_maps = "".join(
            f"{0x1000*i:08x}-{0x1000*(i+1):08x} r-xp 00000000 08:01 {i} /lib/lib{i}.so\n"
            for i in range(1, 11)
        )

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(
                 return_value=MagicMock(
                     __enter__=lambda s: s,
                     __exit__=MagicMock(return_value=False),
                     __iter__=lambda s: iter(sample_maps.splitlines(True)),
                     read=lambda: sample_maps,
                 ),
             )):
            ranges = bridge.enumerate_ranges()

        # Should use /proc/maps (10) since it has more than LLDB (2)
        assert len(ranges) == 10

    def test_no_fallback_for_non_linux(self):
        """When OS is macOS, no /proc/maps fallback is attempted."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        # Make GetMemoryRegionInfo fail immediately (no LLDB regions).
        fail_err = MagicMock()
        fail_err.Fail.return_value = True
        mock_process.GetMemoryRegionInfo.return_value = fail_err

        # Set platform to macOS.
        bridge._platform_info = PlatformInfo(
            arch=ArchType.ARM64, os=OSType.macOS, pid=9999, page_size=16384,
        )
        bridge._remote = None

        ranges = bridge.enumerate_ranges()

        assert ranges == []


# ---------------------------------------------------------------------------
# Tests -- remote connect
# ---------------------------------------------------------------------------

class TestLLDBBridgeRemoteConnect:
    """Tests for remote connection support."""

    def test_remote_creates_platform(self):
        """Remote connect creates an SBPlatform with remote-linux."""
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        mock_platform = MagicMock()
        mock_connect_error = MagicMock()
        mock_connect_error.Fail.return_value = False
        mock_platform.ConnectRemote.return_value = mock_connect_error
        mock_lldb.SBPlatform.return_value = mock_platform
        mock_lldb.SBPlatformConnectOptions.return_value = MagicMock()

        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(
                target=1234, remote="localhost:1234", logger=MagicMock(),
            )
            bridge.connect()

        mock_lldb.SBPlatform.assert_called_once_with("remote-linux")
        mock_platform.ConnectRemote.assert_called_once()

    def test_remote_ios_platform(self):
        """iOS remote URL creates an SBPlatform with remote-ios."""
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        mock_platform = MagicMock()
        mock_connect_error = MagicMock()
        mock_connect_error.Fail.return_value = False
        mock_platform.ConnectRemote.return_value = mock_connect_error
        mock_lldb.SBPlatform.return_value = mock_platform
        mock_lldb.SBPlatformConnectOptions.return_value = MagicMock()

        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(
                target=1234, remote="ios://192.168.1.1:1234",
                logger=MagicMock(),
            )
            bridge.connect()

        mock_lldb.SBPlatform.assert_called_once_with("remote-ios")

    def test_remote_android_platform(self):
        """Android remote URL creates an SBPlatform with remote-linux."""
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        mock_platform = MagicMock()
        mock_connect_error = MagicMock()
        mock_connect_error.Fail.return_value = False
        mock_platform.ConnectRemote.return_value = mock_connect_error
        mock_lldb.SBPlatform.return_value = mock_platform
        mock_lldb.SBPlatformConnectOptions.return_value = MagicMock()

        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(
                target=1234, remote="android://device:5039",
                logger=MagicMock(),
            )
            bridge.connect()

        mock_lldb.SBPlatform.assert_called_once_with("remote-linux")

    def test_remote_connect_failure_raises(self):
        """When ConnectRemote fails, RuntimeError is raised."""
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        mock_platform = MagicMock()
        mock_connect_error = MagicMock()
        mock_connect_error.Fail.return_value = True
        mock_connect_error.GetCString.return_value = "connection refused"
        mock_platform.ConnectRemote.return_value = mock_connect_error
        mock_lldb.SBPlatform.return_value = mock_platform
        mock_lldb.SBPlatformConnectOptions.return_value = MagicMock()

        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(
                target=1234, remote="localhost:1234", logger=MagicMock(),
            )
            with pytest.raises(RuntimeError, match="connection refused"):
                bridge.connect()


# ---------------------------------------------------------------------------
# Tests -- _parse_remote_url
# ---------------------------------------------------------------------------

class TestParseRemoteUrl:
    """Tests for the static _parse_remote_url method."""

    def test_plain_host_port(self):
        """Plain host:port returns remote-linux platform."""
        mock_lldb, *_ = _make_mock_lldb()
        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            platform, url = LLDBBridge._parse_remote_url("localhost:1234")

        assert platform == "remote-linux"
        assert url == "connect://localhost:1234"

    def test_ios_url(self):
        """iOS URL returns remote-ios platform."""
        mock_lldb, *_ = _make_mock_lldb()
        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            platform, url = LLDBBridge._parse_remote_url(
                "ios://192.168.1.1:5678",
            )

        assert platform == "remote-ios"
        assert url == "connect://192.168.1.1:5678"

    def test_android_url(self):
        """Android URL returns remote-linux platform."""
        mock_lldb, *_ = _make_mock_lldb()
        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            platform, url = LLDBBridge._parse_remote_url(
                "android://10.0.0.1:5039",
            )

        assert platform == "remote-linux"
        assert url == "connect://10.0.0.1:5039"


# ---------------------------------------------------------------------------
# Tests -- Linux refinement
# ---------------------------------------------------------------------------

class TestLLDBBridgeLinuxRefinement:
    """Tests for Linux-specific refinement during connect."""

    def test_page_size_from_sysconf(self):
        """Page size is read from os.sysconf on Linux."""
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        # Configure triple as Linux.
        mock_target.GetTriple.return_value = "x86_64-unknown-linux-gnu"

        with patch.dict(sys.modules, {"lldb": mock_lldb}), \
             patch("os.sysconf", return_value=65536) as mock_sysconf, \
             patch("os.path.isfile", return_value=False):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(target=1234, logger=MagicMock())
            bridge.connect()

        mock_sysconf.assert_called_with("SC_PAGE_SIZE")
        assert bridge._platform_info.page_size == 65536

    def test_android_detected_from_maps(self):
        """Android indicators in /proc/pid/maps are recognised by refinement.

        Note: ``_refine_linux_info`` currently detects Android internally but
        does not propagate the updated os_type back to the caller in
        ``connect()``.  This test validates that the detection logic itself
        works by invoking the helper directly.
        """
        mock_lldb, mock_debugger, mock_target, mock_process = _make_mock_lldb()

        # Configure triple as Linux.
        mock_target.GetTriple.return_value = "aarch64-unknown-linux-gnu"

        android_maps = (
            "70000000-70001000 r-xp 00000000 00:00 0 "
            "/system/lib/libandroid_runtime.so\n"
        )

        with patch.dict(sys.modules, {"lldb": mock_lldb}), \
             patch("os.sysconf", return_value=4096), \
             patch("os.path.isfile", return_value=True), \
             patch("builtins.open", MagicMock(
                 return_value=MagicMock(
                     __enter__=lambda s: s,
                     __exit__=MagicMock(return_value=False),
                     read=lambda *_args: android_maps,
                 ),
             )):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(target=1234, logger=MagicMock())
            bridge.connect()

        # Verify detect_os_from_maps correctly identifies Android content.
        from memslicer.acquirer.platform_detect import detect_os_from_maps

        assert detect_os_from_maps(android_maps) == OSType.Android


# ---------------------------------------------------------------------------
# Tests -- enumerate_modules size computation
# ---------------------------------------------------------------------------

class TestLLDBBridgeModuleSize:
    """Tests for module size computation in enumerate_modules()."""

    def test_module_size_from_address_span(self):
        """Size is computed from max_addr - min_addr when load addresses are valid."""
        bridge, mock_lldb, _dbg, mock_target, _proc = _create_and_connect()

        # Create a mock module with 2 sections at different load addresses
        mock_mod = MagicMock()
        mock_fspec = MagicMock()
        mock_fspec.GetFilename.return_value = "libtest.dylib"
        mock_fspec.__str__ = lambda self: "/usr/lib/libtest.dylib"
        mock_mod.GetFileSpec.return_value = mock_fspec

        mock_header_addr = MagicMock()
        mock_header_addr.IsValid.return_value = True
        mock_header_addr.GetLoadAddress.return_value = 0x1000
        mock_mod.GetObjectFileHeaderAddress.return_value = mock_header_addr

        # Two sections: 0x1000 (size 100) and 0x2000 (size 200)
        sec1 = MagicMock()
        sec1.GetByteSize.return_value = 100
        sec1.GetLoadAddress.return_value = 0x1000

        sec2 = MagicMock()
        sec2.GetByteSize.return_value = 200
        sec2.GetLoadAddress.return_value = 0x2000

        mock_mod.GetNumSections.return_value = 2
        mock_mod.GetSectionAtIndex.side_effect = [sec1, sec2]

        mock_target.GetNumModules.return_value = 1
        mock_target.GetModuleAtIndex.return_value = mock_mod

        modules = bridge.enumerate_modules()

        assert len(modules) == 1
        # Size = (0x2000 + 200) - 0x1000 = 4296, not 100 + 200 = 300
        assert modules[0].size == (0x2000 + 200) - 0x1000

    def test_module_size_falls_back_to_sum(self):
        """When load addresses are invalid, size is the sum of section byte sizes."""
        bridge, mock_lldb, _dbg, mock_target, _proc = _create_and_connect()

        mock_mod = MagicMock()
        mock_fspec = MagicMock()
        mock_fspec.GetFilename.return_value = "libfallback.dylib"
        mock_fspec.__str__ = lambda self: "/usr/lib/libfallback.dylib"
        mock_mod.GetFileSpec.return_value = mock_fspec

        mock_header_addr = MagicMock()
        mock_header_addr.IsValid.return_value = True
        mock_header_addr.GetLoadAddress.return_value = 0x5000
        mock_mod.GetObjectFileHeaderAddress.return_value = mock_header_addr

        # Two sections with invalid load addresses (0xFFFFFFFFFFFFFFFF)
        sec1 = MagicMock()
        sec1.GetByteSize.return_value = 100
        sec1.GetLoadAddress.return_value = 0xFFFFFFFFFFFFFFFF

        sec2 = MagicMock()
        sec2.GetByteSize.return_value = 200
        sec2.GetLoadAddress.return_value = 0xFFFFFFFFFFFFFFFF

        mock_mod.GetNumSections.return_value = 2
        mock_mod.GetSectionAtIndex.side_effect = [sec1, sec2]

        mock_target.GetNumModules.return_value = 1
        mock_target.GetModuleAtIndex.return_value = mock_mod

        modules = bridge.enumerate_modules()

        assert len(modules) == 1
        # Fallback: sum of byte sizes = 100 + 200 = 300
        assert modules[0].size == 300


# ---------------------------------------------------------------------------
# Tests -- region skip on failure
# ---------------------------------------------------------------------------

class TestLLDBBridgeRegionSkip:
    """Tests for region enumeration skip-on-failure behavior."""

    def test_skips_forward_on_failure(self):
        """GetMemoryRegionInfo failure skips forward instead of stopping."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.macOS, pid=9999, page_size=4096,
        )

        mock_region = MagicMock()
        mock_region.IsMapped.return_value = True
        mock_region.IsReadable.return_value = True
        mock_region.IsWritable.return_value = False
        mock_region.IsExecutable.return_value = True
        mock_region.GetName.return_value = ""
        mock_lldb.SBMemoryRegionInfo.return_value = mock_region

        success_err = MagicMock()
        success_err.Fail.return_value = False
        fail_err = MagicMock()
        fail_err.Fail.return_value = True
        fail_err.GetCString.return_value = "access denied"

        # Sequence: success at 0, fail, success at skip addr, then stop
        call_count = [0]
        def mock_get_region(addr, region):
            call_count[0] += 1
            if call_count[0] == 1:
                # First region: 0x0 - 0x1000
                region.GetRegionBase.return_value = 0x0
                region.GetRegionEnd.return_value = 0x1000
                return success_err
            elif call_count[0] == 2:
                # Fail at 0x1000
                return fail_err
            elif call_count[0] == 3:
                # Success after skip: 0x101000 - 0x102000
                region.GetRegionBase.return_value = 0x101000
                region.GetRegionEnd.return_value = 0x102000
                return success_err
            else:
                return fail_err

        # Set max consecutive skip to 1 so we stop quickly after the 3rd region
        bridge._MAX_CONSECUTIVE_SKIP = 1
        mock_process.GetMemoryRegionInfo.side_effect = mock_get_region

        ranges = bridge.enumerate_ranges()

        # Should have 2 regions (skipped the failure in between)
        assert len(ranges) == 2


# ---------------------------------------------------------------------------
# Tests -- SIP and ptrace pre-flight checks
# ---------------------------------------------------------------------------

class TestLLDBBridgePreflightChecks:
    """Tests for SIP and ptrace pre-flight checks."""

    def test_sip_warning_on_macos(self):
        """Warning logged when SIP is enabled on macOS."""
        bridge, *_ = _create_and_connect()
        bridge._log = MagicMock()

        with patch("platform.system", return_value="Darwin"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="System Integrity Protection status: enabled.")
            bridge._check_macos_sip()

        bridge._log.warning.assert_called_once()
        assert "SIP" in bridge._log.warning.call_args[0][0]

    def test_sip_silent_on_linux(self):
        """No SIP warning on Linux."""
        bridge, *_ = _create_and_connect()
        bridge._log = MagicMock()

        with patch("platform.system", return_value="Linux"):
            bridge._check_macos_sip()

        bridge._log.warning.assert_not_called()

    def test_ptrace_scope_warning(self):
        """Warning logged when ptrace_scope >= 2."""
        bridge, *_ = _create_and_connect()
        bridge._log = MagicMock()

        with patch("builtins.open", MagicMock(
            return_value=MagicMock(
                __enter__=lambda s: s,
                __exit__=MagicMock(return_value=False),
                read=lambda *a: "2\n",
            )
        )):
            bridge._check_ptrace_scope()

        bridge._log.warning.assert_called_once()


# ---------------------------------------------------------------------------
# Helpers -- read_memory_ex
# ---------------------------------------------------------------------------

def _set_read_outcome(mock_lldb, mock_process, *, success, data, detail=""):
    """Point the shared SBError and ReadMemory at one canned read outcome."""
    error = MagicMock()
    error.Success.return_value = success
    error.GetCString.return_value = detail
    mock_lldb.SBError.return_value = error
    mock_process.ReadMemory.return_value = data
    return error


def _set_region_query_failed(mock_process):
    """Make GetMemoryRegionInfo report that it could not answer."""
    err = MagicMock()
    err.Fail.return_value = True
    mock_process.GetMemoryRegionInfo.return_value = err


def _set_region(
    mock_lldb, mock_process, *, mapped=True, readable=True, base=0, end=0,
):
    """Make GetMemoryRegionInfo answer with a single canned region."""
    region = MagicMock()
    region.IsMapped.return_value = mapped
    region.IsReadable.return_value = readable
    region.GetRegionBase.return_value = base
    region.GetRegionEnd.return_value = end
    mock_lldb.SBMemoryRegionInfo.return_value = region

    err = MagicMock()
    err.Fail.return_value = False
    mock_process.GetMemoryRegionInfo.return_value = err
    return region


# ---------------------------------------------------------------------------
# Tests -- read_memory_ex: whole reads and short reads
# ---------------------------------------------------------------------------

class TestLLDBBridgeReadMemoryExLength:
    """Tests for the all-or-nothing length contract of read_memory_ex()."""

    def test_full_read_returns_the_span(self):
        """A complete read yields the bytes and reports no fault."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        expected = b"\xde\xad\xbe\xef" * 4
        _set_read_outcome(
            mock_lldb, mock_process, success=True, data=expected,
        )

        result = bridge.read_memory_ex(0x140000, 16)

        assert result.data == expected
        assert result.fault_addr is None
        assert result.error == ""
        assert bridge.read_memory(0x140000, 16) == expected

    def test_page_aligned_short_read_reports_no_boundary(self):
        """A page-aligned partial is not evidence of a map edge.

        LLDB accumulates reads in chunks of its maximum packet size, which is
        itself a multiple of the page size, so a transport truncation lands on
        a page boundary just as a real map edge does. Trusting it marks a page
        FAILED that the caller then never attempts -- measured at two readable
        pages lost per truncation.
        """
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.macOS, pid=9999, page_size=4096,
        )
        _set_region_query_failed(mock_process)
        _set_read_outcome(
            mock_lldb, mock_process, success=True, data=b"\x00" * 4096,
        )

        result = bridge.read_memory_ex(0x140000, 8192)

        assert result.data is None
        assert result.fault_addr is None
        assert result.error == "short read: 4096/8192 bytes"

    def test_unaligned_short_read_reports_no_boundary(self):
        """A partial that stops mid-page is a truncation, not a map edge."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        bridge._platform_info = PlatformInfo(
            arch=ArchType.x86_64, os=OSType.macOS, pid=9999, page_size=4096,
        )
        _set_region_query_failed(mock_process)
        _set_read_outcome(
            mock_lldb, mock_process, success=True, data=b"\x00" * 100,
        )

        result = bridge.read_memory_ex(0x140000, 8192)

        assert result.data is None
        assert result.fault_addr is None


# ---------------------------------------------------------------------------
# Tests -- read_memory_ex: region-info derived fault addresses
# ---------------------------------------------------------------------------

class TestLLDBBridgeReadMemoryExRegionInfo:
    """Tests for fault addresses derived from SBMemoryRegionInfo."""

    def test_unmapped_region_reports_no_boundary(self):
        """A wholly unreadable region leaves no readable prefix to salvage.

        Naming the span start as the fault makes the caller re-ask for the
        whole shrinking remainder once per page: 538 MB requested against 4 MB
        for the same zero bytes captured. Saying nothing reads it page by page.
        """
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(mock_lldb, mock_process, mapped=False, end=0x9000)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0x1000, 0x2000)

        assert result.data is None
        assert result.fault_addr is None

    def test_unreadable_region_reports_no_boundary(self):
        """A mapped but unreadable region is the same case as an unmapped one."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(
            mock_lldb, mock_process, mapped=True, readable=False, end=0x9000,
        )
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0x1000, 0x2000)

        assert result.fault_addr is None

    def test_region_ending_inside_the_span_reports_its_end(self):
        """A readable region that stops short of the span names the boundary."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(mock_lldb, mock_process, end=0x2000)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0x1000, 0x2000)

        assert result.fault_addr == 0x2000

    def test_region_covering_the_span_reports_no_boundary(self):
        """One readable region across the whole span offers no boundary."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(mock_lldb, mock_process, end=0x9000)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0x1000, 0x2000)

        assert result.fault_addr is None

    def test_region_query_exception_is_swallowed(self):
        """A GetMemoryRegionInfo that raises still yields a ReadResult."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        mock_process.GetMemoryRegionInfo.side_effect = RuntimeError(
            "process is not alive",
        )
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0x1000, 4096)

        assert result.data is None
        assert result.fault_addr is None


# ---------------------------------------------------------------------------
# Tests -- read_memory_ex: error-text fallback
# ---------------------------------------------------------------------------

class TestLLDBBridgeReadMemoryExErrorText:
    """Tests for the fault address scraped from LLDB error text."""

    def test_echoed_request_address_is_discarded(self):
        """Error text that merely echoes the requested address adds nothing."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region_query_failed(mock_process)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed for 0x1000",
        )

        result = bridge.read_memory_ex(0x1000, 4096)

        assert result.fault_addr is None
        assert result.error == "memory read failed for 0x1000"

    def test_interior_address_in_error_text_is_kept(self):
        """Error text naming an address inside the span is a real boundary."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region_query_failed(mock_process)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="unable to read memory at 0x1800",
        )

        result = bridge.read_memory_ex(0x1000, 4096)

        assert result.fault_addr == 0x1800
        assert result.error == "unable to read memory at 0x1800"

    def test_none_error_string_does_not_raise(self):
        """LLDB returning a null error string still yields usable error text."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region_query_failed(mock_process)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None, detail=None,
        )

        result = bridge.read_memory_ex(0x1000, 4096)

        assert result.data is None
        assert result.fault_addr is None
        assert result.error


# ---------------------------------------------------------------------------
# Tests -- calls made before connect()
# ---------------------------------------------------------------------------

class TestLLDBBridgeBeforeConnect:
    """Tests that an unconnected bridge fails plainly instead of by accident."""

    @staticmethod
    def _unconnected_bridge():
        """Build an LLDBBridge that has never been connected."""
        mock_lldb, *_ = _make_mock_lldb()
        with patch.dict(sys.modules, {"lldb": mock_lldb}):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            return LLDBBridge(target=1234, logger=MagicMock())

    def test_read_memory_ex_reports_the_missing_connect(self):
        """read_memory_ex returns a ReadResult naming connect() as the fix."""
        bridge = self._unconnected_bridge()

        result = bridge.read_memory_ex(0x1000, 4096)

        assert result.data is None
        assert result.fault_addr is None
        assert "connect" in result.error

    def test_read_memory_returns_none(self):
        """read_memory degrades to None rather than raising."""
        bridge = self._unconnected_bridge()

        assert bridge.read_memory(0x1000, 4096) is None

    def test_enumerate_ranges_raises_runtime_error(self):
        """enumerate_ranges raises RuntimeError, not AttributeError."""
        bridge = self._unconnected_bridge()

        with pytest.raises(RuntimeError, match="connect"):
            bridge.enumerate_ranges()

    def test_enumerate_modules_raises_runtime_error(self):
        """enumerate_modules raises RuntimeError, not AttributeError."""
        bridge = self._unconnected_bridge()

        with pytest.raises(RuntimeError, match="connect"):
            bridge.enumerate_modules()


# ---------------------------------------------------------------------------
# Tests -- attach preflight
# ---------------------------------------------------------------------------

class TestLLDBBridgeAttachPreflight:
    """connect() runs the shared attach preflight before touching the target."""

    def test_refusal_propagates_and_never_attaches(self):
        """A preflight refusal aborts connect() before AttachToProcessWithID."""
        from memslicer.acquirer.errors import AttachPreflightError

        mock_lldb, _dbg, mock_target, _proc = _make_mock_lldb()
        refusal = AttachPreflightError(
            "cannot attach to PID 1234: Yama ptrace_scope is 3",
            remediation=["reboot with kernel.yama.ptrace_scope=0"],
        )

        with patch.dict(sys.modules, {"lldb": mock_lldb}), \
             patch("memslicer.acquirer.lldb_bridge.enforce_attach_preflight",
                   side_effect=refusal):
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(target=1234, logger=MagicMock())
            with pytest.raises(AttachPreflightError) as excinfo:
                bridge.connect()

        assert excinfo.value is refusal
        mock_target.AttachToProcessWithID.assert_not_called()
        assert bridge._process is None


class TestLLDBBridgeRegionCache:
    """Region lookups are a round trip to the debug server, so they are cached."""

    def test_repeated_failures_in_one_region_query_it_once(self):
        """A span degrading to page-by-page reads must not re-ask per page."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()
        _set_read_outcome(mock_lldb, mock_process, success=False, data=None)
        _set_region(
            mock_lldb, mock_process, readable=True, base=0x1000, end=0x2000,
        )

        for offset in range(0, 0x1000, 0x400):
            bridge.read_memory_ex(0x1000 + offset, 0x4000)

        assert mock_process.GetMemoryRegionInfo.call_count == 1

    def test_address_outside_the_cached_region_is_re_queried(self):
        """The cache holds one region, so leaving it must miss."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()
        _set_read_outcome(mock_lldb, mock_process, success=False, data=None)
        _set_region(
            mock_lldb, mock_process, readable=True, base=0x1000, end=0x2000,
        )

        bridge.read_memory_ex(0x1000, 0x4000)
        bridge.read_memory_ex(0x9000, 0x4000)

        assert mock_process.GetMemoryRegionInfo.call_count == 2


class TestLLDBBridgeRegionContainment:
    """A region answer is only evidence about addresses it contains."""

    def test_region_not_containing_the_address_is_rejected(self):
        """A stub answering with the next region, or a degenerate empty one,
        must not be read as proof about the address that was asked about."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(
            mock_lldb, mock_process, mapped=False, base=0, end=0,
        )
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
            detail="memory read failed",
        )

        result = bridge.read_memory_ex(0xDEADBEEF000, 0x2000)

        assert result.fault_addr is None

    def test_non_containing_answer_is_not_cached(self):
        """A rejected answer must not be stored, or the cache goes dead."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()

        _set_region(mock_lldb, mock_process, base=0, end=0)
        _set_read_outcome(
            mock_lldb, mock_process, success=False, data=None,
        )

        bridge.read_memory_ex(0xDEADBEEF000, 0x2000)

        assert bridge._region_cache is None


class TestLLDBBridgeDisconnectClearsState:
    """Nothing that describes the old process may outlive the detach."""

    def test_enumerate_modules_refuses_after_disconnect(self):
        """The target belongs to a destroyed debugger; calling into it would
        report "no modules" rather than refusing."""
        bridge, _lldb, _dbg, _tgt, _proc = _create_and_connect()

        bridge.disconnect()

        with pytest.raises(RuntimeError, match="connect"):
            bridge.enumerate_modules()

    def test_region_cache_is_dropped_on_disconnect(self):
        """A reused bridge must not answer from the old process's map."""
        bridge, mock_lldb, _dbg, _tgt, mock_process = _create_and_connect()
        _set_region(mock_lldb, mock_process, base=0x1000, end=0x9000)
        _set_read_outcome(mock_lldb, mock_process, success=False, data=None)
        bridge.read_memory_ex(0x1000, 0x2000)
        assert bridge._region_cache is not None

        bridge.disconnect()

        assert bridge._region_cache is None


# ---------------------------------------------------------------------------
# Tests -- remote platform probing
# ---------------------------------------------------------------------------

def _connect_remote(
    remote="192.168.1.5:1234",
    triple="aarch64-unknown-linux-gnu",
    shell_outputs=None,
    shell_fails=False,
    logger=None,
    extra_patches=(),
):
    """Connect a bridge to a mocked remote platform that answers shells.

    The mock grows two things ``_make_mock_lldb`` does not have: an
    ``SBPlatformShellCommand`` whose ``GetOutput()`` replays *shell_outputs*
    keyed by the command text, and a ``Run()`` that hands back an SBError-like
    object. A command with no entry in *shell_outputs* answers with "" -- the
    same "nothing came back" a real platform gives for an unsupported probe.

    Returns (bridge, mock_lldb, mock_platform, logger).
    """
    mock_lldb, _mock_debugger, mock_target, _mock_process = _make_mock_lldb()
    mock_target.GetTriple.return_value = triple

    mock_platform = MagicMock()
    mock_connect_error = MagicMock()
    mock_connect_error.Fail.return_value = False
    mock_platform.ConnectRemote.return_value = mock_connect_error
    mock_lldb.SBPlatform.return_value = mock_platform
    mock_lldb.SBPlatformConnectOptions.return_value = MagicMock()

    outputs = dict(shell_outputs or {})

    def _build_shell(command):
        shell = MagicMock()
        shell.GetOutput.return_value = outputs.get(command, "")
        return shell

    def _run_shell(_shell):
        error = MagicMock()
        error.Fail.return_value = shell_fails
        error.GetCString.return_value = "shell command unsupported"
        return error

    mock_lldb.SBPlatformShellCommand.side_effect = _build_shell
    mock_platform.Run.side_effect = _run_shell

    logger = logger or MagicMock()

    with patch.dict(sys.modules, {"lldb": mock_lldb}):
        for extra in extra_patches:
            extra.start()
        try:
            from memslicer.acquirer.lldb_bridge import LLDBBridge

            bridge = LLDBBridge(target=1234, remote=remote, logger=logger)
            bridge.connect()
        finally:
            for extra in extra_patches:
                extra.stop()

    return bridge, mock_lldb, mock_platform, logger


def _warned_about(logger, *fragments):
    """Whether any warning the bridge logged mentions all *fragments*."""
    for call in logger.warning.call_args_list:
        text = " ".join(str(arg) for arg in call.args)
        if all(fragment in text for fragment in fragments):
            return True
    return False


class TestLLDBBridgeRemotePageSize:
    """A remote target's page size must come from that target, not this host."""

    def test_page_size_read_from_remote_platform(self):
        """A 64K-page device recorded as 4096 gets a page-state map that is
        sixteen times too fine, and nothing in the file says so."""
        bridge, mock_lldb, _platform, _logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "65536\n"},
        )

        assert bridge._platform_info.page_size == 65536
        mock_lldb.SBPlatformShellCommand.assert_any_call("getconf PAGESIZE")

    def test_host_sysconf_is_not_consulted_for_a_remote_target(self):
        """This machine's page size describes the wrong computer."""
        host_sysconf = MagicMock(return_value=16384)

        bridge, _lldb, _platform, _logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "65536\n"},
            extra_patches=(patch("os.sysconf", host_sysconf),),
        )

        host_sysconf.assert_not_called()
        assert bridge._platform_info.page_size == 65536

    def test_shell_failure_keeps_the_arch_default_and_warns(self):
        """A silent fall back to 4096 would look exactly like a real answer."""
        bridge, _lldb, _platform, logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "65536\n"},
            shell_fails=True,
        )

        assert bridge._platform_info.page_size == 4096
        assert _warned_about(logger, "page size")

    def test_non_numeric_shell_output_is_rejected(self):
        """A shell echoing 'not found' must not become the page size."""
        bridge, _lldb, _platform, logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "sh: getconf: not found\n"},
        )

        assert bridge._platform_info.page_size == 4096
        assert _warned_about(logger, "page size")

    def test_implausible_page_size_is_rejected(self):
        """A value that is not a power of two would reach the MSL writer as a
        PageSizeLog2 no reader can tell is wrong."""
        bridge, _lldb, _platform, logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "3000\n"},
        )

        assert bridge._platform_info.page_size == 4096
        assert _warned_about(logger, "page size")


class TestLLDBBridgeRemoteOSRefinement:
    """The remote OS must be read off the remote /proc, not assumed."""

    def test_android_detected_from_remote_proc_maps(self):
        """An Android device reported as plain Linux hides the ART caveat the
        operator needs before trusting the capture."""
        bridge, _lldb, _platform, logger = _connect_remote(
            shell_outputs={
                "getconf PAGESIZE": "4096\n",
                "head -c 32768 /proc/9999/maps": (
                    "70000000-70001000 r-xp 00000000 00:00 0 "
                    "/system/lib64/libart.so\n"
                ),
            },
        )

        assert bridge._platform_info.os == OSType.Android
        assert _warned_about(logger, "Consider using the Frida backend")

    def test_ios_keeps_the_arm64_default_without_a_shell_round_trip(self):
        """debugserver serves no platform shell; asking anyway would stall the
        attach on a connection that can never answer."""
        bridge, mock_lldb, _platform, _logger = _connect_remote(
            remote="ios://10.0.0.2:1234",
            triple="arm64-apple-ios17.0.0",
        )

        assert bridge._platform_info.page_size == 16384
        mock_lldb.SBPlatformShellCommand.assert_not_called()


class TestLLDBBridgePlatformLifetime:
    """The SBPlatform exists only for as long as a remote target does."""

    def test_local_bridge_never_holds_a_platform(self):
        """Without a platform, _platform_shell short-circuits; a stray one
        would send this host's questions down a channel that does not exist."""
        bridge, _lldb, _dbg, _tgt, _proc = _create_and_connect()

        assert bridge._platform is None

    def test_remote_bridge_holds_the_connected_platform(self):
        """connect() must keep the platform; it is the only channel that can
        answer questions about the remote machine."""
        bridge, _lldb, mock_platform, _logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "4096\n"},
        )

        assert bridge._platform is mock_platform

    def test_disconnect_drops_the_platform(self):
        """The platform's connection went with the destroyed debugger; keeping
        it would let a reused bridge shell into a dead session."""
        bridge, _lldb, _platform, _logger = _connect_remote(
            shell_outputs={"getconf PAGESIZE": "4096\n"},
        )
        assert bridge._platform is not None

        bridge.disconnect()

        assert bridge._platform is None


# ---------------------------------------------------------------------------
# Tests -- locating the LLDB Python bindings
# ---------------------------------------------------------------------------

def _run_results(**by_command):
    """A subprocess.run stand-in answering per executable name."""
    def _run(argv, **_kwargs):
        result = MagicMock()
        result.stdout = by_command.get(argv[0], "")
        return result
    return _run


class TestLLDBBindingCandidates:
    """The bindings must be found wherever the installer actually put them.

    Guessing directory layouts misses the install that `xcode-select --install`
    produces, so the backend refuses to start on a machine set up exactly the
    way its own error message recommends.
    """

    def test_lldb_dash_p_is_asked_first(self):
        """It is the only source that does not assume a layout."""
        from memslicer.acquirer.lldb_bridge import _lldb_binding_candidates

        with patch("subprocess.run", _run_results(
            lldb="/opt/homebrew/opt/llvm/libexec/python3.12/site-packages\n",
        )):
            candidates = _lldb_binding_candidates()

        assert candidates[0] == (
            "/opt/homebrew/opt/llvm/libexec/python3.12/site-packages"
        )

    def test_command_line_tools_layout_is_covered(self):
        """CommandLineTools keeps LLDB in PrivateFrameworks and has no
        Contents/SharedFrameworks at all."""
        from memslicer.acquirer.lldb_bridge import _lldb_binding_candidates

        with patch("subprocess.run", _run_results(
            **{"xcode-select": "/Library/Developer/CommandLineTools\n"},
        )):
            candidates = _lldb_binding_candidates()

        assert (
            "/Library/Developer/CommandLineTools/Library/PrivateFrameworks"
            "/LLDB.framework/Resources/Python"
        ) in candidates

    def test_full_xcode_layout_is_covered(self):
        """Xcode puts them a level above the developer directory."""
        from memslicer.acquirer.lldb_bridge import _lldb_binding_candidates

        with patch("subprocess.run", _run_results(
            **{"xcode-select": "/Applications/Xcode.app/Contents/Developer\n"},
        )):
            candidates = _lldb_binding_candidates()

        assert (
            "/Applications/Xcode.app/Contents/SharedFrameworks"
            "/LLDB.framework/Resources/Python"
        ) in candidates

    def test_warning_line_before_the_path_is_tolerated(self):
        """Some builds print to stdout before the path; the caller's isdir
        check picks the real directory out of what is offered."""
        from memslicer.acquirer.lldb_bridge import _lldb_binding_candidates

        with patch("subprocess.run", _run_results(
            lldb="warning: something\n/real/bindings\n",
        )):
            candidates = _lldb_binding_candidates()

        assert "/real/bindings" in candidates

    def test_missing_tools_yield_no_candidates_rather_than_raising(self):
        """A machine without lldb or Xcode must produce a clear message, not a
        FileNotFoundError from the search itself."""
        from memslicer.acquirer.lldb_bridge import _lldb_binding_candidates

        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert _lldb_binding_candidates() == []


class TestEnsureLLDBImportable:
    """The chosen directory is reported so the caller can explain a failure."""

    def test_already_importable_selects_nothing(self):
        """Nothing was added, so nothing should be blamed later."""
        from memslicer.acquirer import lldb_bridge

        with patch.dict(sys.modules, {"lldb": MagicMock()}):
            assert lldb_bridge._ensure_lldb_importable() is None

    def test_importable_candidate_is_kept_on_sys_path(self):
        """The directory whose bindings actually load is the one that stays."""
        from memslicer.acquirer import lldb_bridge

        with patch.object(
            lldb_bridge, "_lldb_binding_candidates",
            return_value=["/does/not/exist", "/real/bindings"],
        ), patch("os.path.isdir", lambda p: p == "/real/bindings"), patch(
            "importlib.import_module", return_value=MagicMock(),
        ):
            original = list(sys.path)
            try:
                assert lldb_bridge._ensure_lldb_importable() == "/real/bindings"
                assert sys.path[0] == "/real/bindings"
            finally:
                sys.path[:] = original

    def test_search_continues_past_bindings_that_do_not_load(self):
        """Homebrew LLVM beside Xcode gives two builds; only one imports into
        this interpreter, so finding a directory is not the same as being done.
        """
        from memslicer.acquirer import lldb_bridge

        attempted: list[str] = []

        def _import(_name):
            attempted.append(sys.path[0])
            if sys.path[0] != "/good":
                raise ImportError("cannot import name '_lldb'")
            return MagicMock()

        with patch.object(
            lldb_bridge, "_lldb_binding_candidates",
            return_value=["/bad", "/good"],
        ), patch("os.path.isdir", return_value=True), patch(
            "importlib.import_module", _import,
        ):
            original = list(sys.path)
            try:
                assert lldb_bridge._ensure_lldb_importable() == "/good"
                assert attempted == ["/bad", "/good"]
                # The rejected candidate must not be left behind.
                assert "/bad" not in sys.path
            finally:
                sys.path[:] = original

    def test_none_of_the_candidates_load_reports_the_first_that_existed(self):
        """That directory is what the error message needs to name."""
        from memslicer.acquirer import lldb_bridge

        with patch.object(
            lldb_bridge, "_lldb_binding_candidates",
            return_value=["/first", "/second"],
        ), patch("os.path.isdir", return_value=True), patch(
            "importlib.import_module", side_effect=ImportError("nope"),
        ):
            original = list(sys.path)
            try:
                assert lldb_bridge._ensure_lldb_importable() == "/first"
            finally:
                sys.path[:] = original

    def test_no_existing_candidate_selects_nothing(self):
        from memslicer.acquirer import lldb_bridge

        with patch.object(
            lldb_bridge, "_lldb_binding_candidates", return_value=["/nope"],
        ), patch("os.path.isdir", return_value=False):
            assert lldb_bridge._ensure_lldb_importable() is None


class TestLLDBImportMessage:
    """Bindings that were never found and bindings that would not load need
    opposite responses, so the message must tell them apart."""

    def test_not_found_points_at_installation(self):
        from memslicer.acquirer.lldb_bridge import _lldb_import_message

        message = _lldb_import_message(None, ImportError("No module named 'lldb'"))

        assert "no LLDB Python bindings could be found" in message
        assert "lldb -P" in message

    def test_found_but_unloadable_points_at_the_interpreter(self):
        """This is the failure that reads as 'not installed' but is not: the
        compiled extension only imports into the interpreter it was built for."""
        from memslicer.acquirer.lldb_bridge import _lldb_import_message

        message = _lldb_import_message(
            "/Applications/Xcode.app/Contents/SharedFrameworks"
            "/LLDB.framework/Resources/Python",
            ImportError("cannot import name '_lldb'"),
        )

        assert "were found at" in message
        assert "could not be loaded by this interpreter" in message
        assert sys.executable in message
        assert "cannot import name '_lldb'" in message
