"""Tests for the shared collector I/O helpers in ``collectors/_io.py``."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors import _io


# ---------------------------------------------------------------------------
# read_proc_file
# ---------------------------------------------------------------------------

class TestReadProcFile:

    def test_reads_and_strips_text(self, tmp_path: Path) -> None:
        f = tmp_path / "hostname"
        f.write_text("box01\n")
        assert _io.read_proc_file(str(f)) == "box01"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert _io.read_proc_file(str(tmp_path / "nope")) == ""

    def test_size_cap_truncates_large_file(self, tmp_path: Path) -> None:
        f = tmp_path / "big"
        f.write_text("A" * (_io.MAX_ENRICHMENT_READ + 4096))
        out = _io.read_proc_file(str(f))
        assert len(out) == _io.MAX_ENRICHMENT_READ
        assert set(out) == {"A"}

    def test_custom_max_bytes_honored(self, tmp_path: Path) -> None:
        f = tmp_path / "bounded"
        f.write_text("X" * 100)
        assert _io.read_proc_file(str(f), max_bytes=32) == "X" * 32

    def test_symlink_is_refused(self, tmp_path: Path) -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            pytest.skip("O_NOFOLLOW unavailable")
        real = tmp_path / "real"
        real.write_text("secret")
        link = tmp_path / "link"
        link.symlink_to(real)
        # O_NOFOLLOW must reject the symlink; we get an empty string, not
        # the content of the pointee.
        assert _io.read_proc_file(str(link)) == ""

    def test_utf8_decode_replaces_bad_bytes(self, tmp_path: Path) -> None:
        f = tmp_path / "bad"
        f.write_bytes(b"ok\xff\xfe tail")
        out = _io.read_proc_file(str(f))
        # Should not raise; replacement chars allowed.
        assert "ok" in out and "tail" in out


# ---------------------------------------------------------------------------
# read_proc_bytes
# ---------------------------------------------------------------------------

class TestReadProcBytes:

    def test_returns_raw_bytes_including_nuls(self, tmp_path: Path) -> None:
        f = tmp_path / "cmdline"
        f.write_bytes(b"/bin/sh\x00-c\x00echo hi\x00")
        out = _io.read_proc_bytes(str(f))
        assert out == b"/bin/sh\x00-c\x00echo hi\x00"

    def test_missing_file_returns_empty_bytes(self, tmp_path: Path) -> None:
        assert _io.read_proc_bytes(str(tmp_path / "absent")) == b""


# ---------------------------------------------------------------------------
# read_symlink
# ---------------------------------------------------------------------------

class TestReadSymlink:

    def test_reads_symlink_target(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_text("")
        link = tmp_path / "link"
        link.symlink_to(target)
        assert _io.read_symlink(str(link)) == str(target)

    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert _io.read_symlink(str(tmp_path / "nolink")) == ""


# ---------------------------------------------------------------------------
# _resolve_binary / run_cmd_safe
# ---------------------------------------------------------------------------

class TestResolveBinary:

    def test_known_bare_name_resolved(self) -> None:
        # "sysctl" is always in TRUSTED_BIN.
        assert _io._resolve_binary("sysctl") == _io.TRUSTED_BIN["sysctl"]

    def test_unknown_bare_name_raises(self) -> None:
        with pytest.raises(_io.UntrustedBinaryError):
            _io._resolve_binary("curl")

    def test_absolute_path_accepted_if_in_allowlist_values(self) -> None:
        p = _io.TRUSTED_BIN["sysctl"]
        assert _io._resolve_binary(p) == p

    def test_absolute_path_rejected_if_not_in_allowlist(self) -> None:
        with pytest.raises(_io.UntrustedBinaryError):
            _io._resolve_binary("/tmp/evil")


class TestRunCmdSafe:

    def test_unknown_binary_returns_empty_no_raise(self) -> None:
        assert _io.run_cmd_safe(["curl", "http://evil"]) == ""

    def test_missing_binary_on_host_returns_empty(self, tmp_path: Path) -> None:
        # Inject a TRUSTED_BIN entry pointing at a non-existent path.
        with patch.dict(_io.TRUSTED_BIN, {"fake_bin": str(tmp_path / "nope")}):
            assert _io.run_cmd_safe(["fake_bin"]) == ""

    def test_empty_argv_returns_empty(self) -> None:
        assert _io.run_cmd_safe([]) == ""

    def test_success_path_returns_stdout_truncated(self, tmp_path: Path) -> None:
        # Build a tiny shell script, allowlist it, and run it.
        script = tmp_path / "echo_big.sh"
        script.write_text(
            "#!/bin/sh\n"
            "i=0; while [ $i -lt 500 ]; do printf A; i=$((i+1)); done\n"
        )
        script.chmod(0o755)
        with patch.dict(_io.TRUSTED_BIN, {"bigecho": str(script)}):
            out = _io.run_cmd_safe(["bigecho"], timeout=5.0, max_output=100)
        assert len(out) == 100
        assert set(out) == {"A"}

    def test_nonzero_exit_returns_empty(self, tmp_path: Path) -> None:
        script = tmp_path / "fail.sh"
        script.write_text("#!/bin/sh\nexit 3\n")
        script.chmod(0o755)
        with patch.dict(_io.TRUSTED_BIN, {"failer": str(script)}):
            assert _io.run_cmd_safe(["failer"]) == ""

    def test_timeout_returns_empty(self, tmp_path: Path) -> None:
        script = tmp_path / "slow.sh"
        script.write_text("#!/bin/sh\nsleep 5\n")
        script.chmod(0o755)
        with patch.dict(_io.TRUSTED_BIN, {"slowbin": str(script)}):
            assert _io.run_cmd_safe(["slowbin"], timeout=0.2) == ""

    def test_shell_metachars_are_not_interpreted(self, tmp_path: Path) -> None:
        # Proves shell=False: a ';' in an arg stays literal, doesn't chain.
        marker = tmp_path / "marker"
        script = tmp_path / "printarg.sh"
        script.write_text("#!/bin/sh\nprintf '%s' \"$1\"\n")
        script.chmod(0o755)
        with patch.dict(_io.TRUSTED_BIN, {"pa": str(script)}):
            out = _io.run_cmd_safe(
                ["pa", f"; touch {marker}"],
                timeout=2.0,
            )
        assert out == f"; touch {marker}"
        assert not marker.exists()


