"""Sanity tests for the split Frida investigation JS loader (P1.4a)."""
from __future__ import annotations

from importlib import resources

from memslicer.acquirer.collectors.frida_remote import (
    INVESTIGATION_SCRIPT,
    _load_investigation_script,
)


def test_investigation_script_is_nonempty() -> None:
    assert len(INVESTIGATION_SCRIPT) > 1000


def test_investigation_script_contains_rpc_exports() -> None:
    assert "rpc.exports" in INVESTIGATION_SCRIPT


def test_investigation_script_contains_all_known_symbols() -> None:
    for symbol in (
        "readFileText",
        "ensureNativeFuncs",
        "darwinGetConnections",
        "buildInodePidMap",
        "getProcessInfo",
        "getSystemInfo",
        "getProcessTable",
        "getConnectionTable",
        "getHandleTable",
    ):
        assert symbol in INVESTIGATION_SCRIPT, f"missing symbol: {symbol}"


def test_js_files_are_packaged() -> None:
    pkg = resources.files("memslicer.acquirer.collectors.js")
    for name in ("common.js", "darwin_native.js", "proc_helpers.js", "rpc_exports.js"):
        resource = pkg.joinpath(name)
        assert resource.is_file(), f"missing JS resource: {name}"
        assert resource.read_text(encoding="utf-8")  # nonempty


def test_reload_is_deterministic() -> None:
    first = _load_investigation_script()
    second = _load_investigation_script()
    assert first == second
