"""Tests for the on-device investigation JS (Step 9: runtime API feature detection).

Two layers:

1. Static checks on the concatenated ``INVESTIGATION_SCRIPT``: no raw
   version-specific GumJS API may be used outside the ``common.js`` shims
   (``Module.getExportByName`` / ``Module.findBaseAddress`` are gone in
   Frida 17, ``File#read`` never existed, ``Java`` / ``ObjC`` are undefined
   in Frida 17 agents).
2. Runtime checks that load the script into a local Frida *system session*
   (``frida.get_local_device().attach(0)``) and call every RPC export. The
   probe runs in a **subprocess** so it uses the real ``frida`` module even
   when another test module has replaced ``sys.modules["frida"]`` with a mock
   (``tests/test_frida_acquirer.py`` does). Marked ``requires_frida_runtime``
   and skipped only when the subprocess reports that frida cannot be imported
   or the system session cannot be attached.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

from memslicer.acquirer.collectors.frida_remote import INVESTIGATION_SCRIPT

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)
_SHIMS = ("findGlobalExport", "findModuleExport", "javaAvailable", "objcAvailable")


def _strip_comments(script: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", script))


def _matching_close(text: str, open_idx: int, pair: str = "{}") -> int:
    """Index just past the closer matching the opener at ``open_idx``."""
    opener, closer = pair
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    raise AssertionError(f"unbalanced {pair!r} in investigation script")


def _function_span(text: str, name: str) -> tuple[int, int]:
    match = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", text)
    assert match, f"function {name} missing from script"
    return match.start(), _matching_close(text, match.end() - 1)


def _all_function_spans(text: str) -> dict[str, tuple[int, int]]:
    spans = {}
    for match in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", text):
        spans[match.group(1)] = (match.start(), _matching_close(text, match.end() - 1))
    return spans


def _guarded_spans(text: str, guard: str) -> list[tuple[int, int]]:
    """Spans of ``if (<cond>) { ... }`` whose condition positively requires
    ``<guard>()``: it must appear, not negated, and not in an ``||`` chain."""
    spans = []
    for match in re.finditer(r"if\s*\(", text):
        cond_end = _matching_close(text, match.end() - 1, "()")
        cond = text[match.end(): cond_end - 1]
        if not re.search(r"(?<![!\w])" + guard + r"\(\)", cond):
            continue
        if "!" + guard in cond or "||" in cond:
            continue
        brace = text.find("{", cond_end)
        assert brace != -1
        spans.append((match.start(), _matching_close(text, brace)))
    return spans


def _inside(idx: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= idx < end for start, end in spans)


def _without_shims(script: str) -> str:
    """Comment-free script with the shim function bodies blanked out."""
    text = _strip_comments(script)
    for shim in _SHIMS:
        start, end = _function_span(text, shim)
        text = text[:start] + " " * (end - start) + text[end:]
    return text


# --------------------------------------------------------------------------
# 1. static checks
# --------------------------------------------------------------------------

_FORBIDDEN_MODULE_STATIC = re.compile(
    r"\bModule\s*\.\s*(getExportByName|findExportByName|findBaseAddress|getBaseAddress)\s*\("
)
_MODULE_SUBSCRIPT = re.compile(r"\bModule\s*\[")


def test_no_static_module_lookups_outside_shims() -> None:
    text = _without_shims(INVESTIGATION_SCRIPT)
    assert not _FORBIDDEN_MODULE_STATIC.search(text), _FORBIDDEN_MODULE_STATIC.search(text)
    assert not _MODULE_SUBSCRIPT.search(_strip_comments(INVESTIGATION_SCRIPT))


def test_find_global_export_shim_uses_exactly_one_legacy_call() -> None:
    text = _strip_comments(INVESTIGATION_SCRIPT)
    matches = list(_FORBIDDEN_MODULE_STATIC.finditer(text))
    assert len(matches) == 1, [m.group(0) for m in matches]
    start, end = _function_span(text, "findGlobalExport")
    assert start <= matches[0].start() < end
    call = text[matches[0].start(): text.index(")", matches[0].end()) + 1]
    assert re.fullmatch(r"Module\.findExportByName\(null,\s*sym\)", call), call
    # Legacy string-module form must not appear anywhere.
    assert not re.search(r"Module\s*\.\s*findExportByName\s*\(\s*['\"]", text)


def test_find_module_export_shim_uses_instance_lookup_only() -> None:
    text = _strip_comments(INVESTIGATION_SCRIPT)
    start, end = _function_span(text, "findModuleExport")
    body = text[start:end]
    assert "m.findExportByName(sym)" in body
    assert not _FORBIDDEN_MODULE_STATIC.search(body)


def test_no_file_read_call() -> None:
    # File#read never existed in any Frida version; readBytes/readText/readAllText do.
    assert not re.search(r"\.read\(", _strip_comments(INVESTIGATION_SCRIPT))


@pytest.mark.parametrize("bridge,guard", [("Java", "javaAvailable"), ("ObjC", "objcAvailable")])
def test_bridge_globals_only_behind_guards(bridge: str, guard: str) -> None:
    text = _without_shims(INVESTIGATION_SCRIPT)
    identifier = re.compile(r"\b" + bridge + r"\b")

    # Aliasing / passing the global around is forbidden: every reference must
    # be a member access (`Java.` / `ObjC.`).
    for match in identifier.finditer(text):
        assert text[match.end(): match.end() + 1] == ".", (
            f"bare {bridge} reference (alias?) at offset {match.start()}: "
            f"{text[max(0, match.start() - 60): match.start() + 40]!r}"
        )

    guarded = _guarded_spans(text, guard)

    # A helper function whose body uses the bridge outside an inline guard
    # counts as guarded only when every call site sits inside a guarded block.
    for name, (start, end) in _all_function_spans(text).items():
        body = text[start:end]
        unguarded_uses = [
            m for m in identifier.finditer(body) if not _inside(start + m.start(), guarded)
        ]
        if not unguarded_uses:
            continue
        calls = [
            m.start()
            for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text)
            if not (start <= m.start() < end)
        ]
        assert calls, f"{name} uses {bridge}. but is never called"
        for idx in calls:
            assert _inside(idx, guarded), f"{name} (uses {bridge}.) called outside a {guard}() guard"
        guarded.append((start, end))

    for match in identifier.finditer(text):
        assert _inside(match.start(), guarded), (
            f"{bridge}. outside a {guard}() guard at offset {match.start()}: "
            f"{text[max(0, match.start() - 60): match.start() + 40]!r}"
        )


def test_shims_and_helpers_present() -> None:
    for name in (
        "findGlobalExport", "getGlobalExport", "findModuleExport", "getModuleExport",
        "findModuleBase", "javaAvailable", "objcAvailable", "isAndroid",
        "readFileText", "readFileTextW", "decodeUtf8", "agentVersion", "envelope",
        "nanosecondsFromSeconds",
    ):
        assert re.search(r"function\s+" + name + r"\s*\(", INVESTIGATION_SCRIPT), name


def test_every_export_returns_envelope() -> None:
    text = _strip_comments(INVESTIGATION_SCRIPT)
    start = text.index("rpc.exports = {")
    end = _matching_close(text, text.index("{", start))
    exports = text[start:end]
    names = []
    for match in re.finditer(r"(\w+)\s*:\s*function\s*\([^)]*\)\s*\{", exports):
        body_end = _matching_close(exports, match.end() - 1)
        body = exports[match.end(): body_end]
        returns = re.findall(r"\breturn\b[^;]*;", body)
        assert returns, f"export {match.group(1)} has no return"
        for ret in returns:
            assert ret.startswith("return envelope("), f"{match.group(1)}: {ret}"
        names.append(match.group(1))
    assert set(names) == {
        "getProcessInfo", "getSystemInfo", "getProcessTable", "getConnectionTable", "getHandleTable",
    }


def test_shim_order_common_first() -> None:
    assert INVESTIGATION_SCRIPT.index("function findGlobalExport") < INVESTIGATION_SCRIPT.index(
        "function ensureSysctl"
    )


def _android_package_regex() -> "re.Pattern[str]":
    match = re.search(r"var ANDROID_PACKAGE_RE = /(.*)/;", INVESTIGATION_SCRIPT)
    assert match, "ANDROID_PACKAGE_RE missing"
    return re.compile(match.group(1), re.ASCII)


@pytest.mark.parametrize(
    "argv0,expected",
    [
        ("com.android.settings", True),
        ("com.android.settings:remote", True),
        ("org.example.app_v2:bg.worker", True),
        ("sleep", False),                 # native toybox target
        ("/system/bin/sleep", False),
        ("/data/local/tmp/foo", False),
        ("system_server", False),         # no dot -> not a package name
        ("1com.android.x", False),
        ("com.android.", False),
        ("", False),
    ],
)
def test_android_package_regex(argv0: str, expected: bool) -> None:
    assert bool(_android_package_regex().fullmatch(argv0)) is expected


def test_android_app_attribution_is_guarded() -> None:
    text = _strip_comments(INVESTIGATION_SCRIPT)
    start, end = _function_span(text, "linuxFillProcessInfo")
    body = text[start:end]
    assert "isAndroidAppProcess(argv0, exeFromLink)" in body
    assert "result.package = argv0.split(':')[0]" in body
    start, end = _function_span(text, "isAndroidAppProcess")
    helper = text[start:end]
    for probe in ("isAndroid()", "javaAvailable()", "app_process(64|32)$", "ANDROID_PACKAGE_RE.test(argv0)"):
        assert probe in helper, probe


def test_proc_stat_warning_only_in_system_info() -> None:
    text = _strip_comments(INVESTIGATION_SCRIPT)
    start, end = _function_span(text, "linuxFillProcStat")
    assert "readBootTimeSeconds(null)" in text[start:end]
    start, end = _function_span(text, "linuxFillSystemInfo")
    assert "readBootTimeSeconds(warnings)" in text[start:end]


# --------------------------------------------------------------------------
# 2. runtime checks (local Frida system session, real frida in a subprocess)
# --------------------------------------------------------------------------

_PROBE_SCRIPT = r"""
import json, os, sys
out = {"status": "ok"}
try:
    import frida
except Exception as exc:
    print(json.dumps({"status": "skip", "reason": "frida not importable: %s" % exc})); sys.exit(0)
cfg = json.load(open(os.environ["MEMSLICER_PROBE_CONFIG"], encoding="utf-8"))
script_src = open(cfg["script_path"], encoding="utf-8").read()
try:
    session = frida.get_local_device().attach(0)
except Exception as exc:
    print(json.dumps({"status": "skip", "reason": "system session unavailable: %s" % exc})); sys.exit(0)
messages = []
script = session.create_script(script_src + '''
rpc.exports.probe = function() { return {pid: Process.id, platform: Process.platform, bigint: typeof BigInt}; };
rpc.exports.readFile = function(path, maxLen) { return readFileText(path, maxLen); };
rpc.exports.nsFromSeconds = function(s, extra) { return nanosecondsFromSeconds(s, extra); };
''')
script.on("message", lambda msg, _data: messages.append(msg))
script.load()
api = getattr(script, "exports_sync", None) or script.exports
probe = api.probe()
pid = probe["pid"]
out["frida_version"] = frida.__version__
out["probe"] = probe
out["exports"] = {
    "getSystemInfo": api.get_system_info(),
    "getProcessInfo": api.get_process_info(pid),
    "getHandleTable": api.get_handle_table(pid),
    "getProcessTable": api.get_process_table(pid),
    "getConnectionTable": api.get_connection_table(),
}
out["reads"] = {name: api.read_file(path, maxlen) for name, (path, maxlen) in cfg["reads"].items()}
out["ns"] = api.ns_from_seconds(1792334195, 169554950000000)
out["messages"] = messages
try:
    script.unload()
finally:
    session.detach()
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def runtime_probe(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("investigation_probe")
    script_path = tmp / "investigation.js"
    script_path.write_text(INVESTIGATION_SCRIPT, encoding="utf-8")
    nul_file = tmp / "nul.bin"
    nul_file.write_bytes(b"a\x00b\x00")
    utf8_file = tmp / "utf8.bin"
    utf8_file.write_bytes("sléep\x00€\x00\U0001F600".encode("utf-8") + b"\xff\x00")
    config = tmp / "config.json"
    config.write_text(json.dumps({
        "script_path": str(script_path),
        "reads": {
            "nul": [str(nul_file), 8192],
            "utf8": [str(utf8_file), 8192],
            "utf8_truncated": [str(utf8_file), 3],
            "missing": [str(tmp / "missing"), 8192],
        },
    }), encoding="utf-8")
    env = dict(os.environ, MEMSLICER_PROBE_CONFIG=str(config))
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _PROBE_SCRIPT],
        capture_output=True, text=True, env=env, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    if result.get("status") == "skip":
        pytest.skip(result.get("reason", "frida runtime unavailable"))
    return result


def _assert_envelope(result, name: str) -> None:
    assert isinstance(result, dict), f"{name} did not return a dict"
    assert "data" in result and "warnings" in result, f"{name}: {result!r}"
    assert isinstance(result["warnings"], list)
    for warning in result["warnings"]:
        assert "is not defined" not in warning, f"{name}: {warning}"
        assert "not a function" not in warning, f"{name}: {warning}"


@pytest.mark.requires_frida_runtime
def test_runtime_exports_on_local_system_session(runtime_probe) -> None:
    probe = runtime_probe["probe"]
    assert probe["pid"] > 0
    exports = runtime_probe["exports"]
    for name, result in exports.items():
        _assert_envelope(result, name)
        assert result.get("agent") == runtime_probe["frida_version"], name

    assert isinstance(exports["getSystemInfo"]["data"], dict)
    assert isinstance(exports["getProcessInfo"]["data"], dict)
    for name in ("getHandleTable", "getProcessTable", "getConnectionTable"):
        assert isinstance(exports[name]["data"], list), name

    if probe["platform"] in ("darwin", "linux"):
        system = exports["getSystemInfo"]["data"]
        assert system["hostname"], system
        assert system["osDetail"], system
        assert exports["getProcessInfo"]["data"]["exePath"], exports["getProcessInfo"]
        assert exports["getHandleTable"]["data"], "handle table of own process must not be empty"
    assert not [m for m in runtime_probe["messages"] if m.get("type") == "error"], runtime_probe["messages"]


@pytest.mark.requires_frida_runtime
def test_runtime_read_file_text_keeps_nul_bytes(runtime_probe) -> None:
    """/proc/<pid>/cmdline is NUL-separated; the GumJS text APIs reject NUL, so
    readFileText must read bytes and decode UTF-8 itself (verified on Android)."""
    reads = runtime_probe["reads"]
    assert len(reads["nul"]) == 4
    assert "\u0000" in reads["nul"]
    assert reads["nul"] == "a\x00b\x00"
    assert reads["utf8"] == "sléep\x00€\x00\U0001F600�\x00"
    assert reads["utf8_truncated"] == "slé"
    assert reads["missing"] == ""


@pytest.mark.requires_frida_runtime
def test_runtime_nanoseconds_are_exact(runtime_probe) -> None:
    value = runtime_probe["ns"]
    expected = 1792334195 * 10**9 + 169554950000000
    if runtime_probe["probe"]["bigint"] == "function":
        assert value == str(expected), value          # decimal string, no rounding
    else:
        assert abs(int(value) - expected) < 1024      # Number fallback
