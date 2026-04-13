"""Tests for :mod:`memslicer.acquirer.os_detail`.

Covers round-trip, key omission, injection escaping, size caps, and (when
``hypothesis`` is installed) property-based round-trips against
adversarial inputs.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.os_detail import (
    DELIMITER,
    FIELD_ORDER,
    HARD_CAP_BYTES,
    SCHEMA_PREFIX,
    SOFT_BUDGET_BYTES,
    build_human_os_string,
    pack_os_detail,
    parse_os_detail,
    system_info_to_fields,
)
from memslicer.acquirer.investigation import TargetSystemInfo


# ---------------------------------------------------------------------------
# Human prefix
# ---------------------------------------------------------------------------

class TestHumanPrefix:

    def test_distro_only(self) -> None:
        assert build_human_os_string(distro="Ubuntu 24.04.1 LTS") == "Ubuntu 24.04.1 LTS"

    def test_distro_kernel_arch(self) -> None:
        s = build_human_os_string(
            distro="Ubuntu 24.04.1 LTS",
            kernel="6.8.0-45-generic",
            arch="x86_64",
        )
        assert s == "Ubuntu 24.04.1 LTS (6.8.0-45-generic x86_64)"

    def test_fallback_raw_os(self) -> None:
        assert build_human_os_string(raw_os="macOS-14.5-arm64") == "macOS-14.5-arm64"

    def test_empty_inputs(self) -> None:
        assert build_human_os_string() == "unknown OS"


# ---------------------------------------------------------------------------
# Pack: basic shape
# ---------------------------------------------------------------------------

class TestPackBasics:

    def test_starts_with_schema_prefix(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu"})
        assert out.startswith(SCHEMA_PREFIX)

    def test_human_prefix_and_delimiter(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "kernel": "6.8", "arch": "x86_64"})
        # human-readable segment present, then delimiter, then k=v block
        assert DELIMITER in out
        human = out[len(SCHEMA_PREFIX):].split(DELIMITER, 1)[0]
        assert "Ubuntu" in human
        assert "6.8" in human
        assert "x86_64" in human

    def test_field_order_is_stable(self) -> None:
        out = pack_os_detail({
            "kernel": "6.8",
            "distro": "Ubuntu",
            "arch": "x86_64",
            "ram": 16 * 1024**3,
            "hw_vendor": "Dell",
        })
        kv = out.split(DELIMITER, 1)[1]
        # distro MUST come before kernel, which MUST come before arch, which
        # MUST come before hw_vendor, which MUST come before ram.
        idx = lambda k: kv.index(k + "=")
        assert idx("distro") < idx("kernel") < idx("arch")
        assert idx("hw_vendor") < idx("ram")


# ---------------------------------------------------------------------------
# Key omission semantics: empty means "not collected"
# ---------------------------------------------------------------------------

class TestKeyOmission:

    def test_empty_string_omitted(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "hw_serial": ""})
        assert "hw_serial" not in out

    def test_zero_int_omitted(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "ram": 0})
        assert "ram" not in out

    def test_none_omitted(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "bios": None})
        assert "bios" not in out

    def test_empty_list_omitted(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "nic_macs": []})
        assert "nic_macs" not in out

    def test_list_joined_with_commas(self) -> None:
        out = pack_os_detail({"nic_macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]})
        assert "nic_macs=aa:bb:cc:dd:ee:ff,11:22:33:44:55:66" in out

    def test_bool_coerced(self) -> None:
        out = pack_os_detail({"secure_boot": True})
        assert "secure_boot=1" in out


# ---------------------------------------------------------------------------
# Escaping / injection resistance
# ---------------------------------------------------------------------------

class TestEscaping:

    def test_semicolon_in_value_escaped(self) -> None:
        out = pack_os_detail({"hw_model": "Foo; injected=yes"})
        # The literal "; injected=yes" must NOT create a new key.
        parsed = parse_os_detail(out)
        assert parsed.get("hw_model") == "Foo; injected=yes"
        assert "injected" not in parsed

    def test_equals_in_value_escaped(self) -> None:
        out = pack_os_detail({"bios": "v=1.2.3"})
        parsed = parse_os_detail(out)
        assert parsed.get("bios") == "v=1.2.3"

    def test_nul_in_value_escaped(self) -> None:
        out = pack_os_detail({"cpu": "Intel\x00PWN"})
        # No raw NUL survives in the packed output.
        assert "\x00" not in out
        parsed = parse_os_detail(out)
        assert parsed.get("cpu") == "Intel\x00PWN"

    def test_pipe_in_value_escaped(self) -> None:
        # '|' is part of the delimiter and must never appear raw in values.
        out = pack_os_detail({"hw_model": "Model | Pro"})
        # Only the first (human/kv) delimiter is a real '|'; values are escaped.
        assert out.count(DELIMITER) == 1
        parsed = parse_os_detail(out)
        assert parsed.get("hw_model") == "Model | Pro"

    def test_percent_in_value_round_trips(self) -> None:
        out = pack_os_detail({"hw_model": "100% Pure"})
        parsed = parse_os_detail(out)
        assert parsed.get("hw_model") == "100% Pure"

    def test_utf8_values_preserved(self) -> None:
        out = pack_os_detail({"hw_model": "Näive-Fÿbär Ⅵ"})
        parsed = parse_os_detail(out)
        assert parsed.get("hw_model") == "Näive-Fÿbär Ⅵ"

    def test_invalid_key_dropped(self) -> None:
        out = pack_os_detail({
            "distro": "Ubuntu",
            "Bad Key!": "x",
            "UPPER": "y",
        })
        parsed = parse_os_detail(out)
        assert "Bad Key!" not in parsed
        assert "UPPER" not in parsed
        assert parsed.get("distro") == "Ubuntu"


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

class TestParse:

    def test_round_trip_simple(self) -> None:
        inp = {"distro": "Ubuntu 24.04.1 LTS", "kernel": "6.8.0", "arch": "x86_64"}
        out = pack_os_detail(inp)
        parsed = parse_os_detail(out)
        for k, v in inp.items():
            assert parsed[k] == v

    def test_opaque_string_without_prefix_becomes_human(self) -> None:
        parsed = parse_os_detail("Linux 5.10 generic")
        assert parsed == {"_human": "Linux 5.10 generic"}

    def test_empty_string_parses_to_empty_dict(self) -> None:
        assert parse_os_detail("") == {}

    def test_non_string_returns_empty(self) -> None:
        assert parse_os_detail(None) == {}  # type: ignore[arg-type]

    def test_microformat_prefix_only(self) -> None:
        parsed = parse_os_detail(SCHEMA_PREFIX + "Ubuntu")
        assert parsed == {"_human": "Ubuntu"}

    def test_garbage_kv_block_tolerated(self) -> None:
        # Missing '=' in a pair → skip it; valid pairs survive.
        raw = SCHEMA_PREFIX + "X" + DELIMITER + "distro=Ubuntu;garbage;ram=8"
        parsed = parse_os_detail(raw)
        assert parsed["distro"] == "Ubuntu"
        assert parsed["ram"] == "8"


# ---------------------------------------------------------------------------
# Size caps
# ---------------------------------------------------------------------------

class TestSizeCaps:

    def test_under_soft_budget_no_truncation(self) -> None:
        out = pack_os_detail({"distro": "Ubuntu", "ram": 16})
        assert "truncated" not in out
        assert len(out.encode("utf-8")) < SOFT_BUDGET_BYTES

    def test_soft_budget_triggers_tail_drop(self) -> None:
        # Build an oversize payload with many tail fields so the packer
        # drops lowest-priority keys first.
        huge = "X" * 5000
        fields = {
            "distro": "Ubuntu",
            "kernel": "6.8",
            "arch": "x86_64",
            # hw_model is mid-priority, will survive
            "hw_model": "Model",
            # tz sits late in FIELD_ORDER → gets dropped
            "tz": huge,
        }
        out = pack_os_detail(fields)
        assert len(out.encode("utf-8")) <= SOFT_BUDGET_BYTES + 64
        assert "truncated=1" in out
        assert "distro=Ubuntu" in out  # high-priority survives
        assert huge not in out         # the bloated field is gone

    def test_provenance_keys_never_truncated(self) -> None:
        # Provenance keys must survive even when everything else is dropped.
        fields = {
            "distro": "X" * 5000,
            "mode": "safe",
        }
        out = pack_os_detail(fields)
        assert "mode=safe" in out

    def test_hard_cap_respected(self) -> None:
        # Pathological case: a single field that alone exceeds the hard cap.
        out = pack_os_detail({"hw_model": "Z" * (HARD_CAP_BYTES + 1024)})
        assert len(out.encode("utf-8")) <= HARD_CAP_BYTES


# ---------------------------------------------------------------------------
# Hypothesis property tests (optional dep)
# ---------------------------------------------------------------------------

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed")
from hypothesis import given, settings, strategies as st  # noqa: E402


_KEY_STRAT = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_"),
    min_size=1,
    max_size=20,
)
_VALUE_STRAT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # surrogates break UTF-8
    ),
    min_size=1,
    max_size=200,
)


@given(st.dictionaries(_KEY_STRAT, _VALUE_STRAT, max_size=20))
@settings(max_examples=300, deadline=None)
def test_round_trip_property(data: dict[str, str]) -> None:
    out = pack_os_detail(data)
    parsed = parse_os_detail(out)
    # Every non-empty input key must round-trip. Empties are dropped.
    for k, v in data.items():
        if not v:
            continue
        assert parsed.get(k) == v, (k, v, out)


@given(st.text(max_size=1000))
@settings(max_examples=300, deadline=None)
def test_parse_never_raises_on_arbitrary_text(s: str) -> None:
    # Parser must tolerate every possible input, yielding a dict.
    result = parse_os_detail(s)
    assert isinstance(result, dict)


@given(_VALUE_STRAT)
@settings(max_examples=200, deadline=None)
def test_injection_in_value_cannot_spawn_new_key(raw: str) -> None:
    out = pack_os_detail({"target": raw})
    parsed = parse_os_detail(out)
    # Regardless of what raw contains (;, =, %, |, NUL, …), only the
    # 'target' key and any real schema keys (e.g. _human) exist.
    assert set(parsed.keys()) - {"_human"} == {"target"} or parsed == {}
    if "target" in parsed:
        assert parsed["target"] == raw


# ---------------------------------------------------------------------------
# Projector gating: --include-fingerprint (P1.2)
# ---------------------------------------------------------------------------

class TestFingerprintGate:
    """``system_info_to_fields`` must gate ``fingerprint`` on the flag."""

    def test_fingerprint_gated_by_include_fingerprint(self) -> None:
        sys_info = TargetSystemInfo(
            distro="Android 14 (API 34)",
            fingerprint="google/raven/raven:14/UP1A.231105.001/abc:user/release-keys",
        )

        closed = system_info_to_fields(sys_info, include_fingerprint=False)
        assert "fingerprint" not in closed

        opened = system_info_to_fields(sys_info, include_fingerprint=True)
        assert "fingerprint" in opened
        assert opened["fingerprint"].startswith("google/raven")

        closed_packed = pack_os_detail(closed)
        opened_packed = pack_os_detail(opened)
        assert "google/raven" not in closed_packed
        assert "google/raven" in opened_packed
