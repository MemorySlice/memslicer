"""Regression tests pinning the three P0.1 engine attribution fixes.

Covers:

- ``--examiner`` / ``--case-ref`` flowing through CLI → engine → writer
  and landing in SystemContext (previously hardcoded to
  ``getpass.getuser()`` and ``""``).
- The **remote-hostname fallback bug** (`engine.py:310` before the fix):
  an empty collector hostname on a remote target used to silently fall
  back to ``socket.gethostname()``, attributing the MSL to the
  acquisition host rather than the Android/iOS/Windows device the
  operator was dumping. The test pins the new contract via a
  ``socket.gethostname`` patch with ``side_effect=AssertionError`` —
  any fallback call would fail the test loudly.
- ``--hostname-override`` precedence over collector output.
- Redaction bookkeeping: ``TargetSystemInfo.redacted_keys`` surfaces in
  the packed ``os_detail`` as the ``redacted_keys`` marker.
- Forensic-string validation at the CLI boundary.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.acquirer.identity import (
    AttributionConfig,
    ForensicStringError,
    TargetIdentity,
    resolve_target_identity,
    validate_forensic_string,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.acquirer.os_detail import parse_os_detail
from memslicer.acquirer.bridge import MemoryRange
from memslicer.msl.constants import BlockType
from memslicer.msl.types import ProcessEntry, ConnectionEntry, HandleEntry


# Pull the MockBridge / MockCollector from test_engine.py — no point
# re-implementing them. They're local (not importable via the package),
# so use a path-adjusted import.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_engine import (  # noqa: E402
    MockBridge,
    MockCollector,
    _find_block,
    _parse_blocks,
    _read_padded_string,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_system_context(output: Path) -> dict[str, object]:
    """Parse the SystemContext block from an MSL file into a dict.

    Returns keys: ``boot_time``, ``target_count``, ``table_bitmap``,
    ``acq_user``, ``hostname``, ``domain``, ``os_detail``, ``case_ref``.
    """
    raw = output.read_bytes()
    blocks = _parse_blocks(raw)
    payload = _find_block(blocks, BlockType.SystemContext)
    assert payload is not None, "SystemContext block missing"

    boot_time, target_count, table_bitmap = struct.unpack_from("<QII", payload, 0)
    acq_len, host_len, dom_len, osd_len, cref_len = struct.unpack_from(
        "<HHHHH", payload, 16,
    )
    offset = 32

    acq_user = ""
    if acq_len > 0:
        acq_user, offset = _read_padded_string(payload, offset)

    hostname = ""
    if host_len > 0:
        hostname, offset = _read_padded_string(payload, offset)

    domain = ""
    if dom_len > 0:
        domain, offset = _read_padded_string(payload, offset)

    os_detail = ""
    if osd_len > 0:
        os_detail, offset = _read_padded_string(payload, offset)

    case_ref = ""
    if cref_len > 0:
        case_ref, offset = _read_padded_string(payload, offset)

    return {
        "boot_time": boot_time,
        "target_count": target_count,
        "table_bitmap": table_bitmap,
        "acq_user": acq_user,
        "hostname": hostname,
        "domain": domain,
        "os_detail": os_detail,
        "case_ref": case_ref,
    }


def _minimal_bridge_and_collector() -> tuple[MockBridge, MockCollector]:
    data = b"\xaa" * 4096
    ranges = [MemoryRange(base=0x10000, size=4096, protection="rw-", file_path="")]
    return (
        MockBridge(ranges=ranges, modules=[], memory={0x10000: data}),
        MockCollector(),
    )


# ---------------------------------------------------------------------------
# P0.1 bug #1: --case-ref flows to SystemContext.case_ref
# ---------------------------------------------------------------------------

class TestCaseRefAttribution:

    def test_case_ref_lands_in_system_context(self, tmp_path: Path) -> None:
        bridge, collector = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=collector,
            attribution=AttributionConfig(case_ref="CASE-2026-017"),
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["case_ref"] == "CASE-2026-017"

    def test_default_case_ref_is_empty(self, tmp_path: Path) -> None:
        bridge, collector = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge, investigation=True, collector=collector,
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["case_ref"] == ""


# ---------------------------------------------------------------------------
# P0.1 bug #2: --examiner overrides getpass.getuser()
# ---------------------------------------------------------------------------

class TestExaminerAttribution:

    def test_examiner_overrides_getpass(self, tmp_path: Path) -> None:
        bridge, collector = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=collector,
            attribution=AttributionConfig(examiner="alice"),
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["acq_user"] == "alice"

    def test_default_examiner_falls_back_to_getpass(self, tmp_path: Path) -> None:
        import getpass

        bridge, collector = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge, investigation=True, collector=collector,
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["acq_user"] == getpass.getuser()


# ---------------------------------------------------------------------------
# P0.1 bug #3: remote target empty hostname does NOT leak acquisition host
# ---------------------------------------------------------------------------

class _BlindRemoteCollector(MockCollector):
    """Collector that returns an empty hostname (typical stock iOS sandbox)."""

    def collect_system_info(self) -> TargetSystemInfo:
        return TargetSystemInfo(
            boot_time=1699000000_000000000,
            hostname="",  # Simulates sandbox / permission failure.
            domain="",
            os_detail="iOS 17 sandboxed",
        )


class TestRemoteHostnameFallback:

    def test_remote_empty_hostname_does_not_leak_acquisition_host(
        self, tmp_path: Path,
    ) -> None:
        """The key regression test.

        Before P0.1, ``engine.py:310`` fell back to ``socket.gethostname()``
        whenever the collector returned an empty hostname. On a remote
        target that produced an MSL attributed to the **acquisition host**
        — a silent forensic-attribution corruption.

        We patch ``socket.gethostname`` with a side effect that raises
        ``AssertionError``. If the engine tries to fall back on a remote
        target, the test fails loudly. The engine must accept an empty
        hostname on remote targets and move on.
        """
        bridge, _ = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=_BlindRemoteCollector(),
            attribution=AttributionConfig(is_remote=True),
        )
        output = tmp_path / "dump.msl"

        with patch(
            "memslicer.acquirer.identity.socket.gethostname",
            side_effect=AssertionError("socket.gethostname must not be called on remote targets"),
        ):
            engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["hostname"] == ""

    def test_local_empty_hostname_still_falls_back(self, tmp_path: Path) -> None:
        """Local targets keep the fallback — that's the only place it's correct."""
        bridge, _ = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=_BlindRemoteCollector(),
            attribution=AttributionConfig(is_remote=False),
        )
        output = tmp_path / "dump.msl"

        with patch(
            "memslicer.acquirer.identity.socket.gethostname",
            return_value="dev-laptop-42",
        ):
            engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["hostname"] == "dev-laptop-42"

    def test_hostname_override_wins_over_collector(self, tmp_path: Path) -> None:
        bridge, collector = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=collector,
            attribution=AttributionConfig(
                hostname_override="forensics-target-01",
                is_remote=True,
            ),
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        assert parsed["hostname"] == "forensics-target-01"

    def test_remote_hostname_unavailable_warning_in_os_detail(
        self, tmp_path: Path,
    ) -> None:
        bridge, _ = _minimal_bridge_and_collector()
        engine = AcquisitionEngine(
            bridge,
            investigation=True,
            collector=_BlindRemoteCollector(),
            attribution=AttributionConfig(is_remote=True),
        )
        output = tmp_path / "dump.msl"
        engine.acquire(output)

        parsed = _read_system_context(output)
        fields = parse_os_detail(parsed["os_detail"])
        assert "remote_hostname_unavailable" in fields.get("collector_warning", "")


# ---------------------------------------------------------------------------
# resolve_target_identity unit tests
# ---------------------------------------------------------------------------

class TestResolveTargetIdentity:

    def test_collector_value_passes_through(self) -> None:
        result = resolve_target_identity(
            collector_hostname="dev-box",
            collector_domain="corp.example",
            is_remote=False,
        )
        assert result.hostname == "dev-box"
        assert result.domain == "corp.example"
        assert result.warnings == []

    def test_remote_empty_logs_warning_and_no_fallback(self) -> None:
        with patch(
            "memslicer.acquirer.identity.socket.gethostname",
            side_effect=AssertionError("must not fire"),
        ):
            result = resolve_target_identity(
                collector_hostname="",
                collector_domain="",
                is_remote=True,
            )
        assert result.hostname == ""
        assert "remote_hostname_unavailable" in result.warnings

    def test_override_beats_collector(self) -> None:
        result = resolve_target_identity(
            collector_hostname="bad",
            collector_domain="wrong",
            is_remote=True,
            hostname_override="correct",
            domain_override="right",
        )
        assert result.hostname == "correct"
        assert result.domain == "right"


# ---------------------------------------------------------------------------
# validate_forensic_string
# ---------------------------------------------------------------------------

class TestValidateForensicString:

    def test_none_and_empty_pass_through(self) -> None:
        assert validate_forensic_string(None, field_name="x") == ""
        assert validate_forensic_string("", field_name="x") == ""

    def test_plain_text_survives(self) -> None:
        assert validate_forensic_string("CASE-2026-017", field_name="x") == "CASE-2026-017"

    def test_nfc_normalization(self) -> None:
        # "é" composed vs decomposed.
        decomposed = "e\u0301"
        composed = "é"
        out = validate_forensic_string(decomposed, field_name="x")
        assert out == composed

    @pytest.mark.parametrize("bad", [
        "alice\x00bob",      # NUL
        "alice\nbob",        # newline
        "alice\x1fbob",      # unit separator
        "alice\x7fbob",      # DEL
        "alice\x85bob",      # C1 control
    ])
    def test_control_chars_rejected(self, bad: str) -> None:
        with pytest.raises(ForensicStringError):
            validate_forensic_string(bad, field_name="--examiner")

    def test_bidi_override_rejected(self) -> None:
        with pytest.raises(ForensicStringError):
            validate_forensic_string("alice\u202ebob", field_name="--examiner")

    @pytest.mark.parametrize("bad", ["a;b", "a=b"])
    def test_microformat_delimiters_rejected(self, bad: str) -> None:
        with pytest.raises(ForensicStringError):
            validate_forensic_string(bad, field_name="--case-ref")

    def test_length_cap_enforced(self) -> None:
        with pytest.raises(ForensicStringError):
            validate_forensic_string("A" * 300, field_name="x", max_len_bytes=256)

    def test_utf8_length_cap_counts_bytes_not_chars(self) -> None:
        # 100 non-ASCII chars × 2 bytes each = 200 bytes → fits under 256.
        s = "ä" * 100
        assert validate_forensic_string(s, field_name="x") == s
        # 130 × 2 = 260 bytes → rejected.
        with pytest.raises(ForensicStringError):
            validate_forensic_string("ä" * 130, field_name="x")
