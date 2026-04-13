"""Shared target-identity / operator-identity helpers.

Two responsibilities:

1. :func:`validate_forensic_string` — CLI-boundary validation for
   operator-provided strings (``--examiner``, ``--case-ref``,
   ``--hostname-override``, ``--domain-override``). Defends the packed
   ``os_detail`` mini-format and downstream MSL parsers against
   injection or renderer abuse via crafted case references. Applied in
   both the acquire CLI and the new ``memslicer-sysctx`` CLI so a single
   source of truth governs what gets into the SystemContext block.

2. :func:`resolve_target_identity` — single-source-of-truth resolution
   for hostname / domain attribution, called by both
   :class:`memslicer.acquirer.engine.AcquisitionEngine` and the
   ``cli_sysctx`` read-only command.

   Remote targets with an empty collector hostname stay empty rather
   than falling back to ``socket.gethostname()`` — that fallback used
   to silently attribute remote MSLs to the acquisition host. The
   ``--hostname-override`` flag is the escape hatch when the operator
   knows the identity out-of-band.
"""
from __future__ import annotations

import logging
import socket
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from memslicer.msl.constants import OSType


# Maximum length (in UTF-8 bytes) of an operator-provided string that
# lands in the SystemContext block. Short enough that four such strings
# (examiner + case_ref + hostname_override + domain_override) cannot
# individually blow out the 65 KiB ``OSDetailLen`` wire budget, but long
# enough to hold any realistic case reference or operator name.
MAX_FORENSIC_STRING_LEN = 256


# Unicode codepoints that a crafted string could use to mis-render
# itself in any downstream report — left-to-right / right-to-left
# override controls are a classic trick for disguising filenames and
# CVE identifiers. We reject rather than normalize because any
# legitimate forensic string has no reason to contain these.
_BIDI_OVERRIDES = frozenset({
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
})


class ForensicStringError(ValueError):
    """Raised by :func:`validate_forensic_string` on invalid input.

    The CLI layer translates this to a ``click.BadParameter`` so the
    operator sees a clean error message rather than a traceback.
    """


def validate_forensic_string(
    raw: str | None,
    *,
    field_name: str,
    max_len_bytes: int = MAX_FORENSIC_STRING_LEN,
) -> str:
    """Normalize and validate an operator-provided forensic string.

    - ``None`` / empty → ``""`` (empty is valid; it means "not supplied").
    - Applies Unicode NFC normalization so visually-identical strings
      compare equal across different encodings.
    - Rejects C0/C1 control codepoints (``U+0000..U+001F``,
      ``U+007F..U+009F``) which would break the packed ``os_detail``
      mini-format and corrupt terminal output.
    - Rejects bidi override codepoints (``_BIDI_OVERRIDES``) — see note
      above on renderer abuse.
    - Rejects raw ``;`` and ``=`` because they are the delimiters of
      the ``os_detail`` microformat; an ``--case-ref "x=y;evil=1"``
      would otherwise escape into new keys. Operators who legitimately
      need these characters can put them in their own notes field — the
      SystemContext block is structured metadata, not free-text.
    - Enforces a byte-length cap (default 256) so a single crafted
      string cannot dominate the 64 KiB ``OSDetailLen`` budget.
    """
    if raw is None or raw == "":
        return ""

    normalized = unicodedata.normalize("NFC", raw)

    for ch in normalized:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            raise ForensicStringError(
                f"{field_name}: control character U+{cp:04X} is not allowed"
            )
        if ch in _BIDI_OVERRIDES:
            raise ForensicStringError(
                f"{field_name}: bidi override U+{cp:04X} is not allowed"
            )
        if ch in (";", "="):
            raise ForensicStringError(
                f"{field_name}: {ch!r} is not allowed (conflicts with "
                f"os_detail microformat)"
            )

    encoded_len = len(normalized.encode("utf-8"))
    if encoded_len > max_len_bytes:
        raise ForensicStringError(
            f"{field_name}: {encoded_len} bytes exceeds "
            f"{max_len_bytes}-byte limit"
        )

    return normalized


@dataclass
class TargetIdentity:
    """Resolved hostname/domain pair with a structured warning list.

    ``warnings`` carries human-readable tags (e.g.
    ``"remote_hostname_unavailable"``) so callers can surface them in
    both the engine log and the ``os_detail`` k=v block via the
    ``collector_warning`` mechanism.
    """

    hostname: str = ""
    domain: str = ""
    warnings: list[str] | None = None

    def __post_init__(self) -> None:
        if self.warnings is None:
            self.warnings = []


def resolve_target_identity(
    *,
    collector_hostname: str,
    collector_domain: str,
    is_remote: bool,
    hostname_override: str = "",
    domain_override: str = "",
    logger: logging.Logger | None = None,
) -> TargetIdentity:
    """Resolve the final ``(hostname, domain)`` for SystemContext.

    Precedence (first non-empty wins):

    1. Operator overrides (``--hostname-override`` / ``--domain-override``).
       Already validated at the CLI boundary via
       :func:`validate_forensic_string`. These exist precisely for the
       cases where the collector is blind (stock iOS sandbox, locked-
       down target) and the operator knows the identity out-of-band.
    2. Collector-supplied values (the per-platform
       ``collect_system_info()`` result).
    3. **Local-only** fallback: ``socket.gethostname()`` for the
       hostname. **Never fires on remote targets** — falling back to the
       acquisition host's name would silently attribute the MSL to the
       wrong machine.

    Any time the resolution yields an empty value on a remote target, a
    warning is logged and appended to the returned warnings list so the
    caller can surface it in the MSL log / os_detail provenance.
    """
    log = logger or logging.getLogger("memslicer")
    warnings: list[str] = []

    # 1. Operator overrides.
    if hostname_override:
        hostname = hostname_override
    else:
        hostname = collector_hostname or ""

    if domain_override:
        domain = domain_override
    else:
        domain = collector_domain or ""

    # 2. Local-target fallback ONLY.
    if not hostname:
        if is_remote:
            log.warning(
                "remote target hostname unavailable from collector; "
                "leaving empty (use --hostname-override to set)"
            )
            warnings.append("remote_hostname_unavailable")
        else:
            try:
                hostname = socket.gethostname()
            except OSError as exc:
                log.debug("socket.gethostname() failed: %s", exc)
                warnings.append("local_hostname_unavailable")

    return TargetIdentity(
        hostname=hostname,
        domain=domain,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Attribution config + shared CLI plumbing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttributionConfig:
    """Operator-supplied attribution plus privacy gates.

    One object threaded through ``cli`` → ``_create_acquirer`` →
    ``AcquisitionEngine`` and through ``cli_sysctx.main`` →
    ``_collect_all``. Collapsing the seven-kwarg sprawl into a single
    value means any new attribution field added later touches one
    dataclass instead of five call sites.

    Construct via :func:`validate_attribution` from CLI options — the
    string fields are validated at that boundary, so anything that
    lives inside an instance is safe to embed in ``SystemContext``.
    """

    examiner: str = ""
    case_ref: str = ""
    hostname_override: str = ""
    domain_override: str = ""
    is_remote: bool = False
    include_serials: bool = False
    include_network_identity: bool = False
    include_fingerprint: bool = False


def validate_attribution(
    examiner: str = "",
    case_ref: str = "",
    hostname_override: str = "",
    domain_override: str = "",
    *,
    is_remote: bool = False,
    include_serials: bool = False,
    include_network_identity: bool = False,
    include_fingerprint: bool = False,
) -> AttributionConfig:
    """Run :func:`validate_forensic_string` on each operator-supplied string.

    Raises :class:`ForensicStringError` on the first invalid value, so
    the CLI layer can translate to ``click.BadParameter`` once.
    """
    return AttributionConfig(
        examiner=validate_forensic_string(examiner, field_name="--examiner"),
        case_ref=validate_forensic_string(case_ref, field_name="--case-ref"),
        hostname_override=validate_forensic_string(
            hostname_override, field_name="--hostname-override",
        ),
        domain_override=validate_forensic_string(
            domain_override, field_name="--domain-override",
        ),
        is_remote=is_remote,
        include_serials=include_serials,
        include_network_identity=include_network_identity,
        include_fingerprint=include_fingerprint,
    )


# ---------------------------------------------------------------------------
# OS-type dispatch
# ---------------------------------------------------------------------------

_OS_OVERRIDE_MAP = {
    "windows": OSType.Windows,
    "linux": OSType.Linux,
    "macos": OSType.macOS,
    "android": OSType.Android,
    "ios": OSType.iOS,
}


def infer_os_type(os_override: str | None) -> OSType:
    """Resolve the ``--os`` CLI flag (or host auto-detect) to an :class:`OSType`.

    Single source of truth shared by the acquire CLI's
    ``_create_acquirer`` collector dispatch and the ``system-context``
    CLI's ``_make_collector``.
    """
    if os_override:
        return _OS_OVERRIDE_MAP[os_override]
    if sys.platform.startswith("linux"):
        return OSType.Linux
    if sys.platform == "darwin":
        return OSType.macOS
    if sys.platform == "win32":
        return OSType.Windows
    return OSType.Unknown


# ---------------------------------------------------------------------------
# Shared click-option decorator
# ---------------------------------------------------------------------------

_F = TypeVar("_F", bound=Callable[..., object])


def attribution_options(func: _F) -> _F:
    """Stack the six operator-attribution click options onto a command.

    Used by both the acquire CLI and ``memslicer-sysctx`` so flag
    naming and help text stay identical. Option order is reversed
    because ``click.option`` decorators apply bottom-up and we want
    ``--examiner`` to appear first in ``--help`` output.
    """
    import click  # local import — identity.py stays importable without click

    options = [
        click.option(
            "--include-fingerprint", "include_fingerprint",
            is_flag=True, default=False,
            help="Emit ro.build.fingerprint in os_detail (Android; leaks device+region+carrier+build-date)",
        ),
        click.option(
            "--include-network-identity", "include_network_identity",
            is_flag=True, default=False,
            help="Emit NIC MAC addresses in os_detail (privacy-sensitive)",
        ),
        click.option(
            "--include-serials", "include_serials",
            is_flag=True, default=False,
            help="Emit hardware serials / machine-id in os_detail (privacy-sensitive)",
        ),
        click.option(
            "--domain-override", "domain_override", default="",
            help="Override collected domain",
        ),
        click.option(
            "--hostname-override", "hostname_override", default="",
            help="Override collected hostname (use when remote collector is blind)",
        ),
        click.option(
            "--case-ref", "--case-id", "--case-number", "case_ref", default="",
            help="Case / evidence reference for SystemContext.case_ref",
        ),
        click.option(
            "--examiner", "--operator", "examiner", default="",
            help=(
                "Examiner / operator name for SystemContext.acq_user "
                "(defaults to getpass.getuser())"
            ),
        ),
    ]
    for opt in options:
        func = opt(func)
    return func


__all__ = (
    "MAX_FORENSIC_STRING_LEN",
    "AttributionConfig",
    "ForensicStringError",
    "TargetIdentity",
    "attribution_options",
    "infer_os_type",
    "resolve_target_identity",
    "validate_attribution",
    "validate_forensic_string",
)
