"""``OSDetail`` microformat: pack/parse helpers.

MSL Section 6.2 defines ``OSDetail`` as an opaque UTF-8 string. To carry
forensically-valuable enrichment (machine_id, hw_vendor, bios, cpu, ram,
tz, virt, secure_boot, disk_enc, selinux, nic_macs, …) while staying
spec-conformant, we pack structured data into that string using a simple
microformat:

.. code-block:: text

    msl.memslicer/1 <human readable OS string> | k1=v1;k2=v2;k3=v3

**Design principles**

- **Backward-compatible.** A naive consumer that reads ``OSDetail`` as a
  plain string sees a sensible OS description first
  (``Ubuntu 24.04.1 LTS (6.8.0-45-generic x86_64)``). Informed consumers
  split on the ``" | "`` delimiter and parse the k=v block.
- **Producer-scoped.** The ``msl.memslicer/1`` prefix is a producer
  namespace + schema version. If another producer ships a different
  microformat, consumers can detect and route on the prefix.
- **Key-absent means "not collected".** Empty values are dropped entirely
  rather than emitted as ``key=`` — so a parser can distinguish
  "collected as empty" from "not collected" unambiguously.
- **Redaction awareness.** When policy strips a collected value
  post-capture, the packer inserts a ``redacted_keys=k1,k2`` marker
  inside the k=v block. The header-level ``Redacted`` bit (§6.6) is set
  by the caller based on the ``TargetSystemInfo.redacted_keys`` list.
- **Size-safe.** Wire ``OSDetailLen`` is ``uint16`` (max 65535). The
  packer enforces a **hard cap** (60 KiB, leaving room for NUL + pad8)
  and a **soft budget** (4 KiB) beyond which lowest-priority keys are
  truncated and a ``truncated=1`` marker is appended. This protects
  against pathological hosts (many NICs + long vendor strings).
- **Injection-safe.** ``\\x00`` / ``;`` / ``=`` / ``\\n`` / ``|`` / ``%``
  are percent-encoded in values so the format cannot be spoofed via a
  crafted hardware model string or ``--case-ref``.
"""
from __future__ import annotations

from typing import Iterable, Mapping


# Microformat schema identifier. Bump the ``/N`` suffix on breaking
# changes (new reserved key, changed delimiter, …). Parsers match this
# prefix exactly and fall through to "opaque string" on mismatch.
SCHEMA_PREFIX = "msl.memslicer/1 "
DELIMITER = " | "

# Wire-level hard cap: spec ``OSDetailLen`` is uint16 (65535), and the
# writer appends a trailing NUL (see writer.py), so we leave headroom.
HARD_CAP_BYTES = 60 * 1024

# Soft target: packer starts dropping lowest-priority keys beyond this
# to keep typical output readable and bounded.
SOFT_BUDGET_BYTES = 4 * 1024

# Characters that MUST be escaped in packed values. Percent-encoded as
# ``%HH`` (uppercase hex) — the parser reverses this mapping.
_RESERVED_CHARS = "\x00;=\n|%"


# ---------------------------------------------------------------------------
# Field ordering
# ---------------------------------------------------------------------------

# Emit order for the packer. Lower-priority keys at the tail get dropped
# first when the soft budget is exceeded (truncation policy).
#
# Grouped per the plan's forensic categorization:
#   1. Identity (stable across boots) — most durable, always wanted
#   2. Boot state (per-boot) — anchors the slice
#   3. Runtime posture (mutable) — security posture at capture time
#   4. Network identity (opt-in, privacy-gated)
#   5. Provenance — attached last, never truncated unless all else fails
FIELD_ORDER: tuple[str, ...] = (
    # 1. identity
    "distro", "kernel", "arch",
    "machine_id",
    "hw_vendor", "hw_model", "hw_serial",
    "bios", "cpu", "cpu_count", "ram",
    # 2. boot state
    "boot_id", "virt",
    # 3. runtime posture
    "secure_boot", "disk_enc", "selinux", "apparmor", "tz",
    # 4. network identity
    "nic_macs",
    # 5. provenance (never omitted if present)
    "mode",
    "collector_caps",
    "redacted_keys",
    "truncated",
)

# Which keys survive aggressive truncation. The provenance keys are
# cheap and diagnostically critical: an analyst must always be able to
# tell whether a field was stripped, timed out, or never collected.
_PROVENANCE_KEYS = frozenset({
    "mode", "collector_caps", "redacted_keys", "truncated",
})


# ---------------------------------------------------------------------------
# Value escaping
# ---------------------------------------------------------------------------

def _escape_value(value: str) -> str:
    """Percent-encode the reserved set in ``value``.

    Keeps the output UTF-8-safe (non-ASCII bytes pass through untouched;
    only the tight reserved set is encoded). This is the minimum escaping
    necessary to make the k=v grammar unambiguous; it is **not** a
    general-purpose URL encoder.
    """
    out = []
    for ch in value:
        if ch in _RESERVED_CHARS:
            out.append(f"%{ord(ch):02X}")
        else:
            out.append(ch)
    return "".join(out)


def _unescape_value(value: str) -> str:
    """Reverse :func:`_escape_value`.

    Only decodes ``%HH`` where ``HH`` names a reserved character; stray
    percent sequences are left untouched so real hardware model strings
    containing ``%`` don't round-trip mangled. Invalid sequences fall
    back to the literal text.
    """
    if "%" not in value:
        return value
    out = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "%" and i + 2 < n:
            hi = value[i + 1]
            lo = value[i + 2]
            try:
                code = int(hi + lo, 16)
            except ValueError:
                out.append(ch)
                i += 1
                continue
            decoded = chr(code)
            if decoded in _RESERVED_CHARS:
                out.append(decoded)
                i += 3
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _valid_key(key: str) -> bool:
    """Allowed keys: ASCII ``[a-z0-9_]+``. Enforced in the packer.

    Rejecting anything else means we never need to escape keys — they're
    ASCII-safe by construction and cannot collide with the reserved set.
    """
    if not key:
        return False
    return all(
        ("a" <= c <= "z") or ("0" <= c <= "9") or c == "_"
        for c in key
    )


# ---------------------------------------------------------------------------
# Human-readable prefix builder
# ---------------------------------------------------------------------------

def build_human_os_string(
    *,
    distro: str = "",
    kernel: str = "",
    arch: str = "",
    raw_os: str = "",
) -> str:
    """Compose the leading human-readable OS string for ``OSDetail``.

    Priority: ``distro`` if present, else ``raw_os``, else ``"unknown OS"``.
    ``kernel`` and ``arch`` are appended in parentheses when available so
    analysts see something meaningful without decoding the microformat:

        Ubuntu 24.04.1 LTS (6.8.0-45-generic x86_64)
    """
    base = distro or raw_os or "unknown OS"
    extras: list[str] = []
    if kernel:
        extras.append(kernel)
    if arch:
        extras.append(arch)
    if extras:
        return f"{base} ({' '.join(extras)})"
    return base


# ---------------------------------------------------------------------------
# Pack
# ---------------------------------------------------------------------------

def pack_os_detail(
    fields: Mapping[str, object],
    *,
    human_prefix: str | None = None,
    hard_cap_bytes: int = HARD_CAP_BYTES,
    soft_budget_bytes: int = SOFT_BUDGET_BYTES,
) -> str:
    """Pack a mapping of enrichment fields into the ``OSDetail`` microformat.

    ``fields`` keys must be ``[a-z0-9_]+``; values are coerced to ``str``,
    percent-encoded against the reserved set, and emitted in
    :data:`FIELD_ORDER` (unknown keys follow, sorted, for determinism).

    - **Empty values** (``""`` / ``0`` / ``None`` / empty list) are
      **omitted entirely** — never emitted as ``key=``. This is a hard
      invariant: parsers must be able to distinguish "collected but
      empty" from "not collected," and we reserve the former as "not
      collected" because it's the only interpretation the spec allows
      via the header ``Redacted`` bit.

    - **``nic_macs`` list** values are joined with commas.

    - **Size policy**: if the naive packed output exceeds
      ``soft_budget_bytes``, non-provenance keys are dropped from the
      tail until the output fits, and a ``truncated=1`` marker is
      appended. If even after that it exceeds ``hard_cap_bytes`` (this
      would only happen if provenance alone is huge), the output is
      blindly byte-truncated with ``truncated=hard`` as the tail marker
      — never longer than the cap.

    The ``human_prefix`` argument lets callers override the leading
    human-readable string. If ``None``, it is derived from the
    ``distro``/``kernel``/``arch``/``raw_os`` keys inside ``fields``
    (they stay in the k=v block too — the prefix is additive).
    """
    prefix = human_prefix
    if prefix is None:
        prefix = build_human_os_string(
            distro=str(fields.get("distro") or ""),
            kernel=str(fields.get("kernel") or ""),
            arch=str(fields.get("arch") or ""),
            raw_os=str(fields.get("raw_os") or ""),
        )

    # Build ordered (key, escaped_value) pairs, dropping empties.
    ordered_pairs: list[tuple[str, str]] = []

    def _maybe_add(key: str, raw: object) -> None:
        if not _valid_key(key):
            return
        if raw is None:
            return
        # bool is a subclass of int; check it first so a true ``bool``
        # isn't misclassified as a nonzero int. A *false* bool is treated
        # as "not collected" (same contract as 0 / "" / []) — callers who
        # need to emit a literal ``key=0`` should pass the string ``"0"``.
        if isinstance(raw, bool):
            if not raw:
                return
            text = "1"
        elif isinstance(raw, (list, tuple)):
            if not raw:
                return
            text = ",".join(str(v) for v in raw if str(v))
        elif isinstance(raw, int):
            # Treat ``0`` as "not collected" so an uninitialized ``cpu_count``
            # default never reaches the wire. Callers that need to emit a
            # literal zero should pass the string ``"0"``.
            if raw == 0:
                return
            text = str(raw)
        else:
            text = str(raw)
        if not text:
            return
        ordered_pairs.append((key, _escape_value(text)))

    seen: set[str] = set()
    for key in FIELD_ORDER:
        if key in fields:
            _maybe_add(key, fields[key])
            seen.add(key)

    # Surface any unknown keys deterministically (sorted) so the output
    # is stable for golden-file tests.
    for key in sorted(fields.keys()):
        if key in seen:
            continue
        _maybe_add(key, fields[key])

    def _render(pairs: list[tuple[str, str]]) -> str:
        body = ";".join(f"{k}={v}" for k, v in pairs)
        if prefix and body:
            return f"{SCHEMA_PREFIX}{prefix}{DELIMITER}{body}"
        if prefix:
            return f"{SCHEMA_PREFIX}{prefix}"
        if body:
            return f"{SCHEMA_PREFIX}{DELIMITER.strip()} {body}".rstrip()
        return SCHEMA_PREFIX.rstrip()

    rendered = _render(ordered_pairs)

    # Soft-budget truncation: drop lowest-priority (tail) non-provenance
    # keys one at a time until we fit, then mark the result truncated.
    if len(rendered.encode("utf-8")) > soft_budget_bytes:
        droppable = [
            i for i, (k, _) in enumerate(ordered_pairs)
            if k not in _PROVENANCE_KEYS
        ]
        truncation_applied = False
        while droppable and len(rendered.encode("utf-8")) > soft_budget_bytes:
            drop_at = droppable.pop()  # drop from tail
            ordered_pairs.pop(drop_at)
            # Indices in droppable beyond drop_at are invalidated; rebuild.
            droppable = [
                i for i, (k, _) in enumerate(ordered_pairs)
                if k not in _PROVENANCE_KEYS
            ]
            truncation_applied = True
            rendered = _render(ordered_pairs)

        if truncation_applied:
            # Ensure the truncation marker is present / updated.
            ordered_pairs = [
                (k, v) for (k, v) in ordered_pairs if k != "truncated"
            ]
            ordered_pairs.append(("truncated", _escape_value("1")))
            rendered = _render(ordered_pairs)

    # Hard cap: last-resort blind truncation with a marker.
    if len(rendered.encode("utf-8")) > hard_cap_bytes:
        # Force a bytes-safe slice (respect UTF-8 boundaries).
        raw = rendered.encode("utf-8")[: hard_cap_bytes - 16]
        # Back off to a valid UTF-8 prefix.
        while raw:
            try:
                text = raw.decode("utf-8")
                break
            except UnicodeDecodeError:
                raw = raw[:-1]
        else:
            text = ""
        rendered = text + ";truncated=hard"

    return rendered


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

def parse_os_detail(value: str) -> dict[str, str]:
    """Parse an ``OSDetail`` string into a ``{key: value}`` dict.

    Accepts three input shapes:

    - **Microformat** (``msl.memslicer/1 <human> | k1=v1;k2=v2``):
      the k=v block is decoded; the human prefix is returned under the
      synthetic key ``_human``.
    - **Microformat without delimiter** (``msl.memslicer/1 <human>``):
      only ``_human`` is populated.
    - **Opaque string** (no schema prefix): returned as ``{"_human": value}``.
      This is the graceful-degradation path for MSL files produced by
      other tooling or older versions of this producer.

    The parser never raises on malformed input (hypothesis-tested) —
    adversarial strings return best-effort partial dicts. Keys that fail
    :func:`_valid_key` are dropped silently.
    """
    if not isinstance(value, str):
        return {}

    if not value.startswith(SCHEMA_PREFIX):
        return {"_human": value} if value else {}

    remainder = value[len(SCHEMA_PREFIX):]
    if DELIMITER in remainder:
        human, _, kv_block = remainder.partition(DELIMITER)
    else:
        human, kv_block = remainder, ""

    out: dict[str, str] = {}
    if human:
        out["_human"] = human

    if kv_block:
        for pair in kv_block.split(";"):
            if "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            k = k.strip()
            if not _valid_key(k):
                continue
            out[k] = _unescape_value(v)

    return out


def system_info_to_fields(
    sys_info,
    *,
    include_serials: bool = False,
    include_network_identity: bool = False,
    include_fingerprint: bool = False,
    include_kernel_symbols: bool = True,
) -> dict[str, object]:
    """Project a :class:`TargetSystemInfo` onto the packer's field map.

    Privacy gates (closed by default):

    - ``include_serials`` opens ``machine_id`` and ``hw_serial``. Not
      passing the flag leaves both absent from the output (the
      ``os_detail`` microformat omits keys with no value — see the
      ``pack_os_detail`` contract).
    - ``include_network_identity`` opens ``nic_macs``.

    Both the acquire CLI and ``memslicer-sysctx`` call this so the
    wire output and the read-only inspector share one source of truth
    for what ends up in ``os_detail``.
    """
    fields: dict[str, object] = {
        # Identity
        "distro": sys_info.distro,
        "kernel": sys_info.kernel,
        "arch": sys_info.arch,
        "raw_os": sys_info.raw_os or sys_info.os_detail,
        "hw_vendor": sys_info.hw_vendor,
        "hw_model": sys_info.hw_model,
        "bios": sys_info.bios_version,
        "cpu": sys_info.cpu_brand,
        "cpu_count": sys_info.cpu_count,
        "ram": sys_info.ram_bytes,
        # Boot state
        "boot_id": sys_info.boot_id,
        "virt": sys_info.virtualization,
        # Runtime posture
        "secure_boot": sys_info.secure_boot,
        "disk_enc": sys_info.disk_encryption,
        "selinux": sys_info.selinux,
        "apparmor": sys_info.apparmor,
        "tz": sys_info.timezone,
        # Provenance
        "mode": sys_info.mode,
        "truncated": sys_info.truncated,
    }
    if include_serials:
        fields["machine_id"] = sys_info.machine_id
        fields["hw_serial"] = sys_info.hw_serial
    if include_network_identity:
        fields["nic_macs"] = list(sys_info.nic_macs or [])
    # Android enrichment (non-privacy-sensitive except fingerprint).
    # Emitted unconditionally — projector leaves empty strings which
    # pack_os_detail drops. ``fingerprint`` is privacy-gated.
    fields.update({
        "patch_level": getattr(sys_info, "patch_level", ""),
        "verified_boot": getattr(sys_info, "verified_boot", ""),
        "bootloader_locked": getattr(sys_info, "bootloader_locked", ""),
        "dm_verity": getattr(sys_info, "dm_verity", ""),
        "build_type": getattr(sys_info, "build_type", ""),
        "crypto_type": getattr(sys_info, "crypto_type", ""),
        "env": getattr(sys_info, "env", ""),
        "root_method": getattr(sys_info, "root_method", ""),
    })
    # P1.5: Linux kernel/posture enrichment (empty-string-safe on other
    # platforms; pack_os_detail drops empty values).
    fields.update({
        "kernel_cmdline":    getattr(sys_info, "kernel_cmdline", ""),
        "kernel_tainted":    getattr(sys_info, "kernel_tainted", ""),
        "lsm_stack":         getattr(sys_info, "lsm_stack", ""),
        "yama_ptrace_scope": getattr(sys_info, "yama_ptrace_scope", ""),
        "aslr_mode":         getattr(sys_info, "aslr_mode", ""),
        "efi_mode":          getattr(sys_info, "efi_mode", ""),
        "container_scope":   getattr(sys_info, "container_scope", ""),
        "container_runtime": getattr(sys_info, "container_runtime", ""),
        "ns_fingerprint":    getattr(sys_info, "ns_fingerprint", ""),
    })
    # P1.6.2: module / loader posture (empty-string-safe).
    fields.update({
        "ld_so_preload":     getattr(sys_info, "ld_so_preload", ""),
        "kernel_lockdown":   getattr(sys_info, "kernel_lockdown", ""),
        "modules_disabled":  getattr(sys_info, "modules_disabled", ""),
        "module_sig_enforce": getattr(sys_info, "module_sig_enforce", ""),
    })
    # P1.6.4: rootkit / anti-forensics / sysctl posture (empty-string-safe).
    # All 26 fields projected unconditionally — host posture, no gating.
    # ``pack_os_detail`` drops empty values automatically.
    fields.update({
        # Decoded kernel posture
        "taint_decoded":             getattr(sys_info, "taint_decoded", ""),
        "kexec_loaded":              getattr(sys_info, "kexec_loaded", ""),
        "wtmp_size":                 getattr(sys_info, "wtmp_size", 0),
        "wtmp_mtime_ns":             getattr(sys_info, "wtmp_mtime_ns", 0),
        "utmp_size":                 getattr(sys_info, "utmp_size", 0),
        "btmp_size":                 getattr(sys_info, "btmp_size", 0),
        "lastlog_size":              getattr(sys_info, "lastlog_size", 0),
        "hidden_pid_count":          getattr(sys_info, "hidden_pid_count", 0),
        # Security sysctls
        "kptr_restrict":             getattr(sys_info, "kptr_restrict", ""),
        "dmesg_restrict":            getattr(sys_info, "dmesg_restrict", ""),
        "perf_event_paranoid":       getattr(sys_info, "perf_event_paranoid", ""),
        "unprivileged_bpf_disabled": getattr(sys_info, "unprivileged_bpf_disabled", ""),
        "unprivileged_userns_clone": getattr(sys_info, "unprivileged_userns_clone", ""),
        "kexec_load_disabled":       getattr(sys_info, "kexec_load_disabled", ""),
        "sysrq_state":               getattr(sys_info, "sysrq_state", ""),
        "core_pattern":              getattr(sys_info, "core_pattern", ""),
        "suid_dumpable":             getattr(sys_info, "suid_dumpable", ""),
        "protected_symlinks":        getattr(sys_info, "protected_symlinks", ""),
        "protected_hardlinks":       getattr(sys_info, "protected_hardlinks", ""),
        "protected_fifos":           getattr(sys_info, "protected_fifos", ""),
        "protected_regular":         getattr(sys_info, "protected_regular", ""),
        "bpf_jit_enable":            getattr(sys_info, "bpf_jit_enable", ""),
        # auditd / journald / time / CPU-vulnerabilities posture
        "audit_state":               getattr(sys_info, "audit_state", ""),
        "audit_rules_count":         getattr(sys_info, "audit_rules_count", 0),
        "journald_storage":          getattr(sys_info, "journald_storage", ""),
        "ntp_sync":                  getattr(sys_info, "ntp_sync", ""),
        "cpu_vuln_digest":           getattr(sys_info, "cpu_vuln_digest", ""),
    })
    # collector_caps is already listed in FIELD_ORDER as a provenance key;
    # project it from the structured field so it survives truncation.
    fields["collector_caps"] = getattr(sys_info, "collector_caps", "")
    if include_fingerprint:
        fields["fingerprint"] = getattr(sys_info, "fingerprint", "")
    # P1.6.1: memory-forensics anchors (opt-out via --no-include-kernel-symbols).
    # Scalar anchors only; list-typed ``physmem_ranges`` is emitted via the
    # dedicated ``write_physical_memory_map`` block in a later sub-phase.
    if include_kernel_symbols:
        fields.update({
            "page_size":            getattr(sys_info, "page_size", 0),
            "kernel_build_id":      getattr(sys_info, "kernel_build_id", ""),
            "kaslr_text_va":        getattr(sys_info, "kaslr_text_va", 0),
            "kernel_page_offset":   getattr(sys_info, "kernel_page_offset", 0),
            "la57_enabled":         getattr(sys_info, "la57_enabled", ""),
            "pti_active":           getattr(sys_info, "pti_active", ""),
            "btf_sha256":           getattr(sys_info, "btf_sha256", ""),
            "btf_size_bytes":       getattr(sys_info, "btf_size_bytes", 0),
            "vmcoreinfo_sha256":    getattr(sys_info, "vmcoreinfo_sha256", ""),
            "vmcoreinfo_present":   getattr(sys_info, "vmcoreinfo_present", ""),
            "kernel_config_sha256": getattr(sys_info, "kernel_config_sha256", ""),
            "clock_realtime_ns":    getattr(sys_info, "clock_realtime_ns", 0),
            "clock_monotonic_ns":   getattr(sys_info, "clock_monotonic_ns", 0),
            "clock_boottime_ns":    getattr(sys_info, "clock_boottime_ns", 0),
            "clocksource":          getattr(sys_info, "clocksource", ""),
            "zram_devices":         getattr(sys_info, "zram_devices", ""),
            "zswap_enabled":        getattr(sys_info, "zswap_enabled", ""),
            "thp_mode":             getattr(sys_info, "thp_mode", ""),
            "ksm_active":           getattr(sys_info, "ksm_active", ""),
            "directmap_4k":         getattr(sys_info, "directmap_4k", 0),
            "directmap_2m":         getattr(sys_info, "directmap_2m", 0),
            "directmap_1g":         getattr(sys_info, "directmap_1g", 0),
        })
    return fields


def target_info_to_fields(
    proc_info,
    *,
    include_environ: bool = False,
) -> dict[str, object]:
    """Project a :class:`TargetProcessInfo` onto a key/value dict for
    CLI rendering.

    Used by ``cli_sysctx.py`` to render the per-target introspection
    fields in plain / rich / JSON output. **Not** used for wire
    emission — wire data is carried by the ``TargetIntrospection``
    block (0x0058) via :meth:`MSLWriter.write_target_introspection`.

    Every populated field is projected with a ``target_`` prefix.
    Empty / zero values are dropped (same "absent means not collected"
    convention as :func:`system_info_to_fields`). ``include_environ``
    gates the two privacy-sensitive fields.
    """
    fields: dict[str, object] = {}
    attrs = (
        # Baseline identity.
        "ppid", "session_id", "start_time_ns", "exe_path", "cmd_line",
        "process_name", "package",
        # P1.6.3 introspection (non-environ).
        "tracer_pid", "login_uid", "session_audit_id",
        "selinux_context", "target_ns_fingerprint",
        "target_ns_scope_vs_collector",
        "smaps_rollup_pss_kib", "smaps_rollup_swap_kib",
        "smaps_anon_hugepages_kib", "rwx_region_count",
        "target_cgroup", "target_cwd", "target_root",
        "cap_eff", "cap_amb", "no_new_privs", "seccomp_mode",
        "core_dumping", "thread_count", "sig_cgt",
        "io_rchar", "io_wchar", "io_read_bytes", "io_write_bytes",
        "limit_core", "limit_memlock", "limit_nofile",
        "personality_hex", "ancestry", "exe_comm_mismatch",
    )
    for attr in attrs:
        value = getattr(proc_info, attr, None)
        if value is None or value == 0 or value == "" or value == b"":
            continue
        fields[f"target_{attr}"] = value

    if include_environ:
        environ_value = getattr(proc_info, "environ", "")
        if environ_value:
            fields["target_environ"] = environ_value
        redacted = getattr(proc_info, "redacted_env_keys", None)
        if redacted:
            fields["target_redacted_env_keys"] = list(redacted)
    return fields


__all__: Iterable[str] = (
    "DELIMITER",
    "FIELD_ORDER",
    "HARD_CAP_BYTES",
    "SCHEMA_PREFIX",
    "SOFT_BUDGET_BYTES",
    "build_human_os_string",
    "pack_os_detail",
    "parse_os_detail",
    "system_info_to_fields",
    "target_info_to_fields",
)
