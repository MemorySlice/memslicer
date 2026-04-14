"""Protocol and data types for investigation-mode data collection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from memslicer.msl.types import (
    ProcessEntry, ConnectionEntry, HandleEntry, ConnectivityTable,
    KernelModuleList, PersistenceManifest,
)


@dataclass
class TargetProcessInfo:
    """Process identity metadata collected from the target system."""
    ppid: int = 0
    session_id: int = 0
    start_time_ns: int = 0
    exe_path: str = ""
    cmd_line: str = ""
    # Android-only: argv[0] from /proc/pid/cmdline (package process name,
    # e.g. "com.whatsapp:pushservice") and the package identifier derived
    # from it (argv[0].split(":")[0]). Other platforms leave these empty.
    process_name: str = ""
    package: str = ""

    # ------------------------------------------------------------------
    # P1.6.3: per-target introspection (gated by
    # ``include_target_introspection``; Linux-primary, other collectors
    # leave them at empty/zero defaults).
    # ------------------------------------------------------------------
    tracer_pid: int = 0
    login_uid: int = 0
    session_audit_id: int = 0
    selinux_context: str = ""
    target_ns_fingerprint: str = ""
    target_ns_scope_vs_collector: str = ""
    smaps_rollup_pss_kib: int = 0
    smaps_rollup_swap_kib: int = 0
    smaps_anon_hugepages_kib: int = 0
    rwx_region_count: int = 0
    target_cgroup: str = ""
    target_cwd: str = ""
    target_root: str = ""
    cap_eff: str = ""
    cap_amb: str = ""
    no_new_privs: int = 0           # 0 or 1
    seccomp_mode: int = 0           # 0=disabled, 1=strict, 2=filter
    core_dumping: int = 0           # 0 or 1
    thread_count: int = 0
    sig_cgt: str = ""
    io_rchar: int = 0
    io_wchar: int = 0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    limit_core: str = ""
    limit_memlock: str = ""
    limit_nofile: str = ""
    personality_hex: str = ""
    ancestry: str = ""
    exe_comm_mismatch: int = 0      # 0 or 1
    # Privacy-gated (``include_environ``)
    environ: str = ""
    redacted_env_keys: list[str] = field(default_factory=list)


@dataclass
class TargetSystemInfo:
    """System-level metadata collected from the target system.

    The four **core** fields (``boot_time``, ``hostname``, ``domain``,
    ``os_detail``) map directly to Section 6.2 ``SystemContext`` slots
    and are the only fields written to the wire.

    The **enrichment** fields below are gathered by per-platform
    collectors and projected into the ``os_detail`` microformat by
    :func:`memslicer.acquirer.os_detail.system_info_to_fields`. They
    stay as structured fields here (rather than being stuffed into
    ``os_detail`` directly) so the ``system-context`` CLI can render
    them typed — numbers as numbers, MAC lists as lists — instead of
    parsing a flat string.

    All enrichment fields default to empty / zero so collectors that
    populate none of them still build a valid instance.
    """

    # ------------------------------------------------------------------
    # Core wire fields (Section 6.2, written to SystemContext block).
    # ------------------------------------------------------------------
    boot_time: int = 0        # nanoseconds since epoch
    hostname: str = ""
    domain: str = ""
    os_detail: str = ""

    # ------------------------------------------------------------------
    # Enrichment: identity (stable across boots).
    # ------------------------------------------------------------------
    kernel: str = ""          # e.g. "6.8.0-45-generic"
    arch: str = ""            # e.g. "x86_64" / "arm64"
    distro: str = ""          # e.g. "Ubuntu 24.04.1 LTS"
    raw_os: str = ""          # producer's raw os string (platform.platform() etc.)
    machine_id: str = ""      # e.g. /etc/machine-id or IOPlatformUUID (privacy-class)
    hw_vendor: str = ""       # e.g. "Dell Inc." / "Apple"
    hw_model: str = ""        # e.g. "Latitude 7440" / "MacBookPro18,2"
    hw_serial: str = ""       # privacy-class (--include-serials)
    bios_version: str = ""
    cpu_brand: str = ""       # e.g. "Intel(R) Core(TM) Ultra 7 155H"
    cpu_count: int = 0
    ram_bytes: int = 0

    # ------------------------------------------------------------------
    # Enrichment: boot state (per-boot).
    # ------------------------------------------------------------------
    boot_id: str = ""         # e.g. /proc/sys/kernel/random/boot_id
    virtualization: str = ""  # "none" / "hypervisor" / "docker" / "vmware" / ...

    # ------------------------------------------------------------------
    # Enrichment: runtime posture (mutable).
    # ------------------------------------------------------------------
    secure_boot: str = ""     # "1" / "0" / ""
    disk_encryption: str = "" # "luks" / "filevault" / "bitlocker" / "none" / ""
    selinux: str = ""         # "enforcing" / "permissive" / "disabled" / "n/a"
    apparmor: str = ""        # "enabled" / "disabled" / ""
    timezone: str = ""        # IANA zone, e.g. "Europe/Berlin"

    # ------------------------------------------------------------------
    # Enrichment: network identity (opt-in, --include-network-identity).
    # ------------------------------------------------------------------
    nic_macs: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Enrichment: Android-specific (also applicable to non-Android where
    # relevant). Populated by AndroidCollector; other collectors leave
    # them as empty strings.
    # ------------------------------------------------------------------
    fingerprint: str = ""           # Android ro.build.fingerprint (privacy-gated)
    patch_level: str = ""           # Android security_patch date
    verified_boot: str = ""         # "green" / "yellow" / "orange" / "red"
    bootloader_locked: str = ""     # "1" / "0" / ""
    dm_verity: str = ""             # "enforcing" / "logging" / "disabled" / ""
    build_type: str = ""            # "user" / "userdebug" / "eng"
    crypto_type: str = ""           # "file" / "block" / "none" / ""
    env: str = ""                   # "physical" / "emulator" / "cuttlefish" / "waydroid" / "genymotion"
    root_method: str = ""           # advisory: "magisk" / "kernelsu" / "apatch" / "zygisk" / ""

    # ------------------------------------------------------------------
    # Enrichment: Linux kernel/posture (P1.5 — Linux-specific).
    # All additive; other platforms leave them empty.
    # ------------------------------------------------------------------
    kernel_cmdline: str = ""          # /proc/cmdline
    kernel_tainted: str = ""          # /proc/sys/kernel/tainted (decimal)
    lsm_stack: str = ""               # /sys/kernel/security/lsm (comma list)
    yama_ptrace_scope: str = ""       # /proc/sys/kernel/yama/ptrace_scope (0-3)
    aslr_mode: str = ""               # /proc/sys/kernel/randomize_va_space (0/1/2)
    efi_mode: str = ""                # "1" if /sys/firmware/efi/ exists else ""
    collector_caps: str = ""          # hex CapEff from /proc/self/status (or Win token)
    container_scope: str = ""         # "host" / "container" / "partial" / ""
    container_runtime: str = ""       # "docker" / "podman" / "lxc" / "kubernetes" / ""
    ns_fingerprint: str = ""          # comma-separated ns inodes

    # ------------------------------------------------------------------
    # Enrichment: memory-forensics anchors (P1.6.1 — Linux-primary).
    # All additive; other platforms leave them empty/zero. See
    # :class:`memslicer.msl.types.KernelSymbolBundle` for the wire-level
    # counterpart written by ``write_kernel_symbol_bundle``.
    # ------------------------------------------------------------------
    page_size: int = 0
    kernel_build_id: str = ""
    kaslr_text_va: int = 0
    kernel_page_offset: int = 0
    la57_enabled: str = ""              # "1" / "0" / ""
    pti_active: str = ""                # "1" / "0" / ""
    btf_sha256: str = ""
    btf_size_bytes: int = 0
    vmcoreinfo_sha256: str = ""
    vmcoreinfo_present: str = ""        # "1" / "0" / ""
    kernel_config_sha256: str = ""
    clock_realtime_ns: int = 0
    clock_monotonic_ns: int = 0
    clock_boottime_ns: int = 0
    clocksource: str = ""
    zram_devices: str = ""              # comma-separated "name:size:algo"
    zswap_enabled: str = ""             # "1" / "0" / ""
    thp_mode: str = ""                  # "always" / "madvise" / "never"
    ksm_active: str = ""                # "1" / "0" / ""
    directmap_4k: int = 0               # KiB (from /proc/meminfo)
    directmap_2m: int = 0
    directmap_1g: int = 0
    physmem_ranges: list[tuple[int, int, str]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Enrichment: module / loader posture (P1.6.2 — Linux-primary).
    # ------------------------------------------------------------------
    ld_so_preload: str = ""           # /etc/ld.so.preload content
    kernel_lockdown: str = ""         # "none" / "integrity" / "confidentiality" / ""
    modules_disabled: str = ""        # "1" / "0" / ""
    module_sig_enforce: str = ""      # "1" / "0" / ""

    # ------------------------------------------------------------------
    # P1.6.4: rootkit / anti-forensics / sysctl posture
    # (Linux-primary; other collectors leave them empty).
    # ------------------------------------------------------------------
    # Decoded kernel posture (derived from ``kernel_tainted``).
    taint_decoded: str = ""              # letter-encoded, e.g. "F,O,E"
    kexec_loaded: str = ""               # "1" / "0" / ""
    wtmp_size: int = 0
    wtmp_mtime_ns: int = 0
    utmp_size: int = 0
    btmp_size: int = 0
    lastlog_size: int = 0
    hidden_pid_count: int = 0
    # Security sysctls.
    kptr_restrict: str = ""
    dmesg_restrict: str = ""
    perf_event_paranoid: str = ""
    unprivileged_bpf_disabled: str = ""
    unprivileged_userns_clone: str = ""
    kexec_load_disabled: str = ""
    sysrq_state: str = ""
    core_pattern: str = ""
    suid_dumpable: str = ""
    protected_symlinks: str = ""
    protected_hardlinks: str = ""
    protected_fifos: str = ""
    protected_regular: str = ""
    bpf_jit_enable: str = ""
    # auditd / journald / time / CPU-vulnerabilities posture.
    audit_state: str = ""                # "running" / "absent" / ""
    audit_rules_count: int = 0
    journald_storage: str = ""           # "persistent" / "volatile" / "none" / "auto" / ""
    ntp_sync: str = ""                   # "yes" / "no" / "unknown" / ""
    cpu_vuln_digest: str = ""            # 16 hex chars (first 8 bytes of SHA256)

    # ------------------------------------------------------------------
    # Provenance (populated by engine / cli_sysctx, not collectors).
    # ------------------------------------------------------------------
    mode: str = ""                       # "safe" / "deep"
    collector_warnings: list[str] = field(default_factory=list)
    redacted_keys: list[str] = field(default_factory=list)
    truncated: bool = False


@runtime_checkable
class InvestigationCollector(Protocol):
    """Protocol for collecting system-wide investigation data.

    Implementations are OS-specific, not debugger-specific.
    Each method returns best-effort data; empty/zero for
    fields that cannot be collected on the current platform.
    """

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        """Collect identity metadata for the target process.

        P1.6.3 keyword arguments:

        - ``include_target_introspection`` (default ``True``): opt-out
          for the per-target introspection harvest (TracerPid, loginuid,
          SELinux context, smaps rollup, cgroup, ancestry, …).
        - ``include_environ`` (default ``False``): opt-in for
          ``/proc/<pid>/environ`` emission (may leak credentials; the
          collector applies the shared redaction heuristic regardless).
        """
        ...

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system-wide context (hostname, OS detail, boot time)."""
        ...

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate all running processes. Returns empty list on failure."""
        ...

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate network connections. Returns empty list on failure."""
        ...

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate open file handles for a process. Returns empty list on failure."""
        ...

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Collect loaded kernel modules (``/proc/modules`` + ``/sys/module``).

        Returns an empty :class:`KernelModuleList` on platforms that
        don't implement it. Linux populates rows from both sources and
        flags skew between them for LKM-rootkit detection.
        """
        ...

    def collect_connectivity_table(self) -> ConnectivityTable:
        """Collect kernel network state (routes, ARP, packet sockets, etc.).

        Returns an empty ConnectivityTable on platforms that don't
        implement it. Linux collectors populate it from /proc/net/*;
        other platforms return a default-constructed instance.
        """
        ...

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Collect a filesystem persistence manifest (P1.6.4, Block 0x0056).

        Walks top-level filesystem persistence paths (systemd, cron,
        profile.d, pam.d, udev, modprobe, modules, rc_local) and emits
        one row per entry with names + mtime + size + mode only — no
        content reads. Linux-primary; other platforms return an empty
        :class:`PersistenceManifest`. Gated behind
        ``--include-persistence-manifest``.
        """
        ...
