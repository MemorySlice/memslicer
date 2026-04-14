"""Linux-specific investigation collector using /proc filesystem."""
from __future__ import annotations

import gzip
import hashlib
import logging
import os
import re
import struct
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# P1.6.3 — environ redaction helper
# ---------------------------------------------------------------------------

# Matches keys whose NAME (not value) indicates credential material:
# AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DATABASE_PASSWORD, oauth_refresh_token,
# PASS (bare), etc. Triggers on the token appearing as its own underscore-
# delimited component (head, tail, or interior) so benign substrings like
# ``KEYBOARD_LAYOUT`` are not redacted. Bare names equal to the token alone
# also match.
_SECRET_PATTERN = re.compile(
    r"(?i)(?:^|_)(?:token|key|secret|password|pass|credential|auth)(?:$|_)",
)


def redact_environ(raw: bytes) -> tuple[str, list[str]]:
    """Parse a NUL-separated environ blob, redact secret-shaped entries.

    Returns ``(sanitized_blob, redacted_key_names)``. The sanitized
    blob is NUL-separated with the same shape as the input, but values
    for redacted keys are replaced with ``"<redacted>"``. Entries
    without ``=`` are preserved verbatim.
    """
    if not raw:
        return "", []
    entries = raw.split(b"\x00")
    sanitized: list[str] = []
    redacted: list[str] = []
    for entry in entries:
        if not entry:
            continue
        text = entry.decode("utf-8", errors="replace")
        if "=" not in text:
            sanitized.append(text)
            continue
        key, _, _value = text.partition("=")
        if _SECRET_PATTERN.search(key):
            sanitized.append(f"{key}=<redacted>")
            redacted.append(key)
        else:
            sanitized.append(text)
    return "\x00".join(sanitized), redacted

from memslicer.acquirer.collectors._io import read_proc_file, read_symlink
from memslicer.acquirer.elf_notes import parse_elf_notes
from memslicer.acquirer.collectors.addr_utils import (
    decode_proc_net_ipv4,
    decode_proc_net_ipv6,
)
from memslicer.acquirer.collectors.constants import (
    AF_INET, AF_INET6, AF_UNIX, PROTO_TCP, PROTO_UDP,
    HT_UNKNOWN, HT_FILE, HT_DIR, HT_SOCKET, HT_PIPE, HT_DEVICE,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import (
    ConnectionEntry, HandleEntry, ProcessEntry, ConnectivityTable,
    KernelModuleList, KernelModuleRow, PersistenceManifest, PersistenceRow,
)


# ---------------------------------------------------------------------------
# P1.6.4 — kernel taint decoding
# ---------------------------------------------------------------------------

# Authoritative bit → letter mapping from ``include/linux/panic.h`` (Linux
# mainline). Ordered by bit index so ``_TAINT_LETTERS[bit]`` is valid for
# 0..17. Bits 1 (F=force-loaded), 12 (O=out-of-tree), 13 (E=unsigned), and
# 15 (K=live-patched) are the rootkit / compromise smoking-gun signals.
_TAINT_LETTERS: tuple[str, ...] = (
    "P", "F", "S", "R", "M", "B", "U", "D", "A",
    "W", "C", "I", "O", "E", "L", "K", "X", "T",
)
_TAINT_SMOKING_GUN_WARNINGS: dict[int, str] = {
    1: "taint_force_loaded_module",
    12: "taint_out_of_tree_module",
    13: "taint_unsigned_module_loaded",   # highest-signal
    15: "taint_kernel_live_patched",
}


def _decode_kernel_taint(raw: str) -> tuple[str, list[str]]:
    """Decode ``/proc/sys/kernel/tainted`` bitmask into a letter-encoded
    string plus ``collector_warnings`` entries for rootkit-signal bits.

    Returns ``(letters, warnings)``. Letters are comma-separated in bit
    order (e.g. ``"F,O,E"``). Malformed / empty input returns
    ``("", [])`` — never raises.

    Bits 1 (F), 12 (O), 13 (E), and 15 (K) emit warnings; bit 13
    (unsigned LKM) is the highest-signal for modern distros that enforce
    module signing. Everything else decodes to a letter but emits no
    warning (benign taint like the hypervisor flag).
    """
    if not raw:
        return "", []
    try:
        value = int(raw.strip())
    except (ValueError, AttributeError):
        return "", []
    letters: list[str] = []
    warnings: list[str] = []
    for bit in range(len(_TAINT_LETTERS)):
        if value & (1 << bit):
            letters.append(_TAINT_LETTERS[bit])
            if bit in _TAINT_SMOKING_GUN_WARNINGS:
                warnings.append(_TAINT_SMOKING_GUN_WARNINGS[bit])
    return ",".join(letters), warnings


class LinuxCollector:
    """Collects investigation data from Linux /proc filesystem.

    All methods handle errors gracefully, logging warnings and
    returning partial or empty data on failure.
    """

    _is_memslicer_collector = True

    def __init__(
        self,
        proc_root: str = "/proc",
        logger: logging.Logger | None = None,
    ) -> None:
        self._proc = proc_root
        self._log = logger or logging.getLogger("memslicer")
        # P1.6.1: cache the host page size so RSS math is correct on
        # ARM64 systems with 16k/64k pages. The fallback flag is surfaced
        # as a ``collector_warning`` by ``collect_system_info``.
        self._page_size_is_fallback = False
        self._page_size = self._resolve_page_size()
        # P1.6.3: passwd map is loaded lazily on first use and cached
        # per collector instance. ``None`` = not yet attempted.
        self._passwd_map_cache: dict[int, str] | None = None

    @staticmethod
    def _resolve_page_size_sysconf() -> int:
        return os.sysconf("SC_PAGE_SIZE")

    def _resolve_page_size(self) -> int:
        """Resolve the host page size via ``sysconf``.

        Falls back to 4096 and flags ``_page_size_is_fallback`` so the
        caller can emit a ``page_size_assumed_4k`` warning.
        """
        try:
            value = self._resolve_page_size_sysconf()
            if value and value > 0:
                return int(value)
        except (OSError, ValueError):
            pass
        self._page_size_is_fallback = True
        return 4096

    # ------------------------------------------------------------------
    # Public API (matches InvestigationCollector protocol)
    # ------------------------------------------------------------------

    def collect_process_identity(
        self,
        pid: int,
        *,
        include_target_introspection: bool = True,
        include_environ: bool = False,
    ) -> TargetProcessInfo:
        """Collect identity metadata for the target process.

        P1.6.3: when ``include_target_introspection`` is ``True`` (the
        default), the full per-target harvest runs — TracerPid,
        loginuid, SELinux context, smaps rollup, cgroup, ancestry, etc.
        ``include_environ`` additionally opens ``/proc/<pid>/environ``,
        which is always passed through the redaction heuristic.
        """
        info = TargetProcessInfo()
        try:
            stat_fields, _ = self._parse_proc_stat(pid)
            info.ppid = int(stat_fields[1])
            info.session_id = int(stat_fields[3])
            info.start_time_ns = self._calc_start_time_ns(int(stat_fields[19]))
        except (OSError, PermissionError, ValueError, IndexError) as exc:
            self._log.warning("Failed to read stat for pid %d: %s", pid, exc)

        info.exe_path = self._read_exe_path(pid)
        info.cmd_line = self._read_cmdline(pid)

        if not include_target_introspection:
            return info

        # --- P1.6.3 introspection harvest ---
        self._populate_target_introspection(info, pid, include_environ)
        return info

    def _populate_target_introspection(
        self,
        info: TargetProcessInfo,
        pid: int,
        include_environ: bool,
    ) -> None:
        """Harvest the P1.6.3 per-target introspection fields into ``info``.

        Each helper degrades silently to empty/zero on failure, so this
        method is unconditionally safe to call. Split out of
        :meth:`collect_process_identity` to keep that method readable.
        """
        status = self._read_proc_status_full(pid)
        if "TracerPid" in status:
            try:
                info.tracer_pid = int(status["TracerPid"])
            except ValueError:
                pass
        try:
            info.thread_count = int(status.get("Threads", "0") or 0)
        except ValueError:
            info.thread_count = 0
        info.cap_eff = status.get("CapEff", "")
        info.cap_amb = status.get("CapAmb", "")
        info.sig_cgt = status.get("SigCgt", "")
        info.no_new_privs = 1 if status.get("NoNewPrivs") == "1" else 0
        try:
            info.seccomp_mode = int(status.get("Seccomp", "0") or 0)
        except ValueError:
            info.seccomp_mode = 0
        info.core_dumping = 1 if status.get("CoreDumping") == "1" else 0

        login_uid = self._read_loginuid(pid)
        if login_uid is not None:
            info.login_uid = login_uid
        session_id = self._read_sessionid(pid)
        if session_id is not None:
            info.session_audit_id = session_id

        info.selinux_context = self._read_selinux_context(pid)

        fingerprint, scope = self._read_target_ns_fingerprint(pid)
        info.target_ns_fingerprint = fingerprint
        info.target_ns_scope_vs_collector = scope

        pss, swap, anon_hp = self._read_smaps_rollup(pid)
        info.smaps_rollup_pss_kib = pss
        info.smaps_rollup_swap_kib = swap
        info.smaps_anon_hugepages_kib = anon_hp

        info.rwx_region_count = self._scan_maps_for_rwx(pid)
        info.target_cgroup = self._read_target_cgroup(pid)
        info.target_cwd = self._read_cwd(pid)
        info.target_root = self._read_root(pid)

        io_counters = self._read_io_counters(pid)
        info.io_rchar = io_counters.get("rchar", 0)
        info.io_wchar = io_counters.get("wchar", 0)
        info.io_read_bytes = io_counters.get("read_bytes", 0)
        info.io_write_bytes = io_counters.get("write_bytes", 0)

        limits = self._read_limits(pid)
        info.limit_core = limits.get("Max core file size", "")
        info.limit_memlock = limits.get("Max locked memory", "")
        info.limit_nofile = limits.get("Max open files", "")

        info.personality_hex = self._read_personality(pid)
        info.ancestry = self._walk_parent_chain(pid)
        info.exe_comm_mismatch = self._detect_exe_comm_mismatch(pid)

        if include_environ:
            raw_env = self._read_environ_raw(pid)
            if raw_env:
                sanitized, redacted = redact_environ(raw_env)
                info.environ = sanitized
                info.redacted_env_keys = redacted

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system-wide context (hostname, OS detail, boot time)."""
        info = TargetSystemInfo()
        info.boot_time = self._read_boot_time_ns()
        info.hostname = self._read_sysctl("kernel/hostname")

        domain = self._read_sysctl("kernel/domainname")
        info.domain = "" if domain in ("(none)", "") else domain

        # Identity: kernel / arch / distro / raw_os / os_detail
        try:
            uname = os.uname()
            info.kernel = uname.release
            info.arch = uname.machine
        except OSError as exc:
            self._log.warning("os.uname() failed: %s", exc)

        info.raw_os = self._read_file_text(f"{self._proc}/version")
        info.distro = self._read_os_release_distro()
        info.os_detail = self._compose_os_detail(
            info.distro, info.kernel, info.arch
        )

        # Identity: machine / hardware
        info.machine_id = self._read_machine_id()
        info.hw_vendor = self._read_dmi("sys_vendor")
        info.hw_model = self._read_dmi("product_name")
        info.hw_serial = self._read_dmi("product_serial")
        info.bios_version = self._read_dmi("bios_version")

        # CPU / memory
        info.cpu_brand = self._read_cpuinfo_model()
        info.cpu_count = os.cpu_count() or 0
        info.ram_bytes = self._read_meminfo_bytes()

        # Runtime / boot
        info.timezone = self._read_timezone()
        info.virtualization = self._detect_virtualization(info.hw_model)
        info.boot_id = self._read_file_text(
            f"{self._proc}/sys/kernel/random/boot_id"
        )

        # Kernel posture (P1.5).
        info.kernel_cmdline    = self._read_file_text(f"{self._proc}/cmdline")
        info.kernel_tainted    = self._read_file_text(
            f"{self._proc}/sys/kernel/tainted"
        )
        info.lsm_stack         = self._read_lsm_stack()
        info.yama_ptrace_scope = self._read_file_text(
            f"{self._proc}/sys/kernel/yama/ptrace_scope"
        )
        info.aslr_mode         = self._read_file_text(
            f"{self._proc}/sys/kernel/randomize_va_space"
        )
        info.efi_mode          = "1" if os.path.isdir(self._efi_dir) else ""

        # Provenance — collector capabilities (critical DFIR field).
        info.collector_caps    = self._read_collector_caps()

        # Container / namespace awareness.
        ns_info = self._read_ns_fingerprint()
        info.ns_fingerprint    = ns_info.get("fingerprint", "")
        info.container_scope   = ns_info.get("scope", "")
        info.container_runtime = self._detect_container_runtime()

        # hidepid warning (not a field — surfaces as collector_warning).
        if self._detect_hidepid_active():
            info.collector_warnings.append("hidepid_active")

        # P1.6.1 — memory-forensics anchors.
        info.page_size = self._page_size
        if self._page_size_is_fallback:
            info.collector_warnings.append("page_size_assumed_4k")

        info.kernel_build_id = self._read_kernel_build_id()

        kaslr = self._read_kaslr_anchor()
        info.kaslr_text_va = kaslr.get("text_va", 0)
        info.kernel_page_offset = kaslr.get("page_offset", 0)
        if info.kaslr_text_va == 0:
            info.collector_warnings.append("kallsyms_restricted")

        btf_sha, btf_size = self._read_btf_hash_and_size()
        info.btf_sha256 = btf_sha
        info.btf_size_bytes = btf_size
        if not btf_sha:
            info.collector_warnings.append("btf_unavailable")

        vmcoreinfo_sha, vmcoreinfo_present = self._read_vmcoreinfo_hash()
        info.vmcoreinfo_sha256 = vmcoreinfo_sha
        info.vmcoreinfo_present = vmcoreinfo_present
        if vmcoreinfo_present == "0":
            info.collector_warnings.append("vmcoreinfo_unreadable")

        info.kernel_config_sha256 = self._read_kernel_config_hash()
        (info.clock_realtime_ns,
         info.clock_monotonic_ns,
         info.clock_boottime_ns) = self._read_clock_triple()
        info.clocksource = self._read_clocksource()
        info.zram_devices = self._read_zram_devices()
        info.zswap_enabled = self._read_zswap_enabled()
        info.thp_mode = self._read_thp_mode()
        info.ksm_active = self._read_ksm_active()
        (info.directmap_4k,
         info.directmap_2m,
         info.directmap_1g) = self._read_directmap_sizes()
        info.la57_enabled, info.pti_active = self._read_la57_pti()

        info.physmem_ranges = self._read_physmem_map()
        if info.physmem_ranges and all(
            start == 0 and end == 0 for start, end, _ in info.physmem_ranges
        ):
            info.collector_warnings.append("iomem_root_only")

        # P1.6.2 — module / loader posture.
        info.ld_so_preload = self._read_ld_so_preload()
        info.kernel_lockdown = self._read_kernel_lockdown()
        info.modules_disabled = self._read_modules_disabled()
        info.module_sig_enforce = self._read_module_sig_enforce()
        if info.ld_so_preload:
            info.collector_warnings.append("ld_so_preload_present")

        # P1.6.4 — rootkit / anti-forensics / sysctl posture.
        # Decoded kernel taint: free post-processing of the existing
        # ``info.kernel_tainted`` raw decimal, no new file reads.
        taint_letters, taint_warnings = _decode_kernel_taint(info.kernel_tainted)
        info.taint_decoded = taint_letters
        info.collector_warnings.extend(taint_warnings)

        info.kexec_loaded = self._read_kexec_loaded()
        if info.kexec_loaded == "1":
            info.collector_warnings.append("kexec_loaded")

        auth_stats = self._stat_auth_log_files()
        if "wtmp" in auth_stats:
            info.wtmp_size, info.wtmp_mtime_ns = auth_stats["wtmp"]
        if "utmp" in auth_stats:
            info.utmp_size = auth_stats["utmp"][0]
        if "btmp" in auth_stats:
            info.btmp_size = auth_stats["btmp"][0]
        if "lastlog" in auth_stats:
            info.lastlog_size = auth_stats["lastlog"][0]

        # Log integrity heuristics — noisy, so emitted as advisory
        # warnings only when the signal is strong.
        try:
            uptime_seconds = self._read_clock_triple()[2] // 1_000_000_000
        except Exception:  # noqa: BLE001 — best-effort
            uptime_seconds = 0
        if (
            "wtmp" in auth_stats
            and info.wtmp_size == 0
            and uptime_seconds > 3600
        ):
            info.collector_warnings.append("wtmp_zeroed")
        if (
            info.wtmp_mtime_ns > 0
            and info.boot_time > 0
            and info.wtmp_mtime_ns < info.boot_time
        ):
            info.collector_warnings.append("wtmp_stale")

        info.hidden_pid_count = self._sweep_hidden_pids()
        if info.hidden_pid_count > 0:
            info.collector_warnings.append(
                f"hidden_pid_count:{info.hidden_pid_count}",
            )
        info.collector_warnings.append("hidden_pid_sweep_performed")

        sysctls = self._read_security_sysctls()
        info.kptr_restrict = sysctls.get("kptr_restrict", "")
        info.dmesg_restrict = sysctls.get("dmesg_restrict", "")
        info.perf_event_paranoid = sysctls.get("perf_event_paranoid", "")
        info.unprivileged_bpf_disabled = sysctls.get("unprivileged_bpf_disabled", "")
        info.unprivileged_userns_clone = sysctls.get("unprivileged_userns_clone", "")
        info.kexec_load_disabled = sysctls.get("kexec_load_disabled", "")
        info.sysrq_state = sysctls.get("sysrq_state", "")
        info.suid_dumpable = sysctls.get("suid_dumpable", "")
        info.protected_symlinks = sysctls.get("protected_symlinks", "")
        info.protected_hardlinks = sysctls.get("protected_hardlinks", "")
        info.protected_fifos = sysctls.get("protected_fifos", "")
        info.protected_regular = sysctls.get("protected_regular", "")
        info.bpf_jit_enable = sysctls.get("bpf_jit_enable", "")

        info.core_pattern = self._read_core_pattern()
        if info.core_pattern.startswith("|"):
            info.collector_warnings.append("core_pattern_pipe")

        info.audit_state, info.audit_rules_count = self._detect_audit_state()
        info.journald_storage = self._detect_journald_storage()
        info.ntp_sync = self._detect_ntp_sync()
        info.cpu_vuln_digest = self._read_cpu_vuln_digest()

        return info

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Enumerate all running processes via /proc.

        P1.6.3: loads ``/etc/passwd`` once (cached per-instance) and
        fills in ``ProcessEntry.user`` from the uid map. Entries for
        uids not in ``/etc/passwd`` (LDAP/SSSD system users) keep the
        default empty ``user`` field — no attempt is made to resolve
        them out-of-band.
        """
        passwd_map = self._load_passwd_map()
        entries: list[ProcessEntry] = []
        try:
            for name in os.listdir(self._proc):
                if not name.isdigit():
                    continue
                entry = self._read_process_entry(int(name), target_pid)
                if entry is not None:
                    if passwd_map:
                        entry.user = passwd_map.get(entry.uid, "")
                    entries.append(entry)
        except (OSError, PermissionError) as exc:
            self._log.warning("Failed to list %s: %s", self._proc, exc)
            return []

        self._log.info("Collected %d process table entries", len(entries))
        return entries

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Enumerate network connections from /proc/net."""
        inode_pid = self._build_inode_pid_map()
        entries: list[ConnectionEntry] = []

        net_files = [
            ("tcp", AF_INET, PROTO_TCP),
            ("tcp6", AF_INET6, PROTO_TCP),
            ("udp", AF_INET, PROTO_UDP),
            ("udp6", AF_INET6, PROTO_UDP),
        ]
        for filename, family, protocol in net_files:
            path = f"{self._proc}/net/{filename}"
            entries.extend(self._parse_net_file(path, family, protocol, inode_pid))

        # /proc/net/route, /proc/net/arp, /proc/net/packet are not sockets —
        # they are kernel state and do not fit the ConnectionEntry schema.
        # Deferred to a P2 MSL spec extension (0x0054 ConnectivityTable or similar).
        entries.extend(self._parse_unix_file(
            f"{self._proc}/net/unix", inode_pid,
        ))

        self._log.info("Collected %d connection table entries", len(entries))
        return entries

    def collect_connectivity_table(self) -> ConnectivityTable:
        """Collect kernel network state from /proc/net/* (P1.6.5).

        Reuses the inode->pid map from :meth:`collect_connection_table`
        for packet-socket pid attribution. All parsers degrade to empty
        lists on missing / unreadable files.
        """
        from memslicer.acquirer.collectors import linux_connectivity as lc

        inode_pid = self._build_inode_pid_map()
        table = ConnectivityTable()
        table.ipv4_routes = lc.parse_ipv4_routes(
            f"{self._proc}/net/route", logger=self._log,
        )
        table.ipv6_routes = lc.parse_ipv6_routes(
            f"{self._proc}/net/ipv6_route", logger=self._log,
        )
        table.arp_entries = lc.parse_arp_entries(
            f"{self._proc}/net/arp", logger=self._log,
        )
        table.packet_sockets = lc.parse_packet_sockets(
            f"{self._proc}/net/packet", inode_pid, logger=self._log,
        )
        table.netdev_stats = lc.parse_netdev_stats(
            f"{self._proc}/net/dev", logger=self._log,
        )
        table.sockstat_families = lc.parse_sockstat(
            f"{self._proc}/net/sockstat",
            f"{self._proc}/net/sockstat6",
            logger=self._log,
        )
        table.snmp_counters = lc.parse_snmp_counters(
            f"{self._proc}/net/snmp",
            f"{self._proc}/net/netstat",
            logger=self._log,
            max_per_mib=50,
        )
        self._log.info(
            "Collected connectivity table: %d routes4 %d routes6 %d arp "
            "%d pkt %d netdev %d sockstat %d snmp",
            len(table.ipv4_routes), len(table.ipv6_routes),
            len(table.arp_entries), len(table.packet_sockets),
            len(table.netdev_stats), len(table.sockstat_families),
            len(table.snmp_counters),
        )
        return table

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Enumerate open file handles for a process."""
        fd_dir = f"{self._proc}/{pid}/fd"
        entries: list[HandleEntry] = []
        try:
            fd_names = os.listdir(fd_dir)
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot list %s: %s", fd_dir, exc)
            return []

        for fd_name in fd_names:
            if not fd_name.isdigit():
                continue
            fd_num = int(fd_name)
            entries.append(self._read_handle_entry(pid, fd_num, fd_dir))

        self._log.info("Collected %d handle entries for pid %d", len(entries), pid)
        return entries

    # ------------------------------------------------------------------
    # Private helpers: process identity
    # ------------------------------------------------------------------

    def _parse_proc_stat(self, pid: int) -> tuple[list[str], str]:
        """Parse /proc/<pid>/stat, returning fields after comm and the comm name.

        Returns (fields_after_comm, comm_name).
        Fields: index 0=state, 1=ppid, 3=session, 19=starttime.
        """
        with open(f"{self._proc}/{pid}/stat", "r") as fh:
            stat_line = fh.read()
        comm_start = stat_line.index("(") + 1
        comm_end = stat_line.rindex(")")
        comm_name = stat_line[comm_start:comm_end]
        return stat_line[comm_end + 2:].split(), comm_name

    def _calc_start_time_ns(self, starttime_ticks: int) -> int:
        """Convert starttime clock ticks to nanoseconds since epoch."""
        boot_time_sec = self._read_boot_time_sec()
        clk_tck = os.sysconf("SC_CLK_TCK")
        start_sec = boot_time_sec + starttime_ticks / clk_tck
        return int(start_sec * 1_000_000_000)

    def _read_exe_path(self, pid: int) -> str:
        """Read the executable path via /proc/<pid>/exe symlink."""
        try:
            return os.readlink(f"{self._proc}/{pid}/exe")
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read exe for pid %d: %s", pid, exc)
            return ""

    def _read_cmdline(self, pid: int) -> str:
        """Read the command line from /proc/<pid>/cmdline."""
        try:
            with open(f"{self._proc}/{pid}/cmdline", "r") as fh:
                return fh.read().replace("\x00", " ").strip()
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read cmdline for pid %d: %s", pid, exc)
            return ""

    # ------------------------------------------------------------------
    # Private helpers: P1.6.3 per-target introspection
    # ------------------------------------------------------------------

    # Process-state flag for kernel threads (see fs/proc/array.c).
    # Used to skip ``exe``/``comm`` comparison for worker threads.
    _PF_KTHREAD = 0x00200000

    def _read_proc_status_full(self, pid: int) -> dict[str, str]:
        """Parse ``/proc/<pid>/status`` into a ``{key: value}`` dict.

        Values are the raw strings after the ``"Key:"`` prefix with
        surrounding whitespace stripped. Returns ``{}`` on failure.
        """
        try:
            with open(f"{self._proc}/{pid}/status", "r") as fh:
                text = fh.read()
        except (OSError, PermissionError):
            return {}
        out: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip()
        return out

    def _read_single_int_file(self, path: str) -> int | None:
        """Read a single-integer file (``loginuid`` / ``sessionid``).

        Returns ``None`` when the file cannot be read — callers use
        this as "not collected" so a present-but-unset loginuid
        (4294967295) stays distinct from a hard miss.
        """
        try:
            with open(path, "r") as fh:
                raw = fh.read().strip()
        except (OSError, PermissionError):
            return None
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _read_loginuid(self, pid: int) -> int | None:
        """Read ``/proc/<pid>/loginuid``. ``4294967295`` means "no audit"."""
        return self._read_single_int_file(f"{self._proc}/{pid}/loginuid")

    def _read_sessionid(self, pid: int) -> int | None:
        """Read ``/proc/<pid>/sessionid`` (audit session id)."""
        return self._read_single_int_file(f"{self._proc}/{pid}/sessionid")

    def _read_selinux_context(self, pid: int) -> str:
        """Read ``/proc/<pid>/attr/current`` (SELinux process context)."""
        try:
            with open(f"{self._proc}/{pid}/attr/current", "r") as fh:
                return fh.read().strip().rstrip("\x00")
        except (OSError, PermissionError):
            return ""

    def _read_ns_targets(self, ns_dir: str) -> dict[str, str]:
        """Read the 8 well-known namespace symlinks at ``ns_dir``.

        Returns ``{ns: target_or_empty}``. Errors per symlink are
        silently coerced to empty strings so a partially-readable
        ``/proc/<pid>/ns`` still yields a usable fingerprint.
        """
        namespaces = ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time")
        out: dict[str, str] = {}
        for ns in namespaces:
            try:
                out[ns] = os.readlink(f"{ns_dir}/{ns}")
            except (OSError, PermissionError):
                out[ns] = ""
        return out

    def _read_target_ns_fingerprint(self, pid: int) -> tuple[str, str]:
        """Compute the namespace fingerprint of ``pid`` and compare it
        against the collector's own (``/proc/self/ns/*``).

        Returns ``(fingerprint, scope)`` where ``scope`` is one of
        ``"host"`` / ``"container"`` / ``"partial"`` / ``""``. Logic
        mirrors :meth:`_read_ns_fingerprint` but targets the per-pid
        ns dir instead of pid 1. Returns ``("", "")`` when no
        target namespaces could be read.
        """
        namespaces = ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time")
        target_targets = self._read_ns_targets(f"{self._proc}/{pid}/ns")
        if not any(target_targets.values()):
            return "", ""

        fp = ",".join(
            target_targets[ns] for ns in namespaces if target_targets[ns]
        )

        collector_targets = self._read_ns_targets(self._self_ns_dir)
        if not any(collector_targets.values()):
            return fp, ""

        differing = sum(
            1 for ns in namespaces
            if target_targets[ns] and collector_targets[ns]
            and target_targets[ns] != collector_targets[ns]
        )
        if differing == 0:
            scope = "host"
        elif differing == len(namespaces):
            scope = "container"
        else:
            scope = "partial"
        return fp, scope

    def _read_smaps_rollup(self, pid: int) -> tuple[int, int, int]:
        """Parse ``/proc/<pid>/smaps_rollup`` (kernel 4.14+).

        Returns ``(pss_kib, swap_kib, anon_hugepages_kib)``, each
        ``0`` when the corresponding field is missing.
        """
        try:
            with open(f"{self._proc}/{pid}/smaps_rollup", "r") as fh:
                text = fh.read()
        except (OSError, PermissionError):
            return 0, 0, 0
        wanted = {"Pss:": 0, "Swap:": 0, "AnonHugePages:": 0}
        for line in text.splitlines():
            for key in wanted:
                if line.startswith(key):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            wanted[key] = int(parts[1])
                        except ValueError:
                            pass
                    break
        return wanted["Pss:"], wanted["Swap:"], wanted["AnonHugePages:"]

    def _scan_maps_for_rwx(self, pid: int) -> int:
        """Count anonymous ``rwxp`` regions in ``/proc/<pid>/maps``.

        An "anonymous" region here has no file backing — the last
        whitespace-delimited field is empty or is one of the bracketed
        pseudo-names (``[heap]``, ``[stack]``, ``[anon]``,
        ``[anon_shmem]``). These are the classic shellcode-injection
        markers.
        """
        try:
            with open(f"{self._proc}/{pid}/maps", "r") as fh:
                lines = fh.readlines()
        except (OSError, PermissionError):
            return 0

        anon_markers = {"", "[heap]", "[stack]", "[anon]", "[anon_shmem]"}
        count = 0
        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            perms = parts[1]
            if "rwx" not in perms or not perms.endswith("p"):
                continue
            # Backing path is either missing (5 fields) or in field index 5.
            backing = parts[5] if len(parts) >= 6 else ""
            if backing in anon_markers or backing.startswith("[stack:"):
                count += 1
        return count

    def _read_environ_raw(self, pid: int) -> bytes:
        """Read ``/proc/<pid>/environ`` as raw bytes. ``b""`` on failure."""
        try:
            with open(f"{self._proc}/{pid}/environ", "rb") as fh:
                return fh.read()
        except (OSError, PermissionError):
            return b""

    def _read_target_cgroup(self, pid: int) -> str:
        """Read ``/proc/<pid>/cgroup``.

        Cgroup v2: single line ``0::/path`` → returns ``/path``.
        Cgroup v1: multiple lines — returns the first line's path field.
        """
        try:
            with open(f"{self._proc}/{pid}/cgroup", "r") as fh:
                text = fh.read()
        except (OSError, PermissionError):
            return ""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "<hierarchy-id>:<controller>:<path>".
            parts = line.split(":", 2)
            if len(parts) == 3:
                return parts[2]
            return line
        return ""

    def _read_cwd(self, pid: int) -> str:
        """Read ``/proc/<pid>/cwd`` symlink target."""
        try:
            return os.readlink(f"{self._proc}/{pid}/cwd")
        except (OSError, PermissionError):
            return ""

    def _read_root(self, pid: int) -> str:
        """Read ``/proc/<pid>/root`` symlink target (chroot anchor)."""
        try:
            return os.readlink(f"{self._proc}/{pid}/root")
        except (OSError, PermissionError):
            return ""

    def _read_io_counters(self, pid: int) -> dict[str, int]:
        """Parse ``/proc/<pid>/io``.

        Extracts ``rchar`` / ``wchar`` / ``read_bytes`` /
        ``write_bytes``. Returns ``{}`` on failure. Root or same-uid
        only — degraded result is also ``{}``.
        """
        try:
            with open(f"{self._proc}/{pid}/io", "r") as fh:
                text = fh.read()
        except (OSError, PermissionError):
            return {}
        out: dict[str, int] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            try:
                out[key.strip()] = int(value.strip())
            except ValueError:
                continue
        return out

    def _read_limits(self, pid: int) -> dict[str, str]:
        """Parse ``/proc/<pid>/limits``.

        The file has a fixed-width header plus rows like::

            Max core file size        0           unlimited    bytes

        We extract the soft-limit column (4th whitespace field from
        the right). Only core / memlock / nofile are returned.
        """
        try:
            with open(f"{self._proc}/{pid}/limits", "r") as fh:
                lines = fh.readlines()
        except (OSError, PermissionError):
            return {}
        wanted = (
            "Max core file size",
            "Max locked memory",
            "Max open files",
        )
        out: dict[str, str] = {}
        for line in lines[1:]:  # skip header
            stripped = line.rstrip("\n")
            for key in wanted:
                if stripped.startswith(key):
                    tail = stripped[len(key):].split()
                    # tail: [soft, hard, units?]
                    if tail:
                        out[key] = tail[0]
                    break
        return out

    def _read_personality(self, pid: int) -> str:
        """Read ``/proc/<pid>/personality`` (hex string, no prefix)."""
        try:
            with open(f"{self._proc}/{pid}/personality", "r") as fh:
                return fh.read().strip()
        except (OSError, PermissionError):
            return ""

    def _walk_parent_chain(self, pid: int, max_hops: int = 32) -> str:
        """Walk the ``ppid`` chain and serialize the ancestry path.

        Starts at ``pid`` and walks toward pid 1, bounded by
        ``max_hops`` to stop runaway chains. Each hop contributes
        ``<pid>:<name>:<start_time>``. ``name`` is ``basename(exe)``
        when readable, otherwise the ``comm`` from stat. Returns
        ``""`` on the first unreadable stat.
        """
        hops: list[str] = []
        current = pid
        for _ in range(max_hops):
            if current <= 0:
                break
            try:
                stat_fields, comm_name = self._parse_proc_stat(current)
            except (OSError, PermissionError, ValueError, IndexError):
                break
            try:
                ppid = int(stat_fields[1])
                start_time = int(stat_fields[19])
            except (ValueError, IndexError):
                break
            try:
                exe = os.readlink(f"{self._proc}/{current}/exe")
                name = os.path.basename(exe) if exe else comm_name
            except (OSError, PermissionError):
                name = comm_name
            hops.append(f"{current}:{name}:{start_time}")
            if current == 1 or ppid == 0 or ppid == current:
                break
            current = ppid
        return ",".join(hops)

    def _detect_exe_comm_mismatch(self, pid: int) -> int:
        """Flag when ``basename(exe)`` disagrees with ``comm``.

        Classic masquerade marker: an attacker overrides argv[0] or
        copies a binary with a different filename. ``comm`` is kernel-
        truncated to 15 characters, so we compare only the first 15
        chars of the basename. Kernel threads (``PF_KTHREAD``) are
        skipped because they have no userspace exe.
        """
        try:
            stat_fields, comm_name = self._parse_proc_stat(pid)
        except (OSError, PermissionError, ValueError, IndexError):
            return 0
        # Field index 6 (after-comm) is "flags". See proc(5).
        try:
            flags = int(stat_fields[6])
        except (ValueError, IndexError):
            flags = 0
        if flags & self._PF_KTHREAD:
            return 0
        try:
            exe_path = os.readlink(f"{self._proc}/{pid}/exe")
        except (OSError, PermissionError):
            return 0
        if not exe_path:
            return 0
        basename = os.path.basename(exe_path)
        # Strip " (deleted)" suffix the kernel appends for unlinked exes.
        if basename.endswith(" (deleted)"):
            basename = basename[: -len(" (deleted)")]
        truncated = basename[:15]
        return 0 if truncated == comm_name else 1

    def _load_passwd_map(self) -> dict[int, str]:
        """Parse ``/etc/passwd`` into ``{uid: username}``, cached per
        collector instance.

        Returns ``{}`` on read failure. Missing ``/etc/passwd`` is
        not fatal — ``ProcessEntry.user`` simply stays empty.
        """
        if self._passwd_map_cache is not None:
            return self._passwd_map_cache
        mapping: dict[int, str] = {}
        try:
            with open(self._etc_passwd, "r") as fh:
                for line in fh:
                    parts = line.strip().split(":")
                    if len(parts) < 3:
                        continue
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    mapping[uid] = parts[0]
        except (OSError, PermissionError) as exc:
            self._log.debug("Cannot read %s: %s", self._etc_passwd, exc)
        self._passwd_map_cache = mapping
        return mapping

    # ------------------------------------------------------------------
    # Private helpers: system info
    # ------------------------------------------------------------------

    def _read_boot_time_sec(self) -> int:
        """Read boot time in seconds from /proc/stat btime line."""
        try:
            with open(f"{self._proc}/stat", "r") as fh:
                for line in fh:
                    if line.startswith("btime "):
                        return int(line.split()[1])
        except (OSError, PermissionError, ValueError) as exc:
            self._log.warning("Cannot read boot time: %s", exc)
        return 0

    def _read_boot_time_ns(self) -> int:
        """Read boot time in nanoseconds from /proc/stat btime line."""
        return self._read_boot_time_sec() * 1_000_000_000

    def _read_sysctl(self, key: str) -> str:
        """Read a value from /proc/sys/<key>."""
        return self._read_file_text(f"{self._proc}/sys/{key}")

    def _read_file_text(self, path: str) -> str:
        """Read and strip a single-line text file, returning '' on failure.

        Delegates to :func:`memslicer.acquirer.collectors._io.read_proc_file`
        for TOCTOU-hardened opens (``O_NOFOLLOW``) and size-capped reads.
        """
        return read_proc_file(path, logger=self._log)

    # ------------------------------------------------------------------
    # Private helpers: enrichment sources
    # ------------------------------------------------------------------

    # Paths outside of /proc. Exposed as instance attributes so tests
    # can redirect them at the filesystem fixture without monkeypatching
    # module-level constants. Containerized-root scoping is P1.5.
    _etc_os_release = "/etc/os-release"
    _etc_machine_id = "/etc/machine-id"
    _dbus_machine_id = "/var/lib/dbus/machine-id"
    _dmi_id_dir = "/sys/class/dmi/id"
    _etc_localtime = "/etc/localtime"
    _dockerenv_path = "/.dockerenv"
    _containerenv_path = "/run/.containerenv"

    # P1.5 enrichment paths — class-level defaults, overridable per-instance
    # by tests. These are NOT under ``self._proc`` because the kernel exposes
    # them at absolute filesystem paths outside /proc.
    _efi_dir = "/sys/firmware/efi"
    _lsm_path = "/sys/kernel/security/lsm"
    _self_status = "/proc/self/status"          # CapEff
    _self_ns_dir = "/proc/self/ns"
    _pid1_ns_dir = "/proc/1/ns"
    _pid1_cgroup = "/proc/1/cgroup"
    _mountinfo = "/proc/self/mountinfo"
    _systemd_container_marker = "/run/systemd/container"

    # P1.6.1 enrichment paths — memory-forensics anchors. Class-level
    # defaults, overridable per-instance by tests.
    _sys_kernel_notes = "/sys/kernel/notes"
    _sys_kernel_btf = "/sys/kernel/btf/vmlinux"
    _sys_kernel_vmcoreinfo = "/sys/kernel/vmcoreinfo"
    _proc_kallsyms = "/proc/kallsyms"
    _proc_config_gz = "/proc/config.gz"
    _boot_config_prefix = "/boot/config-"
    _proc_iomem = "/proc/iomem"
    _meltdown_vuln_file = "/sys/devices/system/cpu/vulnerabilities/meltdown"
    _clocksource_file = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
    _sys_block_zram_dir = "/sys/block"
    _zswap_enabled_file = "/sys/module/zswap/parameters/enabled"
    _thp_enabled_file = "/sys/kernel/mm/transparent_hugepage/enabled"
    _ksm_run_file = "/sys/kernel/mm/ksm/run"
    _proc_cpuinfo = "/proc/cpuinfo"

    # P1.6.3 enrichment paths — per-target introspection + passwd map.
    # Class-level defaults, overridable per-instance by tests.
    _etc_passwd = "/etc/passwd"

    # P1.6.2 enrichment paths — module / loader posture. Class-level
    # defaults, overridable per-instance by tests.
    _etc_ld_so_preload = "/etc/ld.so.preload"
    _sys_kernel_lockdown = "/sys/kernel/security/lockdown"
    _proc_modules_disabled = "/proc/sys/kernel/modules_disabled"
    _proc_module_sig_enforce = "/proc/sys/kernel/module_sig_enforce"
    _proc_modules = "/proc/modules"
    _sys_module_dir = "/sys/module"

    # P1.6.4 — rootkit / anti-forensics / sysctl posture paths.
    # Class-level defaults, overridable per-instance by tests.
    _kexec_loaded_file = "/sys/kernel/kexec_loaded"
    _wtmp_path = "/var/log/wtmp"
    _utmp_path = "/var/run/utmp"
    _btmp_path = "/var/log/btmp"
    _lastlog_path = "/var/log/lastlog"
    _pid_max_file = "/proc/sys/kernel/pid_max"

    # Security sysctls.
    _sysctl_kptr_restrict = "/proc/sys/kernel/kptr_restrict"
    _sysctl_dmesg_restrict = "/proc/sys/kernel/dmesg_restrict"
    _sysctl_perf_event_paranoid = "/proc/sys/kernel/perf_event_paranoid"
    _sysctl_unprivileged_bpf_disabled = "/proc/sys/kernel/unprivileged_bpf_disabled"
    _sysctl_unprivileged_userns_clone = "/proc/sys/kernel/unprivileged_userns_clone"
    _sysctl_kexec_load_disabled = "/proc/sys/kernel/kexec_load_disabled"
    _sysctl_sysrq = "/proc/sys/kernel/sysrq"
    _sysctl_suid_dumpable = "/proc/sys/fs/suid_dumpable"
    _sysctl_protected_symlinks = "/proc/sys/fs/protected_symlinks"
    _sysctl_protected_hardlinks = "/proc/sys/fs/protected_hardlinks"
    _sysctl_protected_fifos = "/proc/sys/fs/protected_fifos"
    _sysctl_protected_regular = "/proc/sys/fs/protected_regular"
    _sysctl_bpf_jit_enable = "/proc/sys/net/core/bpf_jit_enable"

    _core_pattern_file = "/proc/sys/kernel/core_pattern"

    # auditd / journald / time / CPU-vulnerabilities paths.
    _auditd_pid_file = "/var/run/auditd.pid"
    _auditd_pid_file_alt = "/run/auditd.pid"
    _auditd_binary = "/usr/sbin/auditd"
    _audit_rules_file = "/etc/audit/audit.rules"

    _journald_conf_file = "/etc/systemd/journald.conf"
    _journald_persistent_dir = "/var/log/journal"
    _journald_volatile_dir = "/run/log/journal"

    _timesync_sync_file = "/run/systemd/timesync/synchronized"
    _chrony_drift_file = "/var/lib/chrony/drift"

    _cpu_vuln_dir = "/sys/devices/system/cpu/vulnerabilities"

    # Persistence manifest source roots. Each tuple is
    # ``(source_id, absolute_path)`` — the scanner walks the directory
    # non-recursively and emits one ``PersistenceRow`` per entry.
    _persistence_sources: list[tuple[int, str]] = [
        (1, "/etc/systemd/system"),
        (1, "/run/systemd/system"),
        (1, "/usr/lib/systemd/system"),
        (2, "/etc/systemd/user"),
        (3, "/etc/cron.d"),
        (3, "/etc/cron.hourly"),
        (3, "/etc/cron.daily"),
        (3, "/etc/cron.weekly"),
        (3, "/etc/cron.monthly"),
        (4, "/var/spool/cron"),
        (4, "/var/spool/cron/crontabs"),
        (6, "/etc/profile.d"),
        (7, "/etc/pam.d"),
        (8, "/etc/udev/rules.d"),
        (8, "/run/udev/rules.d"),
        (9, "/etc/modprobe.d"),
        (10, "/etc/systemd/system-generators"),
        (10, "/usr/lib/systemd/system-generators"),
        (11, "/etc/modules-load.d"),
    ]
    _persistence_single_files: list[tuple[int, str]] = [
        (3, "/etc/crontab"),
        (5, "/etc/rc.local"),
        (11, "/etc/modules"),
    ]

    # ``os.kill`` wrapper — injectable class attribute so tests can
    # replace it with a deterministic stub. Production code uses the
    # real syscall; tests swap in a mock that never touches the host
    # process table.
    _kill_func = staticmethod(os.kill)

    @staticmethod
    def _compose_os_detail(distro: str, kernel: str, arch: str) -> str:
        """Compose a human-readable os_detail string from the parts."""
        tail_parts = [p for p in (kernel, arch) if p]
        tail = " ".join(tail_parts)
        if distro and tail:
            return f"{distro} ({tail})"
        if distro:
            return distro
        return tail

    def _read_os_release_distro(self) -> str:
        """Parse /etc/os-release, returning PRETTY_NAME or NAME+VERSION."""
        text = self._read_file_text(self._etc_os_release)
        if not text:
            return ""

        fields: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            fields[key.strip()] = value

        pretty = fields.get("PRETTY_NAME", "")
        if pretty:
            return pretty
        name = fields.get("NAME", "")
        version = fields.get("VERSION", "")
        if name and version:
            return f"{name} {version}"
        return name

    def _read_machine_id(self) -> str:
        """Read /etc/machine-id, falling back to dbus machine-id."""
        value = self._read_file_text(self._etc_machine_id)
        if value:
            return value
        return self._read_file_text(self._dbus_machine_id)

    def _read_dmi(self, name: str) -> str:
        """Read a /sys/class/dmi/id/<name> field."""
        return self._read_file_text(f"{self._dmi_id_dir}/{name}")

    def _read_meminfo_bytes(self) -> int:
        """Parse MemTotal (kB) from /proc/meminfo and return bytes."""
        text = self._read_file_text(f"{self._proc}/meminfo")
        if not text:
            return 0
        for line in text.splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                # Expected: "MemTotal:    16384000 kB"
                try:
                    return int(parts[1]) * 1024
                except (IndexError, ValueError):
                    return 0
        return 0

    def _read_cpuinfo_model(self) -> str:
        """Parse the first human-readable CPU identifier from /proc/cpuinfo."""
        text = self._read_file_text(f"{self._proc}/cpuinfo")
        if not text:
            return ""

        # Prefer "model name" (x86). On ARM there is no model name;
        # fall back to "Hardware" (legacy ARM), then "CPU implementer".
        primary_key = "model name"
        fallback_keys = ("Hardware", "CPU implementer")

        fallback_hits: dict[str, str] = {}
        for line in text.splitlines():
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if not value:
                continue
            if key == primary_key:
                return value
            if key in fallback_keys and key not in fallback_hits:
                fallback_hits[key] = value

        for key in fallback_keys:
            if key in fallback_hits:
                return fallback_hits[key]
        return ""

    def _read_timezone(self) -> str:
        """Read /etc/localtime symlink target, strip zoneinfo prefix."""
        target = read_symlink(self._etc_localtime, self._log)
        prefix = "/usr/share/zoneinfo/"
        if target.startswith(prefix):
            return target[len(prefix):]
        return target

    def _detect_virtualization(self, hw_model: str) -> str:
        """Detect virtualization environment.

        Returns one of: docker / podman / vmware / virtualbox / qemu /
        kvm / hypervisor / none.
        """
        # Container markers win: they're the most specific.
        if os.path.exists(self._dockerenv_path):
            return "docker"
        if os.path.exists(self._containerenv_path):
            return "podman"

        # Hardware model hints from SMBIOS.
        model_lower = (hw_model or "").lower()
        if "vmware" in model_lower:
            return "vmware"
        if "virtualbox" in model_lower:
            return "virtualbox"
        if "qemu" in model_lower:
            return "qemu"
        if "kvm" in model_lower:
            return "kvm"

        # Generic hypervisor flag from cpuinfo (x86 only, but harmless).
        cpuinfo = self._read_file_text(f"{self._proc}/cpuinfo")
        for line in cpuinfo.splitlines():
            if line.startswith("flags") and " hypervisor" in f" {line}":
                return "hypervisor"

        return "none"

    # ------------------------------------------------------------------
    # Private helpers: kernel posture / container awareness (P1.5)
    # ------------------------------------------------------------------

    def _read_lsm_stack(self) -> str:
        """Read the active LSM stack from /sys/kernel/security/lsm."""
        return self._read_file_text(self._lsm_path)

    def _read_collector_caps(self) -> str:
        """Parse ``CapEff:`` from /proc/self/status, return hex mask.

        Example status line: ``CapEff:\\t0000003fffffffff``. Returns
        ``""`` on any failure (missing file, permission error, no line).
        """
        try:
            with open(self._self_status, "r") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        return line.split(":", 1)[1].strip()
        except (OSError, PermissionError):
            pass
        return ""

    def _read_ns_fingerprint(self) -> dict[str, str]:
        """Read 8 namespace inodes and compare to /proc/1/ns/*.

        Returns a dict with:
          fingerprint: comma-joined ns link targets for this process
          scope: "host" | "container" | "partial" | ""
        """
        namespaces = ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time")
        self_targets: dict[str, str] = {}
        pid1_targets: dict[str, str] = {}

        for ns in namespaces:
            self_link = f"{self._self_ns_dir}/{ns}"
            pid1_link = f"{self._pid1_ns_dir}/{ns}"
            try:
                self_targets[ns] = os.readlink(self_link)
            except (OSError, PermissionError):
                self_targets[ns] = ""
            try:
                pid1_targets[ns] = os.readlink(pid1_link)
            except (OSError, PermissionError):
                pid1_targets[ns] = ""

        if not any(self_targets.values()):
            return {"fingerprint": "", "scope": ""}

        fp = ",".join(
            self_targets[ns] for ns in namespaces if self_targets[ns]
        )

        if not any(pid1_targets.values()):
            # Cannot compare — ambiguous.
            return {"fingerprint": fp, "scope": ""}

        differing = sum(
            1 for ns in namespaces
            if self_targets[ns] and pid1_targets[ns]
            and self_targets[ns] != pid1_targets[ns]
        )
        if differing == 0:
            scope = "host"
        elif differing == len(namespaces):
            scope = "container"
        else:
            scope = "partial"
        return {"fingerprint": fp, "scope": scope}

    def _detect_container_runtime(self) -> str:
        """Classify container runtime by filesystem + cgroup signals."""
        # Filesystem markers.
        if os.path.exists(self._dockerenv_path):
            return "docker"
        if os.path.exists(self._containerenv_path):
            return "podman"
        if os.path.exists(self._systemd_container_marker):
            try:
                with open(self._systemd_container_marker, "r") as fh:
                    marker = fh.read().strip()
                if marker:
                    return marker  # e.g. "lxc", "systemd-nspawn"
            except OSError:
                pass

        # /proc/1/cgroup substring match.
        try:
            with open(self._pid1_cgroup, "r") as fh:
                cgroup = fh.read()
            if "kubepods" in cgroup:
                return "kubernetes"
            if "/docker/" in cgroup or "docker-" in cgroup:
                return "docker"
            if "/lxc/" in cgroup or "lxc-" in cgroup:
                return "lxc"
            if "/podman/" in cgroup or "podman-" in cgroup:
                return "podman"
        except (OSError, PermissionError):
            pass

        return ""

    def _detect_hidepid_active(self) -> bool:
        """Return True if /proc is mounted with ``hidepid=1`` or ``hidepid=2``."""
        try:
            with open(self._mountinfo, "r") as fh:
                for line in fh:
                    # mountinfo mount point is field 5 (0-indexed 4).
                    if " / /proc " not in line and " /proc " not in line:
                        continue
                    if "hidepid=" not in line:
                        continue
                    if "hidepid=1" in line or "hidepid=2" in line:
                        return True
        except (OSError, PermissionError):
            pass
        return False

    # ------------------------------------------------------------------
    # Private helpers: process table
    # ------------------------------------------------------------------

    def _read_process_entry(
        self, proc_pid: int, target_pid: int
    ) -> ProcessEntry | None:
        """Read a single process entry from /proc/<pid>. Returns None on failure."""
        proc_dir = f"{self._proc}/{proc_pid}"
        try:
            stat_fields, comm_name = self._parse_proc_stat(proc_pid)
            ppid = int(stat_fields[1])
            start_time = int(stat_fields[19])
        except (OSError, PermissionError, ValueError, IndexError):
            return None

        cmd_line = self._read_cmdline(proc_pid)
        uid = self._read_uid(proc_dir)
        rss = self._read_rss(proc_dir)

        return ProcessEntry(
            pid=proc_pid,
            ppid=ppid,
            uid=uid,
            is_target=(proc_pid == target_pid),
            start_time=start_time,
            rss=rss,
            exe_name=comm_name,
            cmd_line=cmd_line,
            user="",
        )

    def _read_uid(self, proc_dir: str) -> int:
        """Read the real UID from /proc/<pid>/status."""
        try:
            with open(f"{proc_dir}/status", "r") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        return int(line.split()[1])
        except (OSError, PermissionError, ValueError):
            pass
        return 0

    def _read_rss(self, proc_dir: str) -> int:
        """Read RSS in bytes from /proc/<pid>/statm (field 1, in pages).

        Uses the cached ``self._page_size`` so ARM64 hosts with 16k/64k
        pages report correct RSS values. (Pre-P1.6.1 this was hardcoded
        to 4096 and reported 1/4 or 1/16 of actual RSS on those hosts.)
        """
        try:
            with open(f"{proc_dir}/statm", "r") as fh:
                rss_pages = int(fh.read().split()[1])
                return rss_pages * self._page_size
        except (OSError, PermissionError, ValueError, IndexError):
            pass
        return 0

    # ------------------------------------------------------------------
    # Private helpers: connection table
    # ------------------------------------------------------------------

    def _build_inode_pid_map(self) -> dict[int, int]:
        """Build a mapping from socket inode to owning PID.

        Scans /proc/*/fd/ for symlinks matching ``socket:[inode]``.
        """
        inode_pid: dict[int, int] = {}
        try:
            proc_entries = os.listdir(self._proc)
        except (OSError, PermissionError):
            return inode_pid

        for name in proc_entries:
            if not name.isdigit():
                continue
            pid = int(name)
            fd_dir = f"{self._proc}/{pid}/fd"
            try:
                fd_names = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue
            for fd_name in fd_names:
                self._try_map_socket_inode(fd_dir, fd_name, pid, inode_pid)

        return inode_pid

    def _try_map_socket_inode(
        self,
        fd_dir: str,
        fd_name: str,
        pid: int,
        inode_pid: dict[int, int],
    ) -> None:
        """Attempt to map a single fd symlink to a socket inode."""
        try:
            target = os.readlink(f"{fd_dir}/{fd_name}")
            if target.startswith("socket:[") and target.endswith("]"):
                inode = int(target[8:-1])
                inode_pid[inode] = pid
        except (OSError, PermissionError, ValueError):
            pass

    def _parse_net_file(
        self,
        path: str,
        family: int,
        protocol: int,
        inode_pid: dict[int, int],
    ) -> list[ConnectionEntry]:
        """Parse a /proc/net/{tcp,tcp6,udp,udp6} file."""
        entries: list[ConnectionEntry] = []
        is_ipv6 = (family == AF_INET6)
        try:
            with open(path, "r") as fh:
                next(fh, None)  # skip header
                for line in fh:
                    entry = self._parse_net_line(line, family, protocol, is_ipv6, inode_pid)
                    if entry is not None:
                        entries.append(entry)
        except (OSError, PermissionError) as exc:
            self._log.warning("Cannot read %s: %s", path, exc)

        return entries

    def _parse_net_line(
        self,
        line: str,
        family: int,
        protocol: int,
        is_ipv6: bool,
        inode_pid: dict[int, int],
    ) -> ConnectionEntry | None:
        """Parse a single line from a /proc/net file."""
        fields = line.split()
        if len(fields) < 10:
            return None

        try:
            local_addr, local_port = self._parse_hex_addr(fields[1], is_ipv6)
            remote_addr, remote_port = self._parse_hex_addr(fields[2], is_ipv6)
            state = int(fields[3], 16)
            inode = int(fields[9])
        except (ValueError, IndexError):
            return None

        pid = inode_pid.get(inode, 0)
        return ConnectionEntry(
            pid=pid,
            family=family,
            protocol=protocol,
            state=state,
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
        )

    def _parse_unix_file(
        self, path: str, inode_pid: dict[int, int],
    ) -> list[ConnectionEntry]:
        """Parse ``/proc/net/unix`` into ``ConnectionEntry`` rows.

        ``/proc/net/unix`` format::

            Num RefCount Protocol Flags Type St Inode Path
            0000000000000000: 00000002 00000000 00010000 0001 01 12345 /var/run/foo.sock

        We record the inode-owning pid, use AF_UNIX as family, and set
        protocol=0 (unix domain sockets don't carry a tcp/udp protocol).
        The socket path is not stored in the wire type yet — it would
        need a spec extension. Recorded as a bare connection row for pid
        attribution. Missing file or malformed lines degrade silently.
        """
        entries: list[ConnectionEntry] = []
        try:
            with open(path, "r") as fh:
                text = fh.read()
        except (OSError, PermissionError) as exc:
            self._log.debug("Cannot read %s: %s", path, exc)
            return entries

        if not text:
            return entries

        lines = text.splitlines()
        if len(lines) < 2:
            return entries
        for line in lines[1:]:  # skip header
            fields = line.split()
            if len(fields) < 7:
                continue
            try:
                inode = int(fields[6])
            except ValueError:
                continue
            pid = inode_pid.get(inode, 0)
            entries.append(ConnectionEntry(
                pid=pid,
                family=AF_UNIX,
                protocol=0,
                state=0,
                local_addr=b"\x00" * 16,
                local_port=0,
                remote_addr=b"\x00" * 16,
                remote_port=0,
            ))
        return entries

    def _parse_hex_addr(
        self, addr_port: str, is_ipv6: bool
    ) -> tuple[bytes, int]:
        """Parse a hex address:port string from /proc/net.

        For IPv4: the hex address is a 32-bit host-byte-order integer.
        Convert to 4 bytes in network order, padded to 16 bytes.

        For IPv6: 32 hex chars as 4 groups of 32-bit words in host byte
        order. Each group is byte-reversed to network order.

        Returns (16-byte address, port number).
        """
        hex_addr, hex_port = addr_port.split(":")
        port = int(hex_port, 16)

        if is_ipv6:
            addr_bytes = self._decode_ipv6_addr(hex_addr)
        else:
            addr_bytes = self._decode_ipv4_addr(hex_addr)

        return addr_bytes, port

    def _decode_ipv4_addr(self, hex_addr: str) -> bytes:
        """Decode a /proc/net IPv4 hex address to 16-byte padded form."""
        return decode_proc_net_ipv4(hex_addr)

    def _decode_ipv6_addr(self, hex_addr: str) -> bytes:
        """Decode a /proc/net IPv6 hex address to 16-byte form."""
        return decode_proc_net_ipv6(hex_addr)

    # ------------------------------------------------------------------
    # Private helpers: handle table
    # ------------------------------------------------------------------

    def _read_handle_entry(self, pid: int, fd_num: int, fd_dir: str) -> HandleEntry:
        """Read a single handle entry for a file descriptor."""
        try:
            target = os.readlink(f"{fd_dir}/{fd_num}")
            handle_type = self._classify_handle(target)
        except (OSError, PermissionError):
            target = ""
            handle_type = HT_UNKNOWN

        return HandleEntry(pid=pid, fd=fd_num, handle_type=handle_type, path=target)

    @staticmethod
    def _classify_handle(target: str) -> int:
        """Classify a file descriptor target path into a handle type."""
        if target.startswith("socket:"):
            return HT_SOCKET
        if target.startswith("pipe:"):
            return HT_PIPE
        if target.startswith("/dev/"):
            return HT_DEVICE
        if os.path.isdir(target):
            return HT_DIR
        return HT_FILE

    # ------------------------------------------------------------------
    # Private helpers: memory-forensics anchors (P1.6.1)
    # ------------------------------------------------------------------

    def _read_kernel_build_id(self) -> str:
        """Parse ``NT_GNU_BUILD_ID`` from ``/sys/kernel/notes``.

        The file exposes the raw ELF ``.notes`` section payload (not a
        full ELF), so we feed it directly to ``parse_elf_notes`` rather
        than ``extract_build_id``.
        """
        try:
            with open(self._sys_kernel_notes, "rb") as fh:
                data = fh.read()
        except (OSError, PermissionError):
            return ""
        little_endian = sys.byteorder == "little"
        try:
            for name, ntype, desc in parse_elf_notes(
                data, is_64bit=True, little_endian=little_endian,
            ):
                if ntype == 3 and name == "GNU" and desc:
                    return desc.hex()
        except Exception:  # defensive — parser is designed not to raise
            return ""
        return ""

    def _read_kaslr_anchor(self) -> dict[str, int]:
        """Parse ``_stext`` / ``_text`` and ``page_offset_base`` from
        ``/proc/kallsyms``.

        On ``kptr_restrict`` hosts all addresses are zero; the caller
        emits ``kallsyms_restricted`` as a ``collector_warning``.
        """
        text_va = 0
        page_offset = 0
        fallback_text_va = 0
        try:
            with open(self._proc_kallsyms, "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    sym = parts[2]
                    if sym == "_stext":
                        try:
                            text_va = int(parts[0], 16)
                        except ValueError:
                            pass
                    elif sym == "_text" and fallback_text_va == 0:
                        try:
                            fallback_text_va = int(parts[0], 16)
                        except ValueError:
                            pass
                    elif sym == "page_offset_base":
                        try:
                            page_offset = int(parts[0], 16)
                        except ValueError:
                            pass
                    if text_va and page_offset:
                        break
        except (OSError, PermissionError):
            return {"text_va": 0, "page_offset": 0}

        if text_va == 0:
            text_va = fallback_text_va
        return {"text_va": text_va, "page_offset": page_offset}

    def _read_btf_hash_and_size(self) -> tuple[str, int]:
        """SHA256 + size of ``/sys/kernel/btf/vmlinux`` (streamed)."""
        try:
            hasher = hashlib.sha256()
            size = 0
            with open(self._sys_kernel_btf, "rb") as fh:
                while True:
                    chunk = fh.read(4096)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    size += len(chunk)
            if size == 0:
                return "", 0
            return hasher.hexdigest(), size
        except (OSError, PermissionError):
            return "", 0

    def _read_vmcoreinfo_hash(self) -> tuple[str, str]:
        """Return ``(sha256_hex, present_flag)`` for ``/sys/kernel/vmcoreinfo``.

        Root-only on most systems; degrades gracefully.
        """
        try:
            with open(self._sys_kernel_vmcoreinfo, "rb") as fh:
                data = fh.read()
        except (OSError, PermissionError):
            return "", "0"
        if not data:
            return "", "0"
        return hashlib.sha256(data).hexdigest(), "1"

    def _read_kernel_config_hash(self) -> str:
        """SHA256 of the running kernel config, via ``/proc/config.gz`` or
        ``/boot/config-<release>``."""
        try:
            with open(self._proc_config_gz, "rb") as fh:
                compressed = fh.read()
            if compressed:
                try:
                    decompressed = gzip.decompress(compressed)
                except (OSError, ValueError, EOFError):
                    decompressed = b""
                if decompressed:
                    return hashlib.sha256(decompressed).hexdigest()
        except (OSError, PermissionError):
            pass

        try:
            release = os.uname().release
        except OSError:
            return ""
        boot_path = f"{self._boot_config_prefix}{release}"
        try:
            with open(boot_path, "rb") as fh:
                data = fh.read()
            if data:
                return hashlib.sha256(data).hexdigest()
        except (OSError, PermissionError):
            pass
        return ""

    def _read_clock_triple(self) -> tuple[int, int, int]:
        """Three ``clock_gettime`` samples as ns integers."""
        values: list[int] = []
        for clk_name in ("CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"):
            clk_id = getattr(time, clk_name, None)
            if clk_id is None:
                values.append(0)
                continue
            try:
                values.append(int(time.clock_gettime(clk_id) * 1_000_000_000))
            except OSError:
                values.append(0)
        return values[0], values[1], values[2]

    def _read_clocksource(self) -> str:
        """Read the active clocksource name."""
        return self._read_file_text(self._clocksource_file)

    def _read_zram_devices(self) -> str:
        """Enumerate active zram devices.

        Returns comma-separated ``name:size:algo`` entries; empty on
        failure. Iterates ``/sys/block/zram*``.
        """
        entries: list[str] = []
        try:
            for name in sorted(os.listdir(self._sys_block_zram_dir)):
                if not name.startswith("zram"):
                    continue
                dev_dir = f"{self._sys_block_zram_dir}/{name}"
                disksize = self._read_file_text(f"{dev_dir}/disksize")
                algo_raw = self._read_file_text(f"{dev_dir}/comp_algorithm")
                algo = algo_raw.split()[0] if algo_raw else ""
                if disksize:
                    entries.append(f"{name}:{disksize}:{algo}")
        except (OSError, PermissionError):
            return ""
        return ",".join(entries)

    def _read_zswap_enabled(self) -> str:
        """Read zswap enabled flag; normalize ``Y``/``1`` → ``"1"``."""
        raw = self._read_file_text(self._zswap_enabled_file)
        if not raw:
            return ""
        token = raw.strip().upper()
        if token in ("Y", "1", "TRUE", "ENABLED"):
            return "1"
        if token in ("N", "0", "FALSE", "DISABLED"):
            return "0"
        return ""

    def _read_thp_mode(self) -> str:
        """Parse bracketed value from transparent_hugepage/enabled."""
        raw = self._read_file_text(self._thp_enabled_file)
        if not raw:
            return ""
        start = raw.find("[")
        end = raw.find("]", start + 1)
        if start == -1 or end == -1:
            return ""
        return raw[start + 1:end]

    def _read_ksm_active(self) -> str:
        """Read ``/sys/kernel/mm/ksm/run``."""
        return self._read_file_text(self._ksm_run_file)

    def _read_directmap_sizes(self) -> tuple[int, int, int]:
        """Parse DirectMap4k/2M/1G (KiB) from ``/proc/meminfo``."""
        text = self._read_file_text(f"{self._proc}/meminfo")
        if not text:
            return 0, 0, 0
        sizes = {"DirectMap4k": 0, "DirectMap2M": 0, "DirectMap1G": 0}
        for line in text.splitlines():
            for key in sizes:
                if line.startswith(key + ":"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            sizes[key] = int(parts[1])
                        except ValueError:
                            pass
                    break
        return sizes["DirectMap4k"], sizes["DirectMap2M"], sizes["DirectMap1G"]

    def _read_la57_pti(self) -> tuple[str, str]:
        """Detect LA57 (5-level paging) and Meltdown/PTI state."""
        la57 = ""
        try:
            with open(self._proc_cpuinfo, "r") as fh:
                for line in fh:
                    if line.startswith("flags"):
                        tokens = line.split(":", 1)[1].split() if ":" in line else []
                        la57 = "1" if "la57" in tokens else "0"
                        break
        except (OSError, PermissionError):
            la57 = ""

        pti = ""
        try:
            with open(self._meltdown_vuln_file, "r") as fh:
                content = fh.read().strip()
            if "PTI" in content:
                pti = "1"
            elif "Not affected" in content or "Vulnerable" in content:
                pti = "0"
        except (OSError, PermissionError):
            pti = ""

        return la57, pti

    def _read_physmem_map(self) -> list[tuple[int, int, str]]:
        """Parse top-level entries from ``/proc/iomem``.

        Nested (indented) entries are ignored. Each top-level row has
        form ``<start>-<end> : <label>`` with hex addresses. When the
        collector is non-root, the kernel zeroes the addresses — the
        list is still recorded so the caller can surface
        ``iomem_root_only``.
        """
        ranges: list[tuple[int, int, str]] = []
        try:
            with open(self._proc_iomem, "r") as fh:
                for line in fh:
                    if not line or line[0] in (" ", "\t"):
                        continue
                    stripped = line.rstrip("\n")
                    if " : " not in stripped:
                        continue
                    addr_part, _, label = stripped.partition(" : ")
                    if "-" not in addr_part:
                        continue
                    start_s, _, end_s = addr_part.partition("-")
                    try:
                        start = int(start_s.strip(), 16)
                        end = int(end_s.strip(), 16)
                    except ValueError:
                        continue
                    ranges.append((start, end, label.strip()))
        except (OSError, PermissionError):
            return []
        return ranges

    # ------------------------------------------------------------------
    # P1.6.2 — module / loader posture + kernel module list
    # ------------------------------------------------------------------

    # Taint-letter -> bit index mapping per
    # Documentation/admin-guide/tainted-kernels.rst.
    _TAINT_LETTER_TO_BIT = {
        "P": 0,  "F": 1,  "S": 2,  "R": 3,  "M": 4,
        "B": 5,  "U": 6,  "D": 7,  "A": 8,  "W": 9,
        "C": 10, "I": 11, "O": 12, "E": 13, "L": 14,
        "K": 15, "X": 16, "T": 17, "N": 18,
    }

    def _read_ld_so_preload(self) -> str:
        """Read ``/etc/ld.so.preload`` verbatim (stripped, empty on miss)."""
        return self._read_file_text(self._etc_ld_so_preload)

    def _read_kernel_lockdown(self) -> str:
        """Return the bracketed selection from the lockdown sysfs file.

        Typical content: ``"none [integrity] confidentiality"``. When
        the file is absent or unparseable, returns an empty string.
        """
        text = self._read_file_text(self._sys_kernel_lockdown)
        if not text:
            return ""
        # Scan for "[token]"
        start = text.find("[")
        end = text.find("]", start + 1) if start >= 0 else -1
        if start >= 0 and end > start:
            return text[start + 1:end].strip()
        return ""

    def _read_modules_disabled(self) -> str:
        """Return ``modules_disabled`` sysctl value as ``"0"``/``"1"``/``""``."""
        return self._read_file_text(self._proc_modules_disabled)

    def _read_module_sig_enforce(self) -> str:
        """Return ``module_sig_enforce`` sysctl value as ``"0"``/``"1"``/``""``."""
        return self._read_file_text(self._proc_module_sig_enforce)

    def _parse_proc_modules(self) -> list[tuple[str, int, int, int, int]]:
        """Parse ``/proc/modules``.

        Each line is ``name size refcount [deps] state base``. Returns
        ``(name, size, refcount, state_code, base_int)`` tuples.
        ``state_code``: 0=Unknown, 1=Live, 2=Loading, 3=Unloading.
        ``base`` is ``0`` when the kernel redacts it under
        ``kptr_restrict``.
        """
        text = self._read_file_text(self._proc_modules)
        if not text:
            return []
        rows: list[tuple[int, int, int, int, int]] = []  # type: ignore[assignment]
        parsed: list[tuple[str, int, int, int, int]] = []
        state_map = {"Live": 1, "Loading": 2, "Unloading": 3}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[0]
            try:
                size = int(parts[1])
                refcount = int(parts[2])
            except ValueError:
                continue
            # parts[3] is dependency list (may be "-"); skip it.
            state_str = parts[4] if len(parts) > 4 else ""
            state_code = state_map.get(state_str, 0)
            base = 0
            if len(parts) > 5:
                base_s = parts[-1]
                try:
                    if base_s.startswith("0x") or base_s.startswith("0X"):
                        base = int(base_s, 16)
                    else:
                        base = int(base_s, 16)
                except ValueError:
                    base = 0
            parsed.append((name, size, refcount, state_code, base))
        return parsed

    def _parse_taint_letters(self, text: str) -> int:
        """Decode a ``/sys/module/<name>/taint`` letter string to a bitmask."""
        mask = 0
        for ch in text:
            bit = self._TAINT_LETTER_TO_BIT.get(ch)
            if bit is not None:
                mask |= (1 << bit)
        # Clamp to u8 — only the low byte is stored on the wire.
        return mask & 0xFF

    def _read_sysfs_modules(self) -> dict[str, int]:
        """Walk ``/sys/module/<name>/`` and decode each module's taint file."""
        out: dict[str, int] = {}
        try:
            names = os.listdir(self._sys_module_dir)
        except (OSError, PermissionError):
            return {}
        for name in names:
            taint_path = f"{self._sys_module_dir}/{name}/taint"
            try:
                with open(taint_path, "r") as fh:
                    text = fh.read().strip()
            except (OSError, PermissionError):
                # Entry exists but taint file is absent -> taint 0.
                text = ""
            out[name] = self._parse_taint_letters(text) if text else 0
        return out

    def _build_kernel_module_list(self) -> KernelModuleList:
        """Combine ``/proc/modules`` + ``/sys/module`` with skew detection.

        Flags:
          * bit 0 (``0x01``) — present in ``/proc/modules`` only
            (hiding from sysfs)
          * bit 1 (``0x02``) — present in ``/sys/module`` only
            (hiding from ``/proc/modules``)

        Both sources missing a module means the module is hidden from
        the kernel too — there's nothing the collector can say about it.
        """
        proc_rows = self._parse_proc_modules()
        proc_map: dict[str, tuple[int, int, int, int]] = {
            name: (size, refcount, state, base)
            for (name, size, refcount, state, base) in proc_rows
        }
        sysfs_map = self._read_sysfs_modules()

        rows: list[KernelModuleRow] = []
        seen: set[str] = set()

        # /proc/modules preserves load order — walk it first so we
        # keep that ordering when possible.
        for name, size, refcount, state, base in proc_rows:
            seen.add(name)
            in_sysfs = name in sysfs_map
            flags = 0 if in_sysfs else 0x01
            taint = sysfs_map.get(name, 0)
            rows.append(KernelModuleRow(
                name=name, size=size, refcount=refcount,
                state=state, taint=taint, base=base, flags=flags,
            ))

        # Modules present only in /sys/module (sysfs-only) — append in
        # sorted order for determinism.
        for name in sorted(sysfs_map.keys()):
            if name in seen:
                continue
            rows.append(KernelModuleRow(
                name=name, size=0, refcount=0,
                state=0, taint=sysfs_map[name], base=0, flags=0x02,
            ))

        return KernelModuleList(rows=rows)

    def collect_kernel_module_list(self) -> KernelModuleList:
        """Public entry point for the ``InvestigationCollector`` protocol."""
        try:
            return self._build_kernel_module_list()
        except Exception as exc:  # noqa: BLE001
            self._log.warning("kernel module list collection failed: %s", exc)
            return KernelModuleList()

    # ------------------------------------------------------------------
    # P1.6.4 — rootkit / anti-forensics / sysctl posture
    # ------------------------------------------------------------------

    def _read_kexec_loaded(self) -> str:
        """Return the contents of ``/sys/kernel/kexec_loaded`` stripped.

        ``"1"`` means a kexec-staged kernel image is pre-loaded —
        a rootkit persistence vector. ``"0"`` is the safe default.
        Empty string on read failure.
        """
        return self._read_file_text(self._kexec_loaded_file)

    def _stat_auth_log_files(self) -> dict[str, tuple[int, int]]:
        """Stat the auth-log integrity files.

        Returns ``{name: (size_bytes, mtime_ns)}`` where ``name`` is one
        of ``wtmp`` / ``utmp`` / ``btmp`` / ``lastlog``. Missing files
        are omitted from the dict. Analysts use these to detect
        log-zeroing and timestamp tampering.
        """
        out: dict[str, tuple[int, int]] = {}
        paths = (
            ("wtmp", self._wtmp_path),
            ("utmp", self._utmp_path),
            ("btmp", self._btmp_path),
            ("lastlog", self._lastlog_path),
        )
        for name, path in paths:
            try:
                st = os.stat(path)
            except (OSError, PermissionError):
                continue
            out[name] = (st.st_size, int(st.st_mtime * 1_000_000_000))
        return out

    def _sweep_hidden_pids(self, cap: int = 32768) -> int:
        """Detect hidden PIDs via ``/proc`` listdir vs ``kill(pid, 0)`` sweep.

        Returns the count of PIDs the kernel knows about but ``/proc``
        doesn't list. Caps the scan at ``min(pid_max, cap)`` so cost is
        bounded (~1 second at 32768).

        Uses the class-attribute ``_kill_func`` wrapper for
        testability — production code invokes the real ``os.kill``;
        tests inject a deterministic stub that never touches the host
        process table.
        """
        try:
            with open(self._pid_max_file, "r") as fh:
                pid_max = int(fh.read().strip())
        except (OSError, ValueError):
            pid_max = cap

        upper = min(pid_max, cap)

        try:
            visible = {
                int(name) for name in os.listdir(self._proc)
                if name.isdigit()
            }
        except OSError:
            return 0

        hidden = 0
        kill = self._kill_func
        for pid in range(1, upper + 1):
            if pid in visible:
                continue
            try:
                kill(pid, 0)
                # Signal delivered (or EPERM coerced to success) —
                # the pid exists but is not listed in /proc.
                hidden += 1
            except ProcessLookupError:
                # ESRCH — pid truly doesn't exist.
                pass
            except PermissionError:
                # EPERM — pid exists but we can't signal it; still
                # hidden from /proc, still a finding.
                hidden += 1
            except OSError:
                # Any other kernel-side error: be conservative and
                # skip (don't inflate the hidden count).
                pass
        return hidden

    def _read_sysctl_text(self, path: str) -> str:
        """Read a single-line sysctl file; strip; empty string on failure."""
        return self._read_file_text(path)

    def _read_security_sysctls(self) -> dict[str, str]:
        """Batch-read the 13 P1.6.4 security sysctls.

        Keys match :class:`TargetSystemInfo` field names; values are
        the stripped file contents or ``""`` on failure. Paths are
        instance attributes so tests redirect at the fixture.
        """
        return {
            "kptr_restrict":             self._read_sysctl_text(self._sysctl_kptr_restrict),
            "dmesg_restrict":            self._read_sysctl_text(self._sysctl_dmesg_restrict),
            "perf_event_paranoid":       self._read_sysctl_text(self._sysctl_perf_event_paranoid),
            "unprivileged_bpf_disabled": self._read_sysctl_text(self._sysctl_unprivileged_bpf_disabled),
            "unprivileged_userns_clone": self._read_sysctl_text(self._sysctl_unprivileged_userns_clone),
            "kexec_load_disabled":       self._read_sysctl_text(self._sysctl_kexec_load_disabled),
            "sysrq_state":               self._read_sysctl_text(self._sysctl_sysrq),
            "suid_dumpable":             self._read_sysctl_text(self._sysctl_suid_dumpable),
            "protected_symlinks":        self._read_sysctl_text(self._sysctl_protected_symlinks),
            "protected_hardlinks":       self._read_sysctl_text(self._sysctl_protected_hardlinks),
            "protected_fifos":           self._read_sysctl_text(self._sysctl_protected_fifos),
            "protected_regular":         self._read_sysctl_text(self._sysctl_protected_regular),
            "bpf_jit_enable":            self._read_sysctl_text(self._sysctl_bpf_jit_enable),
        }

    def _read_core_pattern(self) -> str:
        """Read ``/proc/sys/kernel/core_pattern`` stripped.

        A value starting with ``"|"`` pipes coredumps to a program,
        which is a known attacker persistence vector — the caller
        emits a ``core_pattern_pipe`` warning on that condition.
        """
        return self._read_file_text(self._core_pattern_file)

    def _detect_audit_state(self) -> tuple[str, int]:
        """Detect auditd state + count configured audit rules.

        Returns ``(state, rules_count)`` where ``state`` is
        ``"running"`` if a pid file exists, ``"absent"`` if only the
        auditd binary is installed, otherwise ``""`` (not installed).
        ``rules_count`` is the number of non-comment, non-blank lines
        in ``/etc/audit/audit.rules``.
        """
        state = ""
        if (os.path.exists(self._auditd_pid_file)
                or os.path.exists(self._auditd_pid_file_alt)):
            state = "running"
        elif os.path.exists(self._auditd_binary):
            state = "absent"

        rules_count = 0
        try:
            with open(self._audit_rules_file, "r") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    rules_count += 1
        except (OSError, PermissionError):
            pass
        return state, rules_count

    def _detect_journald_storage(self) -> str:
        """Detect journald persistence mode.

        Preference: parse ``Storage=`` from ``journald.conf``. Fall
        back to directory existence when the config is silent (auto
        mode). Returns ``"persistent"`` / ``"volatile"`` / ``"none"``
        / ``"auto"`` or ``""`` on hard failure.
        """
        try:
            with open(self._journald_conf_file, "r") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#") or "=" not in stripped:
                        continue
                    if stripped.startswith("Storage"):
                        value = stripped.partition("=")[2].strip().strip('"').lower()
                        if value in ("persistent", "volatile", "none", "auto"):
                            return value
        except (OSError, PermissionError):
            pass
        # Directory-existence fallback — covers ``Storage=auto``.
        try:
            if (os.path.isdir(self._journald_persistent_dir)
                    and os.listdir(self._journald_persistent_dir)):
                return "persistent"
        except OSError:
            pass
        if os.path.isdir(self._journald_volatile_dir):
            return "volatile"
        return ""

    def _detect_ntp_sync(self) -> str:
        """Detect NTP/time-synchronisation state.

        Returns ``"yes"`` when systemd-timesyncd or chrony show signs
        of active sync, ``"unknown"`` otherwise. We never return
        ``"no"`` because an absent marker could equally mean "we
        can't tell" on this host (unusual timesync daemon, restricted
        filesystem access).
        """
        if os.path.exists(self._timesync_sync_file):
            return "yes"
        if os.path.exists(self._chrony_drift_file):
            return "yes"
        return "unknown"

    def _read_cpu_vuln_digest(self) -> str:
        """Produce a stable 16-hex-char digest of
        ``/sys/devices/system/cpu/vulnerabilities/*``.

        One-way hash (SHA-256, first 8 bytes) of the sorted
        ``name:content`` lines. Analysts compare digests across hosts
        to spot microcode / mitigation drift without storing the full
        vulnerability string list on the wire.
        """
        try:
            entries = sorted(os.listdir(self._cpu_vuln_dir))
        except (OSError, PermissionError):
            return ""
        parts: list[str] = []
        for name in entries:
            path = os.path.join(self._cpu_vuln_dir, name)
            try:
                with open(path, "r") as fh:
                    content = fh.read().strip()
            except (OSError, PermissionError):
                continue
            parts.append(f"{name}:{content}")
        if not parts:
            return ""
        full = "\n".join(parts).encode("utf-8")
        return hashlib.sha256(full).hexdigest()[:16]

    def _walk_persistence_manifest(self) -> list[PersistenceRow]:
        """Walk the configured persistence source roots + single files.

        Uses ``os.lstat`` so symlinks are recorded as-is (an attacker
        might point a systemd unit at a decoy path; we want the
        symlink's own mtime, not the target's). Missing source roots
        are silently skipped — this is the expected case on minimal /
        non-systemd systems.
        """
        rows: list[PersistenceRow] = []
        for source_id, root in self._persistence_sources:
            try:
                entries = os.listdir(root)
            except (OSError, PermissionError):
                continue
            for name in entries:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except (OSError, PermissionError):
                    continue
                rows.append(PersistenceRow(
                    source=source_id,
                    path=path,
                    mtime_ns=int(st.st_mtime * 1_000_000_000),
                    size=int(st.st_size),
                    mode=int(st.st_mode) & 0xFFFFFFFF,
                ))
        for source_id, single_path in self._persistence_single_files:
            try:
                st = os.lstat(single_path)
            except (OSError, PermissionError):
                continue
            rows.append(PersistenceRow(
                source=source_id,
                path=single_path,
                mtime_ns=int(st.st_mtime * 1_000_000_000),
                size=int(st.st_size),
                mode=int(st.st_mode) & 0xFFFFFFFF,
            ))
        return rows

    def collect_persistence_manifest(self) -> PersistenceManifest:
        """Public entry point — walks the P1.6.4 persistence sources.

        Linux-primary. Non-Linux collectors return an empty manifest.
        Gated at the engine layer by
        ``AttributionConfig.include_persistence_manifest``; this method
        itself always runs the walk when called.
        """
        try:
            rows = self._walk_persistence_manifest()
        except Exception as exc:  # noqa: BLE001
            self._log.warning("persistence manifest walk failed: %s", exc)
            rows = []
        return PersistenceManifest(rows=rows)
