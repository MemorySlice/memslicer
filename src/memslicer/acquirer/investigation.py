"""Protocol and data types for investigation-mode data collection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from memslicer.msl.types import ProcessEntry, ConnectionEntry, HandleEntry


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

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect identity metadata for the target process."""
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
