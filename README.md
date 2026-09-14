# MemSlicer

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.3.0-green)](pyproject.toml)

A memory acquisition tool that captures process memory snapshots into the MSL (Memory Slice) binary format. Supports multiple debugger backends (Frida, GDB, LLDB) and targets across Windows, Linux, macOS, Android, and iOS. Designed for forensic analysis, reverse engineering, and security research.

---

## Features

- **Pluggable backends**: Frida (local, USB, remote), GDB (MI3 protocol), LLDB (Python API)
- **Investigation mode**: Captures system-wide context — process tables, network connections, file handles, boot time, OS details
- **AEAD encryption**: AES-256-GCM with Argon2id key derivation (default in investigation mode)
- MSL binary format with region metadata, module info, and page-level granularity
- Compression support: zstd, lz4, or none
- BLAKE3 integrity chain across all blocks
- Region filtering by memory protection, address range, or path patterns
- Page-level acquisition with quality assessment
- RWX region detection for forensic analysis
- Progress reporting with per-region and per-page statistics
- Companion log file captures all debug output regardless of verbosity flag
- Cross-platform OS information collection for forensic context

---

## Installation



```bash
pip install memslicer
```

This installs memslicer with all backends (Frida, GDB, LLDB).

### From Source

```bash
git clone git@github.com:MemorySlice/memslicer.git
cd memslicer
pip install -e .
```

Requires Python >= 3.10. Backend-specific requirements:
- **Frida**: A compatible Frida agent on the target device (for USB/remote targets)
- **GDB**: `gdb` binary with MI3 support (installed separately)
- **LLDB**: LLDB Python module on `PYTHONPATH` (typically via Xcode on macOS)

---

## Privileges

Reading another process's address space is a privileged operation on every
supported OS. A capture needs **either elevated privileges, or a relaxed
`ptrace` policy** — memslicer cannot grant itself either one.

These are requirements imposed by the operating system, not by memslicer. The
tool diagnoses them before it touches the target and refuses with
[exit code 3](#exit-codes) rather than failing halfway.

### Linux

Either of these works:

**1. Run elevated.**

```bash
sudo memslicer 1234
```

or grant `CAP_SYS_PTRACE` to the binary, if you would rather not run the whole
capture as root.

**2. Set Yama `ptrace_scope` to `0`, and run as the user that owns the target.**

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope   # until reboot
sudo sysctl -w kernel.yama.ptrace_scope=0              # equivalent
```

Make it survive a reboot with a file in `/etc/sysctl.d/`.

> **`ptrace_scope = 0` is not a substitute for root.** It restores classic
> same-uid `ptrace` — it does **not** let an unprivileged user attach to a
> process owned by somebody else. Capturing another user's process still needs
> root or `CAP_SYS_PTRACE`, whatever the scope is set to.

| `ptrace_scope` | Meaning |
|---|---|
| `0` | Classic — any process may attach to another process of the same uid. |
| `1` | Distro default — only a direct parent, or a `PR_SET_PTRACER` grantee, may attach. |
| `2` | Admin-only — attaching requires `CAP_SYS_PTRACE`. |
| `3` | `ptrace` disabled system-wide. **One-way latch**: it cannot be relaxed at runtime. Reboot with `kernel.yama.ptrace_scope` set to 0–2 via `/etc/sysctl.d/`, and record the constraint in the case notes. |

memslicer **never changes `ptrace_scope` itself.** It reports the value it
found and prints the command to change it; making and documenting that change
is the examiner's decision. Silently relaxing a kernel security control
mid-acquisition would be both a forensic and a security problem.

An AppArmor or SELinux profile on the target can deny `ptrace` even for root.
If an attach fails with `ptrace_scope` at 0 and root in hand, check
`sudo dmesg | grep -i apparmor` for a `DENIED` line.

The preflight check runs on **Linux, for a numeric PID**. Attaching by process
name, or to a remote device, skips it — a failure there surfaces from the
backend instead, without the diagnosis.

### macOS

`task_for_pid` requires root for any process not signed with the
`com.apple.security.get-task-allow` entitlement:

```bash
sudo memslicer 1234 -b lldb
```

With **System Integrity Protection** enabled, Apple-signed and hardened-runtime
processes cannot be attached at all, root or not. memslicer warns when it
detects this:

> macOS System Integrity Protection (SIP) is enabled. Attaching to Apple-signed
> or hardened-runtime processes will fail. Only debug builds with
> `com.apple.security.get-task-allow` entitlement can be debugged. Disable SIP
> or use the Frida backend for broader process access.

Check the current state with `csrutil status`.

### Windows

Opening another user's process, or a service, requires **Administrator** —
`SeDebugPrivilege` is what actually grants it. Run the terminal elevated.

Note that memslicer does **not** request `SeDebugPrivilege` itself; it relies
on the backend and on the token it inherits. Without elevation the capture may
still succeed for a process you own, but investigation mode degrades: the
handle table comes back empty rather than failing the capture.

### Android

`frida-server` must be running **as root** on the device:

```bash
adb shell "su -c '/data/local/tmp/frida-server &'"
memslicer com.example.app -U
```

memslicer probes for root-management markers (Magisk, KernelSU, APatch, Zygisk)
and records what it finds as forensic metadata. That detection is **advisory
only** — it never gates a capture, and a rooted device should not be assumed to
have intact runtime integrity.

The GDB backend is a poor fit here, and memslicer says so: SELinux policy may
block attachment and `/proc` access, and ART managed-heap data will be opaque.
Prefer `-b frida -U`.

### iOS

A **jailbroken** device with `frida-server` installed. Stock iOS sandboxing
blocks the process access memslicer needs, and utilities such as `ps` and
`lsof` may be missing entirely, which thins out investigation mode.

Using the LLDB backend remotely additionally requires `debugserver` on the
device. The Frida backend is the more reliable route for iOS.

### Troubleshooting

A refused attach names the cause and the fix, and touches nothing on the
target:

```
Error: cannot attach to PID 3145: Yama ptrace_scope is 2 — attaching is admin-only and requires CAP_SYS_PTRACE
also: target runs as uid 0 while this process runs as euid 501 without CAP_SYS_PTRACE
  → Yama ptrace_scope is 2 (admin-only): attaching requires CAP_SYS_PTRACE. Run as root, or: sudo sysctl -w kernel.yama.ptrace_scope=0
  → Run the acquisition as root (sudo), or grant CAP_SYS_PTRACE to the memslicer binary.
  Full environment record: dump.msl.log
```

Each `→` line is a remediation for one blocker. A `Probable cause:` line
appears when something was observed that did not itself block — an AppArmor
profile on the target, for instance.

The full privilege situation at capture time — uid, capabilities,
`ptrace_scope`, LSM profile, tracer PID — is written to the companion
`.msl.log` even when the capture succeeds, so the constraint is documented in
the case file.

---

## Usage

### Basic Examples

Dump a process by name (Frida backend, default):

```bash
memslicer chrome
```

Dump a process by PID:

```bash
memslicer 1234
```

Specify output file and compression:

```bash
memslicer chrome -o chrome_dump.msl -c zstd
```

### Linux

*Needs root, `CAP_SYS_PTRACE`, or `ptrace_scope = 0` with a same-uid target — see [Privileges](#privileges).*

Dump a local process using Frida (default backend):

```bash
memslicer 1234
```

Use GDB backend (no Frida dependency required):

```bash
memslicer 1234 -b gdb
```

Investigation mode with full system context (encrypted by default):

```bash
memslicer 1234 -I -v
```

This captures process tables, network connections, file handles, boot time, hostname, and OS details from `/proc` alongside the memory dump. The output is encrypted with AES-256-GCM; you will be prompted for a passphrase.

Investigation mode without encryption:

```bash
memslicer 1234 -I --no-encrypt
```

### Android

*Needs `frida-server` running as root on the device — see [Privileges](#privileges).*

Dump a process on a USB-connected Android device (requires Frida server on device):

```bash
memslicer com.example.app -U
```

Override OS detection if auto-detection fails:

```bash
memslicer com.example.app -U --os android
```

Investigation mode on Android (captures system properties, process table, network state):

```bash
memslicer com.example.app -U -I
```

Connect to a remote Frida server on Android (e.g., over Wi-Fi):

```bash
memslicer com.example.app -R 192.168.1.10:27042 --os android
```

Dump by PID on a USB Android device:

```bash
memslicer 12345 -U --os android -o app_dump.msl -c zstd
```

### macOS / iOS

*macOS needs root unless the target carries `get-task-allow`; iOS needs a jailbroken device — see [Privileges](#privileges).*

Use LLDB backend on macOS (no Frida needed):

```bash
memslicer 1234 -b lldb
```

Dump a process on a USB-connected iOS device (jailbroken, Frida):

```bash
memslicer SpringBoard -U --os ios -I
```

### Windows

*Needs Administrator for another user's process or a service — see [Privileges](#privileges).*

Dump a local process on Windows:

```bash
memslicer 1234 -b gdb
```

Or with Frida:

```bash
memslicer notepad.exe
```

### Common Workflows

**Forensic capture with full debug log:**

```bash
memslicer 4892 -v -o evidence.msl -c zstd
```

**Investigation mode with encryption (default):**

```bash
memslicer 4892 -I -o investigation.msl
```

**Capture only readable and writable regions:**

```bash
memslicer chrome --filter-prot rw-
```

**Capture a specific address range:**

```bash
memslicer chrome --filter-addr 0x7fff00000000-0x7fffffffffff
```

**Include regions without read permission (for completeness):**

```bash
memslicer chrome --include-unreadable
```

**Limit region size and set a per-read timeout:**

```bash
memslicer chrome --max-region-size 104857600 --read-timeout 30
```

---

## CLI Reference

```
Usage: memslicer [OPTIONS] TARGET

  Dump process memory to MSL format.

  TARGET is a PID (integer) or process name (string).

  Supports 4 acquisition modes:
    Analysis unencrypted (default), Analysis encrypted (-E),
    Investigation encrypted (-I, default), Investigation unencrypted (-I --no-encrypt).

Options:
  -b, --backend [frida|gdb|lldb]  Debugger backend. [default: frida]
  -o, --output PATH               Output .msl file path.
  -c, --compress [none|zstd|lz4]  Compression algorithm. [default: none]
  -U, --usb                       Connect to a USB device (Frida only).
  -R, --remote HOST:PORT          Connect to a remote Frida server (Frida only).
  --os [windows|linux|macos|android|ios]
                                  Override automatic OS detection.
  --filter-prot TEXT              Filter regions by protection (e.g. 'rw-', 'r--').
  --filter-addr TEXT              Filter regions by address range (e.g. '0x1000-0x2000').
  -v, --verbose                   Enable verbose/debug output.
  --read-timeout FLOAT            Per-read timeout in seconds. [default: 10]
  --include-unreadable            Include memory regions with no read permission.
  --skip-kernel-pseudo            Skip kernel pseudo-mappings ([vvar], [vsyscall])
                                  instead of attempting them.
  --max-region-size INT           Skip regions larger than this size (0 = no limit).
  -I, --investigation             Investigation mode: capture system-wide context.
  -E, --encrypt                   Enable AEAD encryption (AES-256-GCM + Argon2id).
  --no-encrypt                    Disable encryption (overrides -I default).
  --passphrase TEXT               Encryption passphrase (prompted if not provided).
  --help                          Show this message and exit.
```

---

## Output Format

MemSlicer writes memory snapshots to the MSL (Memory Slice) binary format. Each file contains:

- A file header with format version, target metadata, and capture timestamp
- Process identity block (ppid, session ID, start time, executable path, command line)
- Module list with base addresses, sizes, and paths
- Per-region records with base address, size, protection flags, and page-level data
- BLAKE3 integrity chain across all blocks
- Optional compressed data blocks (zstd or lz4)
- Optional AEAD encryption (AES-256-GCM + Argon2id)

When **investigation mode** (`-I`) is enabled, the MSL file additionally contains:
- System context: boot time, hostname, domain, OS detail string
- System-wide process table (all running processes)
- Network connection table (TCP/UDP, IPv4/IPv6)
- File handle table (open file descriptors for the target process)

A companion `.log` file is written alongside every `.msl` file and contains the full debug output of the capture session, regardless of whether `-v` was passed.

### Example Output Summary

```
MemSlicer - Dumping chrome -> chrome_1773528836.msl
Backend: frida | Compression: none | Device: local
Progress: [##################################################] 100.00% Complete
  Regions : 2621/4199 (1578 filtered out)
            1578 no read permission (use --include-unreadable to include)
  Pages   : 12,500/12,800 captured (97.7%)
  Excluded: 3 pages in kernel pseudo-mappings ([vvar], [vvar_vclock]) — unreadable by design, not counted as data loss
  Bytes   : 51,200,000 / 52,428,800 readable (97.7%)
  Missing : 2 unreadable range(s)
            0x7f2c00a000-0x7f2c00c000 (8,192 bytes)
  Modules : 142
  Duration: 12.34s
  File    : chrome_1773528836.msl (48,234,567 bytes)
  Log     : chrome_1773528836.msl.log
  Quality : GOOD (page-level: 97.7%)
```

`Excluded:` counts kernel-provided mappings (`[vvar]`, `[vvar_vclock]`,
`[vsyscall]`) that appear readable in `/proc/<pid>/maps` but fault on every
`ptrace` read. They are not data loss, so they are kept out of the quality
figure — but they are always named rather than silently dropped. `[vdso]` is
genuinely readable and is captured normally.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Capture completed. |
| `1`  | Capture failed, or was aborted. |
| `2`  | Invalid command-line usage. |
| `3`  | Attach refused by preflight — the environment forbids this capture and **nothing on the target was touched**. |

Exit code `3` is accompanied by the reason and concrete remediation, and the
full environment record (uid, capabilities, `ptrace_scope`, LSM profile) is
written to the companion `.msl.log` so the constraint is documented in the case
file. See [Privileges](#privileges) for what each refusal means and how to
resolve it.

---

## Architecture

```
src/memslicer/
  cli.py                         CLI entry point (click)
  acquirer/
    engine.py                    Backend-agnostic acquisition engine
    bridge.py                    DebuggerBridge protocol definition
    frida_bridge.py              Frida backend
    gdb_bridge.py                GDB/MI3 backend
    lldb_bridge.py               LLDB Python API backend
    frida_acquirer.py            Backward-compatible Frida wrapper
    investigation.py             InvestigationCollector protocol
    attach_preflight.py          Linux ptrace preflight diagnosis
    errors.py                    Error types and exit codes
    platform_detect.py           OS and architecture detection
    region_filter.py             Region filtering logic
    collectors/
      __init__.py                Factory: create_collector()
      linux.py                   Linux collector (/proc)
      android.py                 Android collector (SELinux-aware + system properties)
      darwin.py                  macOS collector (sysctl, ps, lsof)
      ios.py                     iOS collector (sandbox-aware, SystemVersion.plist)
      windows.py                 Windows collector (wmic, tasklist, netstat)
      frida_remote.py            Remote collector via Frida JS RPC
      fallback.py                NullCollector for unsupported platforms
      constants.py               Shared constants (protocols, handle types)
  msl/
    writer.py                    MSL file writer
    encryption.py                AES-256-GCM + Argon2id encryption
    constants.py                 Format constants and enumerations
    integrity.py                 BLAKE3 integrity chain
    types.py                     MSL data types
  utils/
    protection.py                Memory protection parsing
    padding.py                   Alignment utilities
    timestamps.py                Timestamp helpers
```

---

## Development

### Setup

```bash
git clone git@github.com:MemorySlice/memslicer.git
cd memslicer
pip install -e ".[dev]"
```

Dev dependencies include `pytest`, `pytest-cov`, and `ruff`.

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=memslicer --cov-report=term-missing
```

### Linting

```bash
ruff check src/
ruff format src/
```

---

## Dependencies

| Package        | Version  | Purpose                        |
|----------------|----------|--------------------------------|
| frida-tools    | >=12.0   | Frida backend and agent        |
| blake3         | >=0.4    | BLAKE3 integrity checksums     |
| click          | >=8.0    | CLI framework                  |
| zstandard      | >=0.20   | Zstd compression               |
| lz4            | >=4.0    | LZ4 compression                |
| cryptography   | >=42.0   | AES-256-GCM encryption         |
| argon2-cffi    | >=23.1   | Argon2id key derivation         |

---

## License

Apache 2.0
