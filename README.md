# MemSlicer

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-green)](pyproject.toml)

A Frida-based memory acquisition tool that captures process memory snapshots into the MSL (Memory Slice) binary format. Designed for forensic analysis, reverse engineering, and security research across Windows, Linux, macOS, Android, and iOS.

---

## Features

- Capture process memory by PID or process name
- MSL binary format with region metadata, module info, and page-level granularity
- Compression support: zstd, lz4, or none
- BLAKE3 integrity checksums for all captured data
- Region filtering by memory protection, address range, or path patterns
- Page-level acquisition with quality assessment
- RWX region detection for forensic analysis
- Progress reporting with per-region and per-page statistics
- Companion log file captures all debug output regardless of verbosity flag
- Local, USB (iOS/Android), and remote Frida server support

---

## Installation



```bash
pip install memslicer
```

This will give you the `memslicer` command.

### From Source

```bash
git clone https://github.com/danielbaier/memslicer.git
cd memslicer
pip install .
```

Requires Python >= 3.10 and a compatible version of the Frida agent on the target device.

---

## Usage

### Basic Examples

Dump a process by name:

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

Dump a process on a USB-connected Android or iOS device:

```bash
memslicer com.example.app -U
```

Connect to a remote Frida server:

```bash
memslicer chrome -R 192.168.1.10:27042
```

### Common Workflows

**Forensic capture with full debug log:**

```bash
memslicer 4892 -v -o evidence.msl -c zstd
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

  Capture process memory into an MSL snapshot file.

  TARGET is either a PID (integer) or a process name (string).

Options:
  -o, --output PATH               Output .msl file path.
  -c, --compress [none|zstd|lz4]  Compression algorithm. [default: none]
  -U, --usb                       Connect to a USB device (iOS/Android).
  -R, --remote HOST:PORT          Connect to a remote Frida server.
  --os [windows|linux|macos|android|ios]
                                  Override automatic OS detection.
  --filter-prot TEXT              Filter regions by protection (e.g. 'rw-', 'r--').
  --filter-addr TEXT              Filter regions by address range (e.g. '0x1000-0x2000').
  -v, --verbose                   Enable verbose/debug output.
  --read-timeout FLOAT            Per-read timeout in seconds. [default: 10]
  --include-unreadable            Include memory regions with no read permission.
  --max-region-size INT           Skip regions larger than this size in bytes (0 = no limit).
  --help                          Show this message and exit.
```

---

## Output Format

MemSlicer writes memory snapshots to the MSL (Memory Slice) binary format. Each file contains:

- A file header with format version, target metadata, and capture timestamp
- Per-region records with base address, size, protection flags, module path, and page-level data
- Module table listing all mapped modules identified during capture
- Optional BLAKE3 checksums for integrity verification
- Optional compressed data blocks (zstd or lz4)

A companion `.log` file is written alongside every `.msl` file and contains the full debug output of the capture session, regardless of whether `-v` was passed.

### Example Output Summary

```
MemSlicer - Dumping Chrome -> Chrome_1773528836.msl
Compression: none | Device: local
Progress: [##################################################] 100.00% Complete
  Regions : 2621/4199 (1578 filtered out)
            1578 no read permission (use --include-unreadable to include)
  Pages   : 12,500/12,800 captured (97.7%)
  Bytes   : 51,200,000 / 52,428,800 readable (97.7%)
  Modules : 142
  Duration: 12.34s
  File    : Chrome_1773528836.msl (48,234,567 bytes)
  Log     : Chrome_1773528836.msl.log
  Quality : GOOD (page-level: 97.7%)
```

---

## Architecture

```
src/memslicer/
  cli.py                    CLI entry point (click)
  acquirer/
    frida_acquirer.py       Frida-based memory acquisition
    region_filter.py        Region filtering logic
    platform_detect.py      OS and device detection
  msl/
    writer.py               MSL file writer
    compression.py          Compression backends
    constants.py            Format constants
    integrity.py            BLAKE3 checksum handling
    types.py                MSL data types
  utils/
    protection.py           Memory protection parsing
    padding.py              Alignment utilities
    timestamps.py           Timestamp helpers
```

---

## Development

### Setup

```bash
git clone https://github.com/danielbaier/memslicer.git
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
| frida-tools    | >=12.0   | Frida Python bindings and CLI  |
| blake3         | >=0.4    | Integrity checksums            |
| click          | >=8.0    | CLI framework                  |
| zstandard      | >=0.20   | Zstd compression               |
| lz4            | >=4.0    | LZ4 compression                |

---

## License

Apache 2.0
