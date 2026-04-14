# Changelog

All notable changes to this project will be documented in this file.



## [0.2.4] - 2026-04-14

### Changes

- serveral improvements in the linux acquisition

## [0.2.3] - 2026-04-12

### Bug Fixes

- fix: workflow fixes regarding GROUP

## [0.1.0] - 2026-03-15

Initial release of MemSlicer.

- Frida-based memory acquisition by PID or process name
- MSL binary format with region metadata, module info, and page-level granularity
- Compression support: zstd, lz4, none
- BLAKE3 integrity checksums
- Region filtering by protection, address range, and path patterns
- Local, USB (iOS/Android), and remote Frida server support
- Progress bar with page-level quality assessment
- Companion `.msl.log` file with full debug output
- Human-readable skip reason labels in end summary
- CI workflows for PyPI publishing and automated changelog
