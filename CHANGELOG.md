# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Bug Fixes

- Attach failures now name their cause and the fix, instead of printing
  `unable to access /proc/<PID>/mem: Permission denied`
  ([#2](https://github.com/MemorySlice/memslicer/issues/2)). memslicer never
  changes `ptrace_scope` itself — it recommends the change and leaves it to the
  examiner.
- Kernel pseudo-mappings (`[vvar]`, `[vvar_vclock]`, `[vsyscall]`) are recorded
  `UNMAPPED` rather than failed, so Linux 6.13+ captures no longer report
  ~99.9% completeness. `[vdso]` is still captured.
- Short reads are no longer recorded as fully captured, which had shifted page
  data out of step with the page-state map.
- GDB: remote captures no longer come back empty — mapping permissions were
  discarded, so every region was filtered out as unreadable.
- GDB: `^error` replies are detected again. A failing `-target-attach` raised
  nothing, and the capture continued against a process it had not attached to.
- GDB: partly-unreadable reads no longer write bytes at the wrong address.
- GDB: console output is unescaped, so mapped paths keep their names and
  architecture detection works.
- GDB: mapping permissions are no longer glued onto the mapped path.
- GDB: `Yes (*)` in `info sharedlibrary` is no longer taken for a library path.
- GDB: non-ASCII characters in paths survive MI's octal escaping.
- GDB: a read after GDB has exited degrades to failed pages instead of aborting
  the capture.
- GDB: an unparseable read reply is no longer reported as a proven unreadable
  address.
- GDB: remote targets no longer read the local machine's `/proc/<pid>/maps`.
  The PID recorded in the capture now comes from GDB.
- GDB: the OS recorded for a remote target is the target's, read from
  `show osabi`, not this machine's. A Linux host dumping a remote macOS or
  Windows target had been writing `Linux` into the capture header.
- GDB: the page size recorded for a remote target is the target's, read from
  `AT_PAGESZ` in `info auxv`, not this machine's. Only `PageSizeLog2` is stored
  in the file and the page-state map is sized to match, so the wrong value had
  produced a capture that was self-consistent and wrong, with nothing in it to
  say so.
- LLDB: the page size for a remote target is asked of the target
  (`getconf PAGESIZE` over the platform connection) instead of assumed to be
  4096. aarch64 kernels with 16K or 64K pages had been recorded with a
  page-state map several times too fine.
- GDB and LLDB: when the target's page size cannot be established, the log now
  says so instead of assuming 4096 silently.
- GDB: module paths containing spaces are no longer truncated at the first one.
  `/usr/lib/My App/libfoo.so` had been recorded as `/usr/lib/My`, with a base
  and size that still looked valid.
- GDB: `disconnect()` closes GDB's pipes, joins its output reader, and reaps the
  process after `kill()`. The thread, the pipes and a stale queue entry had all
  outlived the connection.
- GDB: remote Android targets are detected as Android and get the
  reduced-capability warning, rather than being recorded as plain Linux.
- GDB: a console command carrying a `"` or `\` is escaped before it is wrapped
  for MI, instead of ending the quoted string early and leaving the rest to be
  read as further arguments. Every current caller passes a fixed literal, so
  this closes a trap rather than a live fault.
- GDB: an unreadable `/proc/<pid>/maps` no longer aborts the capture. The file
  is listed for any live PID, including ones the user cannot read.
- GDB: `disconnect()` no longer raises when the process refuses both
  `terminate()` and `kill()`. It is called from callers' `finally` blocks,
  where raising would have masked the acquisition error that got it there.
- GDB: a `info sharedlibrary` row with no path can no longer take the following
  line as its own, which had recorded GDB's own footnote text as a module path.
- GDB and LLDB: an empty `--remote` is treated as local. It had attached
  locally while every platform probe took the remote path. The investigation
  collector in `cli.py` used the old rule too, and had disagreed with the
  attribution recorded for the same capture.
- GDB: a `--remote` value carrying whitespace or a quote is escaped before it
  reaches `-target-select`, instead of arriving as extra MI arguments.
- LLDB: the local page size is validated like the remote one. `sysconf`
  reports `-1` for "indeterminate" rather than raising, and that had been
  accepted and carried into the capture.
- LLDB: remote Android targets are detected as Android, from the target's own
  `/proc/<pid>/maps`.
- LLDB: the Python bindings are located with `lldb -P` rather than by guessing
  directory layouts. The backend had refused to start on a machine set up with
  `xcode-select --install` — CommandLineTools keeps LLDB in
  `Library/PrivateFrameworks`, which none of the guessed paths covered — and on
  Homebrew LLVM and distribution packages.
- LLDB: bindings that are found but cannot be loaded no longer report as "not
  available". That failure means the interpreter is not the one LLDB was built
  against, and the message now says so, naming the directory and the running
  interpreter, instead of advising an install that is already present. The
  search also continues past a directory whose bindings will not load, so a
  second LLDB build that would have worked is still found.
- LLDB: a failing platform-shell probe can no longer fail the attach. The
  bindings raise types outside any documented contract, and the probe is
  best-effort with a caller that already handles "no answer".
- LLDB: the remote Android check reads the first 32 KiB of the target's maps
  rather than the whole file, matching the local path. A browser or JVM target
  had pulled megabytes across the connection during attach.
- LLDB: a page-aligned short read is no longer mistaken for a map edge, which
  had silently lost readable pages.
- LLDB: a wholly unreadable region no longer triggers repeated whole-span reads.
- LLDB: region lookups are ignored unless they contain the address asked about,
  and are cleared on `disconnect()`.

### Changes

- A capture whose page size had to be assumed says so in the file. The bridges
  record `page_size_assumed_4k` alongside the collector's own warnings, so the
  uncertainty is no longer visible only in the log — a region carries just
  `PageSizeLog2` and a page-state map sized to match, which agree with each
  other whether or not the number was ever measured.
- The page sizes the MSL format accepts are defined once, in
  `msl.constants.valid_page_size`. The writer enforced the rule and the
  acquisition backends restated it, so a change to one could have left the
  backends discarding page sizes the format had started accepting.
- GDB: `info proc mappings` is fetched once per capture rather than twice.
  Platform detection and region enumeration both need it, and for a browser or
  JVM it runs to hundreds of kilobytes crossing the connection each time.
- Failed reads split at the reported fault boundary instead of one read per
  page. A 20 MB chunk with one bad page takes about 3 reads, not 5121.
- GDB and LLDB now report where a read failed, so they get that splitting too.
  Neither passes on an address that merely echoes the one it was asked about.
- GDB caps a single MI read at 1 MiB and splits larger requests.
- GDB read replies are no longer logged in full; the companion `.msl.log` had
  been growing to roughly twice the size of the dump it documents.
- GDB reply parsing is about 9x faster per megabyte read.
- LLDB caches the last region lookup, saving a debug-server round trip per
  failed page.
- LLDB `read_memory` and `enumerate_*` before `connect()` raise a clear error
  instead of `AttributeError`.
- Region names from `/proc/<pid>/maps` are now available on the Frida backend,
  so `[heap]` and `[stack]` are classified as they already were on GDB and LLDB.
- New `Missing :` summary section and `.msl.log` report naming every unreadable
  address range with its mapping name.
- New quality tier `EXCELLENT` for captures with zero failed pages.
- New `--skip-kernel-pseudo` flag to skip kernel pseudo-mappings outright.
- New exit code `3` — the attach was refused and nothing on the target was
  touched. Distinguishes that from a capture that started and failed (`1`).
- The Yama `ptrace_scope` check is shared by all three backends; the Frida
  bridge gained the check it never had.


## [0.2.7] - 2026-04-20

### Changes

- fixes regarding the latest changes in the specification; add now the possibility to change the blake3 hash

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
