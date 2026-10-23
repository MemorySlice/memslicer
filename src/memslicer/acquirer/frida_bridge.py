"""Frida-based DebuggerBridge implementation."""
from __future__ import annotations

import bisect
import logging
from typing import TYPE_CHECKING, Any

from memslicer.acquirer.attach_preflight import (
    PreflightResult, enforce_attach_preflight,
)
from memslicer.acquirer.bridge import (
    MemoryRange, ModuleInfo, PlatformInfo, ReadResult, RegisterValue,
    ThreadInfo, parse_fault_addr, register_width_bytes,
)
from memslicer.acquirer.errors import AttachError
from memslicer.acquirer.platform_detect import detect_platform, parse_maps_text
from memslicer.acquirer.residency import page_count
from memslicer.msl.constants import ArchType, ThreadState

if TYPE_CHECKING:
    from memslicer.acquirer.investigation import InvestigationCollector


# Frida JS script for RPC exports
_FRIDA_SCRIPT = """\
// ---- Page residency (Linux): /proc/self/pagemap, else mincore(2) ----
// Every API is feature-detected with typeof: Frida 17 dropped the static
// Module.* lookups, and older GumJS File objects have no seek()/readBytes().
var _pagemapFile = null;
var _mincoreFn = null;
var _residencyMethodCache = null;
// Sorted [[start, end, swapKb], ...] from /proc/self/smaps, or null while
// VmSwap is 0 kB and mincore() can be trusted for every VMA.
var _swapTable = null;
// Why detection ended at 'none' (or fell past pagemap); for the host log.
var _residencyWhy = '';

function _noteWhy(reason) {
    _residencyWhy = _residencyWhy === '' ? reason : _residencyWhy + '; ' + reason;
}

function _errorText(e) {
    return (e && typeof e.message === 'string') ? e.message : String(e);
}

function _findGlobalExport(sym) {
    if (typeof Module.findGlobalExportByName === 'function') {
        return Module.findGlobalExportByName(sym);
    }
    if (typeof Module.findExportByName === 'function') {
        return Module.findExportByName(null, sym);
    }
    return null;
}

function _readTextFile(path) {
    if (typeof File === 'undefined') return '';
    try {
        if (typeof File.readAllText === 'function') return File.readAllText(path);
    } catch (e) {}
    try {
        var f = new File(path, 'r'), out = '', chunk;
        if (typeof f.readText !== 'function') { f.close(); return ''; }
        while ((chunk = f.readText(65536)) !== '') out += chunk;
        f.close();
        return out;
    } catch (e) {
        return '';
    }
}

// Page indices covered by [addr, addr + size), rounded outwards exactly like
// residency.page_count() on the host, so the mask length is what it expects.
// User-space addresses are far below 2^53, so the double arithmetic is exact.
function _pageSpan(addr, size) {
    var start = Number(ptr(addr).toString());
    var first = Math.floor(start / Process.pageSize);
    var last = Math.floor((start + size - 1) / Process.pageSize);
    return {first: first, pages: last - first + 1};
}

function _openPagemap() {
    if (Process.platform !== 'linux') { _noteWhy('pagemap: not linux'); return null; }
    if (typeof File === 'undefined' ||
        typeof File.prototype.seek !== 'function' ||
        typeof File.prototype.readBytes !== 'function') {
        _noteWhy('pagemap: File.seek/readBytes missing');
        return null;
    }
    var f = new File('/proc/self/pagemap', 'rb');
    var probe = f.readBytes(8);
    if (probe && probe.byteLength === 8) return f;
    try { f.close(); } catch (e) {}
    _noteWhy('pagemap: short read');
    return null;
}

// VmSwap of this process in kB; -1 when /proc/self/status is unreadable, so
// the caller assumes swap may exist.
function _vmSwapKb() {
    var status = _readTextFile('/proc/self/status');
    var m = /^VmSwap:[ \\t]*([0-9]+)[ \\t]*kB/m.exec(status);
    return m === null ? -1 : parseInt(m[1], 10);
}

// Per-VMA swap usage from /proc/self/smaps: each header line
// "start-end perms ..." is followed by a "Swap: N kB" line. Addresses stay
// below 2^53, so parseInt(hex, 16) is exact. null when smaps is unreadable.
function _loadSwapTable() {
    var text = _readTextFile('/proc/self/smaps');
    if (text === '') return null;
    var header = /^([0-9a-f]+)-([0-9a-f]+) /;
    var swapLine = /^Swap:[ \\t]*([0-9]+)[ \\t]*kB/;
    var lines = text.split('\\n'), table = [], current = null;
    for (var i = 0; i < lines.length; i++) {
        var h = header.exec(lines[i]);
        if (h !== null) {
            current = [parseInt(h[1], 16), parseInt(h[2], 16), 0];
            table.push(current);
            continue;
        }
        var sw = swapLine.exec(lines[i]);
        if (sw !== null && current !== null) current[2] = parseInt(sw[1], 10);
    }
    table.sort(function(a, b) { return a[0] - b[0]; });
    return table;
}

// The swap-table entry whose [start, end) contains addr, else null.
function _findSwapEntry(addr) {
    var lo = 0, hi = _swapTable.length - 1;
    while (lo <= hi) {
        var mid = (lo + hi) >> 1;
        if (_swapTable[mid][0] <= addr) lo = mid + 1; else hi = mid - 1;
    }
    if (hi < 0) return null;
    var entry = _swapTable[hi];
    return addr < entry[1] ? entry : null;
}

function _swapTableSummary() {
    var withSwap = 0;
    for (var i = 0; i < _swapTable.length; i++) {
        if (_swapTable[i][2] > 0) withSwap++;
    }
    return 'swap table: ' + _swapTable.length + ' VMAs, ' + withSwap + ' with swap';
}

function _mincoreUsable() {
    var sym = _findGlobalExport('mincore');
    if (sym === null || sym === undefined || sym.isNull()) {
        _noteWhy('mincore export missing');
        return false;
    }
    // mincore() cannot see swapped-out pages. With VmSwap at 0 kB it is
    // trusted everywhere; otherwise /proc/self/smaps says per VMA whether
    // swap is involved and _mincoreMask() refuses to answer for those VMAs.
    // Neither readable => no trust, which keeps the acquisition lossless.
    _swapTable = null;
    if (_vmSwapKb() !== 0) {
        var table = _loadSwapTable();
        if (table === null || table.length === 0) {
            _noteWhy('smaps unreadable');
            return false;
        }
        _swapTable = table;
    }
    _mincoreFn = new NativeFunction(sym, 'int', ['pointer', 'size_t', 'pointer']);
    return true;
}

function _detectResidencyMethod() {
    _residencyWhy = '';
    try {
        _pagemapFile = _openPagemap();
        if (_pagemapFile !== null) return 'pagemap';
    } catch (e) {
        _pagemapFile = null;
        _noteWhy('pagemap: ' + _errorText(e));
    }
    try {
        if (_mincoreUsable()) return 'mincore';
    } catch (e) {
        _noteWhy('mincore: ' + _errorText(e));
    }
    return 'none';
}

function _residencyDetail() {
    var method = _currentResidencyMethod();
    if (method === 'pagemap') return 'pagemap';
    if (method === 'mincore') {
        if (_swapTable === null) return 'mincore (VmSwap 0 kB, no swap table)';
        return 'mincore (' + _swapTableSummary() + ')';
    }
    return 'none: ' + (_residencyWhy === '' ? 'unknown' : _residencyWhy);
}

function _currentResidencyMethod() {
    if (_residencyMethodCache === null) {
        _residencyMethodCache = _detectResidencyMethod();
    }
    return _residencyMethodCache;
}

function _pagemapMask(addr, size) {
    var span = _pageSpan(addr, size);
    var wanted = span.pages * 8;
    var whence = typeof File.SEEK_SET === 'number' ? File.SEEK_SET : 0;
    _pagemapFile.seek(span.first * 8, whence);
    var raw = _pagemapFile.readBytes(wanted);
    if (!raw || raw.byteLength !== wanted) return null;
    var entries = new Uint8Array(raw), mask = new Uint8Array(span.pages);
    for (var i = 0; i < span.pages; i++) {
        // Bit 63 (present) and bit 62 (swapped) both live in the top byte.
        mask[i] = (entries[i * 8 + 7] & 0xC0) ? 1 : 0;
    }
    return mask.buffer;
}

function _mincoreMask(addr, size) {
    var span = _pageSpan(addr, size);
    if (_swapTable !== null) {
        var spanStart = span.first * Process.pageSize;
        var spanEnd = spanStart + span.pages * Process.pageSize;
        var vma = _findSwapEntry(spanStart);
        // Unknown VMA, swap inside it, or a span leaving it: null makes the
        // host read every page instead of trusting a blind mincore().
        if (vma === null || vma[2] > 0 || spanEnd > vma[1]) return null;
    }
    var vec = Memory.alloc(span.pages);
    // mincore() insists on a page-aligned start address.
    var base = ptr(addr).and(ptr(Process.pageSize - 1).not());
    if (_mincoreFn(base, span.pages * Process.pageSize, vec) !== 0) return null;
    var flags = new Uint8Array(vec.readByteArray(span.pages));
    var mask = new Uint8Array(span.pages);
    for (var i = 0; i < span.pages; i++) mask[i] = flags[i] & 1;
    return mask.buffer;
}

// One register value as a '0x...' string, or null when it is not an
// integer register: vector registers arrive as ArrayBuffers and the
// context may carry null/undefined slots, none of which fit Table 19b.
function _hexRegister(v) {
    if (typeof v === 'number') {
        return (Number.isInteger(v) && v >= 0) ? '0x' + v.toString(16) : null;
    }
    if (v !== null && typeof v === 'object') {
        var text = String(v);
        return /^0x[0-9a-fA-F]+$/.test(text) ? text : null;
    }
    return null;
}

function _contextRegisters(context) {
    // Frida 17 exposes the general-purpose registers of a CpuContext as
    // accessors on its prototype (not enumerable, invisible to Object.keys
    // and JSON.stringify), while vector/flag registers are own properties.
    // Walk the object and its prototype chain and read every data property.
    var out = {};
    var seen = {};
    var obj = context;
    while (obj !== null && obj !== Object.prototype) {
        Object.getOwnPropertyNames(obj).forEach(function(name) {
            if (seen[name] || name === 'constructor') return;
            seen[name] = true;
            var value;
            try { value = context[name]; } catch (e) { return; }
            if (typeof value === 'function' || value === undefined) return;
            out[name] = value;
        });
        obj = Object.getPrototypeOf(obj);
    }
    return out;
}

function _hexContext(context) {
    var out = {};
    var regs = _contextRegisters(context);
    Object.keys(regs).forEach(function(name) {
        var text = _hexRegister(regs[name]);
        if (text !== null) out[name] = text;
    });
    return out;
}

rpc.exports = {
    enumerateRanges: function(prot) {
        return Process.enumerateRanges(prot);
    },
    readMemory: function(addr, size) {
        try {
            return ptr(addr).readByteArray(size);
        } catch (e) {
            return {
                __error: true, addr: addr, size: size,
                message: e.message || String(e), stack: e.stack || ''
            };
        }
    },
    readProcMaps: function() {
        if (Process.platform !== 'linux') return '';
        try {
            return File.readAllText('/proc/self/maps');
        } catch (e) {}
        try {
            // /proc/*/maps is a seq_file: a single read() can short-return,
            // so loop until exhausted.
            // GumJS File has readText/readBytes/readLine, never read().
            var f = new File('/proc/self/maps', 'r'), out = '', chunk;
            if (typeof f.readText !== 'function') { f.close(); return ''; }
            while ((chunk = f.readText(65536)) !== '') out += chunk;
            f.close();
            return out;
        } catch (e) {
            return '';
        }
    },
    getPageSize: function() {
        return Process.pageSize;
    },
    enumerateModules: function() {
        return Process.enumerateModules();
    },
    getPlatform: function() {
        return Process.platform;
    },
    getArch: function() {
        return Process.arch;
    },
    getPid: function() {
        return Process.id;
    },
    validateApi: function() {
        var p = ptr(0);
        return {
            ptrType: typeof ptr,
            readByteArrayType: typeof p.readByteArray,
            pageSize: Process.pageSize
        };
    },
    residencyMethod: function() {
        try {
            return _currentResidencyMethod();
        } catch (e) {
            return 'none';
        }
    },
    residencyDetail: function() {
        try {
            return _residencyDetail();
        } catch (e) {
            return 'none: ' + _errorText(e);
        }
    },
    queryResidency: function(addr, size) {
        try {
            var method = _currentResidencyMethod();
            if (method === 'pagemap' && _pagemapFile !== null) {
                return _pagemapMask(addr, size);
            }
            if (method === 'mincore' && _mincoreFn !== null) {
                return _mincoreMask(addr, size);
            }
            return null;
        } catch (e) {
            return null;
        }
    },
    enumerateStackPointers: function() {
        try {
            if (typeof Process.enumerateThreads !== 'function') return [];
            var pointers = [];
            Process.enumerateThreads().forEach(function(t) {
                if (t.context && t.context.sp) pointers.push(t.context.sp.toString());
            });
            return pointers;
        } catch (e) {
            return [];
        }
    },
    enumerateThreads: function() {
        // Every thread with its sampled register file; the thread keeps
        // running while it is read, so the values are not a snapshot.
        try {
            if (typeof Process.enumerateThreads !== 'function') return [];
            return Process.enumerateThreads().map(function(t) {
                return {
                    id: t.id,
                    name: (typeof t.name === 'string') ? t.name : '',
                    state: (typeof t.state === 'string') ? t.state : '',
                    context: _hexContext(t.context || {})
                };
            });
        } catch (e) {
            return [];
        }
    },
    closeResidency: function() {
        var f = _pagemapFile;
        _pagemapFile = null;
        _residencyMethodCache = null;
        _swapTable = null;
        _residencyWhy = '';
        if (f !== null) {
            try { f.close(); } catch (e) {}
        }
        return true;
    }
};
"""


def _parse_frida_addr(value: str | int) -> int:
    """Convert a Frida address (hex string or int) to int."""
    return int(value, 16) if isinstance(value, str) else value


def _ensure_bytes(data: Any) -> bytes:
    """Ensure data from Frida RPC is a bytes object."""
    return data if isinstance(data, bytes) else bytes(data)


def _parse_stack_pointer(value: Any) -> int | None:
    """Parse one agent-reported SP, ``None`` for anything that is not one."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        return _parse_frida_addr(value)
    except ValueError:
        return None


# Frida's ThreadState strings mapped onto spec Table 19a; anything else
# (including Frida's own "" for an unknown state) is UNKNOWN.
_FRIDA_THREAD_STATES: dict[str, ThreadState] = {
    "running": ThreadState.RUNNING,
    "stopped": ThreadState.STOPPED,
    "waiting": ThreadState.WAITING,
    "uninterruptible": ThreadState.UNINTERRUPTIBLE,
    "halted": ThreadState.HALTED,
}

# Frida exposes the generic ``pc``/``sp`` next to the canonical x86 names.
# The aliases are not x86 mnemonics (spec Section 5.7), so they are dropped
# whenever the canonical register is present.
_X86_ALIAS_CANONICAL: dict[ArchType, dict[str, str]] = {
    ArchType.x86: {"pc": "eip", "sp": "esp"},
    ArchType.x86_64: {"pc": "rip", "sp": "rsp"},
}


def _frida_thread_state(text: Any) -> ThreadState:
    """Spec thread state for a Frida ``ThreadState`` string."""
    if not isinstance(text, str):
        return ThreadState.UNKNOWN
    return _FRIDA_THREAD_STATES.get(text.lower(), ThreadState.UNKNOWN)


def _parse_register_value(value: Any, width: int) -> int | None:
    """Unsigned register value that fits *width* bytes, else ``None``.

    Accepts the agent's ``0x...`` strings and plain non-bool ints.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value, 16)
        except ValueError:
            return None
    if not isinstance(value, int) or value < 0 or value >= 1 << (width * 8):
        return None
    return value


def _drop_x86_aliases(context: dict[str, Any], arch: ArchType | None) -> dict[str, Any]:
    """*context* without the generic pc/sp keys that shadow x86 mnemonics."""
    canonical = _X86_ALIAS_CANONICAL.get(arch) if arch is not None else None
    if canonical is None:
        return context
    return {
        name: value for name, value in context.items()
        if canonical.get(name) not in context
    }


def _parse_registers(
    context: dict[str, Any], arch: ArchType | None, width: int,
) -> tuple[list[RegisterValue], bool]:
    """Register file from an agent context; the flag is ``True`` when any
    entry had to be left out."""
    lowered = {str(name).lower(): value for name, value in context.items()}
    registers: list[RegisterValue] = []
    partial = False
    for name, value in _drop_x86_aliases(lowered, arch).items():
        parsed = _parse_register_value(value, width)
        if parsed is None:
            partial = True
            continue
        registers.append(RegisterValue.from_int(name, parsed, width, arch))
    return registers, partial


# The only answers residencyMethod() may give; anything else is treated as
# "none" so a confused agent can never make the engine skip pages.
_RESIDENCY_METHODS = frozenset({"pagemap", "mincore", "none"})


class FridaBridge:
    """DebuggerBridge implementation using Frida."""

    def __init__(
        self,
        target: int | str,
        device: Any | None = None,
        read_timeout: float = 10.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self._target = target
        self._device = device
        self._read_timeout = read_timeout
        self._log = logger or logging.getLogger("memslicer")
        self._session: Any | None = None
        self._api: Any | None = None
        self._platform_info: PlatformInfo | None = None
        self._modules_cache: list[dict] | None = None
        # Lazily fetched (start, end, name) spans from the target's own maps;
        # None until the first enumerate_ranges() call.
        self._map_spans: list[tuple[int, int, str]] | None = None
        self._preflight: PreflightResult | None = None
        # Answer of the agent's residencyMethod(), fetched once per connection.
        self._residency_method: str | None = None

    @property
    def is_remote(self) -> bool:
        """Whether this bridge is connected to a remote target."""
        if self._device is None:
            return False
        device_type = getattr(self._device, 'type', 'local')
        return device_type != 'local'

    def _on_message(self, message: dict, data: bytes | None) -> None:
        """Handle messages from the Frida JS agent."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "read-error":
                self._log.warning(
                    "JS read-error at %s size=%s: %s",
                    payload.get("addr", "?"),
                    payload.get("size", "?"),
                    payload.get("error", "unknown"),
                )
                stack = payload.get("stack", "")
                if stack:
                    self._log.debug("  JS stack: %s", stack)
        elif message.get("type") == "error":
            self._log.error(
                "Frida script error: %s", message.get("description", message),
            )

    def connect(self) -> None:
        """Attach to target process and load the Frida agent script."""
        import frida as _frida

        if self._device is None:
            self._device = _frida.get_local_device()

        if isinstance(self._target, int):
            self._log.info("Attaching to PID %d...", self._target)
        else:
            self._log.info("Attaching to process '%s'...", self._target)

        self._preflight = enforce_attach_preflight(
            self._target if isinstance(self._target, int) else None,
            is_remote=self.is_remote,
            logger=self._log,
        )

        try:
            session = self._device.attach(self._target)
        except Exception as e:
            raise AttachError(
                f"attach to {self._target} failed: {e}",
                probable_cause=self._preflight.probable_cause(),
                cause=e,
            ) from e
        self._session = session

        self._log.info("Loading agent script...")
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", self._on_message)
        script.load()
        self._api = script.exports_sync

        # Validate API
        api_check = self._api.validate_api()
        self._log.debug(
            "API check: ptr=%s readByteArray=%s pageSize=%s",
            api_check.get("ptrType"),
            api_check.get("readByteArrayType"),
            api_check.get("pageSize"),
        )

        # Resolve PID if attached by name
        pid = self._target if isinstance(self._target, int) else self._api.get_pid()

        # Detect platform
        self._log.info("Querying platform info...")
        frida_arch = self._api.get_arch()
        frida_platform = self._api.get_platform()
        self._modules_cache = self._api.enumerate_modules()
        modules_dicts = [{"name": m["name"], "path": m["path"]} for m in self._modules_cache]

        os_type, arch_type = detect_platform(
            frida_arch, frida_platform, modules_dicts,
        )

        page_size = self._api.get_page_size()
        self._log.debug(
            "platform=%s arch=%s pid=%d page_size=%d",
            frida_platform, frida_arch, pid, page_size,
        )

        self._platform_info = PlatformInfo(
            arch=arch_type,
            os=os_type,
            pid=pid,
            page_size=page_size,
        )

    def get_platform_info(self) -> PlatformInfo:
        """Return cached platform info from connect()."""
        if self._platform_info is None:
            raise RuntimeError("FridaBridge.connect() must be called first")
        return self._platform_info

    def create_remote_collector(
        self, logger: logging.Logger | None = None,
    ) -> InvestigationCollector | None:
        """Load the investigation agent on a remote target and return it.

        Implements :class:`~memslicer.acquirer.bridge.RemoteCollectorCapable`.
        The investigation script lives in the attached session, so its
        lifetime is the session's: :meth:`disconnect` detaches it along with
        the bridge script.

        Args:
            logger: Logger for the collector; defaults to the bridge's own.

        Returns:
            A connected ``FridaRemoteCollector``, or ``None`` when the target
            is local, :meth:`connect` has not run, or the agent failed to load
            (logged as a warning so the capture can fall back to an empty
            collector instead of aborting).
        """
        if not self.is_remote or self._session is None:
            return None
        from memslicer.acquirer.collectors.frida_remote import (
            FridaRemoteCollector,
        )

        collector = FridaRemoteCollector(self._session, logger=logger or self._log)
        try:
            collector.connect()
        except Exception as exc:  # noqa: BLE001 - frida raises its own hierarchy
            self._log.warning(
                "Investigation script could not be loaded on the target: %s", exc,
            )
            return None
        self._log.info("Investigation collector attached to remote target")
        return collector

    def _fetch_target_map_spans(self) -> list[tuple[int, int, str]]:
        """Return sorted ``(start, end, name)`` spans from the target's maps.

        Frida only reports a path for file-backed ranges, so pseudo-mappings
        such as ``[vvar]``, ``[heap]`` and ``[stack]`` are invisible to
        :meth:`enumerate_ranges`. The agent runs inside the target, so reading
        ``/proc/self/maps`` there recovers those names for local *and* remote
        devices without needing any host privilege.

        Returns:
            Named spans sorted by start address, or ``[]`` when unavailable.
        """
        fetch = getattr(self._api, "read_proc_maps", None)
        if fetch is None:
            return []
        try:
            text = fetch()
        except Exception as e:
            self._log.debug("readProcMaps RPC failed: %s", e)
            return []
        if not isinstance(text, str) or not text:
            return []
        return sorted(
            (r.base, r.base + r.size, r.file_path)
            for r in parse_maps_text(text) if r.file_path
        )

    def _lookup_map_name(self, base: int) -> str:
        """Return the maps name of the span containing *base*, or ``""``."""
        spans = self._map_spans
        if not spans:
            return ""
        idx = bisect.bisect_right(spans, base, key=lambda span: span[0]) - 1
        if idx < 0:
            return ""
        start, end, name = spans[idx]
        return name if start <= base < end else ""

    def enumerate_ranges(self) -> list[MemoryRange]:
        """Enumerate all memory ranges via Frida RPC."""
        if self._map_spans is None:
            self._map_spans = self._fetch_target_map_spans()

        raw = self._api.enumerate_ranges("---")
        ranges: list[MemoryRange] = []
        named = 0
        for r in raw:
            file_info = r.get("file")
            file_path = file_info.get("path", "") if file_info else ""
            base = _parse_frida_addr(r["base"])
            if not file_path:
                file_path = self._lookup_map_name(base)
                if file_path:
                    named += 1
            ranges.append(MemoryRange(
                base=base,
                size=r["size"],
                protection=r["protection"],
                file_path=file_path,
            ))
        if named:
            self._log.debug(
                "maps enrichment: named %d/%d ranges", named, len(ranges),
            )
        return ranges

    def enumerate_modules(self) -> list[ModuleInfo]:
        """Return loaded modules (cached from connect() if available)."""
        raw = self._modules_cache if self._modules_cache is not None else self._api.enumerate_modules()
        return [
            ModuleInfo(
                name=m["name"],
                path=m["path"],
                base=_parse_frida_addr(m["base"]),
                size=m["size"],
            )
            for m in raw
        ]

    def read_memory_ex(self, address: int, size: int) -> ReadResult:
        """Read memory via Frida RPC, reporting the fault address on failure.

        The agent returns either an ArrayBuffer (marshalled as ``bytes``) or an
        error descriptor (marshalled as ``dict``), so the two cases are
        unambiguous without out-of-band messages.

        Args:
            address: Address to read from.
            size: Number of bytes to read.

        Returns:
            A :class:`ReadResult` carrying the data or the failure detail.
        """
        try:
            data = self._api.read_memory(hex(address), size)
        except Exception as e:
            self._log.debug(
                "Read exception at 0x%x size=%d: %s", address, size, e,
            )
            return ReadResult(data=None, error=str(e))

        if isinstance(data, dict) and data.get("__error"):
            message = str(data.get("message", "unknown"))
            self._log.debug(
                "Read failed at 0x%x size=%d: %s", address, size, message,
            )
            return ReadResult(
                data=None,
                # Frida reports a real CPU fault address, so it is trusted even
                # when it equals the address asked for: that means the first
                # page of the span is the dead one.
                fault_addr=parse_fault_addr(message),
                error=message,
            )
        if data is None:
            return ReadResult(data=None)
        return ReadResult(data=_ensure_bytes(data))

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory via Frida RPC. Returns None on failure."""
        return self.read_memory_ex(address, size).data

    def residency_method(self) -> str:
        """How the agent determines page residency; cached per connection.

        Implements :class:`~memslicer.acquirer.bridge.ResidencyCapable`.
        Any failure -- missing export, RPC error, an unexpected answer --
        degrades to ``"none"``, which makes :meth:`query_residency` answer
        ``None`` and the engine read every page.
        """
        if self._residency_method is None:
            self._residency_method = self._probe_residency_method()
            self._log.debug(
                "residency method %s (%s)",
                self._residency_method, self.residency_detail() or "no detail",
            )
        return self._residency_method

    def residency_detail(self) -> str:
        """One line from the agent explaining :meth:`residency_method`.

        Purely informational (e.g. ``'mincore (swap table: 412 VMAs, 3 with
        swap)'`` or ``'none: pagemap: Permission denied; ...'``); any failure
        -- missing export, RPC error, a non-string answer -- yields ``""``.
        """
        probe = getattr(self._api, "residency_detail", None)
        if probe is None:
            return ""
        try:
            detail = probe()
        except Exception as e:
            self._log.debug("residencyDetail RPC failed: %s", e)
            return ""
        if not isinstance(detail, str):
            self._log.debug("residencyDetail answered a %s", type(detail).__name__)
            return ""
        return detail

    def _probe_residency_method(self) -> str:
        """Ask the agent once which residency method it can use."""
        probe = getattr(self._api, "residency_method", None)
        if probe is None:
            return "none"
        try:
            method = probe()
        except Exception as e:
            self._log.debug("residencyMethod RPC failed: %s", e)
            return "none"
        if not isinstance(method, str) or method not in _RESIDENCY_METHODS:
            self._log.debug("residencyMethod answered %r; using none", method)
            return "none"
        return method

    def query_residency(self, address: int, size: int) -> bytes | None:
        """Residency mask for ``[address, address + size)`` from the agent.

        Implements :class:`~memslicer.acquirer.bridge.ResidencyCapable`. The
        mask is only trusted when it is exactly one byte per page of the span,
        as the bridge's own page size counts them; anything else is ``None``.
        """
        if self.residency_method() == "none" or self._platform_info is None:
            return None
        query = getattr(self._api, "query_residency", None)
        if query is None:
            return None
        try:
            raw = query(hex(address), size)
        except Exception as e:
            self._log.debug(
                "queryResidency RPC failed at 0x%x size=%d: %s", address, size, e,
            )
            return None
        return self._validate_mask(raw, address, size)

    def _validate_mask(self, raw: Any, address: int, size: int) -> bytes | None:
        """Turn an agent answer into a mask, ``None`` unless it fits the span."""
        # Only a real buffer may become a mask: bytes(n) of an int-like answer
        # would be n zero bytes, an "all untouched" mask that skips every page.
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            if raw is not None:
                self._log.debug(
                    "queryResidency answered a %s, not a buffer", type(raw).__name__,
                )
            return None
        mask = _ensure_bytes(raw)
        expected = page_count(address, size, self._platform_info.page_size)
        if len(mask) != expected:
            self._log.debug(
                "queryResidency at 0x%x returned %d pages, expected %d",
                address, len(mask), expected,
            )
            return None
        return mask

    def enumerate_stack_pointers(self) -> list[int]:
        """Current SP of every thread the agent can see; ``[]`` on any failure.

        Implements :class:`~memslicer.acquirer.bridge.ThreadStackCapable`.
        Entries the agent reports in an unparseable form are left out.
        """
        fetch = getattr(self._api, "enumerate_stack_pointers", None)
        if fetch is None:
            return []
        try:
            raw = fetch()
        except Exception as e:
            self._log.debug("enumerateStackPointers RPC failed: %s", e)
            return []
        if not isinstance(raw, list):
            return []
        parsed = (_parse_stack_pointer(value) for value in raw)
        return [sp for sp in parsed if sp is not None]

    def enumerate_threads(self) -> list[ThreadInfo]:
        """Every thread with its sampled register file; ``[]`` on any failure.

        Implements :class:`~memslicer.acquirer.bridge.ThreadRegistersCapable`.
        Threads the agent reports without both a program counter and a stack
        pointer are left out (spec Section 5.7 requires both).
        """
        fetch = getattr(self._api, "enumerate_threads", None)
        if fetch is None:
            return []
        try:
            raw = fetch()
        except Exception as e:
            self._log.debug("enumerateThreads RPC failed: %s", e)
            return []
        if not isinstance(raw, list):
            return []
        arch = self._platform_info.arch if self._platform_info else None
        width = register_width_bytes(arch)
        threads = (
            self._thread_info(item, arch, width)
            for item in raw if isinstance(item, dict)
        )
        return [info for info in threads if info is not None]

    def _thread_info(
        self, raw: dict[str, Any], arch: ArchType | None, width: int,
    ) -> ThreadInfo | None:
        """One agent thread entry as a :class:`ThreadInfo`; ``None`` to skip."""
        context = raw.get("context")
        if not isinstance(context, dict):
            return None
        tid = raw.get("id")
        name = raw.get("name")
        registers, partial = _parse_registers(context, arch, width)
        info = ThreadInfo(
            tid=tid if isinstance(tid, int) and not isinstance(tid, bool) else 0,
            name=name if isinstance(name, str) else "",
            state=_frida_thread_state(raw.get("state")),
            registers=registers,
            # Frida samples a running thread, so the register set is not a
            # consistent snapshot: never claim it was read suspended.
            suspended=False,
            partial=partial,
        )
        if not info.has_pc_and_sp:
            self._log.debug("thread %d has no pc/sp in its context; skipped", info.tid)
            return None
        return info

    def _close_residency(self) -> None:
        """Release the agent's pagemap handle; best-effort."""
        close = getattr(self._api, "close_residency", None)
        if close is None:
            return
        try:
            close()
        except Exception as e:
            self._log.debug("closeResidency RPC failed: %s", e)

    def disconnect(self) -> None:
        """Detach the Frida session."""
        self._map_spans = None
        self._residency_method = None
        self._close_residency()
        session = self._session
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
            self._session = None
