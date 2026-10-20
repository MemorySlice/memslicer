/* common.js - shared helpers, constants, and native function loaders.
 *
 * Runtime API shims
 * -----------------
 * This script runs inside the agent injected by the DEVICE's frida-server, so
 * the GumJS API surface is whatever that server ships (16.x or 17.x). Every
 * version-dependent API is therefore selected at runtime with typeof checks:
 *
 *   findGlobalExport / getGlobalExport   Module.findGlobalExportByName (17)
 *                                        -> Module.findExportByName(null, ..) (16)
 *   findModuleExport / getModuleExport   module instance findExportByName (16 + 17)
 *   findModuleBase                       Process.findModuleByName(..).base (16 + 17)
 *   javaAvailable / objcAvailable        guard the Java / ObjC globals, which are
 *                                        bundled in 16 but undefined in 17
 *   readFileText                         File.readAllText (static) -> File#readText
 *                                        loop -> libc open/read/close
 *   agentVersion                         Frida.version, reported in every envelope
 *
 * All later files must go through these shims and never touch the raw APIs.
 */

function agentVersion() {
    try {
        return (typeof Frida !== 'undefined' && Frida.version) ? String(Frida.version) : '';
    } catch(e) { return ''; }
}

/* RPC envelope shared by every export: {data, warnings} plus the agent version. */
function envelope(data, warnings) {
    return {data: data, warnings: warnings, agent: agentVersion()};
}

/* ---- Export / module lookup shims ---- */
function findGlobalExport(sym) {
    if (typeof Module.findGlobalExportByName === 'function') {
        return Module.findGlobalExportByName(sym);
    }
    return Module.findExportByName(null, sym);
}

function getGlobalExport(sym) {
    var p = findGlobalExport(sym);
    if (p === null || p === undefined) throw new Error('export not found: ' + sym);
    return p;
}

/* Try to load a module; return the Module or null on failure. */
function maybeLoadModule(name) {
    try {
        return Process.getModuleByName(name);
    } catch(e) {
        try {
            Module.load(name);
            return Process.getModuleByName(name);
        } catch(e2) {
            return null;
        }
    }
}

function findModuleExport(lib, sym) {
    var m = maybeLoadModule(lib);
    if (!m) return null;
    try {
        if (typeof m.findExportByName === 'function') return m.findExportByName(sym);
        return m.getExportByName(sym);
    } catch(e) { return null; }
}

function getModuleExport(lib, sym) {
    var p = findModuleExport(lib, sym);
    if (p === null || p === undefined) throw new Error('export not found: ' + lib + '!' + sym);
    return p;
}

function findModuleBase(name) {
    try {
        var m = Process.findModuleByName(name);
        return m ? m.base : null;
    } catch(e) { return null; }
}

/* ---- Bridge availability (Java / ObjC are undefined on Frida 17 agents) ---- */
function javaAvailable() {
    try {
        return typeof Java !== 'undefined' && Java !== null && Java.available === true;
    } catch(e) { return false; }
}

function objcAvailable() {
    try {
        return typeof ObjC !== 'undefined' && ObjC !== null && ObjC.available === true;
    } catch(e) { return false; }
}

/* ---- Android detection (mirrors platform_detect.py heuristics) ---- */
var _isAndroidCache = null;

function _probeAndroid() {
    try { if (javaAvailable()) return true; } catch(e) {}
    try { if (Process.findModuleByName('libandroid_runtime.so') !== null) return true; } catch(e) {}
    try {
        var linkers = ['linker64', 'linker'];
        for (var i = 0; i < linkers.length; i++) {
            var m = Process.findModuleByName(linkers[i]);
            if (m && m.path && (m.path.indexOf('/system/bin/') === 0 ||
                                m.path.indexOf('/apex/com.android.runtime/') === 0)) {
                return true;
            }
        }
    } catch(e) {}
    try { if (findGlobalExport('__system_property_get') !== null) return true; } catch(e) {}
    return false;
}

function isAndroid() {
    if (_isAndroidCache !== null) return _isAndroidCache;
    var result = false;
    if (Process.platform === 'linux') {
        try { result = _probeAndroid(); } catch(e) { result = false; }
    }
    _isAndroidCache = result;
    return result;
}

/* ---- File reading ---- */
/* /proc files (cmdline, environ) contain NUL bytes, and every GumJS text API
 * (File.readAllText, File#readText, NativePointer#readUtf8String(n)) throws
 * "can't decode byte 0x00". So we always read BYTES and decode UTF-8 ourselves,
 * keeping U+0000 in the result (callers split on it). Invalid sequences
 * become U+FFFD. TextDecoder is not available in GumJS; use it only if present. */
function _decodeUtf8Manual(bytes) {
    var out = '';
    var i = 0, n = bytes.length;
    while (i < n) {
        var b = bytes[i];
        var cp, need;
        if (b < 0x80) { cp = b; need = 0; }
        else if (b >= 0xC2 && b <= 0xDF) { cp = b & 0x1F; need = 1; }
        else if (b >= 0xE0 && b <= 0xEF) { cp = b & 0x0F; need = 2; }
        else if (b >= 0xF0 && b <= 0xF4) { cp = b & 0x07; need = 3; }
        else { out += '\uFFFD'; i++; continue; }
        var valid = true;
        for (var k = 1; k <= need; k++) {
            var c = bytes[i + k];
            if (c === undefined || (c & 0xC0) !== 0x80) { valid = false; break; }
            cp = (cp << 6) | (c & 0x3F);
        }
        if (!valid ||
            (need === 2 && cp < 0x800) || (need === 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            out += '\uFFFD'; i++; continue;
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
        } else {
            out += String.fromCharCode(cp);
        }
        i += need + 1;
    }
    return out;
}

function decodeUtf8(arrayBuffer) {
    if (!arrayBuffer) return '';
    var bytes = (arrayBuffer instanceof Uint8Array) ? arrayBuffer : new Uint8Array(arrayBuffer);
    if (typeof TextDecoder === 'function') {
        try { return new TextDecoder('utf-8').decode(bytes); } catch(e) {}
    }
    return _decodeUtf8Manual(bytes);
}

function _concatBytes(chunks, total) {
    var out = new Uint8Array(total);
    var off = 0;
    for (var i = 0; i < chunks.length; i++) {
        out.set(chunks[i], off);
        off += chunks[i].length;
    }
    return out;
}

/* Strategy 1 (16.x+): static File.readAllBytes(path) -> ArrayBuffer. */
function _readFileBytesStatic(path) {
    if (typeof File === 'undefined' || typeof File.readAllBytes !== 'function') return null;
    var ab = File.readAllBytes(path);
    return ab ? new Uint8Array(ab) : new Uint8Array(0);
}

/* Strategy 2 (16.x+): File instance readBytes(n) loop until EOF or maxLen. */
function _readFileBytesChunked(path, maxLen) {
    if (typeof File === 'undefined' || typeof File.prototype.readBytes !== 'function') return null;
    var f = new File(path, 'rb');
    var chunks = [], total = 0;
    try {
        while (total < maxLen) {
            var ab = f.readBytes(65536);
            if (!ab || ab.byteLength === 0) break;
            var chunk = new Uint8Array(ab);
            chunks.push(chunk);
            total += chunk.length;
        }
    } finally {
        try { f.close(); } catch(e) {}
    }
    return _concatBytes(chunks, total);
}

var _libcOpen = null, _libcRead = null, _libcClose = null;
function _ensureLibcFileFuncs() {
    if (_libcOpen !== null) return;
    var o = new NativeFunction(getGlobalExport('open'), 'int', ['pointer', 'int']);
    var r = new NativeFunction(getGlobalExport('read'), 'ssize_t', ['int', 'pointer', 'size_t']);
    var c = new NativeFunction(getGlobalExport('close'), 'int', ['int']);
    _libcOpen = o; _libcRead = r; _libcClose = c;
}

/* Strategy 3 (any version): libc open/read/close into a Memory.alloc buffer. */
function _readFileBytesLibc(path, maxLen) {
    _ensureLibcFileFuncs();
    var fd = _libcOpen(Memory.allocUtf8String(path), 0 /* O_RDONLY */);
    if (fd < 0) return null;
    var chunks = [], total = 0;
    try {
        var chunkSize = 65536;
        var buf = Memory.alloc(chunkSize);
        while (total < maxLen) {
            var n = _libcRead(fd, buf, chunkSize);
            if (typeof n !== 'number') n = parseInt(n.toString(), 10);
            if (n <= 0) break;
            var chunk = new Uint8Array(buf.readByteArray(n));
            chunks.push(chunk);
            total += chunk.length;
        }
    } finally {
        _libcClose(fd);
    }
    return _concatBytes(chunks, total);
}

/* Strategy 4 (last resort, NUL-free files only): the GumJS text APIs. */
function _readFileTextApis(path, maxLen) {
    if (typeof File === 'undefined') return null;
    if (typeof File.readAllText === 'function') {
        var content = File.readAllText(path);
        return (typeof content === 'string') ? content : '';
    }
    if (typeof File.prototype.readText !== 'function') return null;
    var f = new File(path, 'r');
    var text = '';
    try {
        while (text.length < maxLen) {
            var chunk = f.readText(65536);
            if (!chunk) break;
            text += chunk;
        }
    } finally {
        try { f.close(); } catch(e) {}
    }
    return text;
}

function _truncate(content, maxLen) {
    if (typeof content !== 'string') return '';
    return content.length > maxLen ? content.substring(0, maxLen) : content;
}

/* Read a text file (e.g. /proc entries) as UTF-8, NULs preserved; '' on any
 * failure. Each strategy is skipped when its API is absent (returns null) and
 * the next one is tried when it throws or yields nothing. */
function readFileText(path, maxLen) {
    maxLen = maxLen || 8192;
    var strategies = [
        function() { return _readFileBytesStatic(path); },
        function() { return _readFileBytesChunked(path, maxLen); },
        function() { return _readFileBytesLibc(path, maxLen); },
        function() { return _readFileTextApis(path, maxLen); }
    ];
    for (var i = 0; i < strategies.length; i++) {
        try {
            var result = strategies[i]();
            if (result === null) continue;       /* strategy unavailable */
            var content = (typeof result === 'string') ? result : decodeUtf8(result);
            if (content) return _truncate(content, maxLen);
        } catch(e) {}
    }
    return '';
}

/* readFileText that records a warning ('<tag>:unreadable <path>') on ''. */
function readFileTextW(path, maxLen, warnings, tag) {
    var content = readFileText(path, maxLen);
    if (!content && warnings) warnings.push((tag || 'read_file') + ':unreadable ' + path);
    return content;
}

/* ---- Native helpers for connection & handle tables ---- */
var _opendir = null, _readdir = null, _closedir = null, _readlinkNF = null;
var _proc_pidinfo = null, _proc_pidfdinfo = null;

/* Pre-allocated reusable buffer for readlinkStr */
var _linkBuf = null;
var LINK_BUF_SIZE = 4096;

/* Darwin libproc constants */
var PROC_PIDLISTFDS = 1;
var PROC_PIDFDSOCKETINFO = 3;
var PROC_PIDFDVNODEPATHINFO = 2;
var PROC_FDINFO_SIZE = 8;
/* proc_fdtype values */
var PROX_FDTYPE_VNODE = 1;
var PROX_FDTYPE_SOCKET = 2;
var PROX_FDTYPE_PIPE = 6;
/* AF constants on Darwin */
var BSD_AF_INET = 2;
var BSD_AF_INET6 = 30;
/* MSL address family constants */
var MSL_AF_INET = 0x02;
var MSL_AF_INET6 = 0x0A;
/* socket_fdinfo offsets - for PROC_PIDFDSOCKETINFO result */
var PSI_SIZE = 376;
/* offsets within socket_fdinfo (psi) returned by proc_pidfdinfo */
var PSI_SO_KIND_OFF = 8;       /* int32: socket kind (AF) */
var PSI_SO_TYPE_OFF = 12;      /* int32: SOCK_STREAM=1, SOCK_DGRAM=2 */
var PSI_SO_PROTO_OFF = 16;     /* int32: IPPROTO_TCP=6, IPPROTO_UDP=17 */
var PSI_SO_LADDR_OFF = 20;     /* sockaddr_storage: local address */
var PSI_SO_RADDR_OFF = 148;    /* sockaddr_storage: remote address */
var PSI_SO_STATE_OFF = 284;    /* int32: TCP state (or 0) */

/* Resolve all four POSIX helpers first; only publish state when all succeed. */
function ensureNativeFuncs() {
    if (_opendir !== null) return;
    var opendir = new NativeFunction(getGlobalExport('opendir'), 'pointer', ['pointer']);
    var readdir = new NativeFunction(getGlobalExport('readdir'), 'pointer', ['pointer']);
    var closedir = new NativeFunction(getGlobalExport('closedir'), 'int', ['pointer']);
    var readlink = new NativeFunction(getGlobalExport('readlink'), 'int', ['pointer', 'pointer', 'int']);
    var linkBuf = Memory.alloc(LINK_BUF_SIZE);
    _opendir = opendir;
    _readdir = readdir;
    _closedir = closedir;
    _readlinkNF = readlink;
    _linkBuf = linkBuf;
}

/* libproc lives in the dyld shared cache; try the short name, the full path,
 * then the global namespace (libSystem re-exports it). */
function _findLibprocExport(sym) {
    var p = findModuleExport('libproc.dylib', sym);
    if (!p) p = findModuleExport('/usr/lib/libproc.dylib', sym);
    if (!p) p = findGlobalExport(sym);
    if (!p) throw new Error('export not found: libproc.dylib!' + sym);
    return p;
}

function ensureDarwinFuncs() {
    if (_proc_pidinfo !== null) return;
    var pidinfo = new NativeFunction(
        _findLibprocExport('proc_pidinfo'),
        'int', ['int', 'int', 'uint64', 'pointer', 'int']);
    var pidfdinfo = new NativeFunction(
        _findLibprocExport('proc_pidfdinfo'),
        'int', ['int', 'int', 'int', 'pointer', 'int']);
    _proc_pidinfo = pidinfo;
    _proc_pidfdinfo = pidfdinfo;
}

/* Windows UTF-16 string helper - wrap allocUtf16String for W-suffix APIs. */
function W(str) {
    return Memory.allocUtf16String(str);
}
