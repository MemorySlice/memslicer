/* darwin_sysctl.js - Darwin sysctlbyname wrappers.
 * sysctlbyname(name, oldp, oldlenp, newp, newlen) -> int
 * Two-call pattern: (name, NULL, &len, NULL, 0) to size, then allocate.
 *
 * ensureSysctl() resolves the symbol through the common.js shim and is called
 * INSIDE each helper's try, so a missing symbol degrades that one value to ''
 * / 0 instead of aborting the whole darwin branch of getSystemInfo.
 */
var _sysctlbyname = null;
var _sysctl = null;

function ensureSysctl() {
    if (_sysctlbyname !== null) return;
    _sysctlbyname = new NativeFunction(
        getGlobalExport('sysctlbyname'),
        'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']);
}

/* sysctl(name, namelen, oldp, oldlenp, newp, newlen) -> int (MIB form). */
function ensureSysctlMib() {
    if (_sysctl !== null) return;
    _sysctl = new NativeFunction(
        getGlobalExport('sysctl'),
        'int', ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'size_t']);
}

function sysctlStr(name) {
    try {
        ensureSysctl();
        var namePtr = Memory.allocUtf8String(name);
        var lenPtr = Memory.alloc(8);
        lenPtr.writeU64(0);
        var ret = _sysctlbyname(namePtr, ptr(0), lenPtr, ptr(0), 0);
        if (ret !== 0) return '';
        var len = lenPtr.readU64().toNumber();
        if (len === 0) return '';
        var buf = Memory.alloc(len);
        ret = _sysctlbyname(namePtr, buf, lenPtr, ptr(0), 0);
        if (ret !== 0) return '';
        return buf.readUtf8String(len - 1); /* strip NUL */
    } catch(e) { return ''; }
}

function sysctlU64(name) {
    try {
        ensureSysctl();
        var namePtr = Memory.allocUtf8String(name);
        var lenPtr = Memory.alloc(8);
        lenPtr.writeU64(8);
        var buf = Memory.alloc(8);
        var ret = _sysctlbyname(namePtr, buf, lenPtr, ptr(0), 0);
        if (ret !== 0) return 0;
        return buf.readU64().toNumber();
    } catch(e) { return 0; }
}

function sysctlInt(name) {
    try {
        ensureSysctl();
        var namePtr = Memory.allocUtf8String(name);
        var lenPtr = Memory.alloc(8);
        lenPtr.writeU64(4);
        var buf = Memory.alloc(4);
        var ret = _sysctlbyname(namePtr, buf, lenPtr, ptr(0), 0);
        if (ret !== 0) return 0;
        return buf.readS32();
    } catch(e) { return 0; }
}

/* KERN_PROCARGS2: {exePath, args[]} for pid, or null. Works without the ObjC
 * bridge (which Frida 17 agents no longer bundle). Layout: int32 argc, exec
 * path NUL, NUL padding, argv[0..argc-1] NUL-separated, then the environment. */
function sysctlProcArgs(pid) {
    try {
        ensureSysctlMib();
        var argmax = sysctlInt('kern.argmax') || 262144;
        var mib = Memory.alloc(12);
        mib.writeS32(1);                 /* CTL_KERN */
        mib.add(4).writeS32(49);         /* KERN_PROCARGS2 */
        mib.add(8).writeS32(pid);
        var lenPtr = Memory.alloc(8);
        lenPtr.writeU64(argmax);
        var buf = Memory.alloc(argmax);
        var ret = _sysctl(mib, 3, buf, lenPtr, ptr(0), 0);
        if (ret !== 0) return null;
        var size = lenPtr.readU64().toNumber();
        if (size < 4) return null;
        var argc = buf.readS32();
        var bytes = new Uint8Array(buf.add(4).readByteArray(size - 4));
        var pos = 0;
        function nextString() {
            var start = pos;
            while (pos < bytes.length && bytes[pos] !== 0) pos++;
            var s = _utf8FromBytes(bytes, start, pos);
            while (pos < bytes.length && bytes[pos] === 0) pos++;  /* skip NUL padding */
            return s;
        }
        var exePath = nextString();
        var args = [];
        for (var i = 0; i < argc && pos < bytes.length; i++) args.push(nextString());
        return {exePath: exePath, args: args};
    } catch(e) { return null; }
}

function _utf8FromBytes(bytes, start, end) {
    var s = '';
    for (var i = start; i < end; i++) s += '%' + ('0' + bytes[i].toString(16)).slice(-2);
    try { return decodeURIComponent(s); } catch(e) {
        var raw = '';
        for (var j = start; j < end; j++) raw += String.fromCharCode(bytes[j]);
        return raw;
    }
}
