/* darwin_sysctl.js - Darwin sysctlbyname wrappers.
 * sysctlbyname(name, oldp, oldlenp, newp, newlen) -> int
 * Two-call pattern: (name, NULL, &len, NULL, 0) to size, then allocate.
 */
var _sysctlbyname = null;
function ensureSysctl() {
    if (_sysctlbyname !== null) return;
    _sysctlbyname = new NativeFunction(
        Module.getExportByName(null, 'sysctlbyname'),
        'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']);
}

function sysctlStr(name) {
    ensureSysctl();
    try {
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
    ensureSysctl();
    try {
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
    ensureSysctl();
    try {
        var namePtr = Memory.allocUtf8String(name);
        var lenPtr = Memory.alloc(8);
        lenPtr.writeU64(4);
        var buf = Memory.alloc(4);
        var ret = _sysctlbyname(namePtr, buf, lenPtr, ptr(0), 0);
        if (ret !== 0) return 0;
        return buf.readS32();
    } catch(e) { return 0; }
}
