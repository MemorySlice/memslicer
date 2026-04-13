/* windows.js - Windows enrichment.
 *
 * Registry via advapi32!RegGetValueW, kernel version via ntdll!RtlGetVersion,
 * hostname via kernel32!GetComputerNameExW, memory via
 * kernel32!GlobalMemoryStatusEx. All W-suffix APIs use UTF-16 with the W()
 * helper from common.js.
 *
 * iphlpapi.dll is not always loaded (console apps, services) — resolve
 * GetAdaptersAddresses via maybeLoadModule and skip MACs on failure.
 */
var _regGetValueW = null;
var _getComputerNameExW = null;
var _globalMemoryStatusEx = null;
var _rtlGetVersion = null;

function ensureWindowsFuncs() {
    if (_regGetValueW !== null) return;
    try {
        _regGetValueW = new NativeFunction(
            Module.getExportByName('advapi32.dll', 'RegGetValueW'),
            'uint32',
            ['pointer', 'pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'pointer']);
    } catch(e) { _regGetValueW = false; }

    try {
        _getComputerNameExW = new NativeFunction(
            Module.getExportByName('kernel32.dll', 'GetComputerNameExW'),
            'int', ['uint32', 'pointer', 'pointer']);
    } catch(e) { _getComputerNameExW = false; }

    try {
        _globalMemoryStatusEx = new NativeFunction(
            Module.getExportByName('kernel32.dll', 'GlobalMemoryStatusEx'),
            'int', ['pointer']);
    } catch(e) { _globalMemoryStatusEx = false; }

    try {
        _rtlGetVersion = new NativeFunction(
            Module.getExportByName('ntdll.dll', 'RtlGetVersion'),
            'uint32', ['pointer']);
    } catch(e) { _rtlGetVersion = false; }
}

/* Wrapper: RegGetValueW with auto-type-coerce. Returns string or null. */
var RRF_RT_REG_SZ    = 0x00000002;
var RRF_RT_REG_DWORD = 0x00000010;
var RRF_RT_ANY       = 0x0000FFFF;
/* HKLM predefined handle. NOTE: 64-bit pointer literal — Frida targets
 * are almost always 64-bit in 2026; on 32-bit targets you'd need
 * ptr('0x80000002'). */
var HKEY_LOCAL_MACHINE_PTR = ptr('0xFFFFFFFF80000002');

function winReg(hkey, subkey, valueName) {
    ensureWindowsFuncs();
    if (!_regGetValueW) return null;
    try {
        var sub = W(subkey);
        var val = W(valueName);
        var bufSize = Memory.alloc(4); bufSize.writeU32(256);
        var buf = Memory.alloc(256);
        var ret = _regGetValueW(hkey, sub, val, RRF_RT_ANY, ptr(0), buf, bufSize);
        if (ret !== 0) return null;
        var chars = Math.floor(bufSize.readU32() / 2) - 1; /* trailing NUL */
        if (chars <= 0) return null;
        return buf.readUtf16String(chars);
    } catch(e) { return null; }
}

/* RtlGetVersion returns RTL_OSVERSIONINFOEXW. First DWORD is struct size. */
function winGetVersion() {
    ensureWindowsFuncs();
    if (!_rtlGetVersion) return null;
    try {
        var size = 284; /* sizeof(RTL_OSVERSIONINFOEXW) */
        var buf = Memory.alloc(size);
        buf.writeU32(size);
        var ret = _rtlGetVersion(buf);
        if (ret !== 0) return null;
        return {
            major: buf.add(4).readU32(),
            minor: buf.add(8).readU32(),
            build: buf.add(12).readU32(),
        };
    } catch(e) { return null; }
}

function winGetHostname() {
    ensureWindowsFuncs();
    if (!_getComputerNameExW) return '';
    try {
        var ComputerNameDnsFullyQualified = 3;
        var sizePtr = Memory.alloc(4);
        sizePtr.writeU32(0);
        _getComputerNameExW(ComputerNameDnsFullyQualified, ptr(0), sizePtr);
        var chars = sizePtr.readU32();
        if (chars === 0) return '';
        var buf = Memory.alloc(chars * 2);
        var ok = _getComputerNameExW(ComputerNameDnsFullyQualified, buf, sizePtr);
        if (!ok) return '';
        return buf.readUtf16String(sizePtr.readU32());
    } catch(e) { return ''; }
}

function winGetMemory() {
    ensureWindowsFuncs();
    if (!_globalMemoryStatusEx) return 0;
    try {
        var buf = Memory.alloc(64);
        buf.writeU32(64); /* dwLength */
        var ok = _globalMemoryStatusEx(buf);
        if (!ok) return 0;
        /* ullTotalPhys at offset 8 (after dwLength u32 + dwMemoryLoad u32) */
        return buf.add(8).readU64().toNumber();
    } catch(e) { return 0; }
}

function windowsGetSystemInfo(result, warnings) {
    var cvSub = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
    var product     = winReg(HKEY_LOCAL_MACHINE_PTR, cvSub, 'ProductName') || '';
    var display     = winReg(HKEY_LOCAL_MACHINE_PTR, cvSub, 'DisplayVersion') || '';
    var buildNumber = winReg(HKEY_LOCAL_MACHINE_PTR, cvSub, 'CurrentBuildNumber') || '';
    var edition     = winReg(HKEY_LOCAL_MACHINE_PTR, cvSub, 'EditionID') || '';

    /* ProductName trap: build >= 22000 means Windows 11 even if ProductName says 10. */
    var buildInt = parseInt(buildNumber, 10) || 0;
    if (buildInt >= 22000 && product.indexOf('Windows 10') === 0) {
        product = 'Windows 11' + product.substring(10);
    }
    var parts = [product];
    if (edition) parts.push(edition);
    if (display) parts.push(display);
    if (buildNumber) parts.push('(Build ' + buildNumber + ')');
    result.distro = parts.filter(function(p) { return p; }).join(' ');
    result.osDetail = result.distro || 'Windows (via Frida)';

    var ver = winGetVersion();
    if (ver) result.kernel = ver.major + '.' + ver.minor + '.' + ver.build;

    result.hostname = winGetHostname();
    result.ramBytes = winGetMemory();

    /* machine_id via HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid */
    result.machineId = winReg(HKEY_LOCAL_MACHINE_PTR, 'SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid') || '';

    /* cpu brand via HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 */
    result.cpuBrand = winReg(HKEY_LOCAL_MACHINE_PTR, 'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorNameString') || '';

    /* MACs via iphlpapi GetAdaptersAddresses (opt-in, expensive). Skip on
     * failure because iphlpapi.dll may not be loaded in the target. */
    var iphlpapi = maybeLoadModule('iphlpapi.dll');
    if (!iphlpapi) {
        warnings.push('windows_iphlpapi_unavailable');
    }
    /* NOTE: full GetAdaptersAddresses parsing is out of scope for this
     * refactor — leave MAC collection as a follow-up. */
}
