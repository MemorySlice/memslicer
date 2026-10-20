/* android.js - Android enrichment via SystemProperties JNI (SELinux-safe).
 * Runtime.exec('getprop') is blocked for untrusted_app, so we call
 * android.os.SystemProperties.get() through the Java bridge when the agent
 * bundles one (Frida 16, javaAvailable()). Otherwise (Frida 17 agents ship
 * no Java bridge, or a native process) we fall back to
 * libc!__system_property_get resolved through the common.js shims.
 */
var _systemPropertyGet = null;
function ensureSystemPropertyGet() {
    if (_systemPropertyGet !== null) return;
    try {
        var sym = findGlobalExport('__system_property_get');
        if (!sym) sym = getModuleExport('libc.so', '__system_property_get');
        _systemPropertyGet = new NativeFunction(sym, 'int', ['pointer', 'pointer']);
    } catch(e) {
        _systemPropertyGet = false;  /* sentinel: unavailable */
    }
}

function androidGetPropJava(key) {
    var value = '';
    Java.performNow(function() {
        var SP = Java.use('android.os.SystemProperties');
        value = SP.get(key, '');
    });
    return value ? String(value) : '';
}

function androidGetPropNative(key) {
    ensureSystemPropertyGet();
    if (!_systemPropertyGet) return '';
    try {
        /* PROP_VALUE_MAX = 92 */
        var keyBuf = Memory.allocUtf8String(key);
        var valBuf = Memory.alloc(128);
        var len = _systemPropertyGet(keyBuf, valBuf);
        if (len > 0) return valBuf.readUtf8String(len);
    } catch(e) {}
    return '';
}

function androidGetProp(key) {
    /* Preferred: Java SystemProperties (only when a Java bridge is bundled). */
    try {
        if (javaAvailable()) {
            var value = androidGetPropJava(key);
            if (value) return value;
        }
    } catch(e) {}
    /* Fallback: libc __system_property_get. */
    return androidGetPropNative(key);
}

function androidGetSystemInfo(result, warnings) {
    try {
        var release = androidGetProp('ro.build.version.release');
        var sdk     = androidGetProp('ro.build.version.sdk');
        var model   = androidGetProp('ro.product.model');
        var mfr     = androidGetProp('ro.product.manufacturer');
        var fp      = androidGetProp('ro.build.fingerprint');
        var patch   = androidGetProp('ro.build.version.security_patch');
        var vbState = androidGetProp('ro.boot.verifiedbootstate');
        var locked  = androidGetProp('ro.boot.flash.locked');
        var verity  = androidGetProp('ro.boot.veritymode');
        var btype   = androidGetProp('ro.build.type');
        var ctype   = androidGetProp('ro.crypto.type');
        var qemu    = androidGetProp('ro.kernel.qemu');

        if (!release && !fp) warnings.push('android_getprop:no properties readable');

        /* Populate fields the Python side projects into TargetSystemInfo. */
        result.fingerprint      = fp;
        result.patchLevel       = patch;
        result.verifiedBoot     = vbState;
        result.bootloaderLocked = locked;
        result.dmVerity         = verity;
        result.buildType        = btype;
        result.cryptoType       = ctype;
        result.env              = (qemu === '1') ? 'emulator' : 'physical';
        result.hwVendor         = mfr;
        result.hwModel          = model;
        result.distro           = release ? ('Android ' + release + (sdk ? ' (API ' + sdk + ')' : '')) : '';

        /* Compose a human-readable os_detail too. */
        var parts = [];
        if (release) parts.push('Android ' + release);
        if (sdk)     parts.push('(API ' + sdk + ')');
        if (mfr)     parts.push(mfr);
        if (model)   parts.push(model);
        result.osDetail = parts.join(' ');
    } catch(e) {
        warnings.push('android_getprop:' + e.message);
    }
}
