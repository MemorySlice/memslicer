/* common.js - shared helpers, constants, and native function loaders. */
function readFileText(path, maxLen) {
    maxLen = maxLen || 8192;
    try {
        var f = new File(path, 'r');
        var content = f.read(maxLen);
        f.close();
        return (content !== null) ? content : '';
    } catch(e) { return ''; }
}

/* ---- Native helpers for connection & handle tables ---- */
var _opendir = null, _readdir = null, _closedir = null, _readlinkNF = null;
var _proc_pidinfo = null, _proc_pidfdinfo = null;

/* Pre-allocated reusable buffer for readlinkStr */
var _linkBuf = null;

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

function ensureNativeFuncs() {
    if (_opendir !== null) return;
    _opendir = new NativeFunction(
        Module.getExportByName(null, 'opendir'), 'pointer', ['pointer']);
    _readdir = new NativeFunction(
        Module.getExportByName(null, 'readdir'), 'pointer', ['pointer']);
    _closedir = new NativeFunction(
        Module.getExportByName(null, 'closedir'), 'int', ['pointer']);
    _readlinkNF = new NativeFunction(
        Module.getExportByName(null, 'readlink'), 'int', ['pointer', 'pointer', 'int']);
    _linkBuf = Memory.alloc(256);
}

function ensureDarwinFuncs() {
    if (_proc_pidinfo !== null) return;
    var libproc = '/usr/lib/libproc.dylib';
    _proc_pidinfo = new NativeFunction(
        Module.getExportByName(libproc, 'proc_pidinfo'),
        'int', ['int', 'int', 'uint64', 'pointer', 'int']);
    _proc_pidfdinfo = new NativeFunction(
        Module.getExportByName(libproc, 'proc_pidfdinfo'),
        'int', ['int', 'int', 'int', 'pointer', 'int']);
}

/* Windows UTF-16 string helper - wrap allocUtf16String for W-suffix APIs. */
function W(str) {
    return Memory.allocUtf16String(str);
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
