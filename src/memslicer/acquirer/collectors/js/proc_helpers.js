/* proc_helpers.js - /proc parsing helpers (readlink, dirent, inode->pid, /proc/net). */
function readlinkStr(path) {
    var pathBuf = Memory.allocUtf8String(path);
    var len = _readlinkNF(pathBuf, _linkBuf, LINK_BUF_SIZE - 1);
    if (len > 0) {
        return _linkBuf.readUtf8String(len);
    }
    return null;
}

/* Offset of d_name inside struct dirent. 64-bit Linux and bionic (which uses
 * the 64-bit dirent layout even on 32-bit Android) place it at 19; only
 * non-Android 32-bit glibc uses the compact layout with d_name at 11. */
function dNameOffset() {
    if (Process.pointerSize === 8) return 19;
    return isAndroid() ? 19 : 11;
}

function buildInodePidMap() {
    ensureNativeFuncs();
    var map = {};
    var procDir = _opendir(Memory.allocUtf8String('/proc'));
    if (procDir.isNull()) return map;

    var offset = dNameOffset();
    var ent;
    while (!(ent = _readdir(procDir)).isNull()) {
        var name = ent.add(offset).readUtf8String();
        if (!/^\d+$/.test(name)) continue;
        var pid = parseInt(name);

        var fdDir = _opendir(Memory.allocUtf8String('/proc/' + pid + '/fd'));
        if (fdDir.isNull()) continue;

        var fdEnt;
        while (!(fdEnt = _readdir(fdDir)).isNull()) {
            var fdName = fdEnt.add(offset).readUtf8String();
            if (!/^\d+$/.test(fdName)) continue;
            try {
                var target = readlinkStr('/proc/' + pid + '/fd/' + fdName);
                if (target && target.indexOf('socket:[') === 0 && target.charAt(target.length - 1) === ']') {
                    var inode = parseInt(target.substring(8, target.length - 1));
                    if (!isNaN(inode)) map[inode] = pid;
                }
            } catch(e) {}
        }
        _closedir(fdDir);
    }
    _closedir(procDir);
    return map;
}

function parseNetFile(content, family, protocol, inodePidMap) {
    var entries = [];
    if (!content) return entries;
    var lines = content.split('\n');
    for (var i = 1; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        var fields = line.split(/\s+/);
        if (fields.length < 10) continue;
        try {
            var localParts = fields[1].split(':');
            var remoteParts = fields[2].split(':');
            var state = parseInt(fields[3], 16);
            var inode = parseInt(fields[9]);
            var pid = inodePidMap[inode] || 0;
            entries.push({
                pid: pid,
                family: family,
                protocol: protocol,
                state: state,
                localAddr: localParts[0],
                localPort: parseInt(localParts[1], 16),
                remoteAddr: remoteParts[0],
                remotePort: parseInt(remoteParts[1], 16)
            });
        } catch(e) {}
    }
    return entries;
}

/* ---- Linux process start time (startTimeNs) helpers ---- */
var _clkTck = null;
/* sysconf(_SC_CLK_TCK). The constant differs per libc: 2 on glibc/musl, 6 on
 * bionic (where 2 is _SC_BC_DIM_MAX = 2048, verified on an emulator), 3 on
 * Darwin — so this is Linux-only. Falls back to the kernel default USER_HZ=100. */
function clockTicksPerSecond() {
    if (_clkTck !== null) return _clkTck;
    var ticks = 100;
    if (Process.platform === 'linux') {
        try {
            var SC_CLK_TCK = isAndroid() ? 6 : 2;
            var sysconf = new NativeFunction(getGlobalExport('sysconf'), 'long', ['int']);
            var v = sysconf(SC_CLK_TCK);
            if (typeof v !== 'number') v = parseInt(v.toString(), 10);
            if (v > 0 && v <= 100000) ticks = v;
        } catch(e) {}
    }
    _clkTck = ticks;
    return ticks;
}

/* btime from /proc/stat in seconds since the epoch, or 0. */
function readBootTimeSeconds(warnings) {
    var statContent = readFileTextW('/proc/stat', 65536, warnings, 'linux_proc_stat');
    var btimeMatch = statContent.match(/btime\s+(\d+)/);
    return btimeMatch ? parseInt(btimeMatch[1]) : 0;
}

/* seconds*1e9 + extraNs. Epoch nanoseconds (~1.7e18) exceed 2^53, so a Number
 * rounds to ~256 ns; use BigInt when the engine has it and return a decimal
 * STRING (JSON cannot carry BigInt). Older engines get the Number. The Python
 * side (_to_int) accepts both shapes. */
function nanosecondsFromSeconds(seconds, extraNs) {
    extraNs = extraNs || 0;
    if (typeof BigInt === 'function') {
        try {
            var ns = BigInt(seconds) * BigInt(1000000000) + BigInt(Math.round(extraNs));
            return ns.toString();
        } catch(e) {}
    }
    return seconds * 1e9 + extraNs;
}

/* Absolute process start time in ns: btime*1e9 + starttime_ticks*1e9/CLK_TCK;
 * 0 when either part is missing. */
function linuxStartTimeNs(startTicks, bootTimeSeconds) {
    if (!startTicks || !bootTimeSeconds) return 0;
    var sinceBootNs = Math.floor(startTicks * 1e9 / clockTicksPerSecond());
    return nanosecondsFromSeconds(bootTimeSeconds, sinceBootNs);
}
