/* rpc_exports.js - Frida rpc.exports dispatch surface for the investigation script.
 *
 * RPC contract (P1.4b): every export returns {data, warnings} where `data` is the
 * previously-returned value (dict or array) and `warnings` is a list of short
 * "<operation_tag>:<message>" strings emitted on recoverable failures. The Python
 * side unwraps the envelope (with a legacy flat-shape compatibility path) and
 * forwards warnings into TargetSystemInfo.collector_warnings. envelope() (common.js)
 * adds `agent` (Frida.version of the device-side runtime); extra keys are ignored
 * by the Python _unwrap.
 *
 * Every version-dependent API goes through the common.js shims (findGlobalExport,
 * javaAvailable, objcAvailable, isAndroid, readFileText, ...).
 */

/* ---- getProcessInfo helpers (Linux / Android) ---- */
function linuxFillProcStat(pid, result, warnings) {
    var statLine = readFileTextW('/proc/' + pid + '/stat', 8192, warnings, 'linux_proc_stat');
    if (!statLine) return;
    try {
        var commEnd = statLine.lastIndexOf(')');
        var fields = statLine.substring(commEnd + 2).trim().split(/\s+/);
        result.ppid = parseInt(fields[1]) || 0;
        result.sessionId = parseInt(fields[3]) || 0;
        var startTicks = parseInt(fields[19]) || 0;   /* field 22: starttime */
        /* /proc/stat unreadable is reported once, by getSystemInfo. */
        result.startTimeNs = linuxStartTimeNs(startTicks, readBootTimeSeconds(null));
    } catch(e) { warnings.push('linux_proc_stat:' + e.message); }
}

function linuxReadExePath(pid, warnings) {
    try {
        ensureNativeFuncs();
        return readlinkStr('/proc/' + pid + '/exe') || '';
    } catch(e) {
        warnings.push('linux_proc_exe:' + e.message);
        return '';
    }
}

function androidAppProcessPath() {
    return '/system/bin/app_process' + (Process.pointerSize === 8 ? '64' : '32');
}

/* "<package>[:<process>]" as zygote sets argv[0] for app processes. */
var ANDROID_PACKAGE_RE = /^[a-zA-Z_][\w]*(\.[a-zA-Z_][\w]*)+(:[\w.]+)?$/;

/* True only for real Android app (zygote-forked) processes: a Java bridge is
 * present, the exe is app_process, or argv[0] looks like a package name.
 * Native targets like 'sleep' or '/data/local/tmp/foo' stay unattributed. */
function isAndroidAppProcess(argv0, exePath) {
    if (!isAndroid() || !argv0) return false;
    if (javaAvailable()) return true;
    if (/\/app_process(64|32)$/.test(exePath || '')) return true;
    return ANDROID_PACKAGE_RE.test(argv0);
}

function linuxFillProcessInfo(pid, result, warnings) {
    linuxFillProcStat(pid, result, warnings);

    var cmdRaw = readFileTextW('/proc/' + pid + '/cmdline', 8192, warnings, 'linux_proc_cmdline');
    var argv0 = '';
    if (cmdRaw) {
        result.cmdLine = cmdRaw.replace(/\0/g, ' ').trim();
        argv0 = result.cmdLine ? result.cmdLine.split(' ')[0] : '';
    }

    var exeFromLink = linuxReadExePath(pid, warnings);
    result.exePath = exeFromLink || argv0;

    /* Android app: argv[0] is "<package>[:<process>]". Derive
     * processName/package and point exePath at the real ELF (app_process). */
    if (result.cmdLine && isAndroidAppProcess(argv0, exeFromLink)) {
        result.processName = argv0;
        result.package = argv0.split(':')[0];
        if (!exeFromLink) result.exePath = androidAppProcessPath();
    }
}

/* ---- getProcessInfo helpers (Darwin) ---- */
function darwinFillProcessInfo(pid, result, warnings) {
    try {
        if (objcAvailable()) {
            var pi = ObjC.classes.NSProcessInfo.processInfo();
            result.exePath = pi.processName().toString();
            var args = pi.arguments();
            var argList = [];
            for (var i = 0; i < args.count(); i++) {
                argList.push(args.objectAtIndex_(i).toString());
            }
            result.cmdLine = argList.join(' ');
        }
    } catch(e) { warnings.push('darwin_nsprocessinfo:' + e.message); }

    /* No ObjC bridge (Frida 17 agents) or it failed: KERN_PROCARGS2 via sysctl. */
    if (!result.cmdLine || !result.exePath) {
        try {
            var pa = sysctlProcArgs(pid);
            if (pa) {
                if (!result.exePath) result.exePath = pa.exePath;
                if (!result.cmdLine) result.cmdLine = pa.args.join(' ');
            } else {
                warnings.push('darwin_procargs:unavailable for pid ' + pid);
            }
        } catch(e) { warnings.push('darwin_procargs:' + e.message); }
    }
}

/* ---- getSystemInfo helpers ---- */
function linuxFillSystemInfo(result, warnings) {
    /* Shared Linux: /proc/sys/kernel/hostname, /proc/stat btime. */
    result.hostname = readFileTextW('/proc/sys/kernel/hostname', 8192, warnings, 'linux_hostname').trim();
    var btime = readBootTimeSeconds(warnings);
    if (btime) result.bootTime = nanosecondsFromSeconds(btime, 0);

    /* Android vs plain Linux decided by runtime probes, not by the Java bridge
     * alone (which Frida 17 agents do not bundle). */
    if (isAndroid()) {
        androidGetSystemInfo(result, warnings);
    } else {
        result.osDetail = readFileTextW('/proc/version', 8192, warnings, 'linux_proc_version').trim();
    }
}

function darwinFillSystemInfo(result, warnings) {
    /* Could be macOS or iOS. Probe sysctl for iOS markers. */
    var hwMachine = sysctlStr('hw.machine');
    if (hwMachine && (hwMachine.indexOf('iPhone') === 0 ||
                      hwMachine.indexOf('iPad') === 0 ||
                      hwMachine.indexOf('iPod') === 0)) {
        iosGetSystemInfo(result, warnings);
        return;
    }
    /* macOS via Frida - supplement with sysctl. */
    result.hostname = sysctlStr('kern.hostname');
    result.hwModel = sysctlStr('hw.model');
    result.cpuBrand = sysctlStr('machdep.cpu.brand_string');
    result.ramBytes = sysctlU64('hw.memsize');
    result.kernel = sysctlStr('kern.osrelease');
    var prodVer = sysctlStr('kern.osproductversion');
    result.osDetail = prodVer ? ('macOS ' + prodVer) : 'macOS (via Frida)';
    if (!result.kernel && !prodVer) warnings.push('darwin_sysctl:no values readable');
}

/* ---- Linux /proc walkers ---- */
function linuxProcessTable(targetPid, entries, warnings) {
    ensureNativeFuncs();
    var dir = _opendir(Memory.allocUtf8String('/proc'));
    if (dir.isNull()) { warnings.push('linux_proc_walk:cannot open /proc'); return; }
    var offset = dNameOffset();
    var ent;
    while (!(ent = _readdir(dir)).isNull()) {
        var name = ent.add(offset).readUtf8String();
        if (!/^\d+$/.test(name)) continue;
        var pid = parseInt(name);
        var sl = readFileText('/proc/' + pid + '/stat');
        if (!sl) continue;
        try {
            var ce = sl.lastIndexOf(')');
            var cs = sl.indexOf('(');
            var comm = sl.substring(cs + 1, ce);
            var fields = sl.substring(ce + 2).trim().split(/\s+/);
            entries.push({
                pid: pid,
                ppid: parseInt(fields[1]) || 0,
                uid: 0,
                isTarget: pid === targetPid,
                startTime: parseInt(fields[19]) || 0,
                rss: 0,
                exeName: comm,
                cmdLine: '',
                user: ''
            });
        } catch(e) {}
    }
    _closedir(dir);
}

function linuxConnectionTable(entries, warnings) {
    /* pid attribution needs /proc/<pid>/fd of every process; keep the table
     * even when that walk fails (e.g. SELinux-denied on unprivileged apps). */
    var inodePidMap = {};
    try {
        inodePidMap = buildInodePidMap();
    } catch(e) { warnings.push('linux_inode_map:' + e.message); }

    var files = [
        ['/proc/net/tcp',  0x02, 0x06],
        ['/proc/net/tcp6', 0x0A, 0x06],
        ['/proc/net/udp',  0x02, 0x11],
        ['/proc/net/udp6', 0x0A, 0x11]
    ];
    for (var i = 0; i < files.length; i++) {
        var content = readFileTextW(files[i][0], 131072, warnings, 'linux_net_read');
        if (content) {
            var parsed = parseNetFile(content, files[i][1], files[i][2], inodePidMap);
            for (var j = 0; j < parsed.length; j++) entries.push(parsed[j]);
        }
    }
}

function linuxHandleTable(pid, entries, warnings) {
    ensureNativeFuncs();
    var fdPath = '/proc/' + pid + '/fd';
    var fdDir = _opendir(Memory.allocUtf8String(fdPath));
    if (fdDir.isNull()) { warnings.push('linux_fd_walk:cannot open ' + fdPath); return; }
    var offset = dNameOffset();
    var ent;
    while (!(ent = _readdir(fdDir)).isNull()) {
        var name = ent.add(offset).readUtf8String();
        if (!/^\d+$/.test(name)) continue;
        var fd = parseInt(name);
        var target = readlinkStr(fdPath + '/' + name);
        var handleType = 0;
        if (target) {
            if (target.indexOf('socket:') === 0) handleType = 3;
            else if (target.indexOf('pipe:') === 0) handleType = 4;
            else if (target.indexOf('/dev/') === 0) handleType = 5;
            else handleType = 1;
        }
        entries.push({pid: pid, fd: fd, handleType: handleType, path: target || ''});
    }
    _closedir(fdDir);
}

rpc.exports = {
    getProcessInfo: function(pid) {
        var warnings = [];
        var result = {ppid: 0, sessionId: 0, startTimeNs: 0, exePath: '', cmdLine: '',
                      processName: '', package: ''};
        try {
            if (Process.platform === 'linux') {
                linuxFillProcessInfo(pid, result, warnings);
            } else if (Process.platform === 'darwin') {
                darwinFillProcessInfo(pid, result, warnings);
            }
        } catch(e) { warnings.push('getProcessInfo:' + e.message); }
        return envelope(result, warnings);
    },

    getSystemInfo: function() {
        var warnings = [];
        var result = {bootTime: 0, hostname: '', domain: '', osDetail: '',
                      kernel: '', arch: '', distro: '', fingerprint: '',
                      patchLevel: '', verifiedBoot: '', bootloaderLocked: '',
                      dmVerity: '', buildType: '', cryptoType: '', env: '',
                      hwVendor: '', hwModel: '', cpuBrand: '', ramBytes: 0,
                      machineId: ''};
        try {
            if (Process.platform === 'linux') {
                linuxFillSystemInfo(result, warnings);
            } else if (Process.platform === 'darwin') {
                darwinFillSystemInfo(result, warnings);
            } else if (Process.platform === 'windows') {
                windowsGetSystemInfo(result, warnings);
            }
        } catch(e) { warnings.push('getSystemInfo:' + e.message); }
        return envelope(result, warnings);
    },

    getProcessTable: function(targetPid) {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    linuxProcessTable(targetPid, entries, warnings);
                } catch(e) { warnings.push('linux_proc_walk:' + e.message); }
            }
        } catch(e) { warnings.push('getProcessTable:' + e.message); }
        return envelope(entries, warnings);
    },

    getConnectionTable: function() {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    linuxConnectionTable(entries, warnings);
                } catch(e) { warnings.push('linux_net_parse:' + e.message); }
            } else if (Process.platform === 'darwin') {
                try {
                    var darwinResults = darwinGetConnections(Process.id);
                    for (var k = 0; k < darwinResults.length; k++) entries.push(darwinResults[k]);
                } catch(e) { warnings.push('darwin_proc_pidinfo:' + e.message); }
            }
        } catch(e) { warnings.push('getConnectionTable:' + e.message); }
        return envelope(entries, warnings);
    },

    getHandleTable: function(pid) {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    linuxHandleTable(pid, entries, warnings);
                } catch(e) { warnings.push('linux_fd_walk:' + e.message); }
            } else if (Process.platform === 'darwin') {
                try {
                    var darwinH = darwinGetHandles(pid);
                    for (var m = 0; m < darwinH.length; m++) entries.push(darwinH[m]);
                } catch(e) { warnings.push('darwin_proc_pidinfo:' + e.message); }
            }
        } catch(e) { warnings.push('getHandleTable:' + e.message); }
        return envelope(entries, warnings);
    }
};
