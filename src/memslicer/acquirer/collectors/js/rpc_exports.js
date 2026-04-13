/* rpc_exports.js - Frida rpc.exports dispatch surface for the investigation script.
 *
 * RPC contract (P1.4b): every export returns {data, warnings} where `data` is the
 * previously-returned value (dict or array) and `warnings` is a list of short
 * "<operation_tag>:<message>" strings emitted on recoverable failures. The Python
 * side unwraps the envelope (with a legacy flat-shape compatibility path) and
 * forwards warnings into TargetSystemInfo.collector_warnings.
 */
rpc.exports = {
    getProcessInfo: function(pid) {
        var warnings = [];
        var result = {ppid: 0, sessionId: 0, startTimeNs: 0, exePath: '', cmdLine: '',
                      processName: '', package: ''};
        try {
            if (Process.platform === 'linux') {
                var statLine = readFileText('/proc/' + pid + '/stat');
                if (statLine) {
                    try {
                        var commEnd = statLine.lastIndexOf(')');
                        var fields = statLine.substring(commEnd + 2).trim().split(/\s+/);
                        result.ppid = parseInt(fields[1]) || 0;
                        result.sessionId = parseInt(fields[3]) || 0;
                    } catch(e) { warnings.push('linux_proc_stat:' + e.message); }
                }

                var cmdRaw = readFileText('/proc/' + pid + '/cmdline');
                if (cmdRaw) {
                    result.cmdLine = cmdRaw.replace(/\0/g, ' ').trim();
                    if (result.cmdLine) {
                        result.exePath = result.cmdLine.split(' ')[0];
                    }
                }

                /* Android: derive processName/package from argv[0] and rewrite
                 * exePath to the real ELF (app_process64). */
                if (Java.available && result.cmdLine) {
                    var argv0 = result.cmdLine.split(' ')[0];
                    result.processName = argv0;
                    result.package = argv0.split(':')[0];
                    result.exePath = '/system/bin/app_process64';
                }
            } else if (Process.platform === 'darwin') {
                try {
                    if (ObjC.available) {
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
            }
        } catch(e) { warnings.push('getProcessInfo:' + e.message); }
        return {data: result, warnings: warnings};
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
                /* Shared Linux: /proc/sys/kernel/hostname, /proc/stat btime. */
                result.hostname = readFileText('/proc/sys/kernel/hostname').trim();
                var statContent = readFileText('/proc/stat', 4096);
                var btimeMatch = statContent.match(/btime\s+(\d+)/);
                if (btimeMatch) result.bootTime = parseInt(btimeMatch[1]) * 1000000000;

                /* If Java is available -> Android. Otherwise plain Linux. */
                if (Java.available) {
                    androidGetSystemInfo(result, warnings);
                } else {
                    result.osDetail = readFileText('/proc/version').trim();
                }
            } else if (Process.platform === 'darwin') {
                /* Could be macOS or iOS. Probe sysctl for iOS markers. */
                var hwMachine = sysctlStr('hw.machine');
                if (hwMachine && (hwMachine.indexOf('iPhone') === 0 ||
                                  hwMachine.indexOf('iPad') === 0 ||
                                  hwMachine.indexOf('iPod') === 0)) {
                    iosGetSystemInfo(result, warnings);
                } else {
                    /* macOS via Frida - supplement with sysctl. */
                    result.hwModel = sysctlStr('hw.model');
                    result.cpuBrand = sysctlStr('machdep.cpu.brand_string');
                    result.ramBytes = sysctlU64('hw.memsize');
                    result.kernel = sysctlStr('kern.osrelease');
                    var prodVer = sysctlStr('kern.osproductversion');
                    result.osDetail = prodVer ? ('macOS ' + prodVer) : 'macOS (via Frida)';
                }
            } else if (Process.platform === 'windows') {
                windowsGetSystemInfo(result, warnings);
            }
        } catch(e) { warnings.push('getSystemInfo:' + e.message); }
        return {data: result, warnings: warnings};
    },

    getProcessTable: function(targetPid) {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    ensureNativeFuncs();
                    var dir = _opendir(Memory.allocUtf8String('/proc'));
                    if (!dir.isNull()) {
                        var offset = dNameOffset();
                        var ent;
                        while (!(ent = _readdir(dir)).isNull()) {
                            var name = ent.add(offset).readUtf8String();
                            if (/^\d+$/.test(name)) {
                                var pid = parseInt(name);
                                var sl = readFileText('/proc/' + pid + '/stat');
                                if (sl) {
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
                            }
                        }
                        _closedir(dir);
                    }
                } catch(e) { warnings.push('linux_proc_walk:' + e.message); }
            }
        } catch(e) { warnings.push('getProcessTable:' + e.message); }
        return {data: entries, warnings: warnings};
    },

    getConnectionTable: function() {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    var inodePidMap = buildInodePidMap();
                    var files = [
                        ['/proc/net/tcp',  0x02, 0x06],
                        ['/proc/net/tcp6', 0x0A, 0x06],
                        ['/proc/net/udp',  0x02, 0x11],
                        ['/proc/net/udp6', 0x0A, 0x11]
                    ];
                    for (var i = 0; i < files.length; i++) {
                        var content = readFileText(files[i][0], 131072);
                        if (content) {
                            var parsed = parseNetFile(content, files[i][1], files[i][2], inodePidMap);
                            for (var j = 0; j < parsed.length; j++) entries.push(parsed[j]);
                        }
                    }
                } catch(e) { warnings.push('linux_net_parse:' + e.message); }
            } else if (Process.platform === 'darwin') {
                try {
                    var darwinResults = darwinGetConnections(Process.id);
                    for (var k = 0; k < darwinResults.length; k++) entries.push(darwinResults[k]);
                } catch(e) { warnings.push('darwin_proc_pidinfo:' + e.message); }
            }
        } catch(e) { warnings.push('getConnectionTable:' + e.message); }
        return {data: entries, warnings: warnings};
    },

    getHandleTable: function(pid) {
        var warnings = [];
        var entries = [];
        try {
            if (Process.platform === 'linux') {
                try {
                    ensureNativeFuncs();
                    var fdPath = '/proc/' + pid + '/fd';
                    var fdDir = _opendir(Memory.allocUtf8String(fdPath));
                    if (!fdDir.isNull()) {
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
                } catch(e) { warnings.push('linux_fd_walk:' + e.message); }
            } else if (Process.platform === 'darwin') {
                try {
                    var darwinH = darwinGetHandles(pid);
                    for (var m = 0; m < darwinH.length; m++) entries.push(darwinH[m]);
                } catch(e) { warnings.push('darwin_proc_pidinfo:' + e.message); }
            }
        } catch(e) { warnings.push('getHandleTable:' + e.message); }
        return {data: entries, warnings: warnings};
    }
};
