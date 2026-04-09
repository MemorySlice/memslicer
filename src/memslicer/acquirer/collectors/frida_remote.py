"""Frida remote investigation collector.

Executes JavaScript on the target device via Frida RPC to collect
investigation data. Used for Android (USB/ADB) and iOS (USB) targets
where the host machine differs from the target device.
"""
from __future__ import annotations

import logging
from typing import Any

from memslicer.acquirer.collectors.addr_utils import (
    decode_network_order_addr,
    decode_proc_net_addr,
)
from memslicer.acquirer.investigation import TargetProcessInfo, TargetSystemInfo
from memslicer.msl.types import ConnectionEntry, HandleEntry, ProcessEntry


# The Frida JS script extension for investigation data collection.
# This is loaded as a separate script alongside the main acquisition script.
INVESTIGATION_SCRIPT = """\
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

function darwinReadSockAddr(buf, offset) {
    /* Parse a BSD sockaddr at buf+offset. Returns {family, addr (hex), port} or null. */
    var saFamily = buf.add(offset + 1).readU8();
    if (saFamily === BSD_AF_INET) {
        var port = buf.add(offset + 2).readU16() >>> 0; /* already big-endian in struct */
        /* sin_port is stored big-endian; readU16 reads native. Swap if LE. */
        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
        var addrBytes = buf.add(offset + 4).readByteArray(4);
        var hex = '';
        var a = new Uint8Array(addrBytes);
        for (var i = 0; i < 4; i++) hex += ('0' + a[i].toString(16)).slice(-2);
        return {family: MSL_AF_INET, addr: hex, port: port};
    }
    if (saFamily === BSD_AF_INET6) {
        var port6 = buf.add(offset + 2).readU16() >>> 0;
        port6 = ((port6 & 0xFF) << 8) | ((port6 >> 8) & 0xFF);
        var addrBytes6 = buf.add(offset + 8).readByteArray(16);
        var hex6 = '';
        var a6 = new Uint8Array(addrBytes6);
        for (var i = 0; i < 16; i++) hex6 += ('0' + a6[i].toString(16)).slice(-2);
        return {family: MSL_AF_INET6, addr: hex6, port: port6};
    }
    return null;
}

function darwinListFDs(pid) {
    /* List all file descriptors for a given PID. Returns {fdBuf, fdCount} or null. */
    ensureDarwinFuncs();
    var listSize = _proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ptr(0), 0);
    if (listSize <= 0) return null;
    var fdBuf = Memory.alloc(listSize);
    var actualSize = _proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuf, listSize);
    if (actualSize <= 0) return null;
    return {fdBuf: fdBuf, fdCount: Math.floor(actualSize / PROC_FDINFO_SIZE)};
}

function darwinGetConnections(pid) {
    /* Get all socket connections for a given PID using proc_pidinfo. */
    var results = [];
    var fds = darwinListFDs(pid);
    if (!fds) return results;
    var fdBuf = fds.fdBuf;
    var fdCount = fds.fdCount;
    var psiBuf = Memory.alloc(PSI_SIZE);
    for (var i = 0; i < fdCount; i++) {
        var fdNum = fdBuf.add(i * PROC_FDINFO_SIZE).readS32();
        var fdType = fdBuf.add(i * PROC_FDINFO_SIZE + 4).readU32();
        if (fdType !== PROX_FDTYPE_SOCKET) continue;
        var ret = _proc_pidfdinfo(pid, fdNum, PROC_PIDFDSOCKETINFO, psiBuf, PSI_SIZE);
        if (ret <= 0) continue;
        try {
            var kind = psiBuf.add(PSI_SO_KIND_OFF).readS32();
            if (kind !== BSD_AF_INET && kind !== BSD_AF_INET6) continue;
            var sockType = psiBuf.add(PSI_SO_TYPE_OFF).readS32();
            var protocol = 0;
            if (sockType === 1) protocol = 0x06;
            else if (sockType === 2) protocol = 0x11;
            if (protocol === 0) continue;
            var local = darwinReadSockAddr(psiBuf, PSI_SO_LADDR_OFF);
            var remote = darwinReadSockAddr(psiBuf, PSI_SO_RADDR_OFF);
            if (!local) continue;
            var state = 0;
            if (protocol === 0x06) {
                state = psiBuf.add(PSI_SO_STATE_OFF).readS32();
            }
            results.push({
                pid: pid,
                family: local.family,
                protocol: protocol,
                state: state,
                localAddr: local.addr,
                localPort: local.port,
                remoteAddr: remote ? remote.addr : '',
                remotePort: remote ? remote.port : 0,
                _networkOrder: true
            });
        } catch(e) {}
    }
    return results;
}

function darwinGetHandles(pid) {
    /* Get all file descriptors for a given PID using proc_pidinfo. */
    var entries = [];
    var fds = darwinListFDs(pid);
    if (!fds) return entries;
    var fdBuf = fds.fdBuf;
    var fdCount = fds.fdCount;
    /* VNODEPATHINFO buffer: proc_fdinfo (8) + vnode_info_path (struct) */
    var VPI_SIZE = 2352;
    var vpiBuf = Memory.alloc(VPI_SIZE);
    for (var i = 0; i < fdCount; i++) {
        var fdNum = fdBuf.add(i * PROC_FDINFO_SIZE).readS32();
        var fdType = fdBuf.add(i * PROC_FDINFO_SIZE + 4).readU32();
        var handleType = 0;
        var path = '';
        if (fdType === PROX_FDTYPE_SOCKET) {
            handleType = 3;
            path = 'socket';
        } else if (fdType === PROX_FDTYPE_PIPE) {
            handleType = 4;
            path = 'pipe';
        } else if (fdType === PROX_FDTYPE_VNODE) {
            handleType = 1;
            /* Try to get vnode path */
            var ret = _proc_pidfdinfo(pid, fdNum, PROC_PIDFDVNODEPATHINFO, vpiBuf, VPI_SIZE);
            if (ret > 0) {
                try {
                    /* vip_path starts at offset 152 in vnode_fdinfowithpath */
                    path = vpiBuf.add(152).readUtf8String() || '';
                    if (path.indexOf('/dev/') === 0) handleType = 5;
                } catch(e) { path = ''; }
            }
        } else {
            handleType = 0;
        }
        entries.push({pid: pid, fd: fdNum, handleType: handleType, path: path});
    }
    return entries;
}

function readlinkStr(path) {
    var pathBuf = Memory.allocUtf8String(path);
    var len = _readlinkNF(pathBuf, _linkBuf, 255);
    if (len > 0) {
        return _linkBuf.readUtf8String(len);
    }
    return null;
}

function dNameOffset() {
    return Process.pointerSize === 8 ? 19 : 11;
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

rpc.exports = {
    getProcessInfo: function(pid) {
        var result = {ppid: 0, sessionId: 0, startTimeNs: 0, exePath: '', cmdLine: ''};

        if (Process.platform === 'linux') {
            var statLine = readFileText('/proc/' + pid + '/stat');
            if (statLine) {
                try {
                    var commEnd = statLine.lastIndexOf(')');
                    var fields = statLine.substring(commEnd + 2).trim().split(/\\s+/);
                    result.ppid = parseInt(fields[1]) || 0;
                    result.sessionId = parseInt(fields[3]) || 0;
                } catch(e) {}
            }

            var cmdRaw = readFileText('/proc/' + pid + '/cmdline');
            if (cmdRaw) {
                result.cmdLine = cmdRaw.replace(/\\0/g, ' ').trim();
                if (result.cmdLine) {
                    result.exePath = result.cmdLine.split(' ')[0];
                }
            }
        }

        if (Process.platform === 'darwin') {
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
            } catch(e) {}
        }

        return result;
    },

    getSystemInfo: function() {
        var result = {bootTime: 0, hostname: '', domain: '', osDetail: ''};

        if (Process.platform === 'linux') {
            result.hostname = readFileText('/proc/sys/kernel/hostname').trim();

            var statContent = readFileText('/proc/stat', 4096);
            var btimeMatch = statContent.match(/btime\\s+(\\d+)/);
            if (btimeMatch) {
                result.bootTime = parseInt(btimeMatch[1]) * 1000000000;
            }

            if (Java.available) {
                try {
                    Java.performNow(function() {
                        var SP = Java.use('android.os.SystemProperties');
                        var release = SP.get('ro.build.version.release', '');
                        var sdk = SP.get('ro.build.version.sdk', '');
                        var model = SP.get('ro.product.model', '');
                        var mfr = SP.get('ro.product.manufacturer', '');
                        var fp = SP.get('ro.build.fingerprint', '');
                        var parts = [];
                        if (release) parts.push('Android ' + release);
                        if (sdk) parts.push('(API ' + sdk + ')');
                        if (mfr) parts.push(mfr);
                        if (model) parts.push(model);
                        if (fp) parts.push('[' + fp + ']');
                        result.osDetail = parts.join(' ');
                    });
                } catch(e) {
                    result.osDetail = readFileText('/proc/version').trim();
                }
            } else {
                result.osDetail = readFileText('/proc/version').trim();
            }
        }

        if (Process.platform === 'darwin') {
            if (ObjC.available) {
                try {
                    var device = ObjC.classes.UIDevice.currentDevice();
                    result.osDetail = 'iOS ' + device.systemVersion().toString() + ' (' + device.model().toString() + ')';
                    result.hostname = device.name().toString();
                } catch(e) {}
            }
        }

        if (Process.platform === 'windows') {
            result.osDetail = 'Windows (via Frida)';
        }

        return result;
    },

    getProcessTable: function(targetPid) {
        var entries = [];

        if (Process.platform === 'linux') {
            try {
                ensureNativeFuncs();
                var dir = _opendir(Memory.allocUtf8String('/proc'));
                if (!dir.isNull()) {
                    var offset = dNameOffset();
                    var ent;
                    while (!(ent = _readdir(dir)).isNull()) {
                        var name = ent.add(offset).readUtf8String();
                        if (/^\\d+$/.test(name)) {
                            var pid = parseInt(name);
                            var sl = readFileText('/proc/' + pid + '/stat');
                            if (sl) {
                                try {
                                    var ce = sl.lastIndexOf(')');
                                    var cs = sl.indexOf('(');
                                    var comm = sl.substring(cs + 1, ce);
                                    var fields = sl.substring(ce + 2).trim().split(/\\s+/);
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
            } catch(e) {}
        }

        return entries;
    },

    getConnectionTable: function() {
        if (Process.platform === 'linux') {
            try {
                var inodePidMap = buildInodePidMap();
                var results = [];
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
                        for (var j = 0; j < parsed.length; j++) results.push(parsed[j]);
                    }
                }
                return results;
            } catch(e) { return []; }
        }
        if (Process.platform === 'darwin') {
            try {
                return darwinGetConnections(Process.id);
            } catch(e) { return []; }
        }
        return [];
    },

    getHandleTable: function(pid) {
        if (Process.platform === 'linux') {
            try {
                ensureNativeFuncs();
                var entries = [];
                var fdPath = '/proc/' + pid + '/fd';
                var fdDir = _opendir(Memory.allocUtf8String(fdPath));
                if (fdDir.isNull()) return entries;
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
                return entries;
            } catch(e) { return []; }
        }
        if (Process.platform === 'darwin') {
            try {
                return darwinGetHandles(pid);
            } catch(e) { return []; }
        }
        return [];
    }
};
"""


class FridaRemoteCollector:
    """Investigation collector using Frida RPC for remote targets.

    Executes JavaScript on the target device to collect system
    information that cannot be gathered from the host.
    """

    _is_memslicer_collector = True

    def __init__(
        self,
        session: Any,
        logger: logging.Logger | None = None,
    ) -> None:
        self._session = session
        self._log = logger or logging.getLogger("memslicer")
        self._api: Any | None = None

    def connect(self) -> None:
        """Load the investigation script and obtain RPC exports."""
        script = self._session.create_script(INVESTIGATION_SCRIPT)
        script.on("message", self._on_message)
        script.load()
        self._api = script.exports_sync
        self._log.info("Investigation script loaded on target")

    def _on_message(self, message: dict, data: Any) -> None:
        if message.get("type") == "error":
            self._log.warning("Investigation script error: %s", message.get("description"))

    def collect_process_identity(self, pid: int) -> TargetProcessInfo:
        """Collect process identity via Frida RPC on target."""
        if self._api is None:
            return TargetProcessInfo()

        try:
            raw = self._api.get_process_info(pid)
            return TargetProcessInfo(
                ppid=raw.get("ppid", 0),
                session_id=raw.get("sessionId", 0),
                start_time_ns=raw.get("startTimeNs", 0),
                exe_path=raw.get("exePath", ""),
                cmd_line=raw.get("cmdLine", ""),
            )
        except Exception as exc:
            self._log.warning("Frida getProcessInfo failed: %s", exc)
            return TargetProcessInfo()

    def collect_system_info(self) -> TargetSystemInfo:
        """Collect system info via Frida RPC on target."""
        if self._api is None:
            return TargetSystemInfo()

        try:
            raw = self._api.get_system_info()
            return TargetSystemInfo(
                boot_time=raw.get("bootTime", 0),
                hostname=raw.get("hostname", ""),
                domain=raw.get("domain", ""),
                os_detail=raw.get("osDetail", ""),
            )
        except Exception as exc:
            self._log.warning("Frida getSystemInfo failed: %s", exc)
            return TargetSystemInfo()

    def collect_process_table(self, target_pid: int) -> list[ProcessEntry]:
        """Collect process table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw_entries = self._api.get_process_table(target_pid)
            return [
                ProcessEntry(
                    pid=e.get("pid", 0),
                    ppid=e.get("ppid", 0),
                    uid=e.get("uid", 0),
                    is_target=e.get("isTarget", False),
                    start_time=e.get("startTime", 0),
                    rss=e.get("rss", 0),
                    exe_name=e.get("exeName", ""),
                    cmd_line=e.get("cmdLine", ""),
                    user=e.get("user", ""),
                )
                for e in raw_entries
            ]
        except Exception as exc:
            self._log.warning("Frida getProcessTable failed: %s", exc)
            return []

    def collect_connection_table(self) -> list[ConnectionEntry]:
        """Collect connection table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw = self._api.get_connection_table()
            return [self._parse_connection_entry(e) for e in raw]
        except Exception as exc:
            self._log.warning("Frida getConnectionTable failed: %s", exc)
            return []

    def collect_handle_table(self, pid: int) -> list[HandleEntry]:
        """Collect handle table via Frida RPC on target."""
        if self._api is None:
            return []

        try:
            raw = self._api.get_handle_table(pid)
            return [
                HandleEntry(
                    pid=e.get("pid", pid),
                    fd=e.get("fd", 0),
                    handle_type=e.get("handleType", 0),
                    path=e.get("path", ""),
                )
                for e in raw
            ]
        except Exception as exc:
            self._log.warning("Frida getHandleTable failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_connection_entry(self, e: dict) -> ConnectionEntry:
        """Parse a single JS connection entry dict into ConnectionEntry."""
        family = e.get("family", 0x02)
        is_ipv6 = family == 0x0A
        network_order = e.get("_networkOrder", False)
        decode = decode_network_order_addr if network_order else decode_proc_net_addr
        return ConnectionEntry(
            pid=e.get("pid", 0),
            family=family,
            protocol=e.get("protocol", 0x06),
            state=e.get("state", 0),
            local_addr=decode(e.get("localAddr", ""), is_ipv6),
            local_port=e.get("localPort", 0),
            remote_addr=decode(e.get("remoteAddr", ""), is_ipv6),
            remote_port=e.get("remotePort", 0),
        )

    # Legacy static method aliases for backward compatibility with tests
    _decode_darwin_addr = staticmethod(decode_network_order_addr)
    _decode_proc_net_addr = staticmethod(decode_proc_net_addr)
