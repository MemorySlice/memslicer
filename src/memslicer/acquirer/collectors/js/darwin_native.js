/* darwin_native.js - Darwin libproc helpers for connection & handle tables. */
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
