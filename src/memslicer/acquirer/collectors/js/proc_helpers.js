/* proc_helpers.js - /proc parsing helpers (readlink, dirent, inode->pid, /proc/net). */
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
