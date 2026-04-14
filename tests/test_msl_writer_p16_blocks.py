"""Round-trip tests for the P1.6.1 writer blocks.

- ``write_kernel_symbol_bundle`` (Block 0x0055).
- ``write_physical_memory_map`` (Block 0x0059).

Both blocks are inline-parsed rather than routed through a reader
module: the reader path is a separate component that this sub-phase
doesn't land.
"""
from __future__ import annotations

import io
import struct
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.msl.constants import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    HEADER_SIZE,
    ArchType,
    BlockType,
    OSType,
)
from memslicer.msl.types import (
    ArpEntryRow,
    ConnectivityTable,
    FileHeader,
    IPv4RouteRow,
    IPv6RouteRow,
    KernelModuleList,
    KernelModuleRow,
    KernelSymbolBundle,
    ModuleBuildIdManifest,
    ModuleBuildIdRow,
    PersistenceManifest,
    PersistenceRow,
    TargetIntrospection,
    NetdevStatsRow,
    PacketSocketRow,
    PhysicalMemoryMap,
    SnmpCounterRow,
    SockstatFamilyRow,
)
from memslicer.msl.writer import MSLWriter
from memslicer.utils.timestamps import now_ns


@pytest.fixture
def header():
    return FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0,
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=1,
    )


def _last_block_bytes(buf: io.BytesIO) -> tuple[int, bytes]:
    """Walk the stream and return ``(block_type, payload)`` of the last
    block before EoC. Caller writes one block, then calls this.
    """
    data = buf.getvalue()
    offset = HEADER_SIZE
    last_type = None
    last_payload = b""
    while offset < len(data):
        (magic, btype, flags, block_len) = struct.unpack_from(
            "<4sHHI", data, offset,
        )
        if magic != BLOCK_MAGIC:
            break
        payload_start = offset + BLOCK_HEADER_SIZE
        payload_end = offset + block_len
        payload = data[payload_start:payload_end]
        if btype != BlockType.EndOfCapture:
            last_type = btype
            last_payload = payload
        offset = payload_end
    return last_type, last_payload


def _parse_ksb_tlv(payload: bytes) -> dict[int, bytes]:
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    out: dict[int, bytes] = {}
    offset = 8
    for _ in range(row_count):
        tag, length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        out[tag] = payload[offset:offset + length]
        offset += length
    return out


def _parse_phys_rows(payload: bytes) -> list[tuple[int, int, str]]:
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    out: list[tuple[int, int, str]] = []
    offset = 8
    for _ in range(row_count):
        start, end, label_len, _reserved2 = struct.unpack_from(
            "<QQHH", payload, offset,
        )
        offset += 20
        label = payload[offset:offset + label_len].decode("utf-8")
        offset += label_len
        out.append((start, end, label))
    return out


# ---------------------------------------------------------------------------
# KernelSymbolBundle (0x0055)
# ---------------------------------------------------------------------------


class TestKernelSymbolBundleBlock:
    def test_write_kernel_symbol_bundle_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_kernel_symbol_bundle(KernelSymbolBundle())
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.KernelSymbolBundle
        row_count, _ = struct.unpack_from("<II", payload, 0)
        assert row_count == 0

    def test_write_kernel_symbol_bundle_all_tags(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        bundle = KernelSymbolBundle(
            page_size=4096,
            kernel_build_id=bytes(range(20)),
            kaslr_text_va=0xFFFFFFFF81000000,
            kernel_page_offset=0xFFFF888000000000,
            la57_enabled=1,
            pti_active=1,
            btf_sha256=b"\xaa" * 32,
            btf_size_bytes=1_234_567,
            vmcoreinfo_sha256=b"\xbb" * 32,
            kernel_config_sha256=b"\xcc" * 32,
            clock_realtime_ns=111,
            clock_monotonic_ns=222,
            clock_boottime_ns=333,
            clocksource="tsc",
            thp_mode="madvise",
            ksm_active=1,
            directmap_4k_kib=524288,
            directmap_2m_kib=2_097_152,
            directmap_1g_kib=67_108_864,
            zram_devices_json='[{"name":"zram0"}]',
            zswap_enabled=1,
        )
        writer.write_kernel_symbol_bundle(bundle)
        writer.finalize()

        _, payload = _last_block_bytes(buf)
        tags = _parse_ksb_tlv(payload)
        assert tags[0x0001] == struct.pack("<I", 4096)
        assert tags[0x0002] == bytes(range(20))
        assert tags[0x0003] == struct.pack("<Q", 0xFFFFFFFF81000000)
        assert tags[0x0004] == struct.pack("<Q", 0xFFFF888000000000)
        assert tags[0x0005] == b"\x01"
        assert tags[0x0006] == b"\x01"
        assert tags[0x0007] == b"\xaa" * 32
        assert tags[0x0008] == struct.pack("<Q", 1_234_567)
        assert tags[0x0009] == b"\xbb" * 32
        assert tags[0x000A] == b"\xcc" * 32
        assert tags[0x000B] == struct.pack("<Q", 111)
        assert tags[0x000C] == struct.pack("<Q", 222)
        assert tags[0x000D] == struct.pack("<Q", 333)
        assert tags[0x000E] == b"tsc"
        assert tags[0x000F] == b"madvise"
        assert tags[0x0010] == b"\x01"
        assert tags[0x0011] == struct.pack("<Q", 524288)
        assert tags[0x0012] == struct.pack("<Q", 2_097_152)
        assert tags[0x0013] == struct.pack("<Q", 67_108_864)
        assert tags[0x0014] == b'[{"name":"zram0"}]'
        assert tags[0x0015] == b"\x01"
        assert len(tags) == 21

    def test_kernel_symbol_bundle_skips_zero_values(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        bundle = KernelSymbolBundle(
            page_size=4096,
            kernel_build_id=b"\x01\x02\x03\x04",
        )
        writer.write_kernel_symbol_bundle(bundle)
        writer.finalize()

        _, payload = _last_block_bytes(buf)
        row_count, _ = struct.unpack_from("<II", payload, 0)
        assert row_count == 2
        tags = _parse_ksb_tlv(payload)
        assert set(tags.keys()) == {0x0001, 0x0002}

    def test_kernel_symbol_bundle_blocktype(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_kernel_symbol_bundle(KernelSymbolBundle(page_size=4096))
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0055


# ---------------------------------------------------------------------------
# PhysicalMemoryMap (0x0059)
# ---------------------------------------------------------------------------


class TestPhysicalMemoryMapBlock:
    def test_write_physical_memory_map_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_physical_memory_map(PhysicalMemoryMap(ranges=[]))
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.PhysicalMemoryMap
        row_count, _ = struct.unpack_from("<II", payload, 0)
        assert row_count == 0

    def test_write_physical_memory_map_multiple_ranges(self, header):
        ranges = [
            (0x00000000, 0x00000FFF, "Reserved"),
            (0x00100000, 0x7FFFFFFF, "System RAM"),
            (0x80000000, 0xBFFFFFFF, "PCI Bus 0000:00"),
        ]
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_physical_memory_map(PhysicalMemoryMap(ranges=ranges))
        writer.finalize()

        _, payload = _last_block_bytes(buf)
        parsed = _parse_phys_rows(payload)
        assert parsed == ranges

    def test_physical_memory_map_blocktype(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_physical_memory_map(
            PhysicalMemoryMap(ranges=[(0, 0xFFFF, "x")]),
        )
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0059

    def test_physical_memory_map_label_utf8(self, header):
        ranges = [(0x1000, 0x1FFF, "Réservé")]
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_physical_memory_map(PhysicalMemoryMap(ranges=ranges))
        writer.finalize()

        _, payload = _last_block_bytes(buf)
        parsed = _parse_phys_rows(payload)
        assert parsed == ranges


# ---------------------------------------------------------------------------
# ConnectivityTable (0x0054, P1.6.5)
# ---------------------------------------------------------------------------


def _parse_conntable_rows(payload: bytes) -> list[tuple[int, bytes]]:
    """Parse a ConnectivityTable payload into ``[(row_type, body), ...]``."""
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    out: list[tuple[int, bytes]] = []
    offset = 8
    for _ in range(row_count):
        row_type, row_len = struct.unpack_from("<BH", payload, offset)
        offset += 3
        body = payload[offset:offset + row_len]
        offset += row_len
        out.append((row_type, body))
    return out


def _read_str_field(body: bytes, offset: int) -> tuple[str, int]:
    (slen,) = struct.unpack_from("<H", body, offset)
    offset += 2
    s = body[offset:offset + slen].decode("utf-8")
    return s, offset + slen


class TestConnectivityTableBlock:
    def test_empty_connectivity_table_roundtrip(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable())
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.ConnectivityTable
        row_count, _ = struct.unpack_from("<II", payload, 0)
        assert row_count == 0
        assert _parse_conntable_rows(payload) == []

    def test_ipv4_route_roundtrip(self, header):
        row = IPv4RouteRow(
            iface="eth0",
            dest=b"\xc0\xa8\x01\x00",
            gateway=b"\xc0\xa8\x01\x01",
            mask=b"\xff\xff\xff\x00",
            flags=0x0003,
            metric=100,
            mtu=1500,
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(ipv4_routes=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        rows = _parse_conntable_rows(payload)
        assert len(rows) == 1
        rtype, body = rows[0]
        assert rtype == 0x01
        iface, off = _read_str_field(body, 0)
        assert iface == "eth0"
        assert body[off:off + 4] == b"\xc0\xa8\x01\x00"
        assert body[off + 4:off + 8] == b"\xc0\xa8\x01\x01"
        assert body[off + 8:off + 12] == b"\xff\xff\xff\x00"
        flags, metric, mtu = struct.unpack_from("<HII", body, off + 12)
        assert flags == 0x0003
        assert metric == 100
        assert mtu == 1500

    def test_ipv6_route_roundtrip(self, header):
        dest = bytes.fromhex("20010db8000000000000000000000001")
        next_hop = bytes.fromhex("fe800000000000000000000000000001")
        row = IPv6RouteRow(
            iface="eth1",
            dest=dest,
            dest_prefix=64,
            next_hop=next_hop,
            metric=1024,
            flags=0x80200001,
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(ipv6_routes=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        rows = _parse_conntable_rows(payload)
        assert len(rows) == 1
        rtype, body = rows[0]
        assert rtype == 0x02
        iface, off = _read_str_field(body, 0)
        assert iface == "eth1"
        assert body[off:off + 16] == dest
        off += 16
        assert body[off] == 64
        off += 1
        assert body[off:off + 16] == next_hop
        off += 16
        metric, flags = struct.unpack_from("<II", body, off)
        assert metric == 1024
        assert flags == 0x80200001

    def test_arp_entry_roundtrip(self, header):
        row = ArpEntryRow(
            family=0x02,
            ip=b"\xc0\xa8\x01\x05",
            hw_type=1,
            flags=2,
            hw_addr=bytes.fromhex("aabbccddeeff"),
            iface="wlan0",
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(arp_entries=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        rows = _parse_conntable_rows(payload)
        rtype, body = rows[0]
        assert rtype == 0x03
        assert body[0] == 0x02
        assert body[1:5] == b"\xc0\xa8\x01\x05"
        hw_type, flags = struct.unpack_from("<HH", body, 5)
        assert hw_type == 1
        assert flags == 2
        assert body[9:15] == bytes.fromhex("aabbccddeeff")
        iface, _ = _read_str_field(body, 15)
        assert iface == "wlan0"

    def test_packet_socket_roundtrip(self, header):
        row = PacketSocketRow(
            pid=1234, inode=45678, proto=0x0003,
            iface_index=3, user=0, rmem=4096,
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(packet_sockets=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        rows = _parse_conntable_rows(payload)
        rtype, body = rows[0]
        assert rtype == 0x04
        pid, inode, proto, iface_idx, user, rmem = struct.unpack(
            "<IQHIIQ", body,
        )
        assert pid == 1234
        assert inode == 45678
        assert proto == 0x0003
        assert iface_idx == 3
        assert user == 0
        assert rmem == 4096

    def test_netdev_stats_roundtrip(self, header):
        row = NetdevStatsRow(
            iface="eth0",
            rx_bytes=1_000_000, rx_packets=5000, rx_errs=1, rx_drop=2,
            tx_bytes=2_000_000, tx_packets=9000, tx_errs=3, tx_drop=4,
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(netdev_stats=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        rows = _parse_conntable_rows(payload)
        rtype, body = rows[0]
        assert rtype == 0x05
        iface, off = _read_str_field(body, 0)
        assert iface == "eth0"
        vals = struct.unpack_from("<QQQQQQQQ", body, off)
        assert vals == (1_000_000, 5000, 1, 2, 2_000_000, 9000, 3, 4)

    def test_sockstat_family_roundtrip(self, header):
        rows = [
            SockstatFamilyRow(family=0x02, in_use=10, alloc=15, mem=2),
            SockstatFamilyRow(family=0x11, in_use=5, alloc=0, mem=1),
        ]
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(
            ConnectivityTable(sockstat_families=rows),
        )
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        parsed = _parse_conntable_rows(payload)
        assert len(parsed) == 2
        for rtype, body in parsed:
            assert rtype == 0x06
        fam, in_use, alloc, mem = struct.unpack("<BIIQ", parsed[0][1])
        assert (fam, in_use, alloc, mem) == (0x02, 10, 15, 2)
        fam, in_use, alloc, mem = struct.unpack("<BIIQ", parsed[1][1])
        assert (fam, in_use, alloc, mem) == (0x11, 5, 0, 1)

    def test_snmp_counter_roundtrip(self, header):
        row = SnmpCounterRow(mib="Tcp", counter="ActiveOpens", value=12345)
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable(snmp_counters=[row]))
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        parsed = _parse_conntable_rows(payload)
        rtype, body = parsed[0]
        assert rtype == 0x07
        mib, off = _read_str_field(body, 0)
        counter, off = _read_str_field(body, off)
        (value,) = struct.unpack_from("<Q", body, off)
        assert mib == "Tcp"
        assert counter == "ActiveOpens"
        assert value == 12345

    def test_all_row_types_mixed(self, header):
        table = ConnectivityTable(
            ipv4_routes=[IPv4RouteRow(iface="lo")],
            ipv6_routes=[IPv6RouteRow(iface="lo")],
            arp_entries=[ArpEntryRow(iface="eth0", hw_addr=b"\x01" * 6)],
            packet_sockets=[PacketSocketRow(pid=1)],
            netdev_stats=[NetdevStatsRow(iface="lo")],
            sockstat_families=[SockstatFamilyRow(family=0x02)],
            snmp_counters=[SnmpCounterRow(mib="Ip", counter="Forwarding", value=1)],
        )
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(table)
        writer.finalize()
        _, payload = _last_block_bytes(buf)
        row_count, _ = struct.unpack_from("<II", payload, 0)
        assert row_count == 7
        rows = _parse_conntable_rows(payload)
        types = [r[0] for r in rows]
        assert types == [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]

    def test_connectivity_table_blocktype_is_0x0054(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_connectivity_table(ConnectivityTable())
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0054

    def test_unknown_row_type_skip_safe(self, header):
        # Forward-compat pin: manually craft payload with a 0xFF row
        # followed by a valid 0x01 IPv4 row and confirm row_len skipping works.
        unknown_body = b"future-reserved-payload"
        unknown_row = struct.pack("<BH", 0xFF, len(unknown_body)) + unknown_body

        iface = b"lo"
        v4_body = (
            struct.pack("<H", len(iface)) + iface
            + b"\x7f\x00\x00\x01"
            + b"\x00\x00\x00\x00"
            + b"\xff\x00\x00\x00"
            + struct.pack("<HII", 0x0005, 0, 0)
        )
        v4_row = struct.pack("<BH", 0x01, len(v4_body)) + v4_body
        payload = struct.pack("<II", 2, 0) + unknown_row + v4_row

        # Parse using the same parser — should skip the unknown and
        # still see the IPv4 row.
        rows = _parse_conntable_rows(payload)
        assert len(rows) == 2
        assert rows[0][0] == 0xFF
        assert rows[1][0] == 0x01
        iface_parsed, off = _read_str_field(rows[1][1], 0)
        assert iface_parsed == "lo"
        assert rows[1][1][off:off + 4] == b"\x7f\x00\x00\x01"


# ---------------------------------------------------------------------------
# KernelModuleList (0x0057) + ModuleBuildIdManifest (0x005A) — P1.6.2
# ---------------------------------------------------------------------------


def _parse_kernel_module_list(payload: bytes) -> list[dict]:
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    offset = 8
    rows: list[dict] = []
    for _ in range(row_count):
        (name_len,) = struct.unpack_from("<H", payload, offset)
        offset += 2
        name = payload[offset:offset + name_len].decode("utf-8")
        offset += name_len
        (size, refcount, state, taint, base, flags, _reserved_b) = (
            struct.unpack_from("<QIBBQBB", payload, offset)
        )
        offset += 8 + 4 + 1 + 1 + 8 + 1 + 1
        rows.append({
            "name": name, "size": size, "refcount": refcount,
            "state": state, "taint": taint, "base": base, "flags": flags,
        })
    return rows


def _parse_module_build_id_manifest(payload: bytes) -> list[dict]:
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    offset = 8
    rows: list[dict] = []
    for _ in range(row_count):
        (base_addr, bid_len, source, flags, _r) = struct.unpack_from(
            "<QBBBB", payload, offset,
        )
        offset += 12
        build_id = payload[offset:offset + 20]
        offset += 20
        disk_hash = payload[offset:offset + 32]
        offset += 32
        rows.append({
            "base_addr": base_addr,
            "build_id_len": bid_len,
            "build_id_source": source,
            "flags": flags,
            "build_id": build_id,
            "disk_hash": disk_hash,
        })
    return rows


class TestKernelModuleListBlock:
    def test_write_kernel_module_list_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_kernel_module_list(KernelModuleList())
        writer.finalize()
        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.KernelModuleList
        count, _ = struct.unpack_from("<II", payload, 0)
        assert count == 0

    def test_write_kernel_module_list_multiple_rows(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        table = KernelModuleList(rows=[
            KernelModuleRow(
                name="ext4", size=745472, refcount=1,
                state=1, taint=0, base=0xffffffffc0000000, flags=0,
            ),
            KernelModuleRow(
                name="evil_rootkit", size=16384, refcount=0,
                state=1, taint=0x01, base=0, flags=0x01,
            ),
            KernelModuleRow(
                name="ghost_mod", size=0, refcount=0,
                state=0, taint=0x10, base=0, flags=0x02,
            ),
        ])
        writer.write_kernel_module_list(table)
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.KernelModuleList
        rows = _parse_kernel_module_list(payload)
        assert len(rows) == 3
        assert rows[0]["name"] == "ext4"
        assert rows[0]["size"] == 745472
        assert rows[0]["base"] == 0xffffffffc0000000
        assert rows[1]["name"] == "evil_rootkit"
        assert rows[1]["flags"] == 0x01
        assert rows[1]["taint"] == 0x01
        assert rows[2]["name"] == "ghost_mod"
        assert rows[2]["flags"] == 0x02

    def test_kernel_module_list_blocktype_is_0x0057(self, header):
        assert BlockType.KernelModuleList == 0x0057
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_kernel_module_list(KernelModuleList())
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0057


class TestModuleBuildIdManifestBlock:
    def test_write_module_build_id_manifest_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_module_build_id_manifest(ModuleBuildIdManifest())
        writer.finalize()
        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.ModuleBuildIdManifest
        count, _ = struct.unpack_from("<II", payload, 0)
        assert count == 0

    def test_write_module_build_id_manifest_multiple_rows(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        manifest = ModuleBuildIdManifest(rows=[
            ModuleBuildIdRow(
                base_addr=0x400000,
                build_id_len=20, build_id_source=1, flags=0,
                build_id=bytes(range(20)),
                disk_hash=b"\xaa" * 32,
            ),
            ModuleBuildIdRow(
                base_addr=0x500000,
                build_id_len=16, build_id_source=4, flags=0x02,
                build_id=bytes(range(16)),
                disk_hash=b"\xbb" * 32,
            ),
            ModuleBuildIdRow(
                base_addr=0x600000,
                build_id_len=0, build_id_source=0, flags=0x01,
                build_id=b"",
                disk_hash=b"\xcc" * 32,
            ),
        ])
        writer.write_module_build_id_manifest(manifest)
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.ModuleBuildIdManifest
        rows = _parse_module_build_id_manifest(payload)
        assert len(rows) == 3
        assert rows[0]["base_addr"] == 0x400000
        assert rows[0]["build_id_len"] == 20
        assert rows[0]["build_id_source"] == 1
        assert rows[0]["build_id"][:20] == bytes(range(20))
        assert rows[0]["disk_hash"] == b"\xaa" * 32
        assert rows[1]["build_id_source"] == 4
        assert rows[1]["flags"] == 0x02
        # Build-id padded to 20 bytes when shorter.
        assert rows[1]["build_id"][:16] == bytes(range(16))
        assert rows[1]["build_id"][16:] == b"\x00\x00\x00\x00"
        assert rows[2]["flags"] == 0x01
        assert rows[2]["build_id_len"] == 0

    def test_module_build_id_manifest_fixed_row_size(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        manifest = ModuleBuildIdManifest(rows=[
            ModuleBuildIdRow(
                base_addr=0x1000 * (i + 1),
                build_id_len=20, build_id_source=1, flags=0,
                build_id=bytes([i % 256] * 20),
                disk_hash=bytes([i % 256] * 32),
            )
            for i in range(5)
        ])
        writer.write_module_build_id_manifest(manifest)
        writer.finalize()

        _btype, payload = _last_block_bytes(buf)
        count, _ = struct.unpack_from("<II", payload, 0)
        # Rows start at offset 8; total payload = 8 + count * 64.
        assert count == 5
        assert len(payload) - 8 == count * 64

    def test_module_build_id_manifest_blocktype_is_0x005A(self, header):
        assert BlockType.ModuleBuildIdManifest == 0x005A
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_module_build_id_manifest(ModuleBuildIdManifest())
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x005A

    def test_module_build_id_manifest_rejects_oversized_build_id(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        manifest = ModuleBuildIdManifest(rows=[
            ModuleBuildIdRow(
                base_addr=0,
                build_id_len=21, build_id_source=1, flags=0,
                build_id=b"\x00" * 21,
                disk_hash=b"\x00" * 32,
            ),
        ])
        with pytest.raises(ValueError):
            writer.write_module_build_id_manifest(manifest)


# ---------------------------------------------------------------------------
# TargetIntrospection (0x0058, P1.6.3)
# ---------------------------------------------------------------------------


def _parse_target_introspection(payload: bytes) -> tuple[int, dict[int, bytes]]:
    """Walk the TLV rows of a TargetIntrospection payload.

    Returns ``(target_pid, {tag: value_bytes})``. Unlike
    ``KernelSymbolBundle``, the 8-byte header is ``(target_pid,
    reserved)`` — NOT ``(row_count, reserved)`` — so we walk rows
    until ``payload_len - 8`` bytes have been consumed.
    """
    target_pid, _reserved = struct.unpack_from("<II", payload, 0)
    out: dict[int, bytes] = {}
    offset = 8
    while offset + 4 <= len(payload):
        tag, length = struct.unpack_from("<HH", payload, offset)
        # Padding zeros at end of payload stop the walk.
        if tag == 0 and length == 0:
            break
        offset += 4
        out[tag] = payload[offset:offset + length]
        offset += length
    return target_pid, out


class TestTargetIntrospectionBlock:

    def test_write_target_introspection_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(TargetIntrospection(target_pid=1234))
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.TargetIntrospection
        target_pid, tags = _parse_target_introspection(payload)
        assert target_pid == 1234
        assert tags == {}

    def test_write_target_introspection_all_tags(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        info = TargetIntrospection(
            target_pid=4242,
            tracer_pid=1,
            login_uid=1000,
            session_audit_id=17,
            selinux_context="system_u:system_r:init_t:s0",
            target_ns_fingerprint="mnt:[40010000],pid:[40010001]",
            target_ns_scope_vs_collector="container",
            smaps_rollup_pss_kib=51200,
            smaps_rollup_swap_kib=1024,
            smaps_anon_hugepages_kib=4096,
            rwx_region_count=3,
            target_cgroup="/user.slice/foo",
            target_cwd="/home/alice",
            target_root="/",
            cap_eff="0000003fffffffff",
            cap_amb="0000000000000000",
            no_new_privs=1,
            seccomp_mode=2,
            core_dumping=1,
            thread_count=9,
            sig_cgt="0000000180014003",
            io_rchar=1000,
            io_wchar=2000,
            io_read_bytes=512,
            io_write_bytes=1024,
            limit_core="0",
            limit_memlock="65536",
            limit_nofile="1024",
            personality_hex="00000000",
            ancestry="42:bash:9000,1:init:1000",
            exe_comm_mismatch=1,
            environ=b"PATH=/bin\x00HOME=/root",
            redacted_env_keys=["AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"],
        )
        writer.write_target_introspection(info)
        writer.finalize()

        _btype, payload = _last_block_bytes(buf)
        target_pid, tags = _parse_target_introspection(payload)
        assert target_pid == 4242
        assert tags[0x0001] == struct.pack("<I", 1)
        assert tags[0x0002] == struct.pack("<I", 1000)
        assert tags[0x0003] == struct.pack("<I", 17)
        assert tags[0x0004] == b"system_u:system_r:init_t:s0"
        assert tags[0x0005] == b"mnt:[40010000],pid:[40010001]"
        assert tags[0x0006] == b"container"
        assert tags[0x0007] == struct.pack("<Q", 51200)
        assert tags[0x0008] == struct.pack("<Q", 1024)
        assert tags[0x0009] == struct.pack("<Q", 4096)
        assert tags[0x000A] == struct.pack("<I", 3)
        assert tags[0x000B] == b"/user.slice/foo"
        assert tags[0x000C] == b"/home/alice"
        assert tags[0x000D] == b"/"
        assert tags[0x000E] == b"0000003fffffffff"
        # cap_amb is all-zero string → emitted since string is non-empty.
        assert tags[0x000F] == b"0000000000000000"
        assert tags[0x0010] == b"\x01"
        assert tags[0x0011] == b"\x02"
        assert tags[0x0012] == b"\x01"
        assert tags[0x0013] == struct.pack("<I", 9)
        assert tags[0x0014] == b"0000000180014003"
        assert tags[0x0015] == struct.pack("<Q", 1000)
        assert tags[0x0016] == struct.pack("<Q", 2000)
        assert tags[0x0017] == struct.pack("<Q", 512)
        assert tags[0x0018] == struct.pack("<Q", 1024)
        assert tags[0x0019] == b"0"
        assert tags[0x001A] == b"65536"
        assert tags[0x001B] == b"1024"
        assert tags[0x001C] == b"00000000"
        assert tags[0x001D] == b"42:bash:9000,1:init:1000"
        assert tags[0x001E] == b"\x01"
        assert tags[0x001F] == b"PATH=/bin\x00HOME=/root"
        assert tags[0x0020] == b"AWS_SECRET_ACCESS_KEY,DB_PASSWORD"

    def test_target_introspection_skips_zero_values(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(
            TargetIntrospection(target_pid=1, tracer_pid=7),
        )
        writer.finalize()

        _btype, payload = _last_block_bytes(buf)
        target_pid, tags = _parse_target_introspection(payload)
        assert target_pid == 1
        assert set(tags.keys()) == {0x0001}
        assert tags[0x0001] == struct.pack("<I", 7)

    def test_target_introspection_header_target_pid(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(TargetIntrospection(target_pid=0xFEED))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        target_pid, _reserved = struct.unpack_from("<II", payload, 0)
        assert target_pid == 0xFEED

    def test_target_introspection_blocktype_is_0x0058(self, header):
        assert BlockType.TargetIntrospection == 0x0058
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(TargetIntrospection(target_pid=1))
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0058

    def test_target_introspection_environ_tag(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(TargetIntrospection(
            target_pid=1,
            environ=b"PATH=/bin\x00HOME=/root\x00",
        ))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        _target_pid, tags = _parse_target_introspection(payload)
        assert tags[0x001F] == b"PATH=/bin\x00HOME=/root\x00"

    def test_target_introspection_redacted_keys_tag(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_target_introspection(TargetIntrospection(
            target_pid=1,
            redacted_env_keys=["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"],
        ))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        _target_pid, tags = _parse_target_introspection(payload)
        assert tags[0x0020] == b"AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN"


# ---------------------------------------------------------------------------
# PersistenceManifest (0x0056, P1.6.4)
# ---------------------------------------------------------------------------


def _parse_persistence_manifest(
    payload: bytes,
) -> tuple[int, list[tuple[int, str, int, int, int]]]:
    """Parse a PersistenceManifest payload into ``(row_count, rows)``.

    Each row is ``(source, path, mtime_ns, size, mode)``.
    """
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    offset = 8
    rows: list[tuple[int, str, int, int, int]] = []
    for _ in range(row_count):
        source, _pad, path_len = struct.unpack_from("<BBH", payload, offset)
        offset += 4
        path = payload[offset:offset + path_len].decode("utf-8")
        offset += path_len
        mtime_ns, size, mode = struct.unpack_from("<QQI", payload, offset)
        offset += 20
        rows.append((source, path, mtime_ns, size, mode))
    return row_count, rows


class TestPersistenceManifestBlock:
    def test_write_persistence_manifest_empty(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(PersistenceManifest(rows=[]))
        writer.finalize()

        btype, payload = _last_block_bytes(buf)
        assert btype == BlockType.PersistenceManifest
        row_count, rows = _parse_persistence_manifest(payload)
        assert row_count == 0
        assert rows == []

    def test_write_persistence_manifest_multiple_rows(self, header):
        rows = [
            PersistenceRow(
                source=1,
                path="/etc/systemd/system/sshd.service",
                mtime_ns=1_700_000_000_000_000_000,
                size=512,
                mode=0o100644,
            ),
            PersistenceRow(
                source=3,
                path="/etc/crontab",
                mtime_ns=1_700_000_001_000_000_000,
                size=123,
                mode=0o100644,
            ),
            PersistenceRow(
                source=11,
                path="/etc/modules",
                mtime_ns=1_700_000_002_000_000_000,
                size=42,
                mode=0o100644,
            ),
        ]
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(PersistenceManifest(rows=rows))
        writer.finalize()

        _btype, payload = _last_block_bytes(buf)
        row_count, parsed = _parse_persistence_manifest(payload)
        assert row_count == 3
        assert parsed == [
            (1, "/etc/systemd/system/sshd.service",
             1_700_000_000_000_000_000, 512, 0o100644),
            (3, "/etc/crontab", 1_700_000_001_000_000_000, 123, 0o100644),
            (11, "/etc/modules", 1_700_000_002_000_000_000, 42, 0o100644),
        ]

    def test_persistence_manifest_blocktype_is_0x0056(self, header):
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(
            PersistenceManifest(rows=[PersistenceRow(source=1, path="/a")]),
        )
        writer.finalize()
        btype, _ = _last_block_bytes(buf)
        assert int(btype) == 0x0056

    def test_persistence_manifest_preserves_path_utf8(self, header):
        path = "/etc/systemd/system/café-é.service"
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(PersistenceManifest(rows=[
            PersistenceRow(source=1, path=path, mtime_ns=1, size=1, mode=0o644),
        ]))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        _, parsed = _parse_persistence_manifest(payload)
        assert parsed[0][1] == path

    def test_persistence_manifest_source_byte_values(self, header):
        rows = [
            PersistenceRow(source=sid, path=f"/fake/{sid}", mtime_ns=1,
                           size=1, mode=0o644)
            for sid in range(1, 12)
        ]
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(PersistenceManifest(rows=rows))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        _, parsed = _parse_persistence_manifest(payload)
        assert [r[0] for r in parsed] == list(range(1, 12))

    def test_persistence_manifest_mtime_ns_roundtrip(self, header):
        big_mtime = 1_999_999_999_987_654_321
        buf = io.BytesIO()
        writer = MSLWriter(buf, header)
        writer.write_persistence_manifest(PersistenceManifest(rows=[
            PersistenceRow(
                source=5, path="/etc/rc.local",
                mtime_ns=big_mtime, size=256, mode=0o100755,
            ),
        ]))
        writer.finalize()
        _btype, payload = _last_block_bytes(buf)
        _, parsed = _parse_persistence_manifest(payload)
        assert parsed[0][2] == big_mtime
        assert parsed[0][3] == 256
        assert parsed[0][4] == 0o100755
