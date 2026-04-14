"""Parser tests for ``linux_connectivity`` (P1.6.5, Block 0x0054)."""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from memslicer.acquirer.collectors import linux_connectivity as lc
from memslicer.acquirer.collectors.darwin import DarwinCollector
from memslicer.acquirer.collectors.frida_remote import FridaRemoteCollector
from memslicer.acquirer.collectors.ios import IOSCollector
from memslicer.acquirer.collectors.linux import LinuxCollector
from memslicer.acquirer.collectors.windows import WindowsCollector
from memslicer.msl.types import ConnectivityTable


# ---------------------------------------------------------------------------
# /proc/net/route
# ---------------------------------------------------------------------------


IPV4_ROUTE_HEADER = (
    "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\t"
    "Mask\t\tMTU\tWindow\tIRTT\n"
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class TestIPv4Routes:
    def test_parse_ipv4_routes_loopback(self, tmp_path):
        p = tmp_path / "route"
        _write(p, IPV4_ROUTE_HEADER +
               "lo\t0100007F\t00000000\t0005\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
        rows = lc.parse_ipv4_routes(str(p))
        assert len(rows) == 1
        assert rows[0].iface == "lo"
        assert rows[0].dest == b"\x7f\x00\x00\x01"
        assert rows[0].gateway == b"\x00\x00\x00\x00"
        assert rows[0].mask == b"\xff\xff\xff\x00"
        assert rows[0].flags == 0x0005
        assert rows[0].metric == 0
        assert rows[0].mtu == 0

    def test_parse_ipv4_routes_default_gateway(self, tmp_path):
        p = tmp_path / "route"
        _write(p, IPV4_ROUTE_HEADER +
               "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t1500\t0\t0\n")
        rows = lc.parse_ipv4_routes(str(p))
        assert len(rows) == 1
        assert rows[0].iface == "wlan0"
        assert rows[0].dest == b"\x00\x00\x00\x00"
        assert rows[0].gateway == b"\xc0\xa8\x01\x01"  # 192.168.1.1
        assert rows[0].flags == 0x0003
        assert rows[0].metric == 600
        assert rows[0].mtu == 1500

    def test_parse_ipv4_routes_missing_file(self, tmp_path):
        assert lc.parse_ipv4_routes(str(tmp_path / "nope")) == []

    def test_parse_ipv4_routes_header_only(self, tmp_path):
        p = tmp_path / "route"
        _write(p, IPV4_ROUTE_HEADER)
        assert lc.parse_ipv4_routes(str(p)) == []


# ---------------------------------------------------------------------------
# /proc/net/ipv6_route
# ---------------------------------------------------------------------------


class TestIPv6Routes:
    def test_parse_ipv6_routes_lo(self, tmp_path):
        p = tmp_path / "ipv6_route"
        # dest=::1/128, src=::, next_hop=::, metric, refcnt, use, flags, iface
        line = (
            "00000000000000000000000000000001 80 "
            "00000000000000000000000000000000 00 "
            "00000000000000000000000000000000 "
            "00000000 00000001 00000000 80200001 lo\n"
        )
        _write(p, line)
        rows = lc.parse_ipv6_routes(str(p))
        assert len(rows) == 1
        assert rows[0].iface == "lo"
        assert rows[0].dest_prefix == 128
        assert rows[0].dest[-1] == 1
        assert rows[0].flags == 0x80200001

    def test_parse_ipv6_routes_missing_file(self, tmp_path):
        assert lc.parse_ipv6_routes(str(tmp_path / "absent")) == []


# ---------------------------------------------------------------------------
# /proc/net/arp
# ---------------------------------------------------------------------------


ARP_HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"


class TestArpEntries:
    def test_parse_arp_entries_basic(self, tmp_path):
        p = tmp_path / "arp"
        _write(p, ARP_HEADER +
               "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n")
        rows = lc.parse_arp_entries(str(p))
        assert len(rows) == 1
        assert rows[0].ip == socket.inet_aton("192.168.1.1")
        assert rows[0].hw_type == 1
        assert rows[0].flags == 2
        assert rows[0].hw_addr == bytes.fromhex("aabbccddeeff")
        assert rows[0].iface == "wlan0"
        assert rows[0].family == 0x02

    def test_parse_arp_entries_incomplete_skipped(self, tmp_path):
        p = tmp_path / "arp"
        _write(p, ARP_HEADER +
               "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
               "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n")
        rows = lc.parse_arp_entries(str(p))
        assert len(rows) == 1
        assert rows[0].ip == socket.inet_aton("192.168.1.1")


# ---------------------------------------------------------------------------
# /proc/net/packet
# ---------------------------------------------------------------------------


PACKET_HEADER = "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"


class TestPacketSockets:
    def test_parse_packet_sockets_with_pid(self, tmp_path):
        p = tmp_path / "packet"
        _write(p, PACKET_HEADER +
               "ffff8881234abc00 2      3    0003   3     1 0      0      45678\n")
        rows = lc.parse_packet_sockets(str(p), {45678: 1234})
        assert len(rows) == 1
        assert rows[0].pid == 1234
        assert rows[0].inode == 45678
        assert rows[0].proto == 0x0003
        assert rows[0].iface_index == 3
        assert rows[0].user == 0
        assert rows[0].rmem == 0

    def test_parse_packet_sockets_unattributed(self, tmp_path):
        p = tmp_path / "packet"
        _write(p, PACKET_HEADER +
               "ffff8881234abc00 2      3    0800   4     1 128    1000   99999\n")
        rows = lc.parse_packet_sockets(str(p), {})
        assert len(rows) == 1
        assert rows[0].pid == 0
        assert rows[0].inode == 99999
        assert rows[0].proto == 0x0800
        assert rows[0].user == 1000
        assert rows[0].rmem == 128


# ---------------------------------------------------------------------------
# /proc/net/dev
# ---------------------------------------------------------------------------


NETDEV_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
)


class TestNetdevStats:
    def test_parse_netdev_stats_two_interfaces(self, tmp_path):
        p = tmp_path / "dev"
        _write(p, NETDEV_HEADER +
               "    lo: 12345      67    0    0    0     0          0         0 12345        67    0    0    0     0       0          0\n"
               "  eth0: 999000   1234   10    2    0     0          0         0 888000     1000    5    1    0     0       0          0\n")
        rows = lc.parse_netdev_stats(str(p))
        assert len(rows) == 2
        lo_row = rows[0]
        eth0_row = rows[1]
        assert lo_row.iface == "lo"
        assert lo_row.rx_bytes == 12345
        assert lo_row.rx_packets == 67
        assert lo_row.tx_bytes == 12345
        assert lo_row.tx_packets == 67
        assert eth0_row.iface == "eth0"
        assert eth0_row.rx_bytes == 999000
        assert eth0_row.rx_packets == 1234
        assert eth0_row.rx_errs == 10
        assert eth0_row.rx_drop == 2
        assert eth0_row.tx_bytes == 888000
        assert eth0_row.tx_packets == 1000
        assert eth0_row.tx_errs == 5
        assert eth0_row.tx_drop == 1

    def test_parse_netdev_stats_header_skipped(self, tmp_path):
        p = tmp_path / "dev"
        _write(p, NETDEV_HEADER)
        assert lc.parse_netdev_stats(str(p)) == []


# ---------------------------------------------------------------------------
# /proc/net/sockstat
# ---------------------------------------------------------------------------


SOCKSTAT_SAMPLE = (
    "sockets: used 100\n"
    "TCP: inuse 10 orphan 0 tw 0 alloc 15 mem 2\n"
    "UDP: inuse 5 mem 1\n"
    "UDPLITE: inuse 0\n"
    "RAW: inuse 0\n"
    "FRAG: inuse 0 memory 0\n"
)


class TestSockstat:
    def test_parse_sockstat_tcp_udp(self, tmp_path):
        p = tmp_path / "sockstat"
        _write(p, SOCKSTAT_SAMPLE)
        rows = lc.parse_sockstat(str(p))
        by_family = {r.family: r for r in rows}
        assert 0xFF in by_family and by_family[0xFF].in_use == 100
        assert 0x02 in by_family
        assert by_family[0x02].in_use == 10
        assert by_family[0x02].alloc == 15
        assert by_family[0x02].mem == 2
        assert 0x11 in by_family
        assert by_family[0x11].in_use == 5
        assert by_family[0x11].mem == 1
        assert 0x03 in by_family  # RAW
        assert 0x04 in by_family  # FRAG

    def test_parse_sockstat_missing_file(self, tmp_path):
        assert lc.parse_sockstat(str(tmp_path / "no_file")) == []


# ---------------------------------------------------------------------------
# /proc/net/snmp
# ---------------------------------------------------------------------------


class TestSnmp:
    def test_parse_snmp_counters_tcp_mib(self, tmp_path):
        p = tmp_path / "snmp"
        _write(p,
               "Tcp: RtoAlgorithm RtoMin ActiveOpens PassiveOpens\n"
               "Tcp: 1 200 42 7\n")
        rows = lc.parse_snmp_counters(str(p))
        tcp_rows = [r for r in rows if r.mib == "Tcp"]
        assert len(tcp_rows) == 4
        by_name = {r.counter: r.value for r in tcp_rows}
        assert by_name["RtoAlgorithm"] == 1
        assert by_name["RtoMin"] == 200
        assert by_name["ActiveOpens"] == 42
        assert by_name["PassiveOpens"] == 7

    def test_parse_snmp_counters_respects_max_per_mib(self, tmp_path):
        p = tmp_path / "snmp"
        names = " ".join(f"C{i}" for i in range(100))
        values = " ".join(str(i) for i in range(100))
        _write(p, f"Ip: {names}\nIp: {values}\n")
        rows = lc.parse_snmp_counters(str(p), max_per_mib=50)
        assert len(rows) == 50
        assert rows[0].counter == "C0"
        assert rows[49].counter == "C49"


# ---------------------------------------------------------------------------
# End-to-end collector integration
# ---------------------------------------------------------------------------


def _build_full_proc_tree(root: Path) -> None:
    net = root / "net"
    net.mkdir(parents=True, exist_ok=True)
    (net / "route").write_text(IPV4_ROUTE_HEADER +
        "lo\t0100007F\t00000000\t0005\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
    (net / "ipv6_route").write_text(
        "00000000000000000000000000000001 80 "
        "00000000000000000000000000000000 00 "
        "00000000000000000000000000000000 "
        "00000000 00000001 00000000 80200001 lo\n"
    )
    (net / "arp").write_text(ARP_HEADER +
        "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n")
    (net / "packet").write_text(PACKET_HEADER +
        "ffff8881234abc00 2      3    0003   3     1 0      0      45678\n")
    (net / "dev").write_text(NETDEV_HEADER +
        "    lo: 12345      67    0    0    0     0          0         0 12345        67    0    0    0     0       0          0\n")
    (net / "sockstat").write_text(SOCKSTAT_SAMPLE)
    (net / "snmp").write_text(
        "Tcp: RtoAlgorithm RtoMin ActiveOpens\n"
        "Tcp: 1 200 42\n"
    )


class TestCollectConnectivityTableIntegration:
    def test_collect_connectivity_table_full(self, tmp_path):
        _build_full_proc_tree(tmp_path)
        collector = LinuxCollector(proc_root=str(tmp_path))
        table = collector.collect_connectivity_table()
        assert len(table.ipv4_routes) == 1
        assert len(table.ipv6_routes) == 1
        assert len(table.arp_entries) == 1
        assert len(table.packet_sockets) == 1
        assert len(table.netdev_stats) == 1
        assert len(table.sockstat_families) >= 3
        assert len(table.snmp_counters) == 3

    def test_collect_connectivity_table_empty_proc(self, tmp_path):
        (tmp_path / "net").mkdir()
        collector = LinuxCollector(proc_root=str(tmp_path))
        table = collector.collect_connectivity_table()
        assert table.ipv4_routes == []
        assert table.ipv6_routes == []
        assert table.arp_entries == []
        assert table.packet_sockets == []
        assert table.netdev_stats == []
        assert table.sockstat_families == []
        assert table.snmp_counters == []


# ---------------------------------------------------------------------------
# Platform safety + non-Linux stubs
# ---------------------------------------------------------------------------


def test_linux_connectivity_module_import_safe_on_darwin():
    # All parsers should handle nonexistent files gracefully.
    assert lc.parse_ipv4_routes("/nonexistent/route") == []
    assert lc.parse_ipv6_routes("/nonexistent/ipv6_route") == []
    assert lc.parse_arp_entries("/nonexistent/arp") == []
    assert lc.parse_packet_sockets("/nonexistent/packet", {}) == []
    assert lc.parse_netdev_stats("/nonexistent/dev") == []
    assert lc.parse_sockstat("/nonexistent/sockstat") == []
    assert lc.parse_snmp_counters("/nonexistent/snmp") == []


def test_non_linux_collectors_return_empty_connectivity_table():
    darwin_t = DarwinCollector().collect_connectivity_table()
    assert isinstance(darwin_t, ConnectivityTable)
    assert darwin_t.ipv4_routes == []

    win_t = WindowsCollector().collect_connectivity_table()
    assert isinstance(win_t, ConnectivityTable)
    assert win_t.ipv4_routes == []

    ios_t = IOSCollector().collect_connectivity_table()
    assert isinstance(ios_t, ConnectivityTable)
    assert ios_t.ipv4_routes == []

    frida_t = FridaRemoteCollector(session=MagicMock()).collect_connectivity_table()
    assert isinstance(frida_t, ConnectivityTable)
    assert frida_t.ipv4_routes == []


def test_android_inherits_linux_connectivity_table(tmp_path):
    _build_full_proc_tree(tmp_path)
    from memslicer.acquirer.collectors.android import AndroidCollector

    collector = AndroidCollector(proc_root=str(tmp_path))
    table = collector.collect_connectivity_table()
    assert isinstance(table, ConnectivityTable)
    assert len(table.ipv4_routes) == 1
    assert len(table.arp_entries) == 1
