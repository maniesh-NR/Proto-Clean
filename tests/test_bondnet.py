"""Tests for adapter discovery parsers (proto_clean.vpn.bondnet)."""

from __future__ import annotations

from proto_clean.vpn.bondnet import (
    Adapter, PARSERS, list_adapters, resolve_bind_ips,
)

# ------------------------------------------------------------------ linux
IP_JSON = """[
 {"ifname":"lo","operstate":"unknown","addr_info":[{"family":"inet","local":"127.0.0.1"}]},
 {"ifname":"eth0","operstate":"up","addr_info":[{"family":"inet","local":"192.168.1.20"}]},
 {"ifname":"wlan0","operstate":"up","addr_info":[{"family":"inet6","local":"fe80::1"},{"family":"inet","local":"10.0.0.44"}]},
 {"ifname":"docker0","operstate":"down","addr_info":[{"family":"inet","local":"172.17.0.1"}]}
]"""

IP_TEXT = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever
3: wlan0    inet 10.0.0.44/24 brd 10.0.0.255 scope global wlan0\\       valid_lft forever
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
"""


class TestLinuxParsers:
    def test_json(self):
        got = PARSERS["ip_json"](IP_JSON)
        assert got == [Adapter("eth0", "192.168.1.20"),
                       Adapter("wlan0", "10.0.0.44")]

    def test_json_garbage(self):
        assert PARSERS["ip_json"]("not json") == []

    def test_text(self):
        got = PARSERS["ip_text"](IP_TEXT)
        names = [a.name for a in got]
        assert "lo" not in names
        assert Adapter("eth0", "192.168.1.20") in got
        assert Adapter("wlan0", "10.0.0.44") in got


# ------------------------------------------------------------------ macOS
IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255
\tmedia: autoselect
en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:00
awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1484
\tinet6 fe80::12:34%awdl0 prefixlen 64 scopedid 5
"""


class TestMacosParser:
    def test_ifconfig(self):
        got = PARSERS["ifconfig"](IFCONFIG)
        assert got == [Adapter("en0", "192.168.1.5")]

    def test_ifconfig_no_up(self):
        text = IFCONFIG.replace(
            "en0: flags=8863<UP,BROADCAST", "en0: flags=8863<BROADCAST")
        assert PARSERS["ifconfig"](text) == []


# ---------------------------------------------------------------- windows
PS_JSON = """[
 {"InterfaceAlias":"Ethernet","IPAddress":"10.1.2.3"},
 {"InterfaceAlias":"Wi-Fi","IPAddress":"10.4.5.6"},
 {"InterfaceAlias":"Loopback Pseudo-Interface 1","IPAddress":"127.0.0.1"},
 {"InterfaceAlias":"vEthernet (WSL)","IPAddress":"172.30.16.1"}
]"""

IPCONFIG = """\
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 10.1.2.3
   Subnet Mask . . . . . . . . . . . : 255.255.255.0

Wireless LAN adapter Wi-Fi:

   IPv4 Address. . . . . . . . . . . : 10.4.5.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""


class TestWindowsParsers:
    def test_powershell_json(self):
        got = PARSERS["powershell_json"](PS_JSON)
        assert got == [Adapter("Ethernet", "10.1.2.3"),
                       Adapter("Wi-Fi", "10.4.5.6"),
                       Adapter("vEthernet (WSL)", "172.30.16.1")]

    def test_powershell_single_object(self):
        got = PARSERS["powershell_json"](
            '{"InterfaceAlias":"Wi-Fi","IPAddress":"10.0.0.2"}')
        assert got == [Adapter("Wi-Fi", "10.0.0.2")]

    def test_ipconfig(self):
        got = PARSERS["ipconfig"](IPCONFIG)
        assert got == [Adapter("Ethernet", "10.1.2.3"),
                       Adapter("Wi-Fi", "10.4.5.6")]


# --------------------------------------------------------------- resolution
class TestResolveBindIps:
    ADAPTERS = [Adapter("eth0", "192.168.1.20"),
                Adapter("wlan0", "10.0.0.44")]

    def test_by_name(self):
        assert resolve_bind_ips(["eth0", "wlan0"],
                                adapters=self.ADAPTERS) == \
            ["192.168.1.20", "10.0.0.44"]

    def test_bare_ip(self):
        assert resolve_bind_ips(["1.2.3.4"],
                                adapters=self.ADAPTERS) == ["1.2.3.4"]

    def test_name_ip_pair(self):
        assert resolve_bind_ips(["tun0=100.64.0.2"],
                                adapters=self.ADAPTERS) == ["100.64.0.2"]

    def test_unknown_dropped(self):
        assert resolve_bind_ips(["eth0", "nope0"],
                                adapters=self.ADAPTERS) == ["192.168.1.20"]

    def test_empty_selection(self):
        assert resolve_bind_ips([], adapters=self.ADAPTERS) == []

    def test_dedup(self):
        assert resolve_bind_ips(["eth0", "192.168.1.20"],
                                adapters=self.ADAPTERS) == ["192.168.1.20"]


def test_list_adapters_unknown_platform():
    assert list_adapters(platform="plan9") == []
