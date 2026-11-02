"""Tunnel-layer tests: IPv6 config edits, the OpenVPN verb sequence and the
kill-switch transport parameter — driven against a recording fake helper."""

from __future__ import annotations

from proto_clean.vpn import tunnel as tunnel_mod
from proto_clean.vpn.tunnel import TunnelManager, apply_local_edits
from proto_clean.vpn.helper import Helper, HelperError

WG_CONFIG = """[Interface]
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on
PrivateKey = k
Address = 10.2.0.2/32, fd00:dead:beef::2/128
DNS = 10.2.0.1, fd00:dead:beef::1

[Peer]
# US-FREE#1
PublicKey = p
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 1.2.3.4:51820
"""

OVPN_CONFIG = """client
proto tcp
remote 5.6.7.8 443 tcp
resolv-retry infinite
"""


class RecordingHelper:
    """Helper stand-in: records the verb batch, answers ok."""

    def __init__(self):
        self.batches = []
        self.binary = ""

    def call_batch(self, calls, timeout=180.0):
        self.batches.append([tuple(c) for c in calls])
        return [{"ok": True, "state": "up", "tunnel_ip": "10.2.0.2"}
                for _ in calls]

    def call(self, verb, *args, timeout=60.0):
        return self.call_batch([(verb, *args)], timeout)[0]


# ------------------------------------------------------------- config edits

def test_apply_local_edits_strips_ipv6_when_support_is_off():
    out = apply_local_edits(WG_CONFIG, ipv6=False)
    assert "::/0" not in out
    assert "fd00:dead:beef" not in out
    assert "0.0.0.0/0" in out                 # IPv4 untouched
    assert "10.2.0.2/32" in out
    assert "10.2.0.1" in out                  # v4 DNS survives


def test_apply_local_edits_keeps_ipv6_when_support_is_on():
    assert apply_local_edits(WG_CONFIG, ipv6=None) == WG_CONFIG  # passthrough


def test_apply_local_edits_combined_with_cidr_exclusion():
    out = apply_local_edits(WG_CONFIG, excluded_cidrs=["192.168.1.0/24"],
                            ipv6=False)
    assert "::/0" not in out and "192.168.1.0/24" not in out
    assert "0.0.0.0/1" in out                 # CIDR subtraction happened


# ------------------------------------------------------------ verb batches

def _manager(monkeypatch):
    monkeypatch.setattr(tunnel_mod, "_default_route",
                        lambda: ("eth0", "192.168.1.1"))
    mgr = TunnelManager.__new__(TunnelManager)
    mgr.helper = RecordingHelper()
    mgr.ks = type("K", (), {"active": False})()
    mgr.split = type("S", (), {"active": False})()
    mgr.supports_openvpn = True   # orchestration tests: capable platform
    return mgr


def test_wireguard_verb_sequence_and_udp_kill_switch(monkeypatch):
    mgr = _manager(monkeypatch)
    mgr.up(WG_CONFIG, kill_switch=True, ipv6=False)
    batch = mgr.helper.batches[0]
    verbs = [c[0] for c in batch]
    assert verbs[0] == "install-config"
    ks = [c for c in batch if c[0] == "ks-on"][0]
    assert ks[5] == "udp"                      # WG endpoint transport
    assert "tunnel-up" in verbs and "ovpn-up" not in verbs
    # kill switch is armed BEFORE the tunnel comes up
    assert verbs.index("ks-on") < verbs.index("tunnel-up")


def test_openvpn_refused_without_platform_support(monkeypatch):
    """Platforms without the OpenVPN driver (Windows) must refuse cleanly
    before any helper verb is issued — on every host OS."""
    mgr = _manager(monkeypatch)
    mgr.supports_openvpn = False
    try:
        mgr.up(OVPN_CONFIG, protocol="openvpn")
    except HelperError as exc:
        assert "not supported" in str(exc)
    else:
        raise AssertionError("expected HelperError")
    assert mgr.helper.batches == []          # nothing reached the helper


def test_wireguard_still_up_without_openvpn_support(monkeypatch):
    """WireGuard must keep working on OpenVPN-less platforms."""
    mgr = _manager(monkeypatch)
    mgr.supports_openvpn = False
    mgr.up(WG_CONFIG, kill_switch=True)
    verbs = [c[0] for c in mgr.helper.batches[0]]
    assert "tunnel-up" in verbs


def test_openvpn_verb_sequence_tcp_kill_switch_and_driver(monkeypatch):
    mgr = _manager(monkeypatch)
    mgr.up(OVPN_CONFIG, kill_switch=True, protocol="openvpn",
           openvpn_driver="tap", ipv6=True)
    batch = mgr.helper.batches[0]
    verbs = [c[0] for c in batch]
    assert verbs[0] == "ovpn-install-config"
    ks = [c for c in batch if c[0] == "ks-on"][0]
    assert ks[1] == "eth0" and ks[2] == "5.6.7.8" and ks[3] == "443"
    assert ks[5] == "tcp"                      # transport from the config
    up = [c for c in batch if c[0] == "ovpn-up"][0]
    assert up[1] == "tap"                      # driver choice travels
    assert verbs.index("ovpn-up") > verbs.index("ks-on")


def test_ipv6_leak_protection_arms_v6_chain(monkeypatch):
    mgr = _manager(monkeypatch)
    mgr.up(WG_CONFIG, kill_switch=False, ipv6_leak_protection=True)
    verbs = [c[0] for c in mgr.helper.batches[0]]
    assert "v6-on" in verbs
    assert verbs.index("v6-on") < verbs.index("tunnel-up")   # leak-safe order


def test_down_tears_down_both_protocols_and_v6(monkeypatch):
    mgr = _manager(monkeypatch)
    mgr.up(OVPN_CONFIG, protocol="openvpn", ipv6_leak_protection=True)
    mgr.down()
    verbs = [c[0] for c in mgr.helper.batches[-1]]
    for expected in ("tunnel-down", "ovpn-down", "ks-off", "v6-off"):
        assert expected in verbs


def test_hostnames_are_resolved_for_the_kill_switch(monkeypatch):
    import socket

    mgr = _manager(monkeypatch)
    conf = OVPN_CONFIG.replace("remote 5.6.7.8 443 tcp",
                               "remote vpn.example.com 443 tcp")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, None, "",
                                          ("9.9.9.9", 0))])
    mgr.up(conf, kill_switch=True, protocol="openvpn")
    ks = [c for c in mgr.helper.batches[0] if c[0] == "ks-on"][0]
    assert ks[2] == "9.9.9.9"                  # resolved to an IP literal


def test_apply_local_edits_drops_v6_only_address_line():
    """A v6-only Address/DNS must not survive ipv6=False (it used to be
    kept verbatim, leaking IPv6 into the tunnel)."""
    v6_only = WG_CONFIG.replace(
        "Address = 10.2.0.2/32, fd00:dead:beef::2/128",
        "Address = fd00:dead:beef::2/128")
    out = apply_local_edits(v6_only, ipv6=False)
    assert "Address" not in out
    # mixed line keeps the v4 token only
    out2 = apply_local_edits(WG_CONFIG, ipv6=False)
    assert "Address = 10.2.0.2/32" in out2
    assert "fd00" not in out2.split("[Peer]")[0]
