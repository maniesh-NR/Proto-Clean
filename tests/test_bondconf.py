"""Tests for ride-the-bond config chaining (Xray proxySettings /
sing-box detour) and the BondSettings persistence."""

from __future__ import annotations

import json

from proto_clean.settings import (BondSettings, Settings, load_settings,
                                  _bond_from_json)
from proto_clean.vpn.samizdatconf import SamizdatProfile, build_samizdat_config
from proto_clean.vpn.xrayconf import XrayProfile, build_xray_config

PBK = "a" * 64
SID = "0123456789abcdef"

XRAY_PROFILE = XrayProfile(
    protocol="vless-reality", address="1.2.3.4", port=443,
    uuid="11111111-2222-3333-4444-555555555555",
    public_key=PBK, short_id=SID, sni="www.example.org")

SAM_PROFILE = SamizdatProfile(
    address="sam.example.org", port=443,
    public_key=PBK, short_id=SID, server_name="ok.ru")


class TestXrayRideBond:
    def test_no_upstream_by_default(self):
        cfg = build_xray_config(XRAY_PROFILE)
        tags = [o["tag"] for o in cfg["outbounds"]]
        assert "bond-out" not in tags
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        assert "proxySettings" not in proxy

    def test_upstream_adds_socks_chain(self):
        cfg = build_xray_config(XRAY_PROFILE, upstream_socks_port=10811)
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
        assert proxy["proxySettings"] == {"tag": "bond-out"}
        bond = next(o for o in cfg["outbounds"] if o["tag"] == "bond-out")
        assert bond["protocol"] == "socks"
        assert bond["settings"]["servers"][0] == {
            "address": "127.0.0.1", "port": 10811}
        # the private-ip direct rule still bypasses the bond
        assert cfg["routing"]["rules"][0]["outboundTag"] == "direct"

    def test_json_serializable(self):
        cfg = build_xray_config(XRAY_PROFILE, upstream_socks_port=10811)
        assert json.loads(json.dumps(cfg))["outbounds"]


class TestSamizdatRideBond:
    def test_no_upstream_by_default(self):
        cfg = build_samizdat_config(SAM_PROFILE)
        tags = [o["tag"] for o in cfg["outbounds"]]
        assert "bond-out" not in tags
        assert "detour" not in cfg["outbounds"][0]

    def test_upstream_adds_detour(self):
        cfg = build_samizdat_config(SAM_PROFILE,
                                    upstream_socks_port=10811)
        out = cfg["outbounds"][0]
        assert out["type"] == "samizdat"
        assert out["detour"] == "bond-out"
        bond = next(o for o in cfg["outbounds"] if o["tag"] == "bond-out")
        assert bond["type"] == "socks"
        assert bond["server"] == "127.0.0.1"
        assert bond["server_port"] == 10811
        assert bond["version"] == "5"
        assert json.loads(json.dumps(cfg))["outbounds"]


class TestBondSettings:
    def test_defaults(self):
        s = Settings()
        assert s.bond.server == ""
        assert s.bond.port == 10820
        assert s.bond.mode == "bond"
        assert s.bond.interfaces == []
        assert s.bond.socks_port == 10811
        assert s.bond.mode_proxy == "manual"

    def test_normalize(self):
        n = BondSettings(server="  vps.example.org  ", port=70000,
                         mode="nonsense", interfaces=["eth0", "eth0", " ",
                                                      "wlan0"],
                         socks_port="not-a-port", mode_proxy="weird",
                         token=" t ").normalized()
        assert n.server == "vps.example.org"
        assert n.port == 65535
        assert n.mode == "bond"
        assert n.interfaces == ["eth0", "wlan0"]
        assert n.socks_port == 10811        # invalid -> default
        assert n.mode_proxy == "manual"     # invalid -> default
        assert n.token == " t "

    def test_json_roundtrip(self):
        raw = {"server": "vps.example.org", "port": 1234, "mode": "balance",
               "interfaces": ["wlan0", "usb0=172.20.10.2"],
               "socks_port": 10812, "mode_proxy": "system",
               "token": "s3cret"}
        n = _bond_from_json(raw)
        assert n.server == "vps.example.org"
        assert n.mode == "balance"
        assert n.interfaces == ["wlan0", "usb0=172.20.10.2"]
        assert n.mode_proxy == "system"

    def test_json_unknown_fields_coerced(self):
        n = _bond_from_json({"mode": 42, "interfaces": "not-a-list"})
        assert n.mode == "bond"
        # a bare string is accepted as a comma-separated list
        assert n.interfaces == ["not-a-list"]
        n2 = _bond_from_json({"interfaces": "wlan0, eth0"})
        assert n2.interfaces == ["wlan0", "eth0"]

    def test_ride_bond_defaults_on(self):
        assert Settings().xray.ride_bond is True
        assert Settings().samizdat.ride_bond is True
