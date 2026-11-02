"""Tests for the Xray config generator (VLESS + REALITY / Trojan)."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from proto_clean.vpn.xrayconf import (
    XrayConfigError,
    XrayProfile,
    build_xray_config,
    parse_xray_url,
    profile_from_kwargs,
    write_xray_config,
)

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

VLESS_URL = (
    f"vless://{UUID}@proxy.example.com:443?"
    "encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&"
    "pbk=xW46H2JWbRzuLdROUeK0mnjGMsVrRgpMwfqNJOkUt0c&sid=6ba85179&"
    "type=tcp&flow=xtls-rprx-vision&spx=%2F#My%20REALITY%20node"
)

TROJAN_URL = "trojan://s3cret-pw@tro.example.net:8443?security=tls&sni=www.apple.com&allowInsecure=1#Trojan%20node"


# ------------------------------------------------------------------ parsing
def test_parse_vless_reality_url():
    p = parse_xray_url(VLESS_URL)
    assert p.protocol == "vless-reality"
    assert p.address == "proxy.example.com"
    assert p.port == 443
    assert p.uuid == UUID
    assert p.public_key == "xW46H2JWbRzuLdROUeK0mnjGMsVrRgpMwfqNJOkUt0c"
    assert p.short_id == "6ba85179"
    assert p.flow == "xtls-rprx-vision"
    assert p.sni == "www.microsoft.com"          # SNI masking target
    assert p.fingerprint == "chrome"
    assert p.spider_x == "/"
    assert p.name == "My REALITY node"


def test_parse_trojan_url():
    p = parse_xray_url(TROJAN_URL)
    assert p.protocol == "trojan"
    assert p.address == "tro.example.net"
    assert p.port == 8443
    assert p.password == "s3cret-pw"
    assert p.sni == "www.apple.com"
    assert p.allow_insecure is True
    assert p.name == "Trojan node"


def test_parse_trojan_defaults_to_tls_and_sni_falls_back_to_host():
    p = parse_xray_url("trojan://pw@host.example:443#t")
    assert p.protocol == "trojan"
    assert p.sni == "host.example"
    assert p.allow_insecure is False


def test_parse_rejects_bad_input():
    with pytest.raises(XrayConfigError):
        parse_xray_url("not a url")
    with pytest.raises(XrayConfigError):
        parse_xray_url("vmess://eyJhZGQiOiJ4In0=")        # unsupported scheme
    with pytest.raises(XrayConfigError):
        parse_xray_url("ss://YWVzLTI1Ni1nY206cGFzcw@example.com")  # shadowsocks
    # VLESS without REALITY is explicitly out of scope
    with pytest.raises(XrayConfigError):
        parse_xray_url(f"vless://{UUID}@h.example:443?security=tls#x")
    # REALITY without pbk cannot work
    with pytest.raises(XrayConfigError):
        parse_xray_url(f"vless://{UUID}@h.example:443?security=reality#x")
    # bad UUID
    with pytest.raises(XrayConfigError):
        parse_xray_url(f"vless://not-a-uuid@h.example:443?security=reality&pbk=k#x")
    # missing host
    with pytest.raises(XrayConfigError):
        parse_xray_url(f"vless://{UUID}@:443?security=reality&pbk=k#x")


def test_profile_normalization():
    p = XrayProfile(protocol="bogus", address=" a.example ", port="70000",
                    fingerprint="nope", flow="nope")
    n = p.normalized()
    assert n.protocol == "vless-reality"
    assert n.address == "a.example"
    assert n.port == 443
    assert n.fingerprint == "chrome"
    assert n.flow == "xtls-rprx-vision"


def test_profile_from_kwargs_ignores_unknown():
    p = profile_from_kwargs(address="a.example", protocol="trojan",
                            password="pw", uuid=UUID, nonsense="x")
    assert p.address == "a.example"
    assert p.protocol == "trojan"
    assert p.flow == ""                       # trojan carries no flow


# --------------------------------------------------------------- config gen
def test_vless_reality_config_masks_sni():
    p = parse_xray_url(VLESS_URL)
    cfg = build_xray_config(p, socks_port=10808, http_port=10809)
    out = cfg["outbounds"][0]
    assert out["protocol"] == "vless"
    vnext = out["settings"]["vnext"][0]
    assert vnext["address"] == "proxy.example.com"
    assert vnext["port"] == 443
    assert vnext["users"][0]["id"] == UUID
    assert vnext["users"][0]["encryption"] == "none"
    assert vnext["users"][0]["flow"] == "xtls-rprx-vision"
    ss = out["streamSettings"]
    assert ss["security"] == "reality"
    r = ss["realitySettings"]
    assert r["serverName"] == "www.microsoft.com"       # SNI masking
    assert r["fingerprint"] == "chrome"                 # uTLS mimicry
    assert r["publicKey"] == p.public_key
    assert r["shortId"] == p.short_id


def test_trojan_config():
    p = parse_xray_url(TROJAN_URL)
    cfg = build_xray_config(p)
    out = cfg["outbounds"][0]
    assert out["protocol"] == "trojan"
    srv = out["settings"]["servers"][0]
    assert (srv["address"], srv["port"], srv["password"]) == \
        ("tro.example.net", 8443, "s3cret-pw")
    ss = out["streamSettings"]
    assert ss["security"] == "tls"
    assert ss["tlsSettings"]["serverName"] == "www.apple.com"
    assert ss["tlsSettings"]["allowInsecure"] is True


def test_inbounds_and_routing():
    cfg = build_xray_config(parse_xray_url(VLESS_URL),
                            socks_port=12345, http_port=12346)
    socks, http = cfg["inbounds"]
    assert socks["protocol"] == "socks" and socks["port"] == 12345
    assert socks["listen"] == "127.0.0.1"
    assert socks["settings"]["udp"] is True
    assert http["protocol"] == "http" and http["port"] == 12346
    tags = {o["tag"]: o["protocol"] for o in cfg["outbounds"]}
    assert tags == {"proxy": "vless", "direct": "freedom", "block": "blackhole"}
    rules = cfg["routing"]["rules"]
    assert any(r.get("ip") == ["geoip:private"] and
               r["outboundTag"] == "direct" for r in rules)


def test_config_validation_requires_credentials():
    with pytest.raises(XrayConfigError):
        build_xray_config(XrayProfile(protocol="vless-reality",
                                      address="", port=443))
    with pytest.raises(XrayConfigError):     # missing pbk
        build_xray_config(XrayProfile(protocol="vless-reality",
                                      address="a.example", uuid=UUID,
                                      sni="s.example"))
    with pytest.raises(XrayConfigError):     # missing password
        build_xray_config(XrayProfile(protocol="trojan",
                                      address="a.example"))


def test_write_config_is_private_and_valid(tmp_path):
    p = parse_xray_url(VLESS_URL)
    f = tmp_path / "sub" / "config.json"
    write_xray_config(p, str(f), socks_port=10808, http_port=10809)
    data = json.loads(f.read_text())
    assert data["inbounds"][0]["port"] == 10808
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(f).st_mode)
        assert mode == 0o600                # holds uuid / password
