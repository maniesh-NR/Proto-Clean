"""Tests for the OpenVPN config parser and its local edits."""

import pytest

from proton_clean.vpn.ovpnconf import OvpnConf, OvpnConfigError, apply_ovpn_edits

SAMPLE = """client
proto udp
remote 185.159.158.7 443
resolv-retry infinite
nobind
persist-key
persist-tun
<ca>
-----BEGIN CERTIFICATE-----
not a real cert
-----END CERTIFICATE-----
</ca>
"""


def test_parse_endpoint_and_proto():
    conf = OvpnConf.parse(SAMPLE)
    assert conf.endpoint == ("185.159.158.7", 443, None)
    assert conf.proto == "udp"
    assert "client" in conf.directives
    assert "up" not in conf.directives


def test_remote_inline_proto_wins_when_no_proto_line():
    conf = OvpnConf.parse("client\nremote vpn.example.com 443 tcp\n")
    assert conf.endpoint == ("vpn.example.com", 443, "tcp")
    assert conf.proto == "tcp"


def test_no_remote_is_rejected():
    with pytest.raises(OvpnConfigError):
        OvpnConf.parse("client\nproto udp\n")


def test_shell_hooks_are_refused():
    with pytest.raises(OvpnConfigError):
        OvpnConf.parse(SAMPLE + "up /bin/sh -c pwned\n")
    with pytest.raises(OvpnConfigError):
        OvpnConf.parse(SAMPLE + "script-security 2\n")


def test_cert_block_directives_do_not_confuse_the_validator():
    conf = OvpnConf.parse(SAMPLE)
    # content of <ca> must not be treated as directives
    assert "begin" not in conf.directives
    assert conf.remotes == [("185.159.158.7", 443, None)]


def test_ipv6_on_appends_route_and_tun_ipv6():
    out = apply_ovpn_edits(SAMPLE, ipv6=True, driver="tun")
    assert "route-ipv6 ::/0" in out
    assert "tun-ipv6" in out
    # idempotent
    out2 = apply_ovpn_edits(out, ipv6=True, driver="tun")
    assert out2.count("route-ipv6 ::/0") == 1
    assert out2.count("tun-ipv6") == 1


def test_ipv6_on_with_tap_driver_skips_tun_ipv6():
    out = apply_ovpn_edits(SAMPLE, ipv6=True, driver="tap")
    assert "route-ipv6 ::/0" in out
    assert "tun-ipv6" not in out


def test_ipv6_off_strips_route_ipv6():
    with_v6 = apply_ovpn_edits(SAMPLE, ipv6=True, driver="tun")
    out = apply_ovpn_edits(with_v6, ipv6=False)
    assert "route-ipv6" not in out
    assert "tun-ipv6" not in out


def test_no_edit_is_passthrough():
    assert apply_ovpn_edits(SAMPLE, ipv6=None) == SAMPLE


def test_serialize_roundtrip():
    conf = OvpnConf.parse(SAMPLE)
    assert "remote 185.159.158.7 443" in conf.serialize()
