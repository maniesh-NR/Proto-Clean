"""Cross-platform layer: AllowedIPs subtraction, Windows helper validation,
platform factory and tunnel config edits."""

from __future__ import annotations

import ipaddress

import pytest

from proton_clean.helper_win import (WinHelperError, ps_quote, subtract_from_default,
                                  validate_call, validate_wg_conf)
from proton_clean.platforms import capabilities, get_platform
from proton_clean.platforms.base import Capabilities
from proton_clean.vpn.tunnel import apply_local_edits
from proton_clean.vpn.wgconf import WgQuickConf, WgConfigError

SAMPLE = """
[Interface]
PrivateKey = AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM=
Address = 10.2.0.2/32
DNS = 10.2.0.1
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on

[Peer]
# CA-FREE#1
PublicKey = AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.159.158.132:51820
""".strip()


# ----------------------------------------------------------- wgconf.cidrs


def test_without_cidrs_removes_range():
    conf = WgQuickConf.parse(SAMPLE)
    conf.without_cidrs(["10.10.0.0/16"])
    allowed = conf.peer["AllowedIPs"][0]
    nets = [ipaddress.ip_network(t.strip()) for t in allowed.split(",")]
    assert ipaddress.ip_network("10.10.0.0/16") not in nets
    # everything except the hole is still covered (per address family)
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    assert sum(n.num_addresses for n in v4) == 2 ** 32 - 65536
    assert sum(n.num_addresses for n in v6) == 2 ** 128


def test_without_cidrs_disjoint_is_untouched():
    conf = WgQuickConf.parse(SAMPLE)
    conf.without_cidrs(["203.0.113.0/24"])
    nets = [ipaddress.ip_network(t.strip())
            for t in conf.peer["AllowedIPs"][0].split(",")]
    # the excluded /24 is really gone …
    assert all(ipaddress.ip_address("203.0.113.5") not in n for n in nets)
    # … and only that /24 was removed (neighbours survive)
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    assert sum(n.num_addresses for n in v4) == 2 ** 32 - 256


def test_without_cidrs_rejects_garbage():
    conf = WgQuickConf.parse(SAMPLE)
    with pytest.raises(WgConfigError):
        conf.without_cidrs(["not-a-cidr"])


# ---------------------------------------------------- tunnel text editing


def test_apply_local_edits_preserves_comments():
    out = apply_local_edits(SAMPLE, excluded_cidrs=["10.10.0.0/16"],
                            dns="127.0.0.1")
    assert "# VPN Accelerator = on" in out          # comments survive
    assert "DNS = 127.0.0.1" in out
    assert "10.10.0.0" not in out.split("[Peer]")[1] or "10.10.1.0/24" in out
    # still parses as a valid config
    conf = WgQuickConf.parse(out)
    assert conf.dns == "127.0.0.1"


def test_apply_local_edits_noop_when_nothing_requested():
    assert apply_local_edits(SAMPLE) == SAMPLE


# ------------------------------------------------- windows helper surface


def test_subtract_from_default_excludes_endpoint():
    prefixes = subtract_from_default("185.159.158.132")
    nets = [ipaddress.ip_network(p) for p in prefixes]
    total = sum(n.num_addresses for n in nets)
    assert total == 2 ** 32 + 2 ** 128 - 1        # everything except the endpoint
    for n in nets:
        assert ipaddress.ip_address("185.159.158.132") not in n


def test_subtract_from_default_with_lan_ranges():
    prefixes = subtract_from_default("185.159.158.132", ("192.168.0.0/16",))
    nets = [ipaddress.ip_network(p) for p in prefixes]
    for bad in ("185.159.158.132", "192.168.5.5"):
        assert all(ipaddress.ip_address(bad) not in n for n in nets)
    assert any(ipaddress.ip_network("192.169.0.0/16").subnet_of(n) for n in nets)


def test_ps_quote_escapes_single_quotes():
    assert ps_quote("a'b") == "'a''b'"


def test_validate_call_whitelist():
    validate_call("status", ())
    validate_call("ks-on", ("Ethernet", "1.2.3.4", "51820", "0"))
    validate_call("wait-handshake", ("25",))
    with pytest.raises(WinHelperError):
        validate_call("ks-on", ("Ethernet", "not-an-ip", "51820", "0"))
    with pytest.raises(WinHelperError):
        validate_call("ks-on", ("Ethernet", "1.2.3.4", "99999", "0"))
    with pytest.raises(WinHelperError):
        validate_call("rm-rf-/", ())


def test_validate_wg_conf_rejects_hooks():
    assert validate_wg_conf(SAMPLE)
    assert not validate_wg_conf(SAMPLE.replace(
        "Address = 10.2.0.2/32",
        "Address = 10.2.0.2/32\nPostUp = reboot"))


# -------------------------------------------------------- platform factory


def test_platform_factory_matches_os():
    import sys
    backend = get_platform()
    if sys.platform.startswith("win"):
        assert backend.capabilities.name == "windows"
    elif sys.platform == "darwin":
        assert backend.capabilities.name == "macos"
    else:
        assert backend.capabilities.name == "linux"
    # capabilities object exposes the contract the UI relies on
    caps = capabilities()
    assert isinstance(caps, Capabilities)
    assert caps.split_tunnel_note()
    assert caps.elevation in ("sudo", "uac", "none")
    assert caps.dns_backend in ("iptables-redirect", "root-relay",
                                "config-loopback")


def test_linux_client_paths_and_batch(monkeypatch, tmp_path):
    """SudoHelperClient builds helper commands and loops a batch."""
    from proton_clean.platforms.linux import SudoHelperClient

    fake_bin = tmp_path / "proton-clean-helper"
    fake_bin.write_text("#!/bin/sh\n")
    calls_seen = []

    class FakeProc:
        returncode = 0
        stderr = ""
        stdout = '{"ok": true, "state": "up"}'

    def fake_run(cmd, **kw):
        calls_seen.append(cmd)
        return FakeProc()

    import proton_clean.platforms.linux as linux_mod
    monkeypatch.setattr(linux_mod.subprocess, "run", fake_run)
    client = linux_mod.SudoHelperClient(str(fake_bin))
    res = client.call_batch([("tunnel-up",), ("status",)])
    assert len(res) == 2 and all(r.get("ok") for r in res)
    assert [cmd[-1] for cmd in calls_seen] == ["tunnel-up", "status"]
    assert all(str(fake_bin) in cmd for cmd in calls_seen)
