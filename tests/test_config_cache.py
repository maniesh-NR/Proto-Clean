"""Tests for the local WireGuard-config cache (reuse until failure)."""

from proton_clean.vpn.config_cache import (
    ConfigCache, fingerprint_of, parse_config_meta, slugify,
)

SAMPLE = """[Interface]
# Bouncing = 2
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on
PrivateKey = UDRmqqk+os6BvNK09szrUO8V8hZZPDAP6ebi7XF6cE8=
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1, 2a07:b944::2:1

[Peer]
# CA-FREE#1
PublicKey = 4+452KKZ/BpmTeJ0Ua5YulgtVJKrFlw0AKKo4PtlYxM=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 178.249.214.65:51820
PersistentKeepalive = 25
"""

SAMPLE_PMP = SAMPLE.replace("# NAT-PMP (Port Forwarding) = off",
                            "# NAT-PMP (Port Forwarding) = on")


class Opts:
    def __init__(self, accel=True, nat=False, protocol="wireguard",
                 transport="udp"):
        self.vpn_accelerator = accel
        self.nat_pmp_port_forward = nat
        self.protocol = protocol
        self.openvpn_transport = transport


def test_parse_meta_from_real_config():
    m = parse_config_meta(SAMPLE)
    assert m["server"] == "CA-FREE#1"
    assert m["nat_pmp"] is False
    assert m["vpn_accelerator"] is True
    assert m["protocol"] == "wireguard"          # [Interface] config
    m2 = parse_config_meta(SAMPLE_PMP)
    assert m2["nat_pmp"] is True


OVPN_SAMPLE = """client
proto tcp
remote 185.159.158.7 443
# US-FREE#1
<ca>
foo
</ca>
"""


def test_parse_meta_detects_openvpn_and_transport():
    m = parse_config_meta(OVPN_SAMPLE)
    assert m["protocol"] == "openvpn"
    assert m["openvpn_transport"] == "tcp"
    m_udp = parse_config_meta(OVPN_SAMPLE.replace("proto tcp", "proto udp"))
    assert m_udp["openvpn_transport"] == "udp"


def test_fingerprint_differs_by_options():
    assert fingerprint_of(Opts()) != fingerprint_of(Opts(nat=True))
    assert fingerprint_of(Opts()) == fingerprint_of(Opts())


def test_fingerprint_encodes_protocol_and_transport():
    assert fingerprint_of(Opts()).startswith("wg-")
    assert fingerprint_of(Opts(protocol="openvpn")).startswith("ovpn-udp-")
    assert fingerprint_of(Opts(protocol="openvpn",
                               transport="tcp")).startswith("ovpn-tcp-")
    # a WireGuard lookup can never collide with an OpenVPN fingerprint
    assert fingerprint_of(Opts()) != fingerprint_of(Opts(protocol="openvpn"))
    # unknown values fall back to safe defaults
    assert fingerprint_of(Opts(protocol="gopher")).startswith("wg-")


def test_put_and_exact_get(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("CA-FREE#1", SAMPLE, Opts())
    got = c.get("CA-FREE#1", Opts())
    assert got is not None
    assert got.exact is True
    assert got.text == SAMPLE
    assert got.source == "downloaded"


def test_get_falls_back_to_other_options(tmp_path):
    """Options are comments in the file — a different-options config still
    connects, so it is reused rather than re-downloaded."""
    c = ConfigCache(root=tmp_path)
    c.put("CA-FREE#1", SAMPLE, Opts())
    got = c.get("CA-FREE#1", Opts(accel=False, nat=True))
    assert got is not None
    assert got.exact is False


def test_harvested_config_parses_its_own_options(tmp_path):
    c = ConfigCache(root=tmp_path)
    fp = c.put("CA-FREE#1", SAMPLE, options=None, source="harvested")
    assert fp == fingerprint_of(Opts(accel=True, nat=False))
    got = c.get("CA-FREE#1", Opts(accel=True, nat=False))
    assert got is not None and got.exact and got.source == "harvested"


def test_missing_server_returns_none(tmp_path):
    c = ConfigCache(root=tmp_path)
    assert c.get("NL-FREE#9", Opts()) is None


def test_invalidate_removes_every_variant(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("CA-FREE#1", SAMPLE, Opts())
    c.put("CA-FREE#1", SAMPLE_PMP, Opts(nat=True))
    assert len(c) == 2
    c.invalidate("CA-FREE#1")
    assert c.get("CA-FREE#1", Opts()) is None
    assert c.get("CA-FREE#1", Opts(nat=True)) is None
    assert len(c) == 0
    assert list(tmp_path.glob("*.conf")) == []


def test_failure_and_verified_counters(tmp_path):
    c = ConfigCache(root=tmp_path)
    fp = c.put("CA-FREE#1", SAMPLE, Opts())
    c.note_failure("CA-FREE#1", fp)
    c.note_failure("CA-FREE#1", fp)
    c.mark_verified("CA-FREE#1", fp)
    e = [x for x in c.entries() if x["server"] == "CA-FREE#1"][0]
    assert e["failures"] == 2
    assert e["verified_at"] > 0


def test_servers_are_isolated(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("CA-FREE#1", SAMPLE, Opts())
    c.put("US-FREE#50", SAMPLE.replace("CA-FREE#1", "US-FREE#50"), Opts())
    got = c.get("US-FREE#50", Opts())
    assert got is not None
    assert "# US-FREE#50" in got.text
    assert c.get("JP-FREE#3", Opts()) is None


def test_purge(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("CA-FREE#1", SAMPLE, Opts())
    c.purge()
    assert len(c) == 0
    assert c.get("CA-FREE#1", Opts()) is None


def test_slugify_stable_and_safe():
    assert slugify("CA-FREE#1") == "ca-free-1"
    assert slugify("CA-FREE#1") == slugify("CA-FREE#1")
    assert "/" not in slugify("../etc/passwd")


# ------------------------------------------- protocol-aware caching


def test_openvpn_config_never_serves_a_wireguard_lookup(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("US-FREE#1", OVPN_SAMPLE,
          Opts(protocol="openvpn", transport="tcp"))
    assert c.get("US-FREE#1", Opts(protocol="openvpn",
                                    transport="tcp")) is not None
    # same server, WireGuard requested → no cached config may match
    assert c.get("US-FREE#1", Opts()) is None


def test_wireguard_config_never_serves_an_openvpn_lookup(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("US-FREE#1", SAMPLE, Opts())
    assert c.get("US-FREE#1", Opts(protocol="openvpn")) is None
    assert c.get("US-FREE#1", Opts()) is not None


def test_both_protocols_coexist_for_one_server(tmp_path):
    c = ConfigCache(root=tmp_path)
    c.put("US-FREE#1", SAMPLE, Opts())
    c.put("US-FREE#1", OVPN_SAMPLE, Opts(protocol="openvpn",
                                          transport="udp"))
    assert len(c) == 2
    wg = c.get("US-FREE#1", Opts())
    ov = c.get("US-FREE#1", Opts(protocol="openvpn"))
    assert wg.protocol == "wireguard" and "[Interface]" in wg.text
    assert ov.protocol == "openvpn" and ov.text.startswith("client")
    # .ovpn files are stored with the ovpn extension
    assert list(tmp_path.glob("*.ovpn")) and list(tmp_path.glob("*.conf"))


def test_harvested_ovpn_detects_protocol_from_text(tmp_path):
    c = ConfigCache(root=tmp_path)
    fp = c.put("US-FREE#1", OVPN_SAMPLE, options=None, source="harvested")
    assert fp.startswith("ovpn-tcp")           # proto tcp in the text
    assert c.get("US-FREE#1", Opts(protocol="openvpn",
                                    transport="tcp")) is not None


def test_legacy_index_entries_treated_as_wireguard(tmp_path):
    import json

    c = ConfigCache(root=tmp_path)
    c.put("US-FREE#1", SAMPLE, Opts())
    # simulate a pre-OpenVPN index entry (no "protocol" key)
    idx = json.loads((tmp_path / "index.json").read_text())
    for entry in idx[slugify("US-FREE#1")]["entries"].values():
        entry["options"].pop("protocol", None)
    (tmp_path / "index.json").write_text(json.dumps(idx))
    got = c.get("US-FREE#1", Opts())            # WG lookup still matches
    assert got is not None
    assert c.get("US-FREE#1", Opts(protocol="openvpn")) is None
