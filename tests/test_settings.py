import json

from proto_clean import settings as S


def test_defaults_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    s = S.load_settings()
    assert s.autoconnect_fastest is True
    assert s.netshield.enabled is True
    assert "StevenBlack" in s.netshield.blocklists[0].url
    assert s.netshield.blocklists[0].enabled is True
    assert s.cache_configs is True
    assert s.vpn_options.vpn_accelerator is True
    assert s.port_forward.request_in_config is True

    S.update(autoconnect_fastest=False, **{"netshield.enabled": False,
                                           "vpn_options.vpn_accelerator": False})
    s2 = S.load_settings()
    assert s2.autoconnect_fastest is False
    assert s2.netshield.enabled is False
    assert s2.vpn_options.vpn_accelerator is False
    assert s2.netshield.block_nxdomain is True      # untouched nested default
    assert (tmp_path / "settings.json").exists()


def test_protocol_defaults_and_normalization(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    s = S.load_settings()
    # WireGuard by default; NAT-PMP + VPN Accelerator default ON
    assert s.protocol.protocol == "wireguard"
    assert s.protocol.openvpn_transport == "udp"
    assert s.protocol.openvpn_driver == "tun"

    S.update(**{"protocol.protocol": "openvpn",
               "protocol.openvpn_transport": "tcp",
               "protocol.openvpn_driver": "tap"})
    s2 = S.load_settings()
    assert s2.protocol.protocol == "openvpn"
    assert s2.protocol.openvpn_transport == "tcp"
    assert s2.protocol.openvpn_driver == "tap"

    # unknown values fall back to the safe defaults on load
    (tmp_path / "settings.json").write_text(json.dumps(
        {"protocol": {"protocol": "carrier-pigeon",
                      "openvpn_transport": "sctp",
                      "openvpn_driver": "tap"}}))
    s3 = S.load_settings()
    assert s3.protocol.protocol == "wireguard"
    assert s3.protocol.openvpn_transport == "udp"
    assert s3.protocol.openvpn_driver == "tap"      # tap is valid, kept


def test_advanced_defaults_and_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    s = S.load_settings()
    assert s.advanced.alternative_routing is True
    assert s.advanced.custom_dns_enabled is False
    assert s.advanced.custom_dns_servers == []
    assert s.advanced.ipv6_support is False
    assert s.advanced.ipv6_leak_protection is True

    S.update(**{"advanced.alternative_routing": False,
               "advanced.custom_dns_enabled": True,
               "advanced.custom_dns_servers": ["1.1.1.1", "not-an-ip", "9.9.9.9"],
               "advanced.ipv6_support": True,
               "advanced.ipv6_leak_protection": False,
               "kill_switch.allow_lan": True,
               "vpn_options.moderate_nat": True})
    s2 = S.load_settings()
    assert s2.advanced.alternative_routing is False
    assert s2.advanced.custom_dns_enabled is True
    assert s2.advanced.custom_dns_list() == ["1.1.1.1", "9.9.9.9"]  # invalid dropped
    assert s2.advanced.ipv6_support is True
    assert s2.advanced.ipv6_leak_protection is False
    assert s2.kill_switch.allow_lan is True
    assert s2.vpn_options.moderate_nat is True


def test_legacy_sources_migrate_to_named_blocklists(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(json.dumps({
        "netshield": {
            "enabled": True,
            "sources": [
                "https://example.com/hosts",
                "https://other.example.org/list.txt",
            ],
        }
    }))
    s = S.load_settings()
    assert len(s.netshield.blocklists) == 2
    assert s.netshield.blocklists[0].url == "https://example.com/hosts"
    assert s.netshield.blocklists[0].enabled is True
    assert s.netshield.blocklists[0].name  # derived, non-empty
    # persists as the new structure
    S.save_settings(s)
    raw = json.loads((tmp_path / "settings.json").read_text())
    assert isinstance(raw["netshield"]["blocklists"], list)
    assert raw["netshield"]["blocklists"][0]["url"] == "https://example.com/hosts"


def test_blocklist_sources_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    lists = [
        S.BlocklistSource(name="List A", url="https://a.example/hosts"),
        S.BlocklistSource(name="List B", url="https://b.example/hosts",
                          enabled=False),
    ]
    S.update(**{"netshield.blocklists": [b.to_json() for b in lists]})
    s = S.load_settings()
    assert [b.name for b in s.netshield.blocklists] == ["List A", "List B"]
    assert s.netshield.enabled_lists()[0].name == "List A"   # B disabled
    assert s.netshield.urls() == ["https://a.example/hosts",
                                  "https://b.example/hosts"]


def test_corrupt_file_falls_back_to_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text("{not json")
    assert S.load_settings().autoconnect_fastest is True


def test_missing_nested_keys_use_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "SETTINGS_FILE", tmp_path / "settings.json")
    (tmp_path / "settings.json").write_text(json.dumps({"username": "x"}))
    s = S.load_settings()
    assert s.username == "x"
    assert s.split_tunnel.excluded_apps == []
