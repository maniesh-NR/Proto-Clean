"""Tests for the samizdat config generator (Lantern's protocol)."""

import json
import os
import stat

import pytest

from proto_clean.vpn.samizdatconf import (
    DEFAULT_MIXED_PORT,
    SamizdatConfigError,
    SamizdatProfile,
    build_samizdat_config,
    parse_samizdat_url,
    profile_from_kwargs,
    write_samizdat_config,
)

PBK = "a" * 64            # 32-byte X25519 public key as hex
SID = "0123456789abcdef"  # 8-byte short id as hex

FULL_URL = (
    "samizdat://sam.example.org:8443?"
    f"pbk={PBK}&sid={SID}&sni=ok.ru&fp=chrome&profile=firefox"
    "&jitterms=50&streams=64&threshold=9000&jitter=0&padding=0"
    "&tcpfrag=0&recfrag=0&idle=2m&connect=10s#My%20node"
)


# ------------------------------------------------------------------ parsing
def test_parse_full_url():
    p = parse_samizdat_url(FULL_URL)
    assert p.address == "sam.example.org"
    assert p.port == 8443
    assert p.public_key == PBK
    assert p.short_id == SID
    assert p.server_name == "ok.ru"          # cover/masquerade SNI
    assert p.fingerprint == "chrome"
    assert p.padding_profile == "firefox"
    assert p.max_jitter_ms == 50
    assert p.max_streams_per_conn == 64
    assert p.data_threshold == 9000
    assert p.disable_jitter is True
    assert p.disable_padding is True
    assert p.disable_tcp_fragmentation is True
    assert p.disable_record_fragmentation is True
    assert p.idle_timeout == "2m"
    assert p.connect_timeout == "10s"
    assert p.name == "My node"


def test_parse_minimal_url_defaults():
    p = parse_samizdat_url(f"samizdat://h.example:443?pbk={PBK}&sid={SID}")
    assert p.port == 443
    assert p.server_name == ""               # cover SNI is optional
    assert p.fingerprint == "chrome"
    assert p.padding_profile == "chrome"
    assert p.max_jitter_ms == 30             # lantern-box defaults
    assert p.max_streams_per_conn == 100
    assert p.data_threshold == 14000
    assert p.disable_jitter is False
    assert p.disable_padding is False
    assert p.idle_timeout == "5m"
    assert p.connect_timeout == "15s"


def test_parse_accepts_long_param_names():
    p = parse_samizdat_url(
        f"samizdat://h.example:443?public_key={PBK}&short_id={SID}"
        "&server_name=www.example.com")
    assert p.public_key == PBK
    assert p.short_id == SID
    assert p.server_name == "www.example.com"


def test_parse_rejects_bad_input():
    with pytest.raises(SamizdatConfigError):
        parse_samizdat_url("vless://x@y:443")            # wrong scheme
    with pytest.raises(SamizdatConfigError):
        parse_samizdat_url("samizdat://:443")            # no host
    with pytest.raises(SamizdatConfigError):             # missing pbk
        parse_samizdat_url(f"samizdat://h.example?sid={SID}")
    with pytest.raises(SamizdatConfigError):             # missing sid
        parse_samizdat_url(f"samizdat://h.example?pbk={PBK}")
    with pytest.raises(SamizdatConfigError):             # bad public key
        parse_samizdat_url(f"samizdat://h.example?pbk={'z' * 64}&sid={SID}")
    with pytest.raises(SamizdatConfigError):             # wrong key length
        parse_samizdat_url(f"samizdat://h.example?pbk={'a' * 32}&sid={SID}")
    with pytest.raises(SamizdatConfigError):             # bad short id
        parse_samizdat_url(f"samizdat://h.example?pbk={PBK}&sid=abc")


def test_profile_normalization():
    n = SamizdatProfile(address=" h.example ", port="99999",
                        fingerprint="nope", padding_profile="nope",
                        public_key=PBK, short_id=SID,
                        max_jitter_ms="x", max_streams_per_conn=-5,
                        idle_timeout="bogus", connect_timeout="15s").normalized()
    assert n.address == "h.example"
    assert n.port == 65535                # clamped, not defaulted
    assert n.fingerprint == "chrome"
    assert n.padding_profile == "chrome"
    assert n.max_jitter_ms == 30
    assert n.max_streams_per_conn == 1
    assert n.idle_timeout == "5m"
    assert n.public_key == PBK


def test_profile_from_kwargs_ignores_unknown():
    p = profile_from_kwargs(address="a.example", public_key=PBK,
                            short_id=SID, nonsense=1)
    assert p.address == "a.example"
    assert p.protocol == "samizdat"


# --------------------------------------------------------------- config gen
def test_config_structure_matches_lantern_box():
    p = parse_samizdat_url(FULL_URL)
    cfg = build_samizdat_config(p, mixed_port=12345)
    inbound = cfg["inbounds"][0]
    assert inbound["type"] == "mixed"           # SOCKS5 + HTTP on one port
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["listen_port"] == 12345
    out = cfg["outbounds"][0]
    assert out["type"] == "samizdat"
    assert out["server"] == "sam.example.org"
    assert out["server_port"] == 8443
    assert out["public_key"] == PBK
    assert out["short_id"] == SID
    assert out["server_name"] == "ok.ru"        # masquerade cover site
    assert out["fingerprint"] == "chrome"
    assert out["padding_profile"] == "firefox"
    assert out["max_jitter_ms"] == 50
    assert out["max_streams_per_conn"] == 64
    assert out["data_threshold"] == 9000
    assert out["disable_jitter"] is True
    assert out["disable_padding"] is True
    assert out["disable_tcp_fragmentation"] is True
    assert out["disable_record_fragmentation"] is True
    assert out["idle_timeout"] == "2m"
    assert out["connect_timeout"] == "10s"
    tags = {o["tag"]: o["type"] for o in cfg["outbounds"]}
    assert tags == {"samizdat-out": "samizdat", "direct": "direct"}
    assert any(r.get("ip_is_private") and r["outbound"] == "direct"
               for r in cfg["route"]["rules"])


def test_config_omits_empty_cover_sni():
    p = parse_samizdat_url(f"samizdat://h.example:443?pbk={PBK}&sid={SID}")
    out = build_samizdat_config(p)["outbounds"][0]
    assert "server_name" not in out


def test_config_defaults_match_upstream():
    p = parse_samizdat_url(f"samizdat://h.example:443?pbk={PBK}&sid={SID}")
    out = build_samizdat_config(p)["outbounds"][0]
    assert out["max_jitter_ms"] == 30
    assert out["max_streams_per_conn"] == 100
    assert out["data_threshold"] == 14000
    assert out["disable_padding"] is False
    assert out["idle_timeout"] == "5m"
    assert out["connect_timeout"] == "15s"


def test_config_validation():
    with pytest.raises(SamizdatConfigError):
        build_samizdat_config(SamizdatProfile(address=""))          # no host
    with pytest.raises(SamizdatConfigError):                        # bad pbk
        build_samizdat_config(SamizdatProfile(
            address="a.example", public_key="xy", short_id=SID))
    with pytest.raises(SamizdatConfigError):                        # bad sid
        build_samizdat_config(SamizdatProfile(
            address="a.example", public_key=PBK, short_id="zz"))


def test_write_config_is_private_and_valid(tmp_path):
    p = parse_samizdat_url(f"samizdat://h.example:443?pbk={PBK}&sid={SID}")
    f = tmp_path / "samizdat.json"
    write_samizdat_config(p, str(f), mixed_port=DEFAULT_MIXED_PORT)
    data = json.loads(f.read_text())
    assert data["outbounds"][0]["type"] == "samizdat"
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(str(f)).st_mode) == 0o600
