"""Tests for the lantern-box engine (proto_clean.vpn.protocols.boxproto).

Golden tests for build_box_config (one per supported kind), the registry
self-registration, the capability probe (fake binaries) and the engine
lifecycle through the inherited XrayManager machinery.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

# importing boxproto registers the previously factory-less registry kinds
from proto_clean.vpn import xray as xray_mod
from proto_clean.vpn.protocols import boxproto as BP
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.boxproto import (SUPPORTED_KINDS, BoxEngine,
                                                build_box_config,
                                                probe_support)
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.xray import XrayError
from proto_clean.vpn.xrayconf import XrayProfile

from test_xray import _free_port, _write_executable  # noqa: F401  (helpers)

MIXED_IN = {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1"}
DIRECT = {"type": "direct", "tag": "direct"}


# ---------------------------------------------------------------- profiles
SS = M.ShadowsocksProfile(server="ss.example", port=8388,
                          method="aes-256-gcm", password="ss-pass")
AWG = M.AwgProfile(server="awg.example", port=51820, private_key="priv-key",
                   peer_public_key="peer-key", address=["10.8.1.2/32"],
                   allowed_ips=["0.0.0.0/0"],
                   junk={"Jc": 4, "Jmin": 10, "Jmax": 30, "S1": 15, "S2": 16,
                         "H1": 5, "H2": 6, "H3": 7, "H4": 8})


# ---------------------------------------------------------------------------
# golden tests: build_box_config
# ---------------------------------------------------------------------------
class TestShadowsocks:
    def test_plain(self):
        cfg = build_box_config("shadowsocks", SS, 10810)
        assert cfg["inbounds"] == [dict(MIXED_IN, listen_port=10810)]
        out = cfg["outbounds"][0]
        assert out["type"] == "shadowsocks"
        assert out["server"] == "ss.example"
        assert out["server_port"] == 8388
        assert out["method"] == "aes-256-gcm"
        assert out["password"] == "ss-pass"
        assert "plugin" not in out and "plugin_opts" not in out
        assert len(cfg["outbounds"]) == 2
        assert cfg["outbounds"][-1] == DIRECT

    def test_sip002_plugin_parsed(self):
        p = M.ShadowsocksProfile(server="s.example", port=8388,
                                 method="aes-256-gcm", password="p",
                                 plugin="obfs-local;obfs=http;"
                                        "obfs-host=example.com")
        out = build_box_config("shadowsocks", p, 10810)["outbounds"][0]
        assert out["plugin"] == "obfs-local"
        assert out["plugin_opts"] == "obfs=http;obfs-host=example.com"


class TestShadowsocksr:
    def test_fields(self):
        p = M.ShadowsocksrProfile(server="ssr.example", port=8388,
                                  protocol="auth_aes128_md5",
                                  method="aes-256-cfb", obfs="http_simple",
                                  password="ssr-pass",
                                  protocol_param="rr=size", obfs_param="x=1")
        out = build_box_config("shadowsocksr", p, 10810)["outbounds"][0]
        assert out["type"] == "shadowsocksr"
        assert out["server"] == "ssr.example"
        assert out["server_port"] == 8388
        assert out["method"] == "aes-256-cfb"
        assert out["password"] == "ssr-pass"
        assert out["protocol"] == "auth_aes128_md5"
        assert out["protocol_param"] == "rr=size"
        assert out["obfs"] == "http_simple"
        assert out["obfs_param"] == "x=1"


class TestHysteria2:
    def test_salamander_tls_insecure(self):
        p = M.Hysteria2Profile(server="h.example", port=8443, auth="hy-pass",
                               sni="sni.example", insecure=True,
                               obfs="salamander", obfs_password="obf-pass")
        out = build_box_config("hysteria2", p, 10810)["outbounds"][0]
        assert out["type"] == "hysteria2"
        assert out["server"] == "h.example"
        assert out["server_port"] == 8443
        assert out["password"] == "hy-pass"
        assert out["obfs"] == {"type": "salamander", "password": "obf-pass"}
        assert out["tls"] == {"enabled": True, "server_name": "sni.example",
                              "insecure": True}
        assert "pre_initial_junk" not in out

    def test_defaults(self):
        p = M.Hysteria2Profile(server="h.example", port=443, auth="x")
        out = build_box_config("hysteria2", p, 10810)["outbounds"][0]
        assert "obfs" not in out
        assert out["tls"]["server_name"] == "h.example"   # sni falls back
        assert out["tls"]["insecure"] is False

    def test_hysteria2x_variant(self):
        p = M.Hysteria2Profile(server="h.example", port=443, auth="x",
                               engine="hysteria2x")
        out = build_box_config("hysteria2", p, 10810)["outbounds"][0]
        assert out["type"] == "hysteria2x"
        assert out["pre_initial_junk"] is True


class TestTuic:
    def test_fields(self):
        p = M.TuicProfile(uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                          password="tuic-pass", server="t.example", port=8443,
                          sni="sni.example", congestion="cubic",
                          alpn="h3", udp_relay_mode="quic",
                          allow_insecure=True)
        out = build_box_config("tuic", p, 10810)["outbounds"][0]
        assert out["type"] == "tuic"
        assert out["uuid"] == "b831381d-6324-4d53-ad4f-8cda48b30811"
        assert out["password"] == "tuic-pass"
        assert out["congestion_control"] == "cubic"
        assert out["udp_relay_mode"] == "quic"
        assert out["tls"] == {"enabled": True, "server_name": "sni.example",
                              "alpn": ["h3"], "insecure": True}


class TestNaive:
    def test_fields(self):
        p = M.NaiveProfile(server="n.example", port=443, username="user",
                           password="naive-pass", sni="sni.example",
                           insecure=True)
        out = build_box_config("naive", p, 10810)["outbounds"][0]
        assert out["type"] == "naive"
        assert out["server"] == "n.example"
        assert out["server_port"] == 443
        assert out["username"] == "user"
        assert out["password"] == "naive-pass"
        assert out["tls"] == {"enabled": True, "server_name": "sni.example",
                              "insecure": True}


class TestTrojan:
    def test_fields(self):
        p = XrayProfile(protocol="trojan", address="tr.example", port=443,
                        password="trojan-pass", sni="sni.example",
                        allow_insecure=True)
        out = build_box_config("trojan", p, 10810)["outbounds"][0]
        assert out["type"] == "trojan"
        assert out["server"] == "tr.example"
        assert out["server_port"] == 443
        assert out["password"] == "trojan-pass"
        assert out["tls"] == {"enabled": True, "server_name": "sni.example",
                              "insecure": True}


class TestReflex:
    def test_fields(self):
        p = M.ReflexProfile(server="r.example", port=443,
                            cert_pem="-----BEGIN CERTIFICATE-----",
                            key_pem="-----BEGIN PRIVATE KEY-----")
        out = build_box_config("reflex", p, 10810)["outbounds"][0]
        assert out["type"] == "reflex"
        assert out["server"] == "r.example"
        assert out["server_port"] == 443
        assert out["cert_pem"] == "-----BEGIN CERTIFICATE-----"
        assert out["key_pem"] == "-----BEGIN PRIVATE KEY-----"


class TestWater:
    def test_fields(self):
        p = M.WaterProfile(server="w.example", port=9003, transport="mq",
                           hashsum="deadbeef",
                           wasm_urls=["https://a/mod.wasm",
                                      "https://b/mod.wasm"],
                           download_timeout="30s")
        out = build_box_config("water", p, 10810)["outbounds"][0]
        assert out["type"] == "water"
        assert out["server"] == "w.example"
        assert out["server_port"] == 9003
        assert out["transport"] == "mq"
        assert out["hashsum"] == "deadbeef"
        assert out["wasm_available_at"] == ["https://a/mod.wasm",
                                            "https://b/mod.wasm"]
        assert out["download_timeout"] == "30s"
        assert out["config"] == {}


class TestOutline:
    def test_dns_variants(self):
        p = M.OutlineProfile(server="o.example", port=443,
                             dns=["system", "https:dns.example",
                                  "tls:dns.example:8.8.8.8",
                                  "udp:9.9.9.9", "tcp:8.8.4.4"],
                             tls=["fragmentation", "reordering"],
                             domains=["blocked.example"])
        out = build_box_config("outline", p, 10810)["outbounds"][0]
        assert out["type"] == "outline"
        assert out["server"] == "o.example"
        assert out["server_port"] == 443
        assert out["dns"] == [{"system": {}},
                              {"https": {"name": "dns.example"}},
                              {"tls": {"name": "dns.example",
                                       "address": "8.8.8.8"}},
                              {"udp": {"address": "9.9.9.9"}},
                              {"tcp": {"address": "8.8.4.4"}}]
        assert out["tls"] == ["fragmentation", "reordering"]
        assert out["domains"] == ["blocked.example"]
        assert out["test_timeout"] == "10s"

    def test_bad_dns_entries_dropped(self):
        p = M.OutlineProfile(server="o.example", port=443,
                             dns=["", "https:", "weird"])
        out = build_box_config("outline", p, 10810)["outbounds"][0]
        # "weird" falls back to a bare UDP address, empties are dropped
        assert out["dns"] == [{"udp": {"address": "weird"}}]


class TestAlgeneva:
    def test_fields(self):
        p = M.AlgenevaProfile(server="g.example", port=9001,
                              strategy="tcp:5:split2")
        out = build_box_config("algeneva", p, 10810)["outbounds"][0]
        assert out["type"] == "algeneva"
        assert out["server"] == "g.example"
        assert out["server_port"] == 9001
        assert out["strategy"] == "tcp:5:split2"


class TestAmneziawg:
    def test_endpoint_junk_and_route_rules(self):
        cfg = build_box_config("amneziawg", AWG, 10810)
        assert cfg["inbounds"] == [dict(MIXED_IN, listen_port=10810)]
        assert len(cfg["endpoints"]) == 1
        ep = cfg["endpoints"][0]
        assert ep["type"] == "amneziawg"
        assert ep["tag"] == "awg-ep"
        assert ep["address"] == ["10.8.1.2/32"]
        assert ep["private_key"] == "priv-key"
        assert ep["peers"] == [{"public_key": "peer-key",
                                "endpoint": "awg.example:51820",
                                "allowed_ips": ["0.0.0.0/0"]}]
        assert ep["junk_packet_count"] == 4
        assert ep["junk_packet_min_size"] == 10
        assert ep["junk_packet_max_size"] == 30
        assert ep["init_packet_junk_size"] == 15
        assert ep["response_packet_junk_size"] == 16
        assert ep["init_packet_magic_header"] == 5
        assert ep["response_packet_magic_header"] == 6
        assert ep["underload_packet_magic_header"] == 7
        assert ep["transport_packet_magic_header"] == 8
        # endpoints are not outbounds: only "direct" remains, and the
        # inbound is routed to the endpoint by tag
        assert cfg["outbounds"] == [DIRECT]
        assert cfg["route"]["rules"] == [{"inbound": "mixed-in",
                                          "endpoint": "awg-ep"}]
        assert cfg["route"]["final"] == "direct"

    def test_junk_keys_case_insensitive(self):
        p = M.AwgProfile(server="awg.example", port=51820,
                         private_key="k", peer_public_key="p",
                         junk={"jc": 2, "jmin": 5, "jmax": 9})
        ep = build_box_config("amneziawg", p, 10810)["endpoints"][0]
        assert ep["junk_packet_count"] == 2
        assert ep["junk_packet_min_size"] == 5
        assert ep["junk_packet_max_size"] == 9
        assert "init_packet_junk_size" not in ep

    def test_upstream_chaining_raises(self):
        with pytest.raises(ProtocolError):
            build_box_config("amneziawg", AWG, 10810,
                             upstream=("127.0.0.1", 10811))


class TestChainingAndErrors:
    def test_upstream_detour(self):
        cfg = build_box_config("shadowsocks", SS, 10810,
                               upstream=("127.0.0.1", 10811))
        outs = cfg["outbounds"]
        assert outs[0]["type"] == "shadowsocks"
        assert outs[0]["detour"] == "upstream"
        assert {"type": "socks", "tag": "upstream", "server": "127.0.0.1",
                "server_port": 10811, "version": "5"} in outs
        assert outs[-1] == DIRECT                      # direct stays last

    def test_no_upstream_by_default(self):
        out = build_box_config("shadowsocks", SS, 10810)["outbounds"][0]
        assert "detour" not in out

    def test_unknown_kind_raises(self):
        with pytest.raises(ProtocolError):
            build_box_config("bogus", SS, 10810)

    def test_supported_kinds_complete(self):
        assert set(SUPPORTED_KINDS) >= {
            "shadowsocks", "shadowsocksr", "hysteria2", "tuic", "naive",
            "trojan", "reflex", "water", "outline", "algeneva", "amneziawg"}


# ---------------------------------------------------------------------------
# registry integration (importing boxproto wires the None factories)
# ---------------------------------------------------------------------------
class TestRegistry:
    def test_box_kinds_now_have_engines(self):
        from proto_clean.vpn.protocols import has_engine
        for kind in ("shadowsocksr", "naive", "amneziawg", "awg",
                     "reflex", "outline", "algeneva", "water"):
            assert has_engine(kind), kind

    def test_cloak_and_others_stay_external(self):
        from proto_clean.vpn.protocols import has_engine
        assert not has_engine("cloak")     # OpenVPN composite
        assert not has_engine("chain")
        assert has_engine("samizdat")      # untouched

    def test_builtin_engines_not_replaced(self):
        from proto_clean.vpn.protocols import make_engine
        from proto_clean.vpn.protocols.sslocal import ShadowsocksEngine
        eng = make_engine("shadowsocks", M.ShadowsocksProfile(server="x"))
        assert isinstance(eng, ShadowsocksEngine)
        assert not isinstance(eng, BoxEngine)

    def test_make_engine_naive(self):
        from proto_clean.vpn.protocols import make_engine
        eng = make_engine("naive", M.NaiveProfile(server="x"), socks_port=0)
        assert isinstance(eng, BoxEngine)
        assert eng.box_kind == "naive"
        assert eng.proxy_kind == "box"

    def test_make_engine_awg_alias_maps_to_amneziawg(self):
        from proto_clean.vpn.protocols import make_engine
        eng = make_engine("awg", M.AwgProfile(server="x"))
        assert isinstance(eng, BoxEngine)
        assert eng.box_kind == "amneziawg"

    def test_make_engine_reflex_outline(self):
        from proto_clean.vpn.protocols import make_engine
        for kind, prof in (("reflex", M.ReflexProfile(server="x")),
                           ("outline", M.OutlineProfile(server="x")),
                           ("shadowsocksr", M.ShadowsocksrProfile(server="x")),
                           ("water", M.WaterProfile(server="x")),
                           ("algeneva", M.AlgenevaProfile(server="x"))):
            eng = make_engine(kind, prof)
            assert isinstance(eng, BoxEngine) and eng.box_kind == kind


# ---------------------------------------------------------------------------
# capability probe with fake binaries
# ---------------------------------------------------------------------------
class TestProbeSupport:
    def test_yes_binary_supports_everything(self, tmp_path):
        # cross-platform stand-in: exits 0 on every invocation
        exe = _write_executable(tmp_path, "yes-box", "pass")
        res = probe_support(str(exe), SUPPORTED_KINDS)
        assert set(res) == set(SUPPORTED_KINDS)
        assert all(res.values())

    def test_failing_binary_supports_nothing(self, tmp_path):
        # exits non-zero (3) on every invocation
        exe = _write_executable(tmp_path, "no-box", "", fail=True)
        res = probe_support(str(exe), ("naive", "tuic"))
        assert res == {"naive": False, "tuic": False}

    def test_missing_binary_all_false_no_crash(self):
        res = probe_support("/nonexistent/lantern-box-xyz",
                            ("naive", "amneziawg"))
        assert res == {"naive": False, "amneziawg": False}

    def test_empty_binary_arg_all_false(self):
        assert probe_support("", ("naive",)) == {"naive": False}

    def test_results_cached_per_binary(self, tmp_path):
        counter = str(tmp_path / "probe-calls")
        exe = _write_executable(tmp_path, "count-box",
                                "open(%r, 'a').write('x')" % counter)
        probe_support(str(exe), ("naive",))
        probe_support(str(exe), ("naive",))       # cache hit
        with open(counter) as f:
            assert f.read().count("x") == 1

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="POSIX shell script with shebang")
    def test_shell_script_exit_zero(self, tmp_path):
        exe = tmp_path / "sh-box"
        exe.write_text("#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
        assert all(probe_support(str(exe), ("naive", "reflex")).values())


# ---------------------------------------------------------------------------
# engine lifecycle through the inherited XrayManager machinery
# ---------------------------------------------------------------------------
FAKE_BOX_BODY = """
import json, socket, sys, time
if len(sys.argv) > 1 and sys.argv[1] == "check":
    sys.exit(0)
cfg = sys.argv[sys.argv.index("-c") + 1]
with open(cfg) as f:
    port = json.load(f)["inbounds"][0]["listen_port"]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
while True:
    time.sleep(0.2)
"""


@pytest.fixture()
def fake_box(tmp_path):
    """lantern-box stand-in: `check` exits 0, `run` binds the mixed port."""
    return _write_executable(tmp_path, "fake-box", FAKE_BOX_BODY)


@pytest.fixture()
def rejecting_box(tmp_path):
    """lantern-box stand-in whose `check` always fails (exit 1)."""
    return _write_executable(tmp_path, "reject-box", "import sys\n"
                             "sys.exit(1)\n")


class TestBoxEngine:
    def test_start_stop_roundtrip(self, fake_box, tmp_path, monkeypatch):
        monkeypatch.setattr(xray_mod, "CACHE_DIR", tmp_path)
        port = _free_port()
        prof = M.NaiveProfile(server="n.example", port=443, username="u",
                              password="p", sni="n.example")
        eng = BP.engine("naive", prof, socks_port=port)
        eng.start(prof, socks_port=port, binary=fake_box)
        try:
            assert eng.running is True
            st = eng.status()
            assert st["socks_port"] == port
            assert st["http_port"] == port        # mixed inbound mirrors
            assert st["box_kind"] == "naive"
            assert st["protocol"] == "naive"
            cfg_path = tmp_path / "box" / "config.json"
            cfg = json.loads(cfg_path.read_text())
            assert cfg["inbounds"][0]["type"] == "mixed"
            assert cfg["inbounds"][0]["listen_port"] == port
            assert cfg["outbounds"][0]["type"] == "naive"
            assert cfg["outbounds"][-1] == DIRECT
            if not sys.platform.startswith("win"):
                assert (os.stat(str(cfg_path)).st_mode & 0o777) == 0o600
        finally:
            eng.stop(revert_proxy=False)
        assert eng.running is False

    def test_unsupported_kind_message(self, rejecting_box):
        prof = M.NaiveProfile(server="n.example")
        eng = BP.engine("naive", prof)
        with pytest.raises(ProtocolError) as ei:
            eng.start(prof, socks_port=_free_port(), binary=rejecting_box)
        msg = str(ei.value)
        assert "lantern-box" in msg
        assert "PROTO_CLEAN_BOX_BIN" in msg
        assert eng.running is False

    def test_amneziawg_chain_rejected_before_spawn(self, fake_box):
        prof = M.AwgProfile(server="awg.example", private_key="k",
                            peer_public_key="p")
        eng = BP.engine("amneziawg", prof)
        eng.upstream_socks_port = 10811          # controller-style chaining
        with pytest.raises(ProtocolError):
            eng.start(prof, socks_port=_free_port(), binary=fake_box)
        assert eng.running is False

    def test_upstream_socks_attr_reaches_config(self, fake_box, tmp_path,
                                                monkeypatch):
        monkeypatch.setattr(xray_mod, "CACHE_DIR", tmp_path)
        port = _free_port()
        prof = M.ShadowsocksProfile(server="s.example", port=8388,
                                    method="aes-256-gcm", password="p")
        eng = BP.engine("shadowsocks", prof)
        eng.upstream_socks = ("127.0.0.1", 10811)   # engine-style chaining
        eng.start(prof, socks_port=port, binary=fake_box)
        try:
            cfg = json.loads((tmp_path / "box" / "config.json").read_text())
            assert cfg["outbounds"][0]["detour"] == "upstream"
            assert {"type": "socks", "tag": "upstream",
                    "server": "127.0.0.1", "server_port": 10811,
                    "version": "5"} in cfg["outbounds"]
        finally:
            eng.stop(revert_proxy=False)

    def test_missing_binary_help_mentions_lantern_box(self):
        eng = BP.engine("naive", M.NaiveProfile(server="x"))
        with pytest.raises(XrayError) as ei:
            eng.start(M.NaiveProfile(server="x"),
                      binary="/nonexistent/lantern-box-xyz")
        msg = str(ei.value)
        assert "lantern-box" in msg and "not found" in msg
        assert "PROTO_CLEAN_BOX_BIN" in msg

    def test_engine_without_kind_rejected(self):
        eng = BoxEngine()
        with pytest.raises(ProtocolError):
            eng.start(M.NaiveProfile(server="x"), binary="whatever")

    def test_engine_factory_rejects_unknown_kind(self):
        with pytest.raises(ProtocolError):
            BP.engine("bogus", M.NaiveProfile(server="x"))
