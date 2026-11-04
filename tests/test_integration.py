"""Cross-protocol integration: everything working with everything else.

These tests pin the *compositions* rather than single protocols:

* Clash / V2ray / sing-box configs import → store → engine configs
* chains across engine families (with the wiring each hop needs)
* WARP before/after presets
* share-link round-trips through every parser
* the SOCKS relay + upstream plumbing the chains rely on
"""

from __future__ import annotations

import base64
import json

import pytest

from proto_clean.vpn.protocols import boxproto, chain, convert, links
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols import profiles, warp
from proto_clean.vpn.protocols.base import ProtocolError


CLASH = """
proxies:
  - {name: ss1, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: vm1, type: vmess, server: v.io, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: ws, tls: true, ws-opts: {path: /v}}
  - {name: hy1, type: hysteria2, server: h.io, port: 443, password: pw, sni: h.io}
"""


class TestImportToEngineConfigs:
    """clash/v2ray/sing-box import -> profiles -> box engine configs."""

    def test_clash_import_to_box_configs(self):
        imported = convert.parse_clash_yaml(CLASH)
        assert len(imported) == 3
        for prof in imported:
            kind = prof.kind
            cfg = boxproto.build_box_config(kind, prof, 10800)
            # every generated config has the mixed inbound and an outbound
            assert cfg["inbounds"][0]["type"] == "mixed"
            assert cfg["inbounds"][0]["listen_port"] == 10800
            assert any("type" in o for o in cfg.get("outbounds", [])) or \
                cfg.get("endpoints")

    def test_v2ray_import_to_box_configs(self):
        doc = {"outbounds": [
            {"tag": "vm", "protocol": "vmess",
             "settings": {"vnext": [{"address": "v.io", "port": 443,
                                     "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
             "streamSettings": {"network": "ws", "security": "tls"}},
            {"tag": "d", "protocol": "freedom"}]}
        imported = convert.parse_v2ray_json(json.dumps(doc))
        assert len(imported) == 1
        cfg = boxproto.build_box_config("vmess", imported[0], 10801)
        vm = [o for o in cfg["outbounds"] if o.get("type") == "vmess"][0]
        assert vm["server"] == "v.io" and vm["tls"]["enabled"]

    def test_singbox_raw_runs_through_box(self):
        user_cfg = {"inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                                  "listen_port": 12345}],
                    "outbounds": [{"type": "vmess", "tag": "vm",
                                   "server": "v.io", "server_port": 443,
                                   "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}
        imported = convert.parse_singbox_json(json.dumps(user_cfg),
                                              raw_passthrough=True)
        cfg = boxproto.build_box_config("boxraw", imported[0], 10802)
        # the user config is preserved verbatim
        assert cfg["inbounds"][0]["listen_port"] == 12345
        assert cfg["outbounds"][0]["tag"] == "vm"


class TestChains:
    """Chain composition rules + WARP presets."""

    def _stub_engines(self, monkeypatch, order):
        from proto_clean.vpn.protocols import base as P
        import socket as _s
        import threading as _t

        class StubEngine(P.ProtocolEngine):
            supports_upstream = True

            def __init__(self, socks_port=0, http_port=0):
                super().__init__(socks_port, http_port)
                self.sock = None

            def start(self, profile, timeout=15.0):
                self.socks_port = P.free_port(self.socks_port or 20800)
                s = _s.socket()
                s.bind(("127.0.0.1", self.socks_port))
                s.listen(1)
                self.sock = s
                order.append((self.proxy_kind, self.socks_port))

            def stop(self, timeout=5.0):
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None

            @property
            def running(self):
                return self.sock is not None

        def fake_make_engine(kind, profile, socks_port=0):
            eng = StubEngine(socks_port=socks_port)
            eng.proxy_kind = kind
            return eng

        import proto_clean.vpn.protocols as registry
        monkeypatch.setattr(registry, "make_engine", fake_make_engine)
        return StubEngine

    def test_chain_rules_and_upstream_wiring(self, monkeypatch):
        order = []
        self._stub_engines(monkeypatch, order)
        prof = M.ChainProfile(hops=[
            "hysteria2://a@h.io:443/?sni=h.io",
            "vmess://",  # replaced below — built via model
        ])
        vmess = M.VmessProfile(server="v.io", port=443,
                               uuid="b831381d-6324-4d53-ad4f-8cda48b30811")
        prof.hops[1] = vmess.share_url()
        hop_profiles = [links.parse_link(h)[1] for h in prof.hops]
        engines = chain.build_chain(hop_profiles)
        # second hop dials through the first hop's local SOCKS
        assert engines[1][0].upstream_socks[1] == engines[0][0].socks_port
        # starting in order, stopping in reverse
        eng = chain.ChainEngine()
        for e, _p in engines:
            e.start(_p)
        eng.engines = [e for e, _ in engines]
        assert all(e.running for e, _ in engines)
        eng.stop()
        assert not any(e.running for e, _ in engines)
        # order: first hop started first
        kinds = [k for k, _ in order]
        assert kinds[0] == "hysteria2" and kinds[1] == "vmess"
        del kinds

    def test_tunnel_kind_only_first(self, monkeypatch):
        order = []
        self._stub_engines(monkeypatch, order)
        hop_profiles = [
            links.parse_link("hysteria2://a@h.io:443/?sni=h.io")[1],
            links.parse_link("ikev2://user@vpn.example.com/?auth=eap-mschapv2")[1],
        ]
        with pytest.raises(chain.ChainError):
            chain.build_chain(hop_profiles)

    def test_warp_before_and_after_presets(self):
        proto_url = "hysteria2://a@h.io:443/?sni=h.io"
        before = links.parse_link(warp.warp_before_chain_url(proto_url))[1]
        assert before.hops[0].startswith("warp://")
        assert before.hops[1] == proto_url
        after = links.parse_link(warp.warp_after_chain_url(proto_url))[1]
        assert after.hops[0] == proto_url
        assert after.hops[1].startswith("warp://")

    def test_warp_engine_configs_for_both_positions(self):
        prof = warp.new_profile()
        prof.private_key = "AAA="
        prof.peer_public_key = "BBB="
        prof.client_id_b64 = base64.b64encode(bytes([1, 2, 3])).decode()
        prof.address_v4 = "172.16.0.2/32"
        # before: endpoint (no upstream possible)
        cfg = boxproto.build_box_config("warp", prof, 10800)
        assert "endpoints" in cfg
        # after: wireguard outbound with detour
        cfg = boxproto.build_box_config("warp", prof, 10800,
                                        upstream=("127.0.0.1", 5555))
        wg = [o for o in cfg["outbounds"] if o.get("type") == "wireguard"]
        assert wg and wg[0]["detour"] == "upstream"


class TestLinkRoundTrips:
    """Every parser produces links that parse back."""

    PROFILES = [
        (M.ShadowsocksProfile(server="s.io", port=8388,
                              method="aes-256-gcm", password="p", tag="x")),
        (M.Hysteria2Profile(server="h.io", port=443, auth="a",
                            sni="h.io", insecure=True,
                            obfs="salamander", obfs_password="o")),
        (M.TuicProfile(uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                       password="p", server="t.io", port=443, sni="t.io")),
        (M.VmessProfile(server="v.io", port=443,
                        uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                        transport="ws", path="/w", tls=True)),
        (M.MasqueProfile(server="m.io", port=443, template="/masque",
                         sni="m.io", insecure=True)),
        (M.NaiveProfile(server="n.io", port=443, username="u",
                        password="p", sni="n.io")),
        (M.CoverDtlsProfile(server="d.io", port=443, psk="k", sni="d.io")),
        (M.RadianceProfile(server="r.io", port=443, token="t",
                           transport="tls")),
        (M.LampshadeProfile(server="l.io", port=443, token="t",
                            transport="tcp")),
        (M.Ikev2Profile(server="i.io", username="u", password="p",
                        auth="eap-mschapv2")),
    ]

    @pytest.mark.parametrize("profile", PROFILES,
                             ids=lambda p: type(p).__name__)
    def test_roundtrip(self, profile):
        kind, back = links.parse_link(profile.share_url())
        assert kind == profile.kind
        for field in type(profile).__dataclass_fields__:
            want = getattr(profile, field)
            if field in ("tag", "title"):
                continue
            got = getattr(back, field, None)
            assert got == want, "%s.%s: %r != %r" % (
                type(profile).__name__, field, got, want)


class TestStoreIntegration:
    """Import center -> store -> profile -> engine config round trip."""

    def test_full_pipeline(self, tmp_path):
        store = profiles.ProfileStore(str(tmp_path / "profiles.json"))
        center = __import__(
            "proto_clean.vpn.protocols.importers",
            fromlist=["ImportCenter"]).ImportCenter(store)

        summary = center.import_text(
            "hysteria2://auth@h.io:443/?sni=h.io&insecure=1#hy\n"
            "vmess://" + base64.b64encode(json.dumps(
                {"v": "2", "add": "v.io", "port": "443",
                 "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                 "net": "ws", "tls": "tls"}).encode()).decode())
        assert summary.ok and len(summary.added) == 2

        # every stored profile builds an engine config through box
        for entry in store.all():
            prof = entry.profile()
            assert prof is not None, entry.url
            cfg = boxproto.build_box_config(entry.kind, prof, 10800)
            assert cfg["inbounds"][0]["listen_port"] == 10800

        # re-import dedupes
        summary2 = center.import_text(
            "hysteria2://auth@h.io:443/?sni=h.io&insecure=1#hy")
        assert len(summary2.added) == 1
        assert store.count() == 2

    def test_subscription_pipeline(self, tmp_path, monkeypatch):
        import httpx
        from proto_clean.vpn.protocols import importers

        blob = base64.b64encode(
            b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#sub\n").decode()

        def handler(request):
            return httpx.Response(200, text=blob)

        monkeypatch.setattr(
            httpx.Client, "get",
            lambda self, url, **kw: httpx.Response(
                200, text=blob))
        got = importers.fetch_subscription("https://sub.example.com/x")
        assert len(got) == 1
        assert isinstance(got[0], M.ShadowsocksProfile)
