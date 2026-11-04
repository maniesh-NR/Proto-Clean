"""Tests for Clash / V2ray / sing-box conversion, WARP and chains."""

from __future__ import annotations

import base64
import json

import pytest

from proto_clean.vpn.protocols import convert, links, models as M, warp
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.xrayconf import XrayProfile

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


CLASH_YAML = """
port: 7890
proxies:
  - name: "ss-one"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass1
  - name: "vmess-ws"
    type: vmess
    server: vm.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: cdn.example.com
    ws-opts:
      path: /ws
      headers: {Host: cdn.example.com}
  - name: "hy2"
    type: hysteria2
    server: hy.example.com
    port: 443
    password: authpass
    sni: hy.example.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: obfspass
  - name: "trojan"
    type: trojan
    server: tj.example.com
    port: 443
    password: tjpass
    sni: tj.example.com
  - name: "tuic"
    type: tuic
    server: tu.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: tuicpass
    congestion-controller: bbr
    alpn: [h3]
  - name: "unknown-type"
    type: nonsense
    server: x
    port: 1
"""


@pytest.mark.skipif(not HAVE_YAML, reason="PyYAML not installed")
class TestClash:
    def test_clash_yaml_conversion(self):
        profiles = convert.parse_clash_yaml(CLASH_YAML)
        kinds = [type(p).__name__ for p in profiles]
        assert "ShadowsocksProfile" in kinds
        assert "VmessProfile" in kinds
        assert "Hysteria2Profile" in kinds
        assert "XrayProfile" in kinds          # trojan
        assert "TuicProfile" in kinds
        # unknown types are skipped, never fatal
        assert len(profiles) == 5

    def test_clash_vmess_fields(self):
        profiles = convert.parse_clash_yaml(CLASH_YAML)
        vmess = [p for p in profiles if isinstance(p, M.VmessProfile)][0]
        assert vmess.server == "vm.example.com"
        assert vmess.transport == "ws"
        assert vmess.path == "/ws"
        assert vmess.host == "cdn.example.com"
        assert vmess.tls is True
        assert vmess.sni == "cdn.example.com"
        assert vmess.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"

    def test_clash_hysteria2_fields(self):
        profiles = convert.parse_clash_yaml(CLASH_YAML)
        hy2 = [p for p in profiles if isinstance(p, M.Hysteria2Profile)][0]
        assert hy2.auth == "authpass"
        assert hy2.obfs == "salamander"
        assert hy2.obfs_password == "obfspass"
        assert hy2.insecure is True

    def test_clash_proxies_errors_are_skipped(self):
        out = convert.clash_proxies_to_profiles(
            [{"name": "bad", "type": "ss", "server": "x"},   # missing port
             {"name": "ok", "type": "ss", "server": "x", "port": 1,
              "cipher": "aes-256-gcm", "password": "p"}])
        assert len(out) == 1 and out[0].server == "x"

    def test_clash_install_link(self):
        sub, profiles = convert.parse_clash_link(
            "clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub")
        assert sub == "https://example.com/sub"
        assert profiles == []
        with pytest.raises(ProtocolError):
            convert.parse_clash_link("clash://install-config")


V2RAY_JSON = json.dumps({
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "vmess-out", "protocol": "vmess",
         "settings": {"vnext": [{
             "address": "v.example.com", "port": 443,
             "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "alterId": 0, "security": "auto"}]}]},
         "streamSettings": {"network": "ws", "security": "tls",
                            "tlsSettings": {"serverName": "v.example.com"},
                            "wsSettings": {"path": "/v",
                                           "headers": {"Host": "v.example.com"}}}},
        {"tag": "ss-out", "protocol": "shadowsocks",
         "settings": {"servers": [{"address": "s.example.com", "port": 8388,
                                   "method": "chacha20-ietf-poly1305",
                                   "password": "sspass"}]}},
    ]
})


class TestV2ray:
    def test_v2ray_json_conversion(self):
        profiles = convert.parse_v2ray_json(V2RAY_JSON)
        assert len(profiles) == 2               # freedom is skipped
        vmess = [p for p in profiles if isinstance(p, M.VmessProfile)][0]
        assert vmess.server == "v.example.com"
        assert vmess.transport == "ws" and vmess.path == "/v"
        assert vmess.tls and vmess.sni == "v.example.com"
        ss = [p for p in profiles if isinstance(p, M.ShadowsocksProfile)][0]
        assert ss.method == "chacha20-ietf-poly1305"

    def test_v2ray_no_outbounds(self):
        with pytest.raises(ProtocolError):
            convert.parse_v2ray_json(json.dumps({"outbounds": []}))
        with pytest.raises(ProtocolError):
            convert.parse_v2ray_json("not json")


SINGBOX_JSON = json.dumps({
    "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                  "listen_port": 1080}],
    "outbounds": [
        {"type": "selector", "tag": "pick"},
        {"type": "vmess", "tag": "vm", "server": "v.example.com",
         "server_port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
         "transport": {"type": "grpc", "service_name": "svc"},
         "tls": {"enabled": True, "server_name": "v.example.com"}},
        {"type": "hysteria2", "tag": "hy", "server": "h.example.com",
         "server_port": 443, "password": "pw",
         "obfs": {"type": "salamander", "password": "ob"}},
        {"type": "direct", "tag": "direct"},
    ],
})


class TestSingbox:
    def test_singbox_conversion(self):
        profiles = convert.parse_singbox_json(SINGBOX_JSON)
        kinds = [type(p).__name__ for p in profiles]
        assert "VmessProfile" in kinds and "Hysteria2Profile" in kinds
        vmess = [p for p in profiles if isinstance(p, M.VmessProfile)][0]
        assert vmess.transport == "grpc" and vmess.path == "svc"
        assert vmess.tls is True

    def test_singbox_raw_passthrough(self):
        profiles = convert.parse_singbox_json(SINGBOX_JSON,
                                              raw_passthrough=True)
        assert len(profiles) == 1
        assert isinstance(profiles[0], M.BoxRawProfile)
        assert json.loads(profiles[0].config_json)["outbounds"][1]["tag"] == "vm"

    def test_singbox_unconvertible_falls_back_to_raw(self):
        text = json.dumps({"outbounds": [{"type": "mieru", "tag": "x"}]})
        profiles = convert.parse_singbox_json(text)
        assert len(profiles) == 1
        assert isinstance(profiles[0], M.BoxRawProfile)


class TestSubscriptions:
    def test_base64_subscription(self):
        links_text = ("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#one\n"
                      "trojan://pw@t.example.com:443?sni=t.example.com#two")
        blob = base64.b64encode(links_text.encode()).decode()
        profiles = convert.decode_subscription(blob)
        assert len(profiles) == 2
        assert isinstance(profiles[0], M.ShadowsocksProfile)
        assert isinstance(profiles[1], XrayProfile)

    def test_plain_links_subscription(self):
        text = ("hysteria2://auth@h.example.com:443/?sni=h.example.com\n"
                "# a comment line\n")
        profiles = convert.decode_subscription(text)
        assert len(profiles) == 1
        assert isinstance(profiles[0], M.Hysteria2Profile)

    def test_singbox_json_subscription_autodetect(self):
        profiles = convert.decode_subscription(SINGBOX_JSON)
        assert profiles and isinstance(profiles[0], (M.VmessProfile,
                                                     M.BoxRawProfile))

    def test_empty(self):
        assert convert.decode_subscription("") == []
        assert convert.decode_subscription("# only comments\n") == []


class TestWarp:
    def test_keypair_shape(self):
        priv, pub = warp.generate_keypair()
        assert len(base64.b64decode(priv)) == 32
        assert len(base64.b64decode(pub)) == 32

    def test_reserved_from_client_id(self):
        assert warp.reserved_from_client_id(base64.b64encode(
            bytes([1, 2, 3, 4])).decode()) == (1, 2, 3)
        with pytest.raises(ProtocolError):
            warp.reserved_from_client_id("!!!")

    def test_register_roundtrip(self):
        import httpx

        prof = warp.new_profile()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/reg")
            assert request.headers["CF-Client-Version"]
            body = json.loads(request.content)
            assert len(base64.b64decode(body["key"])) == 32
            return httpx.Response(200, json={
                "id": "dev-1", "token": "tok",
                "config": {
                    "client_id": base64.b64encode(bytes(range(16))).decode(),
                    "interface": {"addresses": {
                        "v4": "172.16.0.2/32", "v6": "fd01::2/128"}},
                    "peers": [{"public_key": "PEERPUB",
                               "endpoint": {"v4": "engage:2408"}}]}})

        warp.register(prof, client=httpx.Client(
            transport=httpx.MockTransport(handler)))
        assert prof.private_key and prof.peer_public_key == "PEERPUB"
        assert prof.device_id == "dev-1"
        assert prof.address_v4 == "172.16.0.2/32"
        # reserved = first three bytes of client_id
        assert warp.reserved_from_client_id(prof.client_id_b64) == (0, 1, 2)
        # cached: a second register call must not hit the API
        warp.register(prof, client=httpx.Client(transport=httpx.MockTransport(
            lambda r: pytest.fail("should not re-register"))))

    def test_register_http_error(self):
        import httpx
        prof = warp.new_profile()
        with pytest.raises(ProtocolError):
            warp.register(prof, client=httpx.Client(transport=httpx.MockTransport(
                lambda r: httpx.Response(403, json={"error": "no"}))))

    def test_warp_box_config_before(self):
        prof = M.WarpProfile(private_key="AAA=", peer_public_key="BBB=",
                             client_id_b64=base64.b64encode(
                                 bytes([9, 8, 7])).decode(),
                             address_v4="172.16.0.2/32",
                             address_v6="fd01::2/128")
        cfg = warp.build_warp_box_config(prof, 10800)
        assert cfg["endpoints"][0]["type"] == "wireguard"
        assert cfg["endpoints"][0]["peers"][0]["reserved"] == [9, 8, 7]
        assert cfg["endpoints"][0]["address"] == ["172.16.0.2/32",
                                                  "fd01::2/128"]
        assert cfg["route"]["rules"][0]["endpoint"] == "warp-ep"

    def test_warp_box_config_after(self):
        prof = M.WarpProfile(private_key="AAA=", peer_public_key="BBB=",
                             client_id_b64="Q0JDQg==",
                             address_v4="172.16.0.2/32")
        cfg = warp.build_warp_box_config(prof, 10800,
                                         upstream=("127.0.0.1", 9999))
        wg = [o for o in cfg["outbounds"] if o.get("type") == "wireguard"][0]
        assert wg["detour"] == "upstream"
        assert cfg["route"]["rules"][0]["outbound"] == "warp-out"

    def test_chain_presets(self):
        url = warp.warp_before_chain_url("hysteria2://a@b.c:443")
        kind, prof = links.parse_link(url)
        assert kind == "chain" and len(prof.hops) == 2
        assert prof.hops[0].startswith("warp://")
        assert prof.hops[1].startswith("hysteria2://")
        url = warp.warp_after_chain_url("hysteria2://a@b.c:443")
        _kind, prof = links.parse_link(url)
        assert prof.hops[1].startswith("warp://")


class TestVmessLinks:
    def test_vmess_roundtrip_all_fields(self):
        p = M.VmessProfile(server="v.example.com", port=2053,
                           uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
                           alter_id=0, security="chacha20-poly1305",
                           transport="grpc", host="grpc.example.com",
                           path="svc", tls=True, sni="s.example.com",
                           fp="firefox", tag="my vmess")
        kind, back = links.parse_link(p.share_url())
        assert kind == "vmess"
        assert back.server == p.server and back.port == 2053
        assert back.uuid == p.uuid and back.security == p.security
        assert back.transport == "grpc" and back.path == "svc"
        assert back.tls and back.sni == p.sni and back.fp == "firefox"
        assert back.tag == "my vmess"
