"""Tests for the Obscura relay client + engine.

The HTTP layer runs on ``httpx.MockTransport`` (patched onto
``httpx.Client``); the engine lifecycle runs on a stub ``TunnelManager`` —
no network, no wg-quick, no privileged helper is ever touched.
"""

import base64
import json as _json

import httpx
import pytest

import proto_clean
from proto_clean.vpn.protocols import obscura as OB
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.models import ObscuraProfile
from proto_clean.vpn.wgconf import WgQuickConf

ACCOUNT = "1234567890ABCDEFghij"          # 20-char account number
TOKEN = "tok-1234567890"
PRIV_B64 = base64.b64encode(bytes(range(32))).decode()
EXIT_PUB_B64 = base64.b64encode(bytes(range(32, 64))).decode()

RELAY = {"id": "NYC-001", "country_code": "US", "city_code": "NYC",
         "city_name": "New York", "ip_v4": "8.8.31.3",
         "ip_v6": "2607:8700:5400::1",
         "preferred_exits": [{"id": "NYC-001"}, {"id": "LON-001"}],
         "tls_cert": "-----BEGIN CERTIFICATE-----", "ports": [53, 443]}
RELAY_LON = dict(RELAY, id="LON-001", country_code="GB", city_code="LON",
                 city_name="London", ip_v4="8.8.44.3")
EXIT_NYC = {"id": "NYC-001", "country_code": "US"}
EXIT_LON = {"id": "LON-001", "country_code": "GB"}

GOLDEN_UDP = (
    "# Proto Clean: Obscura tunnel tn-1\n"
    "# tunnel type: udp_port\n"
    "[Interface]\n"
    "PrivateKey = " + PRIV_B64 + "\n"
    "Address = 10.130.0.2/32, fd00:2021:1113::2/128\n"
    "DNS = 10.64.0.1\n"
    "\n"
    "[Peer]\n"
    "PublicKey = " + EXIT_PUB_B64 + "\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = 8.8.31.3:443\n"
    "PersistentKeepalive = 25\n"
)


def _one_tunnel(body, tid):
    """OneTunnel document in the shape the API returns."""
    body = body or {}
    return {
        "id": tid,
        "status": {"type": "Pending", "when": 1735689600},
        "config": {
            "type": body.get("type", "udp_port"),
            "client_pubkey": body.get("wg_pubkey", ""),
            "client_ips_v4": ["10.130.0.2/32"],
            "client_ips_v6": ["fd00:2021:1113::2/128"],
            "dns": ["10.64.0.1"],
            "gateway_ip_v4": "10.130.0.1",
            "relay_addr_v4": "8.8.31.3:443",
            "relay_addr_v6": "[2607:8700:5400::1]:443",
            "relay_cert": "relay-cert-bytes",
            "exit_pubkey": EXIT_PUB_B64,
        },
        "relay": dict(RELAY),
        "exit": dict(EXIT_LON),
    }


class FakeApi:
    """In-memory Obscura API with request recording."""

    def __init__(self):
        self.requests = []          # (method, path, body-dict, headers-dict)
        self.tunnels = []
        self.fail = None            # (status, text-or-json-dict) while set
        self.seq = 0                # monotonic tunnel-id counter

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = None
        if request.content:
            try:
                body = _json.loads(request.content.decode("utf-8"))
            except ValueError:
                body = None
        headers = {k: v for k, v in request.headers.items()}
        self.requests.append((request.method, path, body, headers))
        if self.fail is not None:
            status, payload = self.fail
            if isinstance(payload, dict):
                return httpx.Response(status, json=payload)
            return httpx.Response(status, text=payload)
        if request.method == "POST" and path.endswith("/auth"):
            if not isinstance(body, dict) \
                    or body.get("account_no") != ACCOUNT:
                return httpx.Response(
                    401, json={"message": "unknown account number"})
            return httpx.Response(200, json={"auth_token": TOKEN})
        if headers.get("authorization") != "Bearer " + TOKEN:
            return httpx.Response(403,
                                  json={"message": "missing or invalid token"})
        if request.method == "GET" and path.endswith("/tunnel"):
            return httpx.Response(200, json=list(self.tunnels))
        if request.method == "POST" and path.endswith("/tunnel"):
            self.seq += 1
            tid = "tn-%d" % self.seq
            tunnel = _one_tunnel(body, tid)
            self.tunnels.append(tunnel)
            return httpx.Response(200, json=tunnel)
        if request.method == "DELETE" and "/tunnel/" in path:
            tid = path.rsplit("/", 1)[-1]
            self.tunnels = [t for t in self.tunnels if t.get("id") != tid]
            return httpx.Response(200, json={"deleted": tid})
        return httpx.Response(404, text="unknown command")

    # -- helpers ---------------------------------------------------------
    def count(self, method, path_suffix):
        return sum(1 for m, p, _b, _h in self.requests
                   if m == method and p.endswith(path_suffix))

    def count_delete(self):
        return sum(1 for m, p, _b, _h in self.requests
                   if m == "DELETE" and "/tunnel/" in p)


@pytest.fixture()
def api(monkeypatch):
    """Patch httpx.Client so every request goes through the fake API."""
    fake = FakeApi()
    transport = httpx.MockTransport(fake.handler)
    real_client = httpx.Client

    def patched_client(**kwargs):
        kwargs["transport"] = transport
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", patched_client)
    return fake


def _profile(**kw):
    d = dict(account_id=ACCOUNT, relay="NYC-001", exit="LON-001")
    d.update(kw)
    return ObscuraProfile(**d)


# ---------------------------------------------------------------- client
def test_user_agent_header(api):
    c = OB.ObscuraClient(_profile())
    c.auth_token()
    method, path, _body, headers = api.requests[0]
    assert (method, path) == ("POST", "/api/auth")
    assert headers.get("user-agent") == \
        "ProtoClean/%s (obscura client)" % proto_clean.__version__


def test_auth_token_exchanges_account_and_caches(api):
    prof = _profile()
    c = OB.ObscuraClient(prof)
    assert c.auth_token() == TOKEN
    assert prof.auth_token == TOKEN
    method, path, body, _headers = api.requests[0]
    assert (method, path) == ("POST", "/api/auth")
    assert body == {"account_no": ACCOUNT}
    assert api.count("POST", "/auth") == 1
    assert c.auth_token() == TOKEN              # served from the profile cache
    assert api.count("POST", "/auth") == 1


def test_auth_unknown_account_raises_api_message(api):
    c = OB.ObscuraClient(_profile(account_id="X" * 20))
    with pytest.raises(ProtocolError) as ei:
        c.auth_token()
    assert "unknown account number" in str(ei.value)


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_statuses_raise(api, status):
    api.fail = (status, {"message": "account locked"})
    c = OB.ObscuraClient(_profile())
    with pytest.raises(ProtocolError) as ei:
        c.auth_token()
    assert "account locked" in str(ei.value)


def test_create_tunnel_posts_keypair_and_caches(api):
    prof = _profile()
    c = OB.ObscuraClient(prof)
    tunnel = c.create_tunnel()
    assert api.count("POST", "/auth") == 1      # auto-auth first
    assert api.count("POST", "/tunnel") == 1
    method, path, body, headers = api.requests[-1]
    assert (method, path) == ("POST", "/api/tunnel")
    assert headers.get("authorization") == "Bearer " + TOKEN
    assert body["type"] == "udp_port"           # from profile.tunnel_type
    assert body["relay"] == "NYC-001" and body["exit"] == "LON-001"
    assert body["label"] is None
    pub = base64.b64decode(body["wg_pubkey"])
    assert len(pub) == 32                       # wg_pubkey is 32 bytes, b64
    # the posted public key is derived from the (clamped) cached private key
    priv = base64.b64decode(c.private_key_b64)
    assert priv[0] & 0x07 == 0 and priv[31] & 0x80 == 0 \
        and priv[31] & 0x40 == 0x40
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    derived = X25519PrivateKey.from_private_bytes(priv) \
        .public_key().public_bytes_raw()
    assert derived == pub
    # response + profile caches
    assert tunnel["id"] == "tn-1"
    assert tunnel["config"]["client_pubkey"] == body["wg_pubkey"]
    assert prof.tunnel_id == "tn-1"
    conf = WgQuickConf.parse(prof.wg_conf)      # cached config is a valid conf
    assert conf.interface["PrivateKey"] == [c.private_key_b64]
    assert conf.peer["PublicKey"] == [EXIT_PUB_B64]


def test_create_tunnel_overrides(api):
    c = OB.ObscuraClient(_profile())
    c.create_tunnel(relay="LON-001", exit="LON-001", tunnel_type="obfuscated")
    _m, _p, body, _h = api.requests[-1]
    assert body["relay"] == "LON-001" and body["exit"] == "LON-001"
    assert body["type"] == "obfuscated"


def test_list_tunnels(api):
    api.tunnels = [_one_tunnel({}, "tn-1"), _one_tunnel({}, "tn-2")]
    c = OB.ObscuraClient(_profile())
    assert [t["id"] for t in c.list_tunnels()] == ["tn-1", "tn-2"]


def test_list_relays_derived_from_tunnels(api):
    t1 = _one_tunnel({}, "tn-1")                            # relay NYC-001
    t2 = _one_tunnel({}, "tn-2")
    t2["relay"], t2["exit"] = dict(RELAY_LON), dict(EXIT_NYC)
    t3 = _one_tunnel({}, "tn-3")                            # NYC again (dup)
    api.tunnels = [t1, t2, t3]
    c = OB.ObscuraClient(_profile())
    relays = c.list_relays()
    assert [r["id"] for r in relays] == ["NYC-001", "LON-001"]
    assert relays[0]["country_code"] == "US"
    assert relays[0]["city_name"] == "New York"
    assert relays[0]["preferred_exits"] == ["NYC-001", "LON-001"]
    assert relays[1]["country_code"] == "GB"
    assert relays[1]["city_name"] == "London"
    # explicit tunnels argument skips the API entirely
    relays2 = c.list_relays(tunnels=[t2])
    assert [r["id"] for r in relays2] == ["LON-001"]
    assert api.count("GET", "/tunnel") == 1


def test_delete_tunnel_forgets_profile_tunnel_id(api):
    api.tunnels = [_one_tunnel({}, "tn-1"), _one_tunnel({}, "tn-2")]
    prof = _profile()
    prof.tunnel_id = "tn-1"
    c = OB.ObscuraClient(prof)
    c.delete_tunnel("tn-1")
    assert [t["id"] for t in api.tunnels] == ["tn-2"]
    assert prof.tunnel_id == ""
    assert api.count_delete() == 1


def test_delete_all_removes_every_tunnel(api):
    api.tunnels = [_one_tunnel({}, "tn-1"), _one_tunnel({}, "tn-2")]
    c = OB.ObscuraClient(_profile())
    c.delete_all()
    assert api.tunnels == []
    assert api.count_delete() == 2


def test_error_non_2xx_truncates_response_text(api):
    prof = _profile()
    prof.auth_token = TOKEN                     # skip auth — error on GET
    api.fail = (503, "E" * 500)
    c = OB.ObscuraClient(prof)
    with pytest.raises(ProtocolError) as ei:
        c.list_tunnels()
    msg = str(ei.value)
    assert "503" in msg
    assert "E" * 200 in msg                     # truncated to 200 chars
    assert "E" * 201 not in msg


# ------------------------------------------------------- build_wg_config
def _tunnel(tid="tn-1", ttype="udp_port"):
    return _one_tunnel({"type": ttype}, tid)


def test_build_wg_config_golden_udp_port():
    c = OB.ObscuraClient(_profile())
    conf = c.build_wg_config(_tunnel(), PRIV_B64)
    assert conf == GOLDEN_UDP
    WgQuickConf.parse(conf)                     # valid wg-quick config
    parsed = WgQuickConf.parse(conf)
    assert [a.strip() for a in parsed.addresses] == \
        ["10.130.0.2/32", "fd00:2021:1113::2/128"]
    assert parsed.dns == "10.64.0.1"
    assert parsed.endpoint == "8.8.31.3:443"    # v4 preferred


def test_build_wg_config_v6_endpoint_when_no_v4():
    c = OB.ObscuraClient(_profile())
    t = _tunnel()
    t["config"]["relay_addr_v4"] = ""
    conf = c.build_wg_config(t, PRIV_B64)
    endpoint = [l for l in conf.splitlines()
                if l.startswith("Endpoint")][0]
    assert endpoint == "Endpoint = [2607:8700:5400::1]:443"


def test_build_wg_config_obfuscated_note():
    c = OB.ObscuraClient(_profile())
    conf = c.build_wg_config(_tunnel(ttype="obfuscated"), PRIV_B64)
    assert "# tunnel type: obfuscated" in conf
    assert "obscura client binary" in conf      # needs the official client
    WgQuickConf.parse(conf)                     # comments ignored by the parser


# ---------------------------------------------------------------- engine
class StubTunnelManager:
    """Captures the config text; replaces proto_clean TunnelManager."""

    instances = []
    hs_ok = True
    up_error = None

    def __init__(self, helper=None):
        self.helper = helper
        self.up_calls = []
        self.down_calls = 0
        self.hs_timeouts = []
        StubTunnelManager.instances.append(self)

    def up(self, config_text, **kw):
        if StubTunnelManager.up_error is not None:
            raise RuntimeError(StubTunnelManager.up_error)
        self.up_calls.append(config_text)
        return {"protocol": "wireguard"}

    def wait_handshake(self, timeout=20.0, poll=1.5):
        self.hs_timeouts.append(timeout)
        return StubTunnelManager.hs_ok

    def down(self, **kw):
        self.down_calls += 1


def test_engine_metadata_and_factory():
    e = OB.engine(_profile())
    assert isinstance(e, OB.ObscuraEngine)
    assert e.proxy_kind == "obscura"
    assert e.family == "tunnel"
    assert e.exposes == "tunnel"
    assert e.binary_name == ""
    assert e.running is False


def test_engine_requires_account_id(api):
    prof = _profile(account_id="")
    e = OB.engine(prof)
    with pytest.raises(ProtocolError) as ei:
        e.start(prof, timeout=10)
    assert "account" in str(ei.value)
    assert e.running is False
    assert api.requests == []                   # nothing sent


def test_engine_start_writes_conf_up_and_stop_down(api, monkeypatch, tmp_path):
    monkeypatch.setattr(OB, "TunnelManager", StubTunnelManager)
    monkeypatch.setattr(OB, "CONFIG_DIR", tmp_path)
    prof = _profile()
    e = OB.engine(prof)
    e.start(prof, timeout=10)
    assert e.running is True
    assert prof.tunnel_id == "tn-1"
    # the conf was written to CONFIG_DIR/obscura/<tunnel_id>.conf
    conf_path = tmp_path / "obscura" / "tn-1.conf"
    assert conf_path.is_file()
    on_disk = conf_path.read_text(encoding="utf-8")
    assert on_disk == prof.wg_conf
    # the stub manager brought exactly that config up and waited for a handshake
    mgr = StubTunnelManager.instances[-1]
    assert mgr.up_calls == [prof.wg_conf]
    assert mgr.hs_timeouts and mgr.hs_timeouts[0] >= 5.0
    st = e.status()
    assert st["kind"] == "obscura" and st["running"] is True
    assert st["tool"] == "wireguard"
    assert st["relay"] == "NYC-001" and st["exit"] == "LON-001"
    assert st["tunnel_id"] == "tn-1"
    e.stop()
    assert mgr.down_calls == 1
    assert e.running is False
    # server-side tunnel deliberately kept (idle tunnels are not auto-removed)
    assert all(m != "DELETE" for m, _p, _b, _h in api.requests)


def test_engine_reuses_cached_tunnel(api, monkeypatch, tmp_path):
    monkeypatch.setattr(OB, "TunnelManager", StubTunnelManager)
    monkeypatch.setattr(OB, "CONFIG_DIR", tmp_path)
    prof = _profile()
    e = OB.engine(prof)
    e.start(prof, timeout=10)
    e.stop()
    posts, auths = api.count("POST", "/tunnel"), api.count("POST", "/auth")
    assert (posts, auths) == (1, 1)
    e2 = OB.engine(prof)                        # same profile: tunnel_id + wg_conf
    e2.start(prof, timeout=10)
    assert api.count("POST", "/tunnel") == posts    # no new tunnel created
    assert api.count("POST", "/auth") == auths      # token reused
    assert api.count("GET", "/tunnel") >= 1         # reuse verified via list
    e2.stop()


def test_engine_recreates_deleted_tunnel(api, monkeypatch, tmp_path):
    monkeypatch.setattr(OB, "TunnelManager", StubTunnelManager)
    monkeypatch.setattr(OB, "CONFIG_DIR", tmp_path)
    prof = _profile()
    e = OB.engine(prof)
    e.start(prof, timeout=10)
    e.stop()
    api.tunnels = []                            # tunnel vanished server-side
    e2 = OB.engine(prof)
    e2.start(prof, timeout=10)
    assert api.count("POST", "/tunnel") == 2    # fresh tunnel was created
    assert prof.tunnel_id == "tn-2"
    e2.stop()


def test_engine_handshake_failure_tears_down(api, monkeypatch, tmp_path):
    monkeypatch.setattr(OB, "TunnelManager", StubTunnelManager)
    monkeypatch.setattr(OB, "CONFIG_DIR", tmp_path)
    StubTunnelManager.hs_ok = False
    try:
        prof = _profile()
        e = OB.engine(prof)
        with pytest.raises(ProtocolError) as ei:
            e.start(prof, timeout=10)
        assert "handshake" in str(ei.value)
        mgr = StubTunnelManager.instances[-1]
        assert mgr.down_calls == 1              # torn down, nothing left up
        assert e.running is False
    finally:
        StubTunnelManager.hs_ok = True


def test_engine_up_failure_surfaces_and_tears_down(api, monkeypatch, tmp_path):
    monkeypatch.setattr(OB, "TunnelManager", StubTunnelManager)
    monkeypatch.setattr(OB, "CONFIG_DIR", tmp_path)
    StubTunnelManager.up_error = "helper exploded"
    try:
        prof = _profile()
        e = OB.engine(prof)
        with pytest.raises(ProtocolError) as ei:
            e.start(prof, timeout=10)
        assert "helper exploded" in str(ei.value)
        mgr = StubTunnelManager.instances[-1]
        assert mgr.down_calls == 1
        assert e.running is False
    finally:
        StubTunnelManager.up_error = None
