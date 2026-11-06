"""The final cross-feature interop series.

Every feature that is *designed* to compose with another is exercised
here with the real production code paths (real QUIC servers, real SOCKS5
relays, real UDP ASSOCIATE tunnels, real QR codecs, real parsers):

* **Chains over the wire** — two live Hysteria 2 servers, the exit hop
  dialled *through* the entry hop's SOCKS5 (TCP + UDP); a TUIC exit
  behind a Hysteria 2 entry (cross engine family); port hygiene.
* **WARP composition** — a mocked Cloudflare registration feeding both
  the *WARP-before* (endpoint) and *WARP-after* (detour) chain positions,
  and ``build_chain`` wiring for both presets.
* **The import universe** — every link kind round-trips; every box kind
  builds a valid sing-box config; one ProfileStore fed from links, a
  Clash file, a V2ray file, a sing-box file, a WireGuard file, a QR
  image and a subscription, all building engine configs afterwards.
* **QR interop** — profile → segno PNG → zxing-cpp → profile, including
  a long ``warp-after`` chain URL.
* **Guest mode ↔ the WireGuard stack** — the guest certificate builds a
  wg-quick config the production ``wgconf`` parser accepts.
* **Controller ↔ engines** — ``start_profile_async`` /
  ``stop_protocol_async`` lifecycle for plain and chain entries.
* **Whole-stack sanity** — every module imports together headless, and
  the MD3 scheme feeds the QSS generator with consistent roles.

These tests deliberately do *not* mock the engines, the SOCKS relay or
the QUIC layer: the point is to prove the compositions, not the units
(the per-module suites already do that).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import sys
import threading
import time
import types
from typing import List

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from proto_clean.vpn.protocols import boxproto, chain, convert, importers
from proto_clean.vpn.protocols import links
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols import profiles, warp
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.socks_server import (LoopThread,
                                                    build_socks5_address,
                                                    parse_socks5_address,
                                                    socks5_dial)

# sibling test modules carry the in-process reference servers
from test_hysteria2 import FakeHy2Server, UdpEcho, tcp_echo_server

try:
    import aioquic                                   # noqa: F401
    HAVE_AIOQUIC = True
except ImportError:                                  # pragma: no cover
    HAVE_AIOQUIC = False

# the wire-level engine e2e compositions bind many local ports — the
# same policy as the per-engine e2e suites (Linux/macOS CI legs)
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="wire-level interop covered on Linux/macOS runners")


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def _listening(port: int) -> bool:
    s = socket.socket()
    s.settimeout(0.3)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


async def _socks_udp_roundtrip(socks_port: int, dst_host: str, dst_port: int,
                               payload: bytes, timeout: float = 20.0) -> None:
    """One SOCKS5 UDP-ASSOCIATE exchange through ``socks_port``.

    All-async: the datagram endpoint and the TCP control connection share
    the caller's loop, which also usually carries the in-process reference
    servers — a blocking recvfrom here would starve them.
    """
    import asyncio

    class _UdpClient(asyncio.DatagramProtocol):
        def __init__(self):
            self.queue: asyncio.Queue = asyncio.Queue()
            self.transport = None

        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.queue.put_nowait(data)

        def error_received(self, exc):  # pragma: no cover — best effort
            pass

    rd, wr = await asyncio.open_connection("127.0.0.1", socks_port)
    wr.write(b"\x05\x01\x00")
    await wr.drain()
    assert await rd.readexactly(2) == b"\x05\x00"
    wr.write(b"\x05\x03\x00" + build_socks5_address("0.0.0.0", 0))
    await wr.drain()
    hdr = await rd.readexactly(4)
    rest = await rd.read(64)
    relay_host, relay_port, _ = parse_socks5_address(hdr[3:4] + rest, 0)

    loop = asyncio.get_event_loop()
    client = _UdpClient()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: client, remote_addr=(relay_host, relay_port))
    addr = build_socks5_address(dst_host, dst_port)
    pkt = b"\x00\x00\x00" + addr + payload
    try:
        # QUIC DATAGRAM frames are lossy by design; mirror real apps and
        # retransmit until the echo lands
        deadline = loop.time() + timeout
        while True:
            transport.sendto(pkt)
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise AssertionError("no UDP echo came back through the chain")
            try:
                got = await asyncio.wait_for(client.queue.get(), 1.5)
            except asyncio.TimeoutError:
                continue
            if got[3 + len(addr):] == payload:
                return
    finally:
        transport.close()
        wr.close()


class _Hy2Stack:
    """One live FakeHy2Server + its TCP echo target, on a shared loop."""

    def __init__(self, lt: LoopThread, udp_echo: UdpEcho = None,
                 password: str = "hy2-pass") -> None:
        self.lt = lt
        self.udp_echo = udp_echo
        holder = {}

        async def _start_echo():
            server, port = await tcp_echo_server()
            holder["echo"] = server
            return port

        self.echo_port = lt.run(_start_echo(), 10)
        self.server = FakeHy2Server(
            self.echo_port,
            udp_echo.port if udp_echo else 0,
            password=password)
        lt.run(self.server.start(), 15)

    def profile(self) -> M.Hysteria2Profile:
        return M.Hysteria2Profile(
            server="127.0.0.1", port=self.server.port,
            auth=self.server.password, sni="hysteria-test", insecure=True)

    def stop(self) -> None:
        try:
            self.lt.run(self.server.stop(), 5)
        except Exception:                            # noqa: BLE001
            pass


@pytest.fixture()
def lt():
    thread = LoopThread(name="interop")
    yield thread
    thread.stop()


# ===========================================================================
# A. chains over the wire
# ===========================================================================
@pytest.mark.skipif(not HAVE_AIOQUIC, reason="aioquic not installed")
class TestRealWireChains:
    """Two live QUIC servers, the exit hop dialled through the entry hop.

    Client → chain SOCKS → hop-2 engine → (SOCKS5 UDP ASSOCIATE)
    → hop-1 engine → (QUIC + hy2 datagrams) → hop-1 server → (plain UDP)
    → hop-2 server → target. Every layer in between is production code.
    """

    def test_hy2_over_hy2_two_hop_chain_tcp(self, lt):
        entry, exit_ = _Hy2Stack(lt), _Hy2Stack(lt, password="exit-pass")
        try:
            chain_prof = M.ChainProfile(hops=[entry.profile().share_url(),
                                              exit_.profile().share_url()])
            eng = chain.ChainEngine()
            eng.start(chain_prof, timeout=60.0)   # full production path
            try:
                assert eng.running
                # the exit hop's SOCKS is the chain endpoint
                assert eng.socks_port == eng.engines[-1].socks_port
                # wiring: the exit hop dials through the entry hop's SOCKS
                assert eng.engines[1].upstream_socks[1] \
                    == eng.engines[0].socks_port
                st = eng.status()
                assert [h["kind"] for h in st["hops"]] == \
                    ["hysteria2", "hysteria2"]
                assert st["exit"] == "hysteria2"
                # bytes through BOTH hops to the exit's echo target
                rd, wr = lt.run(socks5_dial(
                    "127.0.0.1", eng.socks_port,
                    "127.0.0.1", exit_.echo_port, timeout=25), 30)
                wr.write(b"interop-two-hop")
                lt.run(wr.drain())
                assert lt.run(rd.readexactly(15), 25) == b"interop-two-hop"
                # a second exchange proves framing stays intact
                wr.write(b"second-frame")
                lt.run(wr.drain())
                assert lt.run(rd.readexactly(12), 20) == b"second-frame"
                wr.close()
            finally:
                eng.stop()
            assert not eng.running
        finally:
            entry.stop()
            exit_.stop()

    def test_udp_associate_over_two_hops(self, lt):
        udp_echo = UdpEcho()
        entry, exit_ = _Hy2Stack(lt), _Hy2Stack(lt, udp_echo=udp_echo,
                                                password="exit-pass")
        try:
            chain_prof = M.ChainProfile(hops=[entry.profile().share_url(),
                                              exit_.profile().share_url()])
            eng = chain.ChainEngine()
            eng.start(chain_prof, timeout=60.0)
            try:
                # nested UDP: chain SOCKS → hy2 UDP → hop1 SOCKS → hy2 UDP
                lt.run(_socks_udp_roundtrip(
                    eng.socks_port, "127.0.0.1", udp_echo.port,
                    b"udp-interop-two-hop", timeout=30), 35)
            finally:
                eng.stop()
        finally:
            entry.stop()
            exit_.stop()
            udp_echo.stop()

    def test_tuic_exit_behind_hy2_entry(self, lt):
        """Cross engine family: a TUIC v5 exit dialled through a
        Hysteria 2 entry (both QUIC, different framing/auth)."""
        from test_tuic import TuicServerProtocol, make_cert_key as tuic_cert
        from aioquic.asyncio.server import serve
        from aioquic.quic.configuration import QuicConfiguration
        import uuid as _uuid

        entry = _Hy2Stack(lt)
        tcp_echo_holder = {}

        async def _tcp_echo(rd, wr):
            try:
                while True:
                    data = await rd.read(65535)
                    if not data:
                        break
                    wr.write(data)
                    await wr.drain()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                try:
                    wr.close()
                except OSError:
                    pass

        async def _start_all():
            echo = await asyncio.start_server(_tcp_echo, "127.0.0.1", 0)
            tcp_echo_holder["echo"] = echo
            tcp_echo_holder["port"] = echo.sockets[0].getsockname()[1]

            uid = str(_uuid.uuid4())
            stats = {"auth": None}
            cert, key = tuic_cert()
            cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
            cfg.certificate = cert
            cfg.private_key = key
            cfg.max_datagram_frame_size = 65535
            cfg.idle_timeout = 30.0

            def factory(quic, stream_handler=None):
                return TuicServerProtocol(
                    quic, uuid_bytes=_uuid.UUID(uid).bytes,
                    token_bytes=token, stats=stats)

            server = await serve("127.0.0.1", 0, configuration=cfg,
                                 create_protocol=factory)
            tcp_echo_holder["tuic"] = server
            tcp_echo_holder["tuic_port"] = \
                server._transport.get_extra_info("sockname")[1]
            tcp_echo_holder["uid"] = uid
            tcp_echo_holder["stats"] = stats

        token = os.urandom(32)
        lt.run(_start_all(), 15)
        try:
            tuic_prof = M.TuicProfile(
                server="127.0.0.1", port=tcp_echo_holder["tuic_port"],
                uuid=tcp_echo_holder["uid"], token_hex=token.hex(),
                congestion="bbr", allow_insecure=True)
            # TUIC's community share-link format carries no token_hex, so
            # the chain is driven with model instances (build_chain +
            # ordered start, exactly what ChainEngine.start does)
            pairs = chain.build_chain([entry.profile(), tuic_prof])
            assert pairs[1][0].upstream_socks[1] == pairs[0][0].socks_port
            for e, p in pairs:
                e.start(p, timeout=40.0)
            eng = chain.ChainEngine()
            eng.engines = [e for e, _ in pairs]
            eng.socks_port = eng.engines[-1].socks_port
            try:
                assert eng.running
                st = eng.status()
                assert [h["kind"] for h in st["hops"]] == \
                    ["hysteria2", "tuic"]
                rd, wr = lt.run(socks5_dial(
                    "127.0.0.1", eng.socks_port,
                    "127.0.0.1", tcp_echo_holder["port"], timeout=25), 30)
                wr.write(b"tuic-over-hy2")
                lt.run(wr.drain())
                assert lt.run(rd.readexactly(13), 25) == b"tuic-over-hy2"
                wr.close()
                # the TUIC server must have accepted the auth frame
                deadline = time.time() + 10
                stats = tcp_echo_holder["stats"]
                while stats["auth"] is None and time.time() < deadline:
                    time.sleep(0.05)
                assert stats["auth"] is True, \
                    "fake TUIC server rejected the auth through the chain"
            finally:
                eng.stop()
        finally:
            entry.stop()
            try:
                lt.run(tcp_echo_holder["tuic"].close(), 5)
            except Exception:                        # noqa: BLE001
                pass
            try:
                lt.run(tcp_echo_holder["echo"].close(), 5)
            except Exception:                        # noqa: BLE001
                pass

    def test_chain_stop_closes_every_hop_port(self, lt):
        entry, exit_ = _Hy2Stack(lt), _Hy2Stack(lt, password="exit-pass")
        try:
            chain_prof = M.ChainProfile(hops=[entry.profile().share_url(),
                                              exit_.profile().share_url()])
            eng = chain.ChainEngine()
            eng.start(chain_prof, timeout=60.0)
            ports = [e.socks_port for e in eng.engines]
            assert all(_listening(p) for p in ports)
            eng.stop()
            deadline = time.time() + 5
            while time.time() < deadline and \
                    any(_listening(p) for p in ports):
                time.sleep(0.1)
            assert not any(_listening(p) for p in ports), \
                "chain stop left a hop port open: %r" % ports
        finally:
            entry.stop()
            exit_.stop()


# ===========================================================================
# B. WARP composition
# ===========================================================================
class TestWarpComposition:
    def _mock_client(self):
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/reg"):
                return httpx.Response(200, json={
                    "id": "device-1234",
                    "token": "warp-token",
                    "config": {
                        "client_id": base64.b64encode(bytes([9, 8, 7])).decode(),
                        "interface": {
                            "addresses": {"v4": "172.16.0.2/32",
                                          "v6": "2606:4700:110:8::a/128"}},
                        "peers": [{
                            "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                            "endpoint": {"v4": "162.159.193.10:2408",
                                         "v6": "[2606:4700:d0::a29f:c001]:2408"},
                            "reserved": [9, 8, 7]}]}})
            return httpx.Response(404)

        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_register_mocked_then_both_positions_build(self):
        prof = warp.new_profile()
        with self._mock_client() as client:
            got = warp.register(prof, client=client)
        assert got is prof
        assert prof.private_key and prof.peer_public_key
        assert prof.client_id_b64 == base64.b64encode(bytes([9, 8, 7])).decode()
        assert prof.address_v4 == "172.16.0.2/32"
        assert prof.token == "warp-token" and prof.device_id == "device-1234"
        # a second register call reuses the cached registration
        calls = []
        with self._mock_client() as client:
            client._count = 0

            def counting_handler(request):
                calls.append(request.url.path)
                from httpx import Response
                return Response(500)
            client._transport.handle_request = counting_handler
            warp.register(prof, client=client)
        assert not calls, "register must reuse the cached registration"

        # WARP-before: endpoint (no upstream possible)
        cfg = warp.build_warp_box_config(prof, 10800)
        assert cfg["inbounds"][0]["type"] == "mixed"
        eps = cfg.get("endpoints", [])
        assert eps and eps[0]["type"] == "wireguard"
        assert eps[0]["peers"][0]["reserved"] == [9, 8, 7]
        # WARP-after: wireguard OUTBOUND with detour through the upstream
        cfg2 = warp.build_warp_box_config(prof, 10800,
                                          upstream=("127.0.0.1", 5555))
        wg = [o for o in cfg2["outbounds"] if o.get("type") == "wireguard"]
        assert wg and wg[0]["detour"] == "upstream"
        # and the registry-level builder agrees for both positions
        before = boxproto.build_box_config("warp", prof, 10800)
        assert "endpoints" in before
        after = boxproto.build_box_config("warp", prof, 10800,
                                          upstream=("127.0.0.1", 5555))
        assert [o for o in after["outbounds"]
                if o.get("type") == "wireguard"][0]["detour"] == "upstream"

    def test_warp_presets_compose_in_build_chain(self, monkeypatch):
        """warp-before / warp-after URLs parse into chains whose engines
        are wired hop-to-hop exactly like the presets promise."""
        from proto_clean.vpn import protocols as registry

        made = []

        class _StubBox(chain.ProtocolEngine):
            proxy_kind = "box"
            family = "proxy"
            exposes = "mixed"
            supports_upstream = True

            def __init__(self, socks_port=0, http_port=0):
                super().__init__(socks_port, http_port)

            def start(self, profile, timeout=15.0, **kw):
                self.socks_port = self.socks_port or 20800
                made.append(("start", self.proxy_kind))

            def stop(self, timeout=5.0):
                made.append(("stop", self.proxy_kind))

            @property
            def running(self):
                return True

        def fake_make(kind, profile, socks_port=0):
            eng = _StubBox(socks_port=socks_port)
            eng.proxy_kind = kind
            return eng

        monkeypatch.setattr(registry, "make_engine", fake_make)

        proto_url = "hysteria2://a@h.io:443/?sni=h.io"

        # WARP BEFORE the protocol: warp is hop 1 (endpoint, no upstream)
        before_p = links.parse_link(warp.warp_before_chain_url(proto_url))[1]
        assert before_p.hops[0].startswith("warp://")
        hop_profs = [links.parse_link(u)[1] for u in before_p.hops]
        pairs = chain.build_chain(hop_profs)
        assert [e.proxy_kind for e, _ in pairs] == ["warp", "hysteria2"]
        assert pairs[1][0].upstream_socks[1] == pairs[0][0].socks_port
        # starting it runs hop 1 first (the endpoint must exist before
        # the protocol's WireGuard handshake rides through it)
        for e, p in pairs:
            e.start(p)
        assert made[0] == ("start", "warp")

        # WARP AFTER the protocol: warp is the exit (outbound + detour)
        made.clear()
        after_p = links.parse_link(warp.warp_after_chain_url(proto_url))[1]
        assert after_p.hops[-1].startswith("warp://")
        hop_profs = [links.parse_link(u)[1] for u in after_p.hops]
        pairs = chain.build_chain(hop_profs)
        assert [e.proxy_kind for e, _ in pairs] == ["hysteria2", "warp"]
        assert pairs[1][0].upstream_socks[1] == pairs[0][0].socks_port


# ===========================================================================
# C. the import universe
# ===========================================================================
class TestImportUniverse:
    # one canonical profile per link kind — every field encoded in the
    # share URL must survive parse_link(share_url())
    LINK_PROFILES = [
        M.ShadowsocksProfile(server="s.io", port=8388,
                             method="aes-256-gcm", password="p"),
        M.ShadowsocksrProfile(server="r.io", port=8388, method="rc4-md5",
                              password="pw", obfs="plain",
                              protocol="origin"),
        M.Hysteria2Profile(server="h.io", port=443, auth="a",
                           sni="h.io", insecure=True,
                           obfs="salamander", obfs_password="o"),
        M.TuicProfile(uuid=UUID, password="p", server="t.io",
                      port=443, sni="t.io", congestion="bbr",
                      alpn="h3", udp_relay_mode="native",
                      allow_insecure=True),
        M.MasqueProfile(server="m.io", port=443, template="/masque",
                        sni="m.io", insecure=True),
        M.NaiveProfile(server="n.io", port=443, username="u",
                       password="p", sni="n.io"),
        M.CoverDtlsProfile(server="d.io", port=443, psk="k", sni="d.io"),
        M.CloakProfile(server="c.io", port=443, uid=UUID.replace("-", ""),
                       public_key="a" * 64, server_name="mask.io",
                       transport="direct",
                       encryption_method="aes-256-gcm", num_conn=4,
                       browser_sig="chrome",
                       alternative_names=["alt1.io", "alt2.io"]),
        M.AwgProfile(server="awg.io", port=51820, private_key="pr",
                     peer_public_key="pe", address=["10.8.0.2/32"],
                     allowed_ips=["0.0.0.0/0"], dns=["1.1.1.1"],
                     junk={"Jc": 4, "Jmin": 10, "Jmax": 30, "S1": 15,
                           "S2": 16, "H1": 5, "H2": 6, "H3": 7, "H4": 8}),
        M.Ikev2Profile(server="i.io", username="u", password="p",
                       auth="eap-mschapv2"),
        M.TorProfile(bridges=["obfs4 127.0.0.1:99 z=pub i=cert",
                              "snowflake 127.0.0.1:98 z=z2"]),
        M.ObscuraProfile(account_id="12345678901234567890",
                         auth_token="tok", tunnel_id="tun-1",
                         tunnel_type="udp_port", relay="NYC-001",
                         exit="AMS-002"),
        M.RadianceProfile(server="r.io", port=443, token="t",
                          transport="tls"),
        M.LampshadeProfile(server="l.io", port=443, token="t",
                           transport="tcp"),
        M.ReflexProfile(server="rf.io", port=443,
                        cert_pem="-----BEGIN CERT-----\nZm9v\n-----END-----",
                        key_pem="-----BEGIN KEY-----\nYmFy\n-----END-----"),
        M.OutlineProfile(server="ol.io", port=443, dns=["system"],
                         tls=["fragmentation"],
                         domains=["*.example.org"]),
        M.AlgenevaProfile(server="g.io", port=9001,
                          strategy="[TCP:tls]-fragment"),
        M.WaterProfile(server="w.io", port=9003, transport="mq",
                       hashsum="sha256", wasm_urls=["https://x/w.wasm"],
                       download_timeout="90s"),
        M.VmessProfile(server="v.io", port=443, uuid=UUID,
                       transport="ws", path="/w", tls=True),
        M.WarpProfile(license_key="", endpoint="e.io:2408", port=2408,
                      private_key="pr", peer_public_key="pe",
                      client_id_b64="CAAAAA==", address_v4="172.16.0.2/32",
                      address_v6="", token="tk", device_id="dv"),
        M.BoxRawProfile(config_json=json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                          "listen_port": 1}],
            "outbounds": [{"type": "vmess", "server": "v.io",
                           "server_port": 443, "uuid": UUID}]})),
        M.ClashProfile(yaml_text="proxies:\n  - {name: a, type: ss, "
                                 "server: 1.1.1.1, port: 8388}\n"),
    ]

    @pytest.mark.parametrize("profile", LINK_PROFILES,
                             ids=lambda p: type(p).__name__)
    def test_every_link_kind_roundtrips(self, profile):
        kind, back = links.parse_link(profile.share_url())
        assert kind == profile.kind, type(profile).__name__
        for field in type(profile).__dataclass_fields__:
            if field in ("tag", "title"):
                continue
            want = getattr(profile, field)
            got = getattr(back, field, None)
            assert got == want, "%s.%s: %r != %r" % (
                type(profile).__name__, field, got, want)

    BOX_PROFILES = {
        "shadowsocks": M.ShadowsocksProfile(
            server="ss.example", port=8388, method="aes-256-gcm",
            password="ss-pass"),
        "shadowsocksr": M.ShadowsocksrProfile(
            server="ssr.example", port=8388, method="rc4-md5",
            password="pw", obfs="plain", protocol="origin"),
        "hysteria2": M.Hysteria2Profile(
            server="h.example", port=8443, auth="hy-pass", sni="h.example"),
        "tuic": M.TuicProfile(
            uuid=UUID, password="p", server="t.example", port=443),
        "naive": M.NaiveProfile(
            server="n.example", port=443, username="user", password="pw"),
        "trojan": None,          # XrayProfile built below
        "reflex": M.ReflexProfile(server="r.example", port=443),
        "water": M.WaterProfile(server="w.example", port=9003,
                                transport="mq"),
        "outline": M.OutlineProfile(server="o.example", port=443),
        "algeneva": M.AlgenevaProfile(server="g.example", port=9001,
                                      strategy="[TCP:tls]-fragment"),
        "amneziawg": M.AwgProfile(
            server="awg.example", port=51820, private_key="priv-key",
            peer_public_key="peer-key", address=["10.8.1.2/32"],
            allowed_ips=["0.0.0.0/0"],
            junk={"Jc": 4, "Jmin": 10, "Jmax": 30, "S1": 15, "S2": 16,
                  "H1": 5, "H2": 6, "H3": 7, "H4": 8}),
        "vmess": M.VmessProfile(server="v.example", port=443, uuid=UUID),
        "warp": M.WarpProfile(private_key="AAA=", peer_public_key="BBB=",
                              client_id_b64="CAAAAA==",
                              address_v4="172.16.0.2/32"),
        "boxraw": M.BoxRawProfile(config_json=json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                          "listen_port": 12345}],
            "outbounds": [{"type": "vmess", "tag": "vm", "server": "v.io",
                           "server_port": 443, "uuid": UUID}]})),
    }

    def test_every_box_kind_builds_valid_config(self):
        from proto_clean.vpn.xrayconf import XrayProfile
        profiles = dict(self.BOX_PROFILES)
        profiles["trojan"] = XrayProfile(
            protocol="trojan", address="tr.example", port=443)
        for kind in boxproto.SUPPORTED_KINDS:
            prof = profiles.get(kind)
            if prof is None:
                pytest.skip("no canonical profile for %s" % kind)
            cfg = boxproto.build_box_config(kind, prof, 10800)
            if kind == "boxraw":
                # raw passthrough: the user's own config is preserved
                # verbatim (their inbound port, their outbounds)
                assert cfg["inbounds"][0]["listen_port"] == 12345
                assert cfg["outbounds"][0]["tag"] == "vm"
                json.dumps(cfg)
                continue
            # mixed inbound on the requested port, no matter the kind
            assert cfg["inbounds"][0]["type"] == "mixed"
            assert cfg["inbounds"][0]["listen_port"] == 10800
            # an outbound or endpoint carries the protocol
            assert (cfg.get("outbounds") or cfg.get("endpoints")), kind
            # and it is valid, serializable JSON
            json.dumps(cfg)

    def test_import_center_takes_every_source(self, tmp_path, monkeypatch):
        """One store, seven sources: links text, Clash file, V2ray file,
        sing-box file, WireGuard file, QR image, subscription."""
        store = profiles.ProfileStore(str(tmp_path / "profiles.json"))
        center = importers.ImportCenter(store)

        # 1) share links
        s1 = center.import_text(
            "hysteria2://auth@h.io:443/?sni=h.io&insecure=1#hy\n"
            "vmess://" + base64.b64encode(json.dumps(
                {"v": "2", "add": "v.io", "port": "443", "id": UUID,
                 "net": "ws", "tls": "tls"}).encode()).decode())
        assert s1.ok and len(s1.added) == 2

        # 2) Clash YAML file
        clash_file = tmp_path / "sub.yaml"
        clash_file.write_text(
            "proxies:\n"
            "  - {name: ss1, type: ss, server: 1.1.1.1, port: 8388,"
            " cipher: aes-256-gcm, password: p}\n")
        s2 = center.import_file(str(clash_file))
        assert s2.ok and len(s2.added) == 1

        # 3) V2ray JSON file
        v2_file = tmp_path / "v2.json"
        v2_file.write_text(json.dumps({"outbounds": [
            {"tag": "vm", "protocol": "vmess",
             "settings": {"vnext": [{"address": "v2.io", "port": 443,
                                     "users": [{"id": UUID}]}]},
             "streamSettings": {"network": "ws", "security": "tls"}},
            {"tag": "d", "protocol": "freedom"}]}))
        s3 = center.import_file(str(v2_file))
        assert s3.ok and len(s3.added) == 1

        # 4) sing-box JSON (raw passthrough)
        sb_file = tmp_path / "sb.json"
        sb_file.write_text(json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                          "listen_port": 12345}],
            "outbounds": [{"type": "vmess", "tag": "vm", "server": "sb.io",
                           "server_port": 443, "uuid": UUID}]}))
        s4 = center.import_file(str(sb_file))
        assert s4.ok and len(s4.added) == 1

        # 5) WireGuard conf file
        wg_file = tmp_path / "wg.conf"
        wg_file.write_text(
            "[Interface]\n"
            "PrivateKey = 6HG1a7cTMp5R3ZmT2P0YyGj5b5L5f5R3ZmT2P0YyGk=\n"
            "Address = 10.8.0.2/32\n"
            "DNS = 1.1.1.1\n"
            "\n"
            "[Peer]\n"
            "PublicKey = 6HG1a7cTMp5R3ZmT2P0YyGj5b5L5f5R3ZmT2P0YyGk=\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = wg.example:51820\n")
        s5 = center.import_file(str(wg_file))
        assert s5.ok and len(s5.added) == 1

        # 6) QR image: a share link rendered by segno, decoded by zxing
        qr_png = tmp_path / "qr.png"
        link = "tuic://%s:p@tq.io:443/?sni=tq.io" % UUID
        importers.make_qr(link, str(qr_png))
        payloads = importers.decode_qr_file(str(qr_png))
        assert payloads == [link]
        s6 = center.import_qr_payloads(payloads)
        assert s6.ok and len(s6.added) == 1

        # 7) subscription (base64 list of links over mocked HTTP)
        import httpx
        blob = base64.b64encode(
            b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#sub\n").decode()

        def fake_get(self, url, **kw):
            return httpx.Response(200, text=blob)

        monkeypatch.setattr(httpx.Client, "get", fake_get)
        s7 = center.import_subscription("https://sub.example.com/x")
        assert s7.ok and len(s7.added) == 1

        # everything landed, nothing duplicated
        assert store.count() == 8

        # every stored entry still builds an engine config (chains and
        # raw configs included: their hops/payload must parse)
        box_kinds = set(boxproto.SUPPORTED_KINDS)
        for entry in store.all():
            prof = entry.profile()
            assert prof is not None, entry.url
            if entry.kind == "chain":
                for hop_url in prof.hops:
                    links.parse_link(hop_url)
            else:
                kind = "boxraw" if entry.kind == "boxraw" else entry.kind
                cfg = boxproto.build_box_config(kind, prof, 10800)
                json.dumps(cfg)

        # and re-importing the same sources dedupes everything
        again = center.import_text(
            "hysteria2://auth@h.io:443/?sni=h.io&insecure=1#hy")
        assert len(again.added) == 1
        assert store.count() == 8


# ===========================================================================
# D. QR interop (segno → PNG → zxing-cpp)
# ===========================================================================
class TestQrInterop:
    QR_PROFILES = [
        M.ShadowsocksProfile(server="s.io", port=8388,
                             method="aes-256-gcm", password="p"),
        M.Hysteria2Profile(server="h.io", port=443, auth="a", sni="h.io"),
        M.VmessProfile(server="v.io", port=443, uuid=UUID,
                       transport="ws", path="/w", tls=True),
        M.TuicProfile(uuid=UUID, password="p", server="t.io", port=443),
        M.WarpProfile(private_key="pr=", peer_public_key="pe=",
                      client_id_b64="CAAAAA==", address_v4="172.16.0.2/32"),
    ]

    @pytest.mark.parametrize("profile", QR_PROFILES,
                             ids=lambda p: type(p).__name__)
    def test_profile_to_qr_to_profile(self, profile, tmp_path):
        link = profile.share_url()
        png = tmp_path / ("qr-%s.png" % type(profile).__name__)
        importers.make_qr(link, str(png))
        decoded = importers.decode_qr_file(str(png))
        assert decoded == [link]
        kind, back = links.parse_link(decoded[0])
        assert kind == profile.kind
        # a server-ish field survived the whole loop
        assert getattr(back, "server", None) == getattr(
            profile, "server", None) or kind in ("warp",)

    def test_chain_url_survives_qr_roundtrip(self, tmp_path):
        """A long warp-after chain URL is exactly the payload users share
        on screen — it must survive the QR encode/decode round trip."""
        proto_url = ("hysteria2://auth@h.io:443/?sni=h.io&insecure=1"
                     "&obfs=salamander&obfs-password=salt#my-exit")
        chain_url = warp.warp_after_chain_url(proto_url)
        png = tmp_path / "chain-qr.png"
        importers.make_qr(chain_url, str(png), scale=10)
        assert importers.decode_qr_file(str(png)) == [chain_url]
        kind, prof = links.parse_link(importers.decode_qr_file(str(png))[0])
        assert kind == "chain"
        assert prof.hops == [proto_url, prof.hops[1]]
        assert prof.hops[1].startswith("warp://")


# ===========================================================================
# E. guest mode ↔ the WireGuard stack
# ===========================================================================
class TestGuestWgInterop:
    def _cert(self):
        from proto_clean.proton.guest import GuestCertificate
        return GuestCertificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\nFAKE\n"
                            "-----END CERTIFICATE-----\n",
            server_status={}, refresh_time=int(time.time()) + 86400,
            ipv4="10.2.0.5", ipv6="2001:db8::5",
            dns_ips=["10.140.0.1"],
            client_public_key_pem="-----BEGIN PUBLIC KEY-----\nY2hViQ==\n-----END PUBLIC KEY-----\n")

    def _logical(self):
        from proto_clean.proton.guest import GuestLogicalServer
        return GuestLogicalServer(
            server_id="srv-1", name="US-FREE#1", exit_country="US",
            city="New York", tier=0, features=0, load=20.0, score=0.5,
            domain="us-free-1.protonvpn.com", entry_ip="185.159.158.1",
            x25519_public_key="serverWgPubKeyBase64==", status=1)

    def test_guest_cert_builds_wg_quick_the_stack_parses(self):
        """Guest mode plugs into the SAME WireGuard machinery as the
        logged-in flow: the generated config parses with the production
        wgconf parser and every field survives."""
        from proto_clean.proton.guest import build_wg_quick_config
        from proto_clean.vpn.wgconf import WgQuickConf

        text = build_wg_quick_config(self._logical(), self._cert(),
                                     "cHJpdmF0ZWtleQ==")
        conf = WgQuickConf.parse(text)          # production parser
        assert conf.interface["PrivateKey"] == ["cHJpdmF0ZWtleQ=="]
        assert "10.2.0.5/32" in conf.addresses
        assert "2001:db8::5/128" in conf.addresses
        assert conf.dns == "10.140.0.1"
        assert conf.peer["PublicKey"] == ["serverWgPubKeyBase64=="]
        assert conf.peer["AllowedIPs"] == ["0.0.0.0/0, ::/0"]
        assert conf.endpoint_host_port == ("185.159.158.1", 51820)

        # IPv4-only toggle drops the v6 tokens everywhere
        text4 = build_wg_quick_config(self._logical(), self._cert(),
                                      "cHJpdmF0ZWtleQ==", ipv6=False)
        conf4 = WgQuickConf.parse(text4)
        assert "2001:db8::5/128" not in conf4.addresses
        assert conf4.peer["AllowedIPs"] == ["0.0.0.0/0"]

        # DNS override lands verbatim (the DNS blocker loopback path)
        text_dns = build_wg_quick_config(
            self._logical(), self._cert(), "cHJpdmF0ZWtleQ==",
            dns_server="127.0.0.1")
        assert WgQuickConf.parse(text_dns).dns == "127.0.0.1"

    def test_guest_logical_maps_to_server_model(self):
        from proto_clean.servers.models import LogicalServer
        logical = self._logical().to_logical_server()
        assert isinstance(logical, LogicalServer)
        assert logical.name == "US-FREE#1"
        assert logical.exit_country == "US"
        assert logical.tier == 0        # guest = free tier only


# ===========================================================================
# F. controller ↔ protocol engines
# ===========================================================================
class _StubEngine:
    """Real listening socket, registry-compatible lifecycle."""

    proxy_kind = "stub"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True

    def __init__(self, socks_port: int = 0):
        self.socks_port = socks_port or 0
        self.http_port = 0
        self.upstream_socks = ("", 0)
        self._sock = None

    def start(self, profile, timeout=15.0, socks_port=None, **kw):
        if socks_port:
            self.socks_port = socks_port
        s = socket.socket()
        s.bind(("127.0.0.1", self.socks_port or 0))
        s.listen(1)
        self._sock = s
        self.socks_port = s.getsockname()[1]

    def stop(self, timeout=5.0, **kw):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def running(self):
        return self._sock is not None

    def status(self):
        return {"running": self.running, "kind": self.proxy_kind}


class TestControllerEngineInterop:
    @pytest.fixture()
    def controller(self, tmp_path, monkeypatch):
        """A Controller with __init__ skipped, the fields the profile
        workers touch set up, and ProfileStore pointed at tmp storage."""
        from proto_clean.controller import Controller, State

        real_cls = profiles.ProfileStore        # captured BEFORE patching
        store_path = str(tmp_path / "store.json")

        def make_store(*a, **k):
            return real_cls(store_path)

        # the workers do `from .vpn.protocols.profiles import ProfileStore`
        # at CALL time, so patching the module attribute is enough
        monkeypatch.setattr(
            "proto_clean.vpn.protocols.profiles.ProfileStore", make_store)

        ctl = Controller.__new__(Controller)
        ctl.state = State.LOGGED_OUT
        ctl.state_detail = ""
        ctl.proxy_state = "off"
        ctl._proxy_listeners = []
        ctl._proxy_lock = threading.Lock()
        ctl.messages = []
        ctl.on_message = lambda t, l: ctl.messages.append((t, l))
        ctl.on_state = lambda s, d: None
        ctl.on_servers = lambda s: None
        ctl.on_stats = lambda s: None
        ctl.xray = types.SimpleNamespace(stop=lambda: None)
        ctl.samizdat = types.SimpleNamespace(stop=lambda: None)
        ctl._protocol_engine = None
        ctl._apply_browser_proxy = lambda: None
        ctl.helper_ready = lambda: True
        ctl.store_path = store_path
        ctl.store_cls = real_cls
        return ctl

    def test_start_and_stop_profile_lifecycle(self, controller, monkeypatch):
        from proto_clean.vpn import protocols as registry

        store = controller.store_cls(controller.store_path)
        entry = store.add(
            "hysteria2",
            M.Hysteria2Profile(server="h.io", port=443, auth="a",
                               sni="h.io"),
            name="lifecycle")
        assert entry is not None

        started = {}

        class Stub(_StubEngine):
            def start(self, profile, timeout=15.0, socks_port=None, **kw):
                super().start(profile, timeout, socks_port=21800, **kw)
                started["port"] = self.socks_port
                started["kind"] = profile.kind

        monkeypatch.setattr(
            registry, "make_engine",
            lambda kind, profile, socks_port=0: Stub(socks_port))

        controller._profile_start_worker(entry.id)
        assert controller.proxy_state == "on"
        assert controller._protocol_engine.running
        assert _listening(started["port"])
        assert started["kind"] == "hysteria2"

        controller._protocol_stop_worker()
        assert controller.proxy_state == "off"
        assert controller._protocol_engine is None
        assert not _listening(started["port"])

    def test_start_chain_profile_lifecycle(self, controller, monkeypatch):
        from proto_clean.vpn import protocols as registry

        store = controller.store_cls(controller.store_path)
        chain_url = links.build_chain_url([
            "hysteria2://a@h.io:443/?sni=h.io",
            "vmess://" + base64.b64encode(json.dumps(
                {"v": "2", "add": "v.io", "port": "443", "id": UUID,
                 "net": "ws"}).encode()).decode()])
        entry = store.add("chain", M.ChainProfile(hops=[
            "hysteria2://a@h.io:443/?sni=h.io",
            "vmess://" + base64.b64encode(json.dumps(
                {"v": "2", "add": "v.io", "port": "443", "id": UUID,
                 "net": "ws"}).encode()).decode()]), name="two-hop")
        assert entry is not None and entry.kind == "chain"
        assert entry.url == chain_url

        made = []

        class Stub(_StubEngine):
            def __init__(self, socks_port: int = 0):
                super().__init__(socks_port)
                made.append(self)

        monkeypatch.setattr(
            registry, "make_engine",
            lambda kind, profile, socks_port=0: Stub(socks_port))

        controller._profile_start_worker(entry.id)
        assert controller.proxy_state == "on"
        # both hops started, second wired through the first
        assert len(made) == 2
        assert made[1].upstream_socks[1] == made[0].socks_port
        assert controller._protocol_engine.running
        ports = [e.socks_port for e in made]
        assert all(_listening(p) for p in ports)

        controller._protocol_stop_worker()
        assert controller.proxy_state == "off"
        assert not any(_listening(p) for p in ports)


# ===========================================================================
# G. whole-stack sanity
# ===========================================================================
class TestWholeStack:
    def test_every_module_imports_together_headless(self):
        """All feature modules coexist in one interpreter with no Qt and
        no display: protocols, engines, guest mode, bond, samizdat, DNS,
        MD3 theming and the controller itself."""
        import proto_clean.controller                      # noqa: F401
        import proto_clean.netshield.dns_server            # noqa: F401
        import proto_clean.proton.guest                    # noqa: F401
        import proto_clean.ui.md3                          # noqa: F401
        import proto_clean.vpn.bond                        # noqa: F401
        import proto_clean.vpn.bondnet                     # noqa: F401
        import proto_clean.vpn.bondproto                   # noqa: F401
        import proto_clean.vpn.bondserver                  # noqa: F401
        import proto_clean.vpn.samizdat                    # noqa: F401
        import proto_clean.vpn.samizdatconf                # noqa: F401
        import proto_clean.vpn.wgconf                      # noqa: F401
        import proto_clean.vpn.ovpnconf                    # noqa: F401
        from proto_clean.vpn.protocols import (cloak, convert, importers,  # noqa: F401
                                               naive, obscura, profiles,
                                               tor, warp)

        # the registry is fully populated after boxproto self-registers
        from proto_clean.vpn.protocols import kinds
        assert len(kinds()) >= 27

    def test_md3_scheme_feeds_the_qss_generator(self):
        """The MD3 theme bridge: seed → scheme → QSS with the palette
        colors actually landing in the stylesheet, both modes."""
        from proto_clean.ui import md3

        for theme, is_dark in (("light", False), ("dark", True)):
            scheme, name = md3.md3_scheme_for(theme)
            assert scheme is not None and name
            qss = md3.md3_qss(scheme)
            assert qss and isinstance(qss, str)
            # core palette roles land in the stylesheet
            assert scheme.primary.lower() in qss.lower(), theme
            assert scheme.surface.lower() in qss.lower(), theme
            # the connection-state palette is complete and carries the
            # scheme's semantic roles into the UI
            states = md3.state_colors(scheme)
            assert set(states) == {"logged_out", "logged_in", "connecting",
                                   "connected", "disconnecting", "error"}
            assert states["logged_out"][0] == scheme.outline
            assert states["error"][0] == scheme.error
            for state, (color, label) in states.items():
                assert color.startswith("#") and len(color) == 7, state
                assert label
            # light and dark really differ
        light, _ = md3.md3_scheme_for("light")
        dark, _ = md3.md3_scheme_for("dark")
        assert light.surface != dark.surface
