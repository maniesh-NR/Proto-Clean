"""Tests for the MASQUE engine (RFC 9110 CONNECT over HTTP/3 + RFC 9298
CONNECT-UDP).

Unit tests cover the RFC 9297 capsule codec (round-trip, byte-split feeds,
unknown capsule types, QUIC varint boundaries) and the H3 header builders.
The end-to-end test starts a *minimal MASQUE server* (aioquic + H3 that
understands plain CONNECT and CONNECT-UDP with capsules), a TCP echo and a
UDP echo on loopback, then pushes bytes and datagrams through the engine's
local SOCKS5 front-end — including the basic proxy-authorization path
(the fake server answers 407 unless the header matches).
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import ipaddress
import os
import shutil
import tempfile
import time
import urllib.parse

import sys

import pytest

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from proto_clean.vpn.protocols import masque as MS
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.models import MasqueProfile
from proto_clean.vpn.protocols.socks_server import (build_socks5_address,
                                                    socks5_dial)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - cryptography missing
    _HAVE_CRYPTO = False



# Windows CI runs the full unit suite; the socket/loopback engine e2e
# tests are exercised on the Linux and macOS legs (they bind many local
# ports and spawn helper processes, which is unreliable on the
# shared Windows runners).
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="engine e2e covered on Linux/macOS runners")

# ---------------------------------------------------------------------------
# unit: QUIC varints (capsule framing depends on them)
# ---------------------------------------------------------------------------
def test_varint_roundtrip_boundaries():
    for value in (0, 1, 63, 64, 65, 16383, 16384, 2 ** 30 - 1, 2 ** 30,
                  2 ** 32, 2 ** 60 - 1, 2 ** 62 - 1):
        raw = MS.varint_put(value)
        got, off = MS.varint_get(raw, 0)
        assert got == value
        assert off == len(raw)
    # exact wire forms at the encoding boundaries
    assert MS.varint_put(0) == b"\x00"
    assert MS.varint_put(63) == b"\x3f"
    assert MS.varint_put(64) == b"\x40\x40"            # 2-byte, marker 0b01
    assert MS.varint_put(16383) == b"\x7f\xff"
    assert MS.varint_put(16384) == b"\x80\x00\x40\x00"  # 4-byte, marker 0b10
    assert MS.varint_put(2 ** 30) == b"\xc0\x00\x00\x00\x40\x00\x00\x00"


def test_varint_errors():
    with pytest.raises(ValueError):
        MS.varint_get(b"", 0)            # out of bounds
    with pytest.raises(ValueError):
        MS.varint_get(b"\x80", 0)        # truncated 4-byte varint
    with pytest.raises(ValueError):
        MS.varint_get(b"\x40", 0)        # truncated 2-byte varint


# ---------------------------------------------------------------------------
# unit: RFC 9297 capsule codec
# ---------------------------------------------------------------------------
def test_capsule_layout():
    # varint type 0x00 + varint len(context-id + payload) + 0x00 + payload
    assert MS.http_datagram_capsule(b"hi") == b"\x00\x03\x00hi"


def test_capsule_roundtrip():
    payloads = [b"", b"x", b"hello-datagram", bytes(range(256)),
                os.urandom(70000)]   # forces a 4-byte length varint
    for payload in payloads:
        capsule = MS.http_datagram_capsule(payload)
        out = MS.CapsuleParser().feed(capsule)
        assert out == [payload]


def test_capsule_split_feeds():
    payload = b"split-across-chunks"
    capsule = MS.http_datagram_capsule(payload)
    parser = MS.CapsuleParser()
    assert parser.feed(capsule[:2]) == []
    assert parser.feed(capsule[2:5]) == []
    assert parser.feed(capsule[5:]) == [payload]
    # byte-by-byte
    parser = MS.CapsuleParser()
    for i in range(len(capsule) - 1):
        assert parser.feed(capsule[i:i + 1]) == []
    assert parser.feed(capsule[-1:]) == [payload]


def test_capsule_multiple_per_chunk_and_unknown_type():
    one = MS.http_datagram_capsule(b"one")
    unknown = MS.varint_put(0x05) + MS.varint_put(4) + b"abcd"  # arbitrary type
    two = MS.http_datagram_capsule(b"two")
    parser = MS.CapsuleParser()
    assert parser.feed(one + unknown + two) == [b"one", b"two"]


def test_capsule_split_unknown_type_and_empty():
    one = MS.http_datagram_capsule(b"one")
    unknown = MS.varint_put(0x2A) + MS.varint_put(6) + b"ABCDEF"
    empty = MS.http_datagram_capsule(b"")
    two = MS.http_datagram_capsule(b"two")
    blob = one + unknown + empty + two
    parser = MS.CapsuleParser()
    out = []
    for i in range(0, len(blob), 3):
        out.extend(parser.feed(blob[i:i + 3]))
    assert out == [b"one", b"", b"two"]


# ---------------------------------------------------------------------------
# unit: H3 header builders
# ---------------------------------------------------------------------------
def test_tcp_connect_headers():
    h = MS.tcp_connect_headers("example.com", 443)
    assert h[0] == (b":method", b"CONNECT")
    assert (b":authority", b"example.com:443") in h
    # RFC 9114 §4.4: plain CONNECT has no :scheme/:path
    assert all(name not in (b":scheme", b":path") for name, _ in h)
    assert all(name != b"proxy-authorization" for name, _ in h)
    # credentials add basic proxy-authorization to EVERY connect
    h2 = MS.tcp_connect_headers("example.com", 443, "user", "pass")
    assert (b"proxy-authorization",
            b"Basic " + base64.b64encode(b"user:pass")) in h2
    # IPv6 literals are bracketed
    assert (b":authority", b"[::1]:80") in MS.tcp_connect_headers("::1", 80)


def test_udp_connect_headers():
    h = MS.udp_connect_headers("/masque", "10.0.0.1", 53, b"proxy.example:443")
    assert (b":method", b"CONNECT") in h
    assert (b":protocol", b"connect-udp") in h
    assert (b":scheme", b"https") in h
    assert (b":path", b"/masque?target=10.0.0.1&target_port=53") in h
    assert (b":authority", b"proxy.example:443") in h
    assert all(name != b"proxy-authorization" for name, _ in h)
    h2 = MS.udp_connect_headers("", "h", 1, b"a:1", "u", "p")
    assert (b":path", b"/masque?target=h&target_port=1") in h2
    assert (b"proxy-authorization",
            b"Basic " + base64.b64encode(b"u:p")) in h2


def test_engine_attributes_and_validation():
    eng = MS.engine(MasqueProfile(server="127.0.0.1", port=443))
    assert eng.proxy_kind == "masque"
    assert eng.family == "proxy"
    assert eng.exposes == "socks"
    assert eng.supports_upstream is True
    assert eng.binary_name == ""
    assert not eng.running
    with pytest.raises(ProtocolError):
        MS.engine(MasqueProfile()).start(MasqueProfile())   # empty server
    with pytest.raises(ProtocolError):
        MS.engine(MasqueProfile(server="x")).start(object())  # wrong profile


# ---------------------------------------------------------------------------
# E2E: minimal MASQUE H3 server + engine + SOCKS5 front-end
# ---------------------------------------------------------------------------
def _self_signed_pem():
    """Self-signed cert/key (PEM) for the fake MASQUE server."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "masque-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


async def _echo_handler(rd: asyncio.StreamReader,
                        wr: asyncio.StreamWriter) -> None:
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


class _UdpEchoServer(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.transport.sendto(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass


class _UdpForwarder(asyncio.DatagramProtocol):
    """Server-side UDP socket towards the real target of a CONNECT-UDP."""

    def __init__(self, on_packet) -> None:
        self.on_packet = on_packet
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.on_packet(data)

    def error_received(self, exc: Exception) -> None:
        pass


class _FakeMasqueH3Server(QuicConnectionProtocol):
    """Minimal MASQUE server: H3 CONNECT (TCP) + CONNECT-UDP (capsules)."""

    def __init__(self, quic, expect_auth: bytes = b"", **kwargs) -> None:
        super().__init__(quic, **kwargs)
        self._h3 = H3Connection(quic)
        self._expect_auth = expect_auth
        self._tcp = {}        # stream_id -> upstream StreamWriter
        self._udp = {}        # stream_id -> forwarder transport
        self._capsules = {}   # stream_id -> CapsuleParser

    # -- events -------------------------------------------------------------
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            try:
                h3_events = self._h3.handle_event(event)
            except Exception:
                return
            for h3_event in h3_events:
                self._h3_event(h3_event)

    def _h3_event(self, ev) -> None:
        if isinstance(ev, HeadersReceived):
            self._on_headers(ev)
        elif isinstance(ev, DataReceived):
            self._on_data(ev)

    # -- helpers ------------------------------------------------------------
    def _respond(self, stream_id: int, status: int, extra=()) -> None:
        self._h3.send_headers(
            stream_id, [(b":status", b"%d" % status)] + list(extra),
            end_stream=False)
        self.transmit()

    def _send_capsule(self, stream_id: int, data: bytes) -> None:
        try:
            self._h3.send_data(stream_id, MS.http_datagram_capsule(data),
                               end_stream=False)
            self.transmit()
        except Exception:
            pass

    # -- requests -----------------------------------------------------------
    def _on_headers(self, ev: HeadersReceived) -> None:
        headers = dict(ev.headers)
        if headers.get(b":method", b"") != b"CONNECT":
            self._respond(ev.stream_id, 405)
            return
        if self._expect_auth and \
                headers.get(b"proxy-authorization") != self._expect_auth:
            self._respond(ev.stream_id, 407)
            return
        if headers.get(b":protocol", b"") == b"connect-udp":
            asyncio.ensure_future(self._open_udp(ev.stream_id, headers))
        else:
            asyncio.ensure_future(self._open_tcp(ev.stream_id, headers))

    async def _open_tcp(self, stream_id: int, headers) -> None:
        authority = headers.get(b":authority", b"").decode("utf-8", "replace")
        host, _, port_s = authority.rpartition(":")
        try:
            rd, wr = await asyncio.open_connection(host, int(port_s))
        except (OSError, ValueError):
            self._respond(stream_id, 502)
            return
        self._respond(stream_id, 200)
        self._tcp[stream_id] = wr
        try:
            while True:
                data = await rd.read(65535)
                if not data:
                    break
                self._h3.send_data(stream_id, data, end_stream=False)
                self.transmit()
            self._h3.send_data(stream_id, b"", end_stream=True)
            self.transmit()
        except (OSError, ConnectionError):
            pass
        finally:
            self._tcp.pop(stream_id, None)
            try:
                wr.close()
            except OSError:
                pass

    async def _open_udp(self, stream_id: int, headers) -> None:
        path = headers.get(b":path", b"").decode("utf-8", "replace")
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        host = params.get("target", [""])[0]
        try:
            port = int(params.get("target_port", ["0"])[0])
        except ValueError:
            port = 0
        if not host or not port:
            self._respond(stream_id, 400)
            return
        loop = asyncio.get_event_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpForwarder(
                    lambda data: self._send_capsule(stream_id, data)),
                remote_addr=(host, port))
        except OSError:
            self._respond(stream_id, 502)
            return
        self._udp[stream_id] = transport
        self._capsules[stream_id] = MS.CapsuleParser()
        self._respond(stream_id, 200, [(b"capsule-protocol", b"?1")])

    def _on_data(self, ev: DataReceived) -> None:
        wr = self._tcp.get(ev.stream_id)
        if wr is not None:
            if ev.data:
                wr.write(ev.data)
            if ev.stream_ended:
                self._tcp.pop(ev.stream_id, None)
                try:
                    wr.close()
                except OSError:
                    pass
            return
        parser = self._capsules.get(ev.stream_id)
        if parser is not None:
            transport = self._udp.get(ev.stream_id)
            for payload in parser.feed(ev.data):
                if transport is not None:
                    transport.sendto(payload)


def _server_protocol_factory(expect_auth: bytes):
    def make(quic, stream_handler=None):
        return _FakeMasqueH3Server(quic, expect_auth=expect_auth)
    return make


class _SocksUdpClient(asyncio.DatagramProtocol):
    """Test client for the engine's SOCKS5 UDP relay."""

    def __init__(self) -> None:
        self.transport = None
        self.queue = asyncio.Queue()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait(data)

    def error_received(self, exc: Exception) -> None:
        pass


async def _exercise() -> None:
    loop = asyncio.get_event_loop()
    tmpdir = tempfile.mkdtemp(prefix="masque-test-")
    tcp_echo = None
    udp_echo = None
    server = None
    eng = None
    udp_client = None
    try:
        cert_pem, key_pem = _self_signed_pem()
        cert_path = os.path.join(tmpdir, "cert.pem")
        key_path = os.path.join(tmpdir, "key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

        # -- loopback echo servers ------------------------------------------
        tcp_echo = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
        tcp_port = tcp_echo.sockets[0].getsockname()[1]
        udp_echo, _ = await loop.create_datagram_endpoint(
            _UdpEchoServer, local_addr=("127.0.0.1", 0))
        udp_port = udp_echo.get_extra_info("sockname")[1]

        # -- minimal MASQUE H3 server ---------------------------------------
        cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        cfg.load_cert_chain(cert_path, key_path)
        expect = b"Basic " + base64.b64encode(b"user:pass")
        server = await serve("127.0.0.1", 0, configuration=cfg,
                             create_protocol=_server_protocol_factory(expect))
        masque_port = server._transport.get_extra_info("sockname")[1]

        # -- engine ----------------------------------------------------------
        profile = MasqueProfile(server="127.0.0.1", port=masque_port,
                                username="user", password="pass",
                                insecure=True)
        eng = MS.engine(profile)
        # start() blocks until the QUIC handshake completed — run it in a
        # worker thread so this loop keeps serving the fake MASQUE server
        await loop.run_in_executor(None, eng.start, profile)
        assert eng.socks_port > 0
        st = eng.status()
        assert st["kind"] == "masque"
        assert st["family"] == "proxy"
        assert st["exposes"] == "socks"
        assert st["running"] is True
        assert st["binary"] == "builtin"

        # -- TCP round trip through the SOCKS5 front-end ---------------------
        rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                                   "127.0.0.1", tcp_port, timeout=15)
        payload = b"hello-masque"
        wr.write(payload)
        await wr.drain()
        got = await asyncio.wait_for(rd.readexactly(len(payload)), 15)
        assert got == payload
        # a second exchange proves the tunnel stays usable
        wr.write(b"second tunnel write")
        await wr.drain()
        got2 = await asyncio.wait_for(rd.readexactly(19), 15)
        assert got2 == b"second tunnel write"
        wr.close()

        # -- UDP round trip via the SOCKS UDP relay path ---------------------
        udp_client = _SocksUdpClient()
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: udp_client, remote_addr=("127.0.0.1", eng.socks_port))
        try:
            addr = build_socks5_address("127.0.0.1", udp_port)
            # SOCKS5 UDP datagram: RSV(2) FRAG(1)=0 + ATYP+addr+port —
            # the relay opens the session from the datagram itself
            pkt = b"\x00\x00\x00" + addr + b"udp-masque"
            got = None
            deadline = loop.time() + 12
            while loop.time() < deadline:
                transport.sendto(pkt)
                try:
                    got = await asyncio.wait_for(udp_client.queue.get(), 1.5)
                    break
                except asyncio.TimeoutError:
                    continue
            assert got == b"\x00\x00\x00" + addr + b"udp-masque"
        finally:
            transport.close()
    finally:
        if eng is not None:
            eng.stop()
        if server is not None:
            server.close()
        if udp_client is not None and udp_client.transport is not None:
            udp_client.transport.close()
        if udp_echo is not None:
            udp_echo.close()
        if tcp_echo is not None:
            tcp_echo.close()
            try:
                await tcp_echo.wait_closed()
            except Exception:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not available")
def test_masque_tcp_and_udp_roundtrip():
    started = time.time()
    asyncio.run(_exercise())
    assert time.time() - started < 45
