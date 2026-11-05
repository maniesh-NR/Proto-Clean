"""Tests for the built-in TUIC v5 engine.

Unit tests pin the wire format (address encoding, Authenticate / Connect /
Packet / Dissociate frames) with golden bytes and exercise the client
protocol against a fake QUIC connection.  The E2E test runs a minimal TUIC
v5 server (aioquic ``serve`` + the quicbase ObfsQuicProtocol base, no
obfuscation) next to loopback TCP/UDP echo servers, starts the real engine
and pushes bytes through its local SOCKS5 front-end — TCP CONNECT round
trip and a SOCKS5 UDP ASSOCIATE round trip.
"""

from __future__ import annotations

import asyncio
import datetime
import functools
import os
import socket
import struct
import time
import uuid as _uuid
from typing import Callable, Dict, Tuple

import sys

import pytest

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (ConnectionTerminated, DatagramFrameReceived,
                                 QuicEvent, StreamDataReceived)

from proto_clean.vpn.protocols import tuic as T
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.models import Hysteria2Profile, TuicProfile
from proto_clean.vpn.protocols.quicbase import ObfsQuicProtocol
from proto_clean.vpn.protocols.socks_server import (build_socks5_address,
                                                    parse_socks5_address,
                                                    socks5_dial)

UUID_STR = "a3b1c2d3-4e5f-4a4b-8c8d-0123456789ab"
TOKEN_HEX = "ab" * 32                    # 32 raw bytes for the v5 token


# ===========================================================================
# unit: address encoding
# ===========================================================================
def test_addr_golden_bytes():
    # domain: [0x00][len][bytes][port BE]
    raw = T.parse_addr("example.com", 443)
    assert raw == b"\x00\x0bexample.com" + struct.pack("!H", 443)
    assert T.read_addr(raw, 0) == ("example.com", 443, len(raw))

    # IPv4: [0x01][4 bytes][port BE]
    raw = T.parse_addr("127.0.0.1", 8080)
    assert raw == b"\x01\x7f\x00\x00\x01" + struct.pack("!H", 8080)
    assert T.read_addr(raw, 0) == ("127.0.0.1", 8080, 7)

    # IPv6: [0x02][16 bytes][port BE]
    raw = T.parse_addr("::1", 9090)
    assert raw == b"\x02" + socket.inet_pton(socket.AF_INET6, "::1") \
        + struct.pack("!H", 9090)
    assert T.read_addr(raw, 0) == ("::1", 9090, 19)


@pytest.mark.parametrize("host,port", [
    ("example.com", 443),
    ("sub.domain.example", 80),
    ("127.0.0.1", 65535),
    ("0.0.0.0", 1),
    ("::", 443),
    ("2001:db8::dead:beef", 53),
])
def test_addr_roundtrip(host, port):
    raw = T.parse_addr(host, port)
    got_host, got_port, used = T.read_addr(raw, 0)
    assert used == len(raw)
    assert got_port == port
    # re-encoding the parsed form must reproduce the exact bytes
    assert T.parse_addr(got_host, port) == raw


def test_read_addr_rejects_unknown_type():
    with pytest.raises(ProtocolError):
        T.read_addr(b"\x09\x00\x00", 0)


# ===========================================================================
# unit: command frames (golden bytes)
# ===========================================================================
def test_auth_frame_golden():
    frame = T.build_auth_frame(UUID_STR, bytes.fromhex(TOKEN_HEX))
    assert frame == (b"\x05\x00"
                     + _uuid.UUID(UUID_STR).bytes
                     + bytes([0xAB]) * 32)
    assert len(frame) == 2 + 16 + 32


def test_packet_frame_golden():
    payload = b"UDP-PAYLOAD"
    frame = T.build_packet_frame(0x0102, 0x0304, "example.com", 443, payload)
    assert frame == (b"\x05\x02"
                     + struct.pack("!H", 0x0102)      # ASSOC_ID
                     + struct.pack("!H", 0x0304)      # PKT_ID
                     + b"\x01\x00"                    # FRAG_TOTAL, FRAG_ID
                     + struct.pack("!H", len(payload))  # SIZE
                     + T.parse_addr("example.com", 443)
                     + payload)
    assert T.parse_packet_frame(frame) == (0x0102, 0x0304, "example.com", 443,
                                           payload)


def test_dissociate_frame_golden():
    assert T.build_dissociate_frame(0xBEEF) == b"\x05\x03\xbe\xef"


def test_parse_packet_frame_rejects_garbage():
    with pytest.raises(ValueError):
        T.parse_packet_frame(b"\x05\x01\x00\x01")          # wrong command
    with pytest.raises(ValueError):
        T.parse_packet_frame(b"\x04\x02" + b"\x00" * 20)   # wrong version
    with pytest.raises(ValueError):
        T.parse_packet_frame(b"\x05\x02\x00")              # truncated
    frag = (b"\x05\x02" + struct.pack("!HHBBH", 1, 1, 2, 0, 3)
            + T.parse_addr("h", 1) + b"abc")               # fragmented
    with pytest.raises(ValueError):
        T.parse_packet_frame(frag)


# ===========================================================================
# unit: client protocol against a fake QUIC connection
# ===========================================================================

# Windows CI runs the full unit suite; the socket/loopback engine e2e
# tests are exercised on the Linux and macOS legs (they bind many local
# ports and spawn helper processes, which is unreliable on the
# shared Windows runners).
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="engine e2e covered on Linux/macOS runners")

class _FakeQuic:
    """Records what the protocol writes; never really sends anything."""

    def __init__(self) -> None:
        self._next_stream = 0
        self.stream_writes = []      # (stream_id, data, end)
        self.datagrams = []          # QUIC datagram frame payloads

    def get_next_available_stream_id(self, is_unidirectional: bool = False
                                     ) -> int:
        sid = self._next_stream
        self._next_stream += 4
        return sid

    def send_stream_data(self, stream_id: int, data: bytes,
                         end_stream: bool = False) -> None:
        self.stream_writes.append((stream_id, bytes(data), end_stream))

    def send_datagram_frame(self, data: bytes) -> None:
        self.datagrams.append(bytes(data))

    # used by ObfsQuicProtocol.transmit()
    def datagrams_to_send(self, now):
        return []

    def get_timer(self):
        return None

    # used when the base class wires a StreamWriter for an incoming stream
    def _stream_can_send(self, stream_id: int) -> bool:
        return False


def test_authenticate_writes_frame_on_stream_zero():
    async def run():
        fq = _FakeQuic()
        proto = T.TuicProtocol(fq)
        await proto.authenticate(TuicProfile(uuid=UUID_STR, token_hex=TOKEN_HEX))
        sid, data, end = fq.stream_writes[0]
        assert sid == 0                              # first client stream
        assert end is True                           # auth stream is closed
        assert data == (b"\x05\x00" + _uuid.UUID(UUID_STR).bytes
                        + bytes([0xAB]) * 32)
    asyncio.run(run())


def test_connect_tcp_header_writer_and_reader():
    async def run():
        fq = _FakeQuic()
        proto = T.TuicProtocol(fq)
        rd, wr = await proto.connect_tcp("example.com", 443)
        sid, data, end = fq.stream_writes[0]
        assert data == b"\x05\x01" + T.parse_addr("example.com", 443)
        assert end is False                          # tunnel stays open

        wr.write(b"GET / HTTP/1.0\r\n\r\n")
        await wr.drain()
        sid2, data2, end2 = fq.stream_writes[1]
        assert (sid2, end2) == (sid, False)
        assert data2 == b"GET / HTTP/1.0\r\n\r\n"

        # server data (may arrive before the request is fully written)
        proto.quic_event_received(StreamDataReceived(
            data=b"HTTP/1.1 200 OK", stream_id=sid, end_stream=False))
        assert await asyncio.wait_for(rd.readexactly(15), 1) == b"HTTP/1.1 200 OK"

        proto.quic_event_received(StreamDataReceived(
            data=b"", stream_id=sid, end_stream=True))
        assert await rd.read() == b""                # EOF
        wr.close()
    asyncio.run(run())


def test_open_udp_send_dissociate_and_oversize_drop():
    async def run():
        fq = _FakeQuic()
        proto = T.TuicProtocol(fq)
        got = []
        send, close = proto.open_udp("example.com", 443, got.append)

        send(b"hi")
        assert fq.datagrams[0] == (
            b"\x05\x02" + struct.pack("!HHBBH", 1, 1, 1, 0, 2)
            + T.parse_addr("example.com", 443) + b"hi")

        send(b"x" * 70000)                           # oversize -> dropped
        assert len(fq.datagrams) == 1

        close()                                      # Dissociate datagram
        assert fq.datagrams[1] == b"\x05\x03" + struct.pack("!H", 1)

        # packets for the closed association are ignored
        proto._handle_udp_datagram(
            b"\x05\x02" + struct.pack("!HHBBH", 1, 2, 1, 0, 0)
            + T.parse_addr("5.6.7.8", 1))
        assert got == []
    asyncio.run(run())


def test_incoming_packet_routes_to_session():
    async def run():
        fq = _FakeQuic()
        proto = T.TuicProtocol(fq)
        got = []
        proto.open_udp("1.2.3.4", 53, got.append)
        proto._handle_udp_datagram(
            b"\x05\x02" + struct.pack("!HHBBH", 1, 9, 1, 0, 4)
            + T.parse_addr("5.6.7.8", 9999) + b"abcd")
        assert got == [b"abcd"]
        proto._handle_udp_datagram(b"\x05\x02short")  # malformed -> ignored
        assert got == [b"abcd"]
    asyncio.run(run())


def test_connection_terminated_fails_bridges():
    async def run():
        fq = _FakeQuic()
        proto = T.TuicProtocol(fq)
        rd, _wr = await proto.connect_tcp("example.com", 443)
        proto.quic_event_received(ConnectionTerminated(
            error_code=0x101, frame_type=None, reason_phrase="bad token"))
        assert await rd.read() == b""                # bridge sees EOF
        with pytest.raises(ProtocolError):
            await proto.connect_tcp("example.com", 443)
    asyncio.run(run())


# ===========================================================================
# unit: engine validation
# ===========================================================================
def test_engine_requires_tuic_profile():
    with pytest.raises(ProtocolError):
        T.engine(TuicProfile()).start(Hysteria2Profile(server="x"))


def test_engine_rejects_missing_token_hex():
    prof = TuicProfile(server="203.0.113.10", uuid=UUID_STR)
    with pytest.raises(ProtocolError) as ei:
        T.engine(prof).start(prof, timeout=5)
    assert "lantern-box" in str(ei.value)


@pytest.mark.parametrize("token_hex", ["zz" * 32, "ab" * 31, "ab" * 33])
def test_engine_rejects_bad_token_hex(token_hex):
    prof = TuicProfile(server="203.0.113.10", uuid=UUID_STR,
                       token_hex=token_hex)
    with pytest.raises(ProtocolError):
        T.engine(prof).start(prof, timeout=5)


def test_engine_rejects_bad_uuid():
    prof = TuicProfile(server="203.0.113.10", uuid="not-a-uuid",
                       token_hex=TOKEN_HEX)
    with pytest.raises(ProtocolError):
        T.engine(prof).start(prof, timeout=5)


def test_engine_rejects_bad_congestion():
    prof = TuicProfile(server="203.0.113.10", uuid=UUID_STR,
                       token_hex=TOKEN_HEX, congestion="vegas")
    with pytest.raises(ProtocolError):
        T.engine(prof).start(prof, timeout=5)


def test_engine_rejects_empty_server():
    prof = TuicProfile(server="", uuid=UUID_STR, token_hex=TOKEN_HEX)
    with pytest.raises(ProtocolError):
        T.engine(prof).start(prof, timeout=5)


# ===========================================================================
# E2E: minimal TUIC v5 server + real engine over loopback
# ===========================================================================
def make_cert_key():
    """Self-signed EC cert/key (cryptography objects) for the test server."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tuic-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert, key


class _UdpRelay(asyncio.DatagramProtocol):
    """Server-side UDP relay for one TUIC association (test fake)."""

    def __init__(self, server, assoc_id: int, dst: Tuple[str, int]) -> None:
        self.server = server
        self.assoc_id = assoc_id
        self.dst = dst
        self.transport = None
        self.pending = []
        self.pkt = 0

    def connection_made(self, transport) -> None:
        self.transport = transport

    async def open(self) -> None:
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, remote_addr=self.dst)
        for payload in self.pending:
            self.transport.sendto(payload)
        self.pending = []

    def forward(self, payload: bytes) -> None:
        if self.transport is not None:
            self.transport.sendto(payload)
        else:
            self.pending.append(payload)

    def datagram_received(self, data: bytes, addr) -> None:
        # echo back through QUIC as a Packet frame (source = target)
        self.pkt = (self.pkt + 1) & 0xFFFF
        self.server.send_datagram(T.build_packet_frame(
            self.assoc_id, self.pkt, self.dst[0], self.dst[1], data))

    def error_received(self, exc: Exception) -> None:
        pass

    def close(self) -> None:
        if self.transport is not None:
            try:
                self.transport.close()
            except OSError:
                pass


class TuicServerProtocol(ObfsQuicProtocol):
    """Minimal TUIC v5 server-side protocol (loopback test fake)."""

    def __init__(self, quic, *, uuid_bytes: bytes, token_bytes: bytes,
                 stats: dict) -> None:
        super().__init__(quic)
        self._uuid = uuid_bytes
        self._token = token_bytes
        self.stats = stats
        self._authed = False
        self._auth_buf = b""
        self._stream_bufs: Dict[int, bytes] = {}
        self._tunnels: Dict[int, asyncio.StreamReader] = {}
        self._udp_relays: Dict[int, _UdpRelay] = {}

    # -- events -------------------------------------------------------------
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            # same reason as TuicProtocol: never delegate stream data to the
            # base class (its throwaway StreamWriters FIN the stream on GC)
            self._handle_stream(event)
            return
        if isinstance(event, DatagramFrameReceived):
            self._handle_datagram(event.data)
        super().quic_event_received(event)

    def send_datagram(self, frame: bytes) -> None:
        self._quic.send_datagram_frame(frame)
        self.transmit()

    # -- auth + TCP ----------------------------------------------------------
    def _handle_stream(self, event: StreamDataReceived) -> None:
        sid = event.stream_id
        if sid == 0:
            self._auth_buf += event.data
            if len(self._auth_buf) >= 50 and not self._authed:
                ok = (self._auth_buf[0] == 0x05 and self._auth_buf[1] == 0x00
                      and self._auth_buf[2:18] == self._uuid
                      and self._auth_buf[18:50] == self._token)
                self._authed = ok
                self.stats["auth"] = ok
                if ok:
                    # full-size relayed packets (chained hops) need a larger
                    # 1-RTT packet budget; Initial/Handshake stayed at 1200
                    self._quic._max_datagram_size = 1350
                if not ok:
                    self._quic.close(error_code=0x101,
                                     reason_phrase="auth failed")
                    self.transmit()
            return
        reader = self._tunnels.get(sid)
        if reader is not None:                    # established tunnel
            if event.data:
                reader.feed_data(event.data)
            if event.end_stream:
                reader.feed_eof()
            return
        if not self._authed:
            return
        buf = self._stream_bufs.get(sid, b"") + event.data
        if len(buf) < 2 or buf[0] != 0x05 or buf[1] != 0x01:
            self._stream_bufs[sid] = buf
            return
        try:
            host, port, used = T.read_addr(buf, 2)
        except (ProtocolError, IndexError, struct.error):
            self._stream_bufs[sid] = buf          # wait for the rest
            return
        self._stream_bufs.pop(sid, None)
        qreader = asyncio.StreamReader()
        self._tunnels[sid] = qreader
        rest = buf[2 + used:]
        if rest:
            qreader.feed_data(rest)
        if event.end_stream:
            qreader.feed_eof()
        asyncio.ensure_future(self._dial(sid, qreader, host, port))

    async def _dial(self, sid: int, qreader: asyncio.StreamReader,
                    host: str, port: int) -> None:
        try:
            target_rd, target_wr = await asyncio.open_connection(host, port)
        except OSError:
            self._tunnels.pop(sid, None)
            self._quic.send_stream_data(sid, b"", end_stream=True)
            self.transmit()
            return

        async def quic_to_target():
            try:
                while True:
                    data = await qreader.read(65535)
                    if not data:
                        break
                    target_wr.write(data)
                    await target_wr.drain()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                try:
                    target_wr.close()
                except OSError:
                    pass

        async def target_to_quic():
            try:
                while True:
                    data = await target_rd.read(65535)
                    if not data:
                        break
                    self._quic.send_stream_data(sid, data)
                    self.transmit()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                try:
                    self._quic.send_stream_data(sid, b"", end_stream=True)
                    self.transmit()
                except Exception:
                    pass

        await asyncio.gather(quic_to_target(), target_to_quic(),
                             return_exceptions=True)
        self._tunnels.pop(sid, None)

    # -- UDP -----------------------------------------------------------------
    def _handle_datagram(self, data: bytes) -> None:
        if len(data) < 2 or data[0] != 0x05:
            return
        if data[1] == 0x02:
            try:
                assoc_id, _pkt, host, port, payload = \
                    T.parse_packet_frame(data)
            except (ValueError, ProtocolError):
                return
            relay = self._udp_relays.get(assoc_id)
            if relay is None:
                if not self._authed:
                    return
                relay = _UdpRelay(self, assoc_id, (host, port))
                self._udp_relays[assoc_id] = relay
                asyncio.ensure_future(relay.open())
                relay.pending.append(payload)
            else:
                relay.forward(payload)
        elif data[1] == 0x03 and len(data) >= 4:
            assoc_id = struct.unpack("!H", data[2:4])[0]
            relay = self._udp_relays.pop(assoc_id, None)
            if relay is not None:
                relay.close()


# -- loopback echo servers ---------------------------------------------------
async def _tcp_echo(rd: asyncio.StreamReader,
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


class _UdpEcho(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.transport.sendto(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass


# -- SOCKS5 UDP ASSOCIATE test client ----------------------------------------
class _SocksUdpClient(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            _host, _port, used = parse_socks5_address(data, 3)
        except (ProtocolError, IndexError, struct.error):
            return
        self.queue.put_nowait(data[3 + used:])

    def error_received(self, exc: Exception) -> None:
        pass


async def _socks_udp_roundtrip(socks_host: str, socks_port: int,
                               dst_host: str, dst_port: int,
                               payload: bytes, timeout: float = 15.0) -> None:
    """One datagram round trip through the engine's SOCKS5 UDP relay.

    The relay identifies sessions by client address; the first datagram
    from a new address must carry CMD 0x03 to open the session (the same
    convention test_masque.py uses), further datagrams carry CMD 0x00.
    """
    loop = asyncio.get_event_loop()
    client = _SocksUdpClient()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: client, remote_addr=(socks_host, socks_port))
    try:
        addr = build_socks5_address(dst_host, dst_port)
        # SOCKS5 UDP datagram: RSV(2)=0x0000, FRAG(1)=0, ATYP+addr+port
        # (the relay opens the session from the first datagram itself)
        deadline = time.time() + timeout
        while True:
            transport.sendto(b"\x00\x00\x00" + addr + payload)
            try:
                got = await asyncio.wait_for(client.queue.get(), 1.5)
            except asyncio.TimeoutError:
                if time.time() >= deadline:
                    raise AssertionError("no UDP echo came back")
                continue
            if got == payload:
                break
    finally:
        transport.close()


# -- the E2E scenario ---------------------------------------------------------
async def _e2e() -> None:
    uid = str(_uuid.uuid4())
    uuid_bytes = _uuid.UUID(uid).bytes
    token = os.urandom(32)
    stats = {"auth": None}

    # fake TUIC v5 server (plain, no obfuscation)
    cert, key = make_cert_key()
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    cfg.certificate = cert
    cfg.private_key = key
    cfg.max_datagram_frame_size = 65535
    cfg.idle_timeout = 30.0

    def create_protocol(quic, stream_handler=None):
        return TuicServerProtocol(quic, uuid_bytes=uuid_bytes,
                                  token_bytes=token, stats=stats)

    server = await serve("127.0.0.1", 0, configuration=cfg,
                         create_protocol=create_protocol)
    server_port = server._transport.get_extra_info("sockname")[1]

    # loopback TCP echo + UDP echo targets
    tcp_echo = await asyncio.start_server(_tcp_echo, "127.0.0.1", 0)
    tcp_port = tcp_echo.sockets[0].getsockname()[1]
    loop = asyncio.get_event_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        _UdpEcho, local_addr=("127.0.0.1", 0))
    udp_port = udp_transport.get_extra_info("sockname")[1]

    profile = TuicProfile(server="127.0.0.1", port=server_port, uuid=uid,
                          token_hex=token.hex(), congestion="bbr",
                          allow_insecure=True)
    eng = T.engine(profile)
    try:
        # eng.start() blocks its caller, so run it off the test loop — the
        # fake server lives on this loop and must answer the handshake.
        await loop.run_in_executor(
            None, functools.partial(eng.start, profile, timeout=20.0))
        assert eng.running
        st = eng.status()
        assert st["kind"] == "tuic"
        assert st["family"] == "proxy"
        assert st["exposes"] == "socks"
        assert st["binary"] == "builtin"
        assert st["server"] == "127.0.0.1:%d" % server_port
        assert st["congestion"] == "bbr"
        assert st["running"] is True

        # the fake server must have accepted our Authenticate frame
        deadline = time.time() + 10
        while stats["auth"] is None and time.time() < deadline:
            await asyncio.sleep(0.05)
        assert stats["auth"] is True, "fake TUIC server rejected the auth frame"

        # TCP round trip: SOCKS CONNECT -> TUIC stream -> echo server
        payload = b"hello-tuic"
        rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                                   "127.0.0.1", tcp_port, timeout=15)
        wr.write(payload)
        await wr.drain()
        got = await asyncio.wait_for(rd.readexactly(len(payload)), 15)
        assert got == payload
        # a second round trip proves the tunnel keeps framing correctly
        wr.write(b"second message")
        await wr.drain()
        assert await asyncio.wait_for(rd.readexactly(14), 15) == b"second message"
        wr.close()

        # UDP round trip: SOCKS UDP ASSOCIATE -> TUIC datagrams -> UDP echo
        await _socks_udp_roundtrip("127.0.0.1", eng.socks_port,
                                   "127.0.0.1", udp_port, b"ping-tuic",
                                   timeout=15)
    finally:
        eng.stop()
        server.close()
        tcp_echo.close()
        try:
            await tcp_echo.wait_closed()
        except Exception:
            pass
        udp_transport.close()


def test_e2e_loopback_tcp_and_udp():
    started = time.time()
    asyncio.run(_e2e())
    assert time.time() - started < 45
