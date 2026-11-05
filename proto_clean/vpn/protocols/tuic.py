"""TUIC v5 client — built-in implementation (aioquic, no binary needed).

Wire protocol (per EAimTY/tuic ``SPEC.md``, TUIC v5; all integers
big-endian, every frame starts with the version byte ``0x05``):

* QUIC with the profile's ALPN (default ``h3``).  Commands travel on QUIC
  *streams*; UDP relay uses QUIC *datagram* frames.  Authentication and
  Connect have **no response** — fire and forget (the server closes the
  connection on failure).
* **Authenticate (0x00)** — client-initiated bidirectional stream (the
  first one, stream 0): ``[05][00][UUID 16 bytes][TOKEN 32 bytes]``.
  The v5 TOKEN is derived from the password via the TLS keying-material
  exporter, which aioquic does not expose — so the built-in engine
  requires ``profile.token_hex`` (64 hex chars).  Password-only profiles
  should use the lantern-box engine.
* **Connect (0x01)** — a NEW bidirectional stream per TCP connection:
  ``[05][01][ADDR]`` where ADDR is ``[ATYP][addr][port]`` (ATYP ``0x00``
  domain with a 1-byte length, ``0x01`` IPv4, ``0x02`` IPv6, then a
  2-byte port).  After the header the stream is a raw TCP tunnel in both
  directions (the server may send data before the client finishes).
* **Packet (0x02)** — QUIC DATAGRAM frame:
  ``[05][02][ASSOC_ID u16][PKT_ID u16][FRAG_TOTAL u8][FRAG_ID u8]
  [SIZE u16][ADDR][payload]``.  Client→server ADDR is the destination,
  server→client it is the source.  Only unfragmented packets are
  exchanged (FRAG_TOTAL=1, FRAG_ID=0); oversize payloads are dropped.
* **Dissociate (0x03)** — QUIC DATAGRAM frame: ``[05][03][ASSOC_ID]``.

The engine exposes a local SOCKS5 (TCP CONNECT + UDP ASSOCIATE) and can
dial its server through an upstream SOCKS5, so it fits anywhere in a
protocol chain.
"""

from __future__ import annotations

import asyncio
import socket as _socket
import struct
import time
import uuid as _uuid
from typing import Callable, Dict, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.quic.events import (ConnectionTerminated, DatagramFrameReceived,
                                 QuicEvent, StreamDataReceived)

from ...log import get
from . import models as M
from .base import ProtocolEngine, ProtocolError, free_port
from .quicbase import (ObfsQuicProtocol, QuicEngineBase, build_quic_config,
                       connect_quic_via_socks, enable_large_datagrams)
from .socks_server import LoopThread

log = get("protocols.tuic")

VER = 0x05                       # TUIC version byte
CMD_AUTHENTICATE = 0x00
CMD_CONNECT = 0x01
CMD_PACKET = 0x02
CMD_DISSOCIATE = 0x03

ATYP_DOMAIN = 0x00               # TUIC's own numbering (differs from SOCKS5)
ATYP_IPV4 = 0x01
ATYP_IPV6 = 0x02

CONGESTIONS = ("bbr", "cubic", "new_reno")


# ---------------------------------------------------------------------------
# address encoding: [ATYP][addr][port BE u16]
# ---------------------------------------------------------------------------
def parse_addr(host: str, port: int) -> bytes:
    """Encode ``host:port`` as a TUIC v5 ADDR (domain form for names)."""
    try:
        packed = _socket.inet_aton(host)
        return struct.pack("!B", ATYP_IPV4) + packed + struct.pack("!H", port)
    except OSError:
        pass
    try:
        packed = _socket.inet_pton(_socket.AF_INET6, host)
        return struct.pack("!B", ATYP_IPV6) + packed + struct.pack("!H", port)
    except (OSError, ValueError):
        pass
    raw = host.encode("idna")
    if not 0 < len(raw) <= 255:
        raise ProtocolError("tuic: bad target host %r" % host)
    return (struct.pack("!BB", ATYP_DOMAIN, len(raw)) + raw
            + struct.pack("!H", port))


def read_addr(buf: bytes, off: int) -> Tuple[str, int, int]:
    """Parse a TUIC v5 ADDR at ``off``. Returns (host, port, bytes used)."""
    atyp = buf[off]
    if atyp == ATYP_IPV4:
        host = _socket.inet_ntoa(buf[off + 1:off + 5])
        port = struct.unpack("!H", buf[off + 5:off + 7])[0]
        return host, port, 7
    if atyp == ATYP_IPV6:
        host = _socket.inet_ntop(_socket.AF_INET6, buf[off + 1:off + 17])
        port = struct.unpack("!H", buf[off + 17:off + 19])[0]
        return host, port, 19
    if atyp == ATYP_DOMAIN:
        ln = buf[off + 1]
        # strict idna (py3's idna codec rejects errors="replace"); callers
        # catch ValueError for hostile bytes
        host = buf[off + 2:off + 2 + ln].decode("idna")
        port = struct.unpack("!H", buf[off + 2 + ln:off + 4 + ln])[0]
        return host, port, 2 + ln + 2
    raise ProtocolError("bad TUIC address type %d" % atyp)


# ---------------------------------------------------------------------------
# frame builders / parsers (module-level so tests can pin the wire format)
# ---------------------------------------------------------------------------
def build_auth_frame(uuid_str: str, token: bytes) -> bytes:
    """``[05][00][UUID 16][TOKEN 32]`` — the Authenticate command."""
    uid = _uuid.UUID(uuid_str).bytes
    return struct.pack("!BB", VER, CMD_AUTHENTICATE) + uid + token


def build_connect_frame(host: str, port: int) -> bytes:
    """``[05][01][ADDR]`` — the Connect command (raw TCP tunnel follows)."""
    return struct.pack("!BB", VER, CMD_CONNECT) + parse_addr(host, port)


def build_packet_frame(assoc_id: int, pkt_id: int, host: str, port: int,
                       payload: bytes) -> bytes:
    """``[05][02][ASSOC][PKT][1][0][SIZE][ADDR][payload]`` (unfragmented)."""
    return (struct.pack("!BBHHBBH", VER, CMD_PACKET, assoc_id, pkt_id,
                        1, 0, len(payload))
            + parse_addr(host, port) + bytes(payload))


def build_dissociate_frame(assoc_id: int) -> bytes:
    """``[05][03][ASSOC]`` — release a UDP association."""
    return struct.pack("!BBH", VER, CMD_DISSOCIATE, assoc_id)


def parse_packet_frame(data: bytes) -> Tuple[int, int, str, int, bytes]:
    """Parse an incoming Packet datagram.

    Returns ``(assoc_id, pkt_id, host, port, payload)``; raises ValueError
    for anything but a well-formed unfragmented TUIC v5 packet frame.
    """
    if len(data) < 10:
        raise ValueError("TUIC packet frame too short")
    ver, cmd = data[0], data[1]
    if ver != VER or cmd != CMD_PACKET:
        raise ValueError("not a TUIC packet frame")
    assoc_id, pkt_id = struct.unpack_from("!HH", data, 2)
    frag_total, frag_id = data[6], data[7]
    if frag_total != 1 or frag_id != 0:
        raise ValueError("fragmented TUIC packets not supported")
    size = struct.unpack_from("!H", data, 8)[0]
    host, port, used = read_addr(data, 10)
    payload = data[10 + used:10 + used + size]
    if len(payload) != size:
        raise ValueError("TUIC packet payload truncated")
    return assoc_id, pkt_id, host, port, payload


# ---------------------------------------------------------------------------
# the QUIC client protocol
# ---------------------------------------------------------------------------
class TuicProtocol(ObfsQuicProtocol):
    """Client-side TUIC v5 protocol on one QUIC connection."""

    def __init__(self, quic) -> None:
        super().__init__(quic)
        self._bridges: Dict[int, "_TcpBridge"] = {}
        self._udp_sessions: Dict[int, Callable[[bytes], None]] = {}
        self._assoc_seq = 0
        self._pkt_seq = 0
        self._terminated: Optional[str] = None

    # -- events -------------------------------------------------------------
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            bridge = self._bridges.get(event.stream_id)
            if bridge is not None:
                bridge.feed(event.data, event.end_stream)
            # NOTE: do NOT delegate stream data to the base class — its
            # implementation wires a throwaway StreamWriter per incoming
            # stream, whose __del__ immediately FINs the stream on
            # aioquic >= 1.0, truncating every tunnel.
            return
        if isinstance(event, DatagramFrameReceived):
            self._handle_udp_datagram(event.data)
        elif isinstance(event, ConnectionTerminated):
            self._terminated = ("connection terminated: %s"
                                % (event.reason_phrase or "code %d"
                                   % event.error_code))
            self._fail_all(self._terminated)
        # NOTE: no super() fallthrough — the aioquic base auto-creates a
        # QuicStreamAdapter per incoming stream whose GC'd writer sends a
        # stray FIN on the live tunnel (see hysteria2.py).

    def _fail_all(self, message: str) -> None:
        for bridge in list(self._bridges.values()):
            bridge.fail(message)

    # -- auth ----------------------------------------------------------------
    async def authenticate(self, profile: M.TuicProfile,
                           timeout: Optional[float] = None) -> None:
        """Send the Authenticate command on stream 0 (fire-and-forget).

        There is no success response; the caller must already have waited
        for the QUIC handshake (``connect(..., wait_connected=True)``).
        """
        try:
            token = bytes.fromhex(profile.token_hex)
            frame = build_auth_frame(profile.uuid, token)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ProtocolError("tuic auth: %s" % exc) from None
        stream_id = self._quic.get_next_available_stream_id()  # first == 0
        self._quic.send_stream_data(stream_id, frame, end_stream=True)
        self.transmit()
        await asyncio.sleep(0.05)   # give the frame a moment to leave

    # -- TCP -----------------------------------------------------------------
    async def connect_tcp(self, host: str, port: int,
                          timeout: float = 10.0):
        """Open a proxied TCP connection; returns ``(reader, writer)``.

        The Connect command has no response — the stream becomes a raw
        tunnel right after the header, so this returns immediately.
        """
        if self._terminated is not None:
            raise ProtocolError("tuic " + self._terminated)
        try:
            request = build_connect_frame(host, port)
        except ProtocolError:
            raise
        stream_id = self._quic.get_next_available_stream_id()
        bridge = _TcpBridge(self, stream_id)
        self._bridges[stream_id] = bridge
        self._quic.send_stream_data(stream_id, request, end_stream=False)
        self.transmit()
        await asyncio.sleep(0)
        return bridge.reader, bridge.writer

    # -- UDP -----------------------------------------------------------------
    def open_udp(self, host: str, port: int,
                 on_packet: Callable[[bytes], None]
                 ) -> Tuple[Callable[[bytes], None], Callable[[], None]]:
        """Register a UDP association; returns ``(send, close)``."""
        # full-size inner packets (chained hops, 1200-byte UDP datagrams)
        # need a larger 1-RTT packet budget than the default handshake one
        enable_large_datagrams(self)
        self._assoc_seq = (self._assoc_seq + 1) & 0xFFFF
        assoc_id = self._assoc_seq
        self._udp_sessions[assoc_id] = on_packet

        def send(payload: bytes) -> None:
            payload = bytes(payload)
            if len(payload) > 0xFFFF:
                log.debug("dropping oversize TUIC UDP payload (%d bytes)",
                          len(payload))
                return
            self._pkt_seq = (self._pkt_seq + 1) & 0xFFFF
            msg = build_packet_frame(assoc_id, self._pkt_seq, host, port,
                                     payload)
            self._quic.send_datagram_frame(msg)
            self.transmit()

        def close() -> None:
            self._udp_sessions.pop(assoc_id, None)
            try:
                self._quic.send_datagram_frame(
                    build_dissociate_frame(assoc_id))
                self.transmit()
            except Exception:
                pass

        return send, close

    def _handle_udp_datagram(self, data: bytes) -> None:
        if len(data) < 2 or data[0] != VER:
            return
        cmd = data[1]
        if cmd == CMD_PACKET:
            try:
                assoc_id, _pkt_id, _host, _port, payload = \
                    parse_packet_frame(data)
            except (ValueError, ProtocolError, IndexError):
                log.debug("dropping malformed TUIC UDP datagram")
                return
            handler = self._udp_sessions.get(assoc_id)
            if handler is not None:
                handler(payload)
        elif cmd == CMD_DISSOCIATE and len(data) >= 4:
            assoc_id = struct.unpack("!H", data[2:4])[0]
            self._udp_sessions.pop(assoc_id, None)


class _TcpBridge:
    """Bridges one raw QUIC stream (after the Connect header) to an
    asyncio reader/writer pair — no response phase, bytes flow freely."""

    def __init__(self, proto: TuicProtocol, stream_id: int) -> None:
        self._proto = proto
        self.stream_id = stream_id
        self.reader = asyncio.StreamReader()
        self._closed = False
        self.writer = _QuicStreamWriter(self)

    def feed(self, data: bytes, end_stream: bool) -> None:
        if self._closed:
            return
        if data:
            self.reader.feed_data(data)
        if end_stream:
            self.reader.feed_eof()

    def fail(self, message: str) -> None:
        log.debug("tuic stream %d failed: %s", self.stream_id, message)
        try:
            self.reader.feed_eof()
        except Exception:
            pass

    def stream_write(self, data: bytes, end: bool = False) -> None:
        self._proto._quic.send_stream_data(self.stream_id, data, end_stream=end)
        self._proto.transmit()

    def stream_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._proto._quic.send_stream_data(self.stream_id, b"", end_stream=True)
            self._proto.transmit()
        except Exception:
            pass
        try:
            self.reader.feed_eof()
        except Exception:
            pass


class _QuicStreamWriter:
    """Minimal StreamWriter over a QUIC stream (for the SOCKS front-end)."""

    def __init__(self, bridge: _TcpBridge) -> None:
        self._bridge = bridge

    def write(self, data: bytes) -> None:
        if data:
            self._bridge.stream_write(bytes(data))

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self._bridge.stream_close()

    def is_closing(self) -> bool:
        return self._bridge._closed

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------
class TuicEngine(QuicEngineBase, ProtocolEngine):
    """TUIC v5 behind a local SOCKS5 (TCP + UDP), binary-free."""

    proxy_kind = "tuic"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True
    binary_name = ""

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self._protocol: Optional[TuicProtocol] = None
        self._close_quic: Optional[Callable[[], None]] = None
        self._profile: Optional[M.TuicProfile] = None

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.TuicProfile, timeout: float = 20.0) -> None:
        if not isinstance(profile, M.TuicProfile):
            raise ProtocolError("tuic engine needs a TuicProfile")
        if not profile.server:
            raise ProtocolError("tuic: empty server address")
        try:
            _uuid.UUID(str(profile.uuid))
        except (ValueError, AttributeError, TypeError):
            raise ProtocolError("tuic: invalid uuid %r"
                                % (profile.uuid,)) from None
        if profile.congestion not in CONGESTIONS:
            raise ProtocolError("tuic: unknown congestion control %r"
                                % profile.congestion)
        if not profile.token_hex:
            raise ProtocolError(
                "TUIC v5 needs token_hex (TLS exporter token) with the "
                "built-in engine — use the lantern-box engine for password "
                "auth")
        try:
            token = bytes.fromhex(profile.token_hex)
        except ValueError:
            raise ProtocolError(
                "tuic: token_hex must be 64 hex characters") from None
        if len(token) != 32:
            raise ProtocolError("tuic: token_hex must decode to 32 bytes")
        self._profile = profile
        self.socks_port = free_port(self.socks_port or 10800)
        thread = LoopThread(name="proto-clean-tuic")
        self._loop_thread = thread
        try:
            thread.run(self._open(profile), timeout=max(timeout, 20.0))
            thread.run(self._serve(), timeout=10.0)
        except BaseException:
            self._teardown_quic()
            thread.stop()
            self._loop_thread = None
            raise
        self._server = thread
        self._started_at = time.time()
        log.info("tuic listening on socks://127.0.0.1:%d -> %s:%d (%s)",
                 self.socks_port, profile.server, profile.port,
                 profile.congestion)

    async def _open(self, profile: M.TuicProfile) -> None:
        alpn = tuple(a.strip() for a in profile.alpn.split(",") if a.strip())
        cfg = build_quic_config(profile.sni or profile.server, alpn,
                                insecure=profile.allow_insecure,
                                max_datagram_frame_size=65535)
        # aioquic only ships cubic/reno; BBR keeps the library default
        cc = {"cubic": "cubic", "new_reno": "reno"}.get(profile.congestion)
        if cc:
            cfg.congestion_control_algorithm = cc
        else:
            log.debug("tuic: %s congestion not available in aioquic; "
                      "using library default", profile.congestion)

        def factory(quic, stream_handler=None):
            # aioquic >=1.0 passes stream_handler= to create_protocol
            return TuicProtocol(quic)

        if self.upstream_socks[1]:
            proto, closer = await connect_quic_via_socks(
                cfg, factory, (profile.server, profile.port),
                self.upstream_socks, obfs=None)
        else:
            cm = connect(profile.server, profile.port, configuration=cfg,
                         create_protocol=factory, wait_connected=True)
            proto = await cm.__aenter__()
            closer = lambda: asyncio.ensure_future(  # noqa: E731
                cm.__aexit__(None, None, None))
        self._protocol = proto
        self._close_quic = closer
        await proto.authenticate(profile)

    async def _serve(self) -> None:
        from .socks_server import SocksServer
        self._socks_server = SocksServer("127.0.0.1", self.socks_port,
                                         self.make_dialer(),
                                         self.make_udp_dialer())
        await self._socks_server.serve()

    def _teardown_quic(self) -> None:
        closer, self._close_quic = self._close_quic, None
        self._protocol = None
        if closer is not None:
            try:
                closer()
            except Exception:
                pass

    def stop(self, timeout: float = 5.0) -> None:
        self._teardown_quic()
        thread, self._loop_thread = self._loop_thread, None
        server = getattr(self, "_socks_server", None)
        self._server = None
        if thread is not None and server is not None:
            try:
                thread.run(server.shutdown(), timeout=3.0)
            except Exception:
                pass
        if thread is not None:
            thread.stop()
        self._started_at = 0.0
        super().stop(timeout)

    @property
    def running(self) -> bool:
        return self._loop_thread is not None and self._protocol is not None

    # -- dialers ------------------------------------------------------------
    def make_dialer(self):
        async def dial(host: str, port: int):
            proto = self._protocol
            if proto is None:
                raise ProtocolError("tuic engine not connected")
            return await proto.connect_tcp(host, port)
        return dial

    def make_udp_dialer(self):
        async def udp_dial(host: str, port: int, on_packet):
            proto = self._protocol
            if proto is None:
                raise ProtocolError("tuic engine not connected")
            return proto.open_udp(host, port, on_packet)
        return udp_dial

    def status(self) -> dict:
        st = super().status()
        prof = self._profile
        if prof:
            st["server"] = "%s:%d" % (prof.server, prof.port)
            st["congestion"] = prof.congestion
        return st


def engine(profile: M.TuicProfile, socks_port: int = 0) -> TuicEngine:
    """Convenience factory used by the protocol registry."""
    return TuicEngine(socks_port=socks_port)
