"""MASQUE client — built-in implementation (aioquic, no binary needed).

Wire protocol (RFC 9110 CONNECT over HTTP/3 + RFC 9298 CONNECT-UDP):

* QUIC with ALPN ``h3``; all signalling is HTTP/3.
* **TCP** — for each proxied connection a NEW bidirectional QUIC stream
  carries an H3 request ``CONNECT`` with ``:authority: host:port`` (no
  body).  The server answers ``:status: 200`` and the stream becomes a raw
  TCP tunnel — plain H3 DATA frames flow both ways until either side
  half-closes.
* **UDP (CONNECT-UDP, RFC 9298)** — one extended CONNECT stream per
  destination: ``:protocol: connect-udp`` and a ``:path`` of
  ``<template>?target=<host>&target_port=<port>``.  After the ``:status:
  200`` response, datagrams flow as HTTP Datagrams carried in RFC 9297
  capsules on that stream: varint type ``0x00`` (HTTP_DATAGRAM) + varint
  length + context-id varint (we use 0) + UDP payload.  Incoming capsules
  are re-assembled across DATA chunks and unknown capsule types skipped.
* **Auth** — when the profile has credentials, a basic
  ``proxy-authorization`` header is added to *every* CONNECT request.
* No packet-level obfuscation is applied (the MasqueProfile carries no
  obfs settings — :class:`models.QuicObfsSettings` stays unused here).

The engine exposes a local SOCKS5 (TCP CONNECT + UDP ASSOCIATE) and can
dial its server through an upstream SOCKS5 (SOCKS UDP ASSOCIATE), so it
fits anywhere in a protocol chain.
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.events import ConnectionTerminated, QuicEvent, \
    StreamDataReceived

from ...log import get
from . import models as M
from .base import ProtocolEngine, ProtocolError, free_port
from .quicbase import (ObfsQuicProtocol, QuicEngineBase, build_quic_config,
                       connect_quic_via_socks)
from .socks_server import LoopThread

log = get("protocols.masque")

ALPN = ("h3",)

#: RFC 9297 capsule type for HTTP Datagrams
CAPSULE_HTTP_DATAGRAM = 0x00
#: the CONNECT-UDP context id we register (first/only flow)
UDP_CONTEXT_ID = 0
#: default CONNECT-UDP request URI (profile.template overrides it)
DEFAULT_UDP_TEMPLATE = "/masque"

_DIAL_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# QUIC varints (RFC 9000 §16) — shared by the capsule codec
# ---------------------------------------------------------------------------
def varint_put(value: int) -> bytes:
    if value < 1 << 6:
        return struct.pack("!B", value)
    if value < 1 << 14:
        return struct.pack("!H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def varint_get(buf: bytes, off: int) -> Tuple[int, int]:
    if off >= len(buf):
        raise ValueError("varint out of bounds")
    first = buf[off]
    length = 1 << (first >> 6)
    raw = buf[off:off + length]
    if len(raw) < length:
        raise ValueError("truncated varint")
    mask = {1: 0x3F, 2: 0x3FFF, 4: 0x3FFFFFFF, 8: 0x3FFFFFFFFFFFFFFF}[length]
    return int.from_bytes(raw, "big") & mask, off + length


# ---------------------------------------------------------------------------
# RFC 9297 capsule codec
# ---------------------------------------------------------------------------
def http_datagram_capsule(payload: bytes) -> bytes:
    """Wrap a UDP payload in an HTTP_DATAGRAM capsule (context id 0)."""
    body = varint_put(UDP_CONTEXT_ID) + bytes(payload)
    return varint_put(CAPSULE_HTTP_DATAGRAM) + varint_put(len(body)) + body


class CapsuleParser:
    """Incremental RFC 9297 capsule parser for one H3 request stream.

    ``feed`` accepts arbitrary chunks (a capsule may be split across DATA
    frames, several capsules may share one frame) and returns the UDP
    payloads of every complete HTTP_DATAGRAM capsule.  Unknown capsule
    types are parsed and skipped, per RFC 9297 §4.
    """

    def __init__(self) -> None:
        self._buf = b""

    def feed(self, data: bytes) -> List[bytes]:
        self._buf += bytes(data)
        out: List[bytes] = []
        while True:
            try:
                ctype, off = varint_get(self._buf, 0)
                clen, off = varint_get(self._buf, off)
            except ValueError:
                break                       # need more bytes for the header
            if len(self._buf) < off + clen:
                break                       # capsule body still incomplete
            value = self._buf[off:off + clen]
            self._buf = self._buf[off + clen:]
            if ctype != CAPSULE_HTTP_DATAGRAM or not value:
                continue                    # unknown/empty capsule: skip
            try:
                _ctx, coff = varint_get(value, 0)
            except ValueError:
                log.debug("dropping malformed http datagram capsule")
                continue
            out.append(value[coff:])
        return out


# ---------------------------------------------------------------------------
# H3 CONNECT header builders
# ---------------------------------------------------------------------------
def _authority(host: str, port: int) -> bytes:
    host = host or ""
    if ":" in host and not host.startswith("["):   # IPv6 literal
        host = "[%s]" % host
    return ("%s:%d" % (host, port)).encode("utf-8")


def basic_proxy_authorization(username: str, password: str
                              ) -> List[Tuple[bytes, bytes]]:
    """Basic ``proxy-authorization`` header (RFC 7617) for CONNECT."""
    if not username and not password:
        return []
    token = base64.b64encode(
        ("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
    return [(b"proxy-authorization", ("Basic " + token).encode("ascii"))]


def tcp_connect_headers(host: str, port: int, username: str = "",
                        password: str = "") -> List[Tuple[bytes, bytes]]:
    """H3 request headers for a plain RFC 9110 CONNECT (TCP tunnel).

    Per RFC 9114 §4.4 a plain CONNECT carries only ``:method`` and
    ``:authority`` — ``:scheme``/``:path`` must be omitted (servers such as
    aioquic reject the request otherwise).
    """
    headers = [
        (b":method", b"CONNECT"),
        (b":authority", _authority(host, port)),
    ]
    headers.extend(basic_proxy_authorization(username, password))
    return headers


def udp_connect_headers(template: str, host: str, port: int,
                        authority: bytes, username: str = "",
                        password: str = "") -> List[Tuple[bytes, bytes]]:
    """H3 request headers for a CONNECT-UDP (RFC 9298) extended CONNECT."""
    if not template:
        template = DEFAULT_UDP_TEMPLATE
    path = "%s?target=%s&target_port=%d" % (template, host, port)
    headers = [
        (b":method", b"CONNECT"),
        (b":protocol", b"connect-udp"),
        (b":scheme", b"https"),
        (b":path", path.encode("utf-8")),
        (b":authority", authority),
    ]
    headers.extend(basic_proxy_authorization(username, password))
    return headers


# ---------------------------------------------------------------------------
# the QUIC client protocol
# ---------------------------------------------------------------------------
class MasqueProtocol(ObfsQuicProtocol):
    """Client-side MASQUE protocol on one QUIC connection (H3)."""

    def __init__(self, quic, *, username: str = "", password: str = "",
                 udp_template: str = DEFAULT_UDP_TEMPLATE,
                 authority: bytes = b"",
                 dial_timeout: float = _DIAL_TIMEOUT) -> None:
        super().__init__(quic)
        self._h3 = H3Connection(quic)
        self._username = username
        self._password = password
        self._udp_template = udp_template or DEFAULT_UDP_TEMPLATE
        self._authority = authority
        self.dial_timeout = dial_timeout
        self.udp_enabled = True
        self._bridges: Dict[int, _TcpBridge] = {}
        self._udp_pending: Dict[int, asyncio.Future] = {}
        self._udp_sessions: Dict[int, _UdpSession] = {}

    # -- events -------------------------------------------------------------
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            try:
                h3_events = self._h3.handle_event(event)
            except Exception as exc:            # malformed H3 from the server
                self._fail_all("masque: bad HTTP/3 from server: %s" % exc)
                return
            for h3_event in h3_events:
                self._handle_h3_event(h3_event)
        elif isinstance(event, ConnectionTerminated):
            self._fail_all("connection terminated: %s"
                           % (event.reason_phrase or "code %d"
                              % event.error_code))
        # NB: no super() — H3 consumes every stream, the raw stream
        # reader/writer pairs of the base class are not used.

    def _fail_all(self, message: str) -> None:
        for bridge in list(self._bridges.values()):
            bridge.fail(message)
        for fut in list(self._udp_pending.values()):
            if not fut.done():
                fut.set_exception(ProtocolError(message))

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            status = ""
            for name, value in event.headers:
                if name == b":status":
                    status = value.decode("latin-1")
            bridge = self._bridges.get(event.stream_id)
            if bridge is not None:
                if status == "200":
                    self._resolve(bridge, True, "")
                else:
                    self._resolve(bridge, False,
                                  "masque TCP connect rejected (status %s)"
                                  % (status or "?"))
                return
            fut = self._udp_pending.get(event.stream_id)
            if fut is not None and not fut.done():
                if status == "200":
                    fut.set_result(True)
                else:
                    fut.set_exception(ProtocolError(
                        "masque UDP connect rejected (status %s)"
                        % (status or "?")))
            return
        if isinstance(event, DataReceived):
            bridge = self._bridges.get(event.stream_id)
            if bridge is not None:
                bridge.feed(event.data, event.stream_ended)
                return
            session = self._udp_sessions.get(event.stream_id)
            if session is not None:
                for payload in session.parser.feed(event.data):
                    try:
                        session.on_packet(payload)
                    except Exception:       # a bad handler must not kill us
                        log.exception("masque udp handler failed")
                if event.stream_ended:
                    self._udp_sessions.pop(event.stream_id, None)

    def _resolve(self, bridge: "_TcpBridge", ok: bool, message: str) -> None:
        if ok:
            bridge.ok = True
            if bridge.responded is not None and not bridge.responded.done():
                bridge.responded.set_result(True)
        else:
            self._bridges.pop(bridge.stream_id, None)
            bridge.fail(message)

    # -- TCP ----------------------------------------------------------------
    async def connect_tcp(self, host: str, port: int,
                          timeout: Optional[float] = None):
        """Open a proxied TCP connection; returns ``(reader, writer)``."""
        timeout = timeout or self.dial_timeout
        stream_id = self._quic.get_next_available_stream_id()
        bridge = _TcpBridge(self, stream_id)
        bridge.responded = asyncio.get_event_loop().create_future()
        self._bridges[stream_id] = bridge
        headers = tcp_connect_headers(host, port, self._username,
                                      self._password)
        try:
            self._h3.send_headers(stream_id, headers, end_stream=False)
            self.transmit()
        except Exception as exc:
            self._bridges.pop(stream_id, None)
            raise ProtocolError("masque: cannot send CONNECT: %s" % exc) \
                from None
        try:
            await asyncio.wait_for(bridge.responded, timeout)
        except asyncio.TimeoutError:
            self._bridges.pop(stream_id, None)
            raise ProtocolError("masque TCP connect timed out") from None
        except BaseException:
            self._bridges.pop(stream_id, None)
            raise
        if not bridge.ok:
            self._bridges.pop(stream_id, None)
            raise ProtocolError("masque TCP connect failed")
        return bridge.reader, bridge.writer

    # -- UDP (CONNECT-UDP) ----------------------------------------------------
    async def open_udp(self, host: str, port: int,
                       on_packet: Callable[[bytes], None],
                       timeout: Optional[float] = None
                       ) -> Tuple[Callable[[bytes], None], Callable[[], None]]:
        """Open a CONNECT-UDP session; returns ``(send, close)``."""
        timeout = timeout or self.dial_timeout
        stream_id = self._quic.get_next_available_stream_id()
        # register before awaiting: the 200 and the first capsules may land
        # in the same QUIC packet
        self._udp_sessions[stream_id] = _UdpSession(stream_id, CapsuleParser(),
                                                    on_packet)
        fut = asyncio.get_event_loop().create_future()
        self._udp_pending[stream_id] = fut
        headers = udp_connect_headers(self._udp_template, host, port,
                                      self._authority or _authority(host, port),
                                      self._username, self._password)
        try:
            self._h3.send_headers(stream_id, headers, end_stream=False)
            self.transmit()
        except Exception as exc:
            self._cleanup_udp(stream_id, end_stream=False)
            raise ProtocolError("masque: cannot send CONNECT-UDP: %s" % exc) \
                from None
        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._cleanup_udp(stream_id)
            raise ProtocolError("masque UDP connect timed out") from None
        except BaseException:
            self._cleanup_udp(stream_id)
            raise
        self._udp_pending.pop(stream_id, None)

        def send(payload: bytes) -> None:
            try:
                self._h3.send_data(stream_id, http_datagram_capsule(payload),
                                   end_stream=False)
                self.transmit()
            except Exception as exc:
                raise ProtocolError("masque UDP send failed: %s" % exc) \
                    from None

        def close() -> None:
            self._cleanup_udp(stream_id)

        return send, close

    def _cleanup_udp(self, stream_id: int, end_stream: bool = True) -> None:
        self._udp_sessions.pop(stream_id, None)
        self._udp_pending.pop(stream_id, None)
        if not end_stream:
            return
        try:
            self._h3.send_data(stream_id, b"", end_stream=True)
            self.transmit()
        except Exception:
            pass


class _UdpSession:
    """One CONNECT-UDP stream: capsule parser + downlink handler."""

    __slots__ = ("stream_id", "parser", "on_packet")

    def __init__(self, stream_id: int, parser: CapsuleParser,
                 on_packet: Callable[[bytes], None]) -> None:
        self.stream_id = stream_id
        self.parser = parser
        self.on_packet = on_packet


class _TcpBridge:
    """Bridges one H3 CONNECT tunnel stream to a reader/writer pair."""

    def __init__(self, proto: MasqueProtocol, stream_id: int) -> None:
        self._proto = proto
        self.stream_id = stream_id
        self.responded: Optional[asyncio.Future] = None
        self.ok = False
        self.reader = asyncio.StreamReader()
        self._closed = False
        self.writer = _H3StreamWriter(self)

    def feed(self, data: bytes, end_stream: bool) -> None:
        if data:
            self.reader.feed_data(data)
        if end_stream:
            self.reader.feed_eof()

    def fail(self, message: str) -> None:
        if self.responded is not None and not self.responded.done():
            self.responded.set_exception(ProtocolError(message))
        try:
            self.reader.feed_eof()
        except Exception:
            pass

    def stream_write(self, data: bytes, end: bool = False) -> None:
        self._proto._h3.send_data(self.stream_id, data, end_stream=end)
        self._proto.transmit()

    def stream_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._proto._h3.send_data(self.stream_id, b"", end_stream=True)
            self._proto.transmit()
        except Exception:
            pass
        try:
            self.reader.feed_eof()
        except Exception:
            pass


class _H3StreamWriter:
    """Minimal StreamWriter over an H3 tunnel stream (for SOCKS piping)."""

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
class MasqueEngine(QuicEngineBase, ProtocolEngine):
    """MASQUE behind a local SOCKS5 (TCP + UDP), binary-free."""

    proxy_kind = "masque"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True
    binary_name = ""

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self._protocol: Optional[MasqueProtocol] = None
        self._close_quic: Optional[Callable[[], None]] = None
        self._profile: Optional[M.MasqueProfile] = None

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.MasqueProfile, timeout: float = 20.0) -> None:
        if not isinstance(profile, M.MasqueProfile):
            raise ProtocolError("masque engine needs a MasqueProfile")
        if not profile.server:
            raise ProtocolError("masque: empty server address")
        self._profile = profile
        self.socks_port = free_port(self.socks_port or 10800)
        thread = LoopThread(name="proto-clean-masque")
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
        log.info("masque listening on socks://127.0.0.1:%d -> %s:%d",
                 self.socks_port, profile.server, profile.port)

    async def _open(self, profile: M.MasqueProfile) -> None:
        cfg = build_quic_config(profile.sni or profile.server, ALPN,
                                insecure=profile.insecure, idle_timeout=30.0)
        authority = _authority(profile.server, profile.port)

        def factory(quic, stream_handler=None):
            return MasqueProtocol(quic, username=profile.username,
                                  password=profile.password,
                                  udp_template=profile.template,
                                  authority=authority)

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

    async def _serve(self) -> None:
        from .socks_server import SocksServer
        self._socks_server = SocksServer("127.0.0.1", self.socks_port,
                                         self.make_dialer(),
                                         self.make_udp_dialer())
        await self._socks_server.serve()

    def _teardown_quic(self) -> None:
        closer, self._close_quic = self._close_quic, None
        self._protocol = None
        if closer is None:
            return
        thread = self._loop_thread
        if thread is not None:
            try:
                # run the closer on the engine's own loop — the QUIC
                # transport and its futures live there
                thread.run(self._close_on_loop(closer), timeout=3.0)
                return
            except Exception:
                pass
        try:
            closer()
        except Exception:
            pass

    async def _close_on_loop(self, closer) -> None:
        """Run the QUIC closer on the engine loop and give the
        CONNECTION_CLOSE handshake a moment to drain."""
        closer()
        await asyncio.sleep(0.25)

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
                raise ProtocolError("masque engine not connected")
            return await proto.connect_tcp(host, port)
        return dial

    def make_udp_dialer(self):
        async def udp_dial(host: str, port: int, on_packet):
            proto = self._protocol
            if proto is None:
                raise ProtocolError("masque engine not connected")
            send, close = await proto.open_udp(host, port, on_packet)
            return send, close
        return udp_dial

    def status(self) -> dict:
        st = super().status()
        prof = self._profile
        st["server"] = "%s:%d" % (prof.server, prof.port) if prof else ""
        st["udp"] = self._protocol is not None
        if prof:
            st["template"] = prof.template
        return st


def engine(profile: M.MasqueProfile, socks_port: int = 0) -> MasqueEngine:
    """Convenience factory used by the protocol registry."""
    return MasqueEngine(socks_port=socks_port)
