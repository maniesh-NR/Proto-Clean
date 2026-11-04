"""Hysteria 2 client — built-in implementation (aioquic, no binary needed).

Wire protocol (verified against apernet/hysteria ``core/internal/protocol``
and ``core/client``, the official implementation):

* QUIC with ALPN ``h3`` (the official client uses quic-go's HTTP/3
  transport for authentication; data streams are raw QUIC streams).
* **Auth** — H3 request on a client-initiated bidirectional stream:
  ``POST /auth`` with ``Hysteria-Auth`` (password), ``Hysteria-CC-RX``
  (requested downlink, 0 = auto) and ``Hysteria-Padding`` headers.
  ``:status: 233`` means OK; ``Hysteria-UDP: <true/false>`` reports UDP
  support.
* **TCP** — a raw bidirectional QUIC stream per connection:
  ``varint 0x401`` + ``varint addr_len`` + ``host:port`` + ``varint
  pad_len`` + padding; the server answers ``status(1)`` + ``varint
  msg_len`` + message + ``varint pad_len`` + padding, then the stream is
  a raw TCP tunnel.
* **UDP** — QUIC datagram frames:
  ``u32 session_id`` + ``u16 packet_id`` + ``u8 frag_id`` + ``u8
  frag_count`` + ``varint addr_len`` + ``host:port`` + payload.
* **Salamander obfuscation** — QUIC packets are wrapped per datagram:
  ``8-byte salt`` + payload XOR ``BLAKE2b-256(key + salt)`` (repeating
  32-byte key).  Applied under the QUIC layer, invisible to it.

The engine exposes a local SOCKS5 (TCP CONNECT + UDP ASSOCIATE) and can
dial its server through an upstream SOCKS5 (SOCKS UDP ASSOCIATE) so it
fits anywhere in a protocol chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import struct
import time
from typing import Callable, Dict, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (ConnectionTerminated, DatagramFrameReceived,
                                 QuicEvent, StreamDataReceived)

from ...log import get
from . import models as M
from .base import ProtocolEngine, ProtocolError, free_port
from .quicbase import (ObfsQuicProtocol, QuicEngineBase, build_quic_config,
                       check_pin_sha256, connect_quic_via_socks)
from .socks_server import LoopThread

log = get("protocols.hysteria2")

ALPN = ("h3",)
FRAME_TCP_REQUEST = 0x401
_AUTH_PATH = "/auth"
_MAX_ADDR = 2048
_MAX_PAD = 4096


# ---------------------------------------------------------------------------
# QUIC varints (RFC 9000 §16)
# ---------------------------------------------------------------------------
def quic_varint_put(value: int) -> bytes:
    if value < 1 << 6:
        return struct.pack("!B", value)
    if value < 1 << 14:
        return struct.pack("!H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def quic_varint_get(buf: bytes, off: int) -> Tuple[int, int]:
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
# salamander obfuscation (official spec)
# ---------------------------------------------------------------------------
class Salamander:
    """Per-datagram wrapper: ``[8-byte salt][payload ^ BLAKE2b-256(k+s)]``."""

    def __init__(self, key: str) -> None:
        self._key = (key or "").encode("utf-8")

    @staticmethod
    def _stream(key_bytes: bytes, salt: bytes) -> bytes:
        return hashlib.blake2b(key_bytes + salt, digest_size=32).digest()

    def wrap(self, data: bytes) -> bytes:
        salt = os.urandom(8)
        ks = self._stream(self._key, salt)
        return salt + bytes(a ^ ks[i % 32] for i, a in enumerate(data))

    def unwrap(self, data: bytes) -> bytes:
        if len(data) < 9:
            raise ProtocolError("salamander datagram too short")
        salt, payload = data[:8], data[8:]
        ks = self._stream(self._key, salt)
        return bytes(a ^ ks[i % 32] for i, a in enumerate(payload))


# ---------------------------------------------------------------------------
# the QUIC client protocol
# ---------------------------------------------------------------------------
class Hysteria2Protocol(ObfsQuicProtocol):
    """Client-side Hysteria 2 protocol on one QUIC connection."""

    def __init__(self, quic, *, udp_handler: Optional[Callable] = None,
                 auth_timeout: float = 15.0) -> None:
        super().__init__(quic)
        self._h3: Optional[H3Connection] = None
        self._auth_stream: Optional[int] = None
        self._auth_result: Optional[asyncio.Future] = None
        self._udp_handler = udp_handler
        self.auth_timeout = auth_timeout
        self.udp_enabled = False
        self._bridges: Dict[int, "_TcpBridge"] = {}
        self._udp_sessions: Dict[int, Callable[[bytes], None]] = {}
        self._udp_out: Dict[int, str] = {}       # session -> "host:port"
        self._session_seq = 0
        self._pkt_seq = 0

    # -- events -------------------------------------------------------------
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == self._auth_stream:
                self._handle_auth_stream(event)
            else:
                self._handle_tcp_stream(event)
        elif isinstance(event, DatagramFrameReceived):
            self._handle_udp_datagram(event.data)
        elif isinstance(event, ConnectionTerminated):
            self._fail_all("connection terminated: %s"
                           % (event.reason_phrase or "code %d"
                              % event.error_code))
        # NOTE: deliberately NO super().quic_event_received(event) here —
        # the aioquic base implementation auto-creates a QuicStreamAdapter
        # for every incoming stream and hands it to stream_handler; with no
        # handler the throwaway writer is garbage-collected and its __del__
        # sends a stray FIN that kills the live tunnel.

    def _fail_all(self, message: str) -> None:
        if self._auth_result is not None and not self._auth_result.done():
            self._auth_result.set_exception(ProtocolError(message))
        for bridge in list(self._bridges.values()):
            bridge.fail(message)

    # -- auth ---------------------------------------------------------------
    async def authenticate(self, auth: str, rx: int = 0,
                           timeout: Optional[float] = None) -> None:
        """H3 ``POST /auth``; raises ProtocolError unless :status is 233."""
        timeout = timeout or self.auth_timeout
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        stream_id = self._quic.get_next_available_stream_id()
        padding = "".join(random.choice("abcdefgh") for _ in range(64))
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":path", _AUTH_PATH.encode()),
            (b":authority", b"hysteria"),
            (b"hysteria-auth", auth.encode("utf-8")),
            (b"hysteria-cc-rx", str(rx).encode()),
            (b"hysteria-padding", padding.encode()),
        ]
        self._auth_result = asyncio.get_event_loop().create_future()
        self._auth_stream = stream_id
        self._h3.send_headers(stream_id, headers, end_stream=True)
        self.transmit()
        try:
            await asyncio.wait_for(self._auth_result, timeout)
        except asyncio.TimeoutError:
            raise ProtocolError("hysteria2 auth timed out") from None

    def _handle_auth_stream(self, event: StreamDataReceived) -> None:
        try:
            for h3_event in self._h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    status = ""
                    for name, value in h3_event.headers:
                        if name == b":status":
                            status = value.decode("latin-1")
                        elif name == b"hysteria-udp":
                            self.udp_enabled = value.lower() in (b"true", b"1")
                    if self._auth_result and not self._auth_result.done():
                        if status == "233":
                            self._auth_result.set_result(True)
                        else:
                            self._auth_result.set_exception(ProtocolError(
                                "hysteria2 auth rejected (status %s)"
                                % (status or "?")))
        except Exception as exc:                      # malformed H3
            if self._auth_result and not self._auth_result.done():
                self._auth_result.set_exception(ProtocolError(
                    "hysteria2 auth failed: %s" % exc))

    # -- TCP ----------------------------------------------------------------
    async def connect_tcp(self, host: str, port: int,
                          timeout: float = 10.0):
        """Open a proxied TCP connection; returns ``(reader, writer)``."""
        addr = "%s:%d" % (host, port)
        if len(addr.encode()) > _MAX_ADDR:
            raise ProtocolError("hysteria2: target address too long")
        stream_id = self._quic.get_next_available_stream_id()
        bridge = _TcpBridge(self, stream_id)
        self._bridges[stream_id] = bridge
        padding = os.urandom(random.randrange(64, 512))
        request = (quic_varint_put(FRAME_TCP_REQUEST)
                   + quic_varint_put(len(addr.encode()))
                   + addr.encode()
                   + quic_varint_put(len(padding)) + padding)
        bridge.responded = asyncio.get_event_loop().create_future()
        self._quic.send_stream_data(stream_id, request, end_stream=False)
        self.transmit()
        try:
            await asyncio.wait_for(bridge.responded, timeout)
        except asyncio.TimeoutError:
            self._bridges.pop(stream_id, None)
            raise ProtocolError("hysteria2 TCP connect timed out") from None
        if not bridge.ok:
            self._bridges.pop(stream_id, None)
            raise ProtocolError("hysteria2 TCP connect failed: %s"
                                % bridge.message)
        return bridge.reader, bridge.writer

    def _handle_tcp_stream(self, event: StreamDataReceived) -> None:
        bridge = self._bridges.get(event.stream_id)
        if bridge is None:
            return
        bridge.feed(event.data, event.end_stream)

    # -- UDP ----------------------------------------------------------------
    def open_udp(self, host: str, port: int,
                 on_packet: Callable[[bytes], None]
                 ) -> Tuple[Callable[[bytes], None], Callable[[], None]]:
        """Register a UDP session; returns ``(send, close)``."""
        if not self.udp_enabled:
            raise ProtocolError("hysteria2 server has UDP disabled")
        self._session_seq += 1
        session_id = self._session_seq & 0xFFFFFFFF
        addr = "%s:%d" % (host, port)
        self._udp_sessions[session_id] = on_packet
        self._udp_out[session_id] = addr

        def send(payload: bytes) -> None:
            self._pkt_seq = (self._pkt_seq + 1) & 0xFFFF
            msg = (struct.pack("!IHBB", session_id, self._pkt_seq, 0, 1)
                   + quic_varint_put(len(addr.encode())) + addr.encode()
                   + bytes(payload))
            if len(msg) > 65535:
                raise ProtocolError("hysteria2 UDP payload too large")
            self._quic.send_datagram_frame(msg)
            self.transmit()
            # QUIC datagrams are unreliable and the packet builder may
            # defer them (congestion window / padding rules); keep
            # transmitting briefly so a one-shot datagram still leaves
            # the host instead of stranding until the next event.
            if self._quic._datagrams_pending:
                asyncio.ensure_future(self._flush_datagrams())

        def close() -> None:
            self._udp_sessions.pop(session_id, None)
            self._udp_out.pop(session_id, None)

        return send, close

    async def _flush_datagrams(self) -> None:
        for _ in range(40):                     # ~2 s worst case
            if not self._quic._datagrams_pending:
                return
            self.transmit()
            await asyncio.sleep(0.05)
            print("DBG-HY2-SENT sess=%d pending=%d" % (
                session_id, len(self._quic._datagrams_pending)), flush=True)

        def close() -> None:
            self._udp_sessions.pop(session_id, None)
            self._udp_out.pop(session_id, None)

        print("DBG-OPEN-UDP-REGISTERED sess=%d udp=%s" % (session_id,
              self.udp_enabled), flush=True)
        return send, close

    def _handle_udp_datagram(self, data: bytes) -> None:
        try:
            session_id, pkt_id, frag_id, frag_count = struct.unpack_from(
                "!IHBB", data, 0)
            addr_len, off = quic_varint_get(data, 8)
            addr = data[off:off + addr_len].decode("utf-8", "replace")
            payload = data[off + addr_len:]
        except (ValueError, struct.error):
            log.debug("dropping malformed hysteria2 UDP datagram (%d bytes)",
                      len(data))
            return
        if frag_id != 0 or frag_count != 1:
            log.debug("dropping fragmented hysteria2 UDP datagram")
            return
        handler = self._udp_sessions.get(session_id)
        if handler is not None:
            handler(payload)


class _TcpBridge:
    """Bridges one raw QUIC stream to an asyncio reader/writer pair."""

    def __init__(self, proto: Hysteria2Protocol, stream_id: int) -> None:
        self._proto = proto
        self.stream_id = stream_id
        self.responded: Optional[asyncio.Future] = None
        self.ok = False
        self.message = ""
        self._resp_buf = b""
        self._resp_done = False
        self.reader = asyncio.StreamReader()
        self._closed = False
        self.writer = _QuicStreamWriter(self)

    # response parsing (status + varint msg + varint pad)
    def feed(self, data: bytes, end_stream: bool) -> None:
        if not self._resp_done:
            self._resp_buf += data
            try:
                if len(self._resp_buf) < 1:
                    return
                status = self._resp_buf[0]
                msg_len, off = quic_varint_get(self._resp_buf, 1)
                if len(self._resp_buf) < off + msg_len:
                    return
                msg = self._resp_buf[off:off + msg_len]
                off += msg_len
                pad_len, off = quic_varint_get(self._resp_buf, off)
                if len(self._resp_buf) < off + pad_len:
                    return
                self.ok = status == 0
                self.message = msg.decode("utf-8", "replace")
                self._resp_done = True
                rest = self._resp_buf[off + pad_len:]
                if self.responded and not self.responded.done():
                    self.responded.set_result(self.ok)
                if rest:
                    self.reader.feed_data(rest)
                if end_stream:
                    self.reader.feed_eof()
                return
            except ValueError as exc:
                self.fail("bad hysteria2 TCP response: %s" % exc)
                return
        if data:
            self.reader.feed_data(data)
        if end_stream:
            self.reader.feed_eof()

    def fail(self, message: str) -> None:
        if self.responded is not None and not self.responded.done():
            self.responded.set_exception(ProtocolError(message))
        self.reader.feed_eof()

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
class Hysteria2Engine(QuicEngineBase, ProtocolEngine):
    """Hysteria 2 behind a local SOCKS5 (TCP + UDP), binary-free."""

    proxy_kind = "hysteria2"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True
    binary_name = ""

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self._protocol: Optional[Hysteria2Protocol] = None
        self._close_quic: Optional[Callable[[], None]] = None
        self._profile: Optional[M.Hysteria2Profile] = None

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.Hysteria2Profile, timeout: float = 20.0) -> None:
        if not isinstance(profile, M.Hysteria2Profile):
            raise ProtocolError("hysteria2 engine needs a Hysteria2Profile")
        if not profile.server:
            raise ProtocolError("hysteria2: empty server address")
        if profile.obfs and profile.obfs != "salamander":
            raise ProtocolError("hysteria2: unknown obfs %r" % profile.obfs)
        if profile.obfs == "salamander" and not profile.obfs_password:
            raise ProtocolError("hysteria2: salamander needs obfs-password")
        self._profile = profile
        self.socks_port = free_port(self.socks_port or 10800)
        thread = LoopThread(name="proto-clean-hy2")
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
        log.info("hysteria2 listening on socks://127.0.0.1:%d -> %s:%d%s",
                 self.socks_port, profile.server, profile.port,
                 " (salamander)" if profile.obfs else "")

    async def _open(self, profile: M.Hysteria2Profile) -> None:
        cfg = build_quic_config(profile.sni or profile.server, ALPN,
                                insecure=profile.insecure,
                                pin_sha256=profile.pin_sha256,
                                idle_timeout=30.0,
                                max_datagram_frame_size=65535)
        obfs = Salamander(profile.obfs_password) if profile.obfs else None
        udp_handler = None  # sessions registered dynamically via open_udp

        def factory(quic, stream_handler=None):
            proto = Hysteria2Protocol(quic, udp_handler=udp_handler)
            if obfs is not None:
                # obfuscation must apply from the very first datagram
                # (including the QUIC Initial), so bind it at construction
                proto.wrap = obfs.wrap          # type: ignore[method-assign]
                proto.unwrap = obfs.unwrap      # type: ignore[method-assign]
            return proto

        if self.upstream_socks[1]:
            proto, closer = await connect_quic_via_socks(
                cfg, factory, (profile.server, profile.port),
                self.upstream_socks, obfs=None)
        else:
            cm = connect(profile.server, profile.port, configuration=cfg,
                         create_protocol=factory, wait_connected=True)
            proto = await cm.__aenter__()

            async def _aclose() -> None:      # runs on the engine's loop
                await cm.__aexit__(None, None, None)
            closer = _aclose
        self._protocol = proto
        self._close_quic = closer
        await proto.authenticate(profile.auth or "",
                                 rx=profile.down_mbps or 0)
        if profile.pin_sha256:
            self._verify_pin(proto, profile.pin_sha256)

    def _verify_pin(self, proto: Hysteria2Protocol, pin: str) -> None:
        cert = getattr(getattr(proto._quic, "tls", None),
                       "_peer_certificate", None)
        if cert is None:
            log.warning("hysteria2: TLS stack did not expose the peer "
                        "certificate; skipping pin check")
            return
        der = cert.public_bytes(_der_encoding())
        if not check_pin_sha256(der, pin):
            raise ProtocolError("hysteria2: server certificate does not "
                                "match pinSHA256")

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
        try:
            if self._loop_thread is not None:
                # the QUIC connection lives on the engine's loop — close it
                # there (a bare call would raise RuntimeError off-loop)
                self._loop_thread.run(closer(), timeout=3.0)
            else:
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
                raise ProtocolError("hysteria2 engine not connected")
            return await proto.connect_tcp(host, port)
        return dial

    def make_udp_dialer(self):
        async def udp_dialer(host: str, port: int, on_packet):
            proto = self._protocol
            if proto is None:
                raise ProtocolError("hysteria2 engine not connected")
            return proto.open_udp(host, port, on_packet)
        return udp_dialer

    def status(self) -> dict:
        st = super().status()
        prof = self._profile
        st["server"] = "%s:%d" % (prof.server, prof.port) if prof else ""
        st["udp"] = bool(self._protocol and self._protocol.udp_enabled)
        if prof and prof.obfs:
            st["obfs"] = prof.obfs
        return st

    def new_identity(self) -> None:
        """Close and reopen the QUIC connection (fresh session)."""
        if self._loop_thread is None or self._profile is None:
            return
        profile = self._profile
        self._teardown_quic()
        self._loop_thread.run(self._open(profile), timeout=20.0)


def _der_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def engine(profile: M.Hysteria2Profile, socks_port: int = 0
           ) -> Hysteria2Engine:
    """Convenience factory used by the protocol registry."""
    return Hysteria2Engine(socks_port=socks_port)
