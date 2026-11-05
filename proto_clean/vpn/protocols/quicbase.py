"""Shared QUIC plumbing for the built-in protocol engines.

* :class:`QuicEngineBase` — the LoopThread + SocksServer skeleton used by
  the Hysteria 2 / TUIC / MASQUE engines, with an upstream-SOCKS5 hook
  (QUIC datagrams tunnelled through a SOCKS5 UDP relay — this is how the
  chain builder puts, say, Hysteria 2 behind a VLESS hop) and an optional
  packet-obfuscation hook (:mod:`.quicobfs`).
* :func:`build_quic_config` — QuicConfiguration defaults shared by all
  engines (ALPN, SNI, insecure mode, certificate pinning, datagram size).
* :func:`open_socks5_udp` — SOCKS5 UDP ASSOCIATE client used for the
  upstream leg.

Engines own the wire protocol on top; nothing here knows about Hysteria
frames or capsules.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from typing import Awaitable, Callable, Optional, Tuple

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent

from ...log import get
from .base import ProtocolError, free_port
from .socks_server import (ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, SocksServer,
                           LoopThread, build_socks5_address, socks5_dial)

log = get("protocols.quic")

#: send/recv packet transform: ``(bytes) -> bytes`` (send) and
#: ``(bytes) -> bytes`` (recv); identity when no obfuscation is used
PacketWrapper = Callable[[bytes], bytes]


def build_quic_config(server_name: str, alpn: Tuple[str, ...],
                      insecure: bool = False,
                      pin_sha256: str = "",
                      idle_timeout: float = 30.0,
                      max_datagram_frame_size: Optional[int] = 65535,
                      ) -> QuicConfiguration:
    """QuicConfiguration shared by the built-in QUIC engines.

    ``insecure`` disables certificate verification (self-signed server
    certs are common for censorship-resistant proxies); ``pin_sha256``
    (base64 DER SHA-256, no prefix) is honoured by the engine after the
    handshake when the TLS stack exposes the peer certificate.
    """
    cfg = QuicConfiguration(is_client=True, alpn_protocols=list(alpn),
                            idle_timeout=idle_timeout)
    cfg.server_name = server_name or None
    cfg.max_datagram_frame_size = max_datagram_frame_size
    if insecure or pin_sha256:
        from aioquic.quic.configuration import QuicConfiguration as _Q
        # aioquic verify_mode: 0 = CERT_NONE, 2 = CERT_REQUIRED
        cfg.verify_mode = 0
    return cfg


def check_pin_sha256(peer_cert_der: bytes, pin: str) -> bool:
    """True when the DER certificate matches the base64 SHA-256 pin."""
    import base64
    try:
        want = base64.b64decode(pin)
    except Exception:
        return False
    return len(want) == 32 and hashlib.sha256(peer_cert_der).digest() == want


#: 1-RTT packet budget once UDP relay is active. A full-size inner QUIC
#: packet (1200 B, spec-padded Initial) plus the tunnel framing does not
#: fit aioquic's default 1200-byte budget — and RFC 9221 forbids
#: fragmenting DATAGRAM frames, so an oversized one strands in the send
#: queue forever. 1350 stays under the common 1500-byte IPv4 MTU while
#: leaving headroom for the framing of every engine in this package.
LARGE_DATAGRAM_PACKET_SIZE = 1350


def enable_large_datagrams(proto, size: int = LARGE_DATAGRAM_PACKET_SIZE) -> None:
    """Grow the connection's 1-RTT packet budget (after the handshake).

    Called when a UDP relay session opens: from then on the connection may
    carry full-size inner packets (a chained hop's QUIC Initial, an
    application's 1200-byte UDP datagram). Initial/Handshake packets were
    already sent at the spec-safe 1200 bytes; only post-handshake 1-RTT
    packets grow, so the anti-amplification and MTU rules for the
    handshake are untouched. Defensive by design: if the private layout
    of aioquic changes, this becomes a no-op instead of breaking.
    """
    quic = getattr(proto, "_quic", None)
    if quic is None:
        return
    try:
        if size > getattr(quic, "_max_datagram_size", 0):
            quic._max_datagram_size = size
    except Exception:                                 # pragma: no cover
        pass
    # keep the pacer's rate math in sync with the new packet size
    pacer = getattr(getattr(quic, "_loss", None), "_pacer", None)
    if pacer is not None:
        try:
            pacer._max_datagram_size = size
        except Exception:                             # pragma: no cover
            pass


class ObfsQuicProtocol(QuicConnectionProtocol):
    """QuicConnectionProtocol with packet-level obfuscation hooks.

    Subclasses of the default protocol that apply ``_wrap``/``_unwrap``
    to every UDP datagram, so the obfuscation layer sits transparently
    under any protocol built on top.
    """

    wrap: PacketWrapper = staticmethod(lambda d: d)
    unwrap: PacketWrapper = staticmethod(lambda d: d)
    #: set True on SERVER-side protocols when the socket-level handler
    #: (e.g. a wrapped QuicServer.datagram_received) already unwrapped the
    #: datagram — QUIC headers must be parsed before the protocol sees the
    #: packet, so server-side unwrapping happens one layer earlier
    pre_unwrapped = False

    def transmit(self) -> None:  # type: ignore[override]
        self._transmit_task = None
        for data, addr in self._quic.datagrams_to_send(now=self._loop.time()):
            self._transport.sendto(self.wrap(data), addr)
        timer_at = self._quic.get_timer()
        if self._timer is not None and self._timer_at != timer_at:
            self._timer.cancel()
            self._timer = None
        if self._timer is None and timer_at is not None:
            self._timer = self._loop.call_at(timer_at, self._handle_timer)
        self._timer_at = timer_at

    def datagram_received(self, data, addr) -> None:  # type: ignore[override]
        if not self.pre_unwrapped:
            try:
                data = self.unwrap(bytes(data))
            except Exception:
                log.debug("dropping undecipherable datagram (%d bytes)",
                          len(data))
                return
        self._quic.receive_datagram(data, addr, now=self._loop.time())
        self._process_events()
        self.transmit()


class QuicEngineBase:
    """Mixin providing the LoopThread + SocksServer lifecycle.

    Concrete engines mix this into :class:`ProtocolEngine` and implement
    :meth:`make_dialer` (and optionally :meth:`make_udp_dialer`).
    """

    _loop_thread: Optional[LoopThread] = None
    _server: Optional[SocksServer] = None

    # -- to implement ------------------------------------------------------
    def make_dialer(self) -> Callable[[str, int],
                                      Awaitable[Tuple[asyncio.StreamReader,
                                                      asyncio.StreamWriter]]]:
        raise NotImplementedError

    def make_udp_dialer(self):
        """Return the shared socks_server UdpDialer or None (TCP only)."""
        return None

    # -- lifecycle ---------------------------------------------------------
    def _start_server(self, udp: bool = True, timeout: float = 15.0) -> None:
        if not self.socks_port:
            self.socks_port = free_port(10800 + (id(self) % 900))
        thread = LoopThread(name="proto-clean-quic")
        try:
            thread.run(_serve(SocksServer(
                "127.0.0.1", self.socks_port, self.make_dialer(),
                self.make_udp_dialer() if udp else None)), timeout)
        except BaseException:
            thread.stop()
            raise
        self._loop_thread = thread
        self._server = thread  # truthy marker for running/status

    def _stop_server(self, timeout: float = 5.0) -> None:
        thread, self._loop_thread = self._loop_thread, None
        self._server = None
        if thread is not None:
            thread.stop()

    # -- upstream SOCKS5 ----------------------------------------------------


class _SendToShim:
    """Stands in for asyncio's UDP transport when a QuicConnectionProtocol
    is wired through a SOCKS5 UDP relay instead of a real socket."""

    def __init__(self, send: Callable[[bytes], None]) -> None:
        self._send = send

    def sendto(self, data: bytes, addr=None) -> None:
        self._send(bytes(data))

    def close(self) -> None:  # pragma: no cover - parity with transports
        pass


async def connect_quic_via_socks(config: QuicConfiguration, protocol_factory,
                                 server_addr: Tuple[str, int],
                                 upstream: Tuple[str, int],
                                 obfs: Optional[object] = None):
    """Open a QUIC connection to ``server_addr`` THROUGH a SOCKS5 UDP relay.

    Returns ``(protocol, close)`` where ``protocol`` is the object built by
    ``protocol_factory(quic)`` (an ObfsQuicProtocol subclass) and ``close()``
    tears everything down. This is how QUIC engines sit behind another
    engine in a chain (e.g. Hysteria 2 behind a VLESS hop): the QUIC
    datagrams are carried over the upstream's SOCKS5 UDP ASSOCIATE.
    """
    from aioquic.quic.connection import QuicConnection

    quic = QuicConnection(configuration=config)
    try:
        proto = protocol_factory(quic, stream_handler=None)
    except TypeError:                          # factories taking (quic) only
        proto = protocol_factory(quic)
    if obfs is not None:                       # packet-level obfuscation
        proto.wrap = obfs.wrap                 # type: ignore[method-assign]
        proto.unwrap = obfs.unwrap             # type: ignore[method-assign]
    state = {"closed": False}

    send, close_relay = await udp_associate(
        upstream[0], upstream[1],
        target=server_addr,
        on_packet=lambda d: (proto.datagram_received(d, server_addr)
                             if not state["closed"] else None))
    proto._transport = _SendToShim(send)       # type: ignore[assignment]
    proto.connection_made(proto._transport)
    quic.connect(server_addr, now=proto._loop.time())
    proto.transmit()

    def close() -> None:
        if state["closed"]:
            return
        state["closed"] = True
        try:
            proto.close()
        except Exception:
            pass
        try:
            close_relay()
        except Exception:
            pass

    return proto, close


class _SocksUdpProtocol(asyncio.DatagramProtocol):
    """SOCKS5-UDP wrapped datagram endpoint (RFC 1928 UDP ASSOCIATE)."""

    def __init__(self, on_packet: Callable[[bytes], None],
                 target: Tuple[str, int] = ("", 0)):
        self.on_packet = on_packet
        self.target = target
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.relay_addr: Tuple[str, int] = ("", 0)

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        # SOCKS5 UDP reply header: RSV(2) FRAG(1) ATYP(1) addr port
        try:
            if len(data) < 4:
                return
            atyp = data[3]
            off = 4
            if atyp == ATYP_IPV4:
                off += 6
            elif atyp == ATYP_DOMAIN:
                off += 1 + data[4] + 2
            elif atyp == ATYP_IPV6:
                off += 18
            else:
                return
            self.on_packet(data[off:])
        except (IndexError, ValueError):
            return

    def send_quic(self, data: bytes) -> None:
        if self.transport is not None:
            # each datagram carries its own SOCKS5 target header naming
            # the QUIC server (the associate was made for 0.0.0.0:0 so
            # servers accept any target per datagram)
            host, port = self.target if self.target[1] else \
                (self.relay_addr[0], 0)
            self.transport.sendto(
                b"\x00\x00\x00" + _udp_header(host, port) + data)


def _udp_header(host: str, port: int) -> bytes:
    """SOCKS5 UDP request header for host:port (ATYP+addr+port)."""
    return build_socks5_address(host, port)


async def udp_associate(host: str, port: int,
                        on_packet: Callable[[bytes], None],
                        target: Tuple[str, int] = ("", 0)):
    """SOCKS5 UDP ASSOCIATE (RFC 1928 §7). Returns ``(send, close)``.

    ``send`` wraps each datagram in a SOCKS5 UDP header addressed to
    ``target`` (the QUIC server this association tunnels towards);
    incoming datagrams are delivered unwrapped to ``on_packet``.
    """
    rd, wr = await _raw_associate(host, port)
    relay_host, relay_port = rd.bnd_addr  # type: ignore[attr-defined]
    proto = _SocksUdpProtocol(on_packet, target)
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: proto, remote_addr=(relay_host, relay_port))
    proto.relay_addr = (relay_host, relay_port)

    def send(data: bytes) -> None:
        proto.send_quic(data)

    def close() -> None:
        try:
            transport.close()
        except OSError:
            pass
        try:
            wr.close()
        except OSError:
            pass

    return send, close


async def _raw_associate(host: str, port: int):
    """Minimal SOCKS5 UDP ASSOCIATE handshake; returns (rd, wr) with a
    ``bnd_addr`` attribute attached."""
    import socket as _s
    rd, wr = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    wr.write(struct.pack("!BBB", 5, 1, 0))
    await wr.drain()
    resp = await asyncio.wait_for(rd.readexactly(2), 10)
    if resp[0] != 5 or resp[1] != 0:
        raise ProtocolError("socks udp associate: bad method reply")
    wr.write(b"\x05\x03\x00" + _udp_header("0.0.0.0", 0))
    await wr.drain()
    hdr = await asyncio.wait_for(rd.readexactly(4), 10)
    if hdr[1] != 0:
        raise ProtocolError("socks udp associate failed (0x%02x)" % hdr[1])
    atyp = hdr[3]
    if atyp == ATYP_IPV4:
        body = await rd.readexactly(6)
        bnd = (_s.inet_ntoa(body[:4]), struct.unpack("!H", body[4:6])[0])
    elif atyp == ATYP_DOMAIN:
        ln = (await rd.readexactly(1))[0]
        body = await rd.readexactly(ln + 2)
        bnd = (body[:ln].decode(), struct.unpack("!H", body[ln:])[0])
    elif atyp == ATYP_IPV6:
        body = await rd.readexactly(18)
        bnd = (_s.inet_ntop(_s.AF_INET6, body[:16]),
               struct.unpack("!H", body[16:18])[0])
    else:
        raise ProtocolError("socks udp associate: bad BND.ADDR")
    setattr(rd, "bnd_addr", bnd)
    return rd, wr


async def _serve(server: SocksServer) -> None:
    await server.serve()
