"""Local SOCKS5 front-end shared by the pure-Python protocol engines.

Each built-in engine (Shadowsocks, Hysteria 2, TUIC v5, MASQUE, Cover-DTLS,
Tor chains, …) runs one :class:`SocksServer` on localhost. The server speaks
SOCKS5 CONNECT and UDP ASSOCIATE and hands every destination to a
**dialer** — an async callable provided by the engine that establishes the
tunnelled connection. This keeps the wire protocols completely separate
from the local plumbing and makes every engine testable against a loopback
echo server.

Also here: :class:`LoopThread`, an asyncio event loop running in a daemon
thread, which engines use from the (synchronous) Qt/controller world.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
from typing import Awaitable, Callable, Dict, Optional, Tuple

from .base import ProtocolError

Dialer = Callable[[str, int], Awaitable[Tuple[asyncio.StreamReader,
                                              asyncio.StreamWriter]]]
UdpDialer = Callable[[str, int], Awaitable["UdpSession"]]

VER5 = 0x05
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04


# A UDP dialer opens one tunneled UDP "session" for a destination:
#   on_packet(payload)  -- the engine calls this for every datagram that
#                          arrives FROM the tunnel (downlink to the client)
#   returns (send, close) -- send(payload) pushes a client datagram INTO
#                          the tunnel (uplink); close() tears it down
UdpDialer = Callable[[str, int, Callable[[bytes], None]],
                     Awaitable[Tuple[Callable[[bytes], None],
                                     Callable[[], None]]]]


def parse_socks5_address(buf: bytes, off: int) -> Tuple[str, int, int]:
    """Parse a SOCKS5 address (IPv4/domain/IPv6 + port). Returns (host,
    port, bytes consumed)."""
    atyp = buf[off]
    if atyp == ATYP_IPV4:
        host = socket.inet_ntoa(buf[off + 1:off + 5])
        port = struct.unpack("!H", buf[off + 5:off + 7])[0]
        return host, port, 7
    if atyp == ATYP_DOMAIN:
        ln = buf[off + 1]
        host = buf[off + 2:off + 2 + ln].decode("idna", "replace")
        port = struct.unpack("!H", buf[off + 2 + ln:off + 4 + ln])[0]
        return host, port, 4 + ln
    if atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, buf[off + 1:off + 17])
        port = struct.unpack("!H", buf[off + 17:off + 19])[0]
        return host, port, 19
    raise ProtocolError("bad SOCKS5 address type %d" % atyp)


def build_socks5_address(host: str, port: int) -> bytes:
    """Encode host:port as a SOCKS5 address (domain form for names)."""
    try:
        socket.inet_aton(host)
        return struct.pack("!B4sH", ATYP_IPV4, socket.inet_aton(host), port)
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, host)
        return struct.pack("!B16sH", ATYP_IPV6, packed, port)
    except (OSError, ValueError):
        pass
    raw = host.encode("idna")
    return struct.pack("!BB", ATYP_DOMAIN, len(raw)) + raw + struct.pack("!H", port)


async def socks5_dial(host: str, port: int, dst_host: str, dst_port: int,
                      timeout: float = 10.0,
                      rd: Optional[asyncio.StreamReader] = None,
                      wr: Optional[asyncio.StreamWriter] = None
                      ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection to ``dst`` through a SOCKS5 server.

    Used both for the *upstream* legs of chained engines and for tests.
    If ``rd``/``wr`` are given, an already-open SOCKS5 control stream is
    reused (CONNECT is written on it); otherwise a new one is created.
    """
    if rd is None or wr is None:
        rd, wr = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
    wr.write(struct.pack("!BBB", VER5, 1, 0))  # no auth (VER, NMETHODS, NO_AUTH)
    await wr.drain()
    resp = await asyncio.wait_for(rd.readexactly(2), timeout)
    if resp[0] != VER5 or resp[1] != 0x00:
        raise ProtocolError("upstream SOCKS5 refused auth (0x%02x)" % resp[1])
    wr.write(b"\x05\x01\x00" + build_socks5_address(dst_host, dst_port))
    await wr.drain()
    hdr = await asyncio.wait_for(rd.readexactly(4), timeout)
    if hdr[1] != 0x00:
        raise ProtocolError("upstream SOCKS5 CONNECT failed (0x%02x)" % hdr[1])
    # BND.ADDR: ATYP sits in hdr[3]; re-attach it for the address parser
    rest, _, _ = parse_socks5_address(hdr[3:4] + await _read_bound(rd, hdr), 0)
    del rest
    return rd, wr


async def _read_bound(rd: asyncio.StreamReader, hdr: bytes) -> bytes:
    atyp = hdr[3]
    if atyp == ATYP_IPV4:
        return await rd.readexactly(6)
    if atyp == ATYP_DOMAIN:
        ln = (await rd.readexactly(1))[0]
        return await rd.readexactly(1 + ln + 2)
    if atyp == ATYP_IPV6:
        return await rd.readexactly(18)
    return b""


class LoopThread:
    """An asyncio event loop on a daemon thread with sync entry points."""

    def __init__(self, name: str = "proto-clean-quic") -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=name)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop

    def run(self, coro, timeout: float = 30.0):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout)
        except (asyncio.TimeoutError, TimeoutError):
            fut.cancel()
            raise ProtocolError("operation timed out")

    def call_soon(self, fn, *args) -> None:
        self._loop.call_soon_threadsafe(fn, *args)

    def stop(self) -> None:
        self.call_soon(self._loop.stop)


class SocksServer:
    """SOCKS5 CONNECT + UDP ASSOCIATE front-end on 127.0.0.1."""

    def __init__(self, host: str, port: int, dialer: Dialer,
                 udp_dialer: Optional[UdpDialer] = None) -> None:
        self.host = host
        self.port = port
        self.dialer = dialer
        self.udp_dialer = udp_dialer
        self._server: Optional[asyncio.AbstractServer] = None
        self._udp: Optional[asyncio.DatagramProtocol] = None
        self.connections = 0

    # -- lifecycle --------------------------------------------------------
    async def serve(self) -> None:
        self._server = await asyncio.start_server(
            self._client, self.host, self.port)
        if self.udp_dialer is not None:
            loop = asyncio.get_event_loop()
            self._udp, _ = await loop.create_datagram_endpoint(
                lambda: _UdpEndpoint(self), local_addr=(self.host, self.port))

    async def shutdown(self) -> None:
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # -- TCP clients -------------------------------------------------------
    async def _client(self, rd: asyncio.StreamReader,
                      wr: asyncio.StreamWriter) -> None:
        try:
            hdr = await asyncio.wait_for(rd.readexactly(3), 10)
            if hdr[0] != VER5:
                raise ProtocolError("not SOCKS5")
            wr.write(b"\x05\x00")  # no auth needed (localhost only)
            await wr.drain()
            req = await asyncio.wait_for(rd.readexactly(4), 10)  # VER CMD RSV ATYP
            cmd = req[1]
            atyp = req[3]
            # read EXACTLY the address that follows — anything already in
            # flight (the first payload bytes) belongs to the tunnel
            if atyp == ATYP_IPV4:
                bound = await rd.readexactly(6)
            elif atyp == ATYP_DOMAIN:
                ln = (await rd.readexactly(1))[0]
                bound = await rd.readexactly(1 + ln + 2)
            elif atyp == ATYP_IPV6:
                bound = await rd.readexactly(18)
            else:
                raise ProtocolError("bad SOCKS5 ATYP 0x%02x" % atyp)
            host, port, _used = parse_socks5_address(
                bytes([atyp]) + bound, 0)
            if cmd == CMD_CONNECT:
                await self._connect(rd, wr, host, port)
            elif cmd == CMD_UDP_ASSOCIATE:
                await self._udp_associate(rd, wr)
            else:
                wr.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await wr.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ProtocolError, OSError, ValueError):
            try:
                wr.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await wr.drain()
            except OSError:
                pass
        finally:
            try:
                wr.close()
            except OSError:
                pass

    async def _connect(self, rd, wr, host: str, port: int) -> None:
        upstream_rd, upstream_wr = await self.dialer(host, port)
        wr.write(b"\x05\x00\x00" + build_socks5_address(host, port))
        await wr.drain()
        self.connections += 1
        pipe_out = asyncio.ensure_future(_pipe(rd, upstream_wr))
        pipe_in = asyncio.ensure_future(_pipe(upstream_rd, wr))
        await pipe_out
        try:
            pipe_in.cancel()
        except Exception:
            pass
        try:
            upstream_wr.close()
        except OSError:
            pass

    async def _udp_associate(self, rd, wr) -> None:
        if self._udp is None or self.udp_dialer is None:
            wr.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await wr.drain()
            return
        # client tells us its UDP port in BND.ADDR; we reply with ours
        wr.write(b"\x05\x00\x00\x01" + socket.inet_aton(self.host) +
                 struct.pack("!H", self.port))
        await wr.drain()
        # the _UdpEndpoint handles the actual datagrams until the client
        # closes the TCP control connection
        try:
            await rd.read()  # blocks until control stream EOF
        except OSError:
            pass


class _UdpEndpoint(asyncio.DatagramProtocol):
    """Receives SOCKS5-wrapped UDP datagrams from clients."""

    def __init__(self, server: SocksServer) -> None:
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.sessions: Dict[Tuple[str, int], Tuple[UdpSession, Tuple[str, int]]] = {}

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        # SOCKS5 UDP datagram: RSV(2)=0x0000, FRAG(1), ATYP, addr, port
        if len(data) < 4 or data[0] != 0x00 or data[1] != 0x00 \
                or data[2] != 0x00:
            return
        try:
            host, port, used = parse_socks5_address(data, 3)
        except (ProtocolError, IndexError):
            return
        payload = data[3 + used:]
        entry = self.sessions.get(addr)
        if entry is None:
            if self.server.udp_dialer is None:
                return
            asyncio.ensure_future(self._open_udp(addr, host, port, payload))
            return
        send, _close = entry
        send(payload)

    async def _open_udp(self, addr, host: str, port: int,
                        first_payload: bytes = b"") -> None:
        assert self.server.udp_dialer is not None

        def on_packet(payload: bytes) -> None:
            """Downlink: wrap the tunnel datagram for the SOCKS client."""
            if self.transport is None:
                return
            frag = (b"\x00\x00\x00" + build_socks5_address(host, port)
                    + payload)
            self.transport.sendto(frag[:65535], addr)

        try:
            send, close = await self.server.udp_dialer(host, port, on_packet)
        except (ProtocolError, OSError, asyncio.TimeoutError) as exc:
            self.sessions.pop(addr, None)
            return
        self.sessions[addr] = (send, close)
        if first_payload:
            send(first_payload)          # don't drop the opening datagram

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass


async def _pipe(rd, wr) -> None:
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
