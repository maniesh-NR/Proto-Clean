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
import time
from typing import Awaitable, Callable, Dict, Optional, Tuple

from .base import ProtocolError

#: idle seconds before a SOCKS5 UDP session (per client addr) is evicted —
#: NAT mappings for UDP die far sooner, so an idle session is almost
#: certainly orphaned and would otherwise leak forever
UDP_SESSION_IDLE = 180.0
#: hard cap on concurrent UDP sessions per server (DoS guard)
UDP_SESSION_MAX = 1024
#: read chunk for the TCP relay pipes (bigger = fewer awaits per MB)
PIPE_CHUNK = 262144
#: StreamReader limit for client connections (default 64 KiB throttles
#: bulk transfers on fast links)
STREAM_LIMIT = 262144

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


def tune_stream_socket(wr) -> None:
    """Best-effort TCP tuning on a stream writer's socket: NODELAY (no
    Nagle — proxies write small bursts) plus keepalive (detect dead peers
    behind NAT instead of hanging on a half-open connection).  Every
    option is optional: anything unsupported on the current OS is
    skipped silently."""
    sock = wr.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    # idle-seconds knob: TCP_KEEPIDLE (Linux/Android), TCP_KEEPALIVE
    # (macOS/iOS); Windows uses its own SIO_KEEPALIVE_VALS defaults
    for opt in (getattr(socket, "TCP_KEEPIDLE", 0),
                getattr(socket, "TCP_KEEPALIVE", 0)):
        if opt:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, 60)
            except OSError:
                pass


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
            asyncio.open_connection(host, port, limit=STREAM_LIMIT), timeout)
        tune_stream_socket(wr)
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
    """An asyncio event loop on a daemon thread with sync entry points.

    :meth:`stop` cancels the loop's pending tasks, waits a beat for their
    cleanup (closing transports), joins the thread and closes the loop —
    nothing leaks per start/stop cycle (threads, loops, sockets)."""

    #: seconds to let cancelled tasks run their ``finally`` blocks before
    #: the loop stops (transport close callbacks included)
    DRAIN_GRACE = 0.1

    def __init__(self, name: str = "proto-clean-quic") -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=name)
        self._stopping = False
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop

    def run(self, coro, timeout: float = 30.0):
        if self._stopping:
            raise ProtocolError("the event loop is shutting down")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout)
        except (asyncio.TimeoutError, TimeoutError):
            fut.cancel()
            raise ProtocolError("operation timed out")

    def call_soon(self, fn, *args) -> None:
        self._loop.call_soon_threadsafe(fn, *args)

    def stop(self, timeout: float = 5.0) -> None:
        """Cancel the loop's tasks, stop it, join the thread, close it."""
        if self._stopping:
            return
        self._stopping = True

        def _halt() -> None:
            tasks = [t for t in asyncio.all_tasks(self._loop) if not t.done()]
            for t in tasks:
                t.cancel()
            if tasks:
                # let the cancellations settle (``finally`` blocks close
                # their transports) before ripping the loop out
                self._loop.call_later(self.DRAIN_GRACE, self._loop.stop)
            else:
                self._loop.stop()

        try:
            self._loop.call_soon_threadsafe(_halt)
        except RuntimeError:            # loop already stopped/closed
            pass
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout)
        if not self._thread.is_alive():
            try:
                self._loop.close()
            except RuntimeError:        # pragma: no cover - still running
                pass


class SocksServer:
    """SOCKS5 CONNECT + UDP ASSOCIATE front-end on 127.0.0.1."""

    def __init__(self, host: str, port: int, dialer: Dialer,
                 udp_dialer: Optional[UdpDialer] = None) -> None:
        self.host = host
        self.port = port
        self.dialer = dialer
        self.udp_dialer = udp_dialer
        self._server: Optional[asyncio.AbstractServer] = None
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._udp_proto: Optional[_UdpEndpoint] = None
        self._clients: set = set()          # open client writers
        self.connections = 0

    # -- lifecycle --------------------------------------------------------
    async def serve(self) -> None:
        self._server = await asyncio.start_server(
            self._client, self.host, self.port, limit=STREAM_LIMIT)
        # record the actually-bound port (port 0 = kernel-assigned)
        for sock in (self._server.sockets or []):
            self.port = sock.getsockname()[1]
            break
        if self.udp_dialer is not None:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UdpEndpoint(self), local_addr=(self.host, self.port))
            self._udp_transport = transport
            self._udp_proto = protocol

    async def shutdown(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()    # triggers connection_lost → evicts
            self._udp_transport = None
            self._udp_proto = None
        if self._server is not None:
            self._server.close()
            # force-close lingering clients: a client that never hung up
            # would otherwise pin wait_closed() (and engine stop) forever
            for wr in list(self._clients):
                try:
                    wr.close()
                except OSError:
                    pass
            self._clients.clear()
            await self._server.wait_closed()
            self._server = None

    # -- TCP clients -------------------------------------------------------
    async def _client(self, rd: asyncio.StreamReader,
                      wr: asyncio.StreamWriter) -> None:
        peer = wr.get_extra_info("peername") or ("", 0)
        self._clients.add(wr)
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
                await self._udp_associate(rd, wr, peer[0])
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
            self._clients.discard(wr)
            try:
                wr.close()
            except OSError:
                pass

    async def _connect(self, rd, wr, host: str, port: int) -> None:
        upstream_rd, upstream_wr = await self.dialer(host, port)
        tune_stream_socket(wr)
        wr.write(b"\x05\x00\x00" + build_socks5_address(host, port))
        await wr.drain()
        self.connections += 1
        pipe_out = asyncio.ensure_future(_pipe(rd, upstream_wr))
        pipe_in = asyncio.ensure_future(_pipe(upstream_rd, wr))
        try:
            # tear down as soon as EITHER side finishes; the other pipe
            # used to linger until its own reader hit EOF (a half-closed
            # upstream stalled the client connection for the full timeout)
            _done, pending = await asyncio.wait(
                {pipe_out, pipe_in}, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
            if pending:
                await asyncio.wait(pending, timeout=2.0)
        finally:
            self.connections -= 1
            try:
                upstream_wr.close()
                await upstream_wr.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass

    async def _udp_associate(self, rd, wr, peer_ip: str = "") -> None:
        if self._udp_proto is None or self.udp_dialer is None:
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
        finally:
            # RFC 1928: the association dies with its control connection
            if peer_ip and self._udp_proto is not None:
                self._udp_proto.close_ip(peer_ip)


class _UdpEndpoint(asyncio.DatagramProtocol):
    """Receives SOCKS5-wrapped UDP datagrams from clients.

    Sessions are keyed by the client's UDP source address; each has an
    idle timestamp — a sweeper task evicts sessions that saw no traffic
    for :data:`UDP_SESSION_IDLE` seconds (and their engine resources
    with them) so long-running proxies cannot accumulate dead sessions.
    """

    def __init__(self, server: SocksServer) -> None:
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.sessions: Dict[Tuple[str, int], Tuple[UdpSession, Tuple[str, int]]] = {}
        self._pending: set = set()          # addrs with a session opening
        self._last_seen: Dict[Tuple[str, int], float] = {}
        self._sweeper: Optional[asyncio.Future] = None

    def connection_made(self, transport) -> None:
        self.transport = transport
        self._sweeper = asyncio.ensure_future(self._sweep())

    def connection_lost(self, exc) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            self._sweeper = None
        for addr in list(self.sessions):
            self._close_session(addr)

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
        self._last_seen[addr] = time.monotonic()
        if addr in self._pending:
            return                          # session still opening
        entry = self.sessions.get(addr)
        if entry is None:
            if self.server.udp_dialer is None:
                return
            if len(self.sessions) >= UDP_SESSION_MAX:
                return                      # at the cap: drop, don't OOM
            # mark BEFORE scheduling: two datagrams in one loop iteration
            # must not spawn two openers (the task cannot run in between)
            self._pending.add(addr)
            asyncio.ensure_future(self._open_udp(addr, host, port, payload))
            return
        send, _close = entry
        send(payload)

    async def _open_udp(self, addr, host: str, port: int,
                        first_payload: bytes = b"") -> None:
        assert self.server.udp_dialer is not None
        # the wrap header is per-session constant — build it once
        hdr = b"\x00\x00\x00" + build_socks5_address(host, port)

        def on_packet(payload: bytes) -> None:
            """Downlink: wrap the tunnel datagram for the SOCKS client."""
            if self.transport is None:
                return
            self.transport.sendto(hdr + payload[:65535 - len(hdr)], addr)

        try:
            send, close = await self.server.udp_dialer(host, port, on_packet)
        except (ProtocolError, OSError, asyncio.TimeoutError):
            self._pending.discard(addr)
            self._last_seen.pop(addr, None)
            return
        if self.transport is None or addr not in self._last_seen:
            # server shut down while opening — don't leak the session
            try:
                close()
            except Exception:               # noqa: BLE001 — best effort
                pass
            self._pending.discard(addr)
            return
        self.sessions[addr] = (send, close)
        self._pending.discard(addr)
        if first_payload:
            send(first_payload)          # don't drop the opening datagram

    # -- eviction ----------------------------------------------------------
    def _close_session(self, addr) -> None:
        self._last_seen.pop(addr, None)
        entry = self.sessions.pop(addr, None)
        if entry is not None:
            _send, close = entry
            try:
                close()
            except Exception:               # noqa: BLE001 — best effort
                pass

    def close_ip(self, ip: str) -> None:
        """Close every session from one client IP (its control TCP
        connection dropped — the association is dead per RFC 1928)."""
        for addr in [a for a in self.sessions if a[0] == ip]:
            self._close_session(addr)

    async def _sweep(self) -> None:
        """Evict idle sessions every minute."""
        while True:
            await asyncio.sleep(60)
            self.evict_idle()

    def evict_idle(self, now: Optional[float] = None) -> None:
        """Close every session idle beyond :data:`UDP_SESSION_IDLE`."""
        now = time.monotonic() if now is None else now
        for addr in [a for a, t in self._last_seen.items()
                     if now - t > UDP_SESSION_IDLE]:
            self._close_session(addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass


async def _pipe(rd, wr) -> None:
    try:
        while True:
            data = await rd.read(PIPE_CHUNK)
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
