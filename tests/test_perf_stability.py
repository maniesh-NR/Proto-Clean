"""Performance / stability / memory regression series.

Guards the optimisation pass across all platforms:

* **Stability**
  - ``spawn()`` drains child stdout: a child that logs megabytes through
    the pipe can never fill the OS buffer and deadlock (the classic
    piped-subprocess freeze), and ``output_tail`` stays bounded.
  - ``LoopThread.stop()`` cancels tasks, joins the thread and closes the
    loop — no thread/loop/socket leak per engine start/stop cycle.
  - SOCKS5 UDP sessions: closed with their control connection
    (RFC 1928), swept when idle, capped, and the opening race is guarded.
  - ``wait_port`` returns the moment a port ACCEPTS a connection (not
    when it merely binds).
* **Performance**
  - Salamander and QUIC-obfs whitening XOR run at big-int speed; the
    whitening keystream is cached per salt.
  - The cover-DTLS keystream is cached per (psk, salt).
  - SS AEAD decrypt buffers with ``bytearray`` (no O(n²) re-copying) and
    reuses the ChaCha20 key schedule.
* **Memory**
  - Engine log tails are bounded; the server store answers lookups from
    an index instead of scanning thousands of entries.
"""

from __future__ import annotations

import asyncio
import functools
import os
import socket
import subprocess
import sys
import threading
import time
from typing import List, Callable

import pytest

from proto_clean.vpn.protocols import quicobfs
from proto_clean.vpn.protocols.base import (ProtocolEngine, ProtocolError,
                                            free_port, wait_port)
from proto_clean.vpn.protocols.coverdtls import cover, whitening_keystream
from proto_clean.vpn.protocols.hysteria2 import Salamander
from proto_clean.vpn.protocols import sscrypto
from proto_clean.vpn.protocols.socks_server import (PIPE_CHUNK, SocksServer,
                                                    UDP_SESSION_IDLE,
                                                    UDP_SESSION_MAX,
                                                    LoopThread,
                                                    build_socks5_address)
from proto_clean.servers.store import ServerStore


def _aitest(fn: Callable) -> Callable:
    """Run an ``async def`` test with ``asyncio.run``.

    The suite deliberately avoids the pytest-asyncio dependency (CI and
    the Windows 7 legacy stack install plain pytest), so async tests are
    wrapped instead of marked.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


# ---------------------------------------------------------------------------
# spawn(): drained pipes, bounded tail
# ---------------------------------------------------------------------------
class _TailEngine(ProtocolEngine):
    proxy_kind = "tailtest"

    def start(self, profile, timeout: float = 15.0) -> None:  # pragma: no cover
        raise NotImplementedError


def test_spawn_drains_chatty_child_without_deadlock(tmp_path):
    """A child that writes 4x the OS pipe buffer must still exit promptly.

    Before the drain thread, the child's ``write`` blocked forever once
    the 64 KiB pipe filled and nothing read it — the engine reported
    "running" while the proxy was frozen."""
    eng = _TailEngine()
    child = tmp_path / "chatty.py"
    child.write_text(
        "import sys\n"
        "for i in range(256):                 # 256 KiB > 4x pipe buffer\n"
        "    sys.stdout.write('line %d %s\\n' % (i, 'x' * 1000))\n"
        "    sys.stdout.flush()\n"
        "print('DONE-MARKER')\n")
    proc = eng.spawn([sys.executable, str(child)])
    try:
        rc = proc.wait(timeout=15)             # would hang without the drain
        assert rc == 0
        deadline = time.time() + 5
        while "DONE-MARKER" not in eng.output_tail() and time.time() < deadline:
            time.sleep(0.05)
        tail = eng.output_tail()
        assert "DONE-MARKER" in tail
        assert "line 0 " not in tail           # old lines were trimmed away
    finally:
        eng.stop()


def test_output_tail_is_bounded():
    eng = _TailEngine()
    child_proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; sys.stdout.write('z' * 500000); sys.stdout.flush()"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    eng._proc = child_proc
    eng._drain_output(child_proc)
    child_proc.wait(timeout=10)
    deadline = time.time() + 5
    while len(eng.output_tail(10**9)) < 8000 and time.time() < deadline:
        time.sleep(0.05)
    # 500 KB flowed through; only the last ~8 KB is retained
    assert len(eng.output_tail(10**9)) <= 8192 + 64


# ---------------------------------------------------------------------------
# LoopThread: full shutdown, no leaks
# ---------------------------------------------------------------------------
def test_loopthread_stop_joins_and_closes():
    lt = LoopThread(name="test-lt")
    started = threading.Event()

    async def forever():
        started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            raise

    fut = asyncio.run_coroutine_threadsafe(forever(), lt.loop)
    assert started.wait(5)
    lt.stop(timeout=5)
    assert not lt._thread.is_alive()           # joined
    assert lt.loop.is_closed()                 # and closed
    # cancelling a pending coroutine settled without error propagation
    with pytest.raises(Exception):
        fut.result(timeout=1)


def test_loopthread_repeated_cycles_do_not_leak_threads():
    """Engine start/stop cycles must not accumulate live threads."""
    before = threading.active_count()
    for _ in range(6):
        lt = LoopThread(name="cycle")
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0), lt.loop) \
            .result(timeout=5)
        lt.stop(timeout=5)
    # give the reaper a moment, then compare
    deadline = time.time() + 3
    while threading.active_count() > before and time.time() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= before


# ---------------------------------------------------------------------------
# SOCKS server: TCP relay + UDP session lifecycle
# ---------------------------------------------------------------------------
async def _tcp_echo(rd, wr):
    try:
        while True:
            data = await rd.read(65536)
            if not data:
                break
            wr.write(data)
            await wr.drain()
    except OSError:
        pass
    finally:
        wr.close()


async def _echo_dialer_factory():
    """A dialer that opens real echo connections (the dialer contract is
    `async (host, port) -> (rd, wr)`, not a server callback)."""
    echo_srv = await asyncio.start_server(_tcp_echo, "127.0.0.1", 0)
    port = echo_srv.sockets[0].getsockname()[1]

    async def dial(host: str, port_: int):
        return await asyncio.open_connection("127.0.0.1", port)
    dial.echo_server = echo_srv
    return dial


async def _udp_echo_dialer(host, port, on_packet):
    def send(payload: bytes) -> None:
        on_packet(payload)

    def close() -> None:
        pass
    return send, close


@_aitest
async def test_socks_tcp_bulk_relay_uses_large_chunks():
    """A 1 MiB bulk transfer through the SOCKS relay (256 KiB reads)."""
    dial = await _echo_dialer_factory()
    port = free_port(0)
    srv = SocksServer("127.0.0.1", port, dial, None)
    await srv.serve()
    try:
        rd, wr = await asyncio.open_connection("127.0.0.1", port)
        wr.write(b"\x05\x01\x00")
        await wr.drain()
        assert await rd.readexactly(2) == b"\x05\x00"
        wr.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        await wr.drain()
        await rd.readexactly(10)
        blob = os.urandom(1024 * 1024)
        wr.write(blob)
        await wr.drain()
        got = await rd.readexactly(len(blob))
        assert got == blob
        wr.close()
    finally:
        await srv.shutdown()
        dial.echo_server.close()
        await dial.echo_server.wait_closed()


@_aitest
async def test_socks_half_close_does_not_stall():
    """Upstream finishing first must tear the client leg down promptly
    (the old code waited for the client to close)."""
    async def oneshot(rd, wr):
        wr.write(b"bye")
        wr.close()

    onesrv = await asyncio.start_server(oneshot, "127.0.0.1", 0)
    onesrv_port = onesrv.sockets[0].getsockname()[1]

    async def dial(host: str, port_: int):
        return await asyncio.open_connection("127.0.0.1", onesrv_port)

    port = free_port(0)
    srv = SocksServer("127.0.0.1", port, dial, None)
    await srv.serve()
    try:
        rd, wr = await asyncio.open_connection("127.0.0.1", port)
        wr.write(b"\x05\x01\x00")
        await wr.drain()
        await rd.readexactly(2)
        wr.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        await wr.drain()
        await rd.readexactly(10)
        t0 = time.monotonic()
        assert await rd.readexactly(3) == b"bye"
        assert await rd.read() == b""               # EOF follows at once
        assert time.monotonic() - t0 < 5.0
        wr.close()
    finally:
        await srv.shutdown()
        onesrv.close()
        await onesrv.wait_closed()


class _AsyncUdp(asyncio.DatagramProtocol):
    """Async UDP client socket with a receive queue (never blocks the loop)."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data, addr) -> None:
        self.queue.put_nowait((data, addr))

    def error_received(self, exc) -> None:      # pragma: no cover
        pass


async def _udp_client(relay: tuple) -> _AsyncUdp:
    loop = asyncio.get_event_loop()
    ep = _AsyncUdp()
    await loop.create_datagram_endpoint(lambda: ep, local_addr=("127.0.0.1", 0))
    ep.relay = relay
    return ep


def _wrap_udp(host: str, port: int, payload: bytes) -> bytes:
    return (b"\x00\x00\x00" + build_socks5_address(host, port) + payload)


async def _assoc_async(port: int):
    """Async SOCKS5 UDP ASSOCIATE; returns (rd, wr, relay_addr)."""
    rd, wr = await asyncio.open_connection("127.0.0.1", port)
    wr.write(b"\x05\x01\x00")
    await wr.drain()
    assert await rd.readexactly(2) == b"\x05\x00"
    wr.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    await wr.drain()
    hdr = await rd.readexactly(4)
    assert hdr[1] == 0
    if hdr[3] == 0x01:
        bnd = await rd.readexactly(6)
    else:
        raise AssertionError("unexpected BND family %d" % hdr[3])
    relay = (socket.inet_ntoa(bnd[:4]), int.from_bytes(bnd[4:], "big"))
    return rd, wr, relay


@_aitest
async def test_udp_sessions_close_with_control_connection():
    """Dropping the TCP control conn closes the client's UDP sessions."""
    port = free_port(0)
    closed = []
    alive: dict = {}

    async def dialer(host, p, on_packet):
        sid = len(alive)
        alive[sid] = True

        def send(payload):     # echo back so the client sees the session
            on_packet(payload)

        def close():
            closed.append(sid)
            alive.pop(sid, None)
        return send, close

    srv = SocksServer("127.0.0.1", port, _unused_dialer, dialer)
    await srv.serve()
    try:
        rd, wr, relay = await _assoc_async(port)
        udp = await _udp_client(relay)
        udp.transport.sendto(_wrap_udp("8.8.8.8", 53, b"ping"), relay)
        data, _ = await asyncio.wait_for(udp.queue.get(), 5)
        assert data.endswith(b"ping")          # session opened and echoed
        assert len(alive) == 1
        wr.close()                              # control conn gone
        deadline = time.time() + 5
        while not closed and time.time() < deadline:
            await asyncio.sleep(0.05)
        assert closed == [0]                   # session reaped
        udp.transport.close()
    finally:
        await srv.shutdown()


async def _unused_dialer(host, port):
    raise AssertionError("TCP CONNECT not expected here")


@_aitest
async def test_udp_idle_sessions_are_swept():
    port = free_port(0)
    closed: List[int] = []

    async def dialer(host, p, on_packet):
        def send(payload):
            pass

        def close():
            closed.append(1)
        return send, close

    srv = SocksServer("127.0.0.1", port, _unused_dialer, dialer)
    await srv.serve()
    try:
        rd, wr, relay = await _assoc_async(port)
        udp = await _udp_client(relay)
        udp.transport.sendto(_wrap_udp("8.8.8.8", 53, b"x"), relay)
        # pretend the session has been idle past the deadline
        ep = srv._udp_proto
        deadline = time.time() + 5
        while not ep.sessions and time.time() < deadline:
            await asyncio.sleep(0.05)
        assert len(ep.sessions) == 1
        for addr in ep._last_seen:
            ep._last_seen[addr] -= UDP_SESSION_IDLE + 1
        ep.evict_idle()
        assert closed == [1]                   # reaped by the sweeper
        assert not ep.sessions
        wr.close()
        udp.transport.close()
    finally:
        await srv.shutdown()


@_aitest
async def test_udp_session_cap_enforced():
    port = free_port(0)
    opened: List[tuple] = []

    async def dialer(host, p, on_packet):
        opened.append((host, p))

        def send(payload):
            pass

        def close():
            pass
        return send, close

    srv = SocksServer("127.0.0.1", port, _unused_dialer, dialer)
    await srv.serve()
    try:
        ep = srv._udp_proto
        # fake a full session table
        for i in range(UDP_SESSION_MAX):
            ep.sessions[("10.0.0.%d" % i, 1000 + i)] = (lambda d: None,
                                                         lambda: None)
        before = len(ep.sessions)
        ep.datagram_received(
            b"\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35nope",
            ("192.0.2.9", 4242))
        assert len(ep.sessions) == before       # refused, nothing opened
    finally:
        await srv.shutdown()


@_aitest
async def test_udp_open_race_guarded():
    """Two datagrams from a new client during the (slow) open must not
    create two engine sessions — the second is dropped until the session
    exists."""
    port = free_port(0)
    opens: List[tuple] = []

    async def slow_dialer(host, p, on_packet):
        opens.append((host, p))
        await asyncio.sleep(0.3)

        def send(payload):
            on_packet(payload)

        def close():
            pass
        return send, close

    srv = SocksServer("127.0.0.1", port, _unused_dialer, slow_dialer)
    await srv.serve()
    try:
        ep = srv._udp_proto
        addr = ("192.0.2.7", 5353)
        pkt = _wrap_udp("8.8.8.8", 53, b"q")
        ep.datagram_received(pkt, addr)
        ep.datagram_received(pkt, addr)         # while the first is opening
        await asyncio.sleep(0.8)
        assert len(opens) == 1                  # exactly one session opened
        assert ep.sessions and list(ep.sessions) == [addr]
    finally:
        await srv.shutdown()


# ---------------------------------------------------------------------------
# wait_port: connect-based readiness
# ---------------------------------------------------------------------------
def test_wait_port_detects_listener_immediately():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    try:
        t0 = time.monotonic()
        wait_port(port, timeout=5)              # returns as soon as it listens
        assert time.monotonic() - t0 < 2.0
    finally:
        srv.close()


def test_wait_port_rejects_bound_but_not_listening():
    """A socket that only BOUND (no listen) is not ready — the old
    bind-based check said it was and the first client connect failed."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    try:
        with pytest.raises(ProtocolError):
            wait_port(port, timeout=0.6)
    finally:
        s.close()


def test_wait_port_reports_engine_death():
    with pytest.raises(ProtocolError, match="engine exited"):
        wait_port(free_port(0), timeout=2.0, stop=lambda: True)


# ---------------------------------------------------------------------------
# crypto hot paths: correctness at speed
# ---------------------------------------------------------------------------
def test_salamander_xor_matches_reference():
    import hashlib
    sal = Salamander("k")
    for n in (0, 1, 8, 9, 31, 32, 33, 100, 1350, 4096):
        d = os.urandom(n)
        salt = os.urandom(8)
        ks = hashlib.blake2b(b"k" + salt, digest_size=32).digest()
        ref = bytes(a ^ ks[i % 32] for i, a in enumerate(d)) if d else b""
        assert sal._xor(d, ks) == ref
    # round trip
    blob = os.urandom(1500)
    assert sal.unwrap(sal.wrap(blob)) == blob


def test_quicobfs_whitening_keystream_cache_matches_fresh():
    ob = quicobfs.PacketObfuscator("whitening", "psk")
    peer = quicobfs.PacketObfuscator("whitening", "psk")
    for size in (10, 100, 1300, 5000, 1300):   # sizes go up AND back down
        d = os.urandom(size)
        w = ob.wrap(d)
        assert peer.unwrap(w) == d
        # cached prefix equals a fresh generation
        assert ob._keystream(size) == quicobfs._keystream("psk", ob._salt, size)
    assert len(ob._ks) >= 5000                 # it really grew/cached


def test_coverdtls_keystream_cache_is_transparent():
    a = whitening_keystream("psk1", b"saltsalt", 64)
    b = whitening_keystream("psk1", b"saltsalt", 200)   # extends the cache
    c = whitening_keystream("psk1", b"saltsalt", 64)    # served from cache
    assert a == b[:64] == c
    assert cover("psk1", b"saltsalt", b"hello" * 10) == \
        cover("psk1", b"saltsalt", b"hello" * 10)
    # round-trip (XOR is self-inverse)
    data = os.urandom(1350)
    assert cover("psk1", b"saltsalt", cover("psk1", b"saltsalt", data)) == data


def test_ss_decrypt_incremental_and_chunked_feeds():
    ctx = sscrypto.CipherCtx.from_password("chacha20-ietf-poly1305", "pw")
    enc = ctx.new_session(b"S" * 32)
    dec = ctx.new_session(b"S" * 32)
    payload = os.urandom(20_000)
    wire = enc.encrypt(payload)
    # feed in awkward slices: every partial state must parse identically
    out = b""
    for i in range(0, len(wire), 1234):
        out += dec.decrypt(wire[i:i + 1234])
    assert out == payload
    assert dec.pending == 0                    # buffer fully consumed


def test_ss_session_reuses_chacha_key_schedule():
    ctx = sscrypto.CipherCtx.from_password("chacha20-ietf-poly1305", "pw")
    s = ctx.new_session(b"S" * 32)
    assert s._aead is not None                 # cached per session
    a = sscrypto.CipherCtx.from_password("aes-256-gcm", "pw")
    g = a.new_session(b"S" * 32)
    assert g._aead is None                     # AES builds per-nonce contexts


# ---------------------------------------------------------------------------
# memory: bounded tails, indexed store
# ---------------------------------------------------------------------------
def test_server_store_index_lookups(tmp_path, monkeypatch):
    from proto_clean.servers import store as st
    monkeypatch.setattr(st, "SERVER_CACHE_FILE",
                        tmp_path / "servers.json")
    ss = ServerStore()
    from proto_clean.servers.models import LogicalServer

    def mk(i):
        return LogicalServer(id="id%d" % i, name="N%d" % i,
                             entry_country="US", exit_country="US",
                             domain="n%d.example" % i, tier=i % 3, features=0)
    servers = [mk(i) for i in range(4000)]
    ss.replace(servers)
    assert ss.by_id("id3999").name == "N3999"
    assert ss.by_name("N0").id == "id0"
    assert ss.by_id("missing") is None
    assert ss.by_name("missing") is None
    assert len(ss.servers) == 4000
    assert len(ss.free_servers()) == len([s for s in servers if s.tier == 0])


def test_pipe_chunk_is_large():
    """The relay reads in 256 KiB chunks (64 KiB throttled bulk flows)."""
    assert PIPE_CHUNK >= 262144


# ---------------------------------------------------------------------------
# QUIC idle keepalive
# ---------------------------------------------------------------------------
class _FakeQuicForKeepalive:
    def __init__(self) -> None:
        self.pings = []

    def send_ping(self, uid: int) -> None:
        self.pings.append(uid)

    def datagrams_to_send(self, now=0):
        return ()

    def get_timer(self):
        return None


class _FakeTransport:
    def __init__(self) -> None:
        self.sent = []

    def sendto(self, data, addr=None) -> None:
        self.sent.append(data)

    def close(self) -> None:
        pass


def _keepalive_proto(monkeypatch):
    """An ObfsQuicProtocol wired to fakes, with a manual clock."""
    from proto_clean.vpn.protocols.quicbase import ObfsQuicProtocol
    quic = _FakeQuicForKeepalive()
    proto = ObfsQuicProtocol(quic)
    proto._loop = asyncio.new_event_loop()
    monkeypatch.setattr(proto._loop, "time", lambda: proto._now)
    proto._now = 1000.0
    transport = _FakeTransport()
    proto.connection_made(transport)
    return proto, quic


@_aitest
async def test_quic_keepalive_pings_when_idle(monkeypatch):
    proto, quic = _keepalive_proto(monkeypatch)
    try:
        # nothing sent for KEEPALIVE_IDLE → the tick sends exactly one PING
        proto._now += proto.KEEPALIVE_IDLE + 0.1
        proto._keepalive_tick()
        assert quic.pings == [0]
        assert quic.pings == [0] and proto._keepalive is not None
        # still no reply but within the give-up horizon → rescheduled
        # (a hair more than KEEPALIVE_IDLE since the first tick's
        # transmit() refreshed the tx clock)
        proto._now += proto.KEEPALIVE_IDLE + 0.5
        proto._keepalive_tick()
        assert len(quic.pings) == 2
        assert proto._keepalive is not None
    finally:
        proto._keepalive and proto._keepalive.cancel()
        proto._loop.close()


@_aitest
async def test_quic_keepalive_gives_up_on_dead_path(monkeypatch):
    proto, quic = _keepalive_proto(monkeypatch)
    try:
        # three keepalive rounds with zero inbound traffic → stops
        proto._now += 3 * proto.KEEPALIVE_IDLE + 1
        proto._keepalive_tick()
        assert quic.pings == [0]
        assert proto._keepalive is None      # timer NOT rescheduled
    finally:
        proto._keepalive and proto._keepalive.cancel()
        proto._loop.close()


@_aitest
async def test_quic_keepalive_silent_when_traffic_flows(monkeypatch):
    proto, quic = _keepalive_proto(monkeypatch)
    try:
        # traffic resets the tx clock → no ping
        proto._now += proto.KEEPALIVE_IDLE + 0.1
        proto._last_tx = proto._now          # transmit() just ran
        proto._keepalive_tick()
        assert quic.pings == []
        assert proto._keepalive is not None
    finally:
        proto._keepalive and proto._keepalive.cancel()
        proto._loop.close()


def test_quic_flow_control_windows_raised():
    """The engine config announces bigger-than-default QUIC windows so
    high-RTT paths are not throttled to ~7 MB/s."""
    from proto_clean.vpn.protocols import quicbase
    assert quicbase.MAX_DATA >= 8 * 1024 * 1024
    assert quicbase.MAX_STREAM_DATA >= 2 * 1024 * 1024
    cfg = quicbase.build_quic_config("example.org", ("h3",))
    assert cfg.max_data == quicbase.MAX_DATA
    assert cfg.max_stream_data == quicbase.MAX_STREAM_DATA
