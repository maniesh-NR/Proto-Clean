"""Link bonding: use two or more network adapters as one fat pipe.

The client side of PCB. A local SOCKS5 endpoint accepts application
connections; every stream is then split into sequenced chunks and sent
over **one TCP member connection per selected adapter**, each socket
bound to its adapter's address (``sock.bind((adapter_ip, 0))``) so the
traffic really leaves through that NIC. The bond server
(:mod:`proto_clean.vpn.bondserver`) reorders and rejoins the stream.

Two modes (Speedify-style, net-merge-inspired):

* ``bond`` — every stream rides *all* adapters at once; one download
  gets the combined bandwidth of Wi-Fi + Ethernet + tethering.
* ``balance`` — each new stream is assigned to a single adapter
  (round-robin); many downloads spread across links.

A dead adapter is dropped from the schedule and its share is taken
over by the survivors; the stream keeps flowing (reassembly is
sequence-based, so re-ordering across links is free).

Interoperability: the local SOCKS port composes with the other engines
— Xray and samizdat can *ride the bond* (their configs gain a SOCKS
outbound/detour pointing here when ``ride_bond`` is on), and the
system proxy points at the chain's head.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Dict, List, Optional

from ..log import get
from .bondnet import resolve_bind_ips
from .bondproto import (
    FRAME_DATA, FRAME_FIN, FRAME_HANDSHAKE, FRAME_PING, FRAME_PONG,
    BondProtocolError, FrameReader, Reassembler, WeightedScheduler,
    chunk_data, new_session_id, pack_frame, pack_handshake,
)
from .xray import XrayError, XrayManager

log = get("bond")

DEFAULT_SOCKS_PORT = 10811
CONNECT_TIMEOUT = 10.0          # member connect budget (seconds)
DRAIN_TIMEOUT = 5.0             # graceful close after client FIN

# SOCKS5 constants
_SOCKS_VERSION = 5
_CMD_CONNECT = 1
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 1, 3, 4
_METHOD_NO_AUTH = 0x00
_SOCKS_OK, _SOCKS_FAIL = 0, 1


class _Member:
    """One adapter-bound TCP connection to the bond server."""

    __slots__ = ("index", "bind_ip", "reader", "writer", "alive")

    def __init__(self, index: int, bind_ip: str,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter) -> None:
        self.index = index
        self.bind_ip = bind_ip or "default"
        self.reader = reader
        self.writer = writer
        self.alive = True


class _Session:
    """One bonded SOCKS session (client side)."""

    def __init__(self, engine: "BondEngine", sid: bytes,
                 bind_ips: List[str],
                 app_writer: asyncio.StreamWriter) -> None:
        self.engine = engine
        self.sid = sid
        self.bind_ips = bind_ips
        self.app_writer = app_writer
        self.members: List[Optional[_Member]] = []
        self.up_sched = WeightedScheduler([1] * max(1, len(bind_ips)))
        self.down_reasm = Reassembler()
        self.up_seq = 0
        self.client_fin_sent = False
        self.server_fin_done = False
        self.closed = False
        self.member_tasks: List[asyncio.Task] = []

    # ------------------------------------------------------------ helpers
    def live_members(self) -> List[_Member]:
        return [m for m in self.members if m is not None and m.alive]

    def member_down(self, member: _Member) -> None:
        if member.alive:
            member.alive = False
            self.up_sched.mark_dead(member.index)
            self.engine.member_down(member.bind_ip)
            log.info("session %s member %d (%s) down",
                     self.sid.hex()[:8], member.index, member.bind_ip)

    async def send(self, member: _Member, ftype: int, seq: int,
                   payload: bytes = b"") -> bool:
        if not member.alive:
            return False
        try:
            member.writer.write(pack_frame(ftype, seq, payload))
            await member.writer.drain()
            if payload:
                self.engine.count_up(member.bind_ip, len(payload))
            return True
        except (ConnectionError, OSError, asyncio.CancelledError):
            self.member_down(member)
            return False

    # --------------------------------------------------------------- up
    async def _send_chunk(self, chunk: bytes) -> bool:
        """Upload one chunk, failing over to the next live member.

        A member whose send fails (its adapter died mid-write) is
        marked down by :meth:`send`; the SAME chunk is then retried on
        a survivor with the SAME seq — the seq may only advance on a
        confirmed send, or the server-side reassembler would wait for
        a gap forever. (A chunk whose bytes were already accepted by
        the kernel but lost with the dying socket still cannot be
        retransmitted — that would need member-level ACKs; see the
        protocol notes in bondproto.py.)
        """
        for _ in range(len(self.up_sched.live_indices()) + 1):
            if not self.live_members():
                return False
            idx = self.up_sched.next()
            member = self.members[idx] \
                if idx < len(self.members) else None
            if member is None or not member.alive:
                continue
            if await self.send(member, FRAME_DATA, self.up_seq, chunk):
                self.up_seq += 1
                return True
            # send failed -> member is down and the scheduler skips it;
            # retry the chunk on a survivor
        return False

    async def pump_up(self, app_reader: asyncio.StreamReader) -> None:
        """Application -> adapters: chunk, schedule, frame, send."""
        try:
            while True:
                data = await app_reader.read(65536)
                if not data:
                    break
                for chunk in chunk_data(data):
                    if not await self._send_chunk(chunk):
                        return      # every adapter failed
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            # application half-closed: tell the server, wait for the
            # tail of the reply, then tear down
            self.client_fin_sent = True
            for m in self.live_members():
                await self.send(m, FRAME_FIN, 0)
            try:
                await asyncio.sleep(DRAIN_TIMEOUT)
            except asyncio.CancelledError:
                pass
            self.close()

    # ------------------------------------------------------------- down
    async def pump_member(self, member: _Member) -> None:
        """Adapter -> application for one member connection."""
        fr = FrameReader()
        try:
            while member.alive and not self.closed:
                data = await member.reader.read(65536)
                if not data:
                    break
                if not await self._feed(member, fr, data):
                    break
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            self.member_down(member)

    async def _feed(self, member: _Member, fr: FrameReader,
                    data: bytes) -> bool:
        try:
            frames = fr.feed(data)
        except BondProtocolError as e:
            log.warning("member %d protocol error: %s", member.index, e)
            return False
        for ftype, seq, payload in frames:
            if ftype == FRAME_DATA:
                try:
                    runs = self.down_reasm.feed(seq, payload)
                except BondProtocolError:
                    return False
                for run in runs:
                    self.engine.count_down(member.bind_ip, len(run))
                    try:
                        self.app_writer.write(run)
                        await self.app_writer.drain()
                    except (ConnectionError, OSError,
                            asyncio.CancelledError):
                        return False
            elif ftype == FRAME_FIN:
                # server's destination closed: half-close the app
                if not self.server_fin_done:
                    self.server_fin_done = True
                    try:
                        self.app_writer.write_eof()
                    except (ConnectionError, OSError):
                        return False
            elif ftype == FRAME_PING:
                if not await self.send(member, FRAME_PONG, 0, payload):
                    return False
        return True

    # ------------------------------------------------------------- close
    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for t in self.member_tasks:
            if not t.done():
                t.cancel()
        for m in self.members:
            if m is not None:
                m.alive = False
                try:
                    m.writer.close()
                except Exception:  # noqa: BLE001
                    pass
        self.engine.session_done(self)


class BondEngine:
    """asyncio engine owning the SOCKS listener and all sessions.

    Runs inside its own thread + event loop (see :class:`BondManager`);
    thread-safe surface: :meth:`start_listener`, :meth:`shutdown`,
    :meth:`stats`.
    """

    def __init__(self, server_host: str, server_port: int, token: str,
                 bind_ips: List[str], mode: str = "bond",
                 socks_port: int = DEFAULT_SOCKS_PORT) -> None:
        self.server_host = server_host
        self.server_port = int(server_port)
        self.token = token
        self.bind_ips = bind_ips or []
        self.mode = mode if mode in ("bond", "balance") else "bond"
        self.socks_port = int(socks_port)
        self.ready = threading.Event()
        self.error: Optional[str] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._sessions: set = set()
        self._lock = threading.Lock()
        self._member_stats: Dict[str, Dict] = {}
        self._balance_rr = 0
        self._stopped = False

    # ------------------------------------------------------------- start
    async def _amain(self) -> None:
        self.loop = asyncio.get_running_loop()
        try:
            self._server = await asyncio.start_server(
                self._handle_socks, "127.0.0.1", self.socks_port)
        except OSError as e:
            self.error = f"cannot bind SOCKS port {self.socks_port}: {e}"
            self.ready.set()
            return
        self.socks_port = self._server.sockets[0].getsockname()[1]
        self.ready.set()
        log.info("bond engine up: socks 127.0.0.1:%d -> %s:%d, mode=%s, "
                 "%d adapter(s)", self.socks_port, self.server_host,
                 self.server_port, self.mode, len(self.bind_ips))
        async with self._server:
            await self._server.serve_forever()

    def start_listener(self) -> None:
        """(engine thread) run the loop until :meth:`shutdown`."""
        try:
            asyncio.run(self._amain())
        except asyncio.CancelledError:
            # normal shutdown: shutdown() closes the server, which
            # cancels serve_forever().  CancelledError is a
            # BaseException, so this MUST be caught separately —
            # otherwise every disconnect prints an "Exception in
            # thread" traceback to stderr.
            pass
        except Exception as e:    # noqa: BLE001
            if not self.error:
                self.error = str(e)
            self.ready.set()

    def shutdown(self) -> None:
        """(thread-safe) stop the listener and every session."""
        if self._stopped or self.loop is None:
            return
        self._stopped = True
        loop = self.loop

        def _stop() -> None:
            for session in list(self._sessions):
                session.close()
            if self._server is not None:
                self._server.close()

        loop.call_soon_threadsafe(_stop)

    # -------------------------------------------------------------- stats
    def count_up(self, bind_ip: str, n: int) -> None:
        with self._lock:
            self._member_stats.setdefault(
                bind_ip, {"up": 0, "down": 0, "alive": False})["up"] += n

    def count_down(self, bind_ip: str, n: int) -> None:
        with self._lock:
            self._member_stats.setdefault(
                bind_ip, {"up": 0, "down": 0, "alive": False})["down"] += n

    def member_down(self, bind_ip: str) -> None:
        with self._lock:
            self._member_stats.setdefault(
                bind_ip, {"up": 0, "down": 0, "alive": False})
            self._member_stats[bind_ip]["alive"] = False

    def member_alive(self, bind_ip: str) -> None:
        with self._lock:
            self._member_stats.setdefault(
                bind_ip, {"up": 0, "down": 0, "alive": True})
            self._member_stats[bind_ip]["alive"] = True

    def session_done(self, session: _Session) -> None:
        with self._lock:
            self._sessions.discard(session)

    def stats(self) -> dict:
        with self._lock:
            return {
                "running": (not self._stopped and self.ready.is_set()
                            and self.error is None),
                "error": self.error,
                "mode": self.mode,
                "server": f"{self.server_host}:{self.server_port}",
                "socks_port": self.socks_port,
                "members": {ip: dict(v)
                            for ip, v in self._member_stats.items()},
                "sessions": len(self._sessions),
            }

    # -------------------------------------------------------------- socks
    @staticmethod
    async def _socks_reply(writer: asyncio.StreamWriter,
                           code: int) -> None:
        writer.write(bytes([_SOCKS_VERSION, code, 0, _ATYP_IPV4])
                     + b"\x00\x00\x00\x00\x00\x00")
        await writer.drain()

    async def _socks_read_request(
            self, reader: asyncio.StreamReader):
        """Parse a SOCKS5 CONNECT request -> (host, port) or None."""
        head = await reader.readexactly(4)
        if head[0] != _SOCKS_VERSION or head[1] != _CMD_CONNECT:
            return None
        atyp = head[3]
        if atyp == _ATYP_IPV4:
            host = ".".join(str(b) for b in await reader.readexactly(4))
        elif atyp == _ATYP_DOMAIN:
            ln = (await reader.readexactly(1))[0]
            raw = await reader.readexactly(ln)
            try:
                host = raw.decode("idna")
            except UnicodeError:
                host = raw.decode("utf-8", errors="replace")
        elif atyp == _ATYP_IPV6:
            raw = await reader.readexactly(16)
            host = ":".join(raw[i:i + 2].hex() for i in range(0, 16, 2))
        else:
            return None
        port = int.from_bytes(await reader.readexactly(2), "big")
        return host, port

    async def _handle_socks(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        """SOCKS5 negotiation, then the bonded pump."""
        session: Optional[_Session] = None
        try:
            head = await reader.readexactly(2)
            if head[0] != _SOCKS_VERSION:
                return
            methods = await reader.readexactly(head[1])
            if _METHOD_NO_AUTH not in methods:
                writer.write(bytes([_SOCKS_VERSION, 0xFF]))
                await writer.drain()
                return
            writer.write(bytes([_SOCKS_VERSION, _METHOD_NO_AUTH]))
            await writer.drain()

            dest = await self._socks_read_request(reader)
            if dest is None:
                await self._socks_reply(writer, _SOCKS_FAIL)
                return
            host, port = dest

            session = await self._open_session(host, port, writer)
            if session is None:
                await self._socks_reply(writer, _SOCKS_FAIL)
                return
            await self._socks_reply(writer, _SOCKS_OK)
            with self._lock:
                self._sessions.add(session)

            await session.pump_up(reader)   # until the app closes
        except (asyncio.IncompleteReadError, ConnectionError, OSError,
                BondProtocolError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            if session is not None:
                session.close()
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------ members
    def _member_bind_ips(self) -> List[str]:
        """Bind IPs for one new session, honouring the mode."""
        if not self.bind_ips:
            return [""]          # single member on the default route
        if self.mode == "bond":
            return list(self.bind_ips)
        ip = self.bind_ips[self._balance_rr % len(self.bind_ips)]
        self._balance_rr += 1
        return [ip]

    async def _connect_member(self, bind_ip: str, sid: bytes, index: int,
                              count: int, host: str,
                              port: int) -> Optional[_Member]:
        kwargs = {"local_addr": (bind_ip, 0)} if bind_ip else {}
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(self.server_host, self.server_port,
                                        **kwargs),
                CONNECT_TIMEOUT)
        except (ConnectionError, OSError, asyncio.TimeoutError) as e:
            log.info("member connect via %s failed: %s",
                     bind_ip or "default", e)
            return None
        hs = pack_handshake(self.token, sid, index, count, host, port)
        w.write(pack_frame(FRAME_HANDSHAKE, 0, hs))
        await w.drain()
        if bind_ip:
            self.member_alive(bind_ip)
        return _Member(index, bind_ip, r, w)

    async def _open_session(self, host: str, port: int,
                            app_writer: asyncio.StreamWriter
                            ) -> Optional[_Session]:
        """Open all members for one application stream."""
        bind_ips = self._member_bind_ips()
        sid = new_session_id()
        session = _Session(self, sid, bind_ips, app_writer)
        session.members = [None] * len(bind_ips)
        connects = [self._connect_member(ip, sid, i, len(bind_ips),
                                         host, port)
                    for i, ip in enumerate(bind_ips)]
        members = await asyncio.gather(*connects)
        for i, m in enumerate(members):
            session.members[i] = m
        if not session.live_members():
            log.info("session %s: no adapter reached the bond server",
                     sid.hex()[:8])
            for m in session.members:
                if m is not None:
                    try:
                        m.writer.close()
                    except Exception:  # noqa: BLE001
                        pass
            return None
        log.info("session %s -> %s:%d over %d member(s)",
                 sid.hex()[:8], host, port, len(session.live_members()))
        for m in session.live_members():
            task = asyncio.ensure_future(session.pump_member(m))
            session.member_tasks.append(task)
        return session


class BondManager(XrayManager):
    """Bonding lifecycle with the same surface as the other engines.

    Inherits the system-proxy switching from :class:`XrayManager`
    (``apply_system_proxy`` / ``revert_system_proxy`` — driven by
    ``socks_port`` / ``http_port``); the process machinery is replaced
    by the asyncio engine running in a daemon thread.
    """

    proxy_kind = "bond"

    def __init__(self) -> None:
        super().__init__()
        self._engine: Optional[BondEngine] = None
        self._thread: Optional[threading.Thread] = None
        self.settings_snapshot: dict = {}

    @property
    def running(self) -> bool:      # type: ignore[override]
        return (self._engine is not None
                and self._thread is not None and self._thread.is_alive()
                and not self._engine._stopped
                and self._engine.error is None)

    def start(self, settings, timeout: float = 10.0) -> None:
        """Start bonding from a BondSettings-like object.

        Needs ``server`` and ``port``; ``interfaces`` is the adapter
        selection (empty = single member on the default route).
        """
        if self.running:
            raise XrayError("link bonding is already running")
        server = (getattr(settings, "server", "") or "").strip()
        if not server:
            raise XrayError("the bond server address is empty")
        port = int(getattr(settings, "port", 10820) or 10820)
        socks_port = int(getattr(settings, "socks_port",
                                 DEFAULT_SOCKS_PORT) or DEFAULT_SOCKS_PORT)
        bind_ips = resolve_bind_ips(
            list(getattr(settings, "interfaces", []) or []))
        mode = getattr(settings, "mode", "bond") or "bond"
        token = getattr(settings, "token", "") or ""
        self.socks_port = socks_port
        # the system proxy switch (inherited) points apps at an HTTP
        # proxy — bonding is SOCKS-only, so advertise the same port for
        # both; apps that need HTTP chain through Xray/samizdat
        # (ride_bond) instead of pointing straight here.
        self.http_port = socks_port
        self.settings_snapshot = {
            "server": server, "port": port, "mode": mode,
            "bind_ips": bind_ips, "socks_port": socks_port,
        }
        engine = BondEngine(server, port, token, bind_ips, mode,
                            socks_port)
        thread = threading.Thread(target=engine.start_listener,
                                  name="proto_clean-bond", daemon=True)
        self._engine, self._thread = engine, thread
        thread.start()
        if not engine.ready.wait(timeout):
            raise XrayError(
                f"the bond engine did not come up within {timeout:.0f}s")
        if engine.error:
            self.stop(revert_proxy=False)
            raise XrayError(engine.error)

    def stop(self, revert_proxy: bool = True, timeout: float = 3.0) -> None:
        """Stop the engine (and restore the system proxy if applied)."""
        if revert_proxy and self._proxy_applied:
            try:
                self.revert_system_proxy()
            except Exception as e:  # noqa: BLE001
                log.warning("proxy revert failed: %s", e)
        engine, thread = self._engine, self._thread
        if engine is not None:
            engine.shutdown()
            engine.ready.clear()
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        self._engine = None
        self._thread = None
        log.info("bond stopped")

    def status(self) -> dict:
        st = self._engine.stats() if self._engine else {
            "running": False, "mode": "", "server": "",
            "socks_port": self.socks_port, "members": {}, "sessions": 0,
        }
        st["kind"] = "bond"
        st["system_proxy"] = self._proxy_applied
        return st
