"""The Proto Clean Bond server — the rejoin point for bonded streams.

Run this on any reachable host (a VPS, a box at home, …):

    python3 -m proto_clean.bondserver --listen 0.0.0.0:10820 --token s3cret

The client side (see :mod:`proto_clean.vpn.bond`) splits each TCP
stream into sequenced PCB chunks and sends them over one *member*
connection per network adapter, each member bound to that adapter's
local address. This module is the mirror image:

* members are grouped by ``session_id`` (from the handshake),
* client->destination chunks are reassembled in ``seq`` order (they
  interleave freely across adapters) and forwarded to the destination,
* destination->client bytes are chunked and spread across the *live*
  members with a weighted scheduler, so the download direction also
  uses every adapter.

A session survives individual member loss — a dropped adapter just
loses its share of the schedule to the survivors, and sequenced chunks
make the reordering a non-event. When the last member dies (or the
destination closes) the session ends.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Dict, Optional

from ..log import get
from .bondproto import (
    FRAME_DATA, FRAME_FIN, FRAME_HANDSHAKE, FRAME_MEMBER_DOWN, FRAME_PING,
    FRAME_PONG, BondProtocolError, FrameReader, Reassembler,
    WeightedScheduler, chunk_data, handshake_matches_token,
    pack_frame, pack_handshake, unpack_handshake,
)

log = get("bondserver")

MEMBER_IDLE_TIMEOUT = 300.0       # seconds without any frame -> drop member
SESSION_ORPHAN_TIMEOUT = 60.0     # no live members for this long -> reap


class _Member:
    """One client TCP connection belonging to a session."""

    __slots__ = ("index", "writer", "alive")

    def __init__(self, index: int, writer: asyncio.StreamWriter) -> None:
        self.index = index
        self.writer = writer
        self.alive = True


class BondSession:
    """All state for one bonded stream: members + the destination pipe."""

    def __init__(self, server: "BondServer", session_id: bytes,
                 host: str, port: int, member_count: int) -> None:
        self.server = server
        self.session_id = session_id
        self.host = host
        self.port = port
        self.members: Dict[int, _Member] = {}
        self.down_sched = WeightedScheduler(
            [1] * max(1, member_count))
        self.up_reasm = Reassembler()
        self.down_seq = 0
        self.dest_reader: Optional[asyncio.StreamReader] = None
        self.dest_writer: Optional[asyncio.StreamWriter] = None
        self.dest_task: Optional[asyncio.Task] = None
        self.up_task: Optional[asyncio.Task] = None
        self._up_queue: asyncio.Queue = asyncio.Queue()
        self.client_fin = False
        self.closed = False

    # ------------------------------------------------------------ helpers
    def live_members(self) -> list:
        return [m for m in self.members.values() if m.alive]

    async def _send(self, member: _Member, ftype: int, seq: int,
                    payload: bytes = b"") -> bool:
        """Send one frame; on failure mark the member dead."""
        if not member.alive:
            return False
        try:
            member.writer.write(pack_frame(ftype, seq, payload))
            await member.writer.drain()
            return True
        except (ConnectionError, OSError, asyncio.CancelledError):
            self._drop_member(member)
            return False

    def _drop_member(self, member: _Member) -> None:
        if member.alive:
            member.alive = False
            log.info("session %s member %d down",
                     self.session_id.hex()[:8], member.index)
            self.down_sched.mark_dead(member.index)

    # ------------------------------------------------------ destination
    async def _connect_dest(self) -> None:
        try:
            self.dest_reader, self.dest_writer = await asyncio.open_connection(
                self.host, self.port)
        except (ConnectionError, OSError) as e:
            log.info("session %s connect to %s:%s failed: %s",
                     self.session_id.hex()[:8], self.host, self.port, e)
            await self._finish()
            return
        self.dest_task = asyncio.ensure_future(self._dest_pump())
        self.up_task = asyncio.ensure_future(self._up_pump())

    async def _up_pump(self) -> None:
        """Reassembled client chunks -> destination, in order.

        Chunks that arrive *before* the destination connects simply wait
        in ``_up_queue`` — bonding must not lose the first packets of a
        stream while the slower adapter's handshake is still in flight.
        ``None`` is the end-of-stream sentinel (client FIN).
        """
        while True:
            item = await self._up_queue.get()
            if item is None:
                if self.dest_writer is not None \
                        and not self.dest_writer.is_closing():
                    try:
                        self.dest_writer.write_eof()
                    except (ConnectionError, OSError):
                        pass
                return
            if self.dest_writer is None or self.dest_writer.is_closing():
                continue        # destination gone; drop quietly
            try:
                self.dest_writer.write(item)
                await self.dest_writer.drain()
            except (ConnectionError, OSError):
                await self._finish()
                return

    async def _dest_pump(self) -> None:
        """Destination -> client: chunk + schedule across live members."""
        try:
            while True:
                data = await self.dest_reader.read(65536)
                if not data:
                    break
                self.server.bytes_down += len(data)
                for chunk in chunk_data(data):
                    if not self.live_members():
                        return
                    sent = False
                    for _ in range(len(self.down_sched.live_indices())):
                        idx = self.down_sched.next()
                        member = self.members.get(idx)
                        if member is None or not member.alive:
                            continue
                        if await self._send(member, FRAME_DATA,
                                            self.down_seq, chunk):
                            sent = True
                        self.down_seq += 1
                        break
                    if not sent:
                        # every live member just failed; session is over
                        return
        except (ConnectionError, OSError):
            pass
        finally:
            # destination closed -> half-close every member (client can
            # still upload; we just have nothing more to say)
            for m in self.live_members():
                await self._send(m, FRAME_FIN, 0)
            if self.client_fin:
                await self._finish()

    async def feed_up(self, seq: int, payload: bytes) -> None:
        """Client -> destination chunk (reassemble, queue for the pump)."""
        for run in self.up_reasm.feed(seq, payload):
            self.server.bytes_up += len(run)
            self._up_queue.put_nowait(run)

    async def client_half_close(self) -> None:
        self.client_fin = True
        self._up_queue.put_nowait(None)
        if self.dest_task is not None and self.dest_task.done():
            await self._finish()

    async def _finish(self) -> None:
        """Tear the whole session down (members get FIN then close)."""
        if self.closed:
            return
        self.closed = True
        for task in (self.dest_task, self.up_task):
            if task is not None and not task.done():
                task.cancel()
        for m in self.live_members():
            try:
                m.writer.write(pack_frame(FRAME_FIN, 0))
                await m.writer.drain()
            except (ConnectionError, OSError):
                pass
        for m in self.members.values():
            try:
                m.writer.close()
            except Exception:  # noqa: BLE001
                pass
        if self.dest_writer is not None:
            try:
                self.dest_writer.close()
            except Exception:  # noqa: BLE001
                pass
        self.server.drop_session(self.session_id)
        log.info("session %s closed", self.session_id.hex()[:8])

    async def last_member_left(self) -> None:
        """No live members remain: give the stream a short grace period,
        then close (a flapping adapter pair should not kill a session
        where one link recovers within the window)."""
        await asyncio.sleep(SESSION_ORPHAN_TIMEOUT)
        if not self.live_members():
            await self._finish()


class BondServer:
    """asyncio server: accept members, validate handshakes, run sessions."""

    def __init__(self, token: str = "") -> None:
        self.token = token
        self.sessions: Dict[bytes, BondSession] = {}
        self.bytes_up = 0
        self.bytes_down = 0
        self._server: Optional[asyncio.AbstractServer] = None

    # ------------------------------------------------------------ serving
    async def handle_member(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        session: Optional[BondSession] = None
        member: Optional[_Member] = None
        reader_fr = FrameReader()
        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.read(65536), MEMBER_IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                for ftype, seq, payload in reader_fr.feed(data):
                    if ftype == FRAME_HANDSHAKE:
                        hs = unpack_handshake(payload)
                        if not handshake_matches_token(
                                hs["auth"], self.token, hs["session_id"]):
                            log.info("auth failed from %s", peer)
                            return
                        session, member = self._join(hs, writer)
                        if session is None:
                            return
                    elif session is None:
                        # data before a (valid) handshake — protocol abuse
                        return
                    elif ftype == FRAME_DATA:
                        await session.feed_up(seq, payload)
                    elif ftype == FRAME_FIN:
                        await session.client_half_close()
                    elif ftype == FRAME_PING:
                        if member is not None:
                            await session._send(member, FRAME_PONG, 0,
                                                payload)
                    elif ftype == FRAME_MEMBER_DOWN:
                        if member is not None and payload:
                            idx = payload[0]
                            other = session.members.get(idx)
                            if other is not None:
                                session._drop_member(other)
                    # PONG: ignore
        except BondProtocolError as e:
            log.info("protocol error from %s: %s", peer, e)
        except (ConnectionError, OSError):
            pass
        finally:
            if session is not None and member is not None:
                session._drop_member(member)
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
                if not session.live_members():
                    asyncio.ensure_future(session.last_member_left())
            else:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass

    def _join(self, hs: dict, writer: asyncio.StreamWriter):
        """Register a member from a handshake; returns (session, member)."""
        sid = hs["session_id"]
        session = self.sessions.get(sid)
        if session is None:
            if hs["member_index"] != 0:
                # a session must be opened by member 0
                log.info("first member of %s has index %d (want 0)",
                         sid.hex()[:8], hs["member_index"])
                return None, None
            session = BondSession(self, sid, hs["host"], hs["port"],
                                  max(1, hs["member_count"]))
            self.sessions[sid] = session
            asyncio.ensure_future(session._connect_dest())
            log.info("session %s -> %s:%s (%d members)",
                     sid.hex()[:8], hs["host"], hs["port"],
                     hs["member_count"])
        if hs["member_index"] in session.members:
            log.info("duplicate member %d for %s",
                     hs["member_index"], sid.hex()[:8])
            return None, None
        member = _Member(hs["member_index"], writer)
        session.members[member.index] = member
        session.down_sched.revive(member.index)
        return session, member

    def drop_session(self, sid: bytes) -> None:
        self.sessions.pop(sid, None)

    # ------------------------------------------------------------- runner
    async def listen(self, host: str, port: int) -> None:
        self._server = await asyncio.start_server(
            self.handle_member, host, port)
        log.info("bond server listening on %s:%d (auth %s)",
                 host, port, "token" if self.token else "OPEN")

    async def serve_forever(self) -> None:
        async with self._server:
            await self._server.serve_forever()

    def close(self) -> None:
        if self._server is not None:
            self._server.close()


def run_server(host: str, port: int, token: str = "") -> None:
    """Blocking entry point (CLI / tests)."""
    server = BondServer(token)

    async def _amain() -> None:
        await server.listen(host, port)
        await server.serve_forever()

    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="proto-clean-bond-server",
        description="Proto Clean bond server: rejoin multi-adapter "
                    "bonded TCP streams (run this on a VPS).")
    ap.add_argument("--listen", default="0.0.0.0:10820",
                    help="host:port to listen on (default 0.0.0.0:10820)")
    ap.add_argument("--token", default="",
                    help="shared secret clients must present "
                         "(no auth when empty)")
    args = ap.parse_args(argv)
    host, _, port = args.listen.rpartition(":")
    host = host or "0.0.0.0"
    try:
        port = int(port)
    except ValueError:
        print(f"invalid --listen {args.listen!r}", file=sys.stderr)
        return 2
    run_server(host, port, args.token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
