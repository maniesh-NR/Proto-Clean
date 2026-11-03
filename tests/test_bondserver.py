"""End-to-end tests for the bond server over real TCP (loopback).

A TCP echo server plays the destination. The "client" is a minimal raw
PCB speaker: plain sockets sending handshakes and sequenced chunks —
deliberately lower-level than the real client so these tests pin the
wire behaviour itself.
"""

from __future__ import annotations

import socket
import time

import pytest

from bond_harness import _BondServerThread, _EchoServer
from proto_clean.vpn.bondproto import (
    FRAME_DATA, FRAME_FIN, FRAME_HANDSHAKE, FrameReader,
    new_session_id, pack_frame, pack_handshake,
)


@pytest.fixture()
def echo():
    srv = _EchoServer()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture()
def bond():
    srv = _BondServerThread()
    srv.start()
    srv.ready.wait(5)
    yield srv
    srv.stop()


def _connect(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(10)
    return s


def _handshake(sock: socket.socket, server_port: int, token: str,
               sid: bytes, index: int, count: int, host: str, port: int):
    payload = pack_handshake(token, sid, index, count, host, port)
    sock.sendall(pack_frame(FRAME_HANDSHAKE, 0, payload))


def _drain_until(sock: socket.socket, reader: FrameReader,
                 want_bytes: int, timeout: float = 10.0) -> bytes:
    """Read frames until `want_bytes` DATA payload has accumulated."""
    out = bytearray()
    deadline = time.time() + timeout
    while len(out) < want_bytes and time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        for ftype, seq, payload in reader.feed(data):
            if ftype == FRAME_DATA:
                out += payload
    return bytes(out)


class TestBondServer:
    def test_two_members_split_and_rejoin(self, echo, bond):
        """The full story: chunks interleaved across two member
        connections rejoin server-side; the echo reply comes back split
        across both members (reassembly by sequence number, exactly
        like the real client does)."""
        sid = new_session_id()
        m0 = _connect(bond.port)
        m1 = _connect(bond.port)
        _handshake(m0, bond.port, "", sid, 0, 2,
                   "127.0.0.1", echo.port)
        _handshake(m1, bond.port, "", sid, 1, 2,
                   "127.0.0.1", echo.port)

        # interleave deliberately: 0 on m0, 1 on m1, 2 on m0, 3 on m1...
        payload = [bytes([65 + i]) * 8 for i in range(4)]
        m0.sendall(pack_frame(FRAME_DATA, 0, payload[0]))
        m1.sendall(pack_frame(FRAME_DATA, 1, payload[1]))
        m1.sendall(pack_frame(FRAME_DATA, 3, payload[3]))
        m0.sendall(pack_frame(FRAME_DATA, 2, payload[2]))

        # first reply is one small chunk: it lands on exactly one member
        r0, r1 = FrameReader(), FrameReader()
        got0 = _drain_until(m0, r0, 32, timeout=2)
        got1 = _drain_until(m1, r1, 32, timeout=2)
        joined = sorted([got0, got1], key=len, reverse=True)
        assert b"".join(joined) == b"".join(payload)

        # now a payload big enough that the *reply* spans several chunks
        # (16 KiB each), so both members must carry part of the download
        blob = [bytes([i % 251]) * 16384 for i in range(6)]   # 96 KiB
        for i, part in enumerate(blob):
            seq = 4 + i          # the first exchange consumed seqs 0..3
            (m0 if i % 2 == 0 else m1).sendall(
                pack_frame(FRAME_DATA, seq, part))

        # reassemble the down direction by frame sequence number,
        # remembering which member carried which chunk
        r0, r1 = FrameReader(), FrameReader()
        got: dict = {}
        carriers: dict = {}
        deadline = time.time() + 15
        while len(got) < 6 and time.time() < deadline:
            for label, sock, fr in (("m0", m0, r0), ("m1", m1, r1)):
                sock.settimeout(0.3)
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    continue
                for ftype, seq, pay in fr.feed(data):
                    if ftype == FRAME_DATA:
                        got[seq] = pay
                        carriers[seq] = label
        # down-seq 0 was the first small reply; the blob is seqs 1..6
        assert sorted(got) == list(range(1, 7)), f"seqs: {sorted(got)}"
        assert b"".join(got[i] for i in range(1, 7)) == b"".join(blob)
        # both members carried part of the blob reply
        assert set(carriers.values()) == {"m0", "m1"}
        m0.close(); m1.close()

    def test_single_member(self, echo, bond):
        sid = new_session_id()
        m = _connect(bond.port)
        _handshake(m, bond.port, "", sid, 0, 1, "127.0.0.1", echo.port)
        m.sendall(pack_frame(FRAME_DATA, 0, b"ping-"))
        m.sendall(pack_frame(FRAME_DATA, 1, b"pong"))
        r = FrameReader()
        assert _drain_until(m, r, 9) == b"ping-pong"
        m.close()

    def test_auth_rejects_wrong_token(self, echo):
        srv = _BondServerThread(token="real-secret")
        srv.start()
        srv.ready.wait(5)
        try:
            sid = new_session_id()
            m = _connect(srv.port)
            _handshake(m, srv.port, "wrong", sid, 0, 1,
                       "127.0.0.1", echo.port)
            m.sendall(pack_frame(FRAME_DATA, 0, b"x"))
            m.settimeout(3)
            # server drops us: recv returns EOF (b"") or ECONNRESET
            try:
                assert m.recv(1024) in (b"",)
            except (ConnectionError, OSError):
                pass
            m.close()
            assert not srv.server.sessions
        finally:
            srv.stop()

    def test_member_loss_survives_on_remaining(self, echo, bond):
        """Kill one adapter mid-stream: the session keeps flowing on the
        survivor — the net-merge 'links without internet receive no
        traffic' behaviour."""
        sid = new_session_id()
        m0 = _connect(bond.port)
        m1 = _connect(bond.port)
        _handshake(m0, bond.port, "", sid, 0, 2,
                   "127.0.0.1", echo.port)
        _handshake(m1, bond.port, "", sid, 1, 2,
                   "127.0.0.1", echo.port)

        m0.sendall(pack_frame(FRAME_DATA, 0, b"first"))
        # let the server see it
        time.sleep(0.2)

        # adapter 1 dies
        m1.close()

        m0.sendall(pack_frame(FRAME_DATA, 1, b"-second"))
        r = FrameReader()
        assert _drain_until(m0, r, 12) == b"first-second"
        m0.close()

    def test_fin_closes_session(self, echo, bond):
        sid = new_session_id()
        m = _connect(bond.port)
        _handshake(m, bond.port, "", sid, 0, 1, "127.0.0.1", echo.port)
        m.sendall(pack_frame(FRAME_DATA, 0, b"bye"))
        r = FrameReader()
        assert _drain_until(m, r, 3) == b"bye"
        m.sendall(pack_frame(FRAME_FIN, 0))
        # server should close the member once the dest EOFs back
        m.settimeout(5)
        deadline = time.time() + 5
        closed = False
        while time.time() < deadline:
            try:
                if m.recv(1024) == b"":
                    closed = True
                    break
            except (ConnectionError, OSError):
                closed = True
                break
        assert closed
        m.close()

    def test_dest_unreachable_sends_fin(self, bond):
        # nothing listens on this port
        dead = socket.socket(); dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]; dead.close()
        sid = new_session_id()
        m = _connect(bond.port)
        _handshake(m, bond.port, "", sid, 0, 1, "127.0.0.1", dead_port)
        r = FrameReader()
        deadline = time.time() + 5
        got_fin = False
        while time.time() < deadline and not got_fin:
            try:
                m.settimeout(1)
                data = m.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            for ftype, seq, payload in r.feed(data):
                if ftype == FRAME_FIN:
                    got_fin = True
        assert got_fin
        m.close()

    def test_data_before_handshake_rejected(self, bond):
        m = _connect(bond.port)
        m.sendall(pack_frame(FRAME_DATA, 0, b"rogue"))
        m.settimeout(3)
        try:
            data = m.recv(1024)
            assert data == b""
        except (ConnectionError, OSError):
            pass
        m.close()

    def test_session_requires_member_zero_first(self, bond):
        sid = new_session_id()
        m = _connect(bond.port)
        _handshake(m, bond.port, "", sid, 1, 2, "127.0.0.1", 80)
        m.settimeout(3)
        try:
            assert m.recv(1024) == b""
        except (ConnectionError, OSError):
            pass
        m.close()
        assert not bond.server.sessions
