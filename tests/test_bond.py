"""End-to-end tests for the bonding client (BondManager + engine).

Everything runs on loopback: a TCP echo destination, the bond server
(test harness from test_bondserver) and the BondManager's local SOCKS5
frontend. The two "adapters" are 127.0.0.1 and 127.0.0.2 (the whole
127/8 is local, but they are distinct *bind addresses*, which is what
multi-member routing needs).
"""

from __future__ import annotations

import socket
import time
from types import SimpleNamespace

import pytest

from tests.test_bondserver import _BondServerThread, _EchoServer
from proto_clean.vpn.bond import BondManager, DEFAULT_SOCKS_PORT
from proto_clean.vpn.xray import XrayError


def _settings(server_port, mode="bond", interfaces=("127.0.0.1",
                                                     "127.0.0.2"),
              socks_port=0, token=""):
    return SimpleNamespace(
        server="127.0.0.1", port=server_port, mode=mode,
        interfaces=list(interfaces), socks_port=socks_port or 0,
        token=token,
    )


class _SocksClient:
    """Minimal SOCKS5 client for driving the engine from tests."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port),
                                             timeout=10)
        self.sock.settimeout(10)

    def connect(self, host: str, port: int) -> bool:
        self.sock.sendall(b"\x05\x01\x00")            # no-auth
        assert self.sock.recv(2) == b"\x05\x00"
        raw = host.encode()
        self.sock.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(raw)])
                          + raw + port.to_bytes(2, "big"))
        reply = self.sock.recv(10)
        return reply[1] == 0

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_all(self, n: int, timeout: float = 15.0) -> bytes:
        out = bytearray()
        deadline = time.time() + timeout
        while len(out) < n and time.time() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = self.sock.recv(min(65536, n - len(out)))
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture()
def echo():
    srv = _EchoServer()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture()
def bond_server():
    srv = _BondServerThread()
    srv.start()
    srv.ready.wait(5)
    yield srv
    srv.stop()


class TestBondManager:
    def test_bond_mode_round_trip(self, echo, bond_server):
        """Two adapters, one stream: the payload crosses in chunks on
        both members and the echo returns over both as well."""
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond"))
            c = _SocksClient(mgr.socks_port)
            assert c.connect("127.0.0.1", echo.port)
            payload = bytes(range(256)) * 300          # 76.8 KiB
            c.send(payload)
            got = c.recv_all(len(payload))
            assert got == payload
            c.close()
            # both members were used (upload split across adapters)
            stats = mgr.status()
            assert stats["mode"] == "bond"
            ups = [m["up"] for m in stats["members"].values()]
            assert len(stats["members"]) == 2
            assert sum(ups) >= len(payload)
        finally:
            mgr.stop()

    def test_balance_mode_round_trip(self, echo, bond_server):
        """Balance mode: one member per stream, round-robin."""
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="balance"))
            c1 = _SocksClient(mgr.socks_port)
            assert c1.connect("127.0.0.1", echo.port)
            c1.send(b"first")
            assert c1.recv_all(5) == b"first"
            c2 = _SocksClient(mgr.socks_port)
            assert c2.connect("127.0.0.1", echo.port)
            c2.send(b"second")
            assert c2.recv_all(6) == b"second"
            stats = mgr.status()
            assert stats["mode"] == "balance"
            assert len(stats["members"]) == 2     # rr touched both
            c1.close(); c2.close()
        finally:
            mgr.stop()

    def test_rejects_empty_server(self):
        mgr = BondManager()
        with pytest.raises(XrayError):
            mgr.start(SimpleNamespace(server="", port=10820, mode="bond",
                                      interfaces=[], socks_port=0,
                                      token=""))

    def test_socks_failure_when_server_unreachable(self):
        mgr = BondManager()
        dead = socket.socket(); dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]; dead.close()
        try:
            mgr.start(_settings(dead_port))
            c = _SocksClient(mgr.socks_port)
            assert not c.connect("127.0.0.1", 80)    # 05 01 failure
            c.close()
        finally:
            mgr.stop()

    def test_stop_stops(self, echo, bond_server):
        mgr = BondManager()
        mgr.start(_settings(bond_server.port))
        port = mgr.socks_port
        assert mgr.running
        mgr.stop()
        assert not mgr.running
        # the SOCKS port is closed again
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1)
            reachable = True
        except OSError:
            reachable = False
        assert not reachable
        # double stop is fine
        mgr.stop()

    def test_status_shape(self, echo, bond_server):
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port))
            st = mgr.status()
            assert st["kind"] == "bond"
            assert st["running"] is True
            assert st["server"] == f"127.0.0.1:{bond_server.port}"
            assert isinstance(st["members"], dict)
        finally:
            mgr.stop()
        assert mgr.status()["running"] is False

    def test_large_transfer_survives_member_death(self, echo, bond_server):
        """Kill one adapter's server-side member mid-transfer: the
        client keeps sending on the survivor (failover)."""
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond"))
            c = _SocksClient(mgr.socks_port)
            assert c.connect("127.0.0.1", echo.port)
            c.send(b"before")
            assert c.recv_all(6) == b"before"
            # drop one member connection server-side (thread-safe:
            # asyncio writers may only be touched from their own loop)
            sid = next(iter(bond_server.server.sessions))
            session = bond_server.server.sessions[sid]
            members = session.live_members()
            assert len(members) == 2
            doomed = members[1].writer
            bond_server.loop.call_soon_threadsafe(doomed.close)
            time.sleep(0.5)
            c.send(b"-after")
            assert c.recv_all(6) == b"-after"
            c.close()
        finally:
            mgr.stop()
