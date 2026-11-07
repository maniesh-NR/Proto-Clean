"""Desktop link-bonding verification: Linux (real), macOS + Windows.

"Combining network interfaces" has one hard requirement: every member
socket is bound to a *different source address*, so the bond server
sees one connection per adapter — and the stream must still survive
when one adapter dies. These tests pin that contract down per desktop
platform:

* **Real multi-adapter E2E.** 127.0.0.2 / 127.0.0.3 are distinct
  bind addresses on Linux ``lo`` (the whole 127/8 is local); macOS
  only configures 127.0.0.1 on lo0 and Windows varies, so the
  primary interface address is also probed as a second source —
  wherever the host offers two usable sources, a bonded session's
  members must carry exactly those peer IPs, the payload must
  round-trip byte-identical, BOTH members must carry upload data,
  balance mode must spread two streams over both adapters, and a
  server-side member kill must not interrupt the stream (failover).
* **macOS / Windows — discovery replayed, everything else real.**
  Discovery shells out to ``ifconfig`` / ``Get-NetIPAddress`` /
  ``ipconfig``, which do not exist on a Linux test host, so genuine
  tool output is replayed through the REAL discovery functions (via
  ``bondnet._run``) and the REAL name->IP resolution; the resolved
  adapters then drive REAL bond sessions over loopback stand-ins
  ("en0=127.0.0.1" pairs — the same manual-override form the settings
  UI accepts). Everything between "tool output" and "packets on the
  wire" is production code. CI additionally runs the whole suite
  natively on macos/windows runners, where those tools execute for
  real.
"""

from __future__ import annotations

import asyncio
import functools
import socket
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from bond_harness import _BondServerThread, _EchoServer
from proto_clean.vpn import bondnet
from proto_clean.vpn.bond import BondManager, _Member, _Session
from proto_clean.vpn.bondnet import Adapter, resolve_bind_ips
from proto_clean.vpn.bondproto import (
    FRAME_DATA, FrameReader,
)
from proto_clean.vpn.bondserver import BondServer, BondSession


def _aitest(fn):
    """Run an ``async def`` test with ``asyncio.run`` (the suite avoids
    the pytest-asyncio dependency — see test_perf_stability.py)."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


# --------------------------------------------------------------- helpers
def _probe(server_port: int, wanted, dest: str = "127.0.0.1") -> list:
    """The wanted source IPs that can reach *dest* here."""
    ok = []
    for ip in dict.fromkeys(wanted):
        if ip == dest:
            continue
        probe = None
        try:
            probe = socket.socket()
            probe.settimeout(2)
            probe.bind((ip, 0))
            probe.connect((dest, server_port))
            ok.append(ip)
        except OSError:
            pass
        finally:
            if probe is not None:
                try:
                    probe.close()
                except OSError:
                    pass
    return ok


def _primary_ip() -> str:
    """This host's primary IPv4 ("" when unknown)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))     # no packets leave; picks a route
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _two_bind_ips(server_port: int, dest: str = "127.0.0.1") -> list:
    """Two distinct source addresses that can reach *dest* here.

    Linux routes all of 127/8 to lo (127.0.0.2/127.0.0.3 work); macOS
    only configures 127.0.0.1 on lo0 and Windows blocks cross-address
    loopback connects (strong host model), so the primary interface
    address is tried as a source too. Empty when the host offers
    only one usable source address.
    """
    candidates = ["127.0.0.2", "127.0.0.3", "127.0.0.1"]
    primary = _primary_ip()
    if primary:
        candidates.append(primary)
    ok = _probe(server_port, candidates, dest)
    return ok[:2] if len(ok) >= 2 else []


def _plan_bind_ips(server_port: int):
    """(bind_ips, member_dest) for the E2E tests.

    Strategy 1 — members dial loopback (all interfaces listen on
    127.0.0.1 anyway). Strategy 2 — for Windows-style stacks that
    block cross-address loopback connects, members dial the primary
    address (connecting to your own IP is allowed there); the bond
    server harness then listens on all interfaces.
    """
    ips = _two_bind_ips(server_port, "127.0.0.1")
    if ips:
        return ips, "127.0.0.1"
    primary = _primary_ip()
    if primary:
        ips = _two_bind_ips(server_port, primary)
        if ips:
            return ips, primary
    return [], "127.0.0.1"


def _settings(server_port, mode="bond", interfaces=(), token="",
               server="127.0.0.1"):
    return SimpleNamespace(
        server=server, port=server_port, mode=mode,
        interfaces=list(interfaces), socks_port=0, token=token,
    )


def _peers(bond_server) -> set:
    """Source IPs the bond server has seen member connections from."""
    out = set()
    for _retry in range(3):
        try:
            sessions = list(bond_server.server.sessions.values())
            for session in sessions:
                for member in list(session.members.values()):
                    try:
                        peer = member.writer.get_extra_info("peername")
                    except Exception:        # pragma: no cover
                        peer = None
                    if peer:
                        out.add(peer[0])
            break
        except RuntimeError:                 # dict mutated mid-copy
            time.sleep(0.2)
    return out


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
        return self.sock.recv(10)[1] == 0

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_all(self, n: int, timeout: float = 20.0) -> bytes:
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
    # all interfaces: the Windows fallback dials the primary address
    srv = _BondServerThread(host="0.0.0.0")
    srv.start()
    srv.ready.wait(5)
    yield srv
    srv.stop()


def _bond_roundtrip(mgr, echo, payload: bytes) -> None:
    c = _SocksClient(mgr.socks_port)
    assert c.connect("127.0.0.1", echo.port)
    c.send(payload)
    assert c.recv_all(len(payload)) == payload
    c.close()


# ------------------------------------------------ real multi-adapter E2E
class TestMultiAdapterBonding:
    def test_two_adapters_distinct_source_ips(self, echo, bond_server):
        """Bond mode over two real bind addresses: the server sees one
        member per adapter IP, both carry data, payload survives."""
        ips, dest = _plan_bind_ips(bond_server.port)
        if len(ips) < 2:
            pytest.skip("host offers only one usable source address "
                        "(CI legs without loopback aliases hit this)")
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond",
                                interfaces=ips, server=dest))
            payload = bytes(range(256)) * 1024          # 256 KiB
            _bond_roundtrip(mgr, echo, payload)
            # exactly one member per adapter, from the right sources
            assert _peers(bond_server) == set(ips)
            st = mgr.status()
            assert st["mode"] == "bond"
            assert set(st["members"]) == set(ips)
            assert all(m["up"] > 0 for m in st["members"].values())
            assert all(m["down"] > 0 for m in st["members"].values())
            assert all(m["alive"] for m in st["members"].values())
        finally:
            mgr.stop()

    def test_balance_mode_spreads_streams(self, echo, bond_server):
        """Balance mode: consecutive streams round-robin over the
        adapters — stream one leaves via adapter A, stream two via B.
        (Finished sessions are dropped from the server's table, so
        observed peers are accumulated across the streams.)"""
        ips, dest = _plan_bind_ips(bond_server.port)
        if len(ips) < 2:
            pytest.skip("host offers only one usable source address")
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="balance",
                                interfaces=ips, server=dest))
            c1 = _SocksClient(mgr.socks_port)
            assert c1.connect("127.0.0.1", echo.port)
            c1.send(b"first-stream")
            assert c1.recv_all(12) == b"first-stream"
            assert _peers(bond_server) == {ips[0]}
            c1.close()

            c2 = _SocksClient(mgr.socks_port)
            assert c2.connect("127.0.0.1", echo.port)
            c2.send(b"second-stream")
            assert c2.recv_all(13) == b"second-stream"
            seen = {ips[0]} | _peers(bond_server)
            assert seen == set(ips)
            c2.close()

            st = mgr.status()
            assert st["mode"] == "balance"
            assert set(st["members"]) == set(ips)
        finally:
            mgr.stop()

    def test_failover_when_member_dies(self, echo, bond_server):
        """One adapter's connection is killed server-side mid-session:
        the client registers the loss, drops that adapter from the
        schedule, and the stream continues on the survivor."""
        ips, dest = _plan_bind_ips(bond_server.port)
        if len(ips) < 2:
            pytest.skip("host offers only one usable source address")
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond",
                                interfaces=ips, server=dest))
            c = _SocksClient(mgr.socks_port)
            assert c.connect("127.0.0.1", echo.port)
            c.send(b"before")
            assert c.recv_all(6) == b"before"

            # kill one member connection server-side (thread-safe:
            # asyncio writers may only be touched from their own loop)
            sid = next(iter(bond_server.server.sessions))
            members = bond_server.server.sessions[sid].live_members()
            assert len(members) == 2
            doomed = members[1].writer
            bond_server.loop.call_soon_threadsafe(doomed.close)

            # wait until the CLIENT has registered the dead member
            # (pump_member hit EOF) — after that every further chunk
            # must be scheduled onto the survivor only
            deadline = time.time() + 3
            while time.time() < deadline:
                if any(not m["alive"]
                       for m in mgr.status()["members"].values()):
                    break
                time.sleep(0.05)
            assert any(not m["alive"]
                       for m in mgr.status()["members"].values())

            c.send(b"-after")
            assert c.recv_all(6) == b"-after"
            c.close()
        finally:
            mgr.stop()


# ------------------------------------------- failover retry (the contract)
class _FakeWriter:
    """StreamWriter stand-in that records frames (or explodes)."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.frames = []

    def write(self, data: bytes) -> None:
        if self.fail:
            raise ConnectionError("adapter gone")
        self.frames.append(data)

    async def drain(self) -> None:
        if self.fail:
            raise ConnectionError("adapter gone")


class _FakeEngine:
    """BondEngine surface used by _Session."""

    def __init__(self) -> None:
        self.down = []

    def count_up(self, bind_ip, n) -> None:
        pass

    def member_down(self, bind_ip) -> None:
        self.down.append(bind_ip)

    def member_alive(self, bind_ip) -> None:
        pass


class TestMemberFailoverRetry:
    """A member death racing a chunk send must not kill the stream
    (regression: the retry loop used to break after the first send
    attempt and advance the seq on failure — a gap the reassembler
    waits for forever)."""

    @_aitest
    async def test_client_upload_retries_on_next_member(self):
        engine = _FakeEngine()
        session = _Session(engine, b"\x01" * 16,
                           ["10.0.0.1", "10.0.0.2"], None)
        dead, live = _FakeWriter(fail=True), _FakeWriter()
        session.members = [_Member(0, "10.0.0.1", None, dead),
                           _Member(1, "10.0.0.2", None, live)]
        assert await session._send_chunk(b"x" * 10) is True
        # the chunk rode the survivor, with seq 0 (no gap)
        frames = FrameReader().feed(b"".join(live.frames))
        assert [(f, s) for f, s, _ in frames] == [(FRAME_DATA, 0)]
        assert session.up_seq == 1
        assert session.members[0].alive is False
        assert engine.down == ["10.0.0.1"]

    @_aitest
    async def test_client_upload_all_members_dead(self):
        engine = _FakeEngine()
        session = _Session(engine, b"\x01" * 16,
                           ["10.0.0.1", "10.0.0.2"], None)
        session.members = [_Member(0, "10.0.0.1", None,
                                   _FakeWriter(fail=True)),
                           _Member(1, "10.0.0.2", None,
                                   _FakeWriter(fail=True))]
        assert await session._send_chunk(b"x" * 10) is False
        assert session.up_seq == 0          # seq never advanced

    @_aitest
    async def test_server_download_retries_on_next_member(self):
        server = BondServer("")
        session = BondSession(server, b"\x01" * 16, "10.9.9.9", 9, 2)
        dead, live = _FakeWriter(fail=True), _FakeWriter()
        session.members = {0: server_member(0, dead),
                           1: server_member(1, live)}
        assert await session._send_chunk(b"y" * 10) is True
        frames = FrameReader().feed(b"".join(live.frames))
        assert [(f, s) for f, s, _ in frames] == [(FRAME_DATA, 0)]
        assert session.down_seq == 1
        assert session.members[0].alive is False

    @_aitest
    async def test_server_download_all_members_dead(self):
        server = BondServer("")
        session = BondSession(server, b"\x01" * 16, "10.9.9.9", 9, 2)
        session.members = {0: server_member(0, _FakeWriter(fail=True)),
                           1: server_member(1, _FakeWriter(fail=True))}
        assert await session._send_chunk(b"y" * 10) is False
        assert session.down_seq == 0


def server_member(index: int, writer):
    from proto_clean.vpn.bondserver import _Member as _ServerMember
    return _ServerMember(index, writer)


# ----------------------------------------------- macOS (discovery replayed)
# Genuine `ifconfig -a` shape from a dual-NIC Mac (Wi-Fi en0 +
# Ethernet en1) with a VPN utun up: lo0 and inet6-only awdl0 must be
# excluded, the VPN utun IS a usable bind address.
IFCONFIG_DUAL = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
        inet 127.0.0.1 netmask 0xff000000
        inet6 ::1 prefixlen 128
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
        nd6 options=201<PERFORMNUD,DAD>
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        ether 98:01:a7:0a:1b:2c
        inet6 fe80::9a:1a:a7ff:fe0a:1b2c%en0 prefixlen 64 secured scopeid 0x4
        inet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255
        nd6 options=201<PERFORMNUD,DAD>
        media: autoselect
        status: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        ether 98:01:a7:0a:1b:2d
        inet 10.120.33.44 netmask 0xfffff000 broadcast 10.120.47.255
        media: autoselect
        status: active
awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1484
        inet6 fe80::8c:5b:6fff:fe23:1a0f%awdl0 prefixlen 64 scopedid 0x8
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffff00
"""


class TestMacosDiscovery:
    def test_discovery_and_resolution(self):
        with mock.patch.object(bondnet, "_run",
                               return_value=IFCONFIG_DUAL):
            adapters = bondnet.list_adapters(platform="macos")
        assert adapters == [Adapter("en0", "192.168.1.5"),
                            Adapter("en1", "10.120.33.44"),
                            Adapter("utun4", "10.8.0.2")]
        # the user's adapter names resolve to exactly those NIC IPs
        assert resolve_bind_ips(["en0", "en1"], adapters=adapters) == \
            ["192.168.1.5", "10.120.33.44"]

    def test_bond_session_over_discovered_adapters(self, echo,
                                                   bond_server):
        """The discovered adapters drive a real bonded session (via
        loopback stand-ins for their NIC IPs)."""
        with mock.patch.object(bondnet, "_run",
                               return_value=IFCONFIG_DUAL):
            adapters = bondnet.list_adapters(platform="macos")
        standins, dest = _plan_bind_ips(bond_server.port)
        if len(standins) < 2:
            pytest.skip("host offers only one usable source address")
        # "name=ip" manual-override pairs: en0 stands on standins[0]…
        pairs = [f"{a.name}={ip}" for a, ip in
                 zip(adapters[:2], standins)]
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond",
                                interfaces=pairs, server=dest))
            payload = bytes(range(256)) * 512          # 128 KiB
            _bond_roundtrip(mgr, echo, payload)
            assert _peers(bond_server) == set(standins)
            st = mgr.status()
            assert set(st["members"]) == set(standins)
            assert all(m["up"] > 0 for m in st["members"].values())
        finally:
            mgr.stop()


# --------------------------------------------- Windows (discovery replayed)
# Genuine `Get-NetIPAddress -AddressFamily IPv4 | Select-Object
# InterfaceAlias,IPAddress | ConvertTo-Json -Compress` shape: Ethernet
# + Wi-Fi + a WSN vEthernet, loopback excluded server-side already
# but the parser guards it anyway.
PS_JSON_DUAL = (
    '[{"InterfaceAlias":"Ethernet","IPAddress":"10.1.2.3"},'
    '{"InterfaceAlias":"Wi-Fi","IPAddress":"10.4.5.6"},'
    '{"InterfaceAlias":"vEthernet (WSL)","IPAddress":"172.30.16.1"},'
    '{"InterfaceAlias":"Loopback Pseudo-Interface 1",'
    '"IPAddress":"127.0.0.1"}]'
)

# Genuine `ipconfig` shape (the fallback when PowerShell is blocked).
IPCONFIG_DUAL = """\
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : lan.example.com
   Link-local IPv6 Address . . . . . : fe80::a123:45ff:fe67:8901%12
   IPv4 Address. . . . . . . . . . . : 10.1.2.3
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.1.2.1

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : lan.example.com
   IPv4 Address. . . . . . . . . . . : 10.4.5.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.4.5.1
"""


def _fake_run_ps(ps_text: str, ipconfig_text: str = ""):
    def _run(cmd, timeout=5.0):
        if "powershell" in (cmd or [""])[0]:
            return ps_text
        if cmd and cmd[0] == "ipconfig":
            return ipconfig_text
        return ""
    return _run


class TestWindowsDiscovery:
    def test_powershell_discovery_and_resolution(self):
        with mock.patch.object(bondnet, "_run",
                               _fake_run_ps(PS_JSON_DUAL)):
            adapters = bondnet.list_adapters(platform="windows")
        assert adapters == [Adapter("Ethernet", "10.1.2.3"),
                            Adapter("Wi-Fi", "10.4.5.6"),
                            Adapter("vEthernet (WSL)", "172.30.16.1")]
        assert resolve_bind_ips(["Wi-Fi", "Ethernet"],
                                adapters=adapters) == \
            ["10.4.5.6", "10.1.2.3"]

    def test_ipconfig_fallback_when_powershell_blocked(self):
        with mock.patch.object(bondnet, "_run",
                               _fake_run_ps("", IPCONFIG_DUAL)):
            adapters = bondnet.list_adapters(platform="windows")
        assert adapters == [Adapter("Ethernet", "10.1.2.3"),
                            Adapter("Wi-Fi", "10.4.5.6")]

    def test_bond_session_over_discovered_adapters(self, echo,
                                                   bond_server):
        standins, dest = _plan_bind_ips(bond_server.port)
        if len(standins) < 2:
            pytest.skip("host offers only one usable source address")
        pairs = [f"Ethernet={standins[0]}", f"Wi-Fi={standins[1]}"]
        mgr = BondManager()
        try:
            mgr.start(_settings(bond_server.port, mode="bond",
                                interfaces=pairs, server=dest))
            payload = bytes(range(256)) * 512          # 128 KiB
            _bond_roundtrip(mgr, echo, payload)
            assert _peers(bond_server) == set(standins)
            st = mgr.status()
            assert set(st["members"]) == set(standins)
            assert all(m["up"] > 0 for m in st["members"].values())
        finally:
            mgr.stop()
