"""Tests for the multiprotocol chain engine.

``build_chain`` rule tests instantiate real registry engines (never started);
the ``ChainEngine`` lifecycle tests run on stub engines that bind a real
loopback TCP socket on their allocated port, so the ``free_port`` allocation
and listening-socket semantics hold end to end.  The registry's
``make_engine`` is monkeypatched to serve the stubs.
"""

import socket

import pytest

import proto_clean.vpn.protocols as registry
from proto_clean.vpn.protocols import chain as CH
from proto_clean.vpn.protocols.base import ProtocolEngine, ProtocolError
from proto_clean.vpn.protocols.models import (ChainProfile, Hysteria2Profile,
                                              Ikev2Profile, ShadowsocksProfile,
                                              TorProfile)

SS = ShadowsocksProfile(server="ss.example", port=8388,
                        method="aes-256-gcm", password="pw")
HY2 = Hysteria2Profile(server="hy.example", port=443, auth="pw")
TOR = TorProfile()
IKE = Ikev2Profile(server="ike.example")

HOP1 = "hysteria2://pass1@h1.example:443/?engine=builtin"
HOP2 = "hysteria2://pass2@h2.example:443/?engine=builtin"
HOP_FAIL = "hysteria2://passf@fail.example:443/?engine=builtin"


# ----------------------------------------------------- build_chain rules
def test_build_chain_all_proxy_wires_upstream_in_order():
    pairs = CH.build_chain([SS, HY2])
    assert [(e.proxy_kind, p) for e, p in pairs] == \
        [("shadowsocks", SS), ("hysteria2", HY2)]
    e0, e1 = pairs[0][0], pairs[1][0]
    assert e0.upstream_socks == ("", 0)
    # hop 2 dials through hop 1's local SOCKS
    assert e1.upstream_socks == ("127.0.0.1", e0.socks_port)
    # distinct ports from the 10800 base, http left unallocated
    assert e0.socks_port >= 10800 and e1.socks_port >= 10800
    assert e0.socks_port != e1.socks_port
    assert e0.http_port == 0 and e1.http_port == 0
    assert e0.running is False and e1.running is False   # built, not started


def test_build_chain_three_hops_chain_ports():
    pairs = CH.build_chain([SS, HY2, TOR])
    assert [e.proxy_kind for e, _p in pairs] == \
        ["shadowsocks", "hysteria2", "tor"]
    e0, e1, e2 = (e for e, _p in pairs)
    ports = [e0.socks_port, e1.socks_port, e2.socks_port]
    assert len(set(ports)) == 3                          # all distinct
    assert e1.upstream_socks == ("127.0.0.1", e0.socks_port)
    assert e2.upstream_socks == ("127.0.0.1", e1.socks_port)


def test_build_chain_tunnel_first_single_hop_ok():
    pairs = CH.build_chain([IKE])
    assert len(pairs) == 1
    eng, prof = pairs[0]
    assert eng.proxy_kind == "ikev2"
    assert prof is IKE
    assert eng.upstream_socks == ("", 0)


def test_build_chain_tunnel_not_first_raises():
    with pytest.raises(CH.ChainError) as ei:
        CH.build_chain([SS, IKE])
    assert "ikev2" in str(ei.value)
    assert "first hop" in str(ei.value)


def test_build_chain_nothing_may_follow_tunnel():
    with pytest.raises(CH.ChainError) as ei:
        CH.build_chain([IKE, SS])
    msg = str(ei.value)
    assert "ikev2" in msg and "takes all traffic" in msg


def test_build_chain_empty_raises():
    with pytest.raises(CH.ChainError):
        CH.build_chain([])


def test_build_chain_unknown_kind_raises():
    class _Ghost(ShadowsocksProfile):
        kind = "nope"

    with pytest.raises(CH.ChainError) as ei:
        CH.build_chain([_Ghost(server="x", method="aes-256-gcm", password="p")])
    assert "hop 1" in str(ei.value) and "nope" in str(ei.value)


class _DumbEngine(ProtocolEngine):
    """Proxy-style engine without upstream support (exposes socks)."""

    proxy_kind = "dumb"
    family = "proxy"
    exposes = "socks"
    supports_upstream = False

    def __init__(self, socks_port=0, http_port=0):
        super().__init__(socks_port, http_port)


class _DumbProfile(ShadowsocksProfile):
    kind = "dumb"


def test_build_chain_no_upstream_support_raises_naming_pair(monkeypatch):
    real_make = registry.make_engine

    def fake_make(kind, profile, socks_port=0):
        if kind == "dumb":
            return _DumbEngine(socks_port=socks_port)
        return real_make(kind, profile, socks_port=socks_port)

    monkeypatch.setattr(registry, "make_engine", fake_make)
    with pytest.raises(CH.ChainError) as ei:
        CH.build_chain([SS, _DumbProfile(server="x", method="aes-256-gcm",
                                         password="p")])
    msg = str(ei.value)
    assert "shadowsocks" in msg and "dumb" in msg
    assert "upstream" in msg


# ------------------------------------------------------------ stub engines
class StubProxyEngine(ProtocolEngine):
    """Binds a real listening TCP socket on its allocated port."""

    proxy_kind = "stub"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True
    binary_name = ""
    recorder = None                       # {"started": [ports], "stopped": [...]}

    def __init__(self, socks_port=0, http_port=0):
        super().__init__(socks_port, http_port)
        self._sock = None

    def start(self, profile, timeout=15.0):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.socks_port))
        sock.listen(16)
        self._sock = sock
        type(self).recorder["started"].append(self.socks_port)

    def stop(self, timeout=5.0):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        type(self).recorder["stopped"].append(self.socks_port)

    @property
    def running(self):
        return self._sock is not None


class FailingStubEngine(StubProxyEngine):
    """Refuses to start (before binding anything)."""

    proxy_kind = "stubfail"

    def start(self, profile, timeout=15.0):
        raise ProtocolError("stub refusal (deliberate)")


@pytest.fixture()
def stub_registry(monkeypatch):
    rec = {"started": [], "stopped": []}
    StubProxyEngine.recorder = rec
    real_make = registry.make_engine

    def fake_make(kind, profile, socks_port=0):
        if kind == "hysteria2":
            cls = FailingStubEngine \
                if getattr(profile, "server", "") == "fail.example" \
                else StubProxyEngine
            return cls(socks_port=socks_port)
        return real_make(kind, profile, socks_port=socks_port)

    monkeypatch.setattr(registry, "make_engine", fake_make)
    yield rec
    StubProxyEngine.recorder = None


def _assert_listening(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def _assert_closed(port):
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            pass


# ------------------------------------------------------------ ChainEngine
def test_chain_engine_factory():
    e = CH.engine(ChainProfile(hops=[HOP1]))
    assert isinstance(e, CH.ChainEngine)
    assert e.proxy_kind == "chain"
    assert e.family == "proxy"
    assert e.exposes == "socks"
    assert e.supports_upstream is True
    assert e.binary_name == ""
    assert e.engines == []
    assert e.running is False


def test_chain_start_stop_two_stubs(stub_registry):
    prof = ChainProfile(hops=[HOP1, HOP2])
    chain = CH.ChainEngine()
    chain.start(prof, timeout=10)
    assert chain.running is True
    started = stub_registry["started"]
    assert len(started) == 2 and started[0] != started[1]
    # start order: first hop first; chain endpoint = last hop's port
    e0, e1 = chain.engines
    assert started == [e0.socks_port, e1.socks_port]
    assert chain.socks_port == e1.socks_port
    # upstream wiring held in order
    assert e0.upstream_socks == ("", 0)
    assert e1.upstream_socks == ("127.0.0.1", e0.socks_port)
    # both hops really listen on their ports
    _assert_listening(e0.socks_port)
    _assert_listening(e1.socks_port)
    st = chain.status()
    assert st["kind"] == "chain" and st["running"] is True
    assert st["socks_port"] == chain.socks_port
    assert st["hops"] == [
        {"kind": "stub", "running": True, "socks_port": e0.socks_port},
        {"kind": "stub", "running": True, "socks_port": e1.socks_port},
    ]
    assert st["exit"] == "stub"
    chain.stop()
    assert chain.running is False
    # stop order: reverse (exit hop first)
    assert stub_registry["stopped"] == [e1.socks_port, e0.socks_port]
    _assert_closed(e0.socks_port)
    _assert_closed(e1.socks_port)


def test_chain_single_hop(stub_registry):
    chain = CH.ChainEngine()
    chain.start(ChainProfile(hops=[HOP1]), timeout=10)
    assert chain.running is True
    assert len(chain.engines) == 1
    assert chain.socks_port == stub_registry["started"][0]
    assert chain.status()["exit"] == "stub"
    chain.stop()
    assert chain.running is False


def test_chain_failure_mid_chain_stops_earlier_engines(stub_registry):
    chain = CH.ChainEngine()
    with pytest.raises(CH.ChainError) as ei:
        chain.start(ChainProfile(hops=[HOP1, HOP_FAIL]), timeout=10)
    msg = str(ei.value)
    assert "hop 2" in msg and "stub refusal" in msg
    # hop 1 was started and then unwound
    started = stub_registry["started"]
    assert len(started) == 1
    assert stub_registry["stopped"] == started
    assert chain.running is False
    assert chain.engines == []
    _assert_closed(started[0])


def test_chain_bad_link_reports_hop(stub_registry):
    chain = CH.ChainEngine()
    with pytest.raises(CH.ChainError) as ei:
        chain.start(ChainProfile(hops=["not-a-link", HOP1]), timeout=10)
    assert "hop 1" in str(ei.value)
    assert chain.running is False
    assert stub_registry["started"] == []       # nothing started


def test_chain_empty_profile_raises(stub_registry):
    with pytest.raises(CH.ChainError):
        CH.ChainEngine().start(ChainProfile(hops=[]), timeout=10)


def test_chain_rejects_non_chain_profile(stub_registry):
    with pytest.raises(CH.ChainError):
        CH.ChainEngine().start(Hysteria2Profile(server="x"), timeout=10)


def test_chain_stop_without_start_is_noop(stub_registry):
    chain = CH.ChainEngine()
    chain.stop()
    assert chain.running is False
    assert chain.status()["hops"] == []
    assert chain.status()["exit"] == ""
