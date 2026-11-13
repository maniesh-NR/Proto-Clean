"""Single-hop hy2 UDP roundtrip through the real engine."""
import os, sys, time
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, "tests")

from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.hysteria2 import Hysteria2Engine
from proto_clean.vpn.protocols.socks_server import (LoopThread,
                                                    build_socks5_address,
                                                    parse_socks5_address)
from test_hysteria2 import FakeHy2Server, UdpEcho, tcp_echo_server

lt = LoopThread(name="udp-dbg")

holder = {}
async def _start_echo():
    server, port = await tcp_echo_server()
    holder["echo"] = server
    return port
echo_port = lt.run(_start_echo(), 10)

udp_echo = UdpEcho()
srv_port_holder = {}
srv = FakeHy2Server(echo_port, udp_echo.port)
lt.run(srv.start(), 15)
print("server on", srv.port, "udp echo on", udp_echo.port)
srv_port_holder["port"] = srv.port

# instrument the engine protocol
from proto_clean.vpn.protocols import hysteria2 as hy2m
orig_ou = hy2m.Hysteria2Protocol.open_udp
def traced_ou(self, host, port, on_pkt):
    print("ENGINE open_udp -> %s:%d (udp_enabled=%s)" % (host, port, self.udp_enabled))
    self._dbg = True
    import socket as _s
    sock = self._transport.get_extra_info("socket")
    print("ENGINE socket: fam=%s proto=%s" % (sock.family, sock.proto))
    tr = self._transport
    print("TRANSPORT: addr=%r buffer=%d writer=%r paused=%r" % (
        getattr(tr, "_address", "?"), len(getattr(tr, "_buffer", ())),
        "registered" if hasattr(tr, "_sock_fd") else "?",
        getattr(tr, "_paused", "?")))
    # probe 1: raw OS sendto from the engine socket
    try:
        sock.sendto(b"RAW-PROBE", ("127.0.0.1", port if port != 0 else 0) if False else srv_port_holder["port"])
        print("RAW-PROBE sent via OS socket")
    except Exception as exc:
        print("RAW-PROBE failed: %r" % exc)
    # probe 2: 4-tuple form (what datagrams_to_send returns)
    try:
        self._transport.sendto(b"PROBE-4TUPLE", ("::ffff:127.0.0.1", srv_port_holder["port"], 0, 0))
        print("PROBE-4TUPLE queued")
    except Exception as exc:
        print("PROBE-4TUPLE failed: %r" % exc)
    import time as _t; _t.sleep(1.0)
    # probe 3: 2-tuple form
    try:
        self._transport.sendto(b"PROBE-2TUPLE", ("127.0.0.1", srv_port_holder["port"]))
        print("PROBE-2TUPLE queued")
    except Exception as exc:
        print("PROBE-2TUPLE failed: %r" % exc)
    send, close = orig_ou(self, host, port, on_pkt)
    def tsend(payload):
        print("ENGINE udp send %d bytes" % len(payload))
        r = send(payload)
        tr = self._transport
        print("  after send, pending=%d tbuf=%d" % (
            len(self._quic._datagrams_pending), len(getattr(tr, "_buffer", ()))))
        return r
    return tsend, close
hy2m.Hysteria2Protocol.open_udp = traced_ou
orig_hud = hy2m.Hysteria2Protocol._handle_udp_datagram
def traced_hud(self, data):
    print("ENGINE udp rx %d bytes" % len(data))
    return orig_hud(self, data)
hy2m.Hysteria2Protocol._handle_udp_datagram = traced_hud

from test_hysteria2 import Hy2ServerProtocol
orig_dgrx = Hy2ServerProtocol.datagram_received
def traced_dgrx(self, data, addr):
    print("SERVER raw rx %d bytes" % len(data))
    return orig_dgrx(self, data, addr)
Hy2ServerProtocol.datagram_received = traced_dgrx
orig_od = Hy2ServerProtocol._on_datagram
def traced_od(self, data):
    print("SERVER _on_datagram %d bytes" % len(data))
    return orig_od(self, data)
Hy2ServerProtocol._on_datagram = traced_od
orig_su = Hy2ServerProtocol._send_udp
def traced_su(self, data):
    print("SERVER _send_udp %d bytes" % len(data))
    return orig_su(self, data)
Hy2ServerProtocol._send_udp = traced_su

from proto_clean.vpn.protocols import quicbase as qb
orig_tx = qb.ObfsQuicProtocol.transmit
def traced_tx(self):
    out = self._quic.datagrams_to_send(now=self._loop.time())
    if out and getattr(self, "_dbg", False):
        print("ENGINE transmit -> %r" % ([(len(d), a) for d, a in out],))
    for data, addr in out:
        try:
            self._transport.sendto(self.wrap(data), addr[:2])
        except Exception as exc:
            print("TRANMIT SENDTO ERROR: %r" % (exc,))
    timer_at = self._quic.get_timer()
    if self._timer is not None and self._timer_at != timer_at:
        self._timer.cancel()
        self._timer = None
    if self._timer is None and timer_at is not None:
        self._timer = self._loop.call_at(timer_at, self._handle_timer)
    self._timer_at = timer_at
qb.ObfsQuicProtocol.transmit = traced_tx

eng = Hysteria2Engine()
prof = M.Hysteria2Profile(server="127.0.0.1", port=srv.port,
                          auth="hy2-pass", sni="hysteria-test", insecure=True)
eng.start(prof)
print("engine up, socks on", eng.socks_port)

async def udp_roundtrip():
    import asyncio, socket, struct
    rd, wr = await asyncio.open_connection("127.0.0.1", eng.socks_port)
    wr.write(struct.pack("!BBB", 5, 1, 0))
    await wr.drain()
    assert await rd.readexactly(2) == b"\x05\x00"
    wr.write(b"\x05\x03\x00" + build_socks5_address("0.0.0.0", 0))
    await wr.drain()
    hdr = await rd.readexactly(4)
    rest = await rd.read(64)
    relay_host, relay_port, _ = parse_socks5_address(hdr[3:4] + rest, 0)
    print("relay:", relay_host, relay_port)
    # main-thread probe straight at the server socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.sendto(b"MAIN-THREAD-PROBE", ("127.0.0.1", srv_port_holder["port"]))
    print("MAIN-THREAD-PROBE sent")
    import time as _tt; _tt.sleep(0.5)
    probe2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    probe2.sendto(b"V6-MAPPED-PROBE", ("::ffff:127.0.0.1", srv_port_holder["port"], 0, 0))
    print("V6-MAPPED-PROBE sent")
    _tt.sleep(0.5)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    addr = build_socks5_address("127.0.0.1", udp_echo.port)
    pkt = b"\x00\x00\x00" + addr + b"udp-single-hop"
    try:
        for i in range(10):
            sock.sendto(pkt, (relay_host, relay_port))
            try:
                got, _ = sock.recvfrom(65535)
            except socket.timeout:
                print("attempt", i, "timeout")
                continue
            print("got %d bytes" % len(got))
            if got[3 + len(addr):] == b"udp-single-hop":
                print("UDP ROUNDTRIP OK")
                return
        print("UDP ROUNDTRIP FAILED")
    finally:
        sock.close()
        wr.close()

lt.run(udp_roundtrip(), 30)
eng.stop()
lt.run(srv.stop(), 5)
udp_echo.stop()
lt.stop()
