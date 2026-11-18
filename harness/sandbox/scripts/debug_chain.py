"""Trace the two-hop chain packet flow step by step."""
import logging
logging.basicConfig(level=logging.DEBUG,
                    format="%(name)s %(message)s")
for noisy in ("asyncio",):
    logging.getLogger(noisy).setLevel(logging.WARNING)
import os, sys, time, socket, threading
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, "tests")

from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols import chain
from proto_clean.vpn.protocols.socks_server import LoopThread
from test_hysteria2 import FakeHy2Server, tcp_echo_server

lt = LoopThread(name="dbg")

# echo
holder = {}
async def _start_echo():
    server, port = await tcp_echo_server()
    holder["echo"] = server
    return port
echo_port = lt.run(_start_echo(), 10)
print("echo on", echo_port)

# hop1 server
hop1_srv = FakeHy2Server(echo_port, 0, password="p1")
lt.run(hop1_srv.start(), 15)
print("hop1 server on", hop1_srv.port)

# hop2 server
hop2_srv = FakeHy2Server(echo_port, 0, password="p2")
lt.run(hop2_srv.start(), 15)
print("hop2 server on", hop2_srv.port)

# instrument hop2 server: count datagrams received at QUIC layer
orig_ev = hop2_srv.__class__  # keep
from test_hysteria2 import Hy2ServerProtocol
recv_count = {"n": 0}
orig_on_dg = Hy2ServerProtocol._on_datagram
def counting_on_dg(self, data):
    recv_count["n"] += 1
    return orig_on_dg(self, data)
Hy2ServerProtocol._on_datagram = counting_on_dg

udp_hits = {"n": 0}
raw_server_rx = {"n": 0}
orig_udp_ev = Hy2ServerProtocol.quic_event_received
orig_dg_rx = Hy2ServerProtocol.datagram_received
def counting_dg_rx(self, data, addr):
    raw_server_rx["n"] += 1
    if raw_server_rx["n"] <= 40:
        print("SERVER raw rx %d bytes (pw=%s)" % (len(data),
              getattr(self, '_password', '?')))
    return orig_dg_rx(self, data, addr)
Hy2ServerProtocol.datagram_received = counting_dg_rx

def counting_ev(self, event):
    from aioquic.quic.events import DatagramFrameReceived
    if isinstance(event, DatagramFrameReceived):
        udp_hits["n"] += 1
        if udp_hits["n"] <= 3:
            print("SERVER datagram frame (%s) %d bytes" % (
                getattr(self, '_password', '?'), len(event.data)))
    return orig_udp_ev(self, event)
Hy2ServerProtocol.quic_event_received = counting_ev

# trace the server-side UDP relay sendto
import struct as _struct
sendto_count = {"n": 0}
_orig_sendto = socket.socket.sendto
def traced_sendto(self, data, *a, **kw):
    sendto_count["n"] += 1
    dst = a[0] if a else kw.get("addr")
    if sendto_count["n"] <= 5 or (isinstance(dst, tuple) and len(dst) >= 2
                                  and dst[1] not in (43042, 56213)
                                  and sendto_count["n"] < 60):
        print("RAW sendto %d bytes -> %r" % (len(data), dst))
    return _orig_sendto(self, data, *a, **kw)
socket.socket.sendto = traced_sendto

# instrument hop1 engine's UDP session send
from proto_clean.vpn.protocols import hysteria2 as hy2mod
open_udp_calls = []
eng1_state = {"proto": None}
orig_open_udp = hy2mod.Hysteria2Protocol.open_udp
def traced_open_udp(self, host, port, on_packet):
    print("ENGINE1 open_udp -> %s:%d" % (host, port))
    if eng1_state["proto"] is None:
        eng1_state["proto"] = self
        self._is_engine_traced = True
    send, close = orig_open_udp(self, host, port, on_packet)
    def traced_send(payload):
        proto = eng1_state["proto"]
        pending = len(proto._quic._datagrams_pending) if proto else -1
        print("ENGINE1 udp send %d bytes (pending-before=%d)" % (len(payload), pending))
        r = send(payload)
        if eng1_state.get("probed") is None:
            eng1_state["probed"] = True
            q = proto._quic
            space = q._spaces and list(q._spaces.values())
            print("  PROBE pacing_at=%r state=%r handshake_complete=%r" % (
                q._pacing_at, q._state, q._handshake_complete))
            print("  PROBE cc: cwnd=%r bytes_in_flight=%r lost=%r pto_count=%r" % (
                q._loss.congestion_window, q._loss.bytes_in_flight,
                getattr(q._loss, "_lost_packets", {}) and 0 or
                len(getattr(q._loss, "_lost_packets", {}) or {}),
                getattr(q._loss, "_pto_count", "?")))
            np = q._network_paths[0]
            print("  PROBE path validated=%r bytes_recv=%r bytes_sent=%r" % (
                np.is_validated, np.bytes_received, np.bytes_sent))
            if space:
                s = [s for s in space if getattr(s, 'ack_at', None) is not None]
                print("  PROBE ack_at=%r" % ([x.ack_at for x in s]))
            out = q.datagrams_to_send(now=proto._loop.time())
            print("  PROBE re-transmit -> %r" % ([(len(d), a) for d, a in out][:2],))
            # deep dive: why is the datagram not packed?
            from aioquic import tls as _tls
            print("  PROBE cfg.max_dg=%r remote_max_dg=%r one_rtt_send=%r" % (
                q._configuration.max_datagram_frame_size,
                q._remote_max_datagram_frame_size,
                q._cryptos[_tls.Epoch.ONE_RTT].send.is_valid()))
            print("  PROBE handshake_confirmed=%r state=%r" % (
                q._handshake_confirmed, q._state))
            import aioquic.quic.connection as qc
            b = qc.QuicPacketBuilder(
                host_cid=q.host_cid, is_client=q._is_client,
                max_datagram_size=q._max_datagram_size,
                packet_number=q._packet_number, peer_cid=q._peer_cid.cid,
                peer_token=q._peer_token, version=q._version)
            b.max_flight_bytes = q._loss.congestion_window - q._loss.bytes_in_flight
            try:
                q._write_application(b, q._network_paths[0],
                                     now=proto._loop.time())
                print("  PROBE manual _write_application OK")
            except Exception as exc:
                print("  PROBE manual _write_application raised %r" % exc)
            print("  PROBE pending after manual=%d" % len(q._datagrams_pending))
            fl = q._flush_builder(builder=b, network_path=q._network_paths[0],
                                  peer_cid=q._peer_cid.cid,
                                  now=proto._loop.time())
            print("  PROBE manual flush -> %r" % ([(len(d), a) for d, a in fl][:2],))
            for d, a in fl:
                proto._transport.sendto(d, a)
        return r
    return traced_send, close
hy2mod.Hysteria2Protocol.open_udp = traced_open_udp

# instrument quicbase udp_associate
from proto_clean.vpn.protocols import quicbase as qb
orig_assoc = qb.udp_associate
async def traced_assoc(host, port, on_packet, target=("", 0)):
    print("UDP_ASSOCIATE to %s:%d target=%r" % (host, port, target))
    return await orig_assoc(host, port, on_packet, target)
qb.udp_associate = traced_assoc

# instrument transmit on the ENGINE protocols (hop1's engine especially)
orig_transmit = qb.ObfsQuicProtocol.transmit
def traced_transmit(self):
    out = self._quic.datagrams_to_send(now=self._loop.time())
    if out and getattr(self, "_is_engine_traced", False):
        print("ENGINE1 transmit -> %d packets: %r" % (
            len(out), [(len(d), a) for d, a in out][:3]))
    for data, addr in out:
        self._transport.sendto(self.wrap(data), addr)
    timer_at = self._quic.get_timer()
    if self._timer is not None and self._timer_at != timer_at:
        self._timer.cancel()
        self._timer = None
    if self._timer is None and timer_at is not None:
        self._timer = self._loop.call_at(timer_at, self._handle_timer)
    self._timer_at = timer_at
qb.ObfsQuicProtocol.transmit = traced_transmit

# build + start chain
p1 = M.Hysteria2Profile(server="127.0.0.1", port=hop1_srv.port, auth="p1",
                        sni="hysteria-test", insecure=True)
p2 = M.Hysteria2Profile(server="127.0.0.1", port=hop2_srv.port, auth="p2",
                        sni="hysteria-test", insecure=True)

pairs = chain.build_chain([p1, p2])
print("wired: hop2 upstream ->", pairs[1][0].upstream_socks)
try:
    pairs[0][0].start(p1, timeout=20)
    print("hop1 engine up, socks on", pairs[0][0].socks_port)
    t0 = time.time()
    pairs[1][0].start(p2, timeout=20)
    print("hop2 engine up in %.1fs, socks on" % (time.time() - t0),
          pairs[1][0].socks_port)
except Exception as exc:
    print("CHAIN FAILED after %.1fs: %r" % (time.time() - t0, exc))
    print("hop2 server datagram events:", udp_hits["n"])
finally:
    for e, _ in pairs:
        try:
            e.stop()
        except Exception:
            pass
    lt.run(hop1_srv.stop(), 5)
    lt.run(hop2_srv.stop(), 5)
    lt.stop()
