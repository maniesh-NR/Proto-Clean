"""Debug: catch the server-side exception during the hy2 handshake."""
import asyncio, os, sys, threading
sys.path.insert(0, "/home/z/my-project/cleanroom")

import tests.test_hysteria2 as T
from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.hysteria2 import Hysteria2Engine
from proto_clean.vpn.protocols.socks_server import LoopThread, socks5_dial

lt = LoopThread(name="dbg")

from proto_clean.vpn.protocols import hysteria2 as H
orig_cli = H.Hysteria2Protocol.quic_event_received
def cli_traced(self, event):
    if type(event).__name__ in ("StreamDataReceived", "ConnectionTerminated",
                                "DatagramFrameReceived"):
        print("CLI-EV:", type(event).__name__, getattr(event, "stream_id", ""),
              len(getattr(event, "data", b"") or b""))
    return orig_cli(self, event)
H.Hysteria2Protocol.quic_event_received = cli_traced

orig = T.Hy2ServerProtocol.quic_event_received
def traced(self, event):
    print("SRV-EV:", type(event).__name__,
          getattr(event, "stream_id", ""),
          (getattr(event, "error_code", ""), getattr(event, "reason_phrase", ""))
          if type(event).__name__ == "ConnectionTerminated" else "")
    return orig(self, event)
T.Hy2ServerProtocol.quic_event_received = traced

orig_cli_wrap = H.Hysteria2Protocol
og_transmit = T.ObfsQuicProtocol.transmit
def tx_traced(self):
    for data, addr in self._quic.datagrams_to_send(now=self._loop.time()):
        wrapped = self.wrap(data)
        who = "CLI" if isinstance(self, H.Hysteria2Protocol) else "SRV"
        print("%s-TX %d->%d first=%s wrap=%s" % (who, len(data), len(wrapped),
              data[:1].hex(), self.wrap.__func__ if hasattr(self.wrap, '__func__') else self.wrap),
              flush=True)
        self._transport.sendto(wrapped, addr)
    timer_at = self._quic.get_timer()
    if self._timer is not None and self._timer_at != timer_at:
        self._timer.cancel()
        self._timer = None
    if self._timer is None and timer_at is not None:
        self._timer = self._loop.call_at(timer_at, self._handle_timer)
    self._timer_at = timer_at
T.ObfsQuicProtocol.transmit = tx_traced

orig_dg = T.ObfsQuicProtocol.datagram_received
def dg_traced(self, data, addr):
    try:
        unw = self.unwrap(bytes(data))
        print("SRV-DG %d -> unwrapped %d head=%s" % (len(data), len(unw),
              unw[:1].hex()), flush=True)
    except Exception as e:
        print("SRV-DG-UNWRAP-FAIL %d: %s" % (len(data), e), flush=True)
        return
    self._quic.receive_datagram(unw, addr, now=self._loop.time())
    while True:
        ev = self._quic.next_event()
        if ev is None:
            break
        self.quic_event_received(ev)
    try:
        self.transmit()
    except IndexError:
        print("SRV-TRANSMIT-NO-PATH", flush=True)
T.ObfsQuicProtocol.datagram_received = dg_traced

orig_maybe = T.Hy2ServerProtocol._maybe_dial_tcp
def traced_maybe(self, sid, end_stream):
    entry = self._pending.get(sid)
    print("MAYBE-DIAL sid=%d entry=%s" % (sid, entry[0] if entry else None))
    parsed = self._parse_tcp_request(bytes(entry[1])) if entry else None
    print("PARSED:", parsed, "| BUFLEN:", len(entry[1]) if entry else 0)
    return orig_maybe(self, sid, end_stream)
T.Hy2ServerProtocol._maybe_dial_tcp = traced_maybe

async def setup():
    async def echo(rd, wr):
        print("ECHO-CONN", flush=True)
        while True:
            d = await rd.read(65535)
            print("ECHO-READ %r" % d[:20], flush=True)
            if not d: break
            wr.write(d); await wr.drain()
    esrv = await asyncio.start_server(echo, "127.0.0.1", 0)
    echo_port = esrv.sockets[0].getsockname()[1]
    srv = T.FakeHy2Server(echo_port, 0, obfs_key="dbg-obf")
    await srv.start()
    return esrv, echo_port, srv

esrv, echo_port, srv = lt.run(setup(), 15)
print("hy2 server on", srv.port, "| echo on", echo_port)

eng = Hysteria2Engine()
prof = M.Hysteria2Profile(server="127.0.0.1", port=srv.port,
                          auth="hy2-pass", sni="hysteria-test",
                          insecure=True, obfs="salamander",
                          obfs_password="dbg-obf")
try:
    eng.start(prof)
    print("engine up, socks:", eng.socks_port, "udp:", eng.status()["udp"])

    async def exchange():
        rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                                   "127.0.0.1", echo_port, timeout=8)
        print("CLIENT-GOT-PAIR transport_closing=%s" % wr.transport.is_closing(), flush=True)
        wr.write(b"ping")
        await wr.drain()
        print("CLIENT-SENT transport_closing=%s" % wr.transport.is_closing(), flush=True)
        return await asyncio.wait_for(rd.readexactly(4), 8)

    print("ROUNDTRIP:", lt.run(exchange(), 20))

    import tests.test_hysteria2 as T2
    udpe = T2.UdpEcho()
    print("udp echo on", udpe.port)
    # direct protocol-level UDP test (bypass SOCKS)
    result = {}
    got_holder = {}
    async def direct_udp():
        proto = eng._protocol
        def on_packet(p):
            print("DIRECT-UDP-PACKET %r" % p, flush=True)
            got_holder["p"] = p
        send, close = proto.open_udp("127.0.0.1", udpe.port, on_packet)
        send(b"direct-dg")
        await asyncio.sleep(1.0)
        close()
    lt.run(direct_udp(), 12)
    print("DIRECT result:", got_holder.get("p"))

    got = lt.run(T2._socks_udp_roundtrip(eng.socks_port, "127.0.0.1",
                                         udpe.port, b"socks-dg"), timeout=12)
    print("SOCKS-UDP-RESULT:", got)
except Exception as e:
    print("FAIL:", type(e).__name__, e)
finally:
    eng.stop()
    lt.run(srv.stop(), 5)
    esrv.close()
    lt.stop()
print("done")
