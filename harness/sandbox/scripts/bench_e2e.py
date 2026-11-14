"""End-to-end throughput through the whole engine stack:
SOCKS5 client -> SocksServer pipe -> Hysteria2 QUIC tunnel (salamander
obfuscation on) -> echo server, all over loopback.  Measures the achieved
application throughput of the optimized data path.
"""
import sys, time
sys.path.insert(0, "/home/z/my-project/cleanroom")
sys.path.insert(0, "/home/z/my-project/cleanroom/tests")

from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.hysteria2 import Hysteria2Engine
from proto_clean.vpn.protocols.socks_server import LoopThread, socks5_dial
from test_hysteria2 import FakeHy2Server, UdpEcho, tcp_echo_server

lt = LoopThread("bench")
total = 8 * 1024 * 1024  # 8 MiB
chunk = 65536


async def _setup():
    echo_srv, echo_port = await tcp_echo_server()
    udp = UdpEcho()
    holder = {"echo": echo_srv, "udp": udp}
    return holder, echo_port


holder, echo_port = lt.run(_setup(), 15)
udp = holder["udp"]

for label, kw in (("plain QUIC", {}),
                  ("salamander obfs", dict(obfs="salamander",
                                           obfs_password="obf-pass"))):
    server = FakeHy2Server(echo_port, udp.port,
                           obfs_key=kw.get("obfs_password"))
    lt.run(server.start(), 15)
    profile = M.Hysteria2Profile(server="127.0.0.1", port=server.port,
                                 auth="hy2-pass", insecure=True, **kw)
    eng = Hysteria2Engine()
    eng.start(profile)
    try:
        blob = bytes(chunk)     # zero-filled is fine for throughput
        async def run_one():
            rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                                       "127.0.0.1", echo_port, timeout=10)
            sent = 0
            t0 = time.monotonic()
            while sent < total:
                wr.write(blob)
                await wr.drain()
                sent += len(blob)
            got = 0
            while got < total:
                data = await rd.read(min(chunk, total - got))
                if not data:
                    raise RuntimeError("early EOF after %d bytes" % got)
                got += len(data)
            dt = time.monotonic() - t0
            wr.close()
            return total / dt / 1e6
        mbps = lt.run(run_one(), 120)
        print(f"{label:16s}: {mbps:7.1f} MB/s through the full stack")
    finally:
        eng.stop()
        try:
            lt.run(server.stop(), 5)
        except Exception:
            pass

lt.stop()
udp.stop()
print("done")
