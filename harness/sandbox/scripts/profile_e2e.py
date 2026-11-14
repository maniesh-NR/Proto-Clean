"""Profile the e2e path to find the current bottleneck."""
import cProfile, pstats, sys, time
sys.path.insert(0, "/home/z/my-project/cleanroom")
sys.path.insert(0, "/home/z/my-project/cleanroom/tests")

from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols.hysteria2 import Hysteria2Engine
from proto_clean.vpn.protocols.socks_server import LoopThread, socks5_dial
from test_hysteria2 import FakeHy2Server, UdpEcho, tcp_echo_server

lt = LoopThread("prof")
total = 4 * 1024 * 1024
chunk = 65536


async def _setup():
    echo_srv, echo_port = await tcp_echo_server()
    udp = UdpEcho()
    return {"echo": echo_srv, "udp": udp}, echo_port


holder, echo_port = lt.run(_setup(), 15)
udp = holder["udp"]
server = FakeHy2Server(echo_port, udp.port)
lt.run(server.start(), 15)
profile = M.Hysteria2Profile(server="127.0.0.1", port=server.port,
                             auth="hy2-pass", insecure=True)
eng = Hysteria2Engine()
eng.start(profile)

import asyncio

async def run_one():
    rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                               "127.0.0.1", echo_port, timeout=10)
    blob = bytes(chunk)
    sent = 0
    while sent < total:
        wr.write(blob)
        await wr.drain()
        sent += len(blob)
    got = 0
    while got < total:
        data = await rd.read(min(chunk, total - got))
        if not data:
            raise RuntimeError("early EOF")
        got += len(data)
    wr.close()

prof = cProfile.Profile()
t0 = time.monotonic()
lt.run(_profiled(), 120) if False else None

# profile inside the loop thread: wrap via run_coroutine_threadsafe on a
# profiled context is awkward; simplest: profile the loop thread's activity
# by enabling profiling on that thread via asyncio task
def _enable():
    import threading
    prof_ = cProfile.Profile()
    prof_.enable()
    asyncio.get_event_loop().profiler = prof_

async def run_profiled():
    # enable profiling for this thread (the loop thread)
    import threading
    th_prof = cProfile.Profile()
    threading.setprofile(th_prof)  # not useful for asyncio...
    return None

# simpler: run the workload with the loop's own profiler hooks via sys.setprofile
# on the loop thread is unreliable. Use cProfile around the LOOP by making the
# benchmark run IN this thread's asyncio loop instead of the LoopThread.

# Instead: measure segment timings with counters
t0 = time.monotonic()
lt.run(run_one(), 120)
dt = time.monotonic() - t0
print(f"throughput: {total/dt/1e6:.1f} MB/s")

eng.stop()
try:
    lt.run(server.stop(), 5)
except Exception:
    pass
lt.stop()
udp.stop()
