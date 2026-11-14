"""Minimal repro: SocksServer + socks5_dial + plain asyncio dialer."""
import asyncio, sys
sys.path.insert(0, "/home/z/my-project/cleanroom")
from proto_clean.vpn.protocols.socks_server import (SocksServer, LoopThread,
                                                    socks5_dial)

lt = LoopThread(name="min")

async def main():
    async def echo(rd, wr):
        while True:
            d = await rd.read(65535)
            if not d: break
            wr.write(d); await wr.drain()
    esrv = await asyncio.start_server(echo, "127.0.0.1", 0)
    echo_port = esrv.sockets[0].getsockname()[1]

    async def dial(host, port):
        return await asyncio.open_connection(host, port)

    srv = SocksServer("127.0.0.1", 0, dial, None)
    await srv.serve()
    port = srv._server.sockets[0].getsockname()[1]
    print("socks on", port, "echo on", echo_port)

    rd, wr = await socks5_dial("127.0.0.1", port, "127.0.0.1", echo_port)
    print("connected")
    wr.write(b"ping-min")
    await wr.drain()
    data = await asyncio.wait_for(rd.readexactly(8), 5)
    print("ROUNDTRIP:", data)
    wr.close()
    await srv.shutdown()
    esrv.close()

lt.run(main(), 15)
lt.stop()
print("done")
