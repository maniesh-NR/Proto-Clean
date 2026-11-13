"""Minimal aioquic datagram exchange probe (client<->server loopback)."""
import asyncio, sys
sys.path.insert(0, "/home/z/my-project/cleanroom")
from aioquic.asyncio.client import connect
from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, QuicEvent

import tests.test_hysteria2 as T

class SrvProto(QuicConnectionProtocol):
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, DatagramFrameReceived):
            print("SRV got dg:", event.data, flush=True)
            self._quic.send_datagram_frame(b"srv-reply:" + event.data)
            self.transmit()

class CliProto(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.replies = []
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, DatagramFrameReceived):
            print("CLI got dg:", event.data, flush=True)
            self.replies.append(event.data)

async def main():
    cert, key = T.make_cert_key()
    der, priv = T.to_crypto_objects(cert, key)
    scfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    scfg.certificate = T.load_cert_from_der(der)
    scfg.private_key = priv
    scfg.verify_mode = 0
    scfg.max_datagram_frame_size = 65535

    def sfactory(quic, stream_handler=None):
        return SrvProto(quic)

    server = await serve("127.0.0.1", 0, configuration=scfg,
                         create_protocol=sfactory)
    port = server._transport.get_extra_info("sockname")[1]
    print("server on", port)

    ccfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    ccfg.verify_mode = 0
    ccfg.server_name = "hysteria-test"
    ccfg.max_datagram_frame_size = 65535

    async with connect("127.0.0.1", port, configuration=ccfg,
                       create_protocol=lambda q, stream_handler=None: CliProto(q),
                       wait_connected=True) as cli:
        print("client connected, peer max dg:",
              cli._quic._remote_max_datagram_frame_size)
        cli._quic.send_datagram_frame(b"hello-dg")
        cli.transmit()
        await asyncio.sleep(1.0)
        print("replies:", cli.replies)
    server.close()

asyncio.run(main())
print("done")
