"""Debug the bond server data path step by step."""
import asyncio, socket, threading, time, sys
sys.path.insert(0, "/home/z/my-project/cleanroom")

from proto_clean.vpn.bondproto import (FRAME_DATA, FRAME_FIN, FRAME_HANDSHAKE,
    FrameReader, new_session_id, pack_frame, pack_handshake)
from proto_clean.vpn.bondserver import BondServer

# echo destination
def echo_server():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0)); s.listen(4)
    port = s.getsockname()[1]
    def run():
        conn, _ = s.accept()
        with conn:
            while True:
                d = conn.recv(65536)
                if not d: break
                conn.sendall(d)
    threading.Thread(target=run, daemon=True).start()
    return port

eport = echo_server()
print("echo on", eport)

server = BondServer("")
loop = asyncio.new_event_loop()

def run_server():
    asyncio.set_event_loop(loop)
    loop.run_until_complete(server.listen("127.0.0.1", 0))
    # get the actual port
    loop.run_until_complete(server.serve_forever())

t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(0.5)
# find port: server._server sockets
for _ in range(20):
    try:
        port = server._server.sockets[0].getsockname()[1]
        break
    except Exception:
        time.sleep(0.1)
print("bond on", port)

sid = new_session_id()
m = socket.create_connection(("127.0.0.1", port), timeout=5)
m.settimeout(5)
m.sendall(pack_frame(FRAME_HANDSHAKE, 0, pack_handshake("", sid, 0, 1, "127.0.0.1", eport)))
time.sleep(0.3)
print("sessions:", len(server.sessions))
m.sendall(pack_frame(FRAME_DATA, 0, b"hello"))
time.sleep(0.5)
print("bytes_up:", server.bytes_up, "bytes_down:", server.bytes_down)
try:
    d = m.recv(65536)
    print("recv:", d[:80])
    r = FrameReader()
    print("frames:", r.feed(d))
except socket.timeout:
    print("RECV TIMEOUT — no data came back")
