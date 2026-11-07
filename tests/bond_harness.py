"""Shared loopback harness for the bond tests (echo destination +
bond server threads). Not a test module — imported by test_bondserver
and test_bond."""

from __future__ import annotations

import asyncio
import socket
import threading

from proto_clean.vpn.bondserver import BondServer


class _EchoServer(threading.Thread):
    """Plain TCP echo destination."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(4)
        self.done = threading.Event()

    def run(self) -> None:
        while not self.done.is_set():
            try:
                self.sock.settimeout(0.2)
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        conn.settimeout(None)      # accepted sockets must not inherit
        with conn:                 # the listening socket's timeout
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                conn.sendall(data)

    def stop(self) -> None:
        self.done.set()
        try:
            self.sock.close()
        except OSError:
            pass


class _BondServerThread(threading.Thread):
    """Run the asyncio bond server in a background thread."""

    def __init__(self, token: str = "", host: str = "127.0.0.1") -> None:
        super().__init__(daemon=True)
        self.server = BondServer(token)
        self.host = host
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.close()
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.stopped = threading.Event()

    def run(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(
                self.server.listen(self.host, self.port))
            self.ready.set()
            self.loop.run_until_complete(self.server.serve_forever())
        except Exception:  # noqa: BLE001
            self.ready.set()
        finally:
            self.stopped.set()

    def stop(self) -> None:
        def _cancel_pending() -> None:
            for task in asyncio.all_tasks(self.loop):
                task.cancel()
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(_cancel_pending)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.join(timeout=5)


