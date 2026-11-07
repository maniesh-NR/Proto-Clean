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
        except asyncio.CancelledError:
            # normal shutdown via stop(): server.close() cancels
            # serve_forever().  CancelledError is a BaseException, so
            # this must not fall through to the thread's default
            # handler (pytest flags it as an unhandled thread
            # exception; real servers would print the traceback).
            pass
        except Exception:  # noqa: BLE001
            self.ready.set()
        finally:
            # Drain the loop: cancel every still-pending task (pumps,
            # handle_member, last_member_left — the latter sleeps 60s,
            # so without an explicit cancel() the drain below would
            # wait it out and stop() would time out on join()).
            # Cancellation is idempotent, so this also covers the case
            # where stop()'s own _cancel_pending callback already ran.
            # The loop itself is closed by stop() after join() — never
            # here, or a stop() racing a dead thread would hit a
            # closed loop.
            try:
                for _round in range(3):
                    pending = [t for t in asyncio.all_tasks(self.loop)
                               if not t.done()]
                    if not pending:
                        break
                    for task in pending:
                        task.cancel()
                    self.loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True))
            except RuntimeError:         # pragma: no cover
                pass
            asyncio.set_event_loop(None)
            self.stopped.set()

    def stop(self) -> None:
        def _cancel_pending() -> None:
            for task in asyncio.all_tasks(self.loop):
                task.cancel()
        if not self.loop.is_closed():
            try:
                self.loop.call_soon_threadsafe(self.server.close)
                self.loop.call_soon_threadsafe(_cancel_pending)
                self.loop.call_soon_threadsafe(self.loop.stop)
            except RuntimeError:         # pragma: no cover
                pass                     # loop died with the thread
        self.join(timeout=5)
        if not self.loop.is_closed():
            if self.loop.is_running():
                # thread outlived join(): nudge it once, then leave the
                # daemon thread alone rather than close a running loop
                # (RuntimeError: Cannot close a running event loop)
                try:
                    self.loop.call_soon_threadsafe(self.loop.stop)
                except RuntimeError:     # pragma: no cover
                    pass
                self.join(timeout=2)
            if not self.loop.is_closed() and not self.loop.is_running():
                self.loop.close()


