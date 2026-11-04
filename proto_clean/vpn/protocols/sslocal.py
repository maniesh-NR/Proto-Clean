"""Built-in Shadowsocks (AEAD) client engine — no external binary.

Runs a :class:`_SocksFrontend` (a SOCKS5 server) on 127.0.0.1 and tunnels
every CONNECT through a Shadowsocks AEAD TCP stream to
``profile.server:profile.port``:

* The client picks a random salt, derives the subkey via
  :func:`sscrypto.derive_subkey` and sends
  ``[salt][chunk(target address)][chunk]...``.  The target address is a
  plain SOCKS5 address — ``ATYP + addr + port`` — exactly what
  :func:`socks_server.build_socks5_address` produces.
* The server answers with its own salt followed by its own chunk
  stream; the response salt is consumed lazily on the first read so
  servers that only write it with the first payload byte also work.
* Afterwards the connection is a raw tunnel: every local write becomes
  one or more AEAD chunks, every read decrypts complete chunks.

Upstream chaining: when ``upstream_socks`` is set the TCP connection to
the SS server is established through that SOCKS5 proxy first
(:func:`socks5_dial`) and the Shadowsocks stream runs inside it
(``supports_upstream = True``).

UDP ASSOCIATE is disabled (``udp_dialer=None``): the shared
``socks_server`` UDP relay currently bounces client datagrams straight
back to the client instead of handing them to the engine's UdpSession
(``_UdpEndpoint.datagram_received``/``_open_udp`` wire the uplink and
downlink queues the wrong way round), so no UdpDialer can relay through
it today.  The SS UDP wire format, once the plumbing is fixed, is
``[salt][chunk(ATYP + addr + port + payload)]`` per datagram with a
fresh salt per datagram.

Front-end note: ``socks_server.SocksServer`` reads the client greeting
as 3 bytes while :func:`socks5_dial` sends a 4-byte greeting, so the
request's command byte ends up shifted (CONNECT gets a ``0x07`` reply).
``_SocksFrontend`` below re-implements only the request reader so both
``socks5_dial`` and canonical SOCKS5 clients work; it is used instead of
the base class by this engine.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Optional, Tuple

from ...log import get
from . import models as M
from .base import ProtocolEngine, ProtocolError, free_port
from .socks_server import (ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT,
                           VER5, LoopThread, SocksServer, build_socks5_address,
                           parse_socks5_address, socks5_dial)
from .sscrypto import CIPHERS, CipherCtx, EVP_BytesToKey, SessionCipher

log = get("protocols.sslocal")


# ---------------------------------------------------------------------------
# SOCKS5 front-end
# ---------------------------------------------------------------------------
async def _read_socks5_request(rd: asyncio.StreamReader) -> Tuple[int, str, int]:
    """Read the SOCKS5 request that follows the method negotiation.

    Tolerates both canonical clients (3-byte greeting ``VER NMETHODS
    METHODS`` followed by ``VER CMD RSV ATYP addr port``) and
    :func:`socks5_dial` (whose 4-byte greeting leaves one stray byte
    before the request).  Returns ``(cmd, host, port)``.
    """
    req = await asyncio.wait_for(rd.readexactly(4), 10)
    if req[0] == VER5:
        cmd, head = req[1], req[3:4]                  # VER CMD RSV ATYP
    else:
        cmd = req[2]                                  # stray greeting byte first
        head = await asyncio.wait_for(rd.readexactly(1), 10)   # ATYP
    atyp = head[0]
    if atyp == ATYP_IPV4:
        body = await asyncio.wait_for(rd.readexactly(6), 10)
    elif atyp == ATYP_DOMAIN:
        ln = (await asyncio.wait_for(rd.readexactly(1), 10))[0]
        body = await asyncio.wait_for(rd.readexactly(1 + ln + 2), 10)
    elif atyp == ATYP_IPV6:
        body = await asyncio.wait_for(rd.readexactly(18), 10)
    else:
        raise ProtocolError("bad SOCKS5 address type %d" % atyp)
    host, port, _ = parse_socks5_address(head + body, 0)
    return cmd, host, port


class _SocksFrontend(SocksServer):
    """:class:`SocksServer` whose request parsing lines up with real
    clients (see the module docstring for the greeting-length mismatch).
    Only CONNECT is served; UDP ASSOCIATE/BIND are refused until the
    shared UDP relay plumbing can forward datagrams."""

    async def _client(self, rd: asyncio.StreamReader,
                      wr: asyncio.StreamWriter) -> None:
        try:
            hdr = await asyncio.wait_for(rd.readexactly(3), 10)
            if hdr[0] != VER5:
                raise ProtocolError("not SOCKS5")
            wr.write(b"\x05\x00")                     # no auth (localhost only)
            await wr.drain()
            cmd, host, port = await _read_socks5_request(rd)
            if cmd == CMD_CONNECT:
                await self._connect(rd, wr, host, port)
            else:
                wr.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await wr.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ProtocolError, OSError, ValueError):
            try:
                wr.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await wr.drain()
            except OSError:
                pass
        finally:
            try:
                wr.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# the tunnelled stream handed to the SocksServer dialer
# ---------------------------------------------------------------------------
class _SSReader:
    """StreamReader-shaped decryptor for the server->client direction.

    The server's response salt is read lazily on the first read (some
    servers only write it together with the first response bytes).
    """

    def __init__(self, raw_rd: asyncio.StreamReader, ctx: CipherCtx) -> None:
        self._rd = raw_rd
        self._ctx = ctx
        self._sess: Optional[SessionCipher] = None
        self._out = b""
        self._eof = False

    def _session(self) -> SessionCipher:
        if self._sess is None:
            raise ProtocolError("shadowsocks response session not opened")
        return self._sess

    async def _open_session(self) -> None:
        salt = await self._rd.readexactly(self._ctx.salt_len)
        self._sess = self._ctx.new_session(salt)

    async def read(self, n: int = -1) -> bytes:
        while not self._out and not self._eof:
            try:
                if self._sess is None:
                    await self._open_session()
                raw = await self._rd.read(65535)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                self._eof = True                 # server vanished: clean EOF
                break
            if not raw:
                self._eof = True
                break
            try:
                self._out = self._session().decrypt(raw)
            except ProtocolError as exc:
                log.warning("shadowsocks stream corrupted: %s", exc)
                self._eof = True
                break
        if not self._out:
            return b""
        if n is None or n < 0:
            data, self._out = self._out, b""
        else:
            data, self._out = self._out[:n], self._out[n:]
        return data


class _SSWriter:
    """StreamWriter-shaped encryptor for the client->server direction."""

    def __init__(self, raw_wr: asyncio.StreamWriter, sess: SessionCipher) -> None:
        self._wr = raw_wr
        self._sess = sess

    def write(self, data: bytes) -> None:
        if data:
            self._wr.write(self._sess.encrypt(bytes(data)))

    async def drain(self) -> None:
        await self._wr.drain()

    def close(self) -> None:
        self._wr.close()

    def is_closing(self) -> bool:
        return self._wr.is_closing()

    async def wait_closed(self) -> None:
        await self._wr.wait_closed()


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------
class ShadowsocksEngine(ProtocolEngine):
    """Pure-Python Shadowsocks AEAD client behind a local SOCKS5 proxy.

    ``start`` validates the profile, derives the master key from the
    password (legacy SS KDF) and binds the front-end; no external
    process is involved (``_proc`` stays ``None``).  ``stop`` shuts the
    front-end down and stops the engine's event-loop thread.
    """

    proxy_kind = "shadowsocks"
    family = "proxy"
    exposes = "socks"
    supports_upstream = True
    binary_name = ""                     # built into Python

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        if not self.socks_port:
            self.socks_port = free_port(10800 + os.getpid() % 997)
        self._ctx: Optional[CipherCtx] = None
        self._profile: Optional[M.ShadowsocksProfile] = None
        self._loop_thread: Optional[LoopThread] = None
        self._server: Optional[_SocksFrontend] = None

    # -- lifecycle --------------------------------------------------------
    def start(self, profile: M.ShadowsocksProfile, timeout: float = 15.0) -> None:
        if self._server is not None:
            raise ProtocolError("shadowsocks engine already running")
        if not isinstance(profile, M.ShadowsocksProfile):
            raise ProtocolError("shadowsocks engine needs a ShadowsocksProfile")
        server = (profile.server or "").strip()
        if not server:
            raise ProtocolError("shadowsocks: empty server address")
        try:
            srv_port = int(profile.port)
        except (TypeError, ValueError):
            raise ProtocolError("shadowsocks: bad server port %r"
                                % (profile.port,)) from None
        if not 1 <= srv_port <= 65535:
            raise ProtocolError("shadowsocks: bad server port %d" % srv_port)
        method = (profile.method or "").strip().lower()
        if method not in CIPHERS:
            raise ProtocolError(
                "shadowsocks: unsupported method %r (built-in engine supports "
                "AEAD only: %s)" % (profile.method, ", ".join(sorted(CIPHERS))))
        if not profile.password:
            raise ProtocolError("shadowsocks: empty password")
        if profile.plugin:
            log.warning("profile has a SIP002 plugin (%s); the built-in "
                        "shadowsocks engine ignores it", profile.plugin)
        self._profile = profile
        self._ctx = CipherCtx(method, EVP_BytesToKey(
            profile.password.encode("utf-8"), CIPHERS[method][0]))
        # UDP ASSOCIATE stays off: the shared SocksServer UDP relay cannot
        # forward datagrams to a UdpDialer yet (see module docstring).
        thread = LoopThread(name="proto-clean-ss")
        frontend = _SocksFrontend("127.0.0.1", self.socks_port, self._dial, None)
        try:
            thread.run(frontend.serve(), timeout=timeout)
        except BaseException:
            thread.stop()
            self._profile = None
            self._ctx = None
            raise
        self._loop_thread = thread
        self._server = frontend
        self._started_at = time.time()
        log.info("shadowsocks listening on 127.0.0.1:%d", self.socks_port)

    def stop(self, timeout: float = 5.0) -> None:
        server, self._server = self._server, None
        thread, self._loop_thread = self._loop_thread, None
        self._ctx = None
        if server is not None and thread is not None:
            try:
                thread.run(server.shutdown(), timeout=timeout)
            except Exception:
                pass
        if thread is not None:
            thread.stop()
        self._started_at = 0.0
        super().stop(timeout)

    @property
    def running(self) -> bool:
        return self._server is not None

    def status(self) -> dict:
        st = super().status()
        prof = self._profile
        st["method"] = prof.method if prof else ""
        st["server"] = "%s:%d" % (prof.server, prof.port) if prof else ""
        return st

    # -- tunnel -----------------------------------------------------------
    async def _dial(self, host: str,
                    port: int) -> Tuple[_SSReader, _SSWriter]:
        """SocksServer dialer: open the SS AEAD stream to ``host:port``.

        Connects to ``profile.server`` (through the upstream SOCKS5 when
        configured), then writes ``[salt][encrypted target address
        chunk]``; the returned pair speaks decrypted plaintext from here
        on.
        """
        profile, ctx = self._profile, self._ctx
        if profile is None or ctx is None:
            raise ProtocolError("shadowsocks engine not started")
        if self.upstream_socks != ("", 0):
            up_host, up_port = self.upstream_socks
            raw_rd, raw_wr = await socks5_dial(up_host, up_port,
                                               profile.server, profile.port,
                                               timeout=10.0)
        else:
            raw_rd, raw_wr = await asyncio.wait_for(
                asyncio.open_connection(profile.server, profile.port), 10.0)
        salt = os.urandom(ctx.salt_len)
        enc = ctx.new_session(salt)
        raw_wr.write(salt + enc.encrypt(build_socks5_address(host, port)))
        await raw_wr.drain()
        # the server's own salt (response direction) is consumed lazily
        # by the reader on its first read
        return _SSReader(raw_rd, ctx), _SSWriter(raw_wr, enc)


def engine(profile: M.ShadowsocksProfile, socks_port: int = 0
           ) -> ShadowsocksEngine:
    """Convenience factory used by the protocol registry."""
    return ShadowsocksEngine(socks_port=socks_port)
