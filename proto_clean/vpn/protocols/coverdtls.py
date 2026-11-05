"""Cover-DTLS — a DTLS 1.2 covert transport (pure pyOpenSSL, no binaries).

The wire is a *normal-looking* DTLS 1.2 session over UDP: to a censor it is
indistinguishable from any DTLS VPN / WebRTC / QUIC-adjacent application.
The proxy protocol runs *inside* the DTLS application-data stream using
simple 4-byte big-endian length-prefixed framing:

* the client's first framed message is the target address, encoded as a
  SOCKS5 address (:func:`socks_server.build_socks5_address`);
* the server dials the target and answers with a 1-byte status frame
  (``0x01`` = dialed, ``0x00`` = dial failed) after which the framed
  stream is a raw bidirectional pipe to the target.

Implementation notes
--------------------
* DTLS is driven through pyOpenSSL's MemoryBIO pair exactly like
  ``scripts/dtls_probe.py`` proves out: ``set_accept_state()`` /
  ``set_connect_state()``, then a loop of ``do_handshake()`` (which raises
  ``WantReadError``/``WantWriteError`` while in progress and returns
  cleanly once complete), ``bio_read`` -> UDP send, UDP recv ->
  ``bio_write``.  Note that ``get_state_string()`` yields the *long-form*
  state string, so completion is detected by ``do_handshake()`` not
  raising — not by comparing against ``b"SSLOK"``.
* The engine opens one DTLS association (fresh UDP socket + handshake)
  per SOCKS CONNECT and tears it down with the CONNECT.  This is the
  simplest correct multiplexing story: each SOCKS stream maps 1:1 onto a
  DTLS session, no cross-stream interleaving locks are needed.
* ``supports_upstream`` is False: upstream chaining in this codebase is a
  TCP dialer (SOCKS5 CONNECT), while the Cover-DTLS transport is a raw
  UDP socket that must reach the DTLS server directly.  Tunnelling that
  socket through an upstream proxy would require UDP-relay semantics the
  upstream plumbing does not expose to engines.

PSK whitening ("cover") layer
-----------------------------
When a PSK is configured, every UDP datagram is XOR-ed with a keystream
before it hits the wire (standard-library blake2b only, no external deps):

    block_i   = blake2b(psk || salt || counter_be32(i),
                        key=psk, digest_size=32, person=b"pc-dtls")
    keystream = block_0 || block_1 || ...        (32-byte blocks)

* The client picks a random 8-byte salt per association and sends it as
  the prefix of its FIRST datagram (first datagram = ``salt || covered
  data``); every later datagram, in both directions, is fully covered.
* Both directions use the same keystream, and each datagram's keystream
  restarts at counter 0 — packet whitening is self-describing and
  therefore survives loss, reordering and DTLS retransmission.
* This is a lightweight cover, NOT per-packet AEAD: the DTLS layer
  provides authenticity and confidentiality.  Whitening only equalises
  the packet-byte shapes so the fixed DTLS record-header fingerprint
  (``0x17 0xfe 0xfd ...``) is not visible to passive classifiers.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import queue
import socket
import struct
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional, Set, Tuple

from ...log import get
from . import models as M
from .base import PROXY_FAMILY, ProtocolEngine, ProtocolError, free_port
from .socks_server import (LoopThread, SocksServer, build_socks5_address,
                           parse_socks5_address)

try:
    from OpenSSL import SSL, crypto  # noqa: F401  (crypto re-exported for tests)
except Exception:  # pragma: no cover - pyOpenSSL not installed
    SSL = None
    crypto = None

if SSL is not None:
    _SSLError = SSL.Error
else:  # pragma: no cover - placeholder so except-clauses stay valid
    class _SSLError(Exception):
        pass

#: Feature detection: DTLS needs ``SSL.DTLS_METHOD`` (pyOpenSSL >= 21) and
#: ciphertext-MTU control for sane packet shapes.  Both are probed at import
#: so the UI/registry can disable the engine without crashing.
DTLS_AVAILABLE = False
if SSL is not None:
    try:
        SSL.Context(SSL.DTLS_METHOD)
        DTLS_AVAILABLE = hasattr(SSL.Connection, "set_ciphertext_mtu")
    except Exception:
        DTLS_AVAILABLE = False

log = get("protocols.coverdtls")

__all__ = ["DTLS_AVAILABLE", "CoverDtlsServer", "CoverDtlsEngine",
           "engine", "whitening_keystream", "cover"]

_MTU = 1200            # ciphertext MTU for realistic packet shapes
_CHUNK = 1200          # plaintext bytes per DTLS record / per frame
_MAX_FRAME = 1 << 20   # sanity cap on one framed message


# ---------------------------------------------------------------------------
# PSK whitening (see module docstring)
# ---------------------------------------------------------------------------
def _psk_bytes(psk) -> bytes:
    """Normalise the PSK to bytes within blake2b's 64-byte key limit."""
    if not psk:
        return b""
    raw = bytes(psk) if isinstance(psk, (bytes, bytearray)) \
        else str(psk).encode("utf-8")
    if len(raw) > 64:
        raw = hashlib.blake2b(raw, digest_size=32, person=b"pc-dtls").digest()
    return raw


def whitening_keystream(psk, salt: bytes, n: int) -> bytes:
    """Keystream for the cover layer: ``n`` bytes, counter blocks starting 0.

    ``block_i = blake2b(psk || salt || be32(i), key=psk, digest_size=32,
    person=b"pc-dtls")``.  Deterministic per (psk, salt) pair; the salt must
    be 8 bytes on the wire.  Generated blocks are cached per (psk, salt)
    and only extended on demand — one datagram of a flow costs a slice,
    not 40+ blake2b calls."""
    key = _psk_bytes(psk)
    if n <= 0:
        return b""
    ck = (key, bytes(salt))
    ks = _KS_CACHE.get(ck)
    if ks is None:
        ks = bytearray()
        _KS_CACHE[ck] = ks
        while len(_KS_CACHE) > _KS_CACHE_MAX:      # FIFO eviction
            _KS_CACHE.pop(next(iter(_KS_CACHE)))
    if len(ks) < n:
        counter = len(ks) // 32
        while len(ks) < n:
            ks += hashlib.blake2b(
                key + bytes(salt) + struct.pack("!I", counter),
                key=key, digest_size=32, person=b"pc-dtls").digest()
            counter += 1
    return bytes(ks[:n])


#: per-(psk, salt) keystream cache — a flow reuses its salt for every
#: datagram; a handful of concurrent flows × a few KB each is the whole
#: footprint, bounded by _KS_CACHE_MAX entries
_KS_CACHE: "OrderedDict[Tuple[bytes, bytes], bytearray]" = OrderedDict()
_KS_CACHE_MAX = 16


def cover(psk, salt: bytes, data: bytes) -> bytes:
    """XOR ``data`` with the PSK keystream (self-inverse; also the decoder)."""
    key = _psk_bytes(psk)
    data = bytes(data)
    if not key or not data:
        return data
    ks = whitening_keystream(key, salt, len(data))
    x = int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")
    return x.to_bytes(len(data), "big")


# ---------------------------------------------------------------------------
# shared DTLS / framing helpers
# ---------------------------------------------------------------------------
def _pop_frame_locked(buf: bytearray) -> Optional[bytes]:
    """Pop one 4-byte-BE-length-prefixed frame from ``buf`` if complete."""
    if len(buf) < 4:
        return None
    ln = struct.unpack("!I", bytes(buf[:4]))[0]
    if ln > _MAX_FRAME:
        raise ProtocolError("cover-dtls frame too large (%d bytes)" % ln)
    if len(buf) < 4 + ln:
        return None
    payload = bytes(buf[4:4 + ln])
    del buf[:4 + ln]
    return payload


def _ssl_send(conn, frame: bytes, flush: Callable[[], None]) -> None:
    """Queue one application-data payload on ``conn`` and flush ciphertext.

    Caller must hold the connection lock.  MemoryBIO SSL_write never really
    wants read/write, but the retry loop keeps it bullet-proof.
    """
    for _ in range(4):
        try:
            conn.send(frame)
            break
        except (SSL.WantReadError, SSL.WantWriteError):  # pragma: no cover
            flush()
    else:  # pragma: no cover
        raise ProtocolError("cover-dtls: SSL_write did not accept data")
    flush()


def _drain_plain(conn, plain: bytearray, cond: threading.Condition) -> bool:
    """Move decrypted bytes out of ``conn`` into ``plain``.

    Returns False on EOF/broken-record (caller should close).  ``cond`` is
    notified whenever bytes land.
    """
    while True:
        try:
            chunk = conn.recv(65535)
        except (SSL.WantReadError, SSL.WantWriteError):
            return True
        except (SSL.ZeroReturnError, _SSLError):
            return False
        if not chunk:
            return False
        with cond:
            plain += chunk
            cond.notify_all()


def _handle_retransmit(conn, flush: Callable[[], None]) -> None:
    """Opportunistically fire the DTLS retransmission timer, if exposed."""
    handle = getattr(conn, "DTLSv1_handle_timeout", None)
    if handle is None:
        return
    try:
        if handle():
            flush()
    except Exception:  # pragma: no cover - timer may be disarmed
        pass


class _StopPeer(Exception):
    """Internal: end a server-side peer session quietly."""


# ---------------------------------------------------------------------------
# client-side association
# ---------------------------------------------------------------------------
class _ClientLink:
    """One client DTLS association: dedicated UDP socket + SSL.Connection.

    Handshake runs on the calling (executor) thread; afterwards a reader
    thread moves UDP datagrams -> BIO -> plaintext buffer, and ``read`` /
    ``read_frame`` / ``write`` provide a synchronous stream API that the
    asyncio dialer bridges via ``run_in_executor``.
    """

    def __init__(self, server_addr: Tuple[str, int], psk: bytes = b"",
                 sni: str = "", insecure: bool = True) -> None:
        if SSL is None:  # pragma: no cover - guarded by DTLS_AVAILABLE
            raise ProtocolError("pyOpenSSL is not available")
        self._psk = psk
        self._salt = os.urandom(8) if psk else b""
        self._salt_sent = False
        self._raw_writes = False   # framed target header first, then raw
        self._alive = True
        self._closing = False
        self._ssl_lk = threading.Lock()
        self._cond = threading.Condition(threading.Lock())
        self._plain = bytearray()
        self._pumps: Set[object] = set()   # strong refs to bridge pump tasks

        ctx = SSL.Context(SSL.DTLS_METHOD)
        if insecure:
            ctx.set_verify(SSL.VERIFY_NONE, lambda *a, **kw: True)
        self._ctx = ctx
        conn = SSL.Connection(ctx)
        if hasattr(conn, "set_ciphertext_mtu"):
            conn.set_ciphertext_mtu(_MTU)
        conn.set_connect_state()
        if sni:
            try:
                conn.set_tlsext_host_name(sni.encode("idna"))
            except (SSL.Error, UnicodeError):  # pragma: no cover
                log.warning("cover-dtls: could not set SNI %r", sni)
        self._conn = conn
        self._sock = self._make_socket(server_addr)

    @staticmethod
    def _make_socket(server_addr: Tuple[str, int]) -> socket.socket:
        host, port = server_addr
        try:
            infos = socket.getaddrinfo(host, int(port), 0, socket.SOCK_DGRAM)
        except (OSError, ValueError) as e:
            raise ProtocolError("cover-dtls: cannot resolve %r: %s" % (host, e))
        if not infos:
            raise ProtocolError("cover-dtls: no address for %r" % (host,))
        fam, _typ, _proto, _cn, target = infos[0]
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            sock.connect(target)
        except OSError:
            sock.close()
            raise
        return sock

    # -- handshake ----------------------------------------------------------
    def handshake(self, timeout: float = 10.0) -> None:
        """Drive the DTLS handshake to completion (dtls_probe.py pattern)."""
        deadline = time.time() + timeout
        while True:
            with self._ssl_lk:
                if not self._alive:
                    raise ProtocolError("cover-dtls association closed")
                try:
                    # Raises WantRead/WantWrite while in progress; returns
                    # cleanly (no exception) once the handshake is done.
                    self._conn.do_handshake()
                    self._flush_locked()
                    return
                except (SSL.WantReadError, SSL.WantWriteError):
                    self._flush_locked()
                except _SSLError as e:
                    raise ProtocolError("cover-dtls handshake failed: %s" % (e,))
            remaining = deadline - time.time()
            if remaining <= 0:
                raise ProtocolError(
                    "cover-dtls handshake timed out after %.0fs" % timeout)
            self._sock.settimeout(min(0.25, max(0.01, remaining)))
            try:
                data = self._sock.recv(65535)
            except socket.timeout:
                with self._ssl_lk:
                    _handle_retransmit(self._conn, self._flush_locked)
                continue
            except OSError as e:
                raise ProtocolError("cover-dtls socket error: %s" % e)
            with self._ssl_lk:
                if not self._alive:
                    raise ProtocolError("cover-dtls association closed")
                try:
                    if self._psk:
                        # inbound datagrams are PSK-covered (see module
                        # docstring) — uncover before the DTLS layer sees them
                        data = cover(self._psk, self._salt, data)
                    self._conn.bio_write(data)
                    self._flush_locked()
                except _SSLError as e:
                    raise ProtocolError("cover-dtls handshake failed: %s" % (e,))

    def start_reader(self) -> None:
        t = threading.Thread(target=self._reader_loop,
                             name="coverdtls-reader", daemon=True)
        t.start()

    def _reader_loop(self) -> None:
        try:
            while self._alive:
                try:
                    self._sock.settimeout(0.2)
                    data = self._sock.recv(65535)
                except socket.timeout:
                    with self._ssl_lk:
                        _handle_retransmit(self._conn, self._flush_locked)
                    continue
                except OSError:
                    break
                if not data:
                    break
                if self._psk:
                    data = cover(self._psk, self._salt, data)
                with self._ssl_lk:
                    if not self._alive:
                        break
                    try:
                        self._conn.bio_write(data)
                        self._flush_locked()
                        if not _drain_plain(self._conn, self._plain, self._cond):
                            break
                    except _SSLError as e:
                        log.debug("cover-dtls: record error: %s", e)
                        break
        except Exception:  # pragma: no cover
            log.debug("cover-dtls: reader loop ended", exc_info=True)
        finally:
            self._alive = False
            with self._cond:
                self._cond.notify_all()

    # -- cipher I/O (connection-lock discipline) ----------------------------
    def _flush_locked(self) -> None:
        """Push pending ciphertext from the write BIO to the UDP socket."""
        while True:
            try:
                out = self._conn.bio_read(65535)
            except SSL.WantReadError:
                return
            self._send_raw(out)

    def _send_raw(self, datagram: bytes) -> None:
        """Whiten (PSK) and put one datagram on the wire."""
        if self._psk:
            if not self._salt_sent:
                # First datagram on the wire = 8-byte salt || covered data.
                self._salt_sent = True
                datagram = self._salt + cover(self._psk, self._salt, datagram)
            else:
                datagram = cover(self._psk, self._salt, datagram)
        self._sock.send(datagram)

    # -- public stream API --------------------------------------------------
    def enter_raw(self) -> None:
        """Switch writes from framed mode to the raw post-header stream."""
        self._raw_writes = True

    def write(self, data: bytes) -> None:
        if not self._alive:
            raise OSError("cover-dtls association is closed")
        for i in range(0, len(data), _CHUNK):
            chunk = bytes(data[i:i + _CHUNK])
            with self._ssl_lk:
                if not self._alive:
                    raise OSError("cover-dtls association is closed")
                if self._raw_writes:
                    _ssl_send(self._conn, chunk, self._flush_locked)
                else:
                    frame = struct.pack("!I", len(chunk)) + chunk
                    _ssl_send(self._conn, frame, self._flush_locked)

    def read(self, size: int = 65536,
             timeout: Optional[float] = None) -> bytes:
        """Blocking read: up to ``size`` plaintext bytes, b'' at EOF."""
        deadline = None if timeout is None else time.time() + timeout
        with self._cond:
            while True:
                if self._plain:
                    out = bytes(self._plain[:size])
                    del self._plain[:size]
                    return out
                if not self._alive:
                    return b""
                if deadline is not None:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        return b""
                    self._cond.wait(min(0.25, remaining))
                else:
                    self._cond.wait(0.25)

    def read_frame(self, timeout: float = 10.0) -> Optional[bytes]:
        """Blocking framed read; None on timeout / closed."""
        deadline = time.time() + timeout
        with self._cond:
            while True:
                frame = _pop_frame_locked(self._plain)
                if frame is not None:
                    return frame
                if not self._alive:
                    return None
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._cond.wait(min(0.25, remaining))

    # -- asyncio bridge -----------------------------------------------------
    def bridge(self, loop: asyncio.AbstractEventLoop,
               on_close: Optional[Callable[[], None]] = None
               ) -> Tuple[asyncio.StreamReader, "_BridgeWriter"]:
        """Return (asyncio StreamReader, StreamWriter-shaped adapter).

        The read side is a real :class:`asyncio.StreamReader` fed by a pump
        task that pulls from the sync stream via ``run_in_executor``; the
        write side adapts ``write``/``drain``/``close`` straight onto the
        sync stream (a real StreamWriter would need a transport).
        """
        reader = asyncio.StreamReader()

        async def _pump() -> None:
            try:
                while True:
                    data = await loop.run_in_executor(None, self.read, 65536)
                    if not data:
                        break
                    reader.feed_data(data)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.debug("cover-dtls: bridge pump ended", exc_info=True)
            finally:
                try:
                    reader.feed_eof()
                except Exception:  # pragma: no cover
                    pass

        pump = loop.create_task(_pump())
        self._pumps.add(pump)
        pump.add_done_callback(self._pumps.discard)
        return reader, _BridgeWriter(self, pump, on_close)

    # -- teardown -----------------------------------------------------------
    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        with self._ssl_lk:
            try:
                self._conn.shutdown()      # best-effort close_notify
                self._flush_locked()
            except Exception:
                pass
        self._alive = False
        try:
            self._sock.close()
        except OSError:
            pass
        with self._cond:
            self._cond.notify_all()


class _BridgeWriter:
    """StreamWriter-shaped adapter over a sync :class:`_ClientLink`.

    Implements exactly the surface :mod:`socks_server` uses (``write``,
    ``drain``, ``close``, ``wait_closed``) plus a couple of common extras.
    """

    def __init__(self, link: _ClientLink, pump: object,
                 on_close: Optional[Callable[[], None]]) -> None:
        self._link = link
        self._pump = pump
        self._on_close = on_close
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed:
            raise OSError("cover-dtls stream is closed")
        self._link.write(data)

    def writelines(self, lines) -> None:  # pragma: no cover
        for line in lines:
            self.write(line)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._link.close()
        except Exception:  # pragma: no cover
            pass
        cb, self._on_close = self._on_close, None
        if cb:
            try:
                cb()
            except Exception:  # pragma: no cover
                pass

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name, default=None):
        return default


# ---------------------------------------------------------------------------
# reference / self-hosting server
# ---------------------------------------------------------------------------
class _ServerPeer:
    """One server-side DTLS association (thread-per-peer + 2 pump threads)."""

    HEADER_TIMEOUT = 30.0   # wait for the target-address header
    IDLE_TIMEOUT = 300.0    # framed-read idle cap inside a session

    def __init__(self, server: "CoverDtlsServer", addr, salt: bytes) -> None:
        self.server = server
        self.addr = addr
        self.salt = salt
        self._psk = server.psk
        self._q: "queue.Queue[bytes]" = queue.Queue()
        self._ssl_lk = threading.Lock()
        self._cond = threading.Condition(threading.Lock())
        self._plain = bytearray()
        self._alive = True
        self._tcp: Optional[socket.socket] = None
        conn = SSL.Connection(server.ctx)
        if hasattr(conn, "set_ciphertext_mtu"):
            conn.set_ciphertext_mtu(_MTU)
        conn.set_accept_state()
        self._conn = conn
        self._thread = threading.Thread(target=self._run,
                                        name="coverdtls-peer", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def push(self, datagram: bytes) -> None:
        """Hand a (already un-whitened) ciphertext datagram to the peer."""
        if self._alive:
            self._q.put(datagram)

    def close(self) -> None:
        self._alive = False
        tcp = self._tcp
        if tcp is not None:
            try:
                tcp.close()
            except OSError:
                pass
        self.server._drop_peer(self.addr)
        with self._cond:
            self._cond.notify_all()

    # -- worker -------------------------------------------------------------
    def _run(self) -> None:
        tcp: Optional[socket.socket] = None
        try:
            self._handshake()
            tcp = self._dial_target()
            t1 = threading.Thread(target=self._pump_dtls_to_tcp, args=(tcp,),
                                  name="coverdtls-d2t", daemon=True)
            t2 = threading.Thread(target=self._pump_tcp_to_dtls, args=(tcp,),
                                  name="coverdtls-t2d", daemon=True)
            t1.start()
            t2.start()
            while self._alive:
                self._pump_step(0.25)
        except _StopPeer as e:
            log.debug("cover-dtls peer %s ended: %s", self.addr, e)
        except Exception as e:  # pragma: no cover
            log.debug("cover-dtls peer %s died: %s", self.addr, e)
        finally:
            self._alive = False
            if tcp is not None:
                try:
                    tcp.close()
                except OSError:
                    pass
            self.close()

    def _handshake(self, timeout: float = 15.0) -> None:
        deadline = time.time() + timeout
        while self._alive:
            if time.time() >= deadline:
                raise _StopPeer("server handshake timed out")
            try:
                dg = self._q.get(timeout=0.25)
            except queue.Empty:
                with self._ssl_lk:
                    _handle_retransmit(self._conn, self._flush_locked)
                continue
            with self._ssl_lk:
                try:
                    self._conn.bio_write(dg)
                    # Completes (returns) once the client's Finished lands.
                    self._conn.do_handshake()
                    self._flush_locked()
                    return
                except (SSL.WantReadError, SSL.WantWriteError):
                    self._flush_locked()
                except _SSLError as e:
                    raise _StopPeer("handshake failed: %s" % (e,))
        raise _StopPeer("closed during handshake")

    def _dial_target(self) -> socket.socket:
        header = self._read_frame(self.HEADER_TIMEOUT)
        if header is None:
            raise _StopPeer("no target header received")
        try:
            host, port, _used = parse_socks5_address(b"\x00" + header, 1)
        except (ProtocolError, IndexError) as e:
            raise _StopPeer("bad target header: %s" % e)
        try:
            tcp = socket.create_connection((host, port), 10.0)
        except OSError as e:
            log.info("cover-dtls: dial %s:%d failed: %s", host, port, e)
            try:
                self._send_frame(b"\x00")   # status: dial failed
            except Exception:  # pragma: no cover
                pass
            raise _StopPeer("dial %s:%d failed: %s" % (host, port, e))
        try:
            tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:  # pragma: no cover
            pass
        self._tcp = tcp
        self._send_frame(b"\x01")           # status: dialed (framed)
        # Payload beyond the header is a raw stream: push anything that was
        # buffered behind the header frame, then read/write raw from here on.
        with self._cond:
            leftover = bytes(self._plain)
            self._plain.clear()
        if leftover:
            tcp.sendall(leftover)
        return tcp

    # -- cipher I/O ---------------------------------------------------------
    def _flush_locked(self) -> None:
        while True:
            try:
                out = self._conn.bio_read(65535)
            except SSL.WantReadError:
                return
            self._send_raw(out)

    def _send_raw(self, datagram: bytes) -> None:
        if self._psk:
            # Server already knows the salt; same keystream, counter from 0.
            datagram = cover(self._psk, self.salt, datagram)
        if not self.server._running:  # pragma: no cover - shutdown race
            return
        self.server._sock.sendto(datagram, self.addr)

    def _send_frame(self, payload: bytes) -> None:
        for i in range(0, len(payload), _CHUNK):
            chunk = payload[i:i + _CHUNK]
            frame = struct.pack("!I", len(chunk)) + chunk
            with self._ssl_lk:
                if not self._alive:
                    raise OSError("peer closed")
                _ssl_send(self._conn, frame, self._flush_locked)

    def _pump_step(self, timeout: float = 0.05) -> None:
        """Move one queued datagram through the BIO into the plain buffer."""
        try:
            dg = self._q.get(timeout=timeout)
        except queue.Empty:
            return
        with self._ssl_lk:
            if not self._alive:
                return
            try:
                self._conn.bio_write(dg)
                self._flush_locked()
                if not _drain_plain(self._conn, self._plain, self._cond):
                    self.close()
            except _SSLError as e:
                log.debug("cover-dtls: bad record from %s: %s", self.addr, e)
                self.close()

    def _read_frame(self, timeout: float) -> Optional[bytes]:
        deadline = time.time() + timeout
        while self._alive:
            self._pump_step(0.02)
            with self._cond:
                frame = _pop_frame_locked(self._plain)
                if frame is not None:
                    return frame
                if time.time() >= deadline:
                    return None
        return None

    def _read_raw(self, timeout: float) -> Optional[bytes]:
        """Raw (post-header) read: up to 64 KiB of payload plaintext."""
        deadline = time.time() + timeout
        while self._alive:
            self._pump_step(0.02)
            with self._cond:
                if self._plain:
                    out = bytes(self._plain[:65536])
                    del self._plain[:65536]
                    return out
                if time.time() >= deadline:
                    return None
        return None

    # -- pumps --------------------------------------------------------------
    def _pump_dtls_to_tcp(self, tcp: socket.socket) -> None:
        try:
            while self._alive:
                chunk = self._read_raw(self.IDLE_TIMEOUT)
                if chunk is None:
                    break
                tcp.sendall(chunk)
        except OSError:
            pass
        finally:
            self.close()

    def _pump_tcp_to_dtls(self, tcp: socket.socket) -> None:
        try:
            while self._alive:
                data = tcp.recv(65535)
                if not data:
                    break
                for i in range(0, len(data), _CHUNK):
                    piece = data[i:i + _CHUNK]
                    with self._ssl_lk:
                        if not self._alive:
                            raise OSError("peer closed")
                        _ssl_send(self._conn, piece, self._flush_locked)
        except (OSError, ProtocolError):
            pass
        finally:
            self.close()


class CoverDtlsServer:
    """Reference Cover-DTLS server (also used for self-hosting).

    Binds one UDP socket on ``(host, port)`` and demultiplexes datagrams to
    a thread-per-peer association; each peer speaks the framed protocol:
    first message = SOCKS5-format target address, then a raw bidirectional
    stream to the dialed target.
    """

    def __init__(self, host: str, port: int, cert, key, psk: str = "") -> None:
        if not DTLS_AVAILABLE:
            raise ProtocolError(
                "Cover-DTLS requires pyOpenSSL with DTLS support "
                "(pip install 'pyOpenSSL>=23'); SSL.DTLS_METHOD is unavailable")
        self._host = host
        self._port = int(port or 0)
        self._cert = cert
        self._key = key
        self.psk = _psk_bytes(psk)
        self.ctx = None                      # SSL.Context, set in start()
        self._sock: Optional[socket.socket] = None
        self._addr: Tuple[str, int] = ("", 0)
        self._peers: dict = {}
        self._peers_lk = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def address(self) -> Tuple[str, int]:
        """(host, port) the UDP socket bound after :meth:`start`."""
        return self._addr

    def start(self) -> None:
        ctx = SSL.Context(SSL.DTLS_METHOD)
        ctx.use_certificate(self._cert)
        ctx.use_privatekey(self._key)
        self.ctx = ctx
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self._host, self._port))
        self._addr = sock.getsockname()[:2]
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop,
                                        name="coverdtls-accept", daemon=True)
        self._thread.start()
        log.info("cover-dtls server on udp://%s:%d%s", self._addr[0],
                 self._addr[1], " (psk whitening)" if self.psk else "")

    def stop(self) -> None:
        self._running = False
        with self._peers_lk:
            peers = list(self._peers.values())
        for p in peers:
            p.close()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # -- internals ----------------------------------------------------------
    def _drop_peer(self, addr) -> None:
        with self._peers_lk:
            self._peers.pop(addr, None)

    def _accept_loop(self) -> None:
        sock = self._sock
        if sock is None:  # pragma: no cover
            return
        sock.settimeout(0.25)
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._route(data, addr)
            except Exception:  # pragma: no cover
                log.debug("cover-dtls: route error", exc_info=True)

    def _route(self, data: bytes, addr) -> None:
        with self._peers_lk:
            peer = self._peers.get(addr)
        if peer is not None:
            if self.psk:
                data = cover(self.psk, peer.salt, data)
            peer.push(data)
            return
        salt = b""
        if self.psk:
            if len(data) <= 8:
                return          # too short to carry salt + a DTLS record
            salt, data = data[:8], data[8:]
            data = cover(self.psk, salt, data)
        peer = _ServerPeer(self, addr, salt)
        with self._peers_lk:
            self._peers[addr] = peer
        peer.push(data)
        peer.start()


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class CoverDtlsEngine(ProtocolEngine):
    """Local SOCKS5 front-end backed by a Cover-DTLS covert transport.

    One DTLS association (fresh UDP socket + full handshake) is opened per
    SOCKS CONNECT and torn down with the stream — simple and correct; a
    single session would need per-stream interleaving locks for no real
    cover benefit.  ``supports_upstream`` is False (see module docstring):
    the DTLS socket dials the server directly and the TCP-only upstream
    dialer plumbing cannot carry it.
    """

    proxy_kind = "coverdtls"
    family = PROXY_FAMILY
    exposes = "socks"
    supports_upstream = False
    binary_name = ""

    def __init__(self, socks_port: int = 0, http_port: int = 0) -> None:
        super().__init__(socks_port, http_port)
        self._loop_thread: Optional[LoopThread] = None
        self._socks: Optional[SocksServer] = None
        self._profile: Optional[M.CoverDtlsProfile] = None
        self._server_addr: Tuple[str, int] = ("", 0)
        self._psk = b""
        self._sni = ""
        self._insecure = True
        self._timeout = 15.0
        self._links: Set[_ClientLink] = set()
        self._links_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------
    def start(self, profile: M.CoverDtlsProfile, timeout: float = 15.0) -> None:
        if self._loop_thread is not None:
            raise ProtocolError("cover-dtls engine is already started")
        if not isinstance(profile, M.CoverDtlsProfile):
            raise ProtocolError("coverdtls engine requires a CoverDtlsProfile")
        if not DTLS_AVAILABLE:
            raise ProtocolError(
                "Cover-DTLS requires pyOpenSSL with DTLS support "
                "(pip install 'pyOpenSSL>=23'); SSL.DTLS_METHOD is unavailable")
        if not profile.server:
            raise ProtocolError("Cover-DTLS profile is missing 'server'")
        self._profile = profile
        self._timeout = float(timeout)
        self._server_addr = (profile.server, int(profile.port))
        self._psk = _psk_bytes(profile.psk)
        self._sni = profile.sni
        self._insecure = bool(profile.insecure)
        self.socks_port = free_port(self.socks_port
                                    or (10850 + os.getpid() % 384))
        self._loop_thread = LoopThread("proto-clean-coverdtls")
        self._socks = SocksServer("127.0.0.1", self.socks_port, self._dialer)
        fut = asyncio.run_coroutine_threadsafe(self._socks.serve(),
                                               self._loop_thread.loop)
        try:
            fut.result(10.0)
        except Exception as e:
            self.stop()
            raise ProtocolError(
                "cover-dtls: cannot start local SOCKS5 front-end on port %d: %s"
                % (self.socks_port, e))
        self._started_at = time.time()
        log.info("cover-dtls engine up: socks=127.0.0.1:%d -> %s:%d%s",
                 self.socks_port, profile.server, profile.port,
                 " (psk)" if self._psk else "")

    def stop(self, timeout: float = 5.0) -> None:
        with self._links_lock:
            links = list(self._links)
            self._links.clear()
        for link in links:
            try:
                link.close()
            except Exception:  # pragma: no cover
                pass
        loop_thread, self._loop_thread = self._loop_thread, None
        socks, self._socks = self._socks, None
        if loop_thread is not None:
            if socks is not None:
                try:
                    fut = asyncio.run_coroutine_threadsafe(socks.shutdown(),
                                                           loop_thread.loop)
                    fut.result(min(3.0, timeout))
                except Exception:  # pragma: no cover
                    pass
            loop_thread.stop()
        super().stop(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._loop_thread is not None

    def status(self) -> dict:
        d = super().status()
        d["running"] = self.running
        if self._server_addr[0]:
            d["server"] = "%s:%d" % self._server_addr
        return d

    # -- dialer -------------------------------------------------------------
    async def _dialer(self, host: str, port: int):
        """SOCKS5 dialer: fresh DTLS association per CONNECT, then a pipe."""
        loop = asyncio.get_running_loop()
        try:
            link = await loop.run_in_executor(None, self._open_association)
        except ProtocolError:
            raise
        except (OSError, _SSLError) as e:
            raise ProtocolError("cover-dtls connect to %s failed: %s"
                                % (self._server_addr[0], e))
        try:
            await loop.run_in_executor(None, link.write,
                                       build_socks5_address(host, port))
            status = await loop.run_in_executor(None, link.read_frame, 15.0)
            if status != b"\x01":
                raise ProtocolError(
                    "cover-dtls server cannot dial %s:%d" % (host, port))
            # Framed header/status exchange done; the rest is a raw stream.
            await loop.run_in_executor(None, link.enter_raw)
        except BaseException:
            self._forget(link)
            raise
        return link.bridge(loop, on_close=lambda: self._forget(link))

    def _open_association(self) -> _ClientLink:
        link = _ClientLink(self._server_addr, psk=self._psk, sni=self._sni,
                           insecure=self._insecure)
        try:
            link.handshake(min(self._timeout, 10.0))
            link.start_reader()
        except BaseException:
            link.close()
            raise
        with self._links_lock:
            self._links.add(link)
        return link

    def _forget(self, link: _ClientLink) -> None:
        with self._links_lock:
            self._links.discard(link)


def engine(profile: M.CoverDtlsProfile, socks_port: int = 0) -> CoverDtlsEngine:
    """Registry factory for the ``coverdtls`` protocol kind."""
    return CoverDtlsEngine(socks_port=socks_port)
