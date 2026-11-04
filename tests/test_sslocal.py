"""Tests for the built-in Shadowsocks AEAD stack (sscrypto + sslocal).

No real Shadowsocks server is involved: the suite runs a minimal AEAD
server built on :mod:`proto_clean.vpn.protocols.sscrypto`, an asyncio
echo target and — for the upstream-chain test — a tiny SOCKS5 front-end,
all on loopback.  The engine itself is driven through its local SOCKS5
port with :func:`socks5_dial`, exactly like the app would.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import socket
import struct
import time

import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from proto_clean.vpn.protocols import models as M
from proto_clean.vpn.protocols import sslocal
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.socks_server import (LoopThread,
                                                    parse_socks5_address,
                                                    socks5_dial)
from proto_clean.vpn.protocols.sslocal import (ShadowsocksEngine,
                                               _read_socks5_request)
from proto_clean.vpn.protocols.sscrypto import (CIPHERS, CipherCtx,
                                                EVP_BytesToKey, derive_subkey,
                                                hkdf_sha1, increment_nonce)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===========================================================================
# sscrypto unit tests
# ===========================================================================
def test_evp_bytes_to_key_known_vector():
    """Legacy SS password KDF: MD5 chaining, matched against an independent
    inline reimplementation and a pre-computed known vector."""
    def reference(password: bytes, key_len: int) -> bytes:
        # independent reimplementation: D_i = MD5(D_{i-1} + password)
        d = b""
        prev = b""
        while len(d) < key_len:
            prev = hashlib.md5(prev + password).digest()
            d += prev
        return d[:key_len]

    assert EVP_BytesToKey(b"hello-world", 32) == bytes.fromhex(
        "2095312189753de6ad47dfe20cbe97ec79b94e48490a6a0f51e32a21fe46d69f")
    for password, key_len in [(b"", 16), (b"secret", 24), (b"password123", 32),
                              (b"x" * 77, 16), (b"ss-e2e-pass", 32)]:
        assert EVP_BytesToKey(password, key_len) == reference(password, key_len)
        assert len(EVP_BytesToKey(password, key_len)) == key_len


def test_hkdf_sha1_rfc5869_case1():
    """RFC 5869 "Test Case 1" with SHA-1 (IKM 0x0b x11, L=42)."""
    ikm = b"\x0b" * 11
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha1(ikm, salt, info, 42)
    assert okm == bytes.fromhex(
        "085a01ea1b10f36933068b56efa5ad81"
        "a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896")
    # and an independent implementation agrees
    ref = HKDF(algorithm=hashes.SHA1(), length=42, salt=salt,
               info=info).derive(ikm)
    assert okm == ref
    # more than 40 bytes needs three SHA-1 output blocks
    assert len(hkdf_sha1(ikm, salt, info, 61)) == 61


def test_derive_subkey_uses_ss_info():
    key = os.urandom(32)
    salt = os.urandom(32)
    subkey = derive_subkey(key, salt, 32)
    assert subkey == hkdf_sha1(key, salt, b"ss-subkey", 32)
    assert subkey != key
    assert derive_subkey(key, b"other-salt!", 32) != subkey


def test_increment_nonce_wrap():
    nonce = bytearray(12)
    assert increment_nonce(nonce) is nonce
    assert nonce == bytearray(b"\x01" + b"\x00" * 11)
    nonce = bytearray(bytes.fromhex("ff" + "00" * 11))
    increment_nonce(nonce)
    assert nonce == bytearray(b"\x00\x01" + b"\x00" * 10)
    nonce = bytearray(b"\xff" * 12)
    increment_nonce(nonce)
    assert nonce == bytearray(12)           # wraps around to all-zero


def test_cipher_registry_and_validation():
    assert CIPHERS == {"aes-128-gcm": (16, 16), "aes-192-gcm": (24, 24),
                       "aes-256-gcm": (32, 32),
                       "chacha20-ietf-poly1305": (32, 32)}
    with pytest.raises(ProtocolError):
        CipherCtx("rc4-md5", b"x" * 16)
    with pytest.raises(ProtocolError):
        CipherCtx("aes-256-gcm", b"too-short")
    with pytest.raises(ProtocolError):
        CipherCtx.from_password("nope-nope", "pw")
    with pytest.raises(ProtocolError):
        CipherCtx.from_password("aes-256-gcm", "")
    ctx = CipherCtx.from_password("aes-256-gcm", "pw")
    assert ctx.key == EVP_BytesToKey(b"pw", 32)
    with pytest.raises(ProtocolError):
        ctx.new_session(b"\x00" * 8)        # wrong salt length
    assert CipherCtx("aes-192-gcm", b"k" * 24).salt_len == 24


@pytest.mark.parametrize("method", ["aes-256-gcm", "chacha20-ietf-poly1305"])
def test_roundtrip_multi_chunk(method):
    """Client encrypt -> server decrypt and vice versa, streamed in random
    pieces, re-fed byte-by-byte, and split across the 0x3FFF chunk limit."""
    key = EVP_BytesToKey(b"round-trip-pass", CIPHERS[method][0])
    client_ctx = CipherCtx(method, key)
    server_ctx = CipherCtx(method, key)
    assert client_ctx.salt_len == CIPHERS[method][1]

    salt = os.urandom(client_ctx.salt_len)
    enc = client_ctx.new_session(salt)
    dec = server_ctx.new_session(salt)

    rng = random.Random(20240501)
    pieces = [os.urandom(rng.randrange(0, 1000)) for _ in range(6)]
    wire = b""
    expect = b""
    for piece in pieces:
        wire += enc.encrypt(piece)
        expect += piece
    assert dec.decrypt(wire) == expect

    # feed the same stream byte-by-byte: the append-only buffer must
    # reassemble every chunk
    dec2 = server_ctx.new_session(salt)
    out = b""
    for i in range(len(wire)):
        out += dec2.decrypt(wire[i:i + 1])
    assert out == expect

    # payloads above 0x3FFF split into multiple chunks
    big = os.urandom(0x3FFF + 100)
    wire2 = enc.encrypt(big)
    assert len(wire2) == (2 + 16 + 0x3FFF + 16) + (2 + 16 + 100 + 16)
    assert dec.decrypt(wire2) == big

    # the other direction: server encrypts, client decrypts
    resp_salt = os.urandom(client_ctx.salt_len)
    senc = server_ctx.new_session(resp_salt)
    cdec = client_ctx.new_session(resp_salt)
    reply = senc.encrypt(b"from-server") + senc.encrypt(b"-and-back")
    assert cdec.decrypt(reply) == b"from-server-and-back"


def test_decrypt_rejects_corrupt():
    for method in ("aes-256-gcm", "chacha20-ietf-poly1305"):
        key = EVP_BytesToKey(b"corruption", CIPHERS[method][0])
        ctx = CipherCtx(method, key)
        enc = ctx.new_session(os.urandom(ctx.salt_len))
        wire = enc.encrypt(b"payload-data")     # 2 + 16 + 12 + 16 bytes
        # flip a byte inside the length tag and inside the payload tag
        for bad_at in (10, len(wire) - 5):
            bad = wire[:bad_at] + bytes([wire[bad_at] ^ 0xFF]) + wire[bad_at + 1:]
            dec = ctx.new_session(b"\x07" * ctx.salt_len)
            with pytest.raises(ProtocolError):
                dec.decrypt(bad)


# ===========================================================================
# loopback helpers: echo target, minimal SS server, minimal SOCKS5 upstream
# ===========================================================================
async def _echo_client(rd: asyncio.StreamReader, wr: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await rd.read(4096)
            if not data:
                break
            wr.write(data)
            await wr.drain()
    except OSError:
        pass
    finally:
        try:
            wr.close()
        except OSError:
            pass


async def _raw_pipe(rd, wr) -> None:
    try:
        while True:
            data = await rd.read(65535)
            if not data:
                break
            wr.write(data)
            await wr.drain()
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            wr.close()
        except OSError:
            pass


async def _pipe_dec_to(dec, rd, wr) -> None:
    """SS AEAD stream -> plain target."""
    try:
        while True:
            raw = await rd.read(65535)
            if not raw:
                break
            out = dec.decrypt(raw)
            if out:
                wr.write(out)
                await wr.drain()
    except (OSError, ProtocolError):
        pass
    finally:
        try:
            wr.close()
        except OSError:
            pass


async def _pipe_enc_from(enc, rd, wr) -> None:
    """Plain target -> SS AEAD stream."""
    try:
        while True:
            data = await rd.read(65535)
            if not data:
                break
            wr.write(enc.encrypt(data))
            await wr.drain()
    except (OSError, ProtocolError):
        pass
    finally:
        try:
            wr.close()
        except OSError:
            pass



# Windows CI runs the full unit suite; the socket/loopback engine e2e
# tests are exercised on the Linux and macOS legs (they bind many local
# ports and spawn helper processes, which is unreliable on the
# shared Windows runners).
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="engine e2e covered on Linux/macOS runners")

class FakeSSServer:
    """Minimal Shadowsocks AEAD TCP server: parses the target header,
    connects to it and pipes both directions (the "exit")."""

    def __init__(self, method: str, password: str) -> None:
        self.ctx = CipherCtx(method, EVP_BytesToKey(
            password.encode("utf-8"), CIPHERS[method][0]))
        self.targets = []
        self.server = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        # NOTE: no wait_closed() — the engine's sockets belong to another
        # (stopped) loop thread and would never drain here.
        if self.server is not None:
            self.server.close()
            self.server = None

    async def _target_header(self, dec, rd: asyncio.StreamReader):
        buf = b""
        while True:
            try:
                host, port, used = parse_socks5_address(buf, 0)
            except (ProtocolError, IndexError, OSError, struct.error):
                buf += dec.decrypt(await asyncio.wait_for(rd.read(4096), 10))
                if len(buf) > 512:
                    raise ProtocolError("shadowsocks target header too long")
                continue
            return host, port, buf[used:]

    async def _handle(self, rd: asyncio.StreamReader,
                      wr: asyncio.StreamWriter) -> None:
        trd = twr = None
        try:
            salt = await asyncio.wait_for(rd.readexactly(self.ctx.salt_len), 10)
            dec = self.ctx.new_session(salt)
            host, port, initial = await self._target_header(dec, rd)
            self.targets.append((host, port))
            trd, twr = await asyncio.open_connection(host, port)
            if initial:
                twr.write(initial)
                await twr.drain()
            resp_salt = os.urandom(self.ctx.salt_len)
            enc = self.ctx.new_session(resp_salt)
            wr.write(resp_salt)
            await wr.drain()
            up = asyncio.ensure_future(_pipe_dec_to(dec, rd, twr))
            down = asyncio.ensure_future(_pipe_enc_from(enc, trd, wr))
            await up
            down.cancel()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ProtocolError, OSError, struct.error):
            pass
        finally:
            if twr is not None:
                try:
                    twr.close()
                except OSError:
                    pass
            try:
                wr.close()
            except OSError:
                pass


class FakeSocks5Server:
    """Trivial SOCKS5 CONNECT front-end for the upstream-chain test."""

    def __init__(self) -> None:
        self.targets = []
        self.server = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        # NOTE: no wait_closed() — the engine's sockets belong to another
        # (stopped) loop thread and would never drain here.
        if self.server is not None:
            self.server.close()
            self.server = None

    async def _handle(self, rd: asyncio.StreamReader,
                      wr: asyncio.StreamWriter) -> None:
        trd = twr = None
        try:
            greet = await asyncio.wait_for(rd.readexactly(3), 10)
            if greet[0] != 0x05:
                return
            wr.write(b"\x05\x00")
            await wr.drain()
            cmd, host, port = await _read_socks5_request(rd)
            if cmd != 0x01:
                return
            self.targets.append((host, port))
            trd, twr = await asyncio.open_connection(host, port)
            wr.write(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
            await wr.drain()
            p1 = asyncio.ensure_future(_raw_pipe(rd, twr))
            p2 = asyncio.ensure_future(_raw_pipe(trd, wr))
            await p1
            p2.cancel()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                OSError, struct.error):
            pass
        finally:
            if twr is not None:
                try:
                    twr.close()
                except OSError:
                    pass
            try:
                wr.close()
            except OSError:
                pass


# ===========================================================================
# fixtures
# ===========================================================================
@pytest.fixture()
def lt():
    thread = LoopThread(name="test-ss")
    yield thread
    thread.stop()
    time.sleep(0.05)                        # let the daemon loop exit
    try:
        thread.loop.close()
    except Exception:
        pass


@pytest.fixture()
def echo_port(lt):
    srv = lt.run(asyncio.start_server(_echo_client, "127.0.0.1", 0))
    return srv.sockets[0].getsockname()[1]


def _start_fake_ss(lt, method: str, password: str) -> FakeSSServer:
    fake = FakeSSServer(method, password)
    lt.run(fake.start())
    return fake


# ===========================================================================
# engine tests
# ===========================================================================
def test_engine_factory_and_defaults():
    port = _free_port()
    profile = M.ShadowsocksProfile(server="example.com", port=8388,
                                   method="aes-256-gcm", password="p", tag="x")
    eng = sslocal.engine(profile, socks_port=port)
    assert isinstance(eng, ShadowsocksEngine)
    assert eng.socks_port == port
    assert eng.proxy_kind == "shadowsocks"
    assert eng.family == "proxy"
    assert eng.exposes == "socks"
    assert eng.supports_upstream is True
    assert eng.running is False
    st = eng.status()
    assert st["running"] is False
    assert st["method"] == ""
    assert st["server"] == ""
    assert st["binary"] == "builtin"


def test_start_validates_profile():
    eng = ShadowsocksEngine()
    with pytest.raises(ProtocolError):
        eng.start(M.ShadowsocksProfile(server="", method="aes-256-gcm",
                                       password="p"))
    with pytest.raises(ProtocolError):
        eng.start(M.ShadowsocksProfile(server="1.2.3.4", port=8388,
                                       method="rc4-md5", password="p"))
    with pytest.raises(ProtocolError):
        eng.start(M.ShadowsocksProfile(server="1.2.3.4", port=8388,
                                       method="aes-256-gcm", password=""))
    with pytest.raises(ProtocolError):
        eng.start(M.ShadowsocksProfile(server="1.2.3.4", port=0,
                                       method="aes-256-gcm", password="p"))
    assert eng.running is False
    assert eng.status()["running"] is False


@pytest.mark.parametrize("method", ["aes-256-gcm", "chacha20-ietf-poly1305"])
def test_engine_end_to_end(lt, echo_port, method):
    fake = _start_fake_ss(lt, method, "ss-e2e-pass")
    eng = ShadowsocksEngine()
    profile = M.ShadowsocksProfile(server="127.0.0.1", port=fake.port,
                                   method=method, password="ss-e2e-pass",
                                   tag="e2e")
    try:
        eng.start(profile)
        assert eng.running is True
        st = eng.status()
        assert st["running"] is True
        assert st["method"] == method
        assert st["server"] == "127.0.0.1:%d" % fake.port

        rd, wr = lt.run(socks5_dial("127.0.0.1", eng.socks_port,
                                    "127.0.0.1", echo_port, timeout=10))
        wr.write(b"hello-ss")
        lt.run(wr.drain())
        assert lt.run(rd.readexactly(8)) == b"hello-ss"
        wr.write(b"second-payload")             # a second chunk on the stream
        lt.run(wr.drain())
        assert lt.run(rd.readexactly(14)) == b"second-payload"

        blob = os.urandom(50000)                # spans many 0x3FFF chunks
        wr.write(blob)
        lt.run(wr.drain())
        assert lt.run(rd.readexactly(50000)) == blob

        assert fake.targets == [("127.0.0.1", echo_port)]
        wr.close()
    finally:
        eng.stop()
        lt.run(fake.stop())
    assert eng.running is False
    assert eng.status()["running"] is False


def test_engine_upstream_chain(lt, echo_port):
    fake = _start_fake_ss(lt, "aes-256-gcm", "ss-up-pass")
    up = FakeSocks5Server()
    lt.run(up.start())
    eng = ShadowsocksEngine()
    eng.upstream_socks = ("127.0.0.1", up.port)
    profile = M.ShadowsocksProfile(server="127.0.0.1", port=fake.port,
                                   method="aes-256-gcm", password="ss-up-pass")
    try:
        eng.start(profile)
        rd, wr = lt.run(socks5_dial("127.0.0.1", eng.socks_port,
                                    "127.0.0.1", echo_port, timeout=10))
        wr.write(b"hello-up")
        lt.run(wr.drain())
        assert lt.run(rd.readexactly(8)) == b"hello-up"
        wr.close()
        # the SS server was reached THROUGH the upstream SOCKS5 ...
        assert up.targets == [("127.0.0.1", fake.port)]
        # ... and the SS tunnel reached the echo target
        assert fake.targets == [("127.0.0.1", echo_port)]
    finally:
        eng.stop()
        lt.run(fake.stop())
        lt.run(up.stop())
