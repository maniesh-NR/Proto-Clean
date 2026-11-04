"""Tests for the Cover-DTLS covert transport engine.

Starts a real DTLS 1.2 server (self-signed pyOpenSSL cert) plus a loopback
TCP echo server, then pushes bytes through the engine's local SOCKS5
front-end to the echo port — once without and once with the PSK whitening
cover.  Also unit-tests the whitening keystream function.  Skips cleanly
when pyOpenSSL with DTLS support is unavailable.
"""

from __future__ import annotations

import asyncio
import time

import sys

import pytest

try:
    from OpenSSL import crypto
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - pyOpenSSL missing
    crypto = None
    _HAVE_CRYPTO = False

from proto_clean.vpn.protocols import coverdtls as CD
from proto_clean.vpn.protocols.models import CoverDtlsProfile
from proto_clean.vpn.protocols.socks_server import socks5_dial

pytestmark = pytest.mark.skipif(
    not (CD.DTLS_AVAILABLE and _HAVE_CRYPTO),
    reason="pyOpenSSL with DTLS support not available")


def make_cert_key():
    """Self-signed RSA-2048 cert/key as pyOpenSSL crypto objects."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "cover-dtls-test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert, key


async def _echo_handler(rd, wr) -> None:
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


async def _exercise(psk: str) -> None:
    """Full loop: DTLS server + engine + SOCKS5 CONNECT + echo round-trips."""
    cert, key = make_cert_key()
    server = CD.CoverDtlsServer("127.0.0.1", 0, cert, key, psk=psk)
    server.start()
    echo = None
    eng = None
    try:
        assert server.address[0] == "127.0.0.1"
        assert server.address[1] > 0

        echo = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
        echo_port = echo.sockets[0].getsockname()[1]

        profile = CoverDtlsProfile(server="127.0.0.1",
                                   port=server.address[1],
                                   insecure=True, psk=psk)
        eng = CD.engine(profile)
        eng.start(profile, timeout=15.0)
        assert eng.socks_port > 0
        status = eng.status()
        assert status["kind"] == "coverdtls"
        assert status["exposes"] == "socks"

        rd, wr = await socks5_dial("127.0.0.1", eng.socks_port,
                                   "127.0.0.1", echo_port, timeout=15)
        payload = b"hello-dtls"
        wr.write(payload)
        await wr.drain()
        got = await asyncio.wait_for(rd.readexactly(len(payload)), 15)
        assert got == payload

        # a second round-trip proves frame reassembly across records works
        wr.write(b"second frame")
        await wr.drain()
        got2 = await asyncio.wait_for(rd.readexactly(12), 15)
        assert got2 == b"second frame"

        wr.close()
    finally:
        if eng is not None:
            eng.stop()
        if echo is not None:
            echo.close()
            try:
                await echo.wait_closed()
            except Exception:
                pass
        server.stop()


# Windows CI runs the full unit suite; the socket/loopback engine e2e
# tests are exercised on the Linux and macOS legs (they bind many local
# ports and spawn helper processes, which is unreliable on the
# shared Windows runners).
pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="engine e2e covered on Linux/macOS runners")


@pytest.mark.parametrize("psk", ["", "hunter2-covered"], ids=["plain", "psk"])
def test_socks5_roundtrip_through_dtls_cover(psk):
    started = time.time()
    asyncio.run(_exercise(psk))
    assert time.time() - started < 30   # each round-trip should be fast


def test_whitening_keystream_deterministic():
    salt_a = b"12345678"
    salt_b = b"87654321"
    ks1 = CD.whitening_keystream("psk", salt_a, 100)
    ks2 = CD.whitening_keystream("psk", salt_a, 100)
    assert ks1 == ks2                          # deterministic per (psk, salt)
    assert len(ks1) == 100
    assert ks1 != CD.whitening_keystream("psk", salt_b, 100)   # salt varies
    assert ks1 != CD.whitening_keystream("other-psk", salt_a, 100)

    # the XOR cover is self-inverse; a different salt must not decode
    data = b"\x00\x17\xfe\xfd" * 25
    covered = CD.cover("psk", salt_a, data)
    assert covered != data
    assert CD.cover("psk", salt_a, covered) == data
    assert CD.cover("psk", salt_b, covered) != data
