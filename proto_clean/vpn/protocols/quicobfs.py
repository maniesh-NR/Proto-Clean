"""QUIC packet obfuscation for the built-in engines.

Censors increasingly fingerprint QUIC by its long-header Initial packets
and by the raw entropy of short-header datagrams.  This module provides
two symmetric, packet-level transforms that the built-in QUIC engines
(Hysteria 2, TUIC, MASQUE, Cover-QUIC) can apply on top of the UDP flow.
They only matter between our client and OUR server side (or a server that
speaks the same transform); when a profile targets an official third-party
server the transform must stay off — except Hysteria 2's *salamander*, the
official obfuscation, which lives in :mod:`.hysteria2` because it is part
of that protocol.

Modes
-----
``http3``   Wrap every datagram in a fake QUIC v1 long header so the flow
            looks like a stream of HTTP/3 Initial/0-RTT packets (random
            DCID each packet, plausible versions, size jitter).  The
            inner bytes are carried as the payload.
``whitening`` XOR each datagram with a counter-mode keystream derived
            from a PSK and a per-flow salt (sent in the first datagram),
            equalising packet entropy without changing shapes.
``http3+whitening`` both: fake headers *and* whitened payload.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Callable, Tuple

MODES = ("none", "http3", "whitening", "http3+whitening")

_SALT_LEN = 8
_FAKE_VERSION = 0x00000001          # QUIC v1 (long-header version field)
_FAKE_DCID_LEN = 8


class ObfuscationError(ValueError):
    """Raised when a datagram cannot be unwrapped."""


def _keystream(key: str, salt: bytes, n: int) -> bytes:
    """Counter-mode keystream: SHA-256(key || salt || be32(i)) blocks."""
    kb = (key or "").encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(
            kb + salt + struct.pack("!I", counter)).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data: bytes, ks: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, ks))


def _fake_long_header(payload: bytes) -> bytes:
    """Wrap ``payload`` in a QUIC v1 long header of the right shape.

    Header: first byte 0b11xxxxxx (long, fixed bits + random bits),
    version (4B), DCID len + DCID (random), SCID len 0, then payload.
    Packet-number and length fields of a real Initial are omitted — this
    only has to *look* like QUIC to a passive observer; the peer unwraps
    structurally.
    """
    hdr = bytes([0xC0 | (os.urandom(1)[0] & 0x3F)])
    hdr += struct.pack("!I", _FAKE_VERSION)
    dcid = os.urandom(_FAKE_DCID_LEN)
    hdr += bytes([_FAKE_DCID_LEN]) + dcid + b"\x00"
    # size jitter so packet sizes do not fingerprint the wrapper itself
    pad = os.urandom(1)[0] % 37
    return hdr + payload + os.urandom(pad)


def _unfake_long_header(datagram: bytes) -> bytes:
    if len(datagram) < 1 + 4 + 1 + _FAKE_DCID_LEN + 1:
        raise ObfuscationError("datagram too short for the http3 wrapper")
    if not datagram[0] & 0x80:
        raise ObfuscationError("not a long-header datagram")
    off = 1 + 4
    dcid_len = datagram[off]
    off += 1 + dcid_len + 1
    return datagram[off:]


class PacketObfuscator:
    """Symmetric packet transform selected by ``mode``.

    Use :meth:`wrap` on outgoing and :meth:`unwrap` on incoming datagrams.
    The first wrapped datagram carries the salt (whitening modes) so both
    sides derive the same keystream without a prior handshake.
    """

    def __init__(self, mode: str = "none", key: str = "") -> None:
        mode = (mode or "none").strip().lower()
        if mode not in MODES:
            raise ObfuscationError("unknown QUIC obfuscation mode %r" % mode)
        if mode != "none" and "whitening" in mode and not key:
            raise ObfuscationError("whitening modes need a PSK (key)")
        self.mode = mode
        self.key = key
        self._salt: bytes = b""
        self._salt_sent = False

    # -- helpers -----------------------------------------------------------
    @property
    def active(self) -> bool:
        return self.mode != "none"

    def _do_wrap(self, data: bytes) -> bytes:
        if self.mode in ("whitening", "http3+whitening"):
            if not self._salt_sent:
                self._salt_sent = True
                self._salt = os.urandom(_SALT_LEN)
                return self._salt + _xor(data, _keystream(
                    self.key, self._salt, len(data)))
            return _xor(data, _keystream(self.key, self._salt, len(data)))
        return data

    def _do_unwrap(self, data: bytes) -> bytes:
        if self.mode in ("whitening", "http3+whitening"):
            if not self._salt:
                if len(data) <= _SALT_LEN:
                    raise ObfuscationError("first datagram lacks the salt")
                self._salt, data = data[:_SALT_LEN], data[_SALT_LEN:]
            return _xor(data, _keystream(self.key, self._salt, len(data)))
        return data

    # -- public API --------------------------------------------------------
    def wrap(self, data: bytes) -> bytes:
        """Transform one outgoing datagram."""
        if not self.active:
            return bytes(data)
        data = self._do_wrap(bytes(data))
        if self.mode in ("http3", "http3+whitening"):
            data = _fake_long_header(data)
        return data

    def unwrap(self, data: bytes) -> bytes:
        """Transform one incoming datagram (raises ObfuscationError on
        garbage — callers drop the datagram)."""
        data = bytes(data)
        if not self.active:
            return data
        if self.mode in ("http3", "http3+whitening"):
            data = _unfake_long_header(data)
        return self._do_unwrap(data)


def make_pair(mode: str = "http3", key: str = "test-key"
              ) -> Tuple[PacketObfuscator, PacketObfuscator]:
    """A matched (client, server) obfuscator pair — test helper and for
    people running both sides."""
    return PacketObfuscator(mode, key), PacketObfuscator(mode, key)
