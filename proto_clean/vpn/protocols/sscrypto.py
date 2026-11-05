"""Pure-Python Shadowsocks AEAD crypto primitives (py3.8+, ``cryptography``).

Implements the wire format of the Shadowsocks AEAD spec (2017 edition as
used by shadowsocks-libev / go-shadowsocks2):

* Key derivation — the legacy password KDF (OpenSSL ``EVP_BytesToKey``
  with MD5 and 1 iteration, no salt) maps the ASCII password to the
  master key; each session then derives a per-session subkey with
  HKDF-SHA1 (info ``b"ss-subkey"``) from the master key and a random
  salt.
* Stream framing — ``[salt][chunk][chunk]...`` where each chunk is
  ``[encrypted 2-byte big-endian payload length][length tag]
  [encrypted payload][payload tag]``.  The 2-byte length is itself the
  AEAD plaintext of the first mini-cipher (no additional data is used
  anywhere in the protocol), the payload is capped at ``0x3FFF`` bytes
  per chunk and the 12-byte nonce starts at zero and is incremented
  (little-endian) once per AEAD operation, for each direction
  independently.

Each :class:`SessionCipher` is bound to ONE salt and therefore to one
direction: the sender calls :meth:`SessionCipher.encrypt`, the receiver
creates its own session from the same salt and calls
:meth:`SessionCipher.decrypt`.  TCP streams and UDP datagrams differ
only in how many chunks they carry (see :mod:`.sslocal`).

AES-GCM runs through streaming ``CipherContext`` (``update`` /
``update_with_tag``); ChaCha20-Poly1305 uses the one-shot AEAD API
because ``cryptography``'s ``CipherContext`` cannot be given a nonce for
that cipher.  No external processes, no OpenSSL CLI.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .base import ProtocolError

__all__ = ["hkdf_sha1", "derive_subkey", "increment_nonce", "EVP_BytesToKey",
           "CIPHERS", "CipherCtx", "SessionCipher"]

#: cipher name -> (key length in bytes, salt length in bytes)
CIPHERS: Dict[str, Tuple[int, int]] = {
    "aes-128-gcm": (16, 16),
    "aes-192-gcm": (24, 24),
    "aes-256-gcm": (32, 32),
    "chacha20-ietf-poly1305": (32, 32),
}

_NONCE_LEN = 12          # both AES-GCM and ChaCha20-Poly1305 use 96-bit nonces
_TAG_LEN = 16            # AEAD tag length
_MAX_PAYLOAD = 0x3FFF    # max plaintext bytes per chunk (SS AEAD spec)
_HKDF_INFO = b"ss-subkey"


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------
def hkdf_sha1(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-1: extract-then-expand, ``length`` output bytes."""
    prk = hmac.new(salt, key, hashlib.sha1).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes((counter,)),
                         hashlib.sha1).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_subkey(master: bytes, salt: bytes, length: int) -> bytes:
    """Shadowsocks per-session subkey: HKDF-SHA1(master, salt, "ss-subkey")."""
    return hkdf_sha1(master, salt, _HKDF_INFO, length)


def increment_nonce(nonce: bytearray) -> bytearray:
    """+1 on the little-endian nonce counter, wrapping around at the top."""
    for i in range(len(nonce)):
        nonce[i] = (nonce[i] + 1) & 0xFF
        if nonce[i]:
            break
    return nonce


def EVP_BytesToKey(password: bytes, key_len: int) -> bytes:
    """OpenSSL ``EVP_BytesToKey`` (MD5, 1 iteration, no salt) — the legacy
    Shadowsocks password KDF: ``D_i = MD5(D_{i-1} + password)``, the key is
    the concatenation of the ``D_i`` truncated to ``key_len`` bytes."""
    d = b""
    prev = b""
    while len(d) < key_len:
        prev = hashlib.md5(prev + password).digest()
        d += prev
    return d[:key_len]


# ---------------------------------------------------------------------------
# AEAD plumbing
# ---------------------------------------------------------------------------
def _seal(method: str, key: bytes, nonce: bytes,
          plaintext: bytes,
          aead: Optional[ChaCha20Poly1305] = None) -> Tuple[bytes, bytes]:
    """AEAD-encrypt ``plaintext``; returns ``(ciphertext, tag)``.

    ``aead``: a pre-built ChaCha20Poly1305 for ``key`` — its key schedule
    is the expensive part, so sessions reuse one object per direction
    instead of rebuilding it for every chunk."""
    if method == "chacha20-ietf-poly1305":
        cipher = aead or ChaCha20Poly1305(key)
        sealed = cipher.encrypt(nonce, plaintext, None)
        return sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct, enc.tag


def _open(method: str, key: bytes, nonce: bytes,
          ciphertext: bytes, tag: bytes,
          aead: Optional[ChaCha20Poly1305] = None) -> bytes:
    """AEAD-decrypt; raises :class:`ProtocolError` when the tag fails."""
    try:
        if method == "chacha20-ietf-poly1305":
            cipher = aead or ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext + tag, None)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        return dec.update(ciphertext) + dec.finalize_with_tag(tag)
    except InvalidTag:
        raise ProtocolError("shadowsocks AEAD tag check failed") from None


class SessionCipher:
    """AEAD chunk stream for one salt / one direction.

    :meth:`encrypt` frames arbitrary data into spec chunks
    (``[2-byte len][len tag][payload][payload tag]``, splitting at
    ``0x3FFF``) with its own nonce counter.  :meth:`decrypt` appends
    arrived bytes to an internal buffer and returns the concatenated
    payload of every chunk that is fully available, raising
    :class:`ProtocolError` on a tag failure or an oversized length.
    """

    MAX_PAYLOAD = _MAX_PAYLOAD
    TAG_LEN = _TAG_LEN
    NONCE_LEN = _NONCE_LEN

    def __init__(self, method: str, subkey: bytes) -> None:
        self._method = method
        self._key = bytes(subkey)
        self._enc_nonce = bytearray(_NONCE_LEN)
        self._dec_nonce = bytearray(_NONCE_LEN)
        # append-only raw input buffer (bytearray: ``+=`` on bytes would
        # copy the whole stream on every feed — O(n²) over a long
        # transfer; bytearray append is amortised O(1))
        self._dec_buf = bytearray()
        # one key schedule per direction for the ChaCha20 AEAD object
        self._aead = (ChaCha20Poly1305(self._key)
                      if method == "chacha20-ietf-poly1305" else None)

    @property
    def pending(self) -> int:
        """Raw bytes buffered by :meth:`decrypt` but not yet a full chunk."""
        return len(self._dec_buf)

    # -- sending ----------------------------------------------------------
    def encrypt(self, data: bytes) -> bytes:
        data = bytes(data)
        if not data:
            return b""
        out = []
        off = 0
        while off < len(data):
            piece = data[off:off + _MAX_PAYLOAD]
            off += len(piece)
            # one nonce per chunk: the length header and the payload share it
            ct, tag = _seal(self._method, self._key, bytes(self._enc_nonce),
                            struct.pack("!H", len(piece)), self._aead)
            out += (ct, tag)
            ct, tag = _seal(self._method, self._key, bytes(self._enc_nonce),
                            piece, self._aead)
            out += (ct, tag)
            increment_nonce(self._enc_nonce)
        return b"".join(out)

    # -- receiving --------------------------------------------------------
    def decrypt(self, data: bytes) -> bytes:
        self._dec_buf += data
        buf = self._dec_buf
        n = len(buf)
        out = []
        pos = 0
        while True:
            if n - pos < 2 + _TAG_LEN:
                break
            try:
                hdr = _open(self._method, self._key, bytes(self._dec_nonce),
                            bytes(buf[pos:pos + 2]),
                            bytes(buf[pos + 2:pos + 2 + _TAG_LEN]),
                            self._aead)
            except ProtocolError:
                del buf[:]
                raise                    # stream is unrecoverable
            size = struct.unpack("!H", hdr)[0]
            if size > _MAX_PAYLOAD:
                del buf[:]
                raise ProtocolError(
                    "shadowsocks chunk length %d exceeds the 0x3FFF limit"
                    % size)
            total = 2 + _TAG_LEN + size + _TAG_LEN
            if n - pos < total:
                break                            # wait for the rest of the chunk
            try:
                payload = _open(self._method, self._key,
                                bytes(self._dec_nonce),
                                bytes(buf[pos + 2 + _TAG_LEN:
                                          pos + 2 + _TAG_LEN + size]),
                                bytes(buf[pos + 2 + _TAG_LEN + size:
                                          pos + total]),
                                self._aead)
            except ProtocolError:
                del buf[:]
                raise
            increment_nonce(self._dec_nonce)
            out.append(payload)
            pos += total
        if pos:
            del buf[:pos]                  # consume parsed chunks (O(rest))
        return b"".join(out)


class CipherCtx:
    """Master key + cipher method; factory for per-salt session ciphers."""

    def __init__(self, method: str, key: bytes) -> None:
        method = (method or "").strip().lower()
        if method not in CIPHERS:
            raise ProtocolError("unsupported Shadowsocks cipher %r" % method)
        key_len, salt_len = CIPHERS[method]
        key = bytes(key or b"")
        if len(key) != key_len:
            raise ProtocolError("%s needs a %d-byte key, got %d bytes"
                                % (method, key_len, len(key)))
        self.method = method
        self.key = key
        self.key_len = key_len
        self.salt_len = salt_len

    @classmethod
    def from_password(cls, method: str, password: str) -> "CipherCtx":
        """Build the master key from a password via the legacy SS KDF."""
        if not password:
            raise ProtocolError("empty Shadowsocks password")
        try:
            key_len = CIPHERS[(method or "").strip().lower()][0]
        except KeyError:
            key_len = 32                        # CipherCtx validates the name
        return cls(method, EVP_BytesToKey(password.encode("utf-8"), key_len))

    def derive(self, salt: bytes) -> bytes:
        """The per-session subkey for ``salt``."""
        return derive_subkey(self.key, salt, self.key_len)

    def new_session(self, salt: bytes) -> SessionCipher:
        """A :class:`SessionCipher` bound to one direction's ``salt`` — the
        sender uses :meth:`SessionCipher.encrypt` on it, the receiver
        constructs the same from the observed salt and decrypts."""
        salt = bytes(salt or b"")
        if len(salt) != self.salt_len:
            raise ProtocolError("shadowsocks salt must be %d bytes, got %d"
                                % (self.salt_len, len(salt)))
        return SessionCipher(self.method, self.derive(salt))
