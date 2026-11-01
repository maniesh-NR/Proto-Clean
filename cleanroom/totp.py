"""RFC 6238 TOTP generation (no external dependency).

If the user stores their Proton 2FA secret, Cleanroom can answer the
two-factor prompt automatically; otherwise the UI asks for a code.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import struct
import time
from urllib.parse import parse_qs, urlparse


def normalize_secret(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    padding = "=" * (-len(secret) % 8)
    return base64.b32decode(secret + padding, casefold=True)


def totp(secret: str, period: int = 30, digits: int = 6, t: int | None = None) -> str:
    key = normalize_secret(secret)
    counter = int((t if t is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
    return str(code % (10 ** digits)).zfill(digits)


def parse_otpauth(uri: str) -> tuple:
    """Return (secret, digits, period) from an otpauth:// URI."""
    parsed = urlparse(uri)
    q = parse_qs(parsed.query)
    secret = q.get("secret", [""])[0]
    digits = int(q.get("digits", ["6"])[0])
    period = int(q.get("period", ["30"])[0])
    return secret, digits, period


def code_from(secret_or_uri: str, t: int | None = None) -> str:
    s = secret_or_uri.strip()
    if s.lower().startswith("otpauth://"):
        secret, digits, period = parse_otpauth(s)
        return totp(secret, period, digits, t)
    return totp(s, t=t)
