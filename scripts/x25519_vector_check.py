"""Reference mirror of the TweetNaCl curve25519 port in
android/app/src/main/java/app/protoclean/proton/X25519.kt.

The two files implement the exact same limb algorithm (16-limb 16-bit
gf representation, car/sel/pack/unpack/A/Z/M/S/inv25519 + Montgomery
ladder) and must stay structurally identical: any change to the Kotlin
crypto should be mirrored here and re-validated with

    python3 scripts/x25519_vector_check.py

which checks RFC 7748 section 5.2 + 6.1 vectors and cross-checks 64
random keypairs against Python `cryptography`. The Android side runs
the same fixed vectors in X25519Test.kt (gradle testDebugUnitTest)."""

M16 = 16


def car25519(o):
    for i in range(16):
        o[i] += 1 << 16
        c = o[i] >> 16
        # o[(i+1)*(i<15)] += c-1+37*(c-1)*(i==15)
        idx = i + 1 if i < 15 else 0
        add = c - 1 + (37 * (c - 1) if i == 15 else 0)
        o[idx] += add
        o[i] -= c << 16


def sel25519(p, q, b):
    c = ~(b - 1) & 0xFFFFFFFFFFFFFFFF  # emulate i64; mask keeps t in range
    for i in range(16):
        t = c & (p[i] ^ q[i])
        p[i] ^= t
        q[i] ^= t


def pack25519(n):
    t = list(n)
    for _ in range(3):
        car25519(t)
    for _ in range(2):
        m = [0] * 16
        m[0] = t[0] - 0xFFED
        for i in range(1, 15):
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1)
            m[i - 1] &= 0xFFFF
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1)
        b = (m[15] >> 16) & 1
        m[14] &= 0xFFFF
        sel25519(t, m, 1 - b)
    out = bytearray(32)
    for i in range(16):
        out[2 * i] = t[i] & 0xFF
        out[2 * i + 1] = (t[i] >> 8) & 0xFF
    return bytes(out)


def unpack25519(n):
    o = [0] * 16
    for i in range(16):
        o[i] = n[2 * i] + (n[2 * i + 1] << 8)
    o[15] &= 0x7FFF
    return o


def A(a, b):
    return [a[i] + b[i] for i in range(16)]


def Z(a, b):
    return [a[i] - b[i] for i in range(16)]


def mul(a, b):
    t = [0] * 31
    for i in range(16):
        for j in range(16):
            t[i + j] += a[i] * b[j]
    for i in range(15):
        t[i] += 38 * t[i + 16]
    o = [t[i] for i in range(16)]
    car25519(o)
    car25519(o)
    return o


def S(a):
    return mul(a, a)


def inv25519(i):
    c = list(i)
    for a in range(253, -1, -1):
        c = S(c)
        if a != 2 and a != 4:
            c = mul(c, i)
    return c


_121665 = [0xDB41, 1] + [0] * 14


def scalar_mult(s, p):
    assert len(s) == 32 and len(p) == 32
    z = bytearray(s)
    z[31] = (s[31] & 127) | 64
    z[0] &= 248
    x = unpack25519(p)
    b = list(x)
    a = [0] * 16
    c = [0] * 16
    d = [0] * 16
    a[0] = 1
    d[0] = 1
    for i in range(254, -1, -1):
        r = (z[i >> 3] >> (i & 7)) & 1
        sel25519(a, b, r)
        sel25519(c, d, r)
        e = A(a, c)
        a = Z(a, c)
        c = A(b, d)
        b = Z(b, d)
        d = S(e)
        f = S(a)
        a = mul(c, a)
        c = mul(b, e)
        e = A(a, c)
        a = Z(a, c)
        b = S(a)
        c = Z(d, f)
        a = mul(c, _121665)
        a = A(a, d)
        c = mul(c, a)
        a = mul(d, f)
        d = mul(b, x)
        b = S(e)
        sel25519(a, b, r)
        sel25519(c, d, r)
    c = inv25519(c)
    a = mul(a, c)
    return pack25519(a)


def scalar_mult_base(s):
    base = bytearray(32)
    base[0] = 9
    return scalar_mult(s, bytes(base))


if __name__ == "__main__":
    # RFC 7748 section 5.2 vectors
    v = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ]
    for sk, u, want in v:
        got = scalar_mult(bytes.fromhex(sk), bytes.fromhex(u)).hex()
        assert got == want, f"vector failed: {got} != {want}"
    print("RFC 7748 5.2 vectors: OK")

    # RFC 7748 section 6.1 DH vectors
    a_priv = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_priv = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    a_pub_want = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b_pub_want = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared_want = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    a_pub = scalar_mult_base(a_priv)
    b_pub = scalar_mult_base(b_priv)
    assert a_pub == a_pub_want, f"a_pub {a_pub.hex()}"
    assert b_pub == b_pub_want, f"b_pub {b_pub.hex()}"
    assert scalar_mult(a_priv, b_pub) == shared_want
    assert scalar_mult(b_priv, a_pub) == shared_want
    print("RFC 7748 6.1 DH vectors: OK")

    # Cross-check vs python cryptography on random keypairs
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    for _ in range(64):
        k = X25519PrivateKey.generate()
        raw = k.private_bytes_raw()
        peer = X25519PrivateKey.generate()
        mine = scalar_mult_base(raw)
        theirs = peer.public_key().public_bytes_raw()
        assert mine == k.public_key().public_bytes_raw(), "pubkey mismatch"
        shared = k.exchange(peer.public_key())
        assert scalar_mult(raw, theirs) == shared, "shared mismatch"
    print("64 random keypairs vs cryptography: OK")
