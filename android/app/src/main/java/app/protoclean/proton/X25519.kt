package app.protoclean.proton

/**
 * Minimal, self-contained X25519 (Curve25519) implementation for the
 * guest-mode WireGuard keypair generation.
 *
 * This is a faithful port of the `crypto_scalarmult` /
 * `crypto_scalarmult_base` functions from TweetNaCl (public domain,
 * by D. J. Bernstein et al.), keeping the same radix-2^16 field
 * representation (16 limbs of 16 bits in a `LongArray(16)`) and the
 * same carry / conditional-swap / pack / unpack helpers, so the
 * algorithm can be audited line-by-line against the original C.
 *
 * Ported structure (TweetNaCl function -> Kotlin):
 *   car25519 -> [car25519], sel25519 -> [sel25519],
 *   pack25519 -> [pack25519], unpack25519 -> [unpack25519],
 *   A -> [add], Z -> [sub], M -> [mul], S -> [square],
 *   inv25519 -> [inv25519], crypto_scalarmult -> [scalarMult].
 *
 * Verified against the RFC 7748 section 5.2 and 6.1 test vectors and
 * cross-checked against Python `cryptography` on random keypairs
 * (see `X25519Test` / `scripts/tnacl_mirror.py`).
 */
internal object X25519 {

    private const val LIMBS = 16
    private val GF_121665 = longArrayOf(0xDB41L, 1L) + LongArray(14)

    /** Multiply the (unclamped) scalar `s` by the standard base point
     *  u=9 — used to derive a WireGuard public key from a private key. */
    fun scalarMultBase(s: ByteArray): ByteArray {
        val base = ByteArray(32)
        base[0] = 9
        return scalarMult(s, base)
    }

    /** X25519 scalar multiplication: RFC 7748 `X25519(k, u)`.
     *  `s` is the scalar and `u` the input point, both 32 bytes
     *  little-endian; returns the 32-byte little-endian result. */
    fun scalarMult(s: ByteArray, u: ByteArray): ByteArray {
        require(s.size == 32 && u.size == 32) { "inputs must be 32 bytes" }

        // Clamp the scalar per RFC 7748 section 5 (as TweetNaCl does).
        val z = s.copyOf()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()

        val x = unpack25519(u)
        var a = LongArray(LIMBS)
        var b = x.copyOf()
        var c = LongArray(LIMBS)
        var d = LongArray(LIMBS)
        a[0] = 1
        d[0] = 1

        // Montgomery ladder, 255 steps (MSB first, bit 254 .. 0).
        for (i in 254 downTo 0) {
            val r = ((z[i shr 3].toInt() and 0xFF) shr (i and 7)) and 1
            sel25519(a, b, r)
            sel25519(c, d, r)
            var e = add(a, c)
            a = sub(a, c)
            c = add(b, d)
            b = sub(b, d)
            d = square(e)
            val f = square(a)
            a = mul(c, a)
            c = mul(b, e)
            e = add(a, c)
            a = sub(a, c)
            b = square(a)
            c = sub(d, f)
            a = mul(c, GF_121665)
            a = add(a, d)
            c = mul(c, a)
            a = mul(d, f)
            d = mul(b, x)
            b = square(e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }

        c = inv25519(c)
        a = mul(a, c)
        return pack25519(a)
    }

    // ---- TweetNaCl field-element helpers (radix 2^16, 16 limbs) -------

    /** Propagate carries so every limb lands in [0, 2^16). */
    private fun car25519(o: LongArray) {
        for (i in 0 until LIMBS) {
            o[i] += 1L shl 16
            val c = o[i] shr 16
            // C: o[(i+1)*(i<15)] += c-1+37*(c-1)*(i==15)
            val idx = if (i < 15) i + 1 else 0
            o[idx] += c - 1 + (if (i == 15) 37 * (c - 1) else 0)
            o[i] -= c shl 16
        }
    }

    /** Constant-time conditional swap: if b == 1, p and q are swapped. */
    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).toLong().inv() // b=1 -> all ones, b=0 -> 0
        for (i in 0 until LIMBS) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    /** Serialize a field element to 32 bytes little-endian, fully reduced. */
    private fun pack25519(n: LongArray): ByteArray {
        val t = n.copyOf()
        repeat(3) { car25519(t) }
        repeat(2) {
            val m = LongArray(LIMBS)
            m[0] = t[0] - 0xFFED
            for (i in 1 until 15) {
                m[i] = t[i] - 0xFFFF - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xFFFF
            }
            m[15] = t[15] - 0x7FFF - ((m[14] shr 16) and 1)
            val b = (m[15] shr 16) and 1
            m[14] = m[14] and 0xFFFF
            sel25519(t, m, (1 - b).toInt())
        }
        val out = ByteArray(32)
        for (i in 0 until LIMBS) {
            out[2 * i] = (t[i] and 0xFF).toByte()
            out[2 * i + 1] = ((t[i] shr 8) and 0xFF).toByte()
        }
        return out
    }

    /** Deserialize 32 little-endian bytes into a field element
     *  (top bit cleared — that is the sign, not a value bit). */
    private fun unpack25519(n: ByteArray): LongArray {
        val o = LongArray(LIMBS)
        for (i in 0 until LIMBS) {
            o[i] = (n[2 * i].toLong() and 0xFF) +
                ((n[2 * i + 1].toLong() and 0xFF) shl 8)
        }
        o[15] = o[15] and 0x7FFF
        return o
    }

    private fun add(a: LongArray, b: LongArray): LongArray {
        val o = LongArray(LIMBS)
        for (i in 0 until LIMBS) o[i] = a[i] + b[i]
        return o
    }

    private fun sub(a: LongArray, b: LongArray): LongArray {
        val o = LongArray(LIMBS)
        for (i in 0 until LIMBS) o[i] = a[i] - b[i]
        return o
    }

    /** Field multiplication (2^255 - 19), as TweetNaCl `M`. */
    private fun mul(a: LongArray, b: LongArray): LongArray {
        val t = LongArray(2 * LIMBS - 1)
        for (i in 0 until LIMBS) {
            for (j in 0 until LIMBS) {
                t[i + j] += a[i] * b[j]
            }
        }
        for (i in 0 until LIMBS - 1) {
            t[i] += 38 * t[i + LIMBS]
        }
        val o = LongArray(LIMBS)
        for (i in 0 until LIMBS) o[i] = t[i]
        car25519(o)
        car25519(o)
        return o
    }

    private fun square(a: LongArray): LongArray = mul(a, a)

    /** Field inversion via Fermat: a^(p-2) with p = 2^255 - 19. */
    private fun inv25519(i: LongArray): LongArray {
        var c = i.copyOf()
        for (a in 253 downTo 0) {
            c = square(c)
            if (a != 2 && a != 4) {
                c = mul(c, i)
            }
        }
        return c
    }
}
