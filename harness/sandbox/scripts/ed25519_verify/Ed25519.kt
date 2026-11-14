package app.protoclean.proton

import java.security.MessageDigest

/**
 * Minimal, self-contained Ed25519 *public-key derivation* for the
 * guest-mode certificate flow (the Edwards-curve mirror of [X25519],
 * ported from the same TweetNaCl sources — public domain, by
 * D. J. Bernstein et al.).
 *
 * The official ProtonVPN clients generate an **Ed25519** keypair per
 * session and send the public half as a PKIX (SubjectPublicKeyInfo) PEM
 * to `POST /vpn/v1/certificate` (`CertInfo.publicKeyPem` in the Android
 * app via gopenpgp's `publicKeyPKIXPem()`, `KeyHandler.ed25519_pk_pem`
 * in the Linux client). The WireGuard private key is *derived* from the
 * same keypair ([GuestApi.ed25519ToX25519PrivB64]) — the server
 * converts the Ed25519 point to its Montgomery (X25519) form when it
 * binds the certificate. A raw base64 X25519 key is rejected there with
 * Code 2001 "unable to read the key, please provide valid EC key".
 *
 * Ported structure (TweetNaCl function -> Kotlin), keeping the same
 * radix-2^16 field representation (16 limbs of 16 bits) and the same
 * value-returning helper style as [X25519] so every line can be audited
 * against the original C:
 *   car25519 -> [car25519], sel25519 -> [sel25519],
 *   pack25519 -> [pack25519], A -> [add], Z -> [sub], M -> [mul],
 *   S -> [square], inv25519 -> [inv25519], par25519 -> [par25519],
 *   add(gf p[4]) -> [pointAdd], cswap -> [cswap], pack -> [pointPack],
 *   scalarmult(gf p[4]) -> [pointScalarmult], scalarbase -> [scalarbase],
 *   crypto_sign_keypair's public half -> [publicKeyFromSeed].
 *
 * Verified against fixed test vectors generated with Python
 * `cryptography` (see `Ed25519Test`).
 */
internal object Ed25519 {

    private const val LIMBS = 16

    private val GF_0 = LongArray(LIMBS)
    private val GF_1 = LongArray(LIMBS).also { it[0] = 1 }

    /** 2 * d — the doubled Edwards curve constant (TweetNaCl `D2`). */
    private val D2 = longArrayOf(
        0xf159L, 0x26b2L, 0x9b94L, 0xebd6L, 0xb156L, 0x8283L, 0x149aL, 0x00e0L,
        0xd130L, 0xeef3L, 0x80f2L, 0x198eL, 0xfce7L, 0x56dfL, 0xd9dcL, 0x2406L,
    )

    /** Edwards base point X coordinate (TweetNaCl `X`). */
    private val BASE_X = longArrayOf(
        0xd51aL, 0x8f25L, 0x2d60L, 0xc956L, 0xa7b2L, 0x9525L, 0xc760L, 0x692cL,
        0xdc5cL, 0xfdd6L, 0xe231L, 0xc0a4L, 0x53feL, 0xcd6eL, 0x36d3L, 0x2169L,
    )

    /** Edwards base point Y coordinate (TweetNaCl `Y`). */
    private val BASE_Y = longArrayOf(
        0x6658L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L,
        0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L,
    )

    // ------------------------------------------ field-element (gf) helpers
    // (identical to the audited implementations in X25519.kt)

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

    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).toLong().inv() // b=1 -> all ones, b=0 -> 0
        for (i in 0 until LIMBS) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

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

    /** Field inversion via Fermat: a^(2^255-21), as TweetNaCl `inv25519`. */
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

    /** Parity of the field element's low bit (TweetNaCl `par25519`). */
    private fun par25519(a: LongArray): Byte = (pack25519(a)[0].toInt() and 1).toByte()

    // ------------------------------------- Edwards point helpers (extended
    // coordinates: p[0]=X, p[1]=Y, p[2]=Z, p[3]=T)

    /** p = p + q (TweetNaCl `add(gf p[4], gf q[4])`, in place on p). */
    private fun pointAdd(p: Array<LongArray>, q: Array<LongArray>) {
        val a = mul(sub(p[1], p[0]), sub(q[1], q[0]))
        val b = mul(add(p[0], p[1]), add(q[0], q[1]))
        val c = mul(mul(p[3], q[3]), D2)
        val d = add(mul(p[2], q[2]), mul(p[2], q[2]))
        val e = sub(b, a)
        val f = sub(d, c)
        val g = add(d, c)
        val h = add(b, a)
        p[0] = mul(e, f)
        p[1] = mul(h, g)
        p[2] = mul(g, f)
        p[3] = mul(e, h)
    }

    /** Constant-time conditional swap of two points. */
    private fun cswap(p: Array<LongArray>, q: Array<LongArray>, b: Int) {
        for (i in 0 until 4) sel25519(p[i], q[i], b)
    }

    /** Encode a point (TweetNaCl `pack`): 32 bytes, sign of X in bit 255. */
    private fun pointPack(p: Array<LongArray>): ByteArray {
        val zi = inv25519(p[2])
        val tx = mul(p[0], zi)
        val ty = mul(p[1], zi)
        val r = pack25519(ty)
        r[31] = (r[31].toInt() xor (par25519(tx).toInt() shl 7)).toByte()
        return r
    }

    /** TweetNaCl `scalarmult(gf p[4], gf q[4], s)`: returns s·q. NOTE the
     *  reference mutates both p and q; here p is fresh and q (the base)
     *  is owned by the caller ([scalarbase] builds it per call). */
    private fun pointScalarmult(q: Array<LongArray>, s: ByteArray): Array<LongArray> {
        val p = Array(4) { LongArray(LIMBS) }
        p[0] = GF_0.copyOf()
        p[1] = GF_1.copyOf()
        p[2] = GF_1.copyOf()
        p[3] = GF_0.copyOf()
        for (i in 255 downTo 0) {
            val b = ((s[i / 8].toInt() and 0xFF) shr (i and 7)) and 1
            cswap(p, q, b)
            pointAdd(q, p)
            pointAdd(p, p)
            cswap(p, q, b)
        }
        return p
    }

    /** TweetNaCl `scalarbase`: s·B with B the Edwards base point. */
    private fun scalarbase(s: ByteArray): Array<LongArray> {
        val q = Array(4) { LongArray(LIMBS) }
        q[0] = BASE_X.copyOf()
        q[1] = BASE_Y.copyOf()
        q[2] = GF_1.copyOf()
        q[3] = mul(BASE_X, BASE_Y)
        return pointScalarmult(q, s)
    }

    // ------------------------------------------------------------- public API

    /** Derive the 32-byte Ed25519 public key from a 32-byte seed — the
     *  public half of TweetNaCl's `crypto_sign_keypair`:
     *  SHA-512(seed), clamp, scalar-base-multiply, pack. */
    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "seed must be 32 bytes" }
        val d = MessageDigest.getInstance("SHA-512").digest(seed)
        d[0] = (d[0].toInt() and 248).toByte()
        d[31] = ((d[31].toInt() and 127) or 64).toByte()
        return pointPack(scalarbase(d))
    }
}
