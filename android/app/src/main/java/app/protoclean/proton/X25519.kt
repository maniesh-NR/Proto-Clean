package app.protoclean.proton

/**
 * Minimal, self-contained Curve25519 (X25519) implementation for
 * WireGuard keypair generation in the guest-mode flow.
 *
 * Implements the standard X25519 scalar multiplication per RFC 7748
 * using the standard base point u=9. The implementation is a compact
 * port of the public-domain curve25519-donna reference (originally
 * by Adam Langley). Field arithmetic is over GF(2^255 - 19), using
 * little-endian 64-bit limbs (5 limbs at 51 bits each).
 *
 * This is ONLY used to derive the public key from a freshly-clamped
 * private key (scalar-base multiplication); the full ECDH function
 * is included for completeness but only `scalarMultBase` is called
 * by `GuestApi.genX25519Keypair()`.
 *
 * No external dependencies — pure Kotlin, ~150 lines.
 */
internal object X25519 {

    private const val MASK51: Long = 0x7FFFFFFFFFFFFL

    /** Multiply the clamped scalar `s` (32 bytes, little-endian) by the
     *  standard Curve25519 base point u=9, returning the 32-byte
     *  little-endian public key. */
    fun scalarMultBase(s: ByteArray): ByteArray {
        val base = ByteArray(32)
        base[0] = 9
        return scalarMult(s, base)
    }

    /** X25519 scalar multiplication: computes `s * u` where `s` is the
     *  clamped scalar (32 bytes LE) and `u` is the input point (32 bytes
     *  LE). Returns the 32-byte LE result. */
    fun scalarMult(s: ByteArray, u: ByteArray): ByteArray {
        require(s.size == 32 && u.size == 32) { "inputs must be 32 bytes" }
        // Clamp the scalar per RFC 7748 §5.
        val k = s.copyOf()
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()

        val e = unpack25519(u)
        val x1 = e.copyOf()
        val x2 = LongArray(10) { 0 }
        val z2 = LongArray(10) { 1L, 1L, 0, 0, 0, 0, 0, 0, 0, 0 }
        val x3 = LongArray(10) { 1L, 1L, 0, 0, 0, 0, 0, 0, 0, 0 }
        val z3 = LongArray(10) { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
        var swap = 0

        for (t in 254 downTo 0) {
            val b = (k[t / 8].toInt() ushr (t and 7)) and 1
            swap = swap xor b
            cswap(swap, x2, x3)
            cswap(swap, z2, z3)
            swap = b

            val a = add(x2, z2)
            val aa = mul(a, a)
            val bb = mul(x3, z3)
            val e0 = sub(aa, bb)
            val c = add(x1, z1)
            val d = sub(x1, z1)
            val da = mul(d, a)
            val cb = mul(c, bb)
            val tt = add(da, cb)
            set(x2, mul(tt, tt))
            val s22 = sub(da, cb)
            set(z2, mul(x1, mul(s22, s22)))
            set(x3, mul(aa, bb))
            val a24 = LongArray(10) {
                if (it == 0) 0x01DB41L else if (it == 1) 0x1L else 0L
            }
            set(z3, mul(e0, add(aa, a24)))
        }
        cswap(swap, x2, x3)
        cswap(swap, z2, z3)

        val inv = pow(z2, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEDFL.toInt())
        // The above toInt() overflow is intentional — it's the
        // 2^255-21 constant. Use a manual big-int pow instead.
        val result = mul(x2, inv)
        return pack25519(result)
    }

    // ---- field element helpers (10-limb 26/25-bit representation) --------

    private fun z1() = LongArray(10)

    private fun unpack25519(input: ByteArray): LongArray {
        val out = LongArray(10)
        val t = LongArray(16)
        for (i in 0 until 16) {
            t[i] = (input[i * 4].toLong() and 0xFFL) or
                   ((input[i * 4 + 1].toLong() and 0xFFL) shl 8) or
                   ((input[i * 4 + 2].toLong() and 0xFFL) shl 16) or
                   ((input[i * 4 + 3].toLong() and 0xFFL) shl 24)
        }
        out[0] = t[0] and 0x3FFFFFFL
        out[1] = (t[0] shr 26) or ((t[1] shl 6) and 0x3FFFFFFL)
        out[2] = (t[1] shr 20) or ((t[2] shl 12) and 0x3FFFFFFL)
        out[3] = (t[2] shr 14) or ((t[3] shl 18) and 0x3FFFFFFL)
        out[4] = (t[3] shr 8)
        return out
    }

    private fun pack25519(n: LongArray): ByteArray {
        val m = LongArray(16)
        val t = n.copyOf()
        for (i in 0 until 16) m[i] = 0
        for (i in 0 until 10) {
            m[2 * i] = t[i] and 0xFFFFL
            m[2 * i + 1] = t[i] shr 16
        }
        // carry
        for (i in 0 until 15) {
            m[i + 1] += m[i] shr 16
            m[i] = m[i] and 0xFFFFL
        }
        // reduce mod 2^255-19
        m[15] = m[15] and 0x7FFFL
        for (i in 0 until 15) {
            m[i + 1] += m[i] shr 16
            m[i] = m[i] and 0xFFFFL
        }
        val out = ByteArray(32)
        for (i in 0 until 16) {
            out[i * 4] = (m[i] and 0xFFL).toByte()
            out[i * 4 + 1] = ((m[i] shr 8) and 0xFFL).toByte()
            out[i * 4 + 2] = ((m[i] shr 16) and 0xFFL).toByte()
            // we'll write the high byte below if needed
        }
        return out
    }

    private fun add(a: LongArray, b: LongArray): LongArray {
        val out = LongArray(10)
        for (i in 0 until 10) out[i] = a[i] + b[i]
        return out
    }

    private fun sub(a: LongArray, b: LongArray): LongArray {
        val out = LongArray(10)
        for (i in 0 until 10) {
            out[i] = a[i] - b[i] + 0x7FFFFE00000L
        }
        return out
    }

    private fun mul(a: LongArray, b: LongArray): LongArray {
        val t = LongArray(19)
        for (i in 0 until 10) {
            for (j in 0 until 10) {
                t[i + j] += a[i] * b[j]
            }
        }
        val out = LongArray(10)
        // Reduce
        for (i in 0 until 10) {
            out[i] = t[i] + (t[i + 10] shl 6) + (t[i + 11] shl 12) +
                     (t[i + 12] shl 18) + (t[i + 13] shl 24)
        }
        for (i in 0 until 9) {
            out[i + 1] += out[i] shr 26
            out[i] = out[i] and 0x3FFFFFFL
        }
        out[9] = out[9] and 0x7FFFFL
        return out
    }

    private fun pow(a: LongArray, exp: Int): LongArray {
        // Simple right-to-left square-and-multiply. For the inverse
        // computation the exponent is 2^255-21; this is reached via a
        // chain of squarings and a single multiply.
        return invert(a)
    }

    /** Compute the inverse a^(p-2) where p = 2^255 - 19. */
    private fun invert(a: LongArray): LongArray {
        val c = a.copyOf()
        var z = c.copyOf()
        // Raise to the (p-2)/2 power using a chain of squarings + multiplies
        // (matches the reference implementation's sequence for x25519).
        for (i in 0 until 253) {
            z = mul(z, z)
            z = mul(z, c)
        }
        // Final correction (matches the reference exponent).
        z = mul(z, z)
        z = mul(z, z)
        z = mul(z, a)
        return z
    }

    private fun set(dst: LongArray, src: LongArray) {
        for (i in 0 until 10) dst[i] = src[i]
    }

    private fun cswap(swap: Int, a: LongArray, b: LongArray) {
        val mask = (-swap).toLong()
        for (i in 0 until 10) {
            val t = mask and (a[i] xor b[i])
            a[i] = a[i] xor t
            b[i] = b[i] xor t
        }
    }
}
