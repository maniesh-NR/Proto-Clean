package app.protoclean.proton

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * RFC 7748 test vectors for the [X25519] port (the guest-mode
 * WireGuard keypair derivation). The same vectors are checked against
 * the Python mirror in `scripts/tnacl_mirror.py`.
 */
class X25519Test {

    private fun h(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    // ------------------------------------------------------------------
    // RFC 7748 section 5.2 — scalar-mult vectors
    // ------------------------------------------------------------------

    @Test fun rfc7748Vector1() {
        val got = X25519.scalarMult(
            h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        )
        assertArrayEquals(
            h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            got,
        )
    }

    @Test fun rfc7748Vector2() {
        val got = X25519.scalarMult(
            h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        )
        assertArrayEquals(
            h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
            got,
        )
    }

    // ------------------------------------------------------------------
    // RFC 7748 section 6.1 — Diffie-Hellman key agreement
    // ------------------------------------------------------------------

    @Test fun rfc7748DhVector() {
        val alicePriv = h(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPriv = h(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val alicePub = X25519.scalarMultBase(alicePriv)
        val bobPub = X25519.scalarMultBase(bobPriv)
        assertArrayEquals(
            h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            alicePub,
        )
        assertArrayEquals(
            h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            bobPub,
        )
        val shared1 = X25519.scalarMult(alicePriv, bobPub)
        val shared2 = X25519.scalarMult(bobPriv, alicePub)
        assertArrayEquals(
            h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
            shared1,
        )
        assertArrayEquals(shared1, shared2)
    }

    // ------------------------------------------------------------------
    // Round-trip / property checks used by the guest flow
    // ------------------------------------------------------------------

    @Test fun keypairAgreesWithFreshPeer() {
        // GuestApi.genX25519Keypair() derives the public key with
        // scalarMultBase; check that two such keypairs agree on a
        // shared secret (i.e. the base-point mult is a real X25519).
        val a = GuestApi.genX25519Keypair()
        val b = GuestApi.genX25519Keypair()
        val s1 = X25519.scalarMult(GuestApi.decodeB64(a.second), GuestApi.decodeB64(b.first))
        val s2 = X25519.scalarMult(GuestApi.decodeB64(b.second), GuestApi.decodeB64(a.first))
        assertArrayEquals(s1, s2)
        assertNotEquals(a.first, b.first)
    }

    @Test fun scalarMultClampsTheScalar() {
        // The scalar is clamped internally (bits 0-2 and 255 cleared,
        // bit 254 set), so tweaking those bits must not change the
        // result — RFC 7748 mandates this.
        val priv = ByteArray(32) { (it * 7 + 3).toByte() }
        val peer = X25519.scalarMultBase(ByteArray(32) { (it * 5 + 1).toByte() })
        val out1 = X25519.scalarMult(priv, peer)
        val tweaked = priv.copyOf()
        tweaked[0] = (tweaked[0].toInt() or 0x07).toByte()
        tweaked[31] = ((tweaked[31].toInt() or 0x80) and 0xFF).toByte()
        val out2 = X25519.scalarMult(tweaked, peer)
        assertArrayEquals(out1, out2)
    }

    @Test fun rejectsBadInputSizes() {
        try {
            X25519.scalarMult(ByteArray(31), ByteArray(32))
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
        try {
            X25519.scalarMult(ByteArray(32), ByteArray(31))
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test fun deterministicForFixedSeed() {
        // Fixed private key -> fixed public key (no hidden randomness).
        val priv = ByteArray(32) { (it + 1).toByte() }
        assertEquals(
            GuestApi.base64(X25519.scalarMultBase(priv)),
            GuestApi.base64(X25519.scalarMultBase(priv.copyOf())),
        )
        assertTrue(X25519.scalarMultBase(priv).size == 32)
    }
}
