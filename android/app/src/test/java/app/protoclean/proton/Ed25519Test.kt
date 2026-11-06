package app.protoclean.proton

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * JVM tests for the [Ed25519] TweetNaCl port used by the guest-mode
 * certificate flow.
 *
 * The fixed vectors were generated with Python `cryptography`
 * (`Ed25519PrivateKey.from_private_bytes(seed).public_key()` for the
 * public half; clamped `SHA-512(seed)[:32]` for the X25519 form — the
 * same conversion as PyNaCl's `crypto_sign_ed25519_sk_to_curve25519`).
 */
class Ed25519Test {

    private fun dec(s: String): ByteArray = Base64.getDecoder().decode(s)

    private val vectors = arrayOf(
        Triple(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
            "OJTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8=",
        ),
        Triple(
            "f1omgZ8t2L4wow540sfPUrEtAL/eCFq57r1UomhzWjQ=",
            "OoYjv9jaJwaMvyn71H+JmN4G8Xzq0TuOQwz7msv3Hdk=",
            "4Jpw5UqxKbojYK7v8lz5UKwGXxt/ozKSG2CWphi3hVo=",
        ),
        Triple(
            "IdIo9q5qtMLMtlMZTDVhYPKRJoq8wWwwpi56S0VbJjo=",
            "yqDrZ+1mfuVTB15SMuyIa19x2Dmf/XUQlwWz+OEaNlw=",
            "GN7Z8irA2MzAZr9D7ZvLsXSj1O08vkLJeqBYRQ/252g=",
        ),
        Triple(
            "7oRNLWTJQuhhofCk9H9/KmAufz6X3NQCzhzFYIr7xX4=",
            "uFzJG6DwZwajItq/TG6MkpHQ8kD/S2taZVAHieb2DIU=",
            "2B1Gz2I0NXLhiVKSMjQGBjVwnrPWJHKbC03XasWT5VQ=",
        ),
        Triple(
            "pwIPc73LADw+mk8aTO03lehLUQ+WrS4879+m5aGOjLA=",
            "IxESzlEWhc5ooSyMTz0n8o5LCt9FcQEM6+83QuO8WPc=",
            "QK6m1jpAe0J+bKylmy2t13+E5E8TpzU1RpKRLK6wfGA=",
        ),
        Triple(
            "J/pKV/WbZxI9TtgS9L3+fPUzg1nlEjcYwHsfZ4R1w0c=",
            "Vok6FTWqjPSMfcN2v8VG7TdgGYOGZA7cRgyzjgwpuVs=",
            "qB6GDVdvAELCoseasZeXg+kDvx6GolG07W85InBqcl4=",
        ),
    )

    @Test
    fun publicKeyFromSeedMatchesPythonCryptography() {
        for ((i, v) in vectors.withIndex()) {
            val pub = Ed25519.publicKeyFromSeed(dec(v.first))
            assertArrayEquals(
                "vector $i public key mismatch",
                dec(v.second), pub,
            )
        }
    }

    @Test
    fun x25519DerivationMatchesReference() {
        for ((i, v) in vectors.withIndex()) {
            val seed = dec(v.first)
            val h = MessageDigest.getInstance("SHA-512").digest(seed).copyOfRange(0, 32)
            h[0] = (h[0].toInt() and 248).toByte()
            h[31] = ((h[31].toInt() and 127) or 64).toByte()
            assertArrayEquals("vector $i x25519 mismatch", dec(v.third), h)
        }
    }

    @Test
    fun genDeviceKeypairPubIsDerivedFromSeed() {
        // The (previously broken) keypair used to return RANDOM pub bytes
        // that did not pair with the seed — the certificate flow depends
        // on the two matching.
        repeat(4) {
            val (pubB64, privB64) = GuestApi.genDeviceKeypair()
            val pub = GuestApi.decodeB64(pubB64)
            val seed = GuestApi.decodeB64(privB64)
            assertEquals(32, pub.size)
            assertEquals(32, seed.size)
            assertArrayEquals(pub, Ed25519.publicKeyFromSeed(seed))
        }
    }

    @Test
    fun pkixPemMatchesPythonCryptographyForm() {
        // Vector 0's public key as produced by Python
        // cryptography's SubjectPublicKeyInfo PEM.
        val expected = (
            "-----BEGIN PUBLIC KEY-----\n" +
                "MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n" +
                "-----END PUBLIC KEY-----\n"
            )
        assertEquals(expected, GuestApi.ed25519PubPem(dec(vectors[0].first)))
    }

    @Test
    fun x25519OfDeviceSeedPairsWithPublicKeyPem() {
        // The WG private key derived from the seed must match the
        // clamped-SHA512 vector for every seed.
        for ((i, v) in vectors.withIndex()) {
            assertEquals(
                "vector $i wg key mismatch",
                v.third,
                GuestApi.ed25519ToX25519PrivB64(dec(v.first)),
            )
        }
    }

    @Test
    fun randomSeedsProduceConsistentPairs() {
        repeat(4) {
            val (pubB64, privB64) = GuestApi.genDeviceKeypair()
            // The PEM wraps exactly the derived public key.
            val pem = GuestApi.ed25519PubPem(GuestApi.decodeB64(privB64))
            val b64Body = pem.lines()[1]
            val der = GuestApi.decodeB64(b64Body)
            assertEquals(44, der.size) // 12-byte SPKI prefix + 32-byte key
            assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"))
            assertArrayEquals(
                GuestApi.decodeB64(pubB64),
                der.copyOfRange(12, 44),
            )
        }
    }
}
