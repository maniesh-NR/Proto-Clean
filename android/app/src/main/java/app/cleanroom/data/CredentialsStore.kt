package app.cleanroom.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Proton credentials + optional TOTP secret, stored with
 * EncryptedSharedPreferences (the Android analogue of the desktop keyring).
 *
 * The TOTP secret lets the app answer Proton's two-factor prompt during the
 * WebView login automatically (RFC 6238, same implementation as desktop).
 */
class CredentialsStore(context: Context) {

    private val prefs: SharedPreferences = runCatching {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "cleanroom_credentials",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }.getOrNull() ?: context.getSharedPreferences("cleanroom_credentials_fallback", Context.MODE_PRIVATE)

    fun save(username: String, password: String, totpSecret: String = "") {
        prefs.edit()
            .putString("username", username)
            .putString("password", password)
            .putString("totp", totpSecret)
            .apply()
    }

    fun username(): String = prefs.getString("username", "") ?: ""
    fun password(): String = prefs.getString("password", "") ?: ""
    fun totpSecret(): String = prefs.getString("totp", "") ?: ""
    fun hasCredentials(): Boolean = username().isNotBlank() && password().isNotBlank()

    fun saveSessionCookies(cookies: String) {
        prefs.edit().putString("session_cookies", cookies).apply()
    }

    fun sessionCookies(): String = prefs.getString("session_cookies", "") ?: ""

    fun clear() {
        prefs.edit().clear().apply()
    }

    // ---------------------------------------------------------------- TOTP
    /** RFC 6238 TOTP (SHA-1, 6 digits, 30s step) — identical to the desktop. */
    fun currentTotp(): String? {
        val secret = totpSecret()
        if (secret.isBlank()) return null
        return runCatching { Totp.code(secret, System.currentTimeMillis() / 1000L) }
            .getOrNull()
    }
}

object Totp {

    private val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private fun base32Decode(secret: String): ByteArray {
        val s = secret.trim().replace(" ", "").uppercase().trimEnd('=')
        var bits = 0
        var value = 0
        val out = ArrayList<Byte>()
        for (c in s) {
            val idx = B32.indexOf(c)
            if (idx < 0) continue
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((value shr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    fun code(secret: String, counterSec: Long, step: Long = 30, digits: Int = 6): String {
        // accept both a bare base32 secret and a full otpauth:// URI
        val bare = if (secret.startsWith("otpauth://", true)) {
            secret.substringAfter("secret=", "").substringBefore("&").substringBefore(" ")
        } else secret
        val key = base32Decode(bare)
        val counter = counterSec / step
        val msg = byteArrayOf(
            (counter ushr 56).toByte(), (counter ushr 48).toByte(),
            (counter ushr 40).toByte(), (counter ushr 32).toByte(),
            (counter ushr 24).toByte(), (counter ushr 16).toByte(),
            (counter ushr 8).toByte(), counter.toByte(),
        )
        val mac = javax.crypto.Mac.getInstance("HmacSHA1")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(msg)
        val offset = hash.last().toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return String.format("%0${digits}d", binary % mod)
    }
}
