package app.protoclean.proton

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Guest-mode (credentialless) Proton API client — the Android mirror of
 * the desktop `proto_clean/proton/guest.py`.
 *
 * Implements the "Continue as guest" flow used by the official ProtonVPN
 * Android app to obtain a free-tier (Tier=0) VPN session without any
 * account credentials. The flow is:
 *
 *   1. `POST /auth/v4/sessions` with a `challengePayload` -> anonymous
 *      AccessToken + RefreshToken + UID.
 *   2. `POST /auth/v4/credentialless` (bearer-authenticated with the
 *      anonymous token, same challengePayload) -> full guest session
 *      with `Scope` including `self vpn` and `tier=0`.
 *   3. Standard VPN endpoints (`/vpn/v2`, `/vpn/v2/logicals`,
 *      `/vpn/v1/certificate`) are then reachable with the guest bearer
 *      token — the logicals endpoint is used to fetch the free-only
 *      server list, and the certificate endpoint is used to obtain the
 *      WireGuard cert + internal tunnel IP for each connection.
 *
 * The challenge payload is permissively validated by Proton's
 * credentialless endpoint — the ED25519 pubkey in `DevicePublicKeys`
 * is recorded but NOT verified, so a randomly-generated 32-byte
 * "pubkey" is acceptable there (documented in `genDeviceKeypair`).
 */
object GuestApi {

    const val API_BASE = "https://api.protonmail.ch"
    const val WG_DEFAULT_PORT = 51820

    val GUEST_HEADERS: Map<String, String> = mapOf(
        "User-Agent" to "ProtonVPN/5.15.95.5 (Android 14; samsung SM-S901U)",
        "x-pm-appversion" to "android-vpn@5.15.95.5-dev+play",
        "x-pm-apiversion" to "4",
        "Accept" to "application/vnd.protonmail.v1+json",
        "Content-Type" to "application/json",
    )

    /** Headers for an unauthenticated / guest API request. `uid` is a
     *  fresh random UUID for the very first POST /sessions (the server
     *  hasn't assigned one yet); once the anonymous session is established
     *  the UID returned in step 1 is reused for every subsequent request. */
    fun defaultHeaders(uid: String = "guest"): Map<String, String> =
        GUEST_HEADERS + ("x-pm-uid" to (uid.ifBlank { "guest" }))

    /** Build the device-integrity challengePayload. The official Android
     *  app's exact payload includes Play-Integrity attestations that
     *  Proton does not currently enforce for credentialless — the shape
     *  below matches what community re-implementations have verified
     *  against the production API. */
    fun makeChallengePayload(devicePubB64: String): JSONObject = JSONObject().apply {
        put("DeviceName", "SM-S901U")
        put("DeviceType", "2")           // 2 = Android
        put("DeviceModulation", " android-")
        put("DevicePublicKeys", JSONObject().put("ED25519", devicePubB64))
        put("OS", "Android")
        put("OSVersion", "14")
        put("SerialNumber", UUID.randomUUID().toString())
        put("Platform", "PlayStore")
    }

    /** Generates a fresh "device keypair" for the credentialless
     *  challengePayload. The credentialless endpoint does NOT verify
     *  this key (it just records the metadata), so we generate 32
     *  random bytes for both pub and priv — Proton's server never
     *  validates them. Returns (base64_pub, base64_priv). */
    fun genDeviceKeypair(): Pair<String, String> {
        val rand = SecureRandom()
        val priv = ByteArray(32).also { rand.nextBytes(it) }
        val pub = ByteArray(32).also { rand.nextBytes(it) }
        return base64(pub) to base64(priv)
    }

    /** Generate a fresh X25519 (Curve25519) keypair for WireGuard.
     *  The public key is sent to Proton in `POST /vpn/v1/certificate`
     *  as `ClientPublicKey`; the private key is the WireGuard
     *  `[Interface] PrivateKey`. Uses a self-contained, public-domain
     *  Curve25519 scalar-base multiplication (curve25519-donna style). */
    fun genX25519Keypair(): Pair<String, String> {
        val rand = SecureRandom()
        val privRaw = ByteArray(32).also { rand.nextBytes(it) }
        // Apply the Curve25519 clamping:
        privRaw[0] = (privRaw[0].toInt() and 248).toByte()
        privRaw[31] = ((privRaw[31].toInt() and 127) or 64).toByte()
        val pubRaw = X25519.scalarMultBase(privRaw)
        return base64(pubRaw) to base64(privRaw)
    }

    /** Encode raw bytes as NO_WRAP base64 (the form Proton expects). */
    fun base64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    /** Decode a NO_WRAP base64 string to raw bytes. */
    fun decodeB64(s: String): ByteArray =
        Base64.decode(s, Base64.NO_WRAP)
}

/** Raised when the Proton API returns a non-success Code in its
 *  `{Code, Response, Error}` envelope. */
class GuestAuthError(message: String) : RuntimeException(message)

/** A successful credentialless guest login result. Mirrors the Python
 *  `GuestSession` dataclass field-for-field. */
data class GuestSession(
    val accessToken: String,
    val refreshToken: String,
    val uid: String,
    val expiresAt: Long,                  // epoch seconds
    val refreshExpiresAt: Long,
    val scope: String,
    val deviceEd25519PubB64: String,
    val deviceEd25519PrivB64: String,     // base64 (JSON-safe)
    val maxTier: Int = 0,
    val maxConnect: Int = 1,
    val planName: String = "guest",
) {
    /** Serialise to a JSON-safe object for credential storage. */
    fun toStorageJson(): JSONObject = JSONObject().apply {
        put("access_token", accessToken)
        put("refresh_token", refreshToken)
        put("uid", uid)
        put("expires_at", expiresAt)
        put("refresh_expires_at", refreshExpiresAt)
        put("scope", scope)
        put("device_ed25519_pub_b64", deviceEd25519PubB64)
        put("device_ed25519_priv_b64", deviceEd25519PrivB64)
        put("max_tier", maxTier)
        put("max_connect", maxConnect)
        put("plan_name", planName)
    }

    companion object {
        fun fromStorageJson(o: JSONObject): GuestSession = GuestSession(
            accessToken = o.optString("access_token"),
            refreshToken = o.optString("refresh_token"),
            uid = o.optString("uid"),
            expiresAt = o.optLong("expires_at"),
            refreshExpiresAt = o.optLong("refresh_expires_at"),
            scope = o.optString("scope"),
            deviceEd25519PubB64 = o.optString("device_ed25519_pub_b64"),
            deviceEd25519PrivB64 = o.optString("device_ed25519_priv_b64"),
            maxTier = o.optInt("max_tier", 0),
            maxConnect = o.optInt("max_connect", 1),
            planName = o.optString("plan_name", "guest"),
        )

        fun fromResponses(
            anon: JSONObject, credless: JSONObject,
            devicePubB64: String, devicePrivB64: String,
        ): GuestSession {
            val now = System.currentTimeMillis() / 1000
            return GuestSession(
                accessToken = credless.optString("AccessToken",
                    anon.optString("AccessToken")),
                refreshToken = credless.optString("RefreshToken",
                    anon.optString("RefreshToken")),
                uid = credless.optString("UID", anon.optString("UID")),
                expiresAt = now + credless.optLong("ExpiresIn", 3600),
                refreshExpiresAt = now + credless.optLong("RefreshExpiresIn", 2592000),
                scope = credless.optString("Scope"),
                deviceEd25519PubB64 = devicePubB64,
                deviceEd25519PrivB64 = devicePrivB64,
                maxTier = 0,
                maxConnect = credless.optInt("MaxConnect", 1),
                planName = "guest",
            )
        }
    }
}

/** A single Proton logical server (free-tier view). */
data class GuestLogicalServer(
    val serverId: String,
    val name: String,
    val exitCountry: String,
    val city: String?,
    val tier: Int,
    val features: Int,
    val load: Float,
    val score: Float,
    val domain: String,
    val entryIp: String,
    val x25519PublicKey: String,
    val status: Int,
) {
    /** Convert to the existing LogicalServer model so the rest of the
     *  app (server list UI, selection) doesn't need guest-specific
     *  handling. The first physical server's WG endpoint is used. */
    fun toLogicalServer(): LogicalServer {
        val phys = PhysicalServer(
            id = "$serverId-phys",
            domain = domain,
            entryIp = entryIp,
            exitIp = entryIp,
            status = status,
            x25519Pk = x25519PublicKey,
        )
        return LogicalServer(
            id = serverId, name = name,
            entryCountry = exitCountry, exitCountry = exitCountry,
            domain = domain, tier = tier, features = features,
            city = city ?: "", region = "",
            load = load, score = score, status = status, enabled = true,
            physical = listOf(phys),
        )
    }
}

/** The WireGuard certificate + tunnel IP assignment returned by
 *  `POST /vpn/v1/certificate`. */
data class GuestCertificate(
    val certificatePem: String,
    val serverStatus: JSONObject,
    val refreshTime: Long,
    val ipv4: String,
    val ipv6: String?,
    val dnsIps: List<String>,
    val clientPublicKeyB64: String,
)

/** Async guest-mode Proton API client. The Android mirror of the
 *  Python `GuestAuth` class. */
class GuestAuth(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build(),
    private val initialUid: String = UUID.randomUUID().toString(),
) {

    /** End-to-end guest login: generate a device keypair, call the
     *  anonymous-session endpoint, then the credentialless upgrade. */
    suspend fun login(): GuestSession = withContext(Dispatchers.IO) {
        val (pubB64, privB64) = GuestApi.genDeviceKeypair()
        val anon = createAnonSession(pubB64)
        val credless = credentiallessUpgrade(anon, pubB64)
        GuestSession.fromResponses(anon, credless, pubB64, privB64)
    }

    suspend fun createAnonSession(devicePubB64: String): JSONObject =
        withContext(Dispatchers.IO) {
            val body = JSONObject().put(
                "challengePayload",
                GuestApi.makeChallengePayload(devicePubB64))
            post("${GuestApi.API_BASE}/auth/v4/sessions",
                 body, GuestApi.defaultHeaders(initialUid),
                 context = "POST /auth/v4/sessions")
        }

    suspend fun credentiallessUpgrade(
        anon: JSONObject, devicePubB64: String,
    ): JSONObject = withContext(Dispatchers.IO) {
        val uid = anon.optString("UID")
        val anonToken = anon.optString("AccessToken")
        val headers = GuestApi.defaultHeaders(uid).toMutableMap()
        if (anonToken.isNotBlank()) headers["Authorization"] = "Bearer $anonToken"
        val body = JSONObject().put(
            "challengePayload",
            GuestApi.makeChallengePayload(devicePubB64))
        post("${GuestApi.API_BASE}/auth/v4/credentialless",
             body, headers, context = "POST /auth/v4/credentialless")
    }

    /** Refresh the access token using the refresh token. Returns a
     *  JSONObject with `access_token`, `refresh_token`, `expires_at`,
     *  `scope`, `uid`. Does NOT mutate the passed-in session. */
    suspend fun refresh(session: GuestSession): JSONObject =
        withContext(Dispatchers.IO) {
            val body = JSONObject()
                .put("RefreshToken", session.refreshToken)
                .put("UID", session.uid)
            val resp = post("${GuestApi.API_BASE}/auth/v4/refresh",
                            body, GuestApi.defaultHeaders(session.uid),
                            context = "POST /auth/v4/refresh")
            val now = System.currentTimeMillis() / 1000
            JSONObject()
                .put("access_token", resp.optString("AccessToken"))
                .put("refresh_token", resp.optString("RefreshToken"))
                .put("expires_at", now + resp.optLong("ExpiresIn", 3600))
                .put("refresh_expires_at",
                     now + resp.optLong("RefreshExpiresIn", 2592000))
                .put("scope", resp.optString("Scope", session.scope))
                .put("uid", resp.optString("UID", session.uid))
        }

    /** `GET /vpn/v2` — user VPN status. Returns the Response payload
     *  with `MaxTier`, `MaxConnect`, etc. For guest: `MaxTier=0`. */
    suspend fun fetchVpnStatus(session: GuestSession): JSONObject =
        withContext(Dispatchers.IO) {
            get("${GuestApi.API_BASE}/vpn/v2", authHeaders(session),
                context = "GET /vpn/v2")
        }

    /** `GET /vpn/v2/logicals` — parse to `GuestLogicalServer` objects.
     *  Only Tier=0 (free) servers are returned. */
    suspend fun fetchLogicals(session: GuestSession): List<GuestLogicalServer> =
        withContext(Dispatchers.IO) {
            val url = "${GuestApi.API_BASE}/vpn/v2/logicals" +
                "?WithEntriesForProtocols=wireguard&WithState=true"
            val resp = get(url, authHeaders(session),
                           context = "GET /vpn/v2/logicals")
            val arr = resp.optJSONArray("LogicalServers") ?: return@withContext emptyList()
            val out = mutableListOf<GuestLogicalServer>()
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                val tier = e.optInt("Tier", 0)
                if (tier != 0) continue       // free-only filter
                val servers = e.optJSONArray("Servers")
                val first = servers?.optJSONObject(0) ?: JSONObject()
                out += GuestLogicalServer(
                    serverId = e.optString("ID"),
                    name = e.optString("Name"),
                    exitCountry = e.optString("ExitCountry"),
                    city = if (e.isNull("City")) null else e.optString("City", null),
                    tier = tier,
                    features = e.optInt("Features", 0),
                    load = e.optDouble("Load", 0.0).toFloat(),
                    score = e.optDouble("Score", 0.0).toFloat(),
                    domain = first.optString("Domain"),
                    entryIp = first.optString("EntryIP"),
                    x25519PublicKey = first.optString("X25519PublicKey"),
                    status = first.optInt("Status", 0),
                )
            }
            out
        }

    /** `POST /vpn/v1/certificate` — returns the WireGuard cert + tunnel IP. */
    suspend fun fetchCertificate(
        session: GuestSession, clientPublicKeyB64: String,
        persistent: Boolean = true,
    ): GuestCertificate = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("ClientPublicKey", clientPublicKeyB64)
            .put("Mode", if (persistent) "persistent" else "ephemeral")
        val resp = post("${GuestApi.API_BASE}/vpn/v1/certificate",
                        body, authHeaders(session),
                        context = "POST /vpn/v1/certificate")
        val dnsBlock = resp.optJSONObject("DNS") ?: JSONObject()
        val dnsIps = mutableListOf<String>()
        val dnsArr = dnsBlock.optJSONArray("IP")
        if (dnsArr != null) {
            for (i in 0 until dnsArr.length()) {
                dnsIps.add(dnsArr.optString(i))
            }
        }
        GuestCertificate(
            certificatePem = resp.optString("Certificate"),
            serverStatus = resp.optJSONObject("ServerStatus") ?: JSONObject(),
            refreshTime = resp.optLong("RefreshTime", 0),
            ipv4 = resp.optString("IPv4"),
            ipv6 = if (resp.isNull("IPv6")) null else resp.optString("IPv6", null),
            dnsIps = dnsIps,
            clientPublicKeyB64 = clientPublicKeyB64,
        )
    }

    // ---------------------------------------------------------------- helpers

    private fun authHeaders(session: GuestSession): Map<String, String> =
        GuestApi.defaultHeaders(session.uid) +
            ("Authorization" to "Bearer ${session.accessToken}")

    private suspend fun post(
        url: String, body: JSONObject, headers: Map<String, String>,
        context: String,
    ): JSONObject {
        val req = Request.Builder().url(url)
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .apply { headers.forEach { (k, v) -> header(k, v) } }
            .build()
        client.newCall(req).execute().use { resp ->
            val text = resp.body?.string() ?: ""
            if (!resp.isSuccessful) {
                throw GuestAuthError("$context: HTTP ${resp.code}: ${text.take(200)}")
            }
            val json = JSONObject(text)
            return unwrap(json, context)
        }
    }

    private suspend fun get(
        url: String, headers: Map<String, String>, context: String,
    ): JSONObject {
        val req = Request.Builder().url(url).get()
            .apply { headers.forEach { (k, v) -> header(k, v) } }
            .build()
        client.newCall(req).execute().use { resp ->
            val text = resp.body?.string() ?: ""
            if (!resp.isSuccessful) {
                throw GuestAuthError("$context: HTTP ${resp.code}: ${text.take(200)}")
            }
            val json = JSONObject(text)
            return unwrap(json, context)
        }
    }

    /** Validate Proton's `{Code, Response, Error}` envelope and return
     *  the Response on success. */
    private fun unwrap(json: JSONObject, context: String): JSONObject {
        val code = json.optInt("Code", 1000)
        if (code == 1000) {
            val resp = json.optJSONObject("Response")
            return resp ?: json
        }
        val resp = json.optJSONObject("Response")
        if (resp != null && resp.length() > 0) return resp
        val err = json.optJSONObject("Error")
        val msg = err?.optString("Message", "") ?: ""
        throw GuestAuthError(
            "Proton API error $code ($context): $msg".trim())
    }
}

/** Build a wg-quick config text from a guest logical server + cert +
 *  X25519 private key. Mirrors `proto_clean/proton/guest.py:build_wg_quick_config`. */
fun buildWgQuickConfig(
    server: GuestLogicalServer,
    cert: GuestCertificate,
    x25519PrivB64: String,
    dnsServer: String? = null,
    ipv6: Boolean = true,
): String {
    val dns = if (dnsServer != null) listOf(dnsServer)
              else cert.dnsIps.ifEmpty { listOf("1.1.1.1") }
    val addresses = mutableListOf<String>()
    if (cert.ipv4.isNotBlank()) addresses += "${cert.ipv4}/32"
    if (ipv6 && !cert.ipv6.isNullOrBlank()) addresses += "${cert.ipv6}/128"
    val allowedIps = if (ipv6) listOf("0.0.0.0/0", "::/0")
                     else listOf("0.0.0.0/0")
    val endpoint = "${server.entryIp}:${GuestApi.WG_DEFAULT_PORT}"
    return buildString {
        append("[Interface]\n")
        append("PrivateKey = $x25519PrivB64\n")
        if (addresses.isNotEmpty()) {
            append("Address = ${addresses.joinToString(", ")}\n")
        }
        if (dns.isNotEmpty()) {
            append("DNS = ${dns.joinToString(", ")}\n")
        }
        append("\n[Peer]\n")
        append("PublicKey = ${server.x25519PublicKey}\n")
        append("AllowedIPs = ${allowedIps.joinToString(", ")}\n")
        append("Endpoint = $endpoint\n")
    }
}
