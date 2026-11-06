package app.protoclean.proton

import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Guest-mode (credentialless) Proton API client — the Android mirror of
 * the desktop `proto_clean/proton/guest.py`.
 *
 * Implements the "Continue as guest" flow used by the official ProtonVPN
 * Android app to obtain a free-tier (Tier=0) VPN session without any
 * account credentials. The flow (shapes transcribed from the official
 * open-source clients: protoncore-android AuthenticationApi.kt +
 * ChallengeFrame.kt, ProtonVPN/android-app ProtonVPNRetrofit.kt +
 * CertificateRequestBody.kt + Constants.kt):
 *
 *   1. `POST /auth/v4/sessions` with the anti-abuse `Payload`
 *      (`vpn-android-v4-challenge-0` device frame) -> anonymous
 *      AccessToken + RefreshToken + UID.
 *   2. `POST /auth/v4/credentialless` (bearer-authenticated with the
 *      anonymous token, same Payload) -> full guest session with
 *      `Scopes` (array) including `vpn`; tier is always 0.
 *   3. Standard VPN endpoints (`/vpn/v2`, `/vpn/v2/logicals`,
 *      `/vpn/v1/certificate`) are then reachable with the guest bearer
 *      token — the logicals endpoint is used to fetch the free-only
 *      server list, and the certificate endpoint is used to obtain the
 *      WireGuard session certificate.
 *   4. The WireGuard tunnel uses FIXED addresses (10.2.0.2/32 client,
 *      10.2.0.1 gateway/DNS, per Constants.kt) — they are NOT in the
 *      certificate response; the cert authenticates the session with
 *      Proton's local agent (10.2.0.1:65432) once the tunnel is up.
 */
object GuestApi {

    const val API_BASE = "https://api.protonmail.ch"
    const val WG_DEFAULT_PORT = 51820

    /** Challenge frame constants (protoncore-android ChallengeUtils.kt). */
    const val CHALLENGE_VERSION = "2.0.7"
    const val CHALLENGE_FRAME_KEY = "vpn-android-v4-challenge-0"

    /** WireGuard tunnel constants (ProtonVPN/android-app Constants.kt):
     *  every Proton WG client uses these fixed addresses; the gateway
     *  doubles as the tunnel DNS resolver and local-agent host. */
    const val VPN_CLIENT_IP = "10.2.0.2"
    const val VPN_CLIENT_IP_V6 = "2a07:b944::2:2"
    const val VPN_GATEWAY_IP = "10.2.0.1"
    const val VPN_GATEWAY_IP_V6 = "2a07:b944::2:1"
    const val LOCAL_AGENT_PORT = 65432

    val GUEST_HEADERS: Map<String, String> = mapOf(
        "User-Agent" to "ProtonVPN/5.15.95.5 (Android 14; samsung SM-S901U)",
        "x-pm-appversion" to "android-vpn@5.15.95.5+play",
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

    /** Build the device-integrity challenge frame. Shape transcribed
     *  from protoncore-android `ChallengeFrame.Device` (the exact
     *  @SerialName keys — v, appLang, timezone, deviceName, ...); the
     *  server records but does not attest these for guest sessions. */
    fun makeChallengeFrame(): JSONObject = JSONObject().apply {
        put("v", CHALLENGE_VERSION)
        put("appLang", "en")
        put("timezone", "Europe/Zurich")
        put("deviceName", 3605)          // stable numeric model id
        put("regionCode", "CH")
        put("timezoneOffset", 60)
        put("isJailbreak", false)
        put("preferredContentSize", "1.0")
        put("storageCapacity", 128.0)
        put("isDarkmodeOn", false)
        put("keyboards", JSONArray().put("com.google.android.inputmethod.latin"))
    }

    /** Build the request body for the auth endpoints (both
     *  `POST /auth/v4/sessions` and `POST /auth/v4/credentialless`):
     *  `{"Payload": {"vpn-android-v4-challenge-0": <device frame>}}`. */
    fun makeChallengePayload(): JSONObject = JSONObject().put(
        "Payload", JSONObject().put(CHALLENGE_FRAME_KEY, makeChallengeFrame()))

    /** Generates a fresh local Ed25519 device/certificate keypair.
     *  Returns (base64_pub, base64_seed). The PUBLIC half (as a PKIX PEM,
     *  see [ed25519PubPem]) is what the official clients send to
     *  `POST /vpn/v1/certificate` as `ClientPublicKey`; the WireGuard
     *  private key is DERIVED from the same keypair
     *  ([ed25519ToX25519PrivB64]) — the two must always pair up. */
    fun genDeviceKeypair(): Pair<String, String> {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val pub = Ed25519.publicKeyFromSeed(seed)
        return base64(pub) to base64(seed)
    }

    /** The Ed25519 public key of a 32-byte seed, as a PKIX
     *  (SubjectPublicKeyInfo) PEM — the exact `ClientPublicKey` form
     *  the official clients send to `POST /vpn/v1/certificate`
     *  (gopenpgp `publicKeyPKIXPem()` / Linux `KeyHandler.ed25519_pk_pem`).
     *  A raw base64 X25519 key is rejected there with Code 2001
     *  "unable to read the key, please provide valid EC key". */
    fun ed25519PubPem(seed: ByteArray): String {
        val pub = Ed25519.publicKeyFromSeed(seed)
        // DER SubjectPublicKeyInfo for Ed25519:
        // 302a300506032b6570032100 || 32-byte key
        val der = ByteArray(12 + 32)
        val prefix = intArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        for (i in prefix.indices) der[i] = prefix[i].toByte()
        System.arraycopy(pub, 0, der, 12, 32)
        val b64 = base64(der)
        return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n"
    }

    /** Derive the WireGuard X25519 private key from an Ed25519 seed —
     *  the same conversion as PyNaCl's
     *  `crypto_sign_ed25519_sk_to_curve25519` and gopenpgp's
     *  `KeyPair.toX25519Base64()` (SHA-512 of the seed, first 32 bytes,
     *  RFC 7748-clamped). Matches the Montgomery form of the public
     *  point sent in the certificate request. */
    fun ed25519ToX25519PrivB64(seed: ByteArray): String {
        val h = MessageDigest.getInstance("SHA-512").digest(seed).copyOfRange(0, 32)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = ((h[31].toInt() and 127) or 64).toByte()
        return base64(h)
    }

    /** Generate a fresh standalone X25519 (Curve25519) keypair.
     *  NOTE: the guest certificate flow no longer uses this — the
     *  official clients derive the WireGuard keypair from the session's
     *  Ed25519 device key ([ed25519ToX25519PrivB64]) so the
     *  `ClientPublicKey` PEM and the WG private key always pair up.
     *  Kept for ad-hoc key generation. Uses the self-contained
     *  TweetNaCl-derived Curve25519 scalar-base multiplication. */
    fun genX25519Keypair(): Pair<String, String> {
        val rand = SecureRandom()
        val privRaw = ByteArray(32).also { rand.nextBytes(it) }
        // Apply the Curve25519 clamping:
        privRaw[0] = (privRaw[0].toInt() and 248).toByte()
        privRaw[31] = ((privRaw[31].toInt() and 127) or 64).toByte()
        val pubRaw = X25519.scalarMultBase(privRaw)
        return base64(pubRaw) to base64(privRaw)
    }

    /** Encode raw bytes as base64 without line wrapping (the form
     *  Proton expects). java.util.Base64 is used (not android.util) so
     *  the JVM unit tests can exercise the same code path. */
    fun base64(bytes: ByteArray): String =
        Base64.getEncoder().encodeToString(bytes)

    /** Decode an unwrapped base64 string to raw bytes. */
    fun decodeB64(s: String): ByteArray =
        Base64.getDecoder().decode(s)
}

/** Normalise `Scopes` (official: a JSON array) or the legacy `Scope`
 *  string to a single space-joined string. */
private fun scopesToOptString(
    resp: JSONObject, fallback: String,
): String {
    val arr = resp.optJSONArray("Scopes")
    if (arr != null) {
        return (0 until arr.length()).joinToString(" ") { arr.optString(it) }
    }
    return resp.optString("Scope", fallback)
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
            // The official LoginResponse has no ExpiresIn field — default
            // conservatively so the caller refreshes early rather than late.
            val expiresIn = if (credless.optLong("ExpiresIn", 0) > 0)
                credless.optLong("ExpiresIn") else 3600L
            val refreshExpiresIn = if (credless.optLong("RefreshExpiresIn", 0) > 0)
                credless.optLong("RefreshExpiresIn") else 2592000L
            return GuestSession(
                accessToken = credless.optString("AccessToken",
                    anon.optString("AccessToken")),
                refreshToken = credless.optString("RefreshToken",
                    anon.optString("RefreshToken")),
                uid = credless.optString("UID", anon.optString("UID")),
                expiresAt = now + expiresIn,
                refreshExpiresAt = now + refreshExpiresIn,
                scope = scopesToOptString(credless, ""),
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
            tier = tier, features = features,
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
    val serverStatus: JSONObject = JSONObject(),
    val refreshTime: Long = 0,
    val expirationTime: Long = 0,
    // Tunnel addresses are the FIXED constants from Constants.kt — they
    // are NOT part of the API response (every Proton WG client uses them).
    val ipv4: String = GuestApi.VPN_CLIENT_IP,
    val ipv6: String? = GuestApi.VPN_CLIENT_IP_V6,
    val dnsIps: List<String> = listOf(
        GuestApi.VPN_GATEWAY_IP, GuestApi.VPN_GATEWAY_IP_V6),
    val clientPublicKeyPem: String = "",
    // X25519 form of the session's Ed25519 device key — pairs with the
    // public key sent in the request; the WireGuard PrivateKey.
    val wgPrivateKeyB64: String = "",
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

    suspend fun createAnonSession(devicePubB64: String = ""): JSONObject =
        withContext(Dispatchers.IO) {
            // devicePubB64 is accepted for call-site compatibility but NOT
            // sent: the official unauth-session body carries device
            // metadata only (no keys).
            post("${GuestApi.API_BASE}/auth/v4/sessions",
                 GuestApi.makeChallengePayload(),
                 GuestApi.defaultHeaders(initialUid),
                 context = "POST /auth/v4/sessions")
        }

    suspend fun credentiallessUpgrade(
        anon: JSONObject, devicePubB64: String = "",
    ): JSONObject = withContext(Dispatchers.IO) {
        val uid = anon.optString("UID")
        val anonToken = anon.optString("AccessToken")
        val headers = GuestApi.defaultHeaders(uid).toMutableMap()
        if (anonToken.isNotBlank()) headers["Authorization"] = "Bearer $anonToken"
        post("${GuestApi.API_BASE}/auth/v4/credentialless",
             GuestApi.makeChallengePayload(), headers,
             context = "POST /auth/v4/credentialless")
    }

    /** Refresh the access token using the refresh token. Returns a
     *  JSONObject with `access_token`, `refresh_token`, `expires_at`,
     *  `scope`, `uid`. Does NOT mutate the passed-in session. */
    suspend fun refresh(session: GuestSession): JSONObject =
        withContext(Dispatchers.IO) {
            // Body per protoncore-android RefreshSessionRequest — the
            // grant fields are required, not decorative.
            val body = JSONObject()
                .put("UID", session.uid)
                .put("RefreshToken", session.refreshToken)
                .put("ResponseType", "token")
                .put("GrantType", "refresh_token")
                .put("RedirectURI", "http://protonmail.ch")
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
                .put("scope", scopesToOptString(resp, session.scope))
                .put("uid", resp.optString("UID", session.uid))
        }

    /** `GET /vpn/v2` — user VPN status. Returns the Response payload
     *  with `MaxTier`, `MaxConnect`, etc. For guest: `MaxTier=0`. */
    suspend fun fetchVpnStatus(session: GuestSession): JSONObject =
        withContext(Dispatchers.IO) {
            get("${GuestApi.API_BASE}/vpn/v2", authHeaders(session),
                context = "GET /vpn/v2")
        }

    /** `GET /vpn/v1/logicals?SecureCoreFilter=all&WithState=true` — the
     *  primary free-tier server list WITH live loads inline (the exact
     *  URL of the official Linux client's v1 flow). */
    suspend fun fetchLogicalsV1(session: GuestSession): JSONArray =
        withContext(Dispatchers.IO) {
            val url = "${GuestApi.API_BASE}/vpn/v1/logicals" +
                "?SecureCoreFilter=all&WithState=true"
            val resp = get(url, authHeaders(session),
                           context = "GET /vpn/v1/logicals")
            resp.optJSONArray("LogicalServers") ?: JSONArray()
        }

    /** `GET /vpn/v1/loads` — live per-logical loads, the endpoint the
     *  official clients poll every ~15 minutes. Returns {id: load}. */
    suspend fun fetchLoads(session: GuestSession): Map<String, Float> =
        withContext(Dispatchers.IO) {
            val resp = get("${GuestApi.API_BASE}/vpn/v1/loads",
                           authHeaders(session), context = "GET /vpn/v1/loads")
            val arr = resp.optJSONArray("LogicalServers") ?: JSONArray()
            val out = mutableMapOf<String, Float>()
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                out[e.optString("ID")] = e.optDouble("Load", 0.0).toFloat()
            }
            out
        }

    /** Free-tier (Tier=0) logical servers **with live loads**.
     *
     * Primary: `/vpn/v1/logicals?SecureCoreFilter=all&WithState=true`
     * (real per-logical Load values inline). Fallback: `/vpn/v2/logicals`
     * with `WithEntriesForProtocols=wireguard` — the v2 payload reports
     * loads as ZERO (official clients compute them from the binary
     * status blob), so after a v2 fetch the live loads are merged in
     * from `/vpn/v1/loads` when reachable; without it every load
     * would read 0%. */
    suspend fun fetchLogicals(session: GuestSession): List<GuestLogicalServer> =
        withContext(Dispatchers.IO) {
            val raw: JSONArray = try {
                fetchLogicalsV1(session)
            } catch (e: Exception) {
                JSONArray()
            }.let { if (it.length() > 0) it else JSONArray() }

            val fromV2 = raw.length() == 0
            val arr = if (!fromV2) raw else {
                val url = "${GuestApi.API_BASE}/vpn/v2/logicals" +
                    "?WithEntriesForProtocols=wireguard&WithState=true"
                val resp = get(url, authHeaders(session),
                               context = "GET /vpn/v2/logicals")
                resp.optJSONArray("LogicalServers") ?: JSONArray()
            }

            val out = mutableListOf<GuestLogicalServer>()
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                parseLogical(e)?.let { out += it }
            }

            if (fromV2) {
                // v2 payloads report zero loads — merge the live values
                // from /vpn/v1/loads when available (best-effort).
                runCatching { fetchLoads(session) }.getOrNull()?.let { loads ->
                    for (i in out.indices) {
                        loads[out[i].serverId]?.let { live ->
                            out[i] = out[i].copy(load = live)
                        }
                    }
                }
            }
            out
        }

    /** Parse one raw logical-server JSON entry (v1 or v2 shape);
     *  null for non-free tiers. `Status` is read from the logical level
     *  first (v1: int, v2: int-or-bool), then from the first physical. */
    private fun parseLogical(e: JSONObject): GuestLogicalServer? {
        val tier = e.optInt("Tier", 0)
        if (tier != 0) return null        // free-only filter
        val servers = e.optJSONArray("Servers")
        val first = servers?.optJSONObject(0) ?: JSONObject()
        fun statusOf(o: JSONObject): Int = when (val v = o.opt("Status")) {
            is Boolean -> if (v) 1 else 0
            is Int -> if (v == 1) 1 else 0
            is Long -> if (v == 1L) 1 else 0
            else -> 0
        }
        return GuestLogicalServer(
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
            status = if (e.has("Status")) statusOf(e) else statusOf(first),
        )
    }

    /** `POST /vpn/v1/certificate` — returns the WireGuard session cert.
     *
     * Body/response per ProtonVPN/android-app CertificateRequestBody /
     * CertificateResponse: `{ClientPublicKey, ClientPublicKeyMode: "EC",
     * DeviceName, Mode: "session", Features: []}` -> `{Certificate,
     * ExpirationTime, RefreshTime}` (no tunnel addresses in the
     * response — they are fixed constants).
     *
     * **Key flow (the official one):** `ClientPublicKey` is the
     * session's Ed25519 device public key as a PKIX PEM
     * (gopenpgp `publicKeyPKIXPem()` / Linux `ed25519_pk_pem`); the
     * WireGuard private key is *derived from the same keypair*
     * (X25519 form of the seed) and returned as
     * `GuestCertificate.wgPrivateKeyB64`. A raw X25519 key is rejected
     * with Code 2001 "unable to read the key, please provide valid EC
     * key". */
    suspend fun fetchCertificate(
        session: GuestSession,
        persistent: Boolean = true,
    ): GuestCertificate = withContext(Dispatchers.IO) {
        val seed = GuestApi.decodeB64(session.deviceEd25519PrivB64)
        val pubPem = GuestApi.ed25519PubPem(seed)
        val body = JSONObject()
            .put("ClientPublicKey", pubPem)
            .put("ClientPublicKeyMode", "EC")
            .put("DeviceName", "SM-S901U")
            .put("Mode", "session")
            .put("Features", JSONArray())
        val resp = post("${GuestApi.API_BASE}/vpn/v1/certificate",
                        body, authHeaders(session),
                        context = "POST /vpn/v1/certificate")
        GuestCertificate(
            certificatePem = resp.optString("Certificate"),
            serverStatus = resp.optJSONObject("ServerStatus") ?: JSONObject(),
            refreshTime = resp.optLong("RefreshTime", 0),
            expirationTime = resp.optLong("ExpirationTime", 0),
            ipv4 = GuestApi.VPN_CLIENT_IP,
            ipv6 = GuestApi.VPN_CLIENT_IP_V6,
            dnsIps = listOf(GuestApi.VPN_GATEWAY_IP, GuestApi.VPN_GATEWAY_IP_V6),
            clientPublicKeyPem = pubPem,
            wgPrivateKeyB64 = GuestApi.ed25519ToX25519PrivB64(seed),
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
    val dns = if (dnsServer != null) listOf(dnsServer) else cert.dnsIps
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
        // Match the official clients: keepalive so the handshake fires
        // even with no user traffic (avoids stuck-in-CONNECTING).
        append("PersistentKeepalive = 60\n")
    }
}
