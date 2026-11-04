package app.protoclean.proton

import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

/**
 * Pure-JVM unit tests for [GuestApi] / [GuestAuth] / [GuestSession] /
 * [buildWgQuickConfig].
 *
 * Mirrors the Python ``tests/test_guest.py`` suite, transposed to the
 * Kotlin API surface. All HTTP is stubbed via a tiny [Interceptor]-
 * based fake ([StubApi]) — no MockWebServer dep needed.
 *
 * Test layout:
 *  1. [defaultHeadersIncludeRequiredFields]
 *  2. [makeChallengePayloadHasAllFields]
 *  3. [genX25519KeypairProducesValid32ByteKeys]
 *  4. [loginCallsBothEndpointsInOrder]
 *  5. [fetchLogicalsParsesServersAndFiltersPaid]
 *  6. [fetchCertificateParsesResponse]
 *  7. [apiErrorCodeRaisesGuestAuthError]
 *  8. [guestSessionStorageRoundTrips]
 *  9. [buildWgQuickConfigProducesExpectedText]
 */
class GuestApiTest {

    // ------------------------------------------------------------------
    // 1. defaultHeaders
    // ------------------------------------------------------------------

    @Test fun defaultHeadersIncludeRequiredFields() {
        val h = GuestApi.defaultHeaders("abc")
        assertEquals("abc", h["x-pm-uid"])
        assertEquals("android-vpn@5.15.95.5-dev+play", h["x-pm-appversion"])
        assertEquals("4", h["x-pm-apiversion"])
        assertEquals("application/vnd.protonmail.v1+json", h["Accept"])
        assertTrue(h["User-Agent"]!!.startsWith("ProtonVPN/"))
        // The constant mirrors these (minus the per-request uid).
        assertEquals(
            "android-vpn@5.15.95.5-dev+play",
            GuestApi.GUEST_HEADERS["x-pm-appversion"],
        )
        // Blank uid falls back to the "guest" sentinel.
        assertEquals("guest", GuestApi.defaultHeaders("")["x-pm-uid"])
        assertEquals("guest", GuestApi.defaultHeaders()["x-pm-uid"])
    }

    // ------------------------------------------------------------------
    // 2. makeChallengePayload shape
    // ------------------------------------------------------------------

    @Test fun makeChallengePayloadHasAllFields() {
        val payload = GuestApi.makeChallengePayload("pubkey")
        // Defaults match the documented guest-mode fingerprint.
        assertEquals("SM-S901U", payload.getString("DeviceName"))
        assertEquals("2", payload.getString("DeviceType"))
        assertEquals(" android-", payload.getString("DeviceModulation"))
        assertEquals("Android", payload.getString("OS"))
        assertEquals("14", payload.getString("OSVersion"))
        assertEquals("PlayStore", payload.getString("Platform"))
        // Nested ED25519 pubkey is preserved.
        val pubKeys = payload.getJSONObject("DevicePublicKeys")
        assertEquals("pubkey", pubKeys.getString("ED25519"))
        // SerialNumber must be a uuid-parseable string.
        UUID.fromString(payload.getString("SerialNumber"))
        // Exactly 8 top-level keys (the Python suite asserts the same set).
        val keys = sequence {
            val iter = payload.keys()
            while (iter.hasNext()) yield(iter.next())
        }.toSet()
        assertEquals(
            setOf(
                "DeviceName", "DeviceType", "DeviceModulation",
                "DevicePublicKeys", "OS", "OSVersion", "SerialNumber", "Platform",
            ),
            keys,
        )
    }

    // ------------------------------------------------------------------
    // 3. X25519 keypair
    // ------------------------------------------------------------------

    @Test fun genX25519KeypairProducesValid32ByteKeys() {
        val (pub, priv) = GuestApi.genX25519Keypair()
        // Both keys are 44-char base64 strings (32 raw bytes + padding).
        assertEquals(44, pub.length)
        assertEquals(44, priv.length)
        // pub and priv are distinct (sanity check).
        assertNotEquals(pub, priv)
        // Decoding yields 32 raw bytes each — real Curve25519 keypair.
        val decoder = java.util.Base64.getDecoder()
        val pubBytes = decoder.decode(pub)
        val privBytes = decoder.decode(priv)
        assertEquals(32, pubBytes.size)
        assertEquals(32, privBytes.size)
        // Two calls produce independent keypairs.
        val (pub2, _) = GuestApi.genX25519Keypair()
        assertNotEquals(pub, pub2)
    }

    // ------------------------------------------------------------------
    // 4. login end-to-end (sessions + credentialless)
    // ------------------------------------------------------------------

    @Test fun loginCallsBothEndpointsInOrder() = runBlocking {
        val api = StubApi()
        api.setEnvelope("POST", "/auth/v4/sessions", JSONObject().apply {
            put("AccessToken", "anon-tok")
            put("RefreshToken", "anon-refresh")
            put("UID", "anon-uid")
            put("ExpiresIn", 3600)
            put("Scope", "self")
        })
        api.setEnvelope("POST", "/auth/v4/credentialless", JSONObject().apply {
            put("AccessToken", "guest-tok")
            put("RefreshToken", "guest-refresh")
            put("UID", "guest-uid")
            put("ExpiresIn", 600)
            put("Scope", "self vpn")
        })
        val auth = GuestAuth(api.client(), "initial-uid-123")

        val sess = auth.login()
        assertEquals("guest-tok", sess.accessToken)
        assertEquals("guest-refresh", sess.refreshToken)
        assertEquals("guest-uid", sess.uid)
        assertEquals("self vpn", sess.scope)
        assertEquals(0, sess.maxTier)
        assertEquals(1, sess.maxConnect)
        assertEquals("guest", sess.planName)
        // The session is bound to a fresh device keypair.
        assertTrue(sess.deviceEd25519PubB64.isNotEmpty())
        assertEquals(32, GuestApi.decodeB64(sess.deviceEd25519PrivB64).size)

        // Two POSTs were made in sequence: /sessions then /credentialless.
        val postPaths = api.requests.filter { it.method == "POST" }.map { it.path }
        assertEquals(
            listOf("/auth/v4/sessions", "/auth/v4/credentialless"),
            postPaths,
        )
        // The same device pubkey was used in both challenge payloads.
        val body1 = api.find("POST", "/auth/v4/sessions").bodyJson!!
        val body2 = api.find("POST", "/auth/v4/credentialless").bodyJson!!
        val pub1 = body1.getJSONObject("challengePayload")
            .getJSONObject("DevicePublicKeys").getString("ED25519")
        val pub2 = body2.getJSONObject("challengePayload")
            .getJSONObject("DevicePublicKeys").getString("ED25519")
        assertEquals(pub1, pub2)
        assertEquals(pub1, sess.deviceEd25519PubB64)
        // The initial uid is used as x-pm-uid on the very first request.
        val headers1 = api.find("POST", "/auth/v4/sessions").headers
        assertEquals("initial-uid-123", headers1["x-pm-uid"])
        // No bearer auth on the very first request.
        assertNull(headers1["authorization"])
        // The credentialless upgrade carries the anonymous bearer token.
        val headers2 = api.find("POST", "/auth/v4/credentialless").headers
        assertEquals("anon-uid", headers2["x-pm-uid"])
        assertEquals("Bearer anon-tok", headers2["authorization"])
    }

    // ------------------------------------------------------------------
    // 5. fetchLogicals filters paid servers
    // ------------------------------------------------------------------

    @Test fun fetchLogicalsParsesServersAndFiltersPaid() = runBlocking {
        val api = StubApi()
        val logicals = JSONArray()
        logicals.put(serverJson("s-free-1", "US-FREE#1", "US", 0))
        // Tier 2 (Plus) — must be filtered out.
        logicals.put(serverJson("s-plus-1", "US-PLUS#1", "US", 2, physical = JSONObject().apply {
            put("Domain", "us-plus-01.protonvpn.com")
            put("EntryIP", "185.159.159.2")
            put("X25519PublicKey", "plusPub==")
            put("Status", 1)
        }))
        logicals.put(
            serverJson(
                "s-free-2", "JP-FREE#1", "JP", 0,
                city = "Tokyo",
                features = 1,   // P2P
                load = 42.0,
                score = 2.0,
                physical = JSONObject().apply {
                    put("Domain", "jp-free-01.protonvpn.com")
                    put("EntryIP", "185.159.158.9")
                    put("X25519PublicKey", "jpPub==")
                    put("Status", 1)
                },
            ),
        )
        api.setEnvelope("GET", "/vpn/v2/logicals", JSONObject().apply {
            put("LogicalServers", logicals)
        })

        val auth = GuestAuth(api.client())
        val sess = testSession()
        val servers = auth.fetchLogicals(sess)

        // Only Tier=0 servers survive the filter.
        assertEquals(2, servers.size)
        val ids = servers.map { it.serverId }.toSet()
        assertEquals(setOf("s-free-1", "s-free-2"), ids)

        // First physical server is parsed correctly.
        val free1 = servers.first { it.serverId == "s-free-1" }
        assertEquals("185.159.158.1", free1.entryIp)
        assertEquals("abcPubKeyBase64==", free1.x25519PublicKey)
        assertEquals("us-free-01.protonvpn.com", free1.domain)
        assertEquals("US", free1.exitCountry)
        assertNull(free1.city)
        assertEquals(0, free1.tier)
        assertEquals(1, free1.status)

        val free2 = servers.first { it.serverId == "s-free-2" }
        assertEquals("Tokyo", free2.city)
        assertEquals("JP", free2.exitCountry)
        assertEquals(1, free2.features)
        assertEquals(42.0f, free2.load)
        assertEquals(2.0f, free2.score)

        // Auth headers used.
        val headers = api.find("GET", "/vpn/v2/logicals").headers
        assertEquals("Bearer guest-tok", headers["authorization"])
        assertEquals("guest-uid", headers["x-pm-uid"])
    }

    // ------------------------------------------------------------------
    // 6. fetchCertificate parses response
    // ------------------------------------------------------------------

    @Test fun fetchCertificateParsesResponse() = runBlocking {
        val api = StubApi()
        val certPem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
        api.setEnvelope("POST", "/vpn/v1/certificate", JSONObject().apply {
            put("Certificate", certPem)
            put("ServerStatus", JSONObject().put("Status", 1))
            put("RefreshTime", 1735689600L)
            put("IPv4", "10.2.0.2")
            put("IPv6", "fd00::2")
            put("DNS", JSONObject().put("IP", JSONArray().apply {
                put("10.64.0.1"); put("10.64.0.2")
            }))
        })
        val auth = GuestAuth(api.client())
        val sess = testSession()
        val cert = auth.fetchCertificate(sess, "wgpub==")
        assertEquals(certPem, cert.certificatePem)
        assertEquals("10.2.0.2", cert.ipv4)
        assertEquals("fd00::2", cert.ipv6)
        assertEquals(listOf("10.64.0.1", "10.64.0.2"), cert.dnsIps)
        assertEquals(1735689600L, cert.refreshTime)
        assertEquals(1, cert.serverStatus.optInt("Status"))
        assertEquals("wgpub==", cert.clientPublicKeyB64)
        // Body had the right shape.
        val body = api.find("POST", "/vpn/v1/certificate").bodyJson!!
        assertEquals("wgpub==", body.getString("ClientPublicKey"))
        assertEquals("persistent", body.getString("Mode"))
        // Bearer auth used.
        val headers = api.find("POST", "/vpn/v1/certificate").headers
        assertEquals("Bearer guest-tok", headers["authorization"])
    }

    // ------------------------------------------------------------------
    // 7. API error code raises GuestAuthError
    // ------------------------------------------------------------------

    @Test fun apiErrorCodeRaisesGuestAuthError() {
        val api = StubApi()
        api.setRaw("POST", "/auth/v4/sessions", JSONObject().apply {
            put("Code", 8002)
            put("Response", JSONObject())
            put("Error", JSONObject().put("Message", "bad challenge"))
        }.toString())
        val auth = GuestAuth(api.client())
        try {
            runBlocking { auth.createAnonSession("devpub") }
            fail("expected GuestAuthError to be raised")
        } catch (e: GuestAuthError) {
            assertTrue(
                "message should contain 'bad challenge': ${e.message}",
                e.message!!.contains("bad challenge"),
            )
            assertTrue(
                "message should contain '8002': ${e.message}",
                e.message!!.contains("8002"),
            )
        }
    }

    // ------------------------------------------------------------------
    // 8. GuestSession storage round-trip
    // ------------------------------------------------------------------

    @Test fun guestSessionStorageRoundTrips() {
        val now = System.currentTimeMillis() / 1000
        val original = GuestSession(
            accessToken = "guest-tok",
            refreshToken = "guest-refresh",
            uid = "guest-uid",
            expiresAt = now + 600,
            refreshExpiresAt = now + 9999,
            scope = "self vpn",
            deviceEd25519PubB64 = "devpub",
            deviceEd25519PrivB64 = GuestApi.base64(ByteArray(32) { it.toByte() }),
            maxTier = 0,
            maxConnect = 1,
            planName = "guest",
        )
        val json = original.toStorageJson()
        val restored = GuestSession.fromStorageJson(json)
        // String fields match (data-class equals on ByteArray uses
        // reference equality, so check fields individually).
        assertEquals(original.accessToken, restored.accessToken)
        assertEquals(original.refreshToken, restored.refreshToken)
        assertEquals(original.uid, restored.uid)
        assertEquals(original.scope, restored.scope)
        assertEquals(original.expiresAt, restored.expiresAt)
        assertEquals(original.refreshExpiresAt, restored.refreshExpiresAt)
        assertEquals(original.deviceEd25519PubB64, restored.deviceEd25519PubB64)
        assertEquals(original.maxTier, restored.maxTier)
        assertEquals(original.maxConnect, restored.maxConnect)
        assertEquals(original.planName, restored.planName)
        // The priv key round-trips through its base64 form (storage
        // keeps it JSON-safe as a String).
        assertEquals(original.deviceEd25519PrivB64, restored.deviceEd25519PrivB64)
        assertTrue(
            restored.deviceEd25519PrivB64.isNotEmpty() &&
                GuestApi.decodeB64(restored.deviceEd25519PrivB64).size == 32,
        )
    }

    // ------------------------------------------------------------------
    // 9. buildWgQuickConfig
    // ------------------------------------------------------------------

    @Test fun buildWgQuickConfigProducesExpectedText() {
        val server = GuestLogicalServer(
            serverId = "s-free-1",
            name = "US-FREE#1",
            exitCountry = "US",
            city = null,
            tier = 0,
            features = 0,
            load = 12.5f,
            score = 1.05f,
            domain = "us-free-01.protonvpn.com",
            entryIp = "185.159.158.1",
            x25519PublicKey = "abcPubKeyBase64==",
            status = 1,
        )
        val cert = GuestCertificate(
            certificatePem = "ignored",   // PEM is not part of the wg-quick text
            serverStatus = JSONObject(),
            refreshTime = 0L,
            ipv4 = "10.2.0.5",
            ipv6 = null,
            dnsIps = listOf("10.64.0.1"),
            clientPublicKeyB64 = "wgpub==",
        )
        val config = buildWgQuickConfig(server, cert, "privB64", dnsServer = "127.0.0.1")
        assertTrue("missing [Interface] section: $config", config.contains("[Interface]"))
        assertTrue("missing [Peer] section: $config", config.contains("[Peer]"))
        assertTrue("missing PrivateKey: $config", config.contains("PrivateKey = privB64"))
        assertTrue("missing Address: $config", config.contains("Address = 10.2.0.5/32"))
        assertTrue("missing DNS: $config", config.contains("DNS = 127.0.0.1"))
        assertTrue(
            "missing Endpoint: $config",
            config.contains("Endpoint = 185.159.158.1:51820"),
        )
        assertTrue(
            "missing peer PublicKey: $config",
            config.contains("PublicKey = abcPubKeyBase64=="),
        )
        // AllowedIPs defaults to both v4 and v6.
        assertTrue(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /** Build a throwaway [GuestSession] for tests that only need the
     *  bearer auth headers (not the device keypair binding). */
    private fun testSession(): GuestSession {
        val now = System.currentTimeMillis() / 1000
        return GuestSession(
            accessToken = "guest-tok",
            refreshToken = "guest-refresh",
            uid = "guest-uid",
            expiresAt = now + 3600,
            refreshExpiresAt = now + 9999,
            scope = "self vpn",
            deviceEd25519PubB64 = "devpub",
            deviceEd25519PrivB64 = GuestApi.base64(ByteArray(32)),
        )
    }

    /** Build a single logical-server JSON dict the way the Proton API
     *  returns it (matches the Python test helper `_logical_server`). */
    private fun serverJson(
        id: String,
        name: String,
        country: String,
        tier: Int,
        city: String? = null,
        features: Int = 0,
        load: Double = 12.5,
        score: Double = 1.05,
        physical: JSONObject = JSONObject().apply {
            put("Domain", "us-free-01.protonvpn.com")
            put("EntryIP", "185.159.158.1")
            put("X25519PublicKey", "abcPubKeyBase64==")
            put("Status", 1)
        },
    ): JSONObject = JSONObject().apply {
        put("ID", id)
        put("Name", name)
        put("ExitCountry", country)
        if (city != null) put("City", city) else put("City", JSONObject.NULL)
        put("Tier", tier)
        put("Features", features)
        put("Load", load)
        put("Score", score)
        put("Servers", JSONArray().put(physical))
    }

    // ------------------------------------------------------------------
    // Fake API harness (Interceptor-based, no MockWebServer dep)
    // ------------------------------------------------------------------

    /** A recorded OkHttp request: method, path, body string, parsed
     *  body JSON (when parseable), and lowercased header map. */
    data class RecordedRequest(
        val method: String,
        val path: String,
        val body: String,
        val bodyJson: JSONObject?,
        val headers: Map<String, String>,
    )

    /** In-memory Proton API with request recording.
     *
     *  Call [setRaw]/[setEnvelope]/[setErrorEnvelope] to program a
     *  response for a `(method, path)` route; [requests] holds the
     *  recorded requests for assertions; [find] retrieves the first
     *  recorded request matching `(method, path)`. */
    private class StubApi {
        private val routes: MutableMap<Pair<String, String>, () -> String> = mutableMapOf()
        val requests: MutableList<RecordedRequest> = mutableListOf()

        /** Program a raw JSON response for `(method, path)`. */
        fun setRaw(method: String, path: String, rawJson: String) {
            routes[method to path] = { rawJson }
        }

        /** Program a route that returns the given `response` payload
         *  wrapped in the Proton success envelope
         *  `{Code:1000, Response}`. */
        fun setEnvelope(method: String, path: String, response: JSONObject) {
            routes[method to path] = {
                JSONObject().apply {
                    put("Code", 1000)
                    put("Response", response)
                }.toString()
            }
        }

        /** Program a route returning a custom (non-1000) envelope. */
        fun setErrorEnvelope(
            method: String, path: String, code: Int,
            error: JSONObject, response: JSONObject = JSONObject(),
        ) {
            routes[method to path] = {
                JSONObject().apply {
                    put("Code", code)
                    put("Response", response)
                    put("Error", error)
                }.toString()
            }
        }

        /** Return the first recorded request matching `(method, path)`. */
        fun find(method: String, path: String): RecordedRequest =
            requests.first { it.method == method && it.path == path }

        /** Build an OkHttpClient that intercepts every request, records
         *  it, and returns the programmed response (HTTP 200 with the
         *  JSON body). Unknown routes return a 4040 envelope. */
        fun client(): OkHttpClient {
            val interceptor = Interceptor { chain ->
                val req = chain.request()
                val bodyStr = readBody(req)
                val bodyJson = runCatching { JSONObject(bodyStr) }.getOrNull()
                val headers = req.headers.toMultimap()
                    .mapKeys { it.key.lowercase() }
                    .mapValues { it.value.joinToString(", ") }
                val path = req.url.encodedPath
                requests += RecordedRequest(req.method, path, bodyStr, bodyJson, headers)
                val json = routes[req.method to path]?.invoke()
                    ?: JSONObject().apply {
                        put("Code", 4040)
                        put("Response", JSONObject())
                        put("Error", JSONObject().put(
                            "Message", "unknown route ${req.method} $path"))
                    }.toString()
                Response.Builder()
                    .request(req)
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body(json.toByteArray(Charsets.UTF_8).toResponseBody(JSON_MEDIA))
                    .build()
            }
            return OkHttpClient.Builder()
                .addInterceptor(interceptor)
                .build()
        }

        private fun readBody(req: Request): String = runCatching {
            req.body?.let {
                val buffer = Buffer()
                it.writeTo(buffer)
                buffer.readUtf8()
            } ?: ""
        }.getOrDefault("")
    }

    companion object {
        private val JSON_MEDIA = "application/json".toMediaType()
    }
}
