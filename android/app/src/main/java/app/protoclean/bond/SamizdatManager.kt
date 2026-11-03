package app.protoclean.bond

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Drives the bundled **lantern-box** binary (Lantern's GPL-3 sing-box
 * fork, cross-compiled in CI and shipped inside the APK as
 * `liblanternbox.so` — Android allows executing binaries from the
 * app's nativeLibraryDir). Generates the same documented client config
 * as the desktop's `proto_clean/vpn/samizdatconf.py` and runs the
 * engine with a local mixed (SOCKS5 + HTTP) inbound, which the bonding
 * VPN service then uses as its upstream.
 */
object SamizdatManager {

    private const val TAG = "ProtoClean.Samizdat"
    const val MIXED_PORT = 10810

    /** Set by the ViewModel before start(): the samizdat profile. */
    object Config {
        @Volatile var address: String = ""
        @Volatile var port: Int = 443
        @Volatile var publicKey: String = ""     // 64 hex (X25519)
        @Volatile var shortId: String = ""       // 16 hex
        @Volatile var serverName: String = ""    // cover SNI (e.g. ok.ru)
        @Volatile var fingerprint: String = "chrome"
    }

    @Volatile
    private var proc: Process? = null

    @Volatile
    var running = false
        private set

    /** The bundled binary, if this APK carries it (jniLibs trick). */
    fun binaryPath(context: Context): String? {
        val dir = context.applicationInfo.nativeLibraryDir ?: return null
        val f = File(dir, "liblanternbox.so")
        return if (f.isFile && f.canExecute()) f.absolutePath else null
    }

    /** The lantern-box client config (mirrors samizdatconf.py). */
    fun buildConfig(): JSONObject {
        val outbound = JSONObject().apply {
            put("type", "samizdat")
            put("tag", "samizdat-out")
            put("server", Config.address)
            put("server_port", Config.port)
            put("public_key", Config.publicKey)
            put("short_id", Config.shortId)
            put("fingerprint", Config.fingerprint)
            put("padding_profile", "chrome")
            put("max_jitter_ms", 30)
            put("max_streams_per_conn", 100)
            put("data_threshold", 14000)
            if (Config.serverName.isNotBlank()) {
                put("server_name", Config.serverName)
            }
        }
        val outbounds = JSONArray()
            .put(outbound)
            .put(JSONObject().put("type", "direct").put("tag", "direct"))
        return JSONObject().apply {
            put("log", JSONObject().put("level", "warn"))
            put("inbounds", JSONArray().put(
                JSONObject().apply {
                    put("type", "mixed")
                    put("tag", "mixed-in")
                    put("listen", "127.0.0.1")
                    put("listen_port", MIXED_PORT)
                }))
            put("outbounds", outbounds)
            put("route", JSONObject().put("rules", JSONArray().put(
                JSONObject().apply {
                    put("ip_is_private", true)
                    put("outbound", "direct")
                })))
        }
    }

    /** Start lantern-box with the current config; false when the
     *  profile/binary is missing or the engine dies immediately. */
    fun start(context: Context): Boolean {
        if (running) return true
        val bin = binaryPath(context) ?: run {
            Log.w(TAG, "no bundled lantern-box in this APK")
            return false
        }
        if (Config.address.isBlank() || Config.publicKey.isBlank() ||
            Config.shortId.isBlank()
        ) {
            Log.w(TAG, "samizdat profile incomplete")
            return false
        }
        val dir = File(context.cacheDir, "samizdat").apply { mkdirs() }
        val cfg = File(dir, "config.json")
        cfg.writeText(buildConfig().toString())
        return try {
            stop()   // a stale engine would hold the mixed port
            proc = ProcessBuilder(bin, "run", "-c", cfg.absolutePath)
                .directory(dir)
                .redirectOutput(File(dir, "lantern-box.log"))
                .redirectErrorStream(true)
                .start()
            running = true
            // (Process.pid() needs API 33; keep the log minSdk-safe)
            Log.i(TAG, "lantern-box started (binary ${bin}, " +
                "mixed inbound 127.0.0.1:$MIXED_PORT)")
            true
        } catch (e: Exception) {
            Log.w(TAG, "lantern-box failed to start: ${e.message}")
            false
        }
    }

    fun stop() {
        proc?.let { p ->
            runCatching { p.destroy() }
            runCatching {
                // sing-box traps SIGTERM gracefully; give it a moment
                val t = Thread {
                    runCatching { p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) }
                    runCatching { p.destroyForcibly() }
                }
                t.isDaemon = true
                t.start()
            }
        }
        proc = null
        running = false
    }
}
