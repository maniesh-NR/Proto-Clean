package app.protoclean.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Wraps the WireGuard tunnel library (GoBackend).
 *
 * Flow (identical semantics to the desktop TunnelManager):
 *   1. start our VpnService subclass so GoBackend binds to it;
 *   2. prepare (system VPN consent dialog) on first use;
 *   3. setState UP with a Config parsed from the downloaded .conf, with
 *      excludedApplications applied from the split-tunnel settings;
 *   4. wait for the peer handshake — a cached config that never handshakes
 *      is exactly the "saved config failed" condition that triggers a
 *      re-download (see AppViewModel.connect).
 */
object TunnelManager {

    private const val TAG = "ProtoClean.Tunnel"
    const val TUNNEL_NAME = "proto-clean"

    /** LAN ranges kept outside the tunnel when "allow LAN" is on. */
    private val LAN_RANGES = listOf("192.168.0.0/16", "172.16.0.0/12")

    private var backend: GoBackend? = null
    private var tunnel: Tunnel? = null

    @Volatile
    var state: Tunnel.State = Tunnel.State.DOWN
        private set

    @Volatile
    var onStateChange: ((Tunnel.State) -> Unit)? = null

    /** Simple named tunnel bound to the config we set. */
    private class ProtoCleanTunnel(private val name: String) : Tunnel {
        override fun getName() = name
        override fun onStateChange(newState: Tunnel.State) {
            state = newState
            Log.i(TAG, "tunnel $newState")
            onStateChange?.invoke(newState)
        }
    }

    fun ensureBackend(context: Context): GoBackend =
        backend ?: synchronized(this) {
            backend ?: GoBackend(context.applicationContext).also { backend = it }
        }

    /** True when the system VPN consent is still needed. */
    fun needsConsent(context: Context): Boolean =
        VpnService.prepare(context) != null

    /**
     * Bring the tunnel up with the given config text.
     * [excludedApps] are package names routed outside the VPN
     * (VpnService.addDisallowedApplication — the Android split tunnel).
     * [ipv6Support] false strips IPv6 routes/addresses from the config;
     * [customDns] replaces the config's DNS with the given servers;
     * [allowLan] keeps LAN ranges outside the tunnel (removed from
     * AllowedIPs — the same portable edit as the desktop).
     */
    fun up(
        context: Context,
        configText: String,
        excludedApps: Set<String> = emptySet(),
        ipv6Support: Boolean = true,
        customDns: Set<String> = emptySet(),
        allowLan: Boolean = false,
    ): Tunnel.State {
        val app = context.applicationContext
        // bind GoBackend to OUR service before it tries to start its own
        app.startService(Intent(app, ProtoCleanVpnService::class.java))

        val edited = applyLocalEdits(configText, ipv6Support, customDns, allowLan)
        val config = parseConfig(edited, excludedApps)
        val t = tunnel ?: ProtoCleanTunnel(TUNNEL_NAME).also { tunnel = it }
        return ensureBackend(app).setState(t, Tunnel.State.UP, config)
    }

    /**
     * Minimal config-text edits mirroring the desktop's applyLocalEdits:
     * IPv6 off → strip ::/0 + v6 addresses; custom DNS → rewrite the DNS
     * line; allow LAN → drop LAN ranges from AllowedIPs so they keep the
     * physical route.
     */
    internal fun applyLocalEdits(
        configText: String,
        ipv6Support: Boolean,
        customDns: Set<String>,
        allowLan: Boolean,
    ): String {
        var text = configText
        if (!ipv6Support) {
            text = text.lineSequence().joinToString("\n") { line ->
                val trimmed = line.trim()
                if (trimmed.startsWith("Address") || trimmed.startsWith("DNS") ||
                    trimmed.startsWith("AllowedIPs")) {
                    val (key, value) = line.split("=", limit = 2)
                    val kept = value.split(",").map { it.trim() }
                        .filter { it.isNotEmpty() && !it.contains(":") }
                    if (kept.isEmpty()) line else "$key = ${kept.joinToString(", ")}"
                } else line
            }
        }
        if (customDns.isNotEmpty()) {
            text = if (Regex("(?m)^\\s*DNS\\s*=").containsMatchIn(text)) {
                text.replaceFirst(Regex("(?m)^\\s*DNS\\s*=.*$"),
                                  "DNS = ${customDns.joinToString(", ")}")
            } else {
                text.replaceFirst("[Interface]", "[Interface]\nDNS = ${customDns.joinToString(", ")}")
            }
        }
        if (allowLan) {
            text = text.lineSequence().joinToString("\n") { line ->
                val trimmed = line.trim()
                if (trimmed.startsWith("AllowedIPs")) {
                    val (key, value) = line.split("=", limit = 2)
                    val kept = value.split(",").map { it.trim() }
                        .filter { it.isNotEmpty() && it !in LAN_RANGES }
                    if (kept.isEmpty()) line else "$key = ${kept.joinToString(", ")}"
                } else line
            }
        }
        return text
    }

    fun down(context: Context): Tunnel.State {
        val t = tunnel ?: return Tunnel.State.DOWN
        return runCatching {
            ensureBackend(context.applicationContext).setState(t, Tunnel.State.DOWN, null)
        }.getOrDefault(Tunnel.State.DOWN)
    }

    /**
     * Parse a wg-quick config; apply the Android app exclusions by injecting
     * the ExcludedApplications key into the [Interface] section (an Android
     * wg-quick extension understood by the tunnel library's parser).
     */
    private fun parseConfig(configText: String, excludedApps: Set<String>): Config {
        var text = configText
        if (excludedApps.isNotEmpty()) {
            val line = "ExcludedApplications = ${excludedApps.joinToString(", ")}"
            text = if (Regex("(?m)^\\s*\\[Interface]\\s*$").containsMatchIn(text))
                text.replaceFirst(Regex("(?m)^\\s*\\[Interface]\\s*$"), "[Interface]\n$line")
            else
                "$text\n[Interface]\n$line"
        }
        return Config.parse(ByteArrayInputStream(text.toByteArray()))
    }

    /**
     * Wait until the peer completes a handshake. Returns false on timeout —
     * the caller treats that as a failed (stale/revoked) cached config.
     */
    suspend fun waitHandshake(
        context: Context,
        timeoutMs: Long = 25_000,
        pollMs: Long = 2_000,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val stats = statistics(context)
            if (stats != null && stats.peers().isNotEmpty()) {
                val handshook = stats.peers().any { key ->
                    (stats.peer(key)?.latestHandshakeEpochMillis ?: 0L) > 0L
                }
                if (handshook) return true
            }
            delay(pollMs)
        }
        return false
    }

    fun statistics(context: Context): Statistics? = runCatching {
        tunnel?.let { ensureBackend(context.applicationContext).getStatistics(it) }
    }.getOrNull()

    /** Whether the system's "Block connections without VPN" lockdown is on. */
    fun isLockdownEnabled(context: Context): Boolean = runCatching {
        ensureBackend(context.applicationContext).isLockdownEnabled
    }.getOrDefault(false)

    /** Revoked by the system — reflect it in the UI state. */
    fun onRevoked(context: Context) {
        state = Tunnel.State.DOWN
        onStateChange?.invoke(Tunnel.State.DOWN)
        CoroutineScope(Dispatchers.Main).launch {
            runCatching { down(context) }
        }
    }

    // ---------------------------------------------------------------- stats
    data class Stats(
        val up: Boolean,
        val rx: Long,
        val tx: Long,
        val handshakeAgeSec: Long?,
    )

    fun snapshot(context: Context): Stats {
        val stats = statistics(context)
        var rx = 0L
        var tx = 0L
        var handshake: Long? = null
        if (stats != null) {
            stats.peers().forEach { key ->
                val ps = stats.peer(key)
                rx += ps?.rxBytes ?: 0L
                tx += ps?.txBytes ?: 0L
                val hs = ps?.latestHandshakeEpochMillis ?: 0L
                if (hs > 0) handshake = hs
            }
        }
        return Stats(
            up = state == Tunnel.State.UP,
            rx = rx, tx = tx,
            handshakeAgeSec = handshake?.let { (System.currentTimeMillis() - it) / 1000L },
        )
    }
}
