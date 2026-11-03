package app.protoclean

import android.app.Application
import android.content.Intent
import android.net.VpnService
import android.webkit.WebView
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.protoclean.data.BlocklistEntry
import app.protoclean.data.ConfigCache
import app.protoclean.data.CredentialsStore
import app.protoclean.data.SettingsStore
import app.protoclean.bond.BondVpnService
import app.protoclean.bond.SamizdatManager
import app.protoclean.dns.DnsFilterVpnService
import app.protoclean.proton.ConfigOptions
import app.protoclean.proton.LogicalServer
import app.protoclean.proton.ProtonSession
import app.protoclean.proton.ProtonWeb
import app.protoclean.proton.Selection
import app.protoclean.vpn.NatPmp
import app.protoclean.vpn.TunnelManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * App state machine — the Android analogue of the desktop Controller:
 * login (WebView session), free-only server list + fastest selection,
 * config caching with failure-based re-download, WireGuard tunnel with
 * handshake verification, NAT-PMP port forwarding, blocklist management
 * and the standalone DNS-filter (ad-blocker) mode.
 */
class AppViewModel(app: Application) : AndroidViewModel(app) {

    enum class VpnState { LOGGED_OUT, LOGGED_IN, CONNECTING, CONNECTED, ERROR }

    data class UiState(
        val vpnState: VpnState = VpnState.LOGGED_OUT,
        val detail: String = "",
        val message: String = "",
        val messageLevel: String = "info",
        val loggedIn: Boolean = false,
        val loginStatus: String = "",
        val currentServer: LogicalServer? = null,
        val viaCache: Boolean = false,
        val stats: TunnelManager.Stats? = null,
        val externalPort: Int? = null,
        val lockdown: Boolean = false,
    )

    private val appCtx = app.applicationContext
    val settings: SettingsStore get() = ProtoCleanApp.instance.settings
    val blocklists get() = ProtoCleanApp.instance.blocklists
    val configCache: ConfigCache get() = ProtoCleanApp.instance.configCache
    val creds = CredentialsStore(appCtx)
    val session = ProtonSession(appCtx, creds)

    /** The shared WebView — created by the UI (main thread), used for automation. */
    @Volatile
    var webView: WebView? = null

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    private val _servers = MutableStateFlow<List<LogicalServer>>(emptyList())
    val servers: StateFlow<List<LogicalServer>> = _servers

    private val _blocklistEntries = MutableStateFlow<List<BlocklistEntry>>(emptyList())
    val blocklistEntries: StateFlow<List<BlocklistEntry>> = _blocklistEntries

    private var connectJob: Job? = null
    private var statsJob: Job? = null
    private var portForwarder: NatPmp.Forwarder? = null

    // ------------------------------------------------------------- helpers

    private fun say(message: String, level: String = "info") {
        _ui.value = _ui.value.copy(message = message, messageLevel = level)
    }

    private fun setVpnState(state: VpnState, detail: String = "") {
        _ui.value = _ui.value.copy(vpnState = state, detail = detail)
    }

    private suspend fun s() = settings.current()

    init {
        // restore the saved Proton session (cookies) on launch
        session.restoreSession()
        if (creds.sessionCookies().contains("AUTH")) {
            _ui.value = _ui.value.copy(loggedIn = true, vpnState = VpnState.LOGGED_IN)
        }
        viewModelScope.launch {
            blocklists.sourcesBlockedSnapshot = blocklists.sources()
            _blocklistEntries.value = blocklists.entries()
            blocklists.rebuild()
        }
        TunnelManager.onStateChange = { state ->
            if (state == com.wireguard.android.backend.Tunnel.State.DOWN &&
                _ui.value.vpnState == VpnState.CONNECTED
            ) {
                _ui.value = _ui.value.copy(vpnState = VpnState.LOGGED_IN, stats = null)
                stopStatsLoop()
            }
        }
    }

    // ---------------------------------------------------------------- login

    /** Driven by the login screen once its WebView is ready. */
    fun loginWithWebView(webView: WebView) {
        this.webView = webView
        viewModelScope.launch {
            _ui.value = _ui.value.copy(loginStatus = "starting…")
            val (ok, msg) = session.login(webView, onStatus = { status ->
                _ui.value = _ui.value.copy(loginStatus = status)
            })
            if (ok) {
                session.openDownloads(webView)
                _ui.value = _ui.value.copy(loggedIn = true, loginStatus = "logged in",
                                           vpnState = VpnState.LOGGED_IN)
                refreshServers()
                say("Logged in — showing free servers")
            } else {
                _ui.value = _ui.value.copy(loginStatus = msg)
                if (msg.contains("no stored credentials")) {
                    say("Type your Proton credentials in the login page", "warn")
                }
            }
        }
    }

    fun saveCredentials(username: String, password: String, totp: String) {
        creds.save(username, password, totp)
        say("credentials saved — they will be filled in automatically")
    }

    fun logout() {
        disconnect()
        session.logout()
        creds.clear()
        _ui.value = UiState()
        _servers.value = emptyList()
    }

    // -------------------------------------------------------------- servers

    fun refreshServers() {
        val webView = webView ?: return say("login first", "warn")
        viewModelScope.launch {
            setVpnState(_ui.value.vpnState, "fetching servers…")
            val alternative = settings.current().alternativeRouting
            val servers = withContext(Dispatchers.Main) {
                runCatching {
                    ProtonWeb.scrapeServers(webView, alternativeRouting = alternative)
                }.getOrDefault(emptyList())
            }
            if (servers.isEmpty()) {
                say("Could not refresh the server list (still showing cached entries)", "warn")
            } else {
                // free only — paid (tier > 0) servers are excluded everywhere
                _servers.value = servers.filter { it.isFree }
                say("${servers.count { it.isFree }} free servers (paid excluded)")
            }
        }
    }

    private fun selectServer(serverId: String?): LogicalServer? {
        val list = _servers.value
        val settingsNow = _ui.value
        if (serverId == null) {
            return Selection.fastest(list)
        }
        return list.firstOrNull { it.id == serverId && it.isFree }
            ?: Selection.fastest(list)?.also {
                say("selected server is not in the free list — using the fastest free server", "warn")
            }
    }

    // -------------------------------------------------------------- connect

    fun connect(serverId: String? = null) {
        if (connectJob?.isActive == true) return say("busy — try again in a moment", "warn")
        connectJob = viewModelScope.launch {
            if (TunnelManager.needsConsent(appCtx)) {
                setVpnState(VpnState.CONNECTING, "waiting for VPN consent…")
                say("accept the VPN connection request, then tap Connect again", "warn")
                return@launch
            }
            if (!session.loggedIn && !creds.sessionCookies().contains("AUTH")) {
                return@launch say("log in first", "error")
            }
            setVpnState(VpnState.CONNECTING, "choosing server…")
            // mutual exclusion: stop the DNS-filter VPN (one VPN per app)
            if (DnsFilterVpnService.running) {
                DnsFilterVpnService.stop(appCtx)
                settings.update { it.copy(dnsFilterEnabled = false) }
                delay(800)
            }

            if (_servers.value.isEmpty()) {
                setVpnState(VpnState.CONNECTING, "fetching servers…")
                refreshServers()
                delay(3000)
            }
            val server = selectServer(serverId) ?: run {
                setVpnState(VpnState.LOGGED_IN, "no usable free server")
                return@launch say("no usable free server found", "error")
            }
            _ui.value = _ui.value.copy(currentServer = server)

            val cfg = s()
            if (cfg.protocol == "openvpn") {
                setVpnState(VpnState.LOGGED_IN, "OpenVPN not available on Android")
                return@launch say(
                    "OpenVPN configs are downloaded and tunneled by the desktop " +
                    "app — the Android build only runs WireGuard. Switch the " +
                    "protocol in Settings.", "error")
            }
            val options = ConfigOptions.fromSettings(cfg)
            val fingerprint = ConfigCache.fingerprint(options.vpnAccelerator,
                                                      options.natPmpPortForward)

            // ---- 1. cached config first (only re-download when it fails)
            if (cfg.cacheConfigs) {
                val cached = configCache.get(server.name, fingerprint)
                if (cached != null) {
                    setVpnState(VpnState.CONNECTING,
                                "connecting to ${server.name} (cached config)…")
                    if (bringUp(cached.text, server, cfg)) {
                        configCache.markVerified(server.name, cached.fingerprint)
                        _ui.value = _ui.value.copy(viaCache = true)
                        return@launch
                    }
                    // saved config failed → invalidate + re-download once
                    configCache.noteFailure(server.name, cached.fingerprint)
                    configCache.invalidate(server.name)
                    say("saved config failed — downloading a fresh one…", "warn")
                }
            }

            // ---- 2. fresh download through the downloads page
            setVpnState(VpnState.CONNECTING, "generating config for ${server.name}…")
            val webView = webView
            if (webView == null) {
                setVpnState(VpnState.ERROR, "no webview")
                return@launch say("login first", "error")
            }
            val text = withContext(Dispatchers.Main) {
                runCatching { ProtonWeb.createConfig(webView, server.name, options) }
                    .getOrNull()
            }
            if (text.isNullOrBlank()) {
                setVpnState(VpnState.ERROR, "config generation failed")
                return@launch say("could not create the config on the downloads page", "error")
            }
            if (cfg.cacheConfigs) {
                configCache.put(server.name, text, fingerprint)
            }
            if (!bringUp(text, server, cfg)) return@launch
            if (cfg.cacheConfigs) configCache.markVerified(server.name, fingerprint)
            _ui.value = _ui.value.copy(viaCache = false)
        }
    }

    /** Tunnel up + handshake check + port forwarding; true when connected. */
    private suspend fun bringUp(configText: String, server: LogicalServer,
                                cfg: app.protoclean.data.AppSettings): Boolean {
        return try {
            withContext(Dispatchers.Main) {
                TunnelManager.up(
                    appCtx, configText,
                    excludedApps = cfg.excludedApps.takeIf { cfg.splitEnabled }
                        ?: emptySet(),
                    ipv6Support = cfg.ipv6Support,
                    customDns = cfg.customDnsServers.takeIf { cfg.customDnsEnabled }
                        ?: emptySet(),
                    allowLan = cfg.allowLan,
                )
            }
            setVpnState(VpnState.CONNECTED, server.name)
            say("Connected to ${server.name} (${server.loadLabel} load)")

            // verify the tunnel actually handshakes (catches stale configs)
            val ok = TunnelManager.waitHandshake(
                appCtx, timeoutMs = cfg.configVerifyTimeoutSec * 1000L)
            if (!ok) {
                throw IllegalStateException(
                    "tunnel is up but the WireGuard handshake never completed " +
                    "(stale or revoked config?)")
            }
            startStatsLoop()
            if (cfg.natPmpInConfig) {
                portForwarder = NatPmp.Forwarder(
                    internalPort = cfg.natPmpInternalPort,
                    onUpdate = { port -> _ui.value = _ui.value.copy(externalPort = port) },
                    onError = { msg -> say("Port forwarding: $msg", "warn") },
                ).also { it.start(viewModelScope) }
            }
            _ui.value = _ui.value.copy(
                lockdown = TunnelManager.isLockdownEnabled(appCtx))
            true
        } catch (e: Exception) {
            setVpnState(VpnState.ERROR, e.message ?: "connect failed")
            say("Connection failed: ${e.message}", "error")
            TunnelManager.down(appCtx)
            false
        }
    }

    fun disconnect() {
        connectJob?.cancel()
        connectJob = null
        portForwarder?.stop()
        portForwarder = null
        statsJob?.cancel()
        statsJob = null
        viewModelScope.launch {
            TunnelManager.down(appCtx)
            _ui.value = _ui.value.copy(
                vpnState = if (_ui.value.loggedIn) VpnState.LOGGED_IN else VpnState.LOGGED_OUT,
                currentServer = null, stats = null, externalPort = null, viaCache = false)
            say("disconnected")
        }
    }

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = viewModelScope.launch {
            while (true) {
                _ui.value = _ui.value.copy(stats = TunnelManager.snapshot(appCtx))
                delay(5000)
            }
        }
    }

    private fun stopStatsLoop() {
        statsJob?.cancel(); statsJob = null
    }

    // ----------------------------------------------------------- ad blocker

    /** Toggle the standalone DNS-filter VPN (runs only while tunnel is down). */
    fun setDnsFilter(enabled: Boolean) {
        viewModelScope.launch {
            if (enabled) {
                if (_ui.value.vpnState == VpnState.CONNECTED ||
                    _ui.value.vpnState == VpnState.CONNECTING) {
                    say("disconnect the VPN first — Android allows one VPN at a time", "warn")
                    return@launch
                }
                settings.update { it.copy(dnsFilterEnabled = true) }
                blocklists.rebuild()
                DnsFilterVpnService.DomainFilterHolder.filter = blocklists.filter
                DnsFilterVpnService.DomainFilterHolder.nxdomain = s().blockNxdomain
                DnsFilterVpnService.start(appCtx)
                say("Ad-blocker on — DNS filtering is active system-wide")
            } else {
                settings.update { it.copy(dnsFilterEnabled = false) }
                DnsFilterVpnService.stop(appCtx)
                say("Ad-blocker off")
            }
        }
    }

    // --------------------------------------------------------- link bonding

    /** Toggle the Speedify-style bonding VPN (Wi-Fi + mobile data as one
     *  pipe; needs a bond server — run the desktop app's
     *  `python3 -m proto_clean.bondserver` on any reachable host). */
    fun setBonding(enabled: Boolean) {
        viewModelScope.launch {
            if (enabled) {
                if (_ui.value.vpnState == VpnState.CONNECTED ||
                    _ui.value.vpnState == VpnState.CONNECTING) {
                    say("disconnect the VPN first — Android allows one VPN at a time", "warn")
                    return@launch
                }
                val cfg = s()
                if (cfg.bondUpstream == "samizdat" &&
                    (cfg.samAddress.isBlank() || cfg.samPublicKey.isBlank() ||
                     cfg.samShortId.isBlank())) {
                    say("set the samizdat profile in Settings first " +
                        "(server, pbk, sid)", "error")
                    return@launch
                }
                if (cfg.bondUpstream == "bond" && cfg.bondServer.isBlank()) {
                    say("set the bond server in Settings first (run " +
                        "proto_clean.bondserver on a VPS)", "error")
                    return@launch
                }
                if (DnsFilterVpnService.running) {
                    DnsFilterVpnService.stop(appCtx)
                    settings.update { it.copy(dnsFilterEnabled = false) }
                    delay(500)
                }
                BondVpnService.Config.server = cfg.bondServer
                BondVpnService.Config.port = cfg.bondPort
                BondVpnService.Config.token = cfg.bondToken
                BondVpnService.Config.mode = cfg.bondMode
                BondVpnService.Config.upstream = cfg.bondUpstream
                SamizdatManager.Config.address = cfg.samAddress
                SamizdatManager.Config.port = cfg.samPort
                SamizdatManager.Config.publicKey = cfg.samPublicKey
                SamizdatManager.Config.shortId = cfg.samShortId
                SamizdatManager.Config.serverName = cfg.samServerName
                BondVpnService.start(appCtx)
                say(if (cfg.bondUpstream == "samizdat")
                    "Samizdat on — traffic rides Lantern's masquerade"
                else
                    "Link bonding on — Wi-Fi + mobile data combined " +
                    "(${cfg.bondMode})")
            } else {
                BondVpnService.stop(appCtx)
                say("Link bonding off")
            }
        }
    }

    // ------------------------------------------------------------ blocklists

    fun addBlocklist(name: String, url: String) = viewModelScope.launch {
        val r = blocklists.add(name, url)
        if (r.ok) say("blocklist added — ${r.totalDomains} domains total")
        else say("blocklist failed: ${r.error}", "error")
        refreshBlocklistUi()
    }

    fun removeBlocklist(name: String) = viewModelScope.launch {
        blocklists.remove(name)
        say("removed blocklist '$name'")
        refreshBlocklistUi()
    }

    fun setBlocklistEnabled(name: String, enabled: Boolean) = viewModelScope.launch {
        blocklists.setEnabled(name, enabled)
        refreshBlocklistUi()
    }

    fun updateBlocklists(name: String? = null) = viewModelScope.launch {
        val r = if (name != null) blocklists.updateOne(name) else blocklists.updateAll()
        if (r.ok) say("${if (name != null) name else "all blocklists"} updated — ${r.totalDomains} domains")
        else say("update failed: ${r.error}", "warn")
        refreshBlocklistUi()
        if (DnsFilterVpnService.running) {
            DnsFilterVpnService.DomainFilterHolder.filter = blocklists.filter
        }
    }

    private suspend fun refreshBlocklistUi() {
        blocklists.sourcesBlockedSnapshot = blocklists.sources()
        _blocklistEntries.value = blocklists.entries()
    }

    fun refreshBlocklistEntries() = viewModelScope.launch { refreshBlocklistUi() }

    // -------------------------------------------------------------- settings

    fun updateSettings(transform: (app.protoclean.data.AppSettings) -> app.protoclean.data.AppSettings) {
        viewModelScope.launch { settings.update(transform) }
    }

    fun purgeConfigCache() {
        configCache.purge()
        say("cached WireGuard configs removed")
    }

    fun configCacheSize(): Int = configCache.size()

    /** System VPN-consent intent, launched by the Activity when needed. */
    fun prepareIntent(): Intent? = VpnService.prepare(appCtx)
}
