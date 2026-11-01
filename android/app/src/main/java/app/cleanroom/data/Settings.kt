package app.cleanroom.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.dataStore by preferencesDataStore(name = "cleanroom_settings")

/**
 * One user-manageable blocklist source (mirrors the desktop BlocklistSource).
 */
data class BlocklistSource(
    val name: String,
    val url: String,
    var enabled: Boolean = true,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name); put("url", url); put("enabled", enabled)
    }

    companion object {
        fun fromJson(o: JSONObject) = BlocklistSource(
            name = o.optString("name").ifBlank { nameFromUrl(o.optString("url")) },
            url = o.optString("url"),
            enabled = o.optBoolean("enabled", true),
        )

        fun nameFromUrl(url: String): String {
            val tail = url.trimEnd('/').split("/").lastOrNull() ?: url
            val host = url.substringAfter("//", "").substringBefore("/")
            val base = host.substringBefore('.').ifBlank { "blocklist" }
            return if (tail.isBlank()) base else "$base · $tail"
        }
    }
}

/** Well-known lists offered as presets (same set as the desktop app). */
val BLOCKLIST_PRESETS = listOf(
    "StevenBlack unified (ads + malware)" to
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "HaGeZi Pro — ads, tracking, malware" to
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    "HaGeZi Multi PRO++ — heavier" to
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multipro.txt",
    "OISD Big — aggregated ads/tracking" to "https://hosts.oisd.nl/big",
    "1Hosts Lite" to "https://badmojr.github.io/1hosts/Lite/hosts",
    "Peter Lowe's ad servers" to
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
)

data class AppSettings(
    val username: String = "",
    val autoconnectFastest: Boolean = true,
    val cacheConfigs: Boolean = true,
    val configVerifyTimeoutSec: Int = 25,
    // netshield-style local blocking
    val netshieldEnabled: Boolean = true,
    val blockNxdomain: Boolean = true,
    // protocol: which config to download from the Proton page. The Android
    // tunnel itself always runs WireGuard (GoBackend); OpenVPN configs can
    // be downloaded only on the desktop app.
    val protocol: String = "wireguard",        // wireguard | openvpn
    val openvpnTransport: String = "udp",      // udp | tcp (OpenVPN only)
    val openvpnDriver: String = "tun",         // tun | tap (desktop only)
    // VPN options applied on the downloads page
    val vpnAccelerator: Boolean = true,
    val moderateNat: Boolean = false,
    val natPmpInConfig: Boolean = true,
    val natPmpInternalPort: Int = 0,
    // advanced connection options (mirrors the desktop Advanced tab)
    val alternativeRouting: Boolean = true,
    val customDnsEnabled: Boolean = false,
    val customDnsServers: Set<String> = emptySet(),
    val ipv6Support: Boolean = false,
    val ipv6LeakProtection: Boolean = true,
    val allowLan: Boolean = false,
    // split tunneling: excluded apps use VpnService.addDisallowedApplication
    val splitEnabled: Boolean = false,
    val excludedApps: Set<String> = emptySet(),
    // DNS-filter (ad-blocker) mode runs when the VPN is down
    val dnsFilterEnabled: Boolean = false,
)

/**
 * Persisted settings — mirrors the desktop settings.json so behaviour is
 * familiar across platforms.
 */
class SettingsStore(private val context: Context) {

    private object Keys {
        val username = stringPreferencesKey("username")
        val autoconnectFastest = booleanPreferencesKey("autoconnect_fastest")
        val cacheConfigs = booleanPreferencesKey("cache_configs")
        val verifyTimeout = intPreferencesKey("config_verify_timeout")
        val netshieldEnabled = booleanPreferencesKey("netshield_enabled")
        val blockNxdomain = booleanPreferencesKey("block_nxdomain")
        val protocol = stringPreferencesKey("protocol")
        val openvpnTransport = stringPreferencesKey("openvpn_transport")
        val openvpnDriver = stringPreferencesKey("openvpn_driver")
        val vpnAccelerator = booleanPreferencesKey("vpn_accelerator")
        val moderateNat = booleanPreferencesKey("moderate_nat")
        val natPmpInConfig = booleanPreferencesKey("nat_pmp_in_config")
        val natPmpInternalPort = intPreferencesKey("nat_pmp_internal_port")
        val alternativeRouting = booleanPreferencesKey("alternative_routing")
        val customDnsEnabled = booleanPreferencesKey("custom_dns_enabled")
        val customDnsServers = stringSetPreferencesKey("custom_dns_servers")
        val ipv6Support = booleanPreferencesKey("ipv6_support")
        val ipv6LeakProtection = booleanPreferencesKey("ipv6_leak_protection")
        val allowLan = booleanPreferencesKey("allow_lan")
        val splitEnabled = booleanPreferencesKey("split_enabled")
        val excludedApps = stringSetPreferencesKey("excluded_apps")
        val dnsFilterEnabled = booleanPreferencesKey("dns_filter_enabled")
        val blocklists = stringPreferencesKey("blocklists_json")
    }

    /** Normalized protocol value (unknown → wireguard). */
    private fun String.asProtocol(): String =
        if (this == "openvpn") "openvpn" else "wireguard"

    private fun String.asTransport(): String =
        if (this == "tcp") "tcp" else "udp"

    private fun String.asDriver(): String =
        if (this == "tap") "tap" else "tun"

    val settings: Flow<AppSettings> = context.dataStore.data.map { p ->
        AppSettings(
            username = p[Keys.username] ?: "",
            autoconnectFastest = p[Keys.autoconnectFastest] ?: true,
            cacheConfigs = p[Keys.cacheConfigs] ?: true,
            configVerifyTimeoutSec = p[Keys.verifyTimeout] ?: 25,
            netshieldEnabled = p[Keys.netshieldEnabled] ?: true,
            blockNxdomain = p[Keys.blockNxdomain] ?: true,
            protocol = (p[Keys.protocol] ?: "wireguard").asProtocol(),
            openvpnTransport = (p[Keys.openvpnTransport] ?: "udp").asTransport(),
            openvpnDriver = (p[Keys.openvpnDriver] ?: "tun").asDriver(),
            vpnAccelerator = p[Keys.vpnAccelerator] ?: true,
            moderateNat = p[Keys.moderateNat] ?: false,
            natPmpInConfig = p[Keys.natPmpInConfig] ?: true,
            natPmpInternalPort = p[Keys.natPmpInternalPort] ?: 0,
            alternativeRouting = p[Keys.alternativeRouting] ?: true,
            customDnsEnabled = p[Keys.customDnsEnabled] ?: false,
            customDnsServers = p[Keys.customDnsServers] ?: emptySet(),
            ipv6Support = p[Keys.ipv6Support] ?: false,
            ipv6LeakProtection = p[Keys.ipv6LeakProtection] ?: true,
            allowLan = p[Keys.allowLan] ?: false,
            splitEnabled = p[Keys.splitEnabled] ?: false,
            excludedApps = p[Keys.excludedApps] ?: emptySet(),
            dnsFilterEnabled = p[Keys.dnsFilterEnabled] ?: false,
        )
    }

    /** Blocklist registry stored as JSON (name+url+enabled), like the desktop. */
    val blocklistSources: Flow<List<BlocklistSource>> =
        context.dataStore.data.map { p ->
            val raw = p[Keys.blocklists]
            if (raw.isNullOrBlank()) {
                listOf(BlocklistSource(
                    "StevenBlack unified (ads + malware)",
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"))
            } else {
                runCatching {
                    JSONArray(raw).let { arr ->
                        (0 until arr.length()).map { BlocklistSource.fromJson(arr.getJSONObject(it)) }
                    }
                }.getOrDefault(emptyList())
            }
        }

    suspend fun current(): AppSettings = settings.first()
    suspend fun currentBlocklists(): List<BlocklistSource> = blocklistSources.first()

    suspend fun update(transform: (AppSettings) -> AppSettings) {
        context.dataStore.edit { p ->
            val s = AppSettings(
                username = p[Keys.username] ?: "",
                autoconnectFastest = p[Keys.autoconnectFastest] ?: true,
                cacheConfigs = p[Keys.cacheConfigs] ?: true,
                configVerifyTimeoutSec = p[Keys.verifyTimeout] ?: 25,
                netshieldEnabled = p[Keys.netshieldEnabled] ?: true,
                blockNxdomain = p[Keys.blockNxdomain] ?: true,
                protocol = (p[Keys.protocol] ?: "wireguard").asProtocol(),
                openvpnTransport = (p[Keys.openvpnTransport] ?: "udp").asTransport(),
                openvpnDriver = (p[Keys.openvpnDriver] ?: "tun").asDriver(),
                vpnAccelerator = p[Keys.vpnAccelerator] ?: true,
                moderateNat = p[Keys.moderateNat] ?: false,
                natPmpInConfig = p[Keys.natPmpInConfig] ?: true,
                natPmpInternalPort = p[Keys.natPmpInternalPort] ?: 0,
                alternativeRouting = p[Keys.alternativeRouting] ?: true,
                customDnsEnabled = p[Keys.customDnsEnabled] ?: false,
                customDnsServers = p[Keys.customDnsServers] ?: emptySet(),
                ipv6Support = p[Keys.ipv6Support] ?: false,
                ipv6LeakProtection = p[Keys.ipv6LeakProtection] ?: true,
                allowLan = p[Keys.allowLan] ?: false,
                splitEnabled = p[Keys.splitEnabled] ?: false,
                excludedApps = p[Keys.excludedApps] ?: emptySet(),
                dnsFilterEnabled = p[Keys.dnsFilterEnabled] ?: false,
            )
            val n = transform(s)
            p[Keys.username] = n.username
            p[Keys.autoconnectFastest] = n.autoconnectFastest
            p[Keys.cacheConfigs] = n.cacheConfigs
            p[Keys.verifyTimeout] = n.configVerifyTimeoutSec
            p[Keys.netshieldEnabled] = n.netshieldEnabled
            p[Keys.blockNxdomain] = n.blockNxdomain
            p[Keys.protocol] = n.protocol.asProtocol()
            p[Keys.openvpnTransport] = n.openvpnTransport.asTransport()
            p[Keys.openvpnDriver] = n.openvpnDriver.asDriver()
            p[Keys.vpnAccelerator] = n.vpnAccelerator
            p[Keys.moderateNat] = n.moderateNat
            p[Keys.natPmpInConfig] = n.natPmpInConfig
            p[Keys.natPmpInternalPort] = n.natPmpInternalPort
            p[Keys.alternativeRouting] = n.alternativeRouting
            p[Keys.customDnsEnabled] = n.customDnsEnabled
            p[Keys.customDnsServers] = n.customDnsServers
            p[Keys.ipv6Support] = n.ipv6Support
            p[Keys.ipv6LeakProtection] = n.ipv6LeakProtection
            p[Keys.allowLan] = n.allowLan
            p[Keys.splitEnabled] = n.splitEnabled
            p[Keys.excludedApps] = n.excludedApps
            p[Keys.dnsFilterEnabled] = n.dnsFilterEnabled
        }
    }

    suspend fun saveBlocklists(list: List<BlocklistSource>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        context.dataStore.edit { it[Keys.blocklists] = arr.toString() }
    }
}
