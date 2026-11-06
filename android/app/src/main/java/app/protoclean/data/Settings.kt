package app.protoclean.data

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

private val Context.dataStore by preferencesDataStore(name = "proto_clean_settings")

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

/**
 * The blocklists enabled by default — identical to the filter lists uBlock
 * Origin enables out of the box (gorhill/uBlock assets.json). uBO's extra
 * locale-based regional lists are not part of a fixed default set.
 * Must stay in sync with desktop `UBLOCK_ORIGIN_DEFAULT_LISTS`.
 */
fun defaultBlocklists(): List<BlocklistSource> = listOf(
    BlocklistSource("uBlock filters – Ads",
        "https://ublockorigin.github.io/uAssets/filters/filters.txt"),
    BlocklistSource("uBlock filters – Badware risks",
        "https://ublockorigin.github.io/uAssets/filters/badware.txt"),
    BlocklistSource("uBlock filters – Privacy",
        "https://ublockorigin.github.io/uAssets/filters/privacy.txt"),
    BlocklistSource("uBlock filters – Unbreak",
        "https://ublockorigin.github.io/uAssets/filters/unbreak.txt"),
    BlocklistSource("uBlock filters – Quick fixes",
        "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt"),
    BlocklistSource("EasyList",
        "https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt"),
    BlocklistSource("EasyPrivacy",
        "https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt"),
    BlocklistSource("Online Malicious URL Blocklist",
        "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-vivaldi-online.txt"),
    BlocklistSource("Peter Lowe's Ad and tracking server list",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
)

/** The single default list shipped before the uBlock Origin parity release. */
private val LEGACY_DEFAULT_BLOCKLIST = BlocklistSource(
    "StevenBlack unified (ads + malware)",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")

/** True when the stored set is exactly the pre-parity default (the single
 * StevenBlack entry) — such settings are upgraded to the uBlock Origin
 * defaults on load; customized lists are kept as they are. */
private fun List<BlocklistSource>.isLegacyDefault(): Boolean =
    size == 1 && this[0].enabled &&
        this[0].name == LEGACY_DEFAULT_BLOCKLIST.name &&
        this[0].url == LEGACY_DEFAULT_BLOCKLIST.url

/** Well-known lists offered as presets (same set as the desktop app): the
 * uBlock Origin defaults first, then popular aggregated hosts lists. */
val BLOCKLIST_PRESETS = defaultBlocklists().map { it.name to it.url } + listOf(
    "StevenBlack unified (ads + malware)" to
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "HaGeZi Pro — ads, tracking, malware" to
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    "HaGeZi Multi PRO++ — heavier" to
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multipro.txt",
    "OISD Big — aggregated ads/tracking" to "https://hosts.oisd.nl/big",
    "1Hosts Lite" to "https://badmojr.github.io/1hosts/Lite/hosts",
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
    // link bonding (Speedify-style multi-adapter VPN)
    val bondServer: String = "",
    val bondPort: Int = 10820,
    val bondToken: String = "",
    val bondMode: String = "bond",        // bond | balance
    // bonding-VPN upstream: the bond server, or the bundled
    // lantern-box (samizdat) engine
    val bondUpstream: String = "bond",    // bond | samizdat
    // samizdat profile (Lantern) — mirrors the desktop tab
    val samAddress: String = "",
    val samPort: Int = 443,
    val samPublicKey: String = "",
    val samShortId: String = "",
    val samServerName: String = "",
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
        val bondServer = stringPreferencesKey("bond_server")
        val bondPort = intPreferencesKey("bond_port")
        val bondToken = stringPreferencesKey("bond_token")
        val bondMode = stringPreferencesKey("bond_mode")
        val bondUpstream = stringPreferencesKey("bond_upstream")
        val samAddress = stringPreferencesKey("sam_address")
        val samPort = intPreferencesKey("sam_port")
        val samPublicKey = stringPreferencesKey("sam_public_key")
        val samShortId = stringPreferencesKey("sam_short_id")
        val samServerName = stringPreferencesKey("sam_server_name")
    }

    /** Normalized protocol value (unknown → wireguard). */
    private fun String.asProtocol(): String =
        if (this == "openvpn") "openvpn" else "wireguard"

    private fun String.asTransport(): String =
        if (this == "tcp") "tcp" else "udp"

    private fun String.asDriver(): String =
        if (this == "tap") "tap" else "tun"

    private fun String.asBondMode(): String =
        if (this == "balance") "balance" else "bond"

    private fun String.asUpstream(): String =
        if (this == "samizdat") "samizdat" else "bond"

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
            bondServer = p[Keys.bondServer] ?: "",
            bondPort = p[Keys.bondPort] ?: 10820,
            bondToken = p[Keys.bondToken] ?: "",
            bondMode = (p[Keys.bondMode] ?: "bond").asBondMode(),
            bondUpstream = (p[Keys.bondUpstream] ?: "bond").asUpstream(),
            samAddress = p[Keys.samAddress] ?: "",
            samPort = p[Keys.samPort] ?: 443,
            samPublicKey = p[Keys.samPublicKey] ?: "",
            samShortId = p[Keys.samShortId] ?: "",
            samServerName = p[Keys.samServerName] ?: "",
        )
    }

    /** Blocklist registry stored as JSON (name+url+enabled), like the desktop. */
    val blocklistSources: Flow<List<BlocklistSource>> =
        context.dataStore.data.map { p ->
            val raw = p[Keys.blocklists]
            if (raw.isNullOrBlank()) {
                defaultBlocklists()
            } else {
                runCatching {
                    JSONArray(raw).let { arr ->
                        (0 until arr.length()).map { BlocklistSource.fromJson(arr.getJSONObject(it)) }
                    }
                }.getOrDefault(emptyList()).let { lists ->
                    if (lists.isLegacyDefault()) defaultBlocklists() else lists
                }
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
                bondServer = p[Keys.bondServer] ?: "",
                bondPort = p[Keys.bondPort] ?: 10820,
                bondToken = p[Keys.bondToken] ?: "",
                bondMode = (p[Keys.bondMode] ?: "bond").asBondMode(),
                bondUpstream = (p[Keys.bondUpstream] ?: "bond").asUpstream(),
                samAddress = p[Keys.samAddress] ?: "",
                samPort = p[Keys.samPort] ?: 443,
                samPublicKey = p[Keys.samPublicKey] ?: "",
                samShortId = p[Keys.samShortId] ?: "",
                samServerName = p[Keys.samServerName] ?: "",
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
            p[Keys.bondServer] = n.bondServer
            p[Keys.bondPort] = n.bondPort
            p[Keys.bondToken] = n.bondToken
            p[Keys.bondMode] = n.bondMode.asBondMode()
            p[Keys.bondUpstream] = n.bondUpstream.asUpstream()
            p[Keys.samAddress] = n.samAddress
            p[Keys.samPort] = n.samPort
            p[Keys.samPublicKey] = n.samPublicKey
            p[Keys.samShortId] = n.samShortId
            p[Keys.samServerName] = n.samServerName
        }
    }

    suspend fun saveBlocklists(list: List<BlocklistSource>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        context.dataStore.edit { it[Keys.blocklists] = arr.toString() }
    }
}
