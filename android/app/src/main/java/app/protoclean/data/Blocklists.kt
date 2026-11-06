package app.protoclean.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/** Status of one cached blocklist (for the management UI). */
data class BlocklistEntry(
    val name: String,
    val url: String,
    val enabled: Boolean,
    val domains: Int,
    val updatedAt: String,
    val error: String = "",
)

data class UpdateResult(
    val ok: Boolean,
    val totalDomains: Int = 0,
    val updated: List<String> = emptyList(),
    val error: String = "",
)

/** Result of parsing one blocklist, in any supported format. */
data class ParsedList(
    val blocked: Set<String>,
    val allowed: Set<String> = emptySet(),
)

/**
 * Suffix-matching domain filter — identical semantics to the desktop
 * DomainFilter: a listed domain also blocks all its subdomains. `exceptions`
 * (from @@||domain^ rules) never block; when both a block and an exception
 * match, the more specific (longer) name wins.
 */
class DomainFilter(domains: Set<String>, exceptions: Set<String> = emptySet()) {
    private val exact: Set<String> = normalize(domains)
    private val allowed: Set<String> = normalize(exceptions)

    val size: Int get() = exact.size

    fun blocked(rawName: String): Boolean {
        val name = rawName.lowercase().trimEnd('.')
        if (name.isEmpty() || name in WHITELIST) return false
        var i = 0
        while (i < name.length) {
            val suffix = name.substring(i)
            if (suffix in allowed) return false
            if (suffix in exact) return true
            i = name.indexOf('.', i).let { if (it < 0) name.length else it + 1 }
        }
        return false
    }

    companion object {
        /** Critical hosts never blocked (parity with the desktop list). */
        private val WHITELIST = setOf(
            "protonvpn.com", "proton.me", "protonmail.com", "account.protonvpn.com",
            "api.protonvpn.ch", "doh.protonvpn.ch", "protonstatus.com",
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "0.0.0.0", "127.0.0.1", "::1",
        )

        private fun normalize(domains: Set<String>): Set<String> = domains
            .map { it.trim().lowercase().trimEnd('.') }
            .filter { it.isNotEmpty() && it !in WHITELIST }
            .toSet()

        /** Cosmetic-filter marker in Adblock/uBlock lists (##, #@#, #$#, …). */
        private val COSMETIC = Regex("#[@\$%?^]*#")

        /** $options that still express a domain-level verdict at DNS level.
         * Everything else (script, image, 3p/1p, domain=, popup, redirect=,
         * removeparam, replace=, …) depends on browser context a DNS
         * filter does not have and the rule is skipped. */
        private val DNS_SAFE_OPTIONS = setOf("all", "document", "doc", "important")

        private fun dnsSafeOptions(line: String): Boolean {
            if (!line.contains('$')) return true
            // options end at the first whitespace
            val options = line.substringAfter('$').split(Regex("\\s"), 2)[0]
            return options.split(',').all { it.trim() in DNS_SAFE_OPTIONS }
        }

        /**
         * Parse hosts-format, plain domain-per-line or Adblock/uBlock
         * network-filter content (the formats of the default lists, which
         * match uBlock Origin's out-of-the-box set):
         * - `||domain^` / `||domain` → blocked
         * - `@@||domain^`            → exception (never blocked)
         * - rules whose $options are all all/document/doc/important stay
         *   applied; any other option, wildcards, URL patterns, URL-specific
         *   rules (||host/path) and cosmetic/scriptlet rules are skipped —
         *   they depend on browser context a DNS filter does not have.
         */
        fun parseList(text: String): ParsedList {
            val blocked = HashSet<String>()
            val allowed = HashSet<String>()
            for (raw in text.lineSequence()) {
                var line = raw.trim()
                if (line.isEmpty() || line.startsWith("!") || line.startsWith("[")) {
                    continue                                   // ABP/uBO comments
                }
                if (!line.startsWith("#") &&
                    (COSMETIC.containsMatchIn(line) || line.contains("\$\$"))) {
                    continue                                   // cosmetic / HTML rule
                }
                line = line.substringBefore("#").trim()        // hosts comment
                if (line.isEmpty() || !dnsSafeOptions(line)) {
                    continue                       // context-dependent $options
                }
                val exception = line.startsWith("@@")
                if (exception) {
                    line = line.substring(2).trim()
                    if (line.isEmpty()) continue
                }
                if (line.startsWith("||")) {
                    var host = line.substring(2).substringBefore("^")
                    if (host.contains('/')) {
                        // URL-specific rule — collapsing it to the bare domain
                        // would block the whole (shared) host
                        continue
                    }
                    host = host.trim('.').lowercase()
                    if (valid(host)) {
                        (if (exception) allowed else blocked).add(host)
                    }
                    continue
                }
                if (exception) continue                        // non-domain exception
                val parts = line.split(Regex("\\s+"))
                if (parts.size == 1) {
                    parts[0].lowercase().trim('.').let { if (valid(it)) blocked.add(it) }
                } else {
                    for (cand in parts.drop(1)) {
                        cand.lowercase().trim('.').let { if (valid(it)) blocked.add(it) }
                    }
                }
            }
            blocked.removeAll(WHITELIST)
            allowed.removeAll(WHITELIST)
            return ParsedList(blocked, allowed)
        }

        /** Backward-compatible alias: just the blocked set. */
        fun parseHosts(text: String): Set<String> = parseList(text).blocked

        private fun valid(name: String): Boolean =
            name.length in 4..253 && name.contains('.') &&
                name.none { it !in 'a'..'z' && it !in '0'..'9' && it !in "-._" } &&
                !name.startsWith(".") && !name.endsWith(".")
    }
}

/**
 * Blocklist manager: registry (add/remove/enable), downloads, per-URL cache
 * files and a merged filter — the same feature set as the desktop manager.
 */
class Blocklists(
    private val context: Context,
    private val settings: SettingsStore,
) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    private val cacheDir: File
        get() = File(context.cacheDir, "blocklists").apply { mkdirs() }

    private val metaFile: File get() = File(cacheDir, "meta.json")

    @Volatile
    var filter: DomainFilter = DomainFilter(emptySet())
        private set

    // ------------------------------------------------------------- registry
    suspend fun sources(): List<BlocklistSource> = settings.currentBlocklists()

    suspend fun add(name: String, url: String): UpdateResult {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return UpdateResult(false, error = "URL must start with http(s)://")
        }
        val list = sources().toMutableList()
        if (list.any { it.url == url }) {
            return UpdateResult(false, error = "that URL is already configured")
        }
        val finalName = name.ifBlank { BlocklistSource.nameFromUrl(url) }
            .let { n -> if (list.any { it.name == n }) "$n (2)" else n }
        list.add(BlocklistSource(finalName, url))
        settings.saveBlocklists(list)
        return updateOne(finalName)
    }

    suspend fun remove(name: String) {
        val list = sources().toMutableList()
        val src = list.firstOrNull { it.name == name } ?: return
        list.remove(src)
        settings.saveBlocklists(list)
        cacheFile(src.url).delete()
        val meta = loadMeta().also { it.remove(src.url) }
        saveMeta(meta)
        rebuild()
    }

    suspend fun setEnabled(name: String, enabled: Boolean) {
        val list = sources().toMutableList()
        val i = list.indexOfFirst { it.name == name }
        if (i >= 0) {
            list[i] = list[i].copy(enabled = enabled)
            settings.saveBlocklists(list)
            rebuild()
        }
    }

    // ----------------------------------------------------------- updating
    suspend fun updateOne(name: String): UpdateResult = withContext(Dispatchers.IO) {
        val src = sources().firstOrNull { it.name == name }
            ?: return@withContext UpdateResult(false, error = "no blocklist named $name")
        try {
            val body = http.newCall(Request.Builder().url(src.url).build()).execute()
                .use { resp ->
                    if (!resp.isSuccessful) error("HTTP ${resp.code}")
                    resp.body?.string() ?: error("empty body")
                }
            val parsed = DomainFilter.parseList(body)
            if (parsed.blocked.isEmpty() && parsed.allowed.isEmpty()) error("no domains parsed")
            cacheFile(src.url).writeText(body)
            val meta = loadMeta()
            meta.put(src.url, JSONObject().apply {
                put("domains", parsed.blocked.size)
                put("updated_at", stamp())
                put("error", "")
            })
            saveMeta(meta)
            rebuild()
            UpdateResult(true, totalDomains = filter.size, updated = listOf(name))
        } catch (e: Exception) {
            val meta = loadMeta()
            meta.put(src.url, JSONObject().apply {
                put("error", e.message ?: "download failed")
            })
            saveMeta(meta)
            UpdateResult(false, error = e.message ?: "download failed")
        }
    }

    suspend fun updateAll(): UpdateResult {
        var total = 0
        val updated = mutableListOf<String>()
        var lastError = ""
        for (src in sources()) {
            val r = updateOne(src.name)
            if (r.ok) { total = r.totalDomains; updated += src.name }
            else lastError = r.error
        }
        return UpdateResult(updated.isNotEmpty(), total, updated, lastError)
    }

    /** Merge the cached files of all *enabled* lists into the live filter. */
    suspend fun rebuild() = withContext(Dispatchers.IO) {
        val merged = HashSet<String>()
        val mergedAllowed = HashSet<String>()
        for (src in sources()) {
            if (!src.enabled) continue
            val f = cacheFile(src.url)
            if (f.isFile) {
                val parsed = DomainFilter.parseList(f.readText())
                merged.addAll(parsed.blocked)
                mergedAllowed.addAll(parsed.allowed)
            }
        }
        filter = DomainFilter(merged, mergedAllowed)
        filter.size
    }

    fun cacheFile(url: String): File =
        File(cacheDir, slugFor(url) + ".txt")

    fun entries(): List<BlocklistEntry> {
        val meta = loadMeta()
        return sourcesBlockedSnapshot.map { src ->
            val m = meta.optJSONObject(src.url)
            BlocklistEntry(
                name = src.name,
                url = src.url,
                enabled = src.enabled,
                domains = m?.optInt("domains", 0) ?: 0,
                updatedAt = m?.optString("updated_at", "") ?: "",
                error = m?.optString("error", "") ?: "",
            )
        }
    }

    // Registry snapshot for synchronous UI listing (kept fresh by the ViewModel).
    @Volatile
    var sourcesBlockedSnapshot: List<BlocklistSource> = emptyList()

    // ---------------------------------------------------------------- meta
    private fun loadMeta(): JSONObject {
        if (!metaFile.isFile) return JSONObject()
        return runCatching { JSONObject(metaFile.readText()) }.getOrNull() ?: JSONObject()
    }

    private fun saveMeta(meta: JSONObject) {
        metaFile.writeText(meta.toString())
    }

    private fun slugFor(url: String): String =
        url.substringAfter("//").replace(Regex("[^A-Za-z0-9]+"), "-").take(80)

    private fun stamp(): String =
        java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.ROOT)
            .format(java.util.Date())
}
