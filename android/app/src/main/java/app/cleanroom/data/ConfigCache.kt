package app.cleanroom.data

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Local cache of downloaded WireGuard configs — same contract as the
 * desktop ConfigCache:
 *
 *  * a config is downloaded once and reused from the cache;
 *  * it is downloaded again ONLY when the saved config fails (the tunnel
 *    never completes a handshake — e.g. the certificate was revoked
 *    server-side);
 *  * entries carry a fingerprint of the options baked into the file
 *    (VPN Accelerator / NAT-PMP comments), but any cached variant for the
 *    server is acceptable: options only change comments.
 */
class ConfigCache(context: Context) {

    private val root: File = File(context.filesDir, "configs").apply { mkdirs() }
    private val indexFile: File get() = File(root, "index.json")

    data class Cached(
        val text: String,
        val server: String,
        val fingerprint: String,
        val exact: Boolean,
        val verifiedAt: Long,
        val failures: Int,
        val source: String,
    )

    fun slugify(name: String): String =
        name.lowercase().map { if (it.isLetterOrDigit()) it else '-' }
            .joinToString("").trim('-').ifBlank { "server" }

    private fun index(): JSONObject {
        if (!indexFile.isFile) return JSONObject()
        return runCatching { JSONObject(indexFile.readText()) }.getOrNull()
            ?: JSONObject()
    }

    private fun saveIndex(idx: JSONObject) {
        indexFile.writeText(idx.toString())
    }

    fun get(serverName: String, fingerprint: String? = null): Cached? {
        val idx = index()
        val rec = idx.optJSONObject(slugify(serverName)) ?: return null
        val entries = rec.optJSONObject("entries") ?: return null
        var fp = fingerprint
        var exact = true
        if (fp == null || entries.isNull(fp) || !entries.has(fp)) {
            // fall back to the most recently created variant
            fp = entries.keys().asSequence().maxByOrNull {
                entries.optJSONObject(it)?.optLong("created", 0) ?: 0
            } ?: return null
            exact = false
        }
        val e = entries.optJSONObject(fp) ?: return null
        val file = File(root, e.optString("file"))
        if (!file.isFile) return null
        val text = file.readText()
        if (!text.contains("[Interface]")) return null
        return Cached(
            text = text,
            server = rec.optString("server", serverName),
            fingerprint = fp,
            exact = exact,
            verifiedAt = e.optLong("verified_at", 0),
            failures = e.optInt("failures", 0),
            source = e.optString("source", "downloaded"),
        )
    }

    fun put(serverName: String, text: String, fingerprint: String,
            source: String = "downloaded") {
        val slug = slugify(serverName)
        val fname = "$slug.$fingerprint.conf"
        File(root, fname).writeText(text)
        val idx = index()
        val rec = idx.optJSONObject(slug) ?: JSONObject().also {
            idx.put(slug, it)
        }
        rec.put("server", serverName)
        val entries = rec.optJSONObject("entries") ?: JSONObject().also {
            rec.put("entries", it)
        }
        entries.put(fingerprint, JSONObject().apply {
            put("file", fname)
            put("created", System.currentTimeMillis() / 1000L)
            put("verified_at", 0L)
            put("failures", 0)
            put("source", source)
        })
        saveIndex(idx)
    }

    /** Drop every cached variant for a server (its saved config failed). */
    fun invalidate(serverName: String) {
        val slug = slugify(serverName)
        val idx = index()
        val rec = idx.optJSONObject(slug) ?: return
        val entries = rec.optJSONObject("entries") ?: JSONObject()
        entries.keys().asSequence().forEach { key ->
            entries.optJSONObject(key)?.optString("file")?.let {
                File(root, it).delete()
            }
        }
        idx.remove(slug)
        saveIndex(idx)
    }

    fun markVerified(serverName: String, fingerprint: String? = null) {
        mutateEntry(serverName, fingerprint) { it.put("verified_at", System.currentTimeMillis() / 1000L) }
    }

    fun noteFailure(serverName: String, fingerprint: String? = null) {
        mutateEntry(serverName, fingerprint) {
            it.put("failures", it.optInt("failures", 0) + 1)
        }
    }

    private fun mutateEntry(serverName: String, fingerprint: String?,
                            transform: (JSONObject) -> Unit) {
        val slug = slugify(serverName)
        val idx = index()
        val rec = idx.optJSONObject(slug) ?: return
        val entries = rec.optJSONObject("entries") ?: return
        val targets = if (fingerprint != null && entries.has(fingerprint)) {
            listOf(fingerprint)
        } else entries.keys().asSequence().toList()
        targets.forEach { key ->
            entries.optJSONObject(key)?.let { transform(it) }
        }
        saveIndex(idx)
    }

    fun size(): Int = index().let { idx ->
        idx.keys().asSequence().sumOf { slug ->
            idx.optJSONObject(slug)?.optJSONObject("entries")?.length() ?: 0
        }
    }

    fun purge() {
        root.listFiles()?.forEach { if (it.name != "index.json") it.delete() }
        saveIndex(JSONObject())
    }

    companion object {
        /** Options that were baked into a generated file (comments). */
        fun fingerprint(accelerator: Boolean, natPmp: Boolean): String =
            "acc${if (accelerator) 1 else 0}-nat${if (natPmp) 1 else 0}"

        fun parseServerName(text: String): String? {
            Regex("^\\s*#\\s*([A-Z]{2}(?:-[A-Z]{2})?-[A-Z0-9]+#\\d+)\\s*$",
                RegexOption.MULTILINE).find(text)?.let { return it.groupValues[1] }
            return null
        }
    }
}
