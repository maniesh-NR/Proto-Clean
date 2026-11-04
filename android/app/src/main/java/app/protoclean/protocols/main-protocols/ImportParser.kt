package app.protoclean.protocols

/**
 * Share-link detection and parsing for the multi-protocol layer.
 *
 * Mirrors proto_clean/vpn/protocols/links.py (the desktop engine): the
 * Android app classifies imported text (clipboard, QR, files) into one
 * of the supported protocol schemes so the config exporter can hand it
 * to the bundled lantern-box runtime.
 */
object ImportParser {

    data class ParsedLink(
        val kind: String,          // registry kind, e.g. "hysteria2"
        val scheme: String,        // raw scheme, e.g. "hy2"
        val name: String,
        val server: String,
        val port: Int,
        val rawUrl: String
    )

    /** All schemes the import path accepts (see links.SCHEMES). */
    val SCHEMES: Set<String> = setOf(
        "ss", "ssr", "vless", "trojan", "vmess", "hysteria2", "hy2", "tuic",
        "naive", "naive+https", "masque", "dtls", "cloak", "awg", "amnezia",
        "vpn", "ikev2", "tor", "obscura", "radiance", "lampshade", "samizdat",
        "reflex", "outline", "algeneva", "water", "chain", "warp", "singbox",
        "clash"
    )

    /** scheme -> registry kind */
    private val KIND_MAP: Map<String, String> = mapOf(
        "ss" to "shadowsocks", "ssr" to "shadowsocksr",
        "hy2" to "hysteria2", "awg" to "amneziawg",
        "amnezia" to "amneziawg", "naive+https" to "naive",
        "singbox" to "boxraw", "dtls" to "coverdtls"
    )

    fun schemeOf(url: String): String? {
        val idx = url.indexOf("://")
        if (idx <= 0) return null
        val scheme = url.substring(0, idx).lowercase()
        return if (scheme in SCHEMES) scheme else null
    }

    fun kindOf(scheme: String): String = KIND_MAP[scheme] ?: scheme

    /** Extract the display name (fragment) and host:port of a link. */
    fun parse(url: String): ParsedLink? {
        val scheme = schemeOf(url) ?: return null
        var rest = url.substring(scheme.length + 3)
        var name = ""
        val hashIdx = rest.indexOf('#')
        if (hashIdx >= 0) {
            name = rest.substring(hashIdx + 1).substringBefore('\n').trim()
            rest = rest.substring(0, hashIdx)
        }
        val hostPart = rest.substringBefore('?').substringBefore('/')
        val authority = hostPart.substringAfterLast('@', "")
        val server: String
        val port: Int
        if (authority.count { it == ':' } >= 1 && authority.startsWith("[")) {
            // [v6]:port
            val close = authority.indexOf(']')
            server = authority.substring(1, close)
            port = authority.substring(close + 2).toIntOrNull()
                ?: defaultPort(scheme)
        } else if (authority.contains(':')) {
            val parts = authority.split(':')
            server = parts.dropLast(1).joinToString(":")
            port = parts.last().toIntOrNull() ?: defaultPort(scheme)
        } else {
            server = authority
            port = defaultPort(scheme)
        }
        return ParsedLink(
            kind = kindOf(scheme),
            scheme = scheme,
            name = if (name.isBlank()) defaultName(scheme) else name,
            server = server,
            port = if (port > 0) port else defaultPort(scheme),
            rawUrl = url.trim()
        )
    }

    /** Parse every link found in arbitrary text (subscriptions, files). */
    fun parseAll(text: String): List<ParsedLink> {
        val out = mutableListOf<ParsedLink>()
        val seen = mutableSetOf<String>()
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            val candidate = trimmed.trimEnd(',', '.', ';', ')')
            val parsed = parse(candidate) ?: continue
            if (parsed.rawUrl in seen) continue
            seen.add(parsed.rawUrl)
            out.add(parsed)
        }
        return out
    }

    fun defaultPort(scheme: String): Int = when (scheme) {
        "ss", "ssr" -> 8388
        "tuic", "hysteria2", "hy2", "vless", "trojan", "vmess", "masque",
        "naive", "naive+https", "radiance", "lampshade" -> 443
        "awg", "amnezia" -> 51820
        "ikev2" -> 500
        "water" -> 9003
        "algeneva" -> 9001
        "warp" -> 2408
        else -> 0
    }

    fun defaultName(scheme: String): String =
        kindOf(scheme).replaceFirstChar { it.uppercase() }

    /** True when the text looks like a whole config document. */
    fun looksLikeConfig(text: String): Boolean {
        val head = text.take(4000)
        return head.trimStart().startsWith("{") ||
            head.contains("proxies:") ||
            head.contains("[Interface]") ||
            head.trimStart().startsWith("client ")
    }
}
