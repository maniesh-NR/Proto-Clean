package app.protoclean.proton

import org.json.JSONObject

/**
 * Proton logical-server model (mirrors the desktop LogicalServer, parsed
 * from the same JSON the account web app fetches).
 */
data class LogicalServer(
    val id: String,
    val name: String,                 // e.g. "US-FREE#1"
    val entryCountry: String,
    val exitCountry: String,
    val tier: Int,                    // 0 = free
    val features: Int,
    val city: String,
    val load: Float,                  // 0..100
    val score: Float,                 // lower = better (Proton's own metric)
    val status: Int,                  // 1 = online
) {
    val isFree: Boolean get() = tier == 0
    val isOnline: Boolean get() = status == 1
    val loadLabel: String get() = "${load.toInt()}%"
    val isP2p: Boolean get() = features and 4 != 0
    val isTor: Boolean get() = features and 2 != 0

    companion object {
        fun fromJson(o: JSONObject): LogicalServer? = runCatching {
            val loc = o.optJSONObject("Location")
            LogicalServer(
                id = o.optString("ID"),
                name = o.optString("Name"),
                entryCountry = o.optString("EntryCountry"),
                exitCountry = o.optString("ExitCountry"),
                tier = o.optInt("Tier", 0),
                features = o.optInt("Features", 0),
                city = loc?.optString("City") ?: "",
                load = o.optDouble("Load", 0.0).toFloat(),
                score = if (o.isNull("Score")) 1e9f else o.optDouble("Score", 1e9).toFloat(),
                status = o.optInt("Status", 1),
            )
        }.getOrNull().takeIf { it != null && it.id.isNotBlank() }

        /**
         * Parse the logicals payload — accepts the API envelope
         * {LogicalServers: [...]} or a bare array.
         */
        fun parse(payload: String): List<LogicalServer> {
            val root = JSONObject(payload)
            val arr = when {
                root.has("LogicalServers") -> root.getJSONArray("LogicalServers")
                root.has("Servers") -> root.getJSONArray("Servers")
                else -> return emptyList()
            }
            return (0 until arr.length()).mapNotNull { fromJson(arr.getJSONObject(it)) }
        }
    }
}

/**
 * Fastest-server ranking — identical to the desktop selection logic:
 * Proton's Score first (lower = better), a load-based fallback estimate,
 * online only, tier 0 only, and saturated servers (>90%) deprioritised.
 */
object Selection {
    private const val CRITICAL_LOAD = 90f

    fun scoreOf(s: LogicalServer): Float {
        var base = if (s.score in 0.001f..1e8f) s.score else s.load / 100f
        if (!s.isOnline) return 1e9f
        if (s.load >= CRITICAL_LOAD) base += 5f
        return base
    }

    /** Free (tier 0), online servers sorted best-first — paid excluded. */
    fun rank(servers: List<LogicalServer>): List<LogicalServer> =
        servers.filter { it.isFree && it.isOnline }.sortedBy { scoreOf(it) }

    fun fastest(servers: List<LogicalServer>): LogicalServer? = rank(servers).firstOrNull()
}
