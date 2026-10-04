package app.nivyx.android.core

import org.json.JSONObject

/** Lifecycle of the local VPN interface + engine. */
sealed interface VpnStatus {
    data object Stopped : VpnStatus

    data object Starting : VpnStatus

    data class Running(val sinceElapsedMs: Long) : VpnStatus

    data object Stopping : VpnStatus

    data class Error(val message: String) : VpnStatus

    val isActive: Boolean get() = this is Running || this is Starting
}

enum class Transport(val label: String, val wire: String) {
    WIFI("Wi-Fi", "wifi"),
    CELLULAR("Mobile data", "cellular"),
    ETHERNET("Ethernet", "ethernet"),
    OTHER("Other", "other"),
    NONE("No network", "none"),
}

/** Counters reported by the engine. All values are local, aggregate and free of host names. */
data class EngineStats(
    val alive: Boolean = true,
    val uptimeSeconds: Long = 0,
    val connectionsTotal: Long = 0,
    val connectionsDirect: Long = 0,
    val connectionsBypassed: Long = 0,
    val connectionsFailed: Long = 0,
    val strategyTlsRec: Long = 0,
    val strategyTlsRecTcp: Long = 0,
    val escalations: Long = 0,
    val flowsActive: Long = 0,
    val dnsQueries: Long = 0,
    val dnsFailures: Long = 0,
    val dnsHealthy: Boolean = true,
    val dnsEncrypted: Boolean = true,
    val quicRejected: Long = 0,
    val ipv6Active: Boolean = false,
    val activeStrategies: Int = 0,
    val strategySummary: Map<String, Int> = emptyMap(),
) {
    companion object {
        /** Tolerant parser: unknown or missing fields fall back to defaults; garbage yields `null`. */
        fun parse(json: String): EngineStats? = runCatching {
            val root = JSONObject(json)
            if (!root.has("stats")) return null
            val s = root.getJSONObject("stats")
            val dns = root.optJSONObject("dns")
            val summaryJson = root.optJSONObject("strategy_summary")
            val summary = buildMap {
                summaryJson?.keys()?.forEach { put(it, summaryJson.optInt(it)) }
            }
            EngineStats(
                alive = root.optBoolean("alive", true),
                uptimeSeconds = root.optLong("uptime_s"),
                connectionsTotal = s.optLong("connections_total"),
                connectionsDirect = s.optLong("connections_direct"),
                connectionsBypassed = s.optLong("connections_bypassed"),
                connectionsFailed = s.optLong("connections_failed"),
                strategyTlsRec = s.optLong("strategy_tlsrec"),
                strategyTlsRecTcp = s.optLong("strategy_tlsrec_tcp"),
                escalations = s.optLong("escalations"),
                flowsActive = s.optLong("flows_active"),
                dnsQueries = s.optLong("dns_queries"),
                dnsFailures = s.optLong("dns_failures"),
                dnsHealthy = dns?.optBoolean("healthy", true) ?: true,
                dnsEncrypted = dns?.optBoolean("encrypted", true) ?: true,
                quicRejected = s.optLong("quic_rejected"),
                ipv6Active = root.optBoolean("ipv6_active"),
                activeStrategies = summary.filterKeys { !it.startsWith("direct-good") }.values.sum(),
                strategySummary = summary,
            )
        }.getOrNull()
    }
}
