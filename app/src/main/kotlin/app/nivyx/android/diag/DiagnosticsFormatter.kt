package app.nivyx.android.diag

import org.json.JSONObject

/** Turns the engine's diagnostics JSON into the human-readable report shown (and copied) in the app. */
object DiagnosticsFormatter {
    fun format(json: String): String {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return "Diagnostics unavailable."
        root.optString("error").takeIf { it.isNotEmpty() }?.let { return "Diagnostics failed: $it" }
        val host = root.optString("host")
        val sb = StringBuilder("Diagnose: $host\n")

        val dns = root.optJSONObject("dns")
        sb.append("\nDNS\n")
        if (dns != null) {
            val doh = dns.optJSONObject("doh")
            if (doh?.optBoolean("ok") == true) {
                sb.append("  Resolver: DoH (${doh.optString("resolver")}, ${doh.optLong("ms")} ms)\n")
                sb.append("  Address: ${addresses(doh)}\n")
            } else {
                sb.append("  Resolver: DoH unavailable (${doh?.optString("error").orEmpty().ifEmpty { "no answer" }})\n")
            }
            val sys = dns.optJSONObject("system")
            if (sys?.optBoolean("ok") == true) {
                sb.append("  Network resolver: ${addresses(sys)}\n")
            } else {
                sb.append("  Network resolver: no answer\n")
            }
            sb.append("  Poisoning suspected: ${dns.optString("poisoning_suspected", "unknown")}\n")
        }

        val https = root.optJSONObject("https")
        sb.append("\nHTTPS\n")
        if (https == null || https.has("error")) {
            sb.append("  ${https?.optString("error") ?: "not tested"}\n")
        } else {
            sb.append("  Target: ${https.optString("address")}\n")
            for ((key, label) in listOf("direct" to "Direct", "tlsrec" to "Strategy tlsrec", "tlsrec-tcp" to "Strategy tlsrec-tcp")) {
                sb.append("  $label: ${probe(https.optJSONObject(key))}\n")
            }
            sb.append("  Result: ${verdict(https)}\n")
        }

        val d = root.optJSONObject("decision")
        sb.append("\nDecision\n")
        if (d != null) {
            sb.append("  Source: ${d.optString("source")}\n")
            sb.append("  State: ${d.optString("state")}\n")
            val ladder = d.optJSONArray("ladder")
            val steps = (0 until (ladder?.length() ?: 0)).joinToString(" → ") { ladder!!.getString(it) }
            sb.append("  Strategy order: $steps\n")
            sb.append("  TTL: ${ttl(d.optLong("ttl_remaining_s"))}\n")
        }
        return sb.toString().trimEnd()
    }

    private fun addresses(o: JSONObject): String {
        val a = o.optJSONArray("addresses") ?: return "none"
        return (0 until a.length()).joinToString(", ") { a.getString(it) }.ifEmpty { "none" }
    }

    private fun probe(o: JSONObject?): String = when {
        o == null -> "not tested"
        o.optBoolean("ok") -> "OK (${o.optLong("ms")} ms)"
        else -> "failed at ${o.optString("stage", "?")} (${o.optString("error", "unknown error")})"
    }

    private fun verdict(https: JSONObject): String {
        val direct = https.optJSONObject("direct")?.optBoolean("ok") == true
        val bypass = https.optJSONObject("tlsrec")?.optBoolean("ok") == true || https.optJSONObject("tlsrec-tcp")?.optBoolean("ok") == true
        return when {
            direct -> "reachable directly; no bypass needed"
            bypass -> "blocked directly, reachable with TLS record splitting"
            else -> "not reachable by any strategy (host may be down or blocked at IP level)"
        }
    }

    fun ttl(seconds: Long): String = when {
        seconds <= 0 -> "n/a"
        seconds < 60 -> "${seconds}s"
        seconds < 3600 -> "${seconds / 60}m"
        else -> "${seconds / 3600}h ${(seconds % 3600) / 60}m"
    }
}
