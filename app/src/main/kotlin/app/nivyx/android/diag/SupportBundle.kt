package app.nivyx.android.diag

import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.Transport
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.settings.Settings

/** Everything that goes into "Export diagnostics". Nothing personal: counts and switches only. */
data class SupportInput(
    val appVersion: String,
    val coreVersion: String,
    val androidRelease: String,
    val sdkInt: Int,
    val abis: List<String>,
    val device: String,
    val status: VpnStatus,
    val transport: Transport,
    val ipv6: Boolean,
    val stats: EngineStats?,
    val settings: Settings,
    val rawLogs: String,
)

object SupportBundle {
    /** [redact] is the native redactor (hosts removed). Logs are redacted before inclusion, always. */
    fun build(input: SupportInput, redact: (String) -> String): String {
        val s = input.settings
        val st = input.stats
        return buildString {
            appendLine("Nivyx support bundle")
            appendLine("====================")
            appendLine("App: ${input.appVersion} (core ${input.coreVersion})")
            appendLine("Android: ${input.androidRelease} (API ${input.sdkInt})")
            appendLine("Device: ${input.device}")
            appendLine("ABIs: ${input.abis.joinToString(", ")}")
            appendLine()
            appendLine("State: ${describe(input.status)}")
            appendLine("Network: ${input.transport.label}, IPv6 ${if (input.ipv6) "yes" else "no"}")
            if (st != null) {
                appendLine(
                    "DNS: ${if (st.dnsEncrypted) "encrypted" else "system"}, " +
                        "${if (st.dnsHealthy) "healthy" else "degraded"}, queries ${st.dnsQueries}, failures ${st.dnsFailures}",
                )
                appendLine(
                    "Connections: total ${st.connectionsTotal}, direct ${st.connectionsDirect}, bypassed ${st.connectionsBypassed}, " +
                        "failed ${st.connectionsFailed}, escalations ${st.escalations}, QUIC rejected ${st.quicRejected}",
                )
                appendLine("Learned scopes: ${st.strategySummary.entries.joinToString { "${it.key}=${it.value}" }.ifEmpty { "none" }}")
            }
            appendLine()
            appendLine("Config summary")
            appendLine("  resolver: ${s.resolver}")
            appendLine("  ipv6: ${s.ipv6}, quic fallback: ${s.quicFallback}, tlsrec-tcp: ${s.tlsRecTcp}")
            appendLine("  manual rules: ${s.manualRules.lines().count { it.isNotBlank() && !it.trim().startsWith("#") }}")
            appendLine("  excluded apps: ${s.excludedPackages.size}")
            appendLine("  start on boot: ${s.startOnBoot}, auto-start: ${s.autoStartOnLaunch}")
            appendLine()
            appendLine("Recent log (redacted)")
            appendLine(redact(input.rawLogs).ifBlank { "(empty)" })
        }
    }

    private fun describe(s: VpnStatus): String = when (s) {
        VpnStatus.Stopped -> "stopped"
        VpnStatus.Starting -> "starting"
        is VpnStatus.Running -> "running"
        VpnStatus.Stopping -> "stopping"
        is VpnStatus.Error -> "error"
    }
}
