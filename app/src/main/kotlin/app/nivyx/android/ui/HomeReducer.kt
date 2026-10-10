package app.nivyx.android.ui

import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.Transport
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.vpn.NetworkSnapshot

/** Everything the home screen shows, derived from raw state by a pure function. */
data class HomeSummary(
    val protectionLabel: String,
    val active: Boolean,
    val networkLabel: String,
    val networkDetail: String,
    val dnsLabel: String,
    val dnsOk: Boolean,
    val buttonLabel: String,
    val buttonEnabled: Boolean,
    val error: String?,
    /** Starting or stopping: the ring shows a calmer teal instead of the active green. */
    val transitioning: Boolean = false,
)

object HomeReducer {
    fun reduce(status: VpnStatus, network: NetworkSnapshot?, stats: EngineStats?): HomeSummary {
        val running = status is VpnStatus.Running
        val transport = network?.transport ?: Transport.NONE
        val protectionLabel = when (status) {
            VpnStatus.Stopped -> "Inactive"
            VpnStatus.Starting -> "Starting…"
            is VpnStatus.Running -> "Active"
            VpnStatus.Stopping -> "Stopping…"
            is VpnStatus.Error -> "Inactive"
        }
        val networkDetail = when {
            !running -> "Not protected"
            transport == Transport.NONE -> "Waiting for network"
            network?.validated == false -> "Protected · no internet yet"
            else -> "Protected"
        }
        val (dnsLabel, dnsOk) = when {
            !running -> "—" to true
            stats == null -> "Checking…" to true
            !stats.dnsEncrypted -> "System DNS (not encrypted)" to true
            stats.dnsHealthy -> "Healthy" to true
            else -> "Degraded · using network DNS" to false
        }
        return HomeSummary(
            protectionLabel = protectionLabel,
            active = running,
            networkLabel = transport.label,
            networkDetail = networkDetail,
            dnsLabel = dnsLabel,
            dnsOk = dnsOk,
            buttonLabel = when (status) {
                VpnStatus.Starting -> "Starting…"
                VpnStatus.Stopping -> "Stopping…"
                is VpnStatus.Running -> "Stop"
                else -> "Start"
            },
            buttonEnabled = status !is VpnStatus.Starting && status !is VpnStatus.Stopping,
            error = (status as? VpnStatus.Error)?.message,
            transitioning = status is VpnStatus.Starting || status is VpnStatus.Stopping,
        )
    }

    fun formatUptime(seconds: Long): String = when {
        seconds < 60 -> "${seconds}s"
        seconds < 3600 -> "${seconds / 60}m ${seconds % 60}s"
        seconds < 86_400 -> "${seconds / 3600}h ${(seconds % 3600) / 60}m"
        else -> "${seconds / 86_400}d ${(seconds % 86_400) / 3600}h"
    }
}
