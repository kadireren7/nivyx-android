package app.nivyx.android.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import app.nivyx.android.core.NivyxNative
import app.nivyx.android.core.Transport
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** What Nivyx knows about the underlying (non-VPN) network. Raw identifiers never leave this class. */
data class NetworkSnapshot(
    val network: Network?,
    val transport: Transport,
    /** Salted hash identifying the network; 0 when there is no network. */
    val fingerprint: Long,
    val hasIpv6: Boolean,
    val dnsServers: List<String>,
    val validated: Boolean,
) {
    val dnsCsv: String get() = dnsServers.joinToString(",")

    /** Changes that require telling the engine. */
    fun materiallyDiffersFrom(other: NetworkSnapshot?): Boolean =
        other == null || fingerprint != other.fingerprint || hasIpv6 != other.hasIpv6 || dnsServers != other.dnsServers
}

/** One candidate underlying network, reduced to what selection needs. */
data class Candidate(val id: Int, val transport: Transport, val validated: Boolean)

/** Mirrors Android's own default-network ranking: validated first, then Ethernet > Wi-Fi > cellular. */
object NetworkChooser {
    private fun rank(t: Transport) = when (t) {
        Transport.ETHERNET -> 0
        Transport.WIFI -> 1
        Transport.CELLULAR -> 2
        else -> 3
    }

    fun pick(candidates: Collection<Candidate>): Candidate? =
        candidates.minWithOrNull(compareBy<Candidate>({ !it.validated }, { rank(it.transport) }, { it.id }))
}

/**
 * Tracks the best underlying network. While the VPN is up the system's *default* network is the VPN
 * itself, so this registers for all non-VPN internet networks and applies [NetworkChooser].
 */
class NetworkMonitor(context: Context, private val saltProvider: () -> String) {
    private val appContext = context.applicationContext
    private val cm = ContextCompat.getSystemService(appContext, ConnectivityManager::class.java)!!
    private val telephony = ContextCompat.getSystemService(appContext, TelephonyManager::class.java)
    private val networks = LinkedHashMap<Int, Network>()
    private val _snapshot = MutableStateFlow<NetworkSnapshot?>(null)
    val snapshot: StateFlow<NetworkSnapshot?> = _snapshot.asStateFlow()
    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = update { networks[network.hashCode()] = network }

        override fun onLost(network: Network) = update { networks.remove(network.hashCode()) }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = update { }

        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = update { }
    }

    @Synchronized
    fun start() {
        if (registered) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
        registered = true
    }

    @Synchronized
    fun stop() {
        if (!registered) return
        runCatching { cm.unregisterNetworkCallback(callback) }
        registered = false
        networks.clear()
        _snapshot.value = null
    }

    @Synchronized
    private fun update(mutate: () -> Unit) {
        mutate()
        val candidates = networks.values.mapNotNull { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
            Candidate(n.hashCode(), transportOf(caps), validated(caps))
        }
        val best = NetworkChooser.pick(candidates)
        val network = best?.let { b -> networks.values.firstOrNull { it.hashCode() == b.id } }
        _snapshot.value = if (best == null || network == null) {
            NetworkSnapshot(null, Transport.NONE, 0L, false, emptyList(), false)
        } else {
            describe(network, best)
        }
    }

    private fun describe(network: Network, best: Candidate): NetworkSnapshot {
        val lp = cm.getLinkProperties(network)
        val dns = lp?.dnsServers.orEmpty().mapNotNull { it.hostAddress }.sorted()
        val v4Gateway = lp?.routes.orEmpty().firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress.orEmpty()
        val v4Link = lp?.linkAddresses.orEmpty().firstOrNull { it.address is Inet4Address }
        val subnet = v4Link?.let { "${networkAddress(it.address, it.prefixLength)}/${it.prefixLength}" }.orEmpty()
        val hasV6 = lp?.linkAddresses.orEmpty().any { isGlobalV6(it.address) } &&
            lp?.routes.orEmpty().any { it.isDefaultRoute && it.destination.address is Inet6Address }
        val carrier = if (best.transport == Transport.CELLULAR) runCatching { telephony?.networkOperator }.getOrNull().orEmpty() else ""
        val fp = runCatching {
            NivyxNative.fingerprint(saltProvider(), best.transport.wire, v4Gateway, subnet, dns.joinToString(","), carrier)
        }.getOrDefault(0L)
        return NetworkSnapshot(network, best.transport, fp, hasV6, dns, best.validated)
    }

    /** NET_CAPABILITY_VALIDATED only exists from API 23; older releases cannot tell, so assume usable. */
    private fun validated(caps: NetworkCapabilities): Boolean = Build.VERSION.SDK_INT < 23 || caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)

    private fun transportOf(caps: NetworkCapabilities): Transport = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Transport.ETHERNET
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
        else -> Transport.OTHER
    }

    companion object {
        internal fun isGlobalV6(a: InetAddress): Boolean = a is Inet6Address &&
            !a.isLinkLocalAddress &&
            !a.isLoopbackAddress &&
            !a.isSiteLocalAddress &&
            (a.address[0].toInt() and 0xFE) != 0xFC

        internal fun networkAddress(a: InetAddress, prefix: Int): String {
            val bytes = a.address.copyOf()
            for (i in bytes.indices) {
                val bitsInByte = (prefix - i * 8).coerceIn(0, 8)
                val mask = if (bitsInByte == 0) 0 else (0xFF shl (8 - bitsInByte)) and 0xFF
                bytes[i] = (bytes[i].toInt() and mask).toByte()
            }
            return InetAddress.getByAddress(bytes).hostAddress.orEmpty()
        }
    }
}
