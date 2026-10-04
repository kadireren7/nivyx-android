package app.nivyx.android.vpn

import app.nivyx.android.core.VpnStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Process-wide view of the service. UI and service live in the same process. */
object VpnStateHolder {
    private val _status = MutableStateFlow<VpnStatus>(VpnStatus.Stopped)
    val status: StateFlow<VpnStatus> = _status.asStateFlow()

    private val _network = MutableStateFlow<NetworkSnapshot?>(null)
    val network: StateFlow<NetworkSnapshot?> = _network.asStateFlow()

    /** Engine handle while running, 0 otherwise. */
    @Volatile
    var handle: Long = 0L
        internal set

    internal fun set(status: VpnStatus) {
        _status.value = status
    }

    internal fun setNetwork(snapshot: NetworkSnapshot?) {
        _network.value = snapshot
    }
}
