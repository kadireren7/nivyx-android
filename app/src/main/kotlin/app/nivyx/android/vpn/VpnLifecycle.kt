package app.nivyx.android.vpn

import app.nivyx.android.core.VpnStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

/** Android-free seam between the lifecycle state machine and the real TUN + native engine. */
interface VpnBackend {
    /**
     * Creates the TUN interface and starts the engine. Returns `false` when it stopped early because
     * [stillWanted] turned false. Either way (false or an exception) the controller calls [teardown],
     * so a partial result may be left for it to release.
     */
    suspend fun establish(stillWanted: () -> Boolean): Boolean

    /** Releases everything: TUN first (traffic returns to the real network at once), then the engine. Idempotent. */
    suspend fun teardown()
}

enum class Phase { STOPPED, STARTING, RUNNING, STOPPING }

/**
 * Serialized VPN lifecycle: `STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED`.
 *
 * Callers only record *intent* ([requestStart], [requestStop], [requestRestart], [abort]); a single worker
 * coroutine drives the machine toward that intent, one transition at a time. Because intent is a level (not a
 * queue of events), repeated or interleaved commands coalesce: whatever the last request was is where the machine
 * settles, and a transition is never entered twice or concurrently.
 *
 * [transitionLock] is shared by every controller in the process, so even a service instance that is being
 * destroyed cannot overlap with the next one: at most one engine and one TUN exist at any time.
 */
class VpnLifecycle(
    private val scope: CoroutineScope,
    private val backend: VpnBackend,
    private val publish: (VpnStatus) -> Unit,
    private val clock: () -> Long,
    private val transitionLock: Mutex = processLock,
    /** Called on the worker after each reconcile pass with the final intent (true = should stay running). */
    private val onSettled: suspend (wantRunning: Boolean) -> Unit = {},
    /** Called once when a [close]d controller has settled at STOPPED and its worker exits. */
    private val onClosed: () -> Unit = {},
) {
    private val wake = Channel<Unit>(Channel.CONFLATED)

    @Volatile private var wantRunning = false

    @Volatile private var restartRequested = false

    @Volatile private var abortMessage: String? = null

    @Volatile private var closed = false
    private var holdingLock = false

    @Volatile var phase: Phase = Phase.STOPPED
        private set

    val wantsRunning: Boolean get() = wantRunning

    init {
        scope.launch { workerLoop() }
    }

    fun requestStart() {
        wantRunning = true
        wake.trySend(Unit)
    }

    fun requestStop() {
        wantRunning = false
        restartRequested = false
        wake.trySend(Unit)
    }

    /** Tear down and bring up again (interface changes). Ignored unless the user still wants protection. */
    fun requestRestart() {
        if (wantRunning) restartRequested = true
        wake.trySend(Unit) // even when ignored, so an idle owner gets a chance to settle and stop itself
    }

    /** Fail open: tear everything down and report [message]. Never retries by itself. */
    fun abort(message: String) {
        abortMessage = message
        wantRunning = false
        restartRequested = false
        wake.trySend(Unit)
    }

    /** The owner is going away: settle at STOPPED, then let the worker finish. */
    fun close() {
        closed = true
        requestStop()
    }

    private suspend fun workerLoop() {
        try {
            while (true) {
                wake.receive()
                reconcile()
                onSettled(wantRunning)
                if (closed && phase == Phase.STOPPED && !wantRunning) {
                    wake.close()
                    onClosed()
                    return
                }
            }
        } catch (e: CancellationException) {
            // Cancelled while idle-but-up: still release the TUN and engine before the worker disappears.
            if (phase != Phase.STOPPED) settleStopped(null)
            throw e
        }
    }

    private suspend fun reconcile() {
        while (true) {
            if (phase == Phase.STOPPED) {
                // An abort that arrived while nothing was running still has to be reported, once.
                val aborted = abortMessage
                abortMessage = null
                if (aborted != null) {
                    publish(VpnStatus.Error(aborted))
                } else if (holdingLock && !wantRunning) {
                    // A restart gap was overtaken by a stop: it never published a final state.
                    publish(VpnStatus.Stopped)
                }
                if (holdingLock && !wantRunning) releaseLock()
            }
            val stopNow = phase == Phase.RUNNING && (!wantRunning || restartRequested || abortMessage != null)
            val startNow = phase == Phase.STOPPED && wantRunning
            when {
                stopNow -> transitionToStopped()
                startNow -> transitionToRunning()
                else -> return
            }
        }
    }

    private suspend fun transitionToRunning() {
        if (!holdingLock) {
            // Held from here until the stack is fully down again, so a replacement owner waits for us.
            transitionLock.lock()
            holdingLock = true
        }
        phase = Phase.STARTING
        publish(VpnStatus.Starting)
        try {
            if (backend.establish { wantRunning && abortMessage == null }) {
                // A non-cancellable native start can finish after the owner was cancelled; never go RUNNING then.
                currentCoroutineContext().ensureActive()
                phase = Phase.RUNNING
                publish(VpnStatus.Running(clock()))
            } else {
                // Stopped early: nothing should be left, but teardown is idempotent and cheap insurance.
                settleStopped(abortMessage.also { abortMessage = null })
            }
        } catch (e: CancellationException) {
            settleStopped(null)
            throw e
        } catch (e: Exception) {
            wantRunning = false
            restartRequested = false
            settleStopped(e.message ?: e.javaClass.simpleName)
        }
    }

    private suspend fun transitionToStopped() {
        phase = Phase.STOPPING
        val restarting = restartRequested && wantRunning && abortMessage == null
        restartRequested = false
        publish(VpnStatus.Stopping)
        settleStopped(abortMessage.also { abortMessage = null }, publishFinal = !restarting)
    }

    /** Teardown must finish even if the worker is cancelled; it is the only way internet comes back. */
    private suspend fun settleStopped(error: String?, publishFinal: Boolean = true) {
        phase = Phase.STOPPING
        withContext(NonCancellable) {
            try {
                backend.teardown()
            } catch (_: Exception) {
                // Best effort; teardown implementations close what they can and swallow the rest.
            }
        }
        phase = Phase.STOPPED
        if (publishFinal) {
            publish(if (error != null) VpnStatus.Error(error) else VpnStatus.Stopped)
            releaseLock()
        }
    }

    private fun releaseLock() {
        if (holdingLock) {
            holdingLock = false
            transitionLock.unlock()
        }
    }

    companion object {
        /** One engine/TUN transition at a time for the whole process, across service instances. */
        val processLock = Mutex()
    }
}
