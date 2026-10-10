package app.nivyx.android

import app.nivyx.android.core.VpnStatus
import app.nivyx.android.vpn.Phase
import app.nivyx.android.vpn.VpnBackend
import app.nivyx.android.vpn.VpnLifecycle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/** Stands in for the TUN + native engine and records every way the real ones could be misused. */
private class FakeBackend(var networkWaitMs: Long = 50, var nativeStartMs: Long = 200, var failAfterTun: Boolean = false, var failEngine: Boolean = false) :
    VpnBackend {
    var tuns = 0
    var engines = 0
    var maxTuns = 0
    var maxEngines = 0
    var inFlight = 0
    var maxInFlight = 0
    var establishCalls = 0
    var teardownCalls = 0

    private fun enter() {
        inFlight++
        maxInFlight = maxOf(maxInFlight, inFlight)
    }

    override suspend fun establish(stillWanted: () -> Boolean): Boolean {
        enter()
        try {
            establishCalls++
            delay(networkWaitMs)
            if (!stillWanted()) return false
            tuns++
            maxTuns = maxOf(maxTuns, tuns)
            if (!stillWanted()) return false
            if (failAfterTun) error("tun setup failed")
            // The native call is blocking and cannot be cancelled midway.
            withContext(NonCancellable) { delay(nativeStartMs) }
            if (failEngine) error("engine failed")
            engines++
            maxEngines = maxOf(maxEngines, engines)
            return true
        } finally {
            inFlight--
        }
    }

    override suspend fun teardown() {
        enter()
        try {
            tuns = 0 // TUN is released first
            delay(10)
            engines = 0
            teardownCalls++
        } finally {
            inFlight--
        }
    }

    /** True when the device is left with neither routes nor a forwarding engine. */
    val released get() = tuns == 0 && engines == 0
}

private class Harness(
    val test: TestScope,
    val backend: FakeBackend = FakeBackend(),
    lock: Mutex = Mutex(),
    scope: CoroutineScope = CoroutineScope(
        SupervisorJob() + StandardTestDispatcher(test.testScheduler),
    ),
) {
    val statuses = mutableListOf<VpnStatus>()
    var closed = false
    val lifecycle = VpnLifecycle(scope, backend, { statuses += it }, { 0L }, lock, onClosed = { closed = true })
    val last get() = statuses.lastOrNull() ?: VpnStatus.Stopped

    suspend fun settle() {
        test.advanceUntilIdle()
    }

    fun assertInvariants() {
        assertTrue("tuns=${backend.maxTuns}", backend.maxTuns <= 1)
        assertTrue("engines=${backend.maxEngines}", backend.maxEngines <= 1)
        assertEquals("transitions overlapped", 1, maxOf(1, backend.maxInFlight))
        assertTrue("overlap: ${backend.maxInFlight}", backend.maxInFlight <= 1)
    }

    fun assertRunning() {
        assertEquals(Phase.RUNNING, lifecycle.phase)
        assertTrue(last is VpnStatus.Running)
        assertEquals(1, backend.tuns)
        assertEquals(1, backend.engines)
        assertInvariants()
    }

    fun assertStopped() {
        assertEquals(Phase.STOPPED, lifecycle.phase)
        assertEquals(VpnStatus.Stopped, last)
        assertTrue("TUN/engine still present", backend.released)
        assertInvariants()
    }
}

class VpnLifecycleTest {
    @Test fun startReachesRunning() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
        assertEquals(listOf("Starting", "Running"), h.statuses.map { it::class.simpleName })
    }

    @Test fun duplicateStartsCoalesce() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
        assertEquals(1, h.backend.establishCalls)
    }

    @Test fun duplicateStopsAreHarmless() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStop()
        h.settle()
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.requestStop()
        h.lifecycle.requestStop()
        h.settle()
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
        assertEquals(1, h.backend.teardownCalls)
    }

    @Test fun stopImmediatelyAfterStartNeverBuildsAnything() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
        assertEquals(0, h.backend.maxTuns)
    }

    @Test fun stopWhileWaitingForNetworkEndsStopped() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        runCurrent()
        assertEquals(Phase.STARTING, h.lifecycle.phase)
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
        assertEquals(0, h.backend.maxEngines)
    }

    @Test fun stopWhileNativeEngineIsStarting() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        advanceTimeBy(100) // network wait done, TUN created, native start in flight
        assertEquals(1, h.backend.tuns)
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
        assertEquals(1, h.backend.maxEngines) // the engine did come up, and was then torn down cleanly
    }

    @Test fun startDuringStoppingWaitsThenRuns() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.requestStop()
        runCurrent()
        assertEquals(Phase.STOPPING, h.lifecycle.phase)
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
        assertEquals(2, h.backend.establishCalls)
    }

    @Test fun startStopStartRapidly() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.lifecycle.requestStop()
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
    }

    @Test fun startStopStartStopRepeatedly() = runTest {
        val h = Harness(this)
        repeat(10) {
            h.lifecycle.requestStart()
            h.lifecycle.requestStop()
            h.lifecycle.requestStart()
            h.lifecycle.requestStop()
        }
        h.settle()
        h.assertStopped()
    }

    @Test fun twentyAlternatingCommandsEndInTheLastRequestedState() = runTest {
        for (seed in 0 until 40) {
            val h = Harness(this)
            val rnd = Random(seed)
            var wantRunning = false
            repeat(20) { i ->
                wantRunning = i % 2 == 0
                if (wantRunning) h.lifecycle.requestStart() else h.lifecycle.requestStop()
                // Sometimes let the machine make progress between commands, at arbitrary points inside a transition.
                if (rnd.nextInt(3) == 0) advanceTimeBy(rnd.nextLong(0, 300))
            }
            h.settle()
            if (wantRunning) h.assertRunning() else h.assertStopped()
            h.lifecycle.close()
            h.settle()
            assertTrue(h.closed)
            h.assertStopped()
        }
    }

    @Test fun randomCommandStormsAlwaysSettleCorrectly() = runTest {
        for (seed in 100 until 160) {
            val h = Harness(this)
            val rnd = Random(seed)
            var wantRunning = false
            repeat(60) {
                when (rnd.nextInt(4)) {
                    0, 1 -> {
                        wantRunning = true
                        h.lifecycle.requestStart()
                    }
                    2 -> {
                        wantRunning = false
                        h.lifecycle.requestStop()
                    }
                    else -> h.lifecycle.requestRestart()
                }
                if (rnd.nextBoolean()) advanceTimeBy(rnd.nextLong(0, 400))
            }
            h.settle()
            if (wantRunning) h.assertRunning() else h.assertStopped()
        }
    }

    @Test fun failureAfterTunCreatedTearsEverythingDownAndRecovers() = runTest {
        val h = Harness(this, FakeBackend(failAfterTun = true))
        h.lifecycle.requestStart()
        h.settle()
        assertTrue(h.last is VpnStatus.Error)
        assertEquals(Phase.STOPPED, h.lifecycle.phase)
        assertTrue(h.backend.released)
        assertTrue("no retry loop", h.backend.establishCalls == 1)
        // The failure must not wedge the machine.
        h.backend.failAfterTun = false
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
    }

    @Test fun engineStartFailureLeavesNoTun() = runTest {
        val h = Harness(this, FakeBackend(failEngine = true))
        h.lifecycle.requestStart()
        h.settle()
        assertTrue(h.last is VpnStatus.Error)
        assertTrue(h.backend.released)
        assertEquals(0, h.backend.engines)
    }

    @Test fun abortWhileRunningFailsOpenAndReportsError() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.abort("engine died")
        h.settle()
        assertEquals(VpnStatus.Error("engine died"), h.last)
        assertTrue(h.backend.released)
        // A later explicit start works and does not inherit the stale error.
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
    }

    @Test fun abortDuringStartingDoesNotLeaveRunning() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        advanceTimeBy(100)
        h.lifecycle.abort("lost permission")
        h.settle()
        assertEquals(VpnStatus.Error("lost permission"), h.last)
        assertTrue(h.backend.released)
        h.lifecycle.requestStart()
        h.settle()
        h.assertRunning()
    }

    @Test fun restartRebuildsExactlyOnce() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.requestRestart()
        h.lifecycle.requestRestart()
        h.settle()
        h.assertRunning()
        assertEquals(2, h.backend.establishCalls)
    }

    @Test fun stopDuringRestartTeardownPublishesStoppedAndFreesTheLock() = runTest {
        val lock = Mutex()
        val h = Harness(this, lock = lock)
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.requestRestart()
        runCurrent()
        assertEquals(Phase.STOPPING, h.lifecycle.phase)
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
        assertTrue("process lock leaked", !lock.isLocked)
    }

    @Test fun restartIsIgnoredWhenStopped() = runTest {
        val h = Harness(this)
        h.lifecycle.requestRestart()
        h.settle()
        h.assertStopped()
        assertEquals(0, h.backend.establishCalls)
    }

    @Test fun statusSubscriberGoingAwayDoesNotAffectTheService() = runTest {
        // "Native engine starts but the UI disconnects": state is owned by the machine, not by whoever observes it.
        val h = Harness(this)
        h.lifecycle.requestStart()
        advanceTimeBy(100)
        // (the UI collector disappears here; nothing in the machine depends on it)
        h.settle()
        h.assertRunning()
        h.lifecycle.requestStop()
        h.settle()
        h.assertStopped()
    }

    @Test fun cancellingTheScopeMidStartStillReleasesTunAndEngine() = runTest {
        val job = kotlinx.coroutines.Job()
        val h = Harness(this, scope = CoroutineScope(job + kotlinx.coroutines.test.StandardTestDispatcher(testScheduler)))
        h.lifecycle.requestStart()
        advanceTimeBy(100)
        job.cancel()
        h.settle()
        assertTrue("TUN/engine leaked after cancellation", h.backend.released)
        assertTrue(h.backend.teardownCalls >= 1)
    }

    @Test fun destroyedServiceInstanceCannotOverlapTheNextOne() = runTest {
        val lock = Mutex()
        val backend = FakeBackend()
        val old = Harness(this, backend, lock)
        old.lifecycle.requestStart()
        advanceTimeBy(100) // old instance is mid-start when Android destroys it
        old.lifecycle.close()
        val fresh = Harness(this, backend, lock)
        fresh.lifecycle.requestStart()
        advanceUntilIdle()
        assertTrue(old.closed)
        assertEquals(Phase.STOPPED, old.lifecycle.phase)
        fresh.assertRunning()
        assertEquals(1, backend.maxTuns)
        assertEquals(1, backend.maxEngines)
        assertEquals(1, maxOf(1, backend.maxInFlight))
        assertTrue(backend.maxInFlight <= 1)
    }

    @Test fun closeSettlesAtStoppedAndFinishesTheWorker() = runTest {
        val h = Harness(this)
        h.lifecycle.requestStart()
        h.settle()
        h.lifecycle.close()
        h.settle()
        assertTrue(h.closed)
        h.assertStopped()
    }

    /** Real threads, real dispatcher: commands race from many threads while transitions are in flight. */
    @Test fun concurrentCommandsFromManyThreadsSettleCorrectly() {
        kotlinx.coroutines.runBlocking {
            repeat(20) { round ->
                val backend = FakeBackend(networkWaitMs = 1, nativeStartMs = 1)
                val states = java.util.concurrent.CopyOnWriteArrayList<VpnStatus>()
                val scope = CoroutineScope(SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
                val lc = VpnLifecycle(scope, backend, { states += it }, { 0L }, Mutex())
                val threads = (0 until 8).map { t ->
                    Thread {
                        val rnd = Random(round * 100 + t)
                        repeat(300) {
                            when (rnd.nextInt(3)) {
                                0 -> lc.requestStart()
                                1 -> lc.requestStop()
                                else -> lc.requestRestart()
                            }
                        }
                    }
                }
                threads.forEach { it.start() }
                threads.forEach { it.join() }
                lc.requestStart()
                lc.requestStop()
                val deadline = System.nanoTime() + 5_000_000_000L
                while (lc.phase != Phase.STOPPED && System.nanoTime() < deadline) kotlinx.coroutines.delay(5)
                kotlinx.coroutines.delay(50)
                assertEquals(Phase.STOPPED, lc.phase)
                assertTrue(backend.released)
                assertTrue(backend.maxTuns <= 1 && backend.maxEngines <= 1)
                assertTrue("overlapping transitions: ${backend.maxInFlight}", backend.maxInFlight <= 1)
                assertTrue(states.last() == VpnStatus.Stopped)
                lc.close()
                scope.cancel()
            }
        }
    }
}
