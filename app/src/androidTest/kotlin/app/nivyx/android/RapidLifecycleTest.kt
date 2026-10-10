package app.nivyx.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.vpn.NivyxVpnService
import app.nivyx.android.vpn.VpnStateHolder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.random.Random

/**
 * Drives the real [NivyxVpnService] (real TUN, real native engine) with rapid, overlapping commands.
 * VPN consent is pre-granted through the shell appop, so no dialog is involved.
 */
@RunWith(AndroidJUnit4::class)
class RapidLifecycleTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val ctx: Context = instrumentation.targetContext

    @Before fun grantConsentAndReset() {
        shell("appops set ${ctx.packageName} ACTIVATE_VPN allow")
        assumeTrue("VPN consent could not be pre-granted", VpnService.prepare(ctx) == null)
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
    }

    private fun shell(cmd: String): String {
        val pfd = instrumentation.uiAutomation.executeShellCommand(cmd)
        return java.io.FileInputStream(pfd.fileDescriptor).bufferedReader().readText().also { pfd.close() }
    }

    private fun tunLines(): List<String> = shell("ip -o addr show").lines().filter { "198.18.0.2" in it }

    /** Descriptors this process still holds on /dev/tun (the app and the instrumentation share a process). */
    private fun ownTunFds(): List<String> = java.io.File("/proc/self/fd").listFiles().orEmpty()
        .filter { runCatching { it.canonicalPath }.getOrDefault("").contains("tun") }
        .map { it.name }

    private fun tunCount(): Int = tunLines().size

    private fun vpnActive(): Boolean {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }

    /** Waits for the machine to settle in the expected stable state and then verifies it stays there. */
    private fun awaitFinal(running: Boolean) {
        val deadline = System.currentTimeMillis() + 30_000
        fun reached() = if (running) VpnStateHolder.status.value is VpnStatus.Running else VpnStateHolder.status.value is VpnStatus.Stopped
        while (!reached() && System.currentTimeMillis() < deadline) Thread.sleep(50)
        assertTrue("never reached running=$running, stuck at ${VpnStateHolder.status.value}", reached())
        Thread.sleep(1500) // must not flip afterwards (no late start/stop from a queued command)
        assertTrue("state flipped after settling: ${VpnStateHolder.status.value}", reached())
    }

    private fun assertRunningCleanly() {
        assertEquals("exactly one TUN: ${tunLines()} ownFds=${ownTunFds()}", 1, tunCount())
        assertTrue("engine handle missing", VpnStateHolder.handle != 0L)
        assertTrue(vpnActive())
    }

    private fun assertStoppedCleanly() {
        assertEquals("TUN left behind: ${tunLines()} ownFds=${ownTunFds()} status=${VpnStateHolder.status.value}", 0, tunCount())
        assertEquals("engine handle left behind", 0L, VpnStateHolder.handle)
        assertFalse("VPN network still present (internet would be routed into a dead TUN)", vpnActive())
    }

    @Test fun startThenStop() {
        NivyxVpnService.start(ctx)
        awaitFinal(running = true)
        assertRunningCleanly()
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
        assertStoppedCleanly()
    }

    @Test fun duplicateStarts() {
        repeat(5) { NivyxVpnService.start(ctx) }
        awaitFinal(running = true)
        assertRunningCleanly()
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
        assertStoppedCleanly()
    }

    @Test fun startImmediatelyFollowedByStop() {
        NivyxVpnService.start(ctx)
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
        assertStoppedCleanly()
    }

    @Test fun startStopStartEndsRunning() {
        NivyxVpnService.start(ctx)
        NivyxVpnService.stop(ctx)
        NivyxVpnService.start(ctx)
        awaitFinal(running = true)
        assertRunningCleanly()
    }

    @Test fun twentyRapidAlternatingCommands() {
        repeat(20) { i -> if (i % 2 == 0) NivyxVpnService.start(ctx) else NivyxVpnService.stop(ctx) }
        awaitFinal(running = false) // last command (index 19) is a stop
        assertStoppedCleanly()
    }

    @Test fun twentyOneRapidAlternatingCommandsEndRunning() {
        repeat(21) { i -> if (i % 2 == 0) NivyxVpnService.start(ctx) else NivyxVpnService.stop(ctx) }
        awaitFinal(running = true)
        assertRunningCleanly()
    }

    @Test fun randomizedStormsWithJitter() {
        for (seed in 0 until 6) {
            val rnd = Random(seed)
            var want = false
            repeat(25) {
                want = rnd.nextBoolean()
                if (want) NivyxVpnService.start(ctx) else NivyxVpnService.stop(ctx)
                if (rnd.nextInt(3) == 0) Thread.sleep(rnd.nextLong(0, 250))
            }
            awaitFinal(running = want)
            if (want) assertRunningCleanly() else assertStoppedCleanly()
        }
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
        assertStoppedCleanly()
    }

    @Test fun restartRebuildsExactlyOneTun() {
        NivyxVpnService.start(ctx)
        awaitFinal(running = true)
        repeat(3) { NivyxVpnService.restart(ctx) }
        awaitFinal(running = true)
        assertRunningCleanly()
        NivyxVpnService.stop(ctx)
        awaitFinal(running = false)
        assertStoppedCleanly()
    }
}
