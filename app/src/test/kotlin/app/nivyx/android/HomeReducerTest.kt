package app.nivyx.android

import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.Transport
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.ui.HomeReducer
import app.nivyx.android.vpn.NetworkSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HomeReducerTest {
    private fun net(t: Transport = Transport.WIFI, validated: Boolean = true) = NetworkSnapshot(null, t, 7L, false, emptyList(), validated)

    @Test fun inactiveShowsStartAndNotProtected() {
        val s = HomeReducer.reduce(VpnStatus.Stopped, null, null)
        assertEquals("Inactive", s.protectionLabel)
        assertEquals("Start", s.buttonLabel)
        assertEquals("Not protected", s.networkDetail)
        assertFalse(s.active)
        assertTrue(s.buttonEnabled)
    }

    @Test fun activeShowsNetworkAndDns() {
        val s = HomeReducer.reduce(VpnStatus.Running(0), net(Transport.CELLULAR), EngineStats(dnsHealthy = true))
        assertEquals("Active", s.protectionLabel)
        assertEquals("Mobile data", s.networkLabel)
        assertEquals("Protected", s.networkDetail)
        assertEquals("Healthy", s.dnsLabel)
        assertEquals("Stop", s.buttonLabel)
    }

    @Test fun transitionsDisableTheButton() {
        assertFalse(HomeReducer.reduce(VpnStatus.Starting, null, null).buttonEnabled)
        assertFalse(HomeReducer.reduce(VpnStatus.Stopping, null, null).buttonEnabled)
        assertEquals("Starting…", HomeReducer.reduce(VpnStatus.Starting, null, null).protectionLabel)
    }

    @Test fun errorIsSurfacedAndStartIsOfferedAgain() {
        val s = HomeReducer.reduce(VpnStatus.Error("boom"), null, null)
        assertEquals("boom", s.error)
        assertEquals("Start", s.buttonLabel)
        assertEquals("Inactive", s.protectionLabel)
        assertNull(HomeReducer.reduce(VpnStatus.Stopped, null, null).error)
    }

    @Test fun dnsStates() {
        val run = VpnStatus.Running(0)
        assertEquals("Checking…", HomeReducer.reduce(run, net(), null).dnsLabel)
        val degraded = HomeReducer.reduce(run, net(), EngineStats(dnsHealthy = false))
        assertTrue(degraded.dnsLabel.startsWith("Degraded"))
        assertFalse(degraded.dnsOk)
        assertTrue(HomeReducer.reduce(run, net(), EngineStats(dnsEncrypted = false)).dnsLabel.startsWith("System DNS"))
    }

    @Test fun networkStates() {
        val run = VpnStatus.Running(0)
        assertEquals("Waiting for network", HomeReducer.reduce(run, net(Transport.NONE), null).networkDetail)
        assertEquals("Protected · no internet yet", HomeReducer.reduce(run, net(validated = false), null).networkDetail)
    }

    @Test fun uptimeFormatting() {
        assertEquals("5s", HomeReducer.formatUptime(5))
        assertEquals("2m 3s", HomeReducer.formatUptime(123))
        assertEquals("1h 1m", HomeReducer.formatUptime(3660))
        assertEquals("2d 1h", HomeReducer.formatUptime(2 * 86_400L + 3600))
    }
}
