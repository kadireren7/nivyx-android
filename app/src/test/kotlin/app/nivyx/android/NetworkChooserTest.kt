package app.nivyx.android

import app.nivyx.android.core.Transport
import app.nivyx.android.vpn.Candidate
import app.nivyx.android.vpn.NetworkChooser
import app.nivyx.android.vpn.NetworkMonitor
import app.nivyx.android.vpn.NetworkSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class NetworkChooserTest {
    private fun c(id: Int, t: Transport, ok: Boolean = true) = Candidate(id, t, ok)

    @Test fun prefersValidatedThenWifiOverCellular() {
        assertEquals(2, NetworkChooser.pick(listOf(c(1, Transport.CELLULAR), c(2, Transport.WIFI)))?.id)
        assertEquals(1, NetworkChooser.pick(listOf(c(1, Transport.CELLULAR), c(2, Transport.WIFI, ok = false)))?.id)
        assertEquals(3, NetworkChooser.pick(listOf(c(1, Transport.WIFI), c(3, Transport.ETHERNET)))?.id)
    }

    @Test fun emptyAndTieBreak() {
        assertNull(NetworkChooser.pick(emptyList()))
        assertEquals(1, NetworkChooser.pick(listOf(c(2, Transport.WIFI), c(1, Transport.WIFI)))?.id)
    }

    @Test fun snapshotChangeDetection() {
        val a = NetworkSnapshot(null, Transport.WIFI, 1, false, listOf("1.1.1.1"), true)
        assertFalse(a.materiallyDiffersFrom(a.copy(validated = false)))
        assertTrue(a.materiallyDiffersFrom(a.copy(fingerprint = 2)))
        assertTrue(a.materiallyDiffersFrom(a.copy(hasIpv6 = true)))
        assertTrue(a.materiallyDiffersFrom(a.copy(dnsServers = listOf("9.9.9.9"))))
        assertTrue(a.materiallyDiffersFrom(null))
    }

    @Test fun networkAddressMasksCorrectly() {
        assertEquals("192.168.1.0", NetworkMonitor.networkAddress(InetAddress.getByName("192.168.1.77"), 24))
        assertEquals("10.0.0.0", NetworkMonitor.networkAddress(InetAddress.getByName("10.200.3.4"), 8))
        assertEquals("172.16.0.0", NetworkMonitor.networkAddress(InetAddress.getByName("172.17.5.5"), 12))
        assertEquals("192.168.1.64", NetworkMonitor.networkAddress(InetAddress.getByName("192.168.1.100"), 26))
    }

    @Test fun globalIpv6Detection() {
        assertTrue(NetworkMonitor.isGlobalV6(InetAddress.getByName("2606:4700:4700::1111")))
        assertFalse(NetworkMonitor.isGlobalV6(InetAddress.getByName("fe80::1")))
        assertFalse(NetworkMonitor.isGlobalV6(InetAddress.getByName("fd12:3456::1")))
        assertFalse(NetworkMonitor.isGlobalV6(InetAddress.getByName("::1")))
        assertFalse(NetworkMonitor.isGlobalV6(InetAddress.getByName("192.168.1.1")))
    }
}
