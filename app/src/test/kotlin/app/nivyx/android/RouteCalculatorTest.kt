package app.nivyx.android

import app.nivyx.android.core.RouteCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteCalculatorTest {
    private fun contains(routes: List<RouteCalculator.Cidr>, ip: String): Boolean {
        val v = ip.split('.').fold(0L) { a, p -> (a shl 8) or p.toLong() }
        return routes.any { r ->
            val (s, e) = RouteCalculator.toRange("${r.address}/${r.prefix}")
            v in s..e
        }
    }

    @Test fun routesCoverExactlyThePublicSpace() {
        val routes = RouteCalculator.publicIpv4()
        val covered = routes.sumOf { 1L shl (32 - it.prefix) }
        val excluded = RouteCalculator.excludedV4.sumOf {
            val (s, e) = RouteCalculator.toRange(it)
            e - s + 1
        }
        assertEquals((1L shl 32) - excluded, covered)
    }

    @Test fun routesDoNotOverlapAndAreAligned() {
        val ranges = RouteCalculator.publicIpv4().map { RouteCalculator.toRange("${it.address}/${it.prefix}") }.sortedBy { it.first }
        for (i in 1 until ranges.size) assertTrue(ranges[i].first > ranges[i - 1].second)
        for (r in RouteCalculator.publicIpv4()) {
            val (s, _) = RouteCalculator.toRange("${r.address}/${r.prefix}")
            assertEquals("${r.address}/${r.prefix} is aligned", 0L, s % (1L shl (32 - r.prefix)))
        }
    }

    @Test fun publicAddressesAreRoutedAndLanIsNot() {
        val routes = RouteCalculator.publicIpv4()
        val tunneled = listOf(
            "1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.216.34", "198.18.0.1", "198.18.0.2", "172.15.255.255",
            "172.32.0.0", "11.0.0.1", "223.255.255.255", "100.63.255.255", "100.128.0.0",
        )
        for (ip in tunneled) {
            assertTrue("$ip should enter the tunnel", contains(routes, ip))
        }
        val local = listOf(
            "10.1.2.3", "192.168.1.10", "172.16.0.1", "172.31.255.255", "169.254.1.1", "127.0.0.1",
            "224.0.0.251", "239.255.255.250", "255.255.255.255", "100.64.0.1", "0.1.2.3",
        )
        for (ip in local) {
            assertFalse("$ip must stay outside the tunnel", contains(routes, ip))
        }
    }

    @Test fun routeCountIsModest() {
        assertTrue(RouteCalculator.publicIpv4().size <= 64)
    }

    @Test fun rangeToCidrsHandlesEdges() {
        assertEquals(listOf(RouteCalculator.Cidr("1.2.3.4", 32)), RouteCalculator.rangeToCidrs(0x01020304, 0x01020304))
        assertEquals(listOf(RouteCalculator.Cidr("0.0.0.0", 0)), RouteCalculator.rangeToCidrs(0, 0xFFFF_FFFFL))
        assertEquals(2, RouteCalculator.rangeToCidrs(1, 2).size + RouteCalculator.rangeToCidrs(3, 3).size - 1)
    }
}
