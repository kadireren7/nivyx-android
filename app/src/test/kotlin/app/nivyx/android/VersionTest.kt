package app.nivyx.android

import app.nivyx.android.update.Version
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VersionTest {
    private fun v(s: String) = Version.parse(s) ?: error("unparsable $s")

    @Test fun parsesPlainAndPrefixed() {
        assertEquals(Version(1, 2, 3), v("1.2.3"))
        assertEquals(Version(1, 2, 3), v("v1.2.3"))
        assertEquals(Version(0, 9, 0, listOf("rc", "1")), v("v0.9.0-rc.1"))
        assertEquals(Version(0, 9, 0, listOf("rc1")), v("0.9.0-rc1+build.5"))
    }

    @Test fun rejectsGarbage() {
        for (bad in listOf("", "1", "1.2", "1.2.3.4", "a.b.c", "01.2.3", "1.2.3-", "1.2.3-a..b", "v", "1.2.-3", "1.2.3 ; rm -rf", "9999999.0.0")) {
            assertNull(bad, Version.parse(bad))
        }
    }

    @Test fun ordersNumerically() {
        assertTrue(v("1.10.0") > v("1.9.9"))
        assertTrue(v("2.0.0") > v("1.99.99"))
        assertTrue(v("0.1.1") > v("0.1.0"))
        assertEquals(0, v("1.2.3").compareTo(v("v1.2.3+meta")))
    }

    @Test fun preReleasesSortBeforeReleaseAndBySemverRules() {
        assertTrue(v("1.0.0") > v("1.0.0-rc.1"))
        assertTrue(v("1.0.0-rc.2") > v("1.0.0-rc.1"))
        assertTrue(v("1.0.0-rc.11") > v("1.0.0-rc.2"))
        assertTrue(v("1.0.0-rc.1") > v("1.0.0-beta.9"))
        assertTrue(v("1.0.0-alpha.1") > v("1.0.0-alpha"))
        assertTrue(v("1.0.0-1") < v("1.0.0-alpha"))
        assertTrue(v("0.9.0") > v("0.9.0-rc1"))
    }

    @Test fun stableFlagAndToString() {
        assertTrue(v("1.0.0").isStable)
        assertFalse(v("1.0.0-rc1").isStable)
        assertEquals("1.0.0-rc.1", v("v1.0.0-rc.1").toString())
        assertNotNull(Version.parse(" 1.0.0 "))
    }
}
