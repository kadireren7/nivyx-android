package app.nivyx.android

import app.nivyx.android.diag.DiagnosticsFormatter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticsFormatterTest {
    private val sample = """{"host":"discord.com",
      "dns":{"doh":{"ok":true,"resolver":"Cloudflare","ms":42,"addresses":["162.159.135.232"]},
             "system":{"ok":true,"addresses":["0.0.0.0"]},"poisoning_suspected":"yes (plain DNS returned a non-routable address)"},
      "https":{"address":"162.159.135.232","direct":{"ok":false,"stage":"tls","error":"connection reset"},
               "tlsrec":{"ok":true,"ms":120},"tlsrec-tcp":{"ok":true,"ms":130}},
      "decision":{"source":"learned","state":"tlsrec-good","ladder":["tlsrec","direct"],"ttl_remaining_s":21540}}"""

    @Test fun rendersTheDesktopStyleReport() {
        val out = DiagnosticsFormatter.format(sample)
        for (expected in listOf(
            "Diagnose: discord.com", "Resolver: DoH (Cloudflare, 42 ms)", "Address: 162.159.135.232",
            "Poisoning suspected: yes", "Direct: failed at tls (connection reset)", "Strategy tlsrec: OK (120 ms)",
            "blocked directly, reachable with TLS record splitting", "Source: learned", "Strategy order: tlsrec → direct", "TTL: 5h 59m",
        )) {
            assertTrue("missing '$expected' in:\n$out", out.contains(expected))
        }
    }

    @Test fun directlyReachableHostSaysNoBypassNeeded() {
        val out = DiagnosticsFormatter.format(
            """{"host":"ok.example","dns":{"doh":{"ok":true,"resolver":"Google","ms":9,"addresses":["1.2.3.4"]},"system":{"ok":false},"poisoning_suspected":"unknown"},
               "https":{"address":"1.2.3.4","direct":{"ok":true,"ms":50},"tlsrec":{"ok":true,"ms":60},"tlsrec-tcp":{"ok":true,"ms":60}},
               "decision":{"source":"default","state":"unknown","ladder":["direct","tlsrec"],"ttl_remaining_s":0}}""",
        )
        assertTrue(out.contains("no bypass needed"))
        assertTrue(out.contains("TTL: n/a"))
        assertTrue(out.contains("Network resolver: no answer"))
    }

    @Test fun handlesErrorsAndGarbage() {
        assertEquals("Diagnostics failed: invalid host name", DiagnosticsFormatter.format("""{"error":"invalid host name"}"""))
        assertEquals("Diagnostics unavailable.", DiagnosticsFormatter.format("nope"))
        val partial = DiagnosticsFormatter.format(
            """{"host":"x.example","dns":{"doh":{"ok":false,"error":"timed out"}},"https":{"error":"no address to probe"}}""",
        )
        assertTrue(partial.contains("DoH unavailable (timed out)"))
        assertTrue(partial.contains("no address to probe"))
        assertFalse(partial.contains("Result:"))
    }

    @Test fun ttlFormatting() {
        assertEquals("n/a", DiagnosticsFormatter.ttl(0))
        assertEquals("45s", DiagnosticsFormatter.ttl(45))
        assertEquals("10m", DiagnosticsFormatter.ttl(600))
        assertEquals("2h 0m", DiagnosticsFormatter.ttl(7200))
    }
}
