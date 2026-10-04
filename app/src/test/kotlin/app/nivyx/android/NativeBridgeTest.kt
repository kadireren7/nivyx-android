package app.nivyx.android

import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.NivyxNative
import app.nivyx.android.core.Transport
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.diag.SupportBundle
import app.nivyx.android.diag.SupportInput
import app.nivyx.android.settings.ConfigBuilder
import app.nivyx.android.settings.Ipv6Setting
import app.nivyx.android.settings.ResolverChoice
import app.nivyx.android.settings.Settings
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** These tests load the real Rust library (built for the host) through JNI. */
class NativeBridgeTest {
    @Test fun versionMatchesTheWorkspace() {
        assertTrue(NivyxNative.version().matches(Regex("""\d+\.\d+\.\d+.*""")))
    }

    @Test fun redactionRemovesHostsIpsAndTokens() {
        val out = NivyxNative.redact("conn 192.168.1.5 to discord.com via https://api.example.org/v1?token=abc Authorization: Bearer xyz.123", false)
        for (leak in listOf("192.168", "discord.com", "example.org", "token=abc", "xyz.123")) assertFalse("leaked $leak in: $out", out.contains(leak))
        assertEquals("Nivyx 0.1.0 started", NivyxNative.redact("Nivyx 0.1.0 started", false))
    }

    @Test fun fingerprintIsStableSaltedAndDistinguishesNetworks() {
        val a = NivyxNative.fingerprint("salt", "wifi", "192.168.1.1", "192.168.1.0/24", "1.1.1.1", "")
        assertEquals(a, NivyxNative.fingerprint("salt", "wifi", "192.168.1.1", "192.168.1.0/24", "1.1.1.1", ""))
        assertNotEquals(a, NivyxNative.fingerprint("other", "wifi", "192.168.1.1", "192.168.1.0/24", "1.1.1.1", ""))
        assertNotEquals(a, NivyxNative.fingerprint("salt", "cellular", "", "", "10.0.0.1", "28603"))
        assertNotEquals(a, NivyxNative.fingerprint("salt", "wifi", "192.168.1.1", "192.168.1.0/24", "9.9.9.9", ""))
    }

    @Test fun manualRuleParsingReportsLineErrors() {
        val ok = JSONObject(NivyxNative.parseRules("a.example = direct\n*.b.example = tlsrec\n# c\n"))
        assertEquals(2, ok.getInt("rules"))
        assertEquals(0, ok.getJSONArray("errors").length())
        val bad = JSONObject(NivyxNative.parseRules("a.example = warp\nnonsense\n"))
        assertEquals(2, bad.getJSONArray("errors").length())
        assertEquals(1, bad.getJSONArray("errors").getJSONObject(0).getInt("line"))
    }

    @Test fun everyResolverChoiceProducesAConfigTheEngineAccepts() {
        for (choice in ResolverChoice.entries) {
            val settings = Settings(
                resolver = choice,
                customDohUrl = "https://dns.example/dns-query",
                customBootstrap = "192.0.2.1",
                ipv6 = Ipv6Setting.OFF,
                manualRules = "x.example = direct",
                tlsRecTcp = true,
            )
            assertEquals("choice $choice", "", NivyxNative.validateConfig(ConfigBuilder.build(settings, "salt")))
        }
    }

    @Test fun invalidCustomResolverIsRejectedByTheEngine() {
        val bad = ConfigBuilder.build(Settings(resolver = ResolverChoice.CUSTOM, customDohUrl = "http://insecure.example"), "s")
        assertTrue(NivyxNative.validateConfig(bad).isNotEmpty())
        val needsBootstrap = ConfigBuilder.build(Settings(resolver = ResolverChoice.CUSTOM, customDohUrl = "https://dns.example/q"), "s")
        assertTrue(NivyxNative.validateConfig(needsBootstrap).contains("bootstrap"))
    }

    @Test fun autoResolverInterleavesProviders() {
        val arr = ConfigBuilder.resolverJson(Settings())
        val names = (0 until arr.length()).map { arr.getJSONObject(it).getString("name") }
        assertEquals(listOf("Cloudflare", "Google", "Quad9", "Cloudflare", "Google", "Quad9"), names)
    }

    @Test fun systemDnsDisablesEncryptedDns() {
        val j = JSONObject(ConfigBuilder.build(Settings(resolver = ResolverChoice.SYSTEM), "s"))
        assertFalse(j.getBoolean("encrypted_dns"))
    }

    @Test fun startWithInvalidInputsFailsSafelyWithoutCrashing() {
        assertEquals(0L, NivyxNative.start(-1, "{}", 0, false, "", Any()))
        assertTrue(NivyxNative.lastError().isNotEmpty())
        assertEquals(0L, NivyxNative.start(5, "not json", 0, false, "", Any()))
        // Stale and zero handles are harmless.
        NivyxNative.stop(0)
        NivyxNative.stop(987654321L)
        assertEquals("{}", NivyxNative.statsJson(0))
        assertEquals(0, NivyxNative.importLearned(0, "[]"))
        assertFalse(NivyxNative.updateConfig(0, "{}"))
        assertTrue(NivyxNative.diagnose(0, "example.com").contains("not running"))
    }

    @Test fun engineStatsParsing() {
        val json = """{"stats":{"connections_total":10,"connections_direct":6,"connections_bypassed":3,"connections_failed":1,
            "dns_queries":50,"dns_failures":2,"escalations":4,"quic_rejected":1,"flows_active":3,"strategy_tlsrec":3,"strategy_tlsrec_tcp":0},
            "uptime_s":120,"dns":{"healthy":false,"encrypted":true},"strategy_summary":{"direct-good":5,"tlsrec-good":2,"direct-bad":1},
            "ipv6_active":true,"alive":true}"""
        val s = EngineStats.parse(json)!!
        assertEquals(10, s.connectionsTotal)
        assertEquals(3, s.activeStrategies) // everything except direct-good
        assertFalse(s.dnsHealthy)
        assertTrue(s.ipv6Active)
        assertEquals(null, EngineStats.parse("{}"))
        assertEquals(null, EngineStats.parse("garbage"))
    }

    @Test fun supportBundleIsRedactedAndCarriesNoHostLists() {
        val input = SupportInput(
            appVersion = "0.1.0", coreVersion = "0.1.0", androidRelease = "14", sdkInt = 34, abis = listOf("arm64-v8a"),
            device = "Test Device", status = VpnStatus.Running(0), transport = Transport.WIFI, ipv6 = false,
            stats = EngineStats(connectionsTotal = 3),
            settings = Settings(manualRules = "secret-site.example = tlsrec\n# c", excludedPackages = setOf("com.bank.app")),
            rawLogs = "WARN connect to 203.0.113.9 failed for blocked.example\nINFO engine 1 started",
        )
        val text = SupportBundle.build(input) { NivyxNative.redact(it, false) }
        assertTrue(text.contains("App: 0.1.0"))
        assertTrue(text.contains("manual rules: 1"))
        assertTrue(text.contains("excluded apps: 1"))
        for (leak in listOf("203.0.113.9", "blocked.example", "secret-site", "com.bank.app")) assertFalse("leaked $leak", text.contains(leak))
        assertTrue(text.contains("engine 1 started"))
    }
}
