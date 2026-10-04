package app.nivyx.android.settings

import org.json.JSONArray
import org.json.JSONObject

/** Translates user [Settings] into the engine's JSON configuration. */
object ConfigBuilder {
    private data class Preset(val name: String, val urls: List<String>)

    private val presets = mapOf(
        ResolverChoice.CLOUDFLARE to Preset("Cloudflare", listOf("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query")),
        ResolverChoice.GOOGLE to Preset("Google", listOf("https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query")),
        ResolverChoice.QUAD9 to Preset("Quad9", listOf("https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query")),
    )

    fun resolverJson(settings: Settings): JSONArray {
        val arr = JSONArray()
        fun add(name: String, url: String, bootstrap: List<String> = emptyList()) {
            arr.put(
                JSONObject().put("name", name).put("url", url).put("bootstrap", JSONArray(bootstrap)),
            )
        }
        when (settings.resolver) {
            ResolverChoice.AUTO -> {
                // Interleave providers so a single provider outage never costs more than one attempt.
                val lists = listOf(ResolverChoice.CLOUDFLARE, ResolverChoice.GOOGLE, ResolverChoice.QUAD9).map { presets.getValue(it) }
                for (i in 0 until 2) lists.forEach { add(it.name, it.urls[i]) }
            }
            ResolverChoice.CLOUDFLARE, ResolverChoice.GOOGLE, ResolverChoice.QUAD9 -> {
                val p = presets.getValue(settings.resolver)
                p.urls.forEach { add(p.name, it) }
            }
            ResolverChoice.CUSTOM -> add(
                "Custom",
                settings.customDohUrl.trim(),
                settings.customBootstrap.split(',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() },
            )
            ResolverChoice.SYSTEM -> Unit
        }
        return arr
    }

    fun build(settings: Settings, salt: String): String {
        val encrypted = settings.resolver != ResolverChoice.SYSTEM
        return JSONObject()
            .put("encrypted_dns", encrypted)
            .put("resolvers", resolverJson(settings))
            .put("strategy", JSONObject().put("allow_tlsrec_tcp", settings.tlsRecTcp))
            .put("manual_rules", settings.manualRules)
            .put("ipv6", settings.ipv6.wire)
            .put("quic_fallback", settings.quicFallback)
            .put("verbose_hosts", settings.verboseHosts)
            .put("salt", salt)
            .toString()
    }
}
