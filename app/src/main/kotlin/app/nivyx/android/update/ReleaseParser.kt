package app.nivyx.android.update

import org.json.JSONObject

data class Asset(val name: String, val url: String, val size: Long)

data class ReleaseInfo(val version: Version, val tag: String, val notes: String, val pageUrl: String, val apk: Asset, val checksums: Asset)

/** Strict parser for the GitHub "latest release" document. Anything unexpected is rejected. */
object ReleaseParser {
    const val MAX_APK_BYTES = 150L * 1024 * 1024
    const val MAX_SUMS_BYTES = 64L * 1024
    private val allowedHosts = setOf("github.com")

    fun parse(json: String): ReleaseInfo? = runCatching {
        val root = JSONObject(json)
        if (root.optBoolean("draft", false) || root.optBoolean("prerelease", false)) return null
        val tag = root.getString("tag_name")
        val version = Version.parse(tag)?.takeIf { it.isStable } ?: return null
        val assets = root.getJSONArray("assets")
        val apkName = "nivyx-android-v$version.apk"
        var apk: Asset? = null
        var sums: Asset? = null
        for (i in 0 until assets.length()) {
            val a = assets.getJSONObject(i)
            val asset = Asset(a.getString("name"), a.getString("browser_download_url"), a.getLong("size"))
            if (!isTrustedUrl(asset.url)) continue
            when (asset.name) {
                apkName -> if (asset.size in 1..MAX_APK_BYTES) apk = asset
                "SHA256SUMS" -> if (asset.size in 1..MAX_SUMS_BYTES) sums = asset
            }
        }
        if (apk == null || sums == null) return null
        ReleaseInfo(
            version = version,
            tag = tag,
            notes = root.optString("body", "").take(4000),
            pageUrl = root.optString("html_url", "").takeIf(::isTrustedUrl) ?: "https://github.com",
            apk = apk,
            checksums = sums,
        )
    }.getOrNull()

    /** HTTPS only, and only GitHub hosts. */
    fun isTrustedUrl(url: String): Boolean {
        val m = Regex("""^https://([a-z0-9.-]+)(?::443)?(/[^\s]*)?$""").matchEntire(url) ?: return false
        return m.groupValues[1] in allowedHosts
    }
}

/** `sha256sum`-style file: `<64 hex>  <name>` per line. */
object Sha256Sums {
    fun parse(text: String): Map<String, String> {
        val out = HashMap<String, String>()
        for (line in text.lineSequence().take(200)) {
            val m = Regex("""^([0-9a-fA-F]{64}) [ *]([^/\\\s]+)$""").matchEntire(line.trim()) ?: continue
            out[m.groupValues[2]] = m.groupValues[1].lowercase()
        }
        return out
    }
}
