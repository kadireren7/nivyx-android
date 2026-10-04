package app.nivyx.android.update

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Minimal HTTP surface so the update logic is testable without a network. */
interface Http {
    fun getText(url: String, maxBytes: Int): String

    fun open(url: String): Pair<InputStream, Long>
}

/** HTTPS-only client that re-validates every redirect hop against the GitHub host allowlist. */
class GithubHttp(private val userAgent: String) : Http {
    override fun getText(url: String, maxBytes: Int): String {
        val (stream, _) = open(url)
        stream.use { s ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8 * 1024)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                if (out.size() + n > maxBytes) throw IOException("response too large")
                out.write(buf, 0, n)
            }
            return out.toString(Charsets.UTF_8.name())
        }
    }

    override fun open(url: String): Pair<InputStream, Long> {
        var current = url
        repeat(MAX_REDIRECTS + 1) {
            require(isAllowed(current)) { "untrusted URL" }
            val conn = (URL(current).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 15_000
                readTimeout = 30_000
                setRequestProperty("User-Agent", userAgent)
                setRequestProperty("Accept", "application/vnd.github+json, application/octet-stream")
            }
            when (val code = conn.responseCode) {
                in 200..299 -> return conn.inputStream to conn.contentLength.toLong()
                301, 302, 303, 307, 308 -> {
                    current = URL(URL(current), conn.getHeaderField("Location") ?: throw IOException("redirect without target")).toString()
                    conn.disconnect()
                }
                else -> {
                    conn.disconnect()
                    throw IOException("HTTP $code")
                }
            }
        }
        throw IOException("too many redirects")
    }

    private fun isAllowed(url: String): Boolean {
        val u = runCatching { URL(url) }.getOrNull() ?: return false
        return u.protocol == "https" && u.host in HOSTS
    }

    private companion object {
        const val MAX_REDIRECTS = 5
        val HOSTS = setOf(
            "api.github.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        )
    }
}

sealed interface UpdateCheck {
    data object UpToDate : UpdateCheck

    data class Available(val release: ReleaseInfo) : UpdateCheck

    data class Failed(val message: String) : UpdateCheck
}

/** User-initiated update flow: check → (user asks) download → verify SHA-256 → hand to the system installer. */
class UpdateService(private val http: Http, private val current: Version, private val repo: String) {
    suspend fun check(): UpdateCheck = withContext(Dispatchers.IO) {
        try {
            val json = http.getText("https://api.github.com/repos/$repo/releases/latest", MAX_JSON)
            val release = ReleaseParser.parse(json) ?: return@withContext UpdateCheck.UpToDate
            if (release.version > current) UpdateCheck.Available(release) else UpdateCheck.UpToDate
        } catch (e: Exception) {
            UpdateCheck.Failed(e.message ?: e.javaClass.simpleName)
        }
    }

    /** Downloads into [dir] and verifies the checksum; the returned file is guaranteed to match. */
    suspend fun download(release: ReleaseInfo, dir: File, progress: (Long, Long) -> Unit): File = withContext(Dispatchers.IO) {
        val sums = Sha256Sums.parse(http.getText(release.checksums.url, ReleaseParser.MAX_SUMS_BYTES.toInt()))
        val expected = sums[release.apk.name] ?: throw IOException("release has no checksum for ${release.apk.name}")
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        // The file name is derived from the parsed version, never from server-supplied text.
        val target = File(dir, "nivyx-android-v${release.version}.apk")
        val part = File(dir, "download.part")
        val digest = MessageDigest.getInstance("SHA-256")
        val (stream, length) = http.open(release.apk.url)
        stream.use { input ->
            part.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > ReleaseParser.MAX_APK_BYTES) throw IOException("download exceeds size limit")
                    digest.update(buf, 0, n)
                    out.write(buf, 0, n)
                    progress(total, if (length > 0) length else release.apk.size)
                }
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (actual != expected) {
            part.delete()
            throw IOException("checksum mismatch: the downloaded file was discarded")
        }
        if (!part.renameTo(target)) throw IOException("could not finalize download")
        target
    }

    companion object {
        private const val MAX_JSON = 1024 * 1024

        /** Opens Android's package installer. The user still has to confirm the installation. */
        fun install(context: Context, apk: File): Boolean {
            if (Build.VERSION.SDK_INT >= 26 && !context.packageManager.canRequestPackageInstalls()) {
                context.startActivity(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, "package:${context.packageName}".toUri())
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
                return false
            }
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.updates", apk)
            context.startActivity(
                Intent(Intent.ACTION_VIEW)
                    .setDataAndType(uri, "application/vnd.android.package-archive")
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            return true
        }
    }
}
