package app.nivyx.android

import app.nivyx.android.update.Http
import app.nivyx.android.update.ReleaseParser
import app.nivyx.android.update.Sha256Sums
import app.nivyx.android.update.UpdateCheck
import app.nivyx.android.update.UpdateService
import app.nivyx.android.update.Version
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

class UpdateTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun releaseJson(
        tag: String = "v0.9.0",
        draft: Boolean = false,
        pre: Boolean = false,
        apkUrl: String = "https://github.com/kadireren7/nivyx-android/releases/download/$tag/nivyx-android-$tag.apk",
        apkName: String = "nivyx-android-$tag.apk",
        sumsUrl: String = "https://github.com/kadireren7/nivyx-android/releases/download/$tag/SHA256SUMS",
        size: Long = 1000,
    ) = """{"tag_name":"$tag","draft":$draft,"prerelease":$pre,"body":"notes","html_url":"https://github.com/kadireren7/nivyx-android/releases/tag/$tag",
        "assets":[{"name":"$apkName","browser_download_url":"$apkUrl","size":$size},
                  {"name":"SHA256SUMS","browser_download_url":"$sumsUrl","size":120}]}"""

    @Test fun parsesAStableRelease() {
        val r = ReleaseParser.parse(releaseJson())!!
        assertEquals(Version(0, 9, 0), r.version)
        assertEquals("nivyx-android-v0.9.0.apk", r.apk.name)
    }

    @Test fun rejectsDraftPrereleaseAndMalformed() {
        assertNull(ReleaseParser.parse(releaseJson(draft = true)))
        assertNull(ReleaseParser.parse(releaseJson(pre = true)))
        assertNull(ReleaseParser.parse(releaseJson(tag = "v0.9.0-rc1")))
        assertNull(ReleaseParser.parse("not json"))
        assertNull(ReleaseParser.parse("{}"))
        assertNull(ReleaseParser.parse("""{"tag_name":"v1.0.0","assets":[]}"""))
    }

    @Test fun rejectsUntrustedHostsSchemesAndWrongAssetNames() {
        assertNull(ReleaseParser.parse(releaseJson(apkUrl = "https://evil.example/nivyx-android-v0.9.0.apk")))
        assertNull(ReleaseParser.parse(releaseJson(apkUrl = "http://github.com/x/nivyx-android-v0.9.0.apk")))
        assertNull(ReleaseParser.parse(releaseJson(apkUrl = "https://github.com.evil.example/a.apk")))
        assertNull(ReleaseParser.parse(releaseJson(apkName = "../../evil.apk")))
        assertNull(ReleaseParser.parse(releaseJson(size = 10L * 1024 * 1024 * 1024)))
        assertNull(ReleaseParser.parse(releaseJson(size = 0)))
        assertTrue(ReleaseParser.isTrustedUrl("https://github.com/a/b"))
        assertFalse(ReleaseParser.isTrustedUrl("https://github.com@evil.example/a"))
        assertFalse(ReleaseParser.isTrustedUrl("javascript:alert(1)"))
    }

    @Test fun checksumFileParsingIsStrict() {
        val h = "a".repeat(64)
        val parsed = Sha256Sums.parse("$h  nivyx-android-v1.0.0.apk\n${"B".repeat(64)} *other.json\nshort  bad\n$h  ../evil\n$h  a/b")
        assertEquals(setOf("nivyx-android-v1.0.0.apk", "other.json"), parsed.keys)
        assertEquals("b".repeat(64), parsed["other.json"])
    }

    private class FakeHttp(val json: String, val sums: String, val apk: ByteArray, val failApk: Boolean = false) : Http {
        override fun getText(url: String, maxBytes: Int): String = when {
            url.contains("/releases/latest") -> json
            url.endsWith("SHA256SUMS") -> sums
            else -> throw IOException("unexpected $url")
        }

        override fun open(url: String): Pair<InputStream, Long> {
            if (failApk) throw IOException("boom")
            return ByteArrayInputStream(apk) to apk.size.toLong()
        }
    }

    private val apkBytes = ByteArray(5000) { (it * 7).toByte() }

    private fun service(current: String, http: Http) = UpdateService(http, Version.parse(current)!!, "kadireren7/nivyx-android")

    @Test fun checkReportsNewerStableOnly() = runBlocking {
        val http = FakeHttp(releaseJson(), "", apkBytes)
        assertTrue(service("0.8.0", http).check() is UpdateCheck.Available)
        assertEquals(UpdateCheck.UpToDate, service("0.9.0", http).check())
        assertEquals(UpdateCheck.UpToDate, service("1.0.0", http).check())
        assertTrue(service("0.9.0-rc1", http).check() is UpdateCheck.Available) // rc → final
    }

    @Test fun networkFailureIsReportedNotThrown() = runBlocking {
        val failing = object : Http {
            override fun getText(url: String, maxBytes: Int): String = throw IOException("offline")

            override fun open(url: String): Pair<InputStream, Long> = throw IOException("offline")
        }
        assertTrue(service("0.1.0", failing).check() is UpdateCheck.Failed)
    }

    @Test fun downloadVerifiesChecksumAndWritesOnlyTheExpectedName() = runBlocking {
        val sums = "${sha(apkBytes)}  nivyx-android-v0.9.0.apk\n"
        val http = FakeHttp(releaseJson(), sums, apkBytes)
        val release = ReleaseParser.parse(releaseJson())!!
        val dir = tmp.newFolder("updates")
        var last = 0L
        val file = service("0.8.0", http).download(release, dir) { done, _ -> last = done }
        assertEquals("nivyx-android-v0.9.0.apk", file.name)
        assertEquals(dir.canonicalPath, file.parentFile!!.canonicalPath)
        assertEquals(apkBytes.size.toLong(), last)
        assertEquals(listOf("nivyx-android-v0.9.0.apk"), dir.list()!!.toList())
    }

    @Test fun checksumMismatchDiscardsTheDownload() = runBlocking {
        val http = FakeHttp(releaseJson(), "${"0".repeat(64)}  nivyx-android-v0.9.0.apk\n", apkBytes)
        val dir = tmp.newFolder("bad")
        try {
            service("0.8.0", http).download(ReleaseParser.parse(releaseJson())!!, dir) { _, _ -> }
            fail("expected checksum failure")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("checksum"))
        }
        assertEquals(0, dir.list()!!.size)
    }

    @Test fun missingChecksumEntryFails() = runBlocking {
        val http = FakeHttp(releaseJson(), "${sha(apkBytes)}  some-other-file.apk\n", apkBytes)
        try {
            service("0.8.0", http).download(ReleaseParser.parse(releaseJson())!!, tmp.newFolder("m")) { _, _ -> }
            fail("expected failure")
        } catch (_: IOException) {
        }
    }
}
