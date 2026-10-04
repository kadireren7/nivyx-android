package app.nivyx.android.core

/**
 * Bridge to the Rust engine. Every function maps 1:1 to an exported JNI symbol in `libnivyx_jni`.
 * Engine handles are opaque ids; passing a stale or zero handle is always safe.
 */
object NivyxNative {
    init {
        System.loadLibrary("nivyx_jni")
    }

    @JvmStatic external fun version(): String

    /** Starts the engine on a TUN fd (duplicated natively). Returns a handle, or 0 on failure. */
    @JvmStatic external fun start(tunFd: Int, configJson: String, networkId: Long, hasIpv6: Boolean, dnsCsv: String, service: Any): Long

    @JvmStatic external fun stop(handle: Long)

    @JvmStatic external fun statsJson(handle: Long): String

    @JvmStatic external fun updateConfig(handle: Long, configJson: String): Boolean

    @JvmStatic external fun networkChanged(handle: Long, networkId: Long, hasIpv6: Boolean, dnsCsv: String): Boolean

    /** Blocking (seconds). Call from a background dispatcher. */
    @JvmStatic external fun diagnose(handle: Long, host: String): String

    @JvmStatic external fun exportLearned(handle: Long): String

    @JvmStatic external fun importLearned(handle: Long, json: String): Int

    @JvmStatic external fun resetLearned(handle: Long)

    @JvmStatic external fun lastError(): String

    @JvmStatic external fun setDebug(on: Boolean)

    @JvmStatic external fun fingerprint(salt: String, transport: String, gateway: String, subnet: String, dns: String, carrier: String): Long

    @JvmStatic external fun redact(text: String, keepHosts: Boolean): String

    /** Empty string when valid, otherwise a human-readable error. */
    @JvmStatic external fun validateConfig(json: String): String

    @JvmStatic external fun parseRules(text: String): String

    @JvmStatic external fun recentLogs(): String
}
