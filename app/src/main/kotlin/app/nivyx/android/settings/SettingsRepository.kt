package app.nivyx.android.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import java.security.SecureRandom

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "nivyx_settings")

/** Persistent, app-private settings. Contains no credentials and no browsing history. */
class SettingsRepository(context: Context) {
    private val store = context.applicationContext.dataStore

    private object Keys {
        val autoStart = booleanPreferencesKey("auto_start_on_launch")
        val boot = booleanPreferencesKey("start_on_boot")
        val resolver = stringPreferencesKey("resolver")
        val customUrl = stringPreferencesKey("custom_doh_url")
        val customBootstrap = stringPreferencesKey("custom_bootstrap")
        val ipv6 = stringPreferencesKey("ipv6")
        val quic = booleanPreferencesKey("quic_fallback")
        val tlsRecTcp = booleanPreferencesKey("tlsrec_tcp")
        val verboseHosts = booleanPreferencesKey("verbose_hosts")
        val debug = booleanPreferencesKey("debug_logs")
        val rules = stringPreferencesKey("manual_rules")
        val excluded = stringSetPreferencesKey("excluded_packages")
        val desired = booleanPreferencesKey("desired_active")
        val salt = stringPreferencesKey("install_salt")
    }

    val settings: Flow<Settings> = store.data
        .catch { if (it is IOException) emit(emptyPreferences()) else throw it }
        .map(::toSettings)

    suspend fun current(): Settings = settings.first()

    suspend fun update(transform: (Settings) -> Settings) {
        store.edit { prefs ->
            val next = transform(toSettings(prefs))
            prefs[Keys.autoStart] = next.autoStartOnLaunch
            prefs[Keys.boot] = next.startOnBoot
            prefs[Keys.resolver] = next.resolver.name
            prefs[Keys.customUrl] = next.customDohUrl
            prefs[Keys.customBootstrap] = next.customBootstrap
            prefs[Keys.ipv6] = next.ipv6.name
            prefs[Keys.quic] = next.quicFallback
            prefs[Keys.tlsRecTcp] = next.tlsRecTcp
            prefs[Keys.verboseHosts] = next.verboseHosts
            prefs[Keys.debug] = next.debugLogs
            prefs[Keys.rules] = next.manualRules
            prefs[Keys.excluded] = next.excludedPackages
            prefs[Keys.desired] = next.desiredActive
        }
    }

    /** Per-install random salt used to hash host names and network identifiers. Not a secret. */
    suspend fun salt(): String {
        store.data.first()[Keys.salt]?.let { return it }
        val fresh = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        var result = fresh
        store.edit { prefs -> result = prefs[Keys.salt] ?: fresh.also { prefs[Keys.salt] = it } }
        return result
    }

    private fun toSettings(p: Preferences): Settings = Settings(
        autoStartOnLaunch = p[Keys.autoStart] ?: false,
        startOnBoot = p[Keys.boot] ?: false,
        resolver = enumOr(p[Keys.resolver], ResolverChoice.AUTO),
        customDohUrl = p[Keys.customUrl] ?: "",
        customBootstrap = p[Keys.customBootstrap] ?: "",
        ipv6 = enumOr(p[Keys.ipv6], Ipv6Setting.AUTO),
        quicFallback = p[Keys.quic] ?: true,
        tlsRecTcp = p[Keys.tlsRecTcp] ?: false,
        verboseHosts = p[Keys.verboseHosts] ?: false,
        debugLogs = p[Keys.debug] ?: false,
        manualRules = p[Keys.rules] ?: "",
        excludedPackages = p[Keys.excluded] ?: emptySet(),
        desiredActive = p[Keys.desired] ?: false,
    )

    private inline fun <reified T : Enum<T>> enumOr(name: String?, default: T): T = enumValues<T>().firstOrNull { it.name == name } ?: default
}
