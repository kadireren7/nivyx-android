package app.nivyx.android.ui

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.FileProvider
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.nivyx.android.BuildConfig
import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.NivyxNative
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.diag.DiagnosticsFormatter
import app.nivyx.android.diag.SupportBundle
import app.nivyx.android.diag.SupportInput
import app.nivyx.android.learned.LearnedStore
import app.nivyx.android.settings.Settings
import app.nivyx.android.settings.SettingsRepository
import app.nivyx.android.update.GithubHttp
import app.nivyx.android.update.ReleaseInfo
import app.nivyx.android.update.UpdateCheck
import app.nivyx.android.update.UpdateService
import app.nivyx.android.update.Version
import app.nivyx.android.vpn.NivyxVpnService
import app.nivyx.android.vpn.VpnStateHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class AppEntry(val packageName: String, val label: String)

data class DiagnosticsUi(val host: String = "", val running: Boolean = false, val report: String = "")

sealed interface UpdateUi {
    data object Idle : UpdateUi

    data object Checking : UpdateUi

    data object UpToDate : UpdateUi

    data class Available(val release: ReleaseInfo) : UpdateUi

    data class Downloading(val release: ReleaseInfo, val done: Long, val total: Long) : UpdateUi

    data class Ready(val release: ReleaseInfo, val file: File) : UpdateUi

    data class Failed(val message: String) : UpdateUi
}

@OptIn(ExperimentalCoroutinesApi::class)
class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = SettingsRepository(app)
    private val learned = LearnedStore(app)
    private val updater = UpdateService(
        http = GithubHttp("nivyx-android/${BuildConfig.VERSION_NAME}"),
        current = Version.parse(BuildConfig.VERSION_NAME.substringBefore("-debug")) ?: Version(0, 0, 0),
        repo = BuildConfig.GITHUB_REPO,
    )

    val settings: StateFlow<Settings> = repo.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())
    val status: StateFlow<VpnStatus> = VpnStateHolder.status
    val network = VpnStateHolder.network

    /** Polled only while a collector is attached (the UI collects with lifecycle awareness), so no wakeups in the background. */
    val stats: StateFlow<EngineStats?> = status
        .flatMapLatest { s ->
            if (s is VpnStatus.Running) {
                flow<EngineStats?> {
                    while (true) {
                        emit(withContext(Dispatchers.Default) { EngineStats.parse(NivyxNative.statsJson(VpnStateHolder.handle)) })
                        delay(STATS_INTERVAL_MS)
                    }
                }
            } else {
                flowOf<EngineStats?>(null)
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(3000), null)

    private val _diagnostics = MutableStateFlow(DiagnosticsUi())
    val diagnostics = _diagnostics.asStateFlow()

    private val _update = MutableStateFlow<UpdateUi>(UpdateUi.Idle)
    val update = _update.asStateFlow()

    private val _apps = MutableStateFlow<List<AppEntry>?>(null)
    val apps = _apps.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()

    private var autoStartHandled = false

    fun consumeMessage() {
        _message.value = null
    }

    /** True when Android still needs to show its VPN consent dialog. Returns the intent to launch. */
    fun consentIntent(): Intent? = VpnService.prepare(getApplication())

    fun startService() {
        NivyxVpnService.start(getApplication())
    }

    fun stopService() {
        NivyxVpnService.stop(getApplication())
    }

    /** Honors "start when the app opens" once per process, only if consent was already granted. */
    fun maybeAutoStart() {
        if (autoStartHandled) return
        autoStartHandled = true
        viewModelScope.launch {
            val s = repo.current()
            if (s.autoStartOnLaunch && status.value is VpnStatus.Stopped && consentIntent() == null) startService()
        }
    }

    fun updateSettings(transform: (Settings) -> Settings) {
        viewModelScope.launch {
            repo.update(transform)
            pushConfigToEngine()
        }
    }

    private suspend fun pushConfigToEngine() {
        val h = VpnStateHolder.handle
        val s = repo.current()
        NivyxNative.setDebug(s.debugLogs)
        if (h != 0L) {
            withContext(Dispatchers.Default) {
                NivyxNative.updateConfig(h, app.nivyx.android.settings.ConfigBuilder.build(s, repo.salt()))
            }
        }
    }

    /** Settings that change the VPN interface itself (routes, excluded apps) need a restart. */
    fun restartIfRunning() {
        if (status.value is VpnStatus.Running) {
            viewModelScope.launch {
                stopService()
                delay(800)
                startService()
            }
        }
    }

    fun validateRules(text: String): List<String> = runCatching {
        val root = org.json.JSONObject(NivyxNative.parseRules(text))
        val errs = root.getJSONArray("errors")
        (0 until errs.length()).map { errs.getJSONObject(it).let { e -> "line ${e.getInt("line")}: ${e.getString("message")}" } }
    }.getOrDefault(emptyList())

    fun validateCustomResolver(url: String, bootstrap: String): String? {
        val s = settings.value.copy(resolver = app.nivyx.android.settings.ResolverChoice.CUSTOM, customDohUrl = url, customBootstrap = bootstrap)
        return NivyxNative.validateConfig(app.nivyx.android.settings.ConfigBuilder.build(s, "x")).takeIf { it.isNotEmpty() }
    }

    fun resetLearned() {
        viewModelScope.launch(Dispatchers.Default) {
            val h = VpnStateHolder.handle
            if (h != 0L) NivyxNative.resetLearned(h)
            learned.clear()
            _message.value = "Learned strategies cleared"
        }
    }

    // ------------------------------------------------------------------------------------ diagnostics

    fun setDiagnosticsHost(host: String) {
        _diagnostics.value = _diagnostics.value.copy(host = host)
    }

    fun runDiagnostics() {
        val host = _diagnostics.value.host.trim()
        if (host.isEmpty() || _diagnostics.value.running) return
        val h = VpnStateHolder.handle
        if (h == 0L) {
            _diagnostics.value = _diagnostics.value.copy(report = "Start Nivyx first: diagnostics run through the active engine.")
            return
        }
        _diagnostics.value = _diagnostics.value.copy(running = true, report = "Running…")
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) { DiagnosticsFormatter.format(NivyxNative.diagnose(h, host)) }
            _diagnostics.value = _diagnostics.value.copy(running = false, report = text)
        }
    }

    fun copyToClipboard(label: String, text: String) {
        val cm = androidx.core.content.ContextCompat.getSystemService(getApplication<Application>(), ClipboardManager::class.java)!!
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        _message.value = "Copied"
    }

    /** Builds the redacted support bundle and returns a share intent for it. */
    suspend fun buildSupportShare(): Intent = withContext(Dispatchers.IO) {
        val ctx = getApplication<Application>()
        val snap = network.value
        val bundle = SupportBundle.build(
            SupportInput(
                appVersion = BuildConfig.VERSION_NAME,
                coreVersion = runCatching { NivyxNative.version() }.getOrDefault("?"),
                androidRelease = Build.VERSION.RELEASE,
                sdkInt = Build.VERSION.SDK_INT,
                abis = Build.SUPPORTED_ABIS.toList(),
                device = "${Build.MANUFACTURER} ${Build.MODEL}",
                status = status.value,
                transport = snap?.transport ?: app.nivyx.android.core.Transport.NONE,
                ipv6 = snap?.hasIpv6 == true,
                stats = stats.value,
                settings = settings.value,
                rawLogs = runCatching { NivyxNative.recentLogs() }.getOrDefault(""),
            ),
            redact = { NivyxNative.redact(it, false) },
        )
        val dir = File(ctx.cacheDir, "support").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val file = File(dir, "nivyx-support.txt").apply { writeText(bundle) }
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.updates", file)
        Intent.createChooser(
            Intent(Intent.ACTION_SEND)
                .setType("text/plain")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .putExtra(Intent.EXTRA_SUBJECT, "Nivyx diagnostics")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
            "Export diagnostics",
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    // ---------------------------------------------------------------------------------------- apps

    fun loadApps() {
        if (_apps.value != null) return
        viewModelScope.launch(Dispatchers.IO) {
            val pm = getApplication<Application>().packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val list = pm.queryIntentActivities(launcher, 0)
                .map { AppEntry(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
                .filter { it.packageName != getApplication<Application>().packageName }
                .distinctBy { it.packageName }
                .sortedBy { it.label.lowercase() }
            _apps.value = list
        }
    }

    // --------------------------------------------------------------------------------------- update

    fun checkForUpdates() {
        if (_update.value is UpdateUi.Checking || _update.value is UpdateUi.Downloading) return
        _update.value = UpdateUi.Checking
        viewModelScope.launch {
            _update.value = when (val r = updater.check()) {
                UpdateCheck.UpToDate -> UpdateUi.UpToDate
                is UpdateCheck.Available -> UpdateUi.Available(r.release)
                is UpdateCheck.Failed -> UpdateUi.Failed(r.message)
            }
        }
    }

    fun downloadUpdate(release: ReleaseInfo) {
        _update.value = UpdateUi.Downloading(release, 0, release.apk.size)
        viewModelScope.launch {
            val dir = File(getApplication<Application>().cacheDir, "updates")
            _update.value = try {
                val f = updater.download(release, dir) { done, total ->
                    _update.value = UpdateUi.Downloading(release, done, total)
                }
                UpdateUi.Ready(release, f)
            } catch (e: Exception) {
                UpdateUi.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun installUpdate(file: File) {
        UpdateService.install(getApplication(), file)
    }

    private companion object {
        const val STATS_INTERVAL_MS = 2000L
    }
}
