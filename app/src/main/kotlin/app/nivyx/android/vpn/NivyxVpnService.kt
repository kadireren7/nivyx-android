package app.nivyx.android.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.core.app.PendingIntentCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import app.nivyx.android.MainActivity
import app.nivyx.android.core.EngineStats
import app.nivyx.android.core.NivyxNative
import app.nivyx.android.core.RouteCalculator
import app.nivyx.android.learned.LearnedStore
import app.nivyx.android.settings.ConfigBuilder
import app.nivyx.android.settings.Ipv6Setting
import app.nivyx.android.settings.Settings
import app.nivyx.android.settings.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Local VPN service. It exists only to obtain a TUN interface for system-wide interception;
 * traffic leaves the device directly through sockets that are excluded from the VPN via `protect()`.
 *
 * Every start/stop/restart is only recorded as intent here; [VpnLifecycle] executes the transitions one at a time,
 * so no sequence of commands can produce two engines, two TUNs, or a TUN without an engine.
 *
 * Fail-open ordering: whenever anything goes wrong, the TUN is closed *first* so traffic immediately
 * returns to the normal network, and only then is the engine stopped.
 */
class NivyxVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val main = Handler(Looper.getMainLooper())
    private lateinit var repo: SettingsRepository
    private lateinit var learned: LearnedStore
    private lateinit var monitor: NetworkMonitor
    private lateinit var lifecycle: VpnLifecycle

    @Volatile private var tun: ParcelFileDescriptor? = null

    @Volatile private var handle = 0L

    @Volatile private var lastStartId = 0

    @Volatile private var userStopRecorded = false
    private var salt = ""
    private var startedWithV6 = false
    private var lastSnapshot: NetworkSnapshot? = null
    private val jobs = mutableListOf<Job>()
    private val restartTimes = ArrayDeque<Long>()

    override fun onCreate() {
        super.onCreate()
        repo = SettingsRepository(this)
        learned = LearnedStore(this)
        monitor = NetworkMonitor(this) { salt }
        Notifications.ensureChannel(this)
        lifecycle = VpnLifecycle(
            scope = scope,
            backend = Backend(),
            publish = VpnStateHolder::set,
            clock = SystemClock::elapsedRealtime,
            onSettled = ::onSettled,
            onClosed = { scope.cancel() },
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        if (intent?.action == ACTION_STOP) {
            userStopRecorded = true
            lifecycle.requestStop()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_RESTART) {
            lifecycle.requestRestart()
            return START_NOT_STICKY
        }
        // ACTION_START, a null intent (OS restart after process death) and always-on VPN all land here.
        if (!enterForeground()) {
            lifecycle.abort("Android did not allow Nivyx to start in the background. Open the app and tap Start.")
            return START_NOT_STICKY
        }
        userStopRecorded = false
        lifecycle.requestStart()
        return START_STICKY
    }

    override fun onRevoke() {
        // The user switched VPN off in system settings, or another VPN took over.
        userStopRecorded = true
        lifecycle.requestStop()
    }

    override fun onDestroy() {
        // Settle at STOPPED (releasing TUN + engine) on the worker, behind any in-flight transition.
        lifecycle.close()
        super.onDestroy()
    }

    private fun enterForeground(): Boolean = try {
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0
        ServiceCompat.startForeground(this, Notifications.NOTIFICATION_ID, Notifications.build(this, "Starting…"), type)
        true
    } catch (e: Exception) {
        Log.w(TAG, "cannot enter foreground: ${e.javaClass.simpleName}")
        false
    }

    /** Runs on the lifecycle worker after every settled pass, so persistence cannot interleave with a later start. */
    private suspend fun onSettled(wantRunning: Boolean) {
        if (wantRunning) return
        if (userStopRecorded) repo.update { it.copy(desiredActive = false) }
        main.post {
            // A START that arrived meanwhile wins; stopSelf(id) is also a no-op if a newer command was queued.
            if (!lifecycle.wantsRunning) {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf(lastStartId)
            }
        }
    }

    // ------------------------------------------------------------------------------------ backend

    private inner class Backend : VpnBackend {
        override suspend fun establish(stillWanted: () -> Boolean): Boolean {
            val settings = repo.current()
            salt = repo.salt()
            NivyxNative.setDebug(settings.debugLogs)
            monitor.start()
            val snapshot = withTimeoutOrNull(NETWORK_WAIT_MS) { monitor.snapshot.filterNotNull().first() }
            if (!stillWanted()) return false
            lastSnapshot = snapshot
            val v6 = when (settings.ipv6) {
                Ipv6Setting.ON -> true
                Ipv6Setting.OFF -> false
                Ipv6Setting.AUTO -> snapshot?.hasIpv6 == true
            }
            val pfd = buildInterface(settings, snapshot, v6) ?: error("Android refused to create the VPN interface (permission revoked?)")
            tun = pfd // from here teardown owns it, whatever happens next
            if (!stillWanted()) return false
            val h = NivyxNative.start(
                pfd.fd,
                ConfigBuilder.build(settings, salt),
                snapshot?.fingerprint ?: 0L,
                snapshot?.hasIpv6 ?: false,
                snapshot?.dnsCsv.orEmpty(),
                this@NivyxVpnService,
            )
            if (h == 0L) error("Engine failed to start: " + NivyxNative.lastError())
            handle = h
            VpnStateHolder.handle = h
            startedWithV6 = v6
            learned.load()?.let { NivyxNative.importLearned(h, it) }
            repo.update { it.copy(desiredActive = true) }
            VpnStateHolder.setNetwork(snapshot)
            Notifications.update(this@NivyxVpnService, "Protection active · traffic stays on this device")
            startBackgroundJobs()
            return true
        }

        override suspend fun teardown() = withContext(Dispatchers.IO) {
            closeTunAndEngine()
            monitor.stop()
            VpnStateHolder.setNetwork(null)
        }
    }

    private fun buildInterface(settings: Settings, snapshot: NetworkSnapshot?, ipv6: Boolean): ParcelFileDescriptor? {
        val b = Builder()
            .setSession("Nivyx")
            .setMtu(MTU)
            .addAddress(TUN_ADDRESS, 24)
            .addDnsServer(VIRTUAL_DNS)
            .setBlocking(false)
        RouteCalculator.publicIpv4().forEach { b.addRoute(it.address, it.prefix) }
        if (ipv6) {
            b.addAddress(TUN_ADDRESS_V6, 64)
            b.addRoute(RouteCalculator.IPV6_ROUTE.substringBefore('/'), RouteCalculator.IPV6_ROUTE.substringAfter('/').toInt())
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        if (Build.VERSION.SDK_INT >= 22) snapshot?.network?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        settings.excludedPackages.forEach { pkg ->
            try {
                b.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // App was uninstalled since it was excluded; ignore.
            }
        }
        PendingIntentCompat.getActivity(this, 2, Intent(this, MainActivity::class.java), 0, false)?.let { b.setConfigureIntent(it) }
        return b.establish()
    }

    private fun startBackgroundJobs() {
        jobs += scope.launch { watchNetwork() }
        jobs += scope.launch { watchdog() }
        jobs += scope.launch { persistLearnedPeriodically() }
    }

    // ------------------------------------------------------------------------------ network & health

    private suspend fun watchNetwork() {
        monitor.snapshot.filterNotNull().collect { snap ->
            if (!snap.materiallyDiffersFrom(lastSnapshot)) return@collect
            delay(NETWORK_DEBOUNCE_MS) // let flapping settle
            val latest = monitor.snapshot.value ?: snap
            val h = handle
            if (h == 0L) return@collect
            lastSnapshot = latest
            VpnStateHolder.setNetwork(latest)
            NivyxNative.networkChanged(h, latest.fingerprint, latest.hasIpv6, latest.dnsCsv)
            if (Build.VERSION.SDK_INT >= 22) setUnderlyingNetworks(latest.network?.let { arrayOf(it) })
            val settings = repo.current()
            if (settings.ipv6 == Ipv6Setting.AUTO && latest.hasIpv6 != startedWithV6) {
                Log.i(TAG, "IPv6 availability changed; re-establishing interface")
                lifecycle.requestRestart()
            }
        }
    }

    /** Detects a dead packet loop and fails open instead of black-holing traffic. */
    private suspend fun watchdog() {
        while (true) {
            delay(WATCHDOG_MS)
            val h = handle
            if (h == 0L) continue
            val stats = EngineStats.parse(NivyxNative.statsJson(h))
            if (stats == null || !stats.alive) {
                Log.w(TAG, "engine is not alive; failing open")
                onEngineDead()
                return
            }
        }
    }

    private fun onEngineDead() {
        val now = SystemClock.elapsedRealtime()
        restartTimes.addLast(now)
        while (restartTimes.isNotEmpty() && now - restartTimes.first() > RESTART_WINDOW_MS) restartTimes.removeFirst()
        if (restartTimes.size > MAX_RESTARTS) {
            lifecycle.abort("The Nivyx engine stopped repeatedly, so protection was turned off. Your normal connection is unaffected.")
        } else {
            lifecycle.requestRestart()
        }
    }

    private suspend fun persistLearnedPeriodically() {
        while (true) {
            delay(PERSIST_MS)
            val h = handle
            if (h != 0L) learned.save(NivyxNative.exportLearned(h))
        }
    }

    // ------------------------------------------------------------------------------------ tear down

    /** Fail-open order: release the TUN first so traffic is back on the real network at once. Idempotent. */
    private fun closeTunAndEngine() {
        val pfd = tun
        val h = handle
        tun = null
        handle = 0L
        VpnStateHolder.handle = 0L
        jobs.forEach { it.cancel() }
        jobs.clear()
        runCatching { pfd?.close() }
        if (h != 0L) {
            runCatching { learned.save(NivyxNative.exportLearned(h)) }
            NivyxNative.stop(h)
        }
    }

    companion object {
        const val ACTION_START = "app.nivyx.android.action.START"
        const val ACTION_STOP = "app.nivyx.android.action.STOP"
        const val ACTION_RESTART = "app.nivyx.android.action.RESTART"
        private const val TAG = "nivyx"
        private const val MTU = 1500
        private const val TUN_ADDRESS = "198.18.0.2"
        private const val VIRTUAL_DNS = "198.18.0.1"
        private const val TUN_ADDRESS_V6 = "fd6e:6976:7978::2"
        private const val NETWORK_WAIT_MS = 1500L
        private const val NETWORK_DEBOUNCE_MS = 400L
        private const val WATCHDOG_MS = 10_000L
        private const val PERSIST_MS = 10 * 60_000L
        private const val RESTART_BACKOFF_MS = 1_500L
        private const val RESTART_WINDOW_MS = 120_000L
        private const val MAX_RESTARTS = 3

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, NivyxVpnService::class.java).setAction(ACTION_START))
        }

        /** Re-creates the interface (route/app-exclusion changes). Ignored unless protection is wanted. */
        fun restart(context: Context) {
            context.startService(Intent(context, NivyxVpnService::class.java).setAction(ACTION_RESTART))
        }

        fun stop(context: Context) {
            // Plain startService: the service is already foreground (or not running at all).
            context.startService(Intent(context, NivyxVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
