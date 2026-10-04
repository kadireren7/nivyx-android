package app.nivyx.android.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
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
import app.nivyx.android.core.VpnStatus
import app.nivyx.android.learned.LearnedStore
import app.nivyx.android.settings.ConfigBuilder
import app.nivyx.android.settings.Ipv6Setting
import app.nivyx.android.settings.Settings
import app.nivyx.android.settings.SettingsRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Local VPN service. It exists only to obtain a TUN interface for system-wide interception;
 * traffic leaves the device directly through sockets that are excluded from the VPN via `protect()`.
 *
 * Fail-open ordering: whenever anything goes wrong, the TUN is closed *first* so traffic immediately
 * returns to the normal network, and only then is the engine stopped.
 */
class NivyxVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Mutex()
    private lateinit var repo: SettingsRepository
    private lateinit var learned: LearnedStore
    private lateinit var monitor: NetworkMonitor

    @Volatile private var tun: ParcelFileDescriptor? = null

    @Volatile private var handle = 0L
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
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            scope.launch { shutdown(userRequested = true) }
            return START_NOT_STICKY
        }
        // ACTION_START, a null intent (OS restart after process death) and always-on VPN all land here.
        if (!enterForeground()) {
            stopSelf()
            return START_NOT_STICKY
        }
        scope.launch { bringUp() }
        return START_STICKY
    }

    override fun onRevoke() {
        // The user switched VPN off in system settings, or another VPN took over.
        scope.launch { shutdown(userRequested = true) }
    }

    override fun onDestroy() {
        // Synchronous best-effort teardown; never leave a TUN open behind a dead service.
        closeTunAndEngine(export = false)
        VpnStateHolder.set(VpnStatus.Stopped)
        monitor.stop()
        scope.cancel()
        super.onDestroy()
    }

    private fun enterForeground(): Boolean = try {
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0
        ServiceCompat.startForeground(this, Notifications.NOTIFICATION_ID, Notifications.build(this, "Starting…"), type)
        true
    } catch (e: Exception) {
        Log.w(TAG, "cannot enter foreground: ${e.javaClass.simpleName}")
        VpnStateHolder.set(VpnStatus.Error("Android did not allow Nivyx to start in the background. Open the app and tap Start."))
        false
    }

    // ---------------------------------------------------------------------------------------- bring up

    private suspend fun bringUp() {
        lock.withLock {
            if (handle != 0L) return // duplicate start: already running
            VpnStateHolder.set(VpnStatus.Starting)
            try {
                establishLocked()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    private suspend fun establishLocked() {
        val settings = repo.current()
        salt = repo.salt()
        NivyxNative.setDebug(settings.debugLogs)
        monitor.start()
        val snapshot = withTimeoutOrNull(NETWORK_WAIT_MS) { monitor.snapshot.filterNotNull().first() }
        lastSnapshot = snapshot
        val v6 = when (settings.ipv6) {
            Ipv6Setting.ON -> true
            Ipv6Setting.OFF -> false
            Ipv6Setting.AUTO -> snapshot?.hasIpv6 == true
        }
        val pfd = buildInterface(settings, snapshot, v6) ?: error("Android refused to create the VPN interface (permission revoked?)")
        val h = NivyxNative.start(
            pfd.fd,
            ConfigBuilder.build(settings, salt),
            snapshot?.fingerprint ?: 0L,
            snapshot?.hasIpv6 ?: false,
            snapshot?.dnsCsv.orEmpty(),
            this,
        )
        if (h == 0L) {
            runCatching { pfd.close() }
            error("Engine failed to start: " + NivyxNative.lastError())
        }
        tun = pfd
        handle = h
        startedWithV6 = v6
        VpnStateHolder.handle = h
        learned.load()?.let { NivyxNative.importLearned(h, it) }
        repo.update { it.copy(desiredActive = true) }
        VpnStateHolder.set(VpnStatus.Running(SystemClock.elapsedRealtime()))
        VpnStateHolder.setNetwork(snapshot)
        Notifications.update(this, "Protection active · traffic stays on this device")
        startBackgroundJobs()
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
                reestablish()
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

    private suspend fun onEngineDead() {
        lock.withLock {
            closeTunAndEngine(export = false)
            val now = SystemClock.elapsedRealtime()
            restartTimes.addLast(now)
            while (restartTimes.isNotEmpty() && now - restartTimes.first() > RESTART_WINDOW_MS) restartTimes.removeFirst()
            if (restartTimes.size > MAX_RESTARTS) {
                fail("The Nivyx engine stopped repeatedly, so protection was turned off. Your normal connection is unaffected.")
                return
            }
            VpnStateHolder.set(VpnStatus.Starting)
            delay(RESTART_BACKOFF_MS)
            try {
                establishLocked()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    private suspend fun reestablish() {
        lock.withLock {
            if (handle == 0L) return
            exportLearned()
            closeTunAndEngine(export = false)
            try {
                establishLocked()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    private suspend fun persistLearnedPeriodically() {
        while (true) {
            delay(PERSIST_MS)
            exportLearned()
        }
    }

    private fun exportLearned() {
        val h = handle
        if (h != 0L) learned.save(NivyxNative.exportLearned(h))
    }

    // ------------------------------------------------------------------------------------ tear down

    /** Fail-open order: release the TUN first so traffic is back on the real network at once. */
    private fun closeTunAndEngine(export: Boolean) {
        val pfd = tun
        val h = handle
        tun = null
        handle = 0L
        VpnStateHolder.handle = 0L
        jobs.forEach { it.cancel() }
        jobs.clear()
        runCatching { pfd?.close() }
        if (h != 0L) {
            if (export) runCatching { learned.save(NivyxNative.exportLearned(h)) }
            NivyxNative.stop(h)
        }
    }

    private suspend fun shutdown(userRequested: Boolean) {
        lock.withLock {
            VpnStateHolder.set(VpnStatus.Stopping)
            closeTunAndEngine(export = true)
            if (userRequested) repo.update { it.copy(desiredActive = false) }
            monitor.stop()
            VpnStateHolder.setNetwork(null)
            VpnStateHolder.set(VpnStatus.Stopped)
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun fail(message: String) {
        Log.w(TAG, "protection stopped: $message")
        closeTunAndEngine(export = false)
        monitor.stop()
        VpnStateHolder.setNetwork(null)
        VpnStateHolder.set(VpnStatus.Error(message))
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        const val ACTION_START = "app.nivyx.android.action.START"
        const val ACTION_STOP = "app.nivyx.android.action.STOP"
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

        fun stop(context: Context) {
            // Plain startService: the service is already foreground (or not running at all).
            context.startService(Intent(context, NivyxVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
