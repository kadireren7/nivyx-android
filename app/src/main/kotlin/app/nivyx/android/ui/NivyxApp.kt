package app.nivyx.android.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.nivyx.android.core.NivyxNative
import app.nivyx.android.core.VpnStatus
import kotlinx.coroutines.launch

private enum class Tab(val label: String) { Home("Home"), Diagnostics("Diagnostics"), Settings("Settings"), About("About") }

@Composable
fun NivyxApp(vm: MainViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val snackbar = remember { SnackbarHostState() }

    val status by vm.status.collectAsStateWithLifecycle()
    val network by vm.network.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val diagnostics by vm.diagnostics.collectAsStateWithLifecycle()
    val update by vm.update.collectAsStateWithLifecycle()
    val apps by vm.apps.collectAsStateWithLifecycle()
    val message by vm.message.collectAsState()

    LaunchedEffect(Unit) { vm.maybeAutoStart() }
    LaunchedEffect(message) {
        message?.let {
            snackbar.showSnackbar(it)
            vm.consumeMessage()
        }
    }

    // Android's VPN consent dialog, shown the first time (and again if it was revoked).
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.startService()
    }
    fun startWithConsent() {
        val intent = vm.consentIntent()
        if (intent != null) consent.launch(intent) else vm.startService()
    }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { startWithConsent() }

    fun onToggle() {
        if (status is VpnStatus.Running) {
            vm.stopService()
        } else if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // The status notification is how Android lets you see and stop the VPN; ask once, then continue either way.
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startWithConsent()
        }
    }

    NivyxTheme {
        Scaffold(
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = {
                NavigationBar {
                    Tab.entries.forEachIndexed { i, t ->
                        NavigationBarItem(
                            selected = tab == i,
                            onClick = { tab = i },
                            icon = {
                                Icon(
                                    when (t) {
                                        Tab.Home -> Icons.Filled.Home
                                        Tab.Diagnostics -> Icons.Filled.Search
                                        Tab.Settings -> Icons.Filled.Settings
                                        Tab.About -> Icons.Filled.Info
                                    },
                                    contentDescription = null,
                                )
                            },
                            label = { Text(t.label) },
                            modifier = Modifier.testTag("tab_${t.name}"),
                        )
                    }
                }
            },
        ) { padding ->
            val mod = Modifier.padding(padding)
            androidx.compose.foundation.layout.Box(mod) {
                when (Tab.entries[tab]) {
                    Tab.Home -> HomeScreen(HomeReducer.reduce(status, network, stats), stats, ::onToggle)
                    Tab.Diagnostics -> DiagnosticsScreen(
                        state = diagnostics,
                        onHost = vm::setDiagnosticsHost,
                        onRun = vm::runDiagnostics,
                        onCopy = { vm.copyToClipboard("Nivyx diagnostics", diagnostics.report) },
                        onExport = { scope.launch { context.startActivity(vm.buildSupportShare()) } },
                    )
                    Tab.Settings -> SettingsScreen(
                        settings = settings,
                        apps = apps,
                        onLoadApps = vm::loadApps,
                        onChange = vm::updateSettings,
                        onRestartIfRunning = vm::restartIfRunning,
                        onValidateRules = vm::validateRules,
                        onValidateResolver = vm::validateCustomResolver,
                        onResetLearned = vm::resetLearned,
                    )
                    Tab.About -> AboutScreen(
                        coreVersion = remember { runCatching { NivyxNative.version() }.getOrDefault("unavailable") },
                        update = update,
                        onCheck = vm::checkForUpdates,
                        onDownload = vm::downloadUpdate,
                        onInstall = vm::installUpdate,
                    )
                }
            }
        }
    }
}
