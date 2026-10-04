package app.nivyx.android.ui

import android.content.Intent
import android.os.Build
import android.os.PowerManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.nivyx.android.settings.Ipv6Setting
import app.nivyx.android.settings.ResolverChoice
import app.nivyx.android.settings.Settings
import android.provider.Settings as AndroidSettings

@Composable
fun SettingsScreen(
    settings: Settings,
    apps: List<AppEntry>?,
    onLoadApps: () -> Unit,
    onChange: ((Settings) -> Settings) -> Unit,
    onRestartIfRunning: () -> Unit,
    onValidateRules: (String) -> List<String>,
    onValidateResolver: (String, String) -> String?,
    onResetLearned: () -> Unit,
) {
    val context = LocalContext.current
    var showApps by remember { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("Settings", fontSize = 28.sp)

        SectionTitle("General")
        SwitchRow("Start when the app opens", "Only if Android VPN consent was already granted", settings.autoStartOnLaunch) { v ->
            onChange { it.copy(autoStartOnLaunch = v) }
        }
        SwitchRow("Start after reboot", "Requires the setting above to have been granted once", settings.startOnBoot) { v ->
            onChange { it.copy(startOnBoot = v) }
        }

        SectionTitle("DNS")
        RadioGroup(ResolverChoice.entries.map { it to it.label }, settings.resolver) { choice ->
            onChange { it.copy(resolver = choice) }
        }
        if (settings.resolver == ResolverChoice.CUSTOM) {
            CustomResolver(settings, onChange, onValidateResolver)
        }

        SectionTitle("Network")
        Text("IPv6", style = MaterialTheme.typography.labelMedium)
        RadioGroup(Ipv6Setting.entries.map { it to it.label }, settings.ipv6) { v -> onChange { it.copy(ipv6 = v) } }
        SwitchRow(
            "QUIC fallback",
            "For hosts that need bypass, reject QUIC so apps retry over TCP/TLS",
            settings.quicFallback,
        ) { v -> onChange { it.copy(quicFallback = v) } }

        SectionTitle("Apps")
        Text(
            "Excluded apps bypass Nivyx completely (useful for banking apps that refuse VPN interfaces). " +
                "Currently excluded: ${settings.excludedPackages.size}.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(
            onClick = {
                onLoadApps()
                showApps = true
            },
            modifier = Modifier.padding(top = 8.dp),
        ) { Text("Choose excluded apps") }

        if (Build.VERSION.SDK_INT >= 23) {
            SectionTitle("Battery")
            Text(
                "Nivyx is event-driven and does not poll in the background. If Android stops it while the screen is off, " +
                    "you can allow it to run unrestricted. Nivyx never changes this silently.",
                style = MaterialTheme.typography.bodySmall,
            )
            val pm = androidx.core.content.ContextCompat.getSystemService(context, PowerManager::class.java)!!
            val ignoring = pm.isIgnoringBatteryOptimizations(context.packageName)
            Text(
                if (ignoring) "Battery optimization: unrestricted" else "Battery optimization: active",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 4.dp),
            )
            OutlinedButton(
                onClick = { context.startActivity(Intent(AndroidSettings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) },
                modifier = Modifier.padding(top = 8.dp),
            ) { Text("Open battery settings") }
        }

        SectionTitle("Advanced")
        Text("Manual rules override automatic learning.", style = MaterialTheme.typography.bodySmall)
        RulesEditor(settings.manualRules, onValidateRules) { text -> onChange { it.copy(manualRules = text) } }
        SwitchRow(
            "tlsrec-tcp strategy (experimental)",
            "Also send the split records in separate TCP segments",
            settings.tlsRecTcp,
        ) { v -> onChange { it.copy(tlsRecTcp = v) } }
        SwitchRow("Host names in debug logs", "Off by default. Logs never contain URLs, cookies or tokens", settings.verboseHosts) { v ->
            onChange { it.copy(verboseHosts = v) }
        }
        SwitchRow("Debug logging", "Local ring buffer only, 400 lines", settings.debugLogs) { v -> onChange { it.copy(debugLogs = v) } }
        OutlinedButton(onClick = onResetLearned, modifier = Modifier.padding(top = 8.dp)) { Text("Reset learned strategies") }
        Spacer(Modifier.height(24.dp))
    }

    if (showApps) {
        ExcludedAppsDialog(
            apps = apps,
            selected = settings.excludedPackages,
            onDismiss = { showApps = false },
            onConfirm = { chosen ->
                showApps = false
                onChange { it.copy(excludedPackages = chosen) }
                onRestartIfRunning()
            },
        )
    }
}

@Composable
private fun CustomResolver(settings: Settings, onChange: ((Settings) -> Settings) -> Unit, validate: (String, String) -> String?) {
    var url by remember { mutableStateOf(settings.customDohUrl) }
    var boot by remember { mutableStateOf(settings.customBootstrap) }
    val error = if (url.isBlank()) null else validate(url, boot)
    Column(Modifier.padding(top = 4.dp)) {
        OutlinedTextField(url, { url = it }, label = { Text("https://host/dns-query") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            boot,
            { boot = it },
            label = { Text("Bootstrap IPs (only if host is a name)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Button(
            onClick = { onChange { it.copy(customDohUrl = url.trim(), customBootstrap = boot.trim()) } },
            enabled = url.isNotBlank() && error == null,
            modifier = Modifier.padding(top = 8.dp),
        ) { Text("Apply") }
    }
}

@Composable
private fun RulesEditor(saved: String, validate: (String) -> List<String>, onSave: (String) -> Unit) {
    var text by remember(saved) { mutableStateOf(saved) }
    val errors = validate(text)
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text("example.com = direct\nexample.org = tlsrec") },
        textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
        minLines = 3,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .testTag("rules"),
    )
    errors.take(5).forEach { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    Button(onClick = { onSave(text) }, enabled = text != saved && errors.isEmpty(), modifier = Modifier.padding(top = 8.dp)) {
        Text("Save rules")
    }
}

@Composable
private fun ExcludedAppsDialog(apps: List<AppEntry>?, selected: Set<String>, onDismiss: () -> Unit, onConfirm: (Set<String>) -> Unit) {
    var chosen by remember { mutableStateOf(selected) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Excluded apps") },
        text = {
            if (apps == null) {
                Text("Loading…")
            } else {
                LazyColumn(Modifier.height(380.dp)) {
                    items(apps, key = { it.packageName }) { app ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable { chosen = if (app.packageName in chosen) chosen - app.packageName else chosen + app.packageName },
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Checkbox(checked = app.packageName in chosen, onCheckedChange = null)
                            Text(app.label, maxLines = 1)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(chosen) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
