package app.nivyx.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.nivyx.android.BuildConfig
import java.io.File

@Composable
fun AboutScreen(
    coreVersion: String,
    update: UpdateUi,
    onCheck: () -> Unit,
    onDownload: (app.nivyx.android.update.ReleaseInfo) -> Unit,
    onInstall: (File) -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("About", fontSize = 28.sp)
        Spacer(Modifier.height(12.dp))
        LabeledRow("Version", BuildConfig.VERSION_NAME)
        LabeledRow("Native core", coreVersion)

        SectionTitle("Updates")
        when (update) {
            UpdateUi.Idle -> Unit
            UpdateUi.Checking -> Text("Checking GitHub Releases…")
            UpdateUi.UpToDate -> Text("You are on the latest stable release.")
            is UpdateUi.Available -> {
                Text("Version ${update.release.version} is available.", fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                if (update.release.notes.isNotBlank()) {
                    Text(update.release.notes.take(600), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
                }
                Button(onClick = { onDownload(update.release) }, modifier = Modifier.padding(top = 8.dp)) {
                    Text("Download (${update.release.apk.size / 1_000_000} MB)")
                }
            }
            is UpdateUi.Downloading -> {
                Text("Downloading ${update.release.version}…")
                LinearProgressIndicator(
                    progress = { if (update.total > 0) (update.done.toFloat() / update.total).coerceIn(0f, 1f) else 0f },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
            is UpdateUi.Ready -> {
                Text("Downloaded and verified (SHA-256). Android will ask you to confirm the installation.")
                Button(onClick = { onInstall(update.file) }, modifier = Modifier.padding(top = 8.dp)) { Text("Install") }
            }
            is UpdateUi.Failed -> Text("Update failed: ${update.message}", color = MaterialTheme.colorScheme.error)
        }
        OutlinedButton(onClick = onCheck, modifier = Modifier.padding(top = 8.dp).testTag("check_updates")) { Text("Check for updates") }
        Text(
            "Updates are only checked when you tap the button, are never installed silently, and must be signed with the same key.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )

        SectionTitle("How it works")
        Text(
            "Many networks block sites by reading the site's name at the start of a connection. Nivyx sends that start in a " +
                "slightly different shape, so the block doesn't recognise it, while the site itself works normally. " +
                "Your connection still goes out through your own internet: no server of ours, your IP stays the same, " +
                "and nothing you send is decrypted or read.",
            style = MaterialTheme.typography.bodyMedium,
        )

        SectionTitle("Privacy")
        Text(
            "No tracking, ads or accounts, and no Nivyx servers. Nivyx only looks up site names over an encrypted DNS service " +
                "and, when you tap the button, checks GitHub for updates.",
            style = MaterialTheme.typography.bodyMedium,
        )

        SectionTitle("Limitations")
        Text(
            "Sites blocked by their IP address cannot be opened, because Nivyx has no server to go around the block. " +
                "Results depend on how your network blocks sites. Ping does not work while Nivyx is on.",
            style = MaterialTheme.typography.bodyMedium,
        )

        SectionTitle("Open source")
        Text(
            "MIT licensed. Source and release notes: github.com/${BuildConfig.GITHUB_REPO}. " +
                "Third-party components are listed in docs/third-party.md.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(24.dp))
    }
}
