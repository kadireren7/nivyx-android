package app.nivyx.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DiagnosticsScreen(state: DiagnosticsUi, onHost: (String) -> Unit, onRun: () -> Unit, onCopy: () -> Unit, onExport: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("Diagnostics", fontSize = 28.sp)
        Spacer(Modifier.height(4.dp))
        Text(
            "Checks DNS, HTTPS reachability and the strategy Nivyx would use for one domain. Results stay on this device.",
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = state.host,
            onValueChange = onHost,
            label = { Text("Domain, e.g. discord.com") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
            keyboardActions = KeyboardActions(onGo = { onRun() }),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("diag_host"),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = onRun, enabled = !state.running && state.host.isNotBlank(), modifier = Modifier.fillMaxWidth().testTag("diag_run")) {
            Text(if (state.running) "Running…" else "Diagnose")
        }
        if (state.report.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            SelectionContainer {
                Text(state.report, fontFamily = FontFamily.Monospace, fontSize = 13.sp, modifier = Modifier.testTag("diag_report"))
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onCopy, modifier = Modifier.fillMaxWidth()) { Text("Copy diagnostics") }
        }
        SectionTitle("Support")
        Text(
            "Exports app and network state with host names, addresses, SSIDs and tokens removed.",
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
        )
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onExport) { Text("Export diagnostics") }
        }
    }
}
