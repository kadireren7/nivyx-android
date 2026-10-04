package app.nivyx.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.nivyx.android.core.EngineStats

@Composable
fun HomeScreen(summary: HomeSummary, stats: EngineStats?, onToggle: () -> Unit) {
    val ring = if (summary.active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Nivyx", fontSize = 28.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.align(Alignment.Start))
        Spacer(Modifier.height(20.dp))

        Box(
            Modifier
                .size(176.dp)
                .semantics { contentDescription = "Protection ${summary.protectionLabel}" },
            contentAlignment = Alignment.Center,
        ) {
            Canvas(Modifier.fillMaxSize()) {
                val stroke = 10.dp.toPx()
                drawArc(
                    color = ring,
                    startAngle = -90f,
                    sweepAngle = 360f,
                    useCenter = false,
                    topLeft = Offset(stroke / 2, stroke / 2),
                    size = Size(size.width - stroke, size.height - stroke),
                    style = Stroke(width = stroke, cap = StrokeCap.Round),
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Protection", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(
                    summary.protectionLabel,
                    fontSize = 26.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = if (summary.active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.testTag("protection_state"),
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            InfoCard("Network", summary.networkLabel, Modifier.weight(1f), detail = summary.networkDetail)
            InfoCard("DNS", summary.dnsLabel, Modifier.weight(1f), ok = summary.dnsOk)
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = onToggle,
            enabled = summary.buttonEnabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .testTag("toggle"),
            shape = RoundedCornerShape(16.dp),
        ) {
            Text(summary.buttonLabel, fontSize = 18.sp)
        }
        summary.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(16.dp))
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        ) {
            Text(
                "Android labels this connection as a VPN because Nivyx uses VpnService for local traffic interception. " +
                    "No remote VPN server is used: your public IP does not change and nothing is decrypted.",
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (summary.active && stats != null) {
            SectionTitle("Status")
            Card(
                Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            ) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    LabeledRow("Uptime", HomeReducer.formatUptime(stats.uptimeSeconds))
                    LabeledRow("Active strategies", stats.activeStrategies.toString())
                    LabeledRow("Connections", stats.connectionsTotal.toString())
                    LabeledRow("Bypassed connections", stats.connectionsBypassed.toString())
                    LabeledRow("Failures", stats.connectionsFailed.toString())
                    LabeledRow("Open flows", stats.flowsActive.toString())
                    LabeledRow("DNS queries / failures", "${stats.dnsQueries} / ${stats.dnsFailures}")
                    LabeledRow("IPv6", if (stats.ipv6Active) "tunneled" else "not tunneled")
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}
