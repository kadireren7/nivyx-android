package app.nivyx.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 20.dp, bottom = 6.dp),
    )
}

@Composable
fun InfoCard(title: String, value: String, modifier: Modifier = Modifier, detail: String? = null, ok: Boolean = true) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(4.dp))
            Text(
                value,
                fontSize = 18.sp,
                color = if (ok) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error,
            )
            if (detail != null) {
                Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun LabeledRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value)
    }
}

@Composable
fun SwitchRow(title: String, subtitle: String? = null, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Composable
fun <T> RadioGroup(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit) {
    Column(Modifier.semantics { }) {
        options.forEach { (value, label) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .selectable(selected = value == selected, role = Role.RadioButton, onClick = { onSelect(value) })
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = value == selected, onClick = null)
                Spacer(Modifier.size(12.dp))
                Text(label)
            }
        }
    }
}
