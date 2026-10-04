package app.nivyx.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val NivyxCyan = Color(0xFF22D3EE)
private val Ink = Color(0xFF0B0F14)
private val Panel = Color(0xFF121923)
private val PanelHigh = Color(0xFF1A2431)

private val DarkColors = darkColorScheme(
    primary = NivyxCyan,
    onPrimary = Ink,
    secondary = Color(0xFF67E8F9),
    background = Ink,
    onBackground = Color(0xFFE6EEF5),
    surface = Panel,
    onSurface = Color(0xFFE6EEF5),
    surfaceVariant = PanelHigh,
    onSurfaceVariant = Color(0xFF9FB1C2),
    error = Color(0xFFFF8A80),
    outline = Color(0xFF2A394A),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF0E7490),
    onPrimary = Color.White,
    secondary = Color(0xFF0891B2),
    background = Color(0xFFF5F8FA),
    onBackground = Color(0xFF0B1620),
    surface = Color.White,
    onSurface = Color(0xFF0B1620),
    surfaceVariant = Color(0xFFE6EEF3),
    onSurfaceVariant = Color(0xFF475B6D),
    error = Color(0xFFB3261E),
    outline = Color(0xFFC3D0DA),
)

@Composable
fun NivyxTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}
