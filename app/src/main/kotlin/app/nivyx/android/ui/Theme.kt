package app.nivyx.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val NivyxEmerald = Color(0xFF10B981)
private val Ink = Color(0xFF06120E)
private val Panel = Color(0xFF0C1C16)
private val PanelHigh = Color(0xFF14281F)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF34D399),
    onPrimary = Ink,
    secondary = Color(0xFF6EE7B7),
    background = Ink,
    onBackground = Color(0xFFE6F3EC),
    surface = Panel,
    onSurface = Color(0xFFE6F3EC),
    surfaceVariant = PanelHigh,
    onSurfaceVariant = Color(0xFF9DB8AB),
    error = Color(0xFFFF8A80),
    outline = Color(0xFF1F3A2E),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF047857),
    onPrimary = Color.White,
    secondary = Color(0xFF0D9488),
    background = Color(0xFFF4FAF7),
    onBackground = Color(0xFF0B1620),
    surface = Color.White,
    onSurface = Color(0xFF0B1620),
    surfaceVariant = Color(0xFFE2F1EA),
    onSurfaceVariant = Color(0xFF456356),
    error = Color(0xFFB3261E),
    outline = Color(0xFFBFD6CA),
)

@Composable
fun NivyxTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}
