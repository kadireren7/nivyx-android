package app.nivyx.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Android brand palette (matches assets/logo-android.svg).
val NivyxEmerald = Color(0xFF10B981)
val NivyxMint = Color(0xFF6EE7B7)
val NivyxTeal = Color(0xFF0D9488)
private val Accent = Color(0xFF34D399)
private val Ink = Color(0xFF06120E)
private val Panel = Color(0xFF0C1C16)
private val PanelHigh = Color(0xFF14281F)

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Ink,
    primaryContainer = Color(0xFF0B3D2E),
    onPrimaryContainer = NivyxMint,
    secondary = NivyxMint,
    onSecondary = Ink,
    secondaryContainer = Color(0xFF123A2E),
    onSecondaryContainer = NivyxMint,
    tertiary = Color(0xFF2DD4BF),
    onTertiary = Ink,
    tertiaryContainer = Color(0xFF0F3B37),
    onTertiaryContainer = Color(0xFF99F6E4),
    background = Ink,
    onBackground = Color(0xFFE6F3EC),
    surface = Panel,
    onSurface = Color(0xFFE6F3EC),
    surfaceVariant = PanelHigh,
    onSurfaceVariant = Color(0xFF9DB8AB),
    error = Color(0xFFFF8A80),
    outline = Color(0xFF3A5A4B),
    outlineVariant = Color(0xFF1F3A2E),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF047857),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCFF5E3),
    onPrimaryContainer = Color(0xFF064E3B),
    secondary = Color(0xFF0F766E),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCDEFE9),
    onSecondaryContainer = Color(0xFF134E4A),
    tertiary = NivyxTeal,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFCCFBF1),
    onTertiaryContainer = Color(0xFF0F4F4A),
    background = Color(0xFFF4FAF7),
    onBackground = Color(0xFF0B1620),
    surface = Color.White,
    onSurface = Color(0xFF0B1620),
    surfaceVariant = Color(0xFFE2F1EA),
    onSurfaceVariant = Color(0xFF456356),
    error = Color(0xFFB3261E),
    outline = Color(0xFF7A9A8A),
    outlineVariant = Color(0xFFBFD6CA),
)

@Composable
fun NivyxTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}
