package app.protoclean.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val PineBright = Color(0xFF60AA6B)   // proto green (dark scheme)
private val Pine = Color(0xFF2F6D3F)         // proto green (light scheme)
private val Dark = Color(0xFF14171C)
private val Surface = Color(0xFF1B1F24)

private val DarkColors = darkColorScheme(
    primary = PineBright,
    onPrimary = Color(0xFF10241A),
    background = Dark,
    surface = Surface,
    onBackground = Color(0xFFE7EAF2),
    onSurface = Color(0xFFE7EAF2),
    secondaryContainer = Color(0xFF272D38),
    onSecondaryContainer = Color(0xFFC6CDE0),
    error = Color(0xFFFF6B6B),
)

private val LightColors = lightColorScheme(
    primary = Pine,
    onPrimary = Color.White,
    background = Color(0xFFF7F8FB),
    surface = Color.White,
    onBackground = Color(0xFF191C22),
    onSurface = Color(0xFF191C22),
    secondaryContainer = Color(0xFFE8EAF6),
    onSecondaryContainer = Color(0xFF2F3542),
    error = Color(0xFFC0392B),
)

@Composable
fun ProtoCleanTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
