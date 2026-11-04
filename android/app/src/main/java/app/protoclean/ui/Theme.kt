package app.protoclean.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Proto palette: a single pine-green seed drives both schemes. The
// primary / secondary / tertiary triad is tuned so MD3 widgets
// (FilledTonalButton, OutlinedTextField, Surface tonal elevations,
// dividers) all pick up colours that read as "proto" without
// conflicting with the existing pine-green brand.

private val PineBright = Color(0xFF60AA6B)        // proto green (dark scheme)
private val Pine = Color(0xFF2F6D3F)              // proto green (light scheme)
private val PineBrightContainer = Color(0xFF1F3A24)
private val PineContainer = Color(0xFFB8E8B8)

private val Amber = Color(0xFFE7A14C)
private val AmberDark = Color(0xFF8C5A12)
private val AmberContainer = Color(0xFFFFD9A8)
private val AmberContainerDark = Color(0xFF5A3A05)

private val Dark = Color(0xFF14171C)
private val DarkSurface = Color(0xFF1B1F24)
private val DarkSurfaceVariant = Color(0xFF222831)
private val DarkSurfaceContainer = Color(0xFF1E2229)
private val DarkSurfaceContainerHigh = Color(0xFF232831)
private val DarkSurfaceContainerHighest = Color(0xFF2A2F38)
private val DarkOnSurfaceVariant = Color(0xFFB6BECC)
private val DarkOutline = Color(0xFF5A6271)
private val DarkOutlineVariant = Color(0xFF333945)

private val LightSurfaceVariant = Color(0xFFE6E9EF)
private val LightSurfaceContainer = Color(0xFFF1F3F7)
private val LightSurfaceContainerHigh = Color(0xFFEBEEF3)
private val LightSurfaceContainerHighest = Color(0xFFE5E8EE)
private val LightOnSurfaceVariant = Color(0xFF444B55)
private val LightOutline = Color(0xFF747B85)
private val LightOutlineVariant = Color(0xFFC7CCD5)

private val ErrorDark = Color(0xFFFF6B6B)
private val ErrorDarkContainer = Color(0xFF5A1F1F)
private val OnErrorDarkContainer = Color(0xFFFFB4B4)
private val ErrorLight = Color(0xFFC0392B)
private val ErrorLightContainer = Color(0xFFFFE0DC)
private val OnErrorLightContainer = Color(0xFF4A1010)

private val DarkColors = darkColorScheme(
    // Identity
    primary = PineBright,
    onPrimary = Color(0xFF10241A),
    primaryContainer = PineBrightContainer,
    onPrimaryContainer = Color(0xFFC6E8CC),
    // Secondary — neutral container chips (load badges, banners)
    secondary = Color(0xFF8C9BB0),
    onSecondary = Color(0xFF101820),
    secondaryContainer = Color(0xFF272D38),
    onSecondaryContainer = Color(0xFFC6CDE0),
    // Tertiary — amber accent (warnings, P2P tags, FilledTonalButton hover)
    tertiary = Amber,
    onTertiary = Color(0xFF241000),
    tertiaryContainer = AmberContainerDark,
    onTertiaryContainer = AmberContainer,
    // Error
    error = ErrorDark,
    onError = Color(0xFF3A0A0A),
    errorContainer = ErrorDarkContainer,
    onErrorContainer = OnErrorDarkContainer,
    // Background / surface
    background = Dark,
    onBackground = Color(0xFFE7EAF2),
    surface = DarkSurface,
    onSurface = Color(0xFFE7EAF2),
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = DarkOnSurfaceVariant,
    surfaceContainerLowest = Color(0xFF15191E),
    surfaceContainerLow = DarkSurfaceContainer,
    surfaceContainer = DarkSurfaceContainer,
    surfaceContainerHigh = DarkSurfaceContainerHigh,
    surfaceContainerHighest = DarkSurfaceContainerHighest,
    // Outline — used by dividers + OutlinedTextField borders
    outline = DarkOutline,
    outlineVariant = DarkOutlineVariant,
    // Inverse — for snackbar / inverse-themed surfaces
    inverseSurface = Color(0xFFE7EAF2),
    inverseOnSurface = Color(0xFF1B1F24),
    inversePrimary = Pine,
    // Scrim — used by ModalBottomSheet / Dialog
    scrim = Color(0xFF000000),
)

private val LightColors = lightColorScheme(
    // Identity
    primary = Pine,
    onPrimary = Color.White,
    primaryContainer = PineContainer,
    onPrimaryContainer = Color(0xFF08200E),
    // Secondary — neutral container chips
    secondary = Color(0xFF5A6271),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8EAF6),
    onSecondaryContainer = Color(0xFF2F3542),
    // Tertiary — amber accent
    tertiary = AmberDark,
    onTertiary = Color.White,
    tertiaryContainer = AmberContainer,
    onTertiaryContainer = AmberContainerDark,
    // Error
    error = ErrorLight,
    onError = Color.White,
    errorContainer = ErrorLightContainer,
    onErrorContainer = OnErrorLightContainer,
    // Background / surface
    background = Color(0xFFF7F8FB),
    onBackground = Color(0xFF191C22),
    surface = Color.White,
    onSurface = Color(0xFF191C22),
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = LightOnSurfaceVariant,
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF7F8FB),
    surfaceContainer = LightSurfaceContainer,
    surfaceContainerHigh = LightSurfaceContainerHigh,
    surfaceContainerHighest = LightSurfaceContainerHighest,
    // Outline
    outline = LightOutline,
    outlineVariant = LightOutlineVariant,
    // Inverse
    inverseSurface = Color(0xFF191C22),
    inverseOnSurface = Color(0xFFE7EAF2),
    inversePrimary = PineBright,
    // Scrim
    scrim = Color(0xFF000000),
)

@Composable
fun ProtoCleanTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
