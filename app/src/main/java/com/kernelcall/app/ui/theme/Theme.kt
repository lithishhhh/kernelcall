package com.kernelcall.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val KernelColorScheme = darkColorScheme(
    primary = KernelGreen,
    onPrimary = KernelBackground,
    primaryContainer = KernelGreen,
    onPrimaryContainer = KernelBackground,
    secondary = KernelCyan,
    onSecondary = KernelBackground,
    background = KernelBackground,
    onBackground = KernelTextPrimary,
    surface = KernelSurface,
    onSurface = KernelTextPrimary,
    surfaceVariant = KernelSurfaceHigh,
    onSurfaceVariant = KernelTextSecondary,
    outline = KernelBorder,
    error = KernelRed,
    onError = KernelBackground,
    errorContainer = KernelRed,
    onErrorContainer = KernelBackground,
)

@Composable
fun KernelCallTheme(content: @Composable () -> Unit) {
    // The app is intentionally a dark "security console" theme in both modes.
    isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = KernelColorScheme,
        typography = AppTypography,
        content = content,
    )
}
