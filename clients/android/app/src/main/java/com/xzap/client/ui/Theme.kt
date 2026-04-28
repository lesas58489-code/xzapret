package com.xzap.client.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Color tokens straight from the design handoff.
 *  - bg / bgPure: near-black surfaces
 *  - accent: lime, used when CONNECTED (slash, peer dots, stat highlights, switch on)
 *  - error / errorSoft: red palette for ERROR state
 *  - surface1..3, border, textSecondary..quaternary: layered grays
 */
object XzapColors {
    val Bg              = Color(0xFF0A0A0B)
    val BgPure          = Color(0xFF000000)
    val Fg              = Color(0xFFFFFFFF)
    val Accent          = Color(0xFFC6FF3D)
    val Error           = Color(0xFFFF4D4D)
    val ErrorSoft       = Color(0xFFFFB3B3)
    val Surface1        = Color(0x08FFFFFF) // ~ rgba(255,255,255,0.03)
    val Surface2        = Color(0x0AFFFFFF) // 0.04
    val Surface3        = Color(0x0FFFFFFF) // 0.06
    val Border          = Color(0x14FFFFFF) // 0.08
    val TextSecondary   = Color(0x8CFFFFFF) // 0.55
    val TextTertiary    = Color(0x73FFFFFF) // 0.45
    val TextQuaternary  = Color(0x66FFFFFF) // 0.40
}

/** Whether the user has reduced-motion enabled (falls back to false on older Android). */
val LocalReduceMotion = staticCompositionLocalOf { false }

@Composable
fun XzapTheme(content: @Composable () -> Unit) {
    val scheme = darkColorScheme(
        background = XzapColors.Bg,
        surface    = XzapColors.Bg,
        primary    = XzapColors.Accent,
        onBackground = XzapColors.Fg,
        onSurface  = XzapColors.Fg,
        error      = XzapColors.Error,
    )
    MaterialTheme(
        colorScheme = scheme,
        content = content,
    )
}
