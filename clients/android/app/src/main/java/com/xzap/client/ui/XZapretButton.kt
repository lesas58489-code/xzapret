package com.xzap.client.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

/**
 * Animated wordmark-as-button. The mark "Xzapret" set in heavy bold; the
 * diagonal slash that cuts through "zapret" is the connection-state
 * indicator. Slash draws in left→right when CONNECTING, retracts
 * right→left when DISCONNECTING. While CONNECTED slash glows accent
 * (lime), bottom half of wordmark stays slid ~14px along the slash-normal,
 * a soft halo breathes behind. ERROR turns slash red.
 *
 * See design_handoff_xzapret_vpn_button/README.md for the source-of-truth
 * geometry and timings. ViewBox 1000×360, slash from (305,268) to (880,152).
 */

// Slash geometry in design viewBox (1000 × 360)
private const val VB_W = 1000f
private const val VB_H = 360f
private const val SLASH_X1 = 305f
private const val SLASH_Y1 = 268f
private const val SLASH_X2 = 880f
private const val SLASH_Y2 = 152f
private const val SLASH_STROKE_VB = 22f       // line width in viewBox units (~6% of VB_H)
private const val FONT_SIZE_VB = 280f         // wordmark height in viewBox units
private const val BASELINE_Y_VB = 248f        // text baseline in viewBox space
private const val CUT_AMOUNT_VB = 14f         // slide distance along slash-normal

// Slash unit-normal (90° CCW of slash direction); along which the bottom half slides.
// Per spec: dir = (0.9802, -0.1977), norm = (0.1977, 0.9802) → "down-left" displacement.
private const val NORM_X = 0.1977f
private const val NORM_Y = 0.9802f

private val SlashEasing = CubicBezierEasing(0.7f, 0.0f, 0.3f, 1f)
private val BounceEasing = CubicBezierEasing(0.34f, 1.56f, 0.64f, 1f)

@Composable
fun XZapretButton(
    state: VpnState,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = XzapColors.Accent,
) {
    // State-derived animated values
    val cutAmount by animateFloatAsState(
        targetValue = if (state == VpnState.IDLE || state == VpnState.DISCONNECTING) 0f else 1f,
        animationSpec = tween(550, easing = SlashEasing),
        label = "cut",
    )
    val slashProgress by animateFloatAsState(
        targetValue = when (state) {
            VpnState.IDLE, VpnState.DISCONNECTING -> 0f
            else -> 1f
        },
        animationSpec = tween(550, easing = SlashEasing),
        label = "slash",
    )
    val slashColor by animateColorAsState(
        targetValue = when (state) {
            VpnState.ERROR -> XzapColors.Error
            VpnState.CONNECTED -> accent
            else -> Color.White
        },
        animationSpec = tween(220),
        label = "slashColor",
    )
    val haloAlpha by animateFloatAsState(
        targetValue = if (state == VpnState.CONNECTED) 1f else 0f,
        animationSpec = tween(600),
        label = "halo",
    )

    // Tap-bounce
    var pressed by remember { mutableStateOf(false) }
    val pressScale by animateFloatAsState(
        targetValue = if (pressed) 0.96f else 1f,
        animationSpec = tween(140, easing = BounceEasing),
        label = "press",
    )

    // Reduced-motion accommodation: skip looping animations, keep transitional ones.
    val reduceMotion = LocalReduceMotion.current

    // Halo "breathing" loop — CONNECTED, scale 0.92↔1.06, 2.4s, ease-in-out.
    // When reduce-motion, both endpoints set to 1.0 → animation runs but no
    // visual motion (cleaner than conditional animateFloat which breaks `by`).
    val infinite = rememberInfiniteTransition(label = "infinite")
    val haloPulse by infinite.animateFloat(
        initialValue = if (reduceMotion) 1f else 0.92f,
        targetValue  = if (reduceMotion) 1f else 1.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2400, easing = CubicBezierEasing(0.4f, 0f, 0.6f, 1f)),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "halo",
    )

    // Idle dashed-ring rotation — 24s/turn. reduce-motion → target equals
    // initial so it stays static at 0°.
    val idleRingAngle by infinite.animateFloat(
        initialValue = 0f,
        targetValue  = if (reduceMotion) 0f else 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 24_000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "idleRing",
    )

    // ERROR glitch — bottom-half jitter on 220ms square-wave loop. Same
    // pattern: target=initial when not in ERROR or reduce-motion → no motion.
    val glitchActive = state == VpnState.ERROR && !reduceMotion
    val glitchPhase by infinite.animateFloat(
        initialValue = 0f,
        targetValue  = if (glitchActive) 1f else 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 110, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "glitch",
    )
    val glitchDx = if (glitchActive) (if (glitchPhase < 0.5f) 3f else -3f) else 0f
    val glitchDy = if (glitchActive) (if (glitchPhase < 0.5f) -1f else 1f) else 0f

    // Concentric ring pulse — one-shot wave on CONNECTING (scale 0.85→1.6, 900ms)
    val ringPulse = remember { Animatable(0f) }
    LaunchedEffect(state) {
        if (state == VpnState.CONNECTING) {
            ringPulse.snapTo(0f)
            ringPulse.animateTo(
                targetValue = 1f,
                animationSpec = tween(durationMillis = 900, easing = CubicBezierEasing(0.16f, 1f, 0.3f, 1f)),
            )
        } else {
            ringPulse.snapTo(0f)
        }
    }

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(300.dp)
                .scale(pressScale)
                .pointerInput(Unit) {
                    detectTapGestures(
                        onPress = {
                            pressed = true
                            try { tryAwaitRelease() } finally { pressed = false }
                        },
                        onTap = { onTap() },
                    )
                },
            contentAlignment = Alignment.Center,
        ) {
            // Halo behind everything (CONNECTED only) — breathing scale
            if (haloAlpha > 0f) {
                Box(
                    modifier = Modifier
                        .matchParentSize()
                        .scale(haloPulse)
                        .alpha(haloAlpha * 0.55f)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(accent.copy(alpha = 0.30f), Color.Transparent),
                                radius = 360f,
                            )
                        )
                )
            }

            // Idle dashed ring (rotating, only when fully IDLE)
            if (state == VpnState.IDLE) {
                Canvas(modifier = Modifier.matchParentSize()) {
                    val cx = size.width / 2f
                    val cy = size.height / 2f
                    val ringRadius = minOf(size.width, size.height) / 2f * 0.92f
                    rotate(idleRingAngle, pivot = Offset(cx, cy)) {
                        drawCircle(
                            color = XzapColors.TextQuaternary,
                            radius = ringRadius,
                            center = Offset(cx, cy),
                            style = Stroke(
                                width = 1.5f,
                                pathEffect = PathEffect.dashPathEffect(floatArrayOf(8f, 14f)),
                            ),
                        )
                    }
                }
            }

            // Concentric ring pulse on CONNECTING (one-shot 900ms wave)
            if (ringPulse.value > 0f && ringPulse.value < 1f) {
                val p = ringPulse.value
                val pulseScale = 0.85f + (1.6f - 0.85f) * p
                val pulseAlpha = 1f - p // fades out as it expands
                Canvas(
                    modifier = Modifier
                        .matchParentSize()
                        .scale(pulseScale)
                        .alpha(pulseAlpha),
                ) {
                    val r = minOf(size.width, size.height) / 2f * 0.7f
                    drawCircle(
                        color = accent,
                        radius = r,
                        center = Offset(size.width / 2f, size.height / 2f),
                        style = Stroke(width = 2f),
                    )
                }
            }

            // Wordmark + slash
            Canvas(modifier = Modifier.matchParentSize()) {
                drawWordmark(
                    cutFraction = cutAmount,
                    slashFraction = slashProgress,
                    slashColor = slashColor,
                    glitchDx = glitchDx,
                    glitchDy = glitchDy,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        Text(
            text = captionFor(state),
            style = TextStyle(
                color = captionColor(state, accent),
                fontSize = 13.sp,
                letterSpacing = 0.18.em,
                fontWeight = FontWeight.Medium,
            ),
        )
    }
}

private fun DrawScope.drawWordmark(
    cutFraction: Float,
    slashFraction: Float,
    slashColor: Color,
    glitchDx: Float = 0f,
    glitchDy: Float = 0f,
) {
    // Map design viewBox (1000×VB_H) onto the actual pixel canvas, fit-by-width
    val sx = size.width / VB_W
    val sy = size.height / VB_H
    val s = minOf(sx, sy)
    val pxW = VB_W * s
    val pxH = VB_H * s
    val ox = (size.width - pxW) / 2f
    val oy = (size.height - pxH) / 2f

    fun vb(x: Float, y: Float) = Offset(ox + x * s, oy + y * s)

    val sx1 = ox + SLASH_X1 * s
    val sy1 = oy + SLASH_Y1 * s
    val sx2 = ox + SLASH_X2 * s
    val sy2 = oy + SLASH_Y2 * s

    val cutDx = CUT_AMOUNT_VB * NORM_X * s * cutFraction
    val cutDy = CUT_AMOUNT_VB * NORM_Y * s * cutFraction

    // Top-half clip: polygon above the slash line.
    val topPath = Path().apply {
        moveTo(vb(0f, 0f).x, vb(0f, 0f).y)
        lineTo(sx1, sy1)
        lineTo(sx2, sy2)
        lineTo(vb(VB_W, 0f).x, vb(VB_W, 0f).y)
        close()
    }
    // Bottom-half clip: polygon below the slash line.
    val bottomPath = Path().apply {
        moveTo(vb(0f, VB_H).x, vb(0f, VB_H).y)
        lineTo(sx1, sy1)
        lineTo(sx2, sy2)
        lineTo(vb(VB_W, VB_H).x, vb(VB_W, VB_H).y)
        close()
    }

    val paint = android.graphics.Paint().apply {
        color = android.graphics.Color.WHITE
        textSize = FONT_SIZE_VB * s
        isAntiAlias = true
        textAlign = android.graphics.Paint.Align.CENTER
        typeface = android.graphics.Typeface.create(
            android.graphics.Typeface.SANS_SERIF, android.graphics.Typeface.BOLD
        )
        letterSpacing = -0.04f
    }
    val textY = oy + BASELINE_Y_VB * s
    val textX = size.width / 2f

    // Top half — drawn in clipped region, NOT translated
    clipPath(topPath) {
        drawIntoCanvas { canvas ->
            canvas.nativeCanvas.drawText("Xzapret", textX, textY, paint)
        }
    }
    // Bottom half — clipped + translated by cutAmount*norm + ERROR glitch jitter
    clipPath(bottomPath) {
        translate(left = cutDx + glitchDx, top = cutDy + glitchDy) {
            drawIntoCanvas { canvas ->
                canvas.nativeCanvas.drawText("Xzapret", textX, textY, paint)
            }
        }
    }

    // Slash itself — partial line based on slashFraction. Three layers:
    //   1. Wide soft blur (BlurMaskFilter) for the drop-shadow glow
    //   2. Mid semi-transparent stroke
    //   3. Crisp top line
    if (slashFraction > 0f) {
        val drawX2 = sx1 + (sx2 - sx1) * slashFraction
        val drawY2 = sy1 + (sy2 - sy1) * slashFraction
        val blurPaint = android.graphics.Paint().apply {
            color = slashColor.toArgb()
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = SLASH_STROKE_VB * s
            strokeCap = android.graphics.Paint.Cap.ROUND
            isAntiAlias = true
            maskFilter = android.graphics.BlurMaskFilter(
                12f * s, android.graphics.BlurMaskFilter.Blur.NORMAL
            )
        }
        drawIntoCanvas { canvas ->
            canvas.nativeCanvas.drawLine(sx1, sy1, drawX2, drawY2, blurPaint)
        }
        // Mid-glow (wider, semi-transparent)
        drawLine(
            color = slashColor.copy(alpha = 0.6f),
            start = Offset(sx1, sy1),
            end = Offset(drawX2, drawY2),
            strokeWidth = SLASH_STROKE_VB * s * 1.6f,
            cap = StrokeCap.Round,
        )
        // Crisp line
        drawLine(
            color = slashColor,
            start = Offset(sx1, sy1),
            end = Offset(drawX2, drawY2),
            strokeWidth = SLASH_STROKE_VB * s,
            cap = StrokeCap.Round,
        )
    }
}

private fun captionFor(state: VpnState): String = when (state) {
    VpnState.IDLE          -> "TAP TO CONNECT"
    VpnState.CONNECTING    -> "CONNECTING…"
    VpnState.CONNECTED     -> "CONNECTED"
    VpnState.DISCONNECTING -> "DISCONNECTING…"
    VpnState.ERROR         -> "RECONNECTING…"
}

private fun captionColor(state: VpnState, accent: Color): Color = when (state) {
    VpnState.CONNECTED -> accent
    VpnState.ERROR     -> XzapColors.Error
    else               -> XzapColors.TextSecondary
}
