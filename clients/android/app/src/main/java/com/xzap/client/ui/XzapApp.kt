package com.xzap.client.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

/** Connection state mirrored to the UI. Production: backed by VpnService flow. */
enum class VpnState { IDLE, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

/** Live stats reported to the UI when CONNECTED. Phase 4 wires real telemetry. */
data class TunnelStats(
    val activeTunnels: Int = 0, // 0..N (each server contributes ~3 tunnels in pool)
    val totalCap:      Int = 9, // visual cap for the swarm dots grid
    val avgRttMs:      Int = 0,
    val downKBps:      Int = 0,
    val upKBps:        Int = 0,
    val uptimeSec:     Int = 0,
)

/**
 * Main app screen — Phase 1 stub of the new design.
 *
 * Hi-fi target (see design/README.md) has 6 zones top→bottom:
 *   1. App top bar with eyebrow "XZAPRET" + overflow menu
 *   2. Tunnel-swarm chip with peer-dot grid + RTT
 *   3. Big Xzapret wordmark-button (this Phase: simple text; Phase 2: animated slash)
 *   4. Caption under button
 *   5. Stats row (CONNECTED only)
 *   6. Toggle row: kill switch / auto-connect (visual only Phase 1)
 *   7. Error banner (ERROR only)
 *
 * Phase 1 shows the layout skeleton with all five states accessible via tap.
 * Phase 2 will replace the placeholder wordmark with the Canvas-rendered
 * "Xzapret" + animated slash from the spec.
 */
@Composable
fun XzapApp(
    state: VpnState,
    stats: TunnelStats,
    killSwitchOn: Boolean,
    autoConnectOn: Boolean,
    onTapButton: () -> Unit,
    onKillSwitchToggle: (Boolean) -> Unit,
    onAutoConnectToggle: (Boolean) -> Unit,
    onShareLogs: () -> Unit,
    onReconnect: () -> Unit = {},
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = XzapColors.Bg,
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            TopBar(onShareLogs = onShareLogs, onReconnect = onReconnect)
            SwarmChip(state = state, stats = stats)
            Spacer(Modifier.height(8.dp))

            // Big button area
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                XZapretButton(state = state, onTap = onTapButton)
            }

            AnimatedVisibility(
                visible = state == VpnState.CONNECTED,
                enter = fadeIn(tween(400)),
                exit = fadeOut(tween(200)),
            ) {
                StatsRow(stats = stats)
            }

            ToggleRow(
                killOn = killSwitchOn,
                autoOn = autoConnectOn,
                onKill = onKillSwitchToggle,
                onAuto = onAutoConnectToggle,
            )

            // Error banner: top of screen in spec; here we put it just above
            // toggles for now — Phase 3 will move it to its proper position.
            AnimatedVisibility(
                visible = state == VpnState.ERROR,
                enter = fadeIn(tween(200)),
                exit = fadeOut(tween(200)),
            ) {
                ErrorBanner()
            }
        }
    }
}

@Composable
private fun TopBar(onShareLogs: () -> Unit, onReconnect: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 14.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "XZAPRET",
            style = TextStyle(
                color = XzapColors.TextSecondary,
                fontSize = 13.sp,
                letterSpacing = 0.22.em,
                fontWeight = FontWeight.Medium,
            ),
        )
        Spacer(Modifier.weight(1f))
        var menuOpen by remember { mutableStateOf(false) }
        Box {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(XzapColors.Surface3)
                    .clickable { menuOpen = true },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "⋮",
                    style = TextStyle(color = XzapColors.Fg, fontSize = 18.sp),
                )
            }
            DropdownMenu(
                expanded = menuOpen,
                onDismissRequest = { menuOpen = false },
            ) {
                DropdownMenuItem(
                    text = { Text("Reconnect") },
                    onClick = { menuOpen = false; onReconnect() },
                )
                DropdownMenuItem(
                    text = { Text("Share logs") },
                    onClick = { menuOpen = false; onShareLogs() },
                )
            }
        }
    }
}

@Composable
private fun SwarmChip(state: VpnState, stats: TunnelStats) {
    Row(
        modifier = Modifier
            .padding(horizontal = 18.dp, vertical = 6.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(XzapColors.Surface2)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // 3×3 dot grid (Phase 2 will animate per-peer fade-in / pulse)
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(3) { row ->
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    repeat(3) { col ->
                        val idx = row * 3 + col
                        val lit = state == VpnState.CONNECTED && idx < stats.activeTunnels
                        DotIndicator(lit = lit)
                    }
                }
            }
        }
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Eyebrow(text = "TUNNEL SWARM")
            Spacer(Modifier.height(2.dp))
            Row {
                Text(
                    text = if (state == VpnState.CONNECTED) "${stats.activeTunnels}" else "—",
                    style = TextStyle(
                        color = if (state == VpnState.CONNECTED) XzapColors.Accent else XzapColors.TextTertiary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                    ),
                )
                Text(
                    text = " / ${stats.totalCap} peers",
                    style = TextStyle(color = XzapColors.TextQuaternary, fontSize = 14.sp),
                )
            }
        }
        Column(horizontalAlignment = Alignment.End) {
            Eyebrow(text = "RTT")
            Spacer(Modifier.height(2.dp))
            Text(
                text = if (state == VpnState.CONNECTED && stats.avgRttMs > 0) "${stats.avgRttMs}ms" else "—",
                style = TextStyle(
                    color = if (state == VpnState.CONNECTED) XzapColors.Accent else XzapColors.TextTertiary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium,
                ),
            )
        }
    }
}

@Composable
private fun DotIndicator(lit: Boolean) {
    val color by animateFloatAsState(
        targetValue = if (lit) 1f else 0.2f,
        animationSpec = tween(durationMillis = 220),
        label = "dot",
    )
    Box(
        modifier = Modifier
            .size(6.dp)
            .clip(RoundedCornerShape(3.dp))
            .background(if (lit) XzapColors.Accent.copy(alpha = color) else XzapColors.Border),
    )
}

@Composable
private fun ButtonStub(state: VpnState, onTap: () -> Unit) {
    val pressedScale by animateFloatAsState(
        targetValue = 1f,
        animationSpec = tween(140),
        label = "press",
    )
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clickable { onTap() }
            .padding(40.dp),
    ) {
        // PHASE 1 PLACEHOLDER: just bold text; Phase 2 will draw the real
        // wordmark with the Canvas slash and clipPath split.
        val slashColor = when (state) {
            VpnState.CONNECTED      -> XzapColors.Accent
            VpnState.ERROR          -> XzapColors.Error
            else                    -> XzapColors.Fg
        }
        Text(
            text = "Xzapret",
            style = TextStyle(
                color = XzapColors.Fg,
                fontSize = 64.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-0.04).em,
            ),
        )
        Spacer(Modifier.height(8.dp))
        // Crude placeholder for the slash — a horizontal line that changes color
        // by state. Phase 2 replaces with the diagonal Canvas-rendered slash.
        Box(
            modifier = Modifier
                .height(3.dp)
                .width(if (state == VpnState.CONNECTED || state == VpnState.ERROR) 220.dp else 0.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(slashColor),
        )
        Spacer(Modifier.height(20.dp))
        Text(
            text = captionFor(state),
            style = TextStyle(
                color = captionColor(state),
                fontSize = 13.sp,
                letterSpacing = 0.18.em,
                fontWeight = FontWeight.Medium,
            ),
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

private fun captionColor(state: VpnState): Color = when (state) {
    VpnState.CONNECTED -> XzapColors.Accent
    VpnState.ERROR     -> XzapColors.Error
    else               -> XzapColors.TextSecondary
}

@Composable
private fun StatsRow(stats: TunnelStats) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        StatCard("DOWN ↓", "${stats.downKBps}", "KB/s", modifier = Modifier.weight(1f))
        StatCard("UP ↑",   "${stats.upKBps}",   "KB/s", modifier = Modifier.weight(1f))
        StatCard("TIME",   formatUptime(stats.uptimeSec), "", modifier = Modifier.weight(1f))
    }
}

@Composable
private fun StatCard(eyebrow: String, value: String, unit: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(XzapColors.Surface1)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Eyebrow(text = eyebrow)
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                text = value,
                style = TextStyle(color = XzapColors.Fg, fontSize = 16.sp, fontWeight = FontWeight.SemiBold),
            )
            if (unit.isNotEmpty()) {
                Spacer(Modifier.width(4.dp))
                Text(
                    text = unit,
                    style = TextStyle(color = XzapColors.TextQuaternary, fontSize = 10.sp),
                )
            }
        }
    }
}

@Composable
private fun ToggleRow(killOn: Boolean, autoOn: Boolean, onKill: (Boolean) -> Unit, onAuto: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 4.dp, bottom = 24.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        ToggleCard(label = "Kill switch", on = killOn, onChange = onKill, modifier = Modifier.weight(1f))
        ToggleCard(label = "Auto-connect", on = autoOn, onChange = onAuto, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun ToggleCard(label: String, on: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(XzapColors.Surface1)
            .clickable { onChange(!on) }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = TextStyle(color = XzapColors.Fg, fontSize = 13.sp, fontWeight = FontWeight.Medium),
            modifier = Modifier.weight(1f),
        )
        Switch(checked = on)
    }
}

@Composable
private fun Switch(checked: Boolean) {
    val knobX by animateFloatAsState(
        targetValue = if (checked) 16f else 2f,
        animationSpec = tween(200),
        label = "knob",
    )
    Box(
        modifier = Modifier
            .width(34.dp)
            .height(20.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(if (checked) XzapColors.Accent else XzapColors.Surface3),
    ) {
        Box(
            modifier = Modifier
                .padding(top = 2.dp, start = knobX.dp)
                .size(16.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(XzapColors.Bg),
        )
    }
}

@Composable
private fun ErrorBanner() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 6.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(XzapColors.Error.copy(alpha = 0.12f))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(
            text = "Connection dropped — reconnecting…",
            style = TextStyle(color = XzapColors.ErrorSoft, fontSize = 13.sp),
        )
    }
}

@Composable
private fun Eyebrow(text: String) {
    Text(
        text = text,
        style = TextStyle(
            color = XzapColors.TextTertiary,
            fontSize = 10.sp,
            letterSpacing = 0.18.em,
            fontWeight = FontWeight.Medium,
        ),
    )
}

private fun formatUptime(seconds: Int): String {
    val m = seconds / 60
    val s = seconds % 60
    return "%02d:%02d".format(m, s)
}
