package com.xzap.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.xzap.client.ui.TunnelStats
import com.xzap.client.ui.VpnState
import com.xzap.client.ui.XzapApp
import com.xzap.client.ui.XzapTheme
import kotlinx.coroutines.delay
import org.json.JSONObject

/**
 * Compose-based main activity. Phase 1 of the redesign per
 * design_handoff_xzapret_vpn_button/README.md — wires the new screen
 * skeleton with simulated state. Server/Port/Key are no longer in the UI;
 * they come from BuildConfig (populated from local.properties at build time).
 *
 * Tap-to-connect logic, real VpnState wiring, and the Canvas-rendered
 * wordmark with animated slash come in Phase 2.
 */
class MainActivity : ComponentActivity() {

    companion object {
        private const val VPN_REQUEST_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            android.util.Log.e("XZAP-CRASH", "thread=${t.name} unhandled", e)
        }
        android.util.Log.i("XZAP-BOOT", "MainActivity onCreate start")
        try {
            mobile.Mobile.touch()
            android.util.Log.i("XZAP-BOOT", "Mobile.touch OK (native lib loaded)")
        } catch (t: Throwable) {
            android.util.Log.e("XZAP-BOOT", "Mobile.touch failed", t)
        }
        val reduceMotion = runCatching {
            android.provider.Settings.Global.getFloat(
                contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE
            ) == 0f
        }.getOrDefault(false)
        setContent {
            XzapTheme {
                androidx.compose.runtime.CompositionLocalProvider(
                    com.xzap.client.ui.LocalReduceMotion provides reduceMotion,
                ) {
                // VPN state теперь приходит из сервиса через StateFlow.
                // Если сервис ещё не запущен — observable начинается с IDLE.
                val health by XzapVpnService.health.collectAsState()
                val countdownSec by XzapVpnService.countdown.collectAsState()
                val state = healthToUiState(health)
                // Тумблеры — read-through из Prefs, write-through через onToggle.
                var killOn by remember { mutableStateOf(Prefs.isKillSwitch(this@MainActivity)) }
                var autoOn by remember { mutableStateOf(Prefs.isAutoConnect(this@MainActivity)) }
                var stats by remember { mutableStateOf(TunnelStats()) }
                var showBypassDialog by remember { mutableStateOf(false) }
                // Poll Mobile.stats() once per second while CONNECTED.
                // Pulls active tunnel count, average RTT, uptime; computes
                // DOWN/UP KB/s as delta of bytes_in/out between polls.
                LaunchedEffect(state) {
                    if (state != VpnState.CONNECTED && state != VpnState.ERROR) return@LaunchedEffect
                    var prevIn = 0L
                    var prevOut = 0L
                    var prevTimeMs = System.currentTimeMillis()
                    while (true) {
                        try {
                            val js = mobile.Mobile.stats()
                            val obj = JSONObject(js)
                            val bIn = obj.optLong("bytes_in")
                            val bOut = obj.optLong("bytes_out")
                            val now = System.currentTimeMillis()
                            val dt = (now - prevTimeMs).coerceAtLeast(1)
                            val downKBps = if (prevIn > 0) ((bIn - prevIn) * 1000 / dt / 1024).toInt().coerceAtLeast(0) else 0
                            val upKBps   = if (prevOut > 0) ((bOut - prevOut) * 1000 / dt / 1024).toInt().coerceAtLeast(0) else 0
                            prevIn = bIn; prevOut = bOut; prevTimeMs = now
                            stats = TunnelStats(
                                activeTunnels = obj.optInt("active"),
                                totalCap     = 9,
                                avgRttMs     = obj.optInt("avg_rtt_ms"),
                                uptimeSec    = obj.optInt("uptime_sec"),
                                downKBps     = downKBps,
                                upKBps       = upKBps,
                            )
                        } catch (_: Throwable) { /* swallow JSON / native errors */ }
                        delay(1000)
                    }
                }
                XzapApp(
                    state = state,
                    stats = stats,
                    killSwitchOn = killOn,
                    autoConnectOn = autoOn,
                    countdownSec = countdownSec,
                    onTapButton = {
                        when (state) {
                            VpnState.IDLE -> requestVpn { /* state придёт из flow */ }
                            VpnState.CONNECTED, VpnState.ERROR -> disconnect()
                            else -> { /* ignore taps mid-transition */ }
                        }
                    },
                    onKillSwitchToggle = {
                        killOn = it
                        Prefs.setKillSwitch(this@MainActivity, it)
                    },
                    onAutoConnectToggle = {
                        autoOn = it
                        Prefs.setAutoConnect(this@MainActivity, it)
                    },
                    onShareLogs = { shareLogs() },
                    onReconnect = {
                        // Существующий Reconnect — мягкий (disconnect + 800ms + connect).
                        // Жёсткий вариант теперь живёт за onKillSwitchTap.
                        if (state == VpnState.CONNECTED || state == VpnState.ERROR) {
                            disconnect()
                            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                                requestVpn { /* state из flow */ }
                            }, 800)
                        }
                    },
                    onKillSwitchTap = { killSwitch() },
                    onBypassApps = { showBypassDialog = true },
                    onSystemAlwaysOnVpn = {
                        // Открывает экран Настройки → VPN, где есть тумблеры
                        // «Постоянная VPN» и «Блокировать соединения без VPN» —
                        // это встроенный системный kill-switch. Получить эти
                        // привилегии программно (WRITE_SECURE_SETTINGS) нельзя
                        // без adb pm grant.
                        try {
                            startActivity(Intent("android.net.vpn.SETTINGS").apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            })
                        } catch (_: Throwable) {
                            // Fallback: общие настройки сети
                            startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            })
                        }
                    },
                )
                if (showBypassDialog) {
                    com.xzap.client.ui.BypassAppsDialog(
                        initial = Prefs.getBypassPackages(this@MainActivity),
                        onApply = { newSet ->
                            Prefs.setBypassPackages(this@MainActivity, newSet)
                        },
                        onDismiss = { showBypassDialog = false },
                    )
                }
                }
            }
        }
    }

    private var pendingStart: (() -> Unit)? = null

    private fun requestVpn(onStarted: () -> Unit) {
        pendingStart = onStarted
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, VPN_REQUEST_CODE) else startVpn()
    }

    @Deprecated("Compat shim")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) startVpn()
    }

    private fun startVpn() {
        val intent = Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_CONNECT
            putExtra(XzapVpnService.EXTRA_SERVER, BuildConfig.XZAP_SERVERS)
            putExtra(XzapVpnService.EXTRA_PORT, BuildConfig.XZAP_PORT)
            putExtra(XzapVpnService.EXTRA_KEY, BuildConfig.XZAP_KEY)
            putExtra(XzapVpnService.EXTRA_TLS_PROFILE, "chrome131")
            putExtra(XzapVpnService.EXTRA_WS_FALLBACK, BuildConfig.XZAP_WS_FALLBACK)
        }
        startService(intent)
        pendingStart?.invoke()
        pendingStart = null
    }

    private fun disconnect() {
        startService(Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_DISCONNECT
        })
    }

    private fun killSwitch() {
        startService(Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_KILLSWITCH
        })
    }

    /**
     * Grab last few thousand lines of our process's logcat for the relevant
     * tags, write to cache, pop a Share intent so user can send the file.
     */
    private fun shareLogs() {
        android.widget.Toast.makeText(this, "Collecting logs…", android.widget.Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val logsDir = java.io.File(cacheDir, "logs")
                logsDir.mkdirs()
                val logFile = java.io.File(logsDir, "xzap_log.txt")

                val proc = Runtime.getRuntime().exec(arrayOf(
                    "logcat", "-d", "-t", "5000",
                    "XZAP-BOOT:V", "XZAP-CRASH:V", "XZAP-LOG:V",
                    "XzapVpnService:V", "MainActivity:V",
                    "GoLog:V",
                    "*:S"
                ))

                val secretKey = BuildConfig.XZAP_KEY
                logFile.bufferedWriter().use { writer ->
                    writer.write("=== XZAP debug log ===\n")
                    writer.write("Captured: ${java.util.Date()}\n")
                    writer.write("Android: ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})\n")
                    writer.write("Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}\n")
                    writer.write("App: ${packageName} v${packageManager.getPackageInfo(packageName, 0).versionName}\n")
                    writer.write("=====================\n\n")
                    proc.inputStream.bufferedReader().forEachLine { line ->
                        val sanitized = if (secretKey.length >= 16) {
                            line.replace(secretKey, "<KEY-REDACTED>")
                        } else line
                        writer.write(sanitized)
                        writer.write("\n")
                    }
                }
                proc.waitFor()

                val uri = androidx.core.content.FileProvider.getUriForFile(
                    this, "$packageName.fileprovider", logFile
                )
                val sendIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    putExtra(Intent.EXTRA_SUBJECT, "XZAP debug log")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                runOnUiThread {
                    startActivity(Intent.createChooser(sendIntent, "Send XZAP log"))
                }
            } catch (e: Exception) {
                android.util.Log.e("XZAP-LOG", "shareLogs failed", e)
                runOnUiThread {
                    android.widget.Toast.makeText(this, "Log export failed: ${e.message}", android.widget.Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }
}

private fun healthToUiState(h: XzapVpnService.VpnHealth): VpnState = when (h) {
    XzapVpnService.VpnHealth.IDLE         -> VpnState.IDLE
    XzapVpnService.VpnHealth.CONNECTING   -> VpnState.CONNECTING
    XzapVpnService.VpnHealth.HEALTHY      -> VpnState.CONNECTED
    XzapVpnService.VpnHealth.DEGRADED     -> VpnState.CONNECTED  // UI продолжает «зелёный», нотификация говорит правду
    XzapVpnService.VpnHealth.RECONNECTING -> VpnState.CONNECTING
    XzapVpnService.VpnHealth.DEAD         -> VpnState.ERROR
}
