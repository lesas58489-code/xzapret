package com.xzap.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import mobile.Mobile
import org.json.JSONObject

/**
 * VPN service: tun2socks + XZAP core (Go, uTLS) — all in xzapcore.aar.
 *
 * Kotlin side is thin: establish TUN, hand FD to Go, wait for ready, update UI.
 */
class XzapVpnService : VpnService() {

    /** Состояние пула, наблюдаемое UI. */
    enum class VpnHealth { IDLE, CONNECTING, HEALTHY, DEGRADED, RECONNECTING, DEAD }

    companion object {
        const val TAG = "XzapVPN"
        const val CHANNEL_ID = "xzap_vpn"
        const val ACTION_CONNECT = "com.xzap.CONNECT"
        const val ACTION_DISCONNECT = "com.xzap.DISCONNECT"
        const val ACTION_KILLSWITCH = "com.xzap.KILLSWITCH"
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"
        const val EXTRA_TLS_PROFILE = "tls_profile"
        const val EXTRA_WS_FALLBACK = "ws_fallback"
        const val SOCKS_PORT = 10808

        /** Соединительный мост Service↔UI. Сервис апдейтит, MainActivity подписывается. */
        private val _health = MutableStateFlow(VpnHealth.IDLE)
        val health: StateFlow<VpnHealth> = _health.asStateFlow()

        /** Сек до Tier-2 действия (kill-switch / hard restart / DEAD). 0 если вне countdown'а. */
        private val _countdown = MutableStateFlow(0)
        val countdown: StateFlow<Int> = _countdown.asStateFlow()

        /** Сколько сек ждать в DEGRADED перед Tier-2 действием. */
        private const val WATCHDOG_COUNTDOWN_SEC = 10

        // Russian apps that detect VPN and refuse to work (banks, gov, marketplaces).
        // Phase A добавляет к этому пользовательский set из Prefs.
        val BYPASS_APPS = listOf(
            "ru.sberbankmobile", "ru.sberbank.online", "ru.sberbankmobile_beta",
            "ru.sberbank.sbol", "ru.sberbank.spasibo", "ru.sberbank.sberdevices.smartapp",
            "com.idamob.tinkoff.android", "com.tinkoff.investing",
            "com.tinkoff.tinkoffbusiness", "ru.tinkoff.mb",
            "ru.vtb24.mobilebanking.android", "ru.vtb.mobilebanking",
            "ru.alfabank.mobile.android", "ru.alfabank.oavdo.amc",
            "ru.raiffeisennews", "ru.gazprombank.android.mobilebank.app",
            "ru.rosbank.android", "ru.mtsbank.mobile", "ru.psbank.mobile",
            "ru.akbars.mobile", "ru.uralsib.mobile", "ru.rshb.mbank",
            "ru.otpbank.mobile", "ru.pochta.post",
            "ru.ozon.app.android", "ru.ozon.seller", "ru.ozon.card.android",
            "ru.ozon.fintech.finance",
            "com.wildberries.ru", "com.wildberries.ru_seller",
            "ru.yandex.taxi", "ru.yandex.eda", "ru.yandex.lavka",
            "ru.yandex.market", "ru.yandex.yandexmaps",
            "ru.yandex.yandexnavi", "ru.yandex.searchplugin",
            "ru.yandex.mail", "ru.yandex.music", "ru.yandex.disk",
            "ru.yandex.weatherplugin", "ru.yandex.metro",
            "ru.yandex.rasp", "ru.yandex.pay",
            "ru.yandex.kinopoisk", "ru.yandex.kinopoisk.tv",
            "com.yandex.browser", "com.yandex.messenger", "com.yandex.mobile.realty",
            "com.yandex.bank", "com.yandex.toloka.androidapp",
            "ru.rostel", "ru.gosuslugi.goskey", "ru.mos.polis.ooms", "ru.mos.ru",
            "ru.aeroflot", "ru.rzd.pass", "ru.s7.airlines",
            "com.vkontakte.android", "com.vk.vkclient", "ru.mail.mailapp",
            "ru.mvideo.androidapp", "ru.dns.dnsshop", "ru.sima.land",
            "ru.leroymerlin.mobileapp",
            "ru.rbc.news", "ru.rambler.news", "ru.yoomoney.android",
            "ru.litres.android",
            "ru.dodopizza.app", "ru.kfc.kfcrus", "ru.burgerking",
            "ru.foodfox.client", "ru.foodband.customer",
        )
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastSeenNetwork: Network? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var watchdogJob: Job? = null

    /** Кеш последних extras для авто-рестарта в watchdog'е. */
    private var cachedServer: String? = null
    private var cachedPort: Int = 443
    private var cachedKey: String? = null
    private var cachedTlsProfile: String = "chrome131"
    private var cachedWsFallback: String = ""

    /** Сколько раз подряд watchdog рестартил сервис без успеха. Сбрасывается при HEALTHY. */
    private var failedRestartStreak = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_KILLSWITCH -> killSwitch()
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 8443)
                val keyB64 = intent.getStringExtra(EXTRA_KEY) ?: return START_NOT_STICKY
                val profile = intent.getStringExtra(EXTRA_TLS_PROFILE) ?: "chrome131"
                val wsFallback = intent.getStringExtra(EXTRA_WS_FALLBACK) ?: ""
                cachedServer = server
                cachedPort = port
                cachedKey = keyB64
                cachedTlsProfile = profile
                cachedWsFallback = wsFallback
                connect(server, port, keyB64, profile, wsFallback)
            }
        }
        return START_STICKY
    }

    private fun connect(server: String, port: Int, keyB64: String, tlsProfile: String, wsFallback: String = "") {
        if (running.get()) {
            disconnect()
            Thread.sleep(500)
        }
        _health.value = VpnHealth.CONNECTING

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))

        // Validate key
        try {
            val decoded = Base64.decode(keyB64.replace(Regex("\\s"), ""), Base64.DEFAULT)
            if (decoded.size != 32) {
                Log.e(TAG, "Invalid key size ${decoded.size} — must be 32 bytes")
                updateNotification("Error: invalid key size")
                _health.value = VpnHealth.DEAD
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return
            }
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Invalid base64 key: ${e.message}")
            updateNotification("Error: invalid key")
            _health.value = VpnHealth.DEAD
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
            return
        }

        // Normalise url-like inputs (autocorrect safety)
        val normalised = when {
            server.startsWith("http://", true)  -> "ws://"  + server.removePrefix("http://")
            server.startsWith("https://", true) -> "wss://" + server.removePrefix("https://")
            else -> server
        }
        val isWs = normalised.startsWith("wss://", true) || normalised.startsWith("ws://", true)

        running.set(true)

        Thread {
            val fd = setupVpn() ?: run {
                Log.e(TAG, "setupVpn returned null")
                running.set(false)
                _health.value = VpnHealth.DEAD
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return@Thread
            }

            // Read Android Private DNS state. If "opportunistic" (Automatic with
            // fallback), Go core will block DoT to force fallback to plain DNS,
            // which our DNS hijack catches. If "hostname" (user-pinned provider)
            // — Go core leaves DoT alone, MainActivity will have shown a dialog.
            val privateDnsMode = try {
                android.provider.Settings.Global.getString(contentResolver, "private_dns_mode") ?: "off"
            } catch (_: Throwable) { "off" }
            Log.i(TAG, "Private DNS mode: $privateDnsMode")

            // Build JSON config for Go core
            val cfg = JSONObject().apply {
                put("key_b64", keyB64.replace(Regex("\\s"), ""))
                put("socks_port", SOCKS_PORT)
                put("tun_fd", fd)
                put("mtu", 1500)
                put("log_level", "warn")
                put("cache_dir", cacheDir.absolutePath)
                put("private_dns_mode", privateDnsMode)
                if (wsFallback.isNotEmpty()) {
                    put("ws_fallback_url", wsFallback)
                }
                if (isWs) {
                    put("transport", "ws")
                    put("ws_url", normalised)
                } else {
                    put("transport", "tls")
                    put("server_host", normalised)
                    put("server_port", port)
                    put("tls_profile", tlsProfile)
                }
            }

            val err = Mobile.start(cfg.toString())
            if (err.isNotEmpty()) {
                Log.e(TAG, "Mobile.start failed: $err")
                updateNotification("Error: $err")
                running.set(false)
                _health.value = VpnHealth.DEAD
                closeVpn()
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return@Thread
            }

            // Wait up to 15s for at least one tunnel ready
            val ready = Mobile.waitReady(15L)
            if (!ready) {
                Log.w(TAG, "No tunnel ready after 15s — continuing anyway")
            }

            val label = if (isWs) normalised else "$normalised:$port"
            updateNotification("Connected to $label")
            Log.i(TAG, "VPN ready (xzapcore + uTLS + tun2socks)")
            _health.value = VpnHealth.HEALTHY
            failedRestartStreak = 0
            registerNetworkCallback()
            startWatchdog()
        }.start()
    }

    /**
     * Watchdog: при `active==0` сразу делаем мягкий kick (Mobile.networkChanged),
     * переходим в DEGRADED + countdown, и даём WATCHDOG_COUNTDOWN_SEC сек на
     * самовосстановление. Если за это время не поднялись — Tier-2 действие:
     *   - killSwitch включён → killSwitch (network rebind + reconnect)
     *   - иначе autoConnect включён → hardRestart (teardown + reconnect)
     *   - иначе → DEAD (notification «нажмите для подключения»)
     *
     * 3 неудачных Tier-2 подряд → DEAD без дальнейших попыток (избегаем
     * рестарт-цикла при длительном сетевом провале).
     */
    private fun startWatchdog() {
        watchdogJob?.cancel()
        _countdown.value = 0
        watchdogJob = scope.launch {
            var zeroSince = 0L  // ms since first time we saw active=0; 0=not in zero-state

            while (running.get()) {
                delay(1000)
                val active = currentActiveCount()
                val now = System.currentTimeMillis()

                if (active > 0) {
                    if (zeroSince != 0L) {
                        Log.i(TAG, "watchdog: pool recovered (active=$active)")
                        updateNotification("Connected")
                        _countdown.value = 0
                    }
                    zeroSince = 0L
                    failedRestartStreak = 0
                    if (_health.value == VpnHealth.DEGRADED ||
                        _health.value == VpnHealth.RECONNECTING) {
                        _health.value = VpnHealth.HEALTHY
                    }
                    continue
                }

                // active == 0
                if (zeroSince == 0L) {
                    Log.w(TAG, "watchdog: pool=0 — immediate soft kick + ${WATCHDOG_COUNTDOWN_SEC}s countdown")
                    zeroSince = now
                    runCatching { Mobile.networkChanged() }
                    _health.value = VpnHealth.DEGRADED
                    _countdown.value = WATCHDOG_COUNTDOWN_SEC
                    updateNotification("Восстанавливаем связь... ${WATCHDOG_COUNTDOWN_SEC}с")
                    continue
                }

                val zeroFor = now - zeroSince
                val remaining = WATCHDOG_COUNTDOWN_SEC - (zeroFor / 1000).toInt()
                if (remaining > 0) {
                    _countdown.value = remaining
                    updateNotification("Восстанавливаем связь... ${remaining}с")
                    continue
                }

                // remaining <= 0 — Tier-2 действие
                _countdown.value = 0
                val killOn = Prefs.isKillSwitch(this@XzapVpnService)
                val autoOn = Prefs.isAutoConnect(this@XzapVpnService)
                when {
                    killOn && failedRestartStreak < 3 -> {
                        Log.w(TAG, "watchdog: T+${zeroFor}ms — killSwitch (killOn=on, streak=$failedRestartStreak)")
                        _health.value = VpnHealth.RECONNECTING
                        updateNotification("Перезагрузка сети...")
                        failedRestartStreak++
                        killSwitch()
                        return@launch  // killSwitch перезапустит watchdog
                    }
                    autoOn && failedRestartStreak < 3 -> {
                        Log.w(TAG, "watchdog: T+${zeroFor}ms — hardRestart (autoOn=on, streak=$failedRestartStreak)")
                        _health.value = VpnHealth.RECONNECTING
                        updateNotification("Переподключение...")
                        failedRestartStreak++
                        hardRestart()
                        return@launch
                    }
                    else -> {
                        Log.e(TAG, "watchdog: T+${zeroFor}ms — DEAD (killOn=$killOn, autoOn=$autoOn, streak=$failedRestartStreak)")
                        _health.value = VpnHealth.DEAD
                        updateNotification("Связь потеряна — нажмите для подключения")
                        return@launch
                    }
                }
            }
        }
    }

    private fun currentActiveCount(): Int = try {
        JSONObject(Mobile.stats()).optInt("active", 0)
    } catch (_: Throwable) { 0 }

    /**
     * Тяжёлый рестарт: полный teardown + connect с теми же параметрами.
     * Используется watchdog'ом и killSwitch'ом.
     */
    private fun hardRestart() {
        val server = cachedServer ?: run {
            Log.e(TAG, "hardRestart: no cached server — abort")
            _health.value = VpnHealth.DEAD
            return
        }
        val key = cachedKey ?: run {
            Log.e(TAG, "hardRestart: no cached key — abort")
            _health.value = VpnHealth.DEAD
            return
        }
        Log.i(TAG, "hardRestart: teardown + reconnect")
        teardownInternal()
        Thread.sleep(800)
        connect(server, cachedPort, key, cachedTlsProfile, cachedWsFallback)
    }

    /**
     * killSwitch (вариант B): полный teardown пула + сброс bindProcessToNetwork
     * + запрос свежей underlying network → reconnect.
     *
     * Это сильнее обычного Reconnect: явно «отвязываемся» от текущей underlying
     * network и просим OS дать нам новую. Радио не трогаем (нельзя — системная
     * привилегия), но с точки зрения OS получаем свежую network reference.
     */
    private fun killSwitch() {
        if (!running.get() && cachedServer == null) {
            Log.i(TAG, "killSwitch: not connected — ignored")
            return
        }
        Log.i(TAG, "killSwitch: tier-B reset (full teardown + network rebind)")
        _health.value = VpnHealth.RECONNECTING
        updateNotification("Перезагрузка сети...")
        scope.launch {
            teardownInternal()
            delay(1500)
            // Снимаем bind на старую network и просим у системы свежую.
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) cm.bindProcessToNetwork(null)
            }
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val gotNetwork = MutableStateFlow<Network?>(null)
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) { gotNetwork.value = network }
            }
            // requestNetwork(req, cb, timeout) требует API 26; используем no-timeout
            // форму (API 21+) и таймаутим сами через while-loop ниже.
            try {
                cm.requestNetwork(req, cb)
            } catch (e: Throwable) {
                Log.w(TAG, "killSwitch: requestNetwork failed: ${e.message}")
            }
            // Ждём ≤5с свежую network
            val deadline = System.currentTimeMillis() + 5000
            while (gotNetwork.value == null && System.currentTimeMillis() < deadline) delay(100)
            runCatching { cm.unregisterNetworkCallback(cb) }
            val net = gotNetwork.value
            if (net != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                runCatching { cm.bindProcessToNetwork(net) }
                Log.i(TAG, "killSwitch: rebound to fresh underlying network=$net")
            } else {
                Log.w(TAG, "killSwitch: no fresh network within 5s — proceeding anyway")
            }
            // Reconnect с теми же параметрами
            val server = cachedServer
            val key = cachedKey
            if (server != null && key != null) {
                connect(server, cachedPort, key, cachedTlsProfile, cachedWsFallback)
            } else {
                Log.e(TAG, "killSwitch: no cached params — staying down")
                _health.value = VpnHealth.DEAD
            }
        }
    }

    /** Закрывает Mobile + TUN, не трогает foreground/health. */
    private fun teardownInternal() {
        watchdogJob?.cancel()
        watchdogJob = null
        unregisterNetworkCallback()
        try { Mobile.stop() } catch (_: Exception) {}
        closeVpn()
        running.set(false)
    }

    /**
     * Register a NetworkCallback that watches for the underlying real network
     * to switch (cellular → Wi-Fi or back). On change we tell Go core to
     * KillAll tunnels — the existing TCP sockets are bound to the old source
     * IP and become zombies after the switch (still "alive" until PING/PONG
     * times out, ~30s, during which the user sees throughput collapse).
     *
     * NET_CAPABILITY_NOT_VPN filters out our own VPN interface so we only
     * track the underlying network.
     */
    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = lastSeenNetwork
                lastSeenNetwork = network
                if (prev == null) {
                    // First network seen since VPN started — initialize, no kick.
                    return
                }
                if (prev != network) {
                    Log.i(TAG, "network changed ($prev → $network) — kicking pool")
                    kickPool()
                }
            }
            override fun onLost(network: Network) {
                Log.i(TAG, "network lost: $network — kicking pool (existing tunnels' source IP just died)")
                if (network == lastSeenNetwork) lastSeenNetwork = null
                // Even if onAvailable hasn't fired yet for the next network,
                // the existing tunnels are dead — kill them now so pick()
                // doesn't keep routing streams through zombie sockets.
                kickPool()
            }
        }
        try {
            cm.registerNetworkCallback(req, cb)
            networkCallback = cb
            Log.i(TAG, "NetworkCallback registered (underlying-network switch detection)")
        } catch (e: Throwable) {
            Log.w(TAG, "registerNetworkCallback failed: ${e.message}")
        }
    }

    private fun kickPool() {
        runCatching { Mobile.networkChanged() }
            .onFailure { Log.w(TAG, "Mobile.networkChanged failed: ${it.message}") }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        runCatching { cm.unregisterNetworkCallback(cb) }
        networkCallback = null
    }

    /** Create the TUN interface and return the FD; null on failure. */
    private fun setupVpn(): Int? {
        val builder = Builder()
            .setSession("XZAP")
            .addAddress("10.255.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

        // Keep RFC1918 private ranges + link-local + multicast out of tunnel.
        // Without this, apps probing local gateway (192.168.0.1:53) waste mux
        // streams trying to reach the phone's own LAN from Warsaw.
        // excludeRoute requires Android 13 (API 33); fall back silently otherwise.
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("10.0.0.0"), 8))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("172.16.0.0"), 12))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("192.168.0.0"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("169.254.0.0"), 16))
                builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName("224.0.0.0"), 4))
                Log.i(TAG, "excludeRoute: RFC1918 + link-local + multicast out of tunnel")
            } catch (e: Exception) { Log.w(TAG, "excludeRoute failed: $e") }
        }

        // BypassResolver = static defaults + MIUI/system noise + user prefs (Phase A).
        // На будущее: cloud list (Phase C) и эвристики (Phase B) подключаются как
        // дополнительные источники в BypassResolver.
        val miuiBypass = setOf(
            "com.miui.daemon", "com.miui.analytics", "com.miui.systemAdSolution",
            "com.miui.msa.global", "com.miui.securitycenter", "com.xiaomi.metoknlp",
            "com.xiaomi.xmsf", "com.xiaomi.mipicks", "com.miui.weather2",
            "com.android.vending",             // Google Play (huge chat, reconnects)
            "com.google.android.gms",           // Google Play Services — massive traffic
            "com.google.android.gsf",
            "com.google.android.apps.tachyon",  // Google Meet / Duo
            "com.google.android.ims",
        )
        val staticDefaults = (BYPASS_APPS + miuiBypass).toSet()
        val resolver = BypassResolver.build(this, staticDefaults)
        var bypassed = 0
        for (pkg in resolver.packages()) {
            try { builder.addDisallowedApplication(pkg); bypassed++ } catch (_: Exception) {}
        }
        Log.i(TAG, "Bypass total: $bypassed apps routed direct")

        try {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            val active = cm?.activeNetwork
            if (active != null) builder.setUnderlyingNetworks(arrayOf(active))
        } catch (_: Exception) {}

        // Retry establish() up to 3 times with 300ms delay. After phone reboot
        // or fresh consent grant, the first call often returns null due to
        // a race between MainActivity granting VPN permission and the Service
        // process seeing it as live. Reproducible on MIUI; affects multiple
        // Android versions. Tiny delay clears it.
        var fd: android.os.ParcelFileDescriptor? = null
        for (attempt in 1..3) {
            fd = builder.establish()
            if (fd != null) {
                if (attempt > 1) Log.i(TAG, "establish() succeeded on attempt $attempt")
                break
            }
            Log.w(TAG, "establish() returned null on attempt $attempt — retrying after 300ms")
            try { Thread.sleep(300) } catch (_: InterruptedException) {}
        }
        if (fd == null) {
            Log.e(TAG, "establish() failed all 3 attempts — VPN consent missing or denied")
            return null
        }
        vpnInterface = fd
        Log.i(TAG, "VPN established, fd=${vpnInterface?.fd}")
        return vpnInterface?.fd
    }

    private fun closeVpn() {
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }

    private fun disconnect() {
        teardownInternal()
        _health.value = VpnHealth.IDLE
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Disconnected")
    }

    override fun onDestroy() {
        disconnect()
        scope.cancel()
        super.onDestroy()
    }
    override fun onRevoke() { disconnect(); super.onRevoke() }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(NotificationChannel(CHANNEL_ID, "XZAP VPN", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("XZAP").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi).setOngoing(true).build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(1, buildNotification(text))
    }
}
