package com.xzap.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN service: tun2socks (Go) → SOCKS5 → XZAP TLS (direct to server).
 *
 * Same proven protocol as Windows client: AES-256-GCM + fragmentation + SNI masquerade.
 */
class XzapVpnService : VpnService() {

    companion object {
        const val TAG = "XzapVPN"
        const val CHANNEL_ID = "xzap_vpn"
        const val ACTION_CONNECT = "com.xzap.CONNECT"
        const val ACTION_DISCONNECT = "com.xzap.DISCONNECT"
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"  // AES-256 key, base64-encoded
        const val SOCKS_PORT = 10808

        // Russian apps that detect VPN and refuse to work (banks, gov, marketplaces).
        // These are routed direct, bypassing tun2socks entirely. Missing packages
        // are silently ignored (the bypass list is a superset of what any one user
        // might have installed).
        val BYPASS_APPS = listOf(
            // Sber
            "ru.sberbankmobile", "ru.sberbank.online", "ru.sberbankmobile_beta",
            "ru.sberbank.sbol", "ru.sberbank.spasibo", "ru.sberbank.sberdevices.smartapp",
            // Tinkoff / T-Bank
            "com.idamob.tinkoff.android", "com.tinkoff.investing",
            "com.tinkoff.tinkoffbusiness", "ru.tinkoff.mb",
            // VTB
            "ru.vtb24.mobilebanking.android", "ru.vtb.mobilebanking",
            // Alfa
            "ru.alfabank.mobile.android", "ru.alfabank.oavdo.amc",
            // Other Russian banks
            "ru.raiffeisennews", "ru.gazprombank.android.mobilebank.app",
            "ru.rosbank.android", "ru.mtsbank.mobile", "ru.psbank.mobile",
            "ru.akbars.mobile", "ru.uralsib.mobile", "ru.rshb.mbank",
            "ru.otpbank.mobile", "ru.pochta.post",
            // Ozon / Ozon Bank / Ozon Card
            "ru.ozon.app.android", "ru.ozon.seller", "ru.ozon.card.android",
            "ru.ozon.fintech.finance",
            // Wildberries
            "com.wildberries.ru", "com.wildberries.ru_seller",
            // Yandex ecosystem (Taxi, Eda, Lavka, Market, Maps, Music, Mail, etc.)
            "ru.yandex.taxi", "ru.yandex.eda", "ru.yandex.lavka",
            "ru.yandex.market", "ru.yandex.yandexmaps",
            "ru.yandex.yandexnavi", "ru.yandex.searchplugin",
            "ru.yandex.mail", "ru.yandex.music", "ru.yandex.disk",
            "ru.yandex.weatherplugin", "ru.yandex.metro",
            "ru.yandex.rasp", "ru.yandex.pay",
            "ru.yandex.kinopoisk", "ru.yandex.kinopoisk.tv",
            "com.yandex.browser", "com.yandex.messenger", "com.yandex.mobile.realty",
            "com.yandex.bank", "com.yandex.toloka.androidapp",
            // Gov / official
            "ru.rostel", "ru.gosuslugi.goskey", "ru.mos.polis.ooms", "ru.mos.ru",
            // Travel
            "ru.aeroflot", "ru.rzd.pass", "ru.s7.airlines",
            // VK / Mail
            "com.vkontakte.android", "com.vk.vkclient", "ru.mail.mailapp",
            // Marketplaces / retailers
            "ru.mvideo.androidapp", "ru.dns.dnsshop", "ru.sima.land",
            "ru.leroymerlin.mobileapp",
            // Media / misc
            "ru.rbc.news", "ru.rambler.news", "ru.yoomoney.android",
            "ru.litres.android",
            // Delivery / food
            "ru.dodopizza.app", "ru.kfc.kfcrus", "ru.burgerking",
            "ru.foodfox.client", "ru.foodband.customer",
        )
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var socksProxy: XzapSocksProxy? = null
    private val running = AtomicBoolean(false)
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastNetworkId: Long = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 8443)
                val keyB64 = intent.getStringExtra(EXTRA_KEY) ?: return START_NOT_STICKY
                connect(server, port, keyB64)
            }
        }
        return START_STICKY
    }

    private fun connect(server: String, port: Int, keyB64: String) {
        if (running.get()) {
            disconnect()
            Thread.sleep(500)
        }

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))

        val key = try {
            Base64.decode(keyB64.replace(Regex("\\s"), ""), Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Invalid base64 key — aborting: ${e.message}")
            updateNotification("Error: invalid key")
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
            return
        }
        if (key.size != 32) {
            Log.e(TAG, "Key must be 32 bytes, got ${key.size} — aborting")
            updateNotification("Error: key must be 32 bytes")
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
            return
        }
        running.set(true)

        // Bypass domains (Russian sites go direct, no tunnel needed)
        val bypass = setOf(
            "vk.com", "ok.ru", "yandex.ru", "yandex.net", "mail.ru",
            "rambler.ru", "avito.ru", "sberbank.ru", "gosuslugi.ru",
            "mos.ru", "rbc.ru", "lenta.ru", "ria.ru", "rt.com",
            "tinkoff.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru",
            "2gis.ru", "dzen.ru",
        )

        Thread {
            // Detect transport mode. Any URL-like input (contains "://") → WebSocket.
            // Normalise http:// and https:// to wss:// — Android autocorrect can
            // stealthily replace 'wss' with 'http' even with inputType=textUri,
            // and we still want the user's intent to work.
            val normalised = when {
                server.startsWith("http://", true)  -> "ws://"  + server.removePrefix("http://")
                server.startsWith("https://", true) -> "wss://" + server.removePrefix("https://")
                else -> server
            }
            val isWs = normalised.startsWith("wss://", ignoreCase = true) ||
                       normalised.startsWith("ws://", ignoreCase = true)
            if (normalised != server) {
                Log.i(TAG, "server url normalised: '$server' → '$normalised'")
            }
            val effHost: String
            val effPort: Int
            val effWsUrl: String?
            if (isWs) {
                effWsUrl = normalised
                effHost = try { java.net.URI(normalised).host ?: normalised } catch (_: Exception) { normalised }
                effPort = try { java.net.URI(normalised).port.takeIf { it > 0 } ?: 443 } catch (_: Exception) { 443 }
            } else {
                effWsUrl = null
                effHost = server
                effPort = port
            }
            socksProxy = XzapSocksProxy(effHost, effPort, key, running, bypass, effWsUrl)
            socksProxy!!.start(SOCKS_PORT)

            // Wait until at least one pool connection is ready (up to 8s).
            // Android fires a connectivity probe (connectivitycheck.gstatic.com)
            // immediately after VPN comes up. If the pool isn't ready, the probe
            // times out → VPN network marked NOT_VALIDATED → YouTube app and
            // other apps that check NET_CAPABILITY_VALIDATED spin indefinitely.
            socksProxy!!.waitReady(8000)

            setupVpn()
            startTun2Socks()
            registerNetworkCallback()

            updateNotification("Connected to $server:$port")
            Log.i(TAG, "VPN ready (tun2socks + XZAP TLS)")
        }.start()
    }

    private fun setupVpn() {
        val builder = Builder()
            .setSession("XZAP")
            .addAddress("10.255.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

        // Russian banks/marketplaces/gov apps detect VPN and block. Route direct.
        // Missing packages throw NameNotFoundException → swallow per-item so one
        // missing pkg doesn't abort the whole list.
        var bypassed = 0
        for (pkg in BYPASS_APPS) {
            try { builder.addDisallowedApplication(pkg); bypassed++ } catch (_: Exception) {}
        }
        Log.i(TAG, "Bypass: $bypassed of ${BYPASS_APPS.size} Russian apps installed → routed direct")

        // Inherit NET_CAPABILITY_VALIDATED from the underlying physical network (WiFi/LTE).
        // Without this, Android performs its own connectivity check through the VPN tunnel:
        // the probe hits Xiaomi's server (180.153.201.124) via Warsaw (Polish IP) which
        // returns a non-204 redirect → VPN marked NOT_VALIDATED → Chrome refuses to use
        // it (Telegram ignores this flag and works anyway).
        // With setUnderlyingNetworks(activeNetwork), the VPN inherits validated status
        // from the already-validated physical network — no separate probe needed.
        try {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            val active = cm?.activeNetwork
            if (active != null) builder.setUnderlyingNetworks(arrayOf(active))
        } catch (_: Exception) {}
        vpnInterface = builder.establish()
        Log.i(TAG, "VPN established")
    }

    private fun startTun2Socks() {
        try {
            val fd = vpnInterface?.fd ?: return
            val key = engine.Key()
            key.mark = 0
            key.mtu = 1500
            key.device = "fd://$fd"
            key.proxy = "socks5://127.0.0.1:$SOCKS_PORT"
            key.logLevel = "warning"
            engine.Engine.insert(key)
            engine.Engine.start()
            Log.i(TAG, "tun2socks started")
        } catch (e: Exception) {
            Log.e(TAG, "tun2socks error: ${e.message}")
        }
    }

    private fun disconnect() {
        running.set(false)
        unregisterNetworkCallback()
        try { engine.Engine.stop() } catch (_: Exception) {}
        socksProxy?.stop()
        vpnInterface?.close()
        vpnInterface = null
        socksProxy = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Disconnected")
    }

    /** Watch underlying network (WiFi/LTE) for changes. On any change —
     *  wake from Doze, handoff between WiFi and cellular, loss/restore —
     *  invalidate all mux tunnels. Their TCP state is almost certainly
     *  stale after a network transition, and new streams would stall
     *  until ping detected the break. */
    private fun registerNetworkCallback() {
        val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)
            .build()
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                val nid = network.networkHandle
                if (lastNetworkId != 0L && nid != lastNetworkId) {
                    Log.i(TAG, "network changed (id $lastNetworkId → $nid) — invalidating tunnels")
                    socksProxy?.invalidateAllTunnels("network changed")
                    // Also update underlyingNetworks so VPN inherits fresh validated status
                    try { setUnderlyingNetworks(arrayOf(network)) } catch (_: Exception) {}
                }
                lastNetworkId = nid
            }
            override fun onLost(network: android.net.Network) {
                if (network.networkHandle == lastNetworkId) {
                    Log.i(TAG, "network lost — invalidating tunnels")
                    socksProxy?.invalidateAllTunnels("network lost")
                }
            }
        }
        try {
            cm.registerNetworkCallback(request, cb)
            networkCallback = cb
            val active = cm.activeNetwork
            if (active != null) lastNetworkId = active.networkHandle
            Log.i(TAG, "network callback registered (active id=$lastNetworkId)")
        } catch (e: Exception) {
            Log.w(TAG, "network callback register failed: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        try {
            getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {}
        networkCallback = null
        lastNetworkId = 0
    }

    override fun onDestroy() { disconnect(); super.onDestroy() }
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
