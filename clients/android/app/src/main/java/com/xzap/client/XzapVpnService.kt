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
import mobile.Mobile
import org.json.JSONObject

/**
 * VPN service: tun2socks + XZAP core (Go, uTLS) — all in xzapcore.aar.
 *
 * Kotlin side is thin: establish TUN, hand FD to Go, wait for ready, update UI.
 */
class XzapVpnService : VpnService() {

    companion object {
        const val TAG = "XzapVPN"
        const val CHANNEL_ID = "xzap_vpn"
        const val ACTION_CONNECT = "com.xzap.CONNECT"
        const val ACTION_DISCONNECT = "com.xzap.DISCONNECT"
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"
        const val EXTRA_TLS_PROFILE = "tls_profile"
        const val SOCKS_PORT = 10808

        // Russian apps that detect VPN and refuse to work (banks, gov, marketplaces).
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 8443)
                val keyB64 = intent.getStringExtra(EXTRA_KEY) ?: return START_NOT_STICKY
                val profile = intent.getStringExtra(EXTRA_TLS_PROFILE) ?: "chrome131"
                connect(server, port, keyB64, profile)
            }
        }
        return START_STICKY
    }

    private fun connect(server: String, port: Int, keyB64: String, tlsProfile: String) {
        if (running.get()) {
            disconnect()
            Thread.sleep(500)
        }

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))

        // Validate key
        try {
            val decoded = Base64.decode(keyB64.replace(Regex("\\s"), ""), Base64.DEFAULT)
            if (decoded.size != 32) {
                Log.e(TAG, "Invalid key size ${decoded.size} — must be 32 bytes")
                updateNotification("Error: invalid key size")
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                return
            }
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Invalid base64 key: ${e.message}")
            updateNotification("Error: invalid key")
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
        }.start()
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

        var bypassed = 0
        for (pkg in BYPASS_APPS) {
            try { builder.addDisallowedApplication(pkg); bypassed++ } catch (_: Exception) {}
        }
        // MIUI/system noise that otherwise hammers mux with background probes
        val miuiBypass = listOf(
            "com.miui.daemon", "com.miui.analytics", "com.miui.systemAdSolution",
            "com.miui.msa.global", "com.miui.securitycenter", "com.xiaomi.metoknlp",
            "com.xiaomi.xmsf", "com.xiaomi.mipicks", "com.miui.weather2",
            "com.android.vending",             // Google Play (huge chat, reconnects)
            "com.google.android.gms",           // Google Play Services — massive traffic
            "com.google.android.gsf",
            "com.google.android.apps.tachyon",  // Google Meet / Duo
            "com.google.android.ims",
        )
        for (pkg in miuiBypass) {
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
        running.set(false)
        try { Mobile.stop() } catch (_: Exception) {}
        closeVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Disconnected")
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
