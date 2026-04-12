package com.xzap.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN service that runs a local SOCKS5 proxy connected through MUX/WSS.
 *
 * Architecture:
 *   All apps → VPN TUN → local SOCKS5 (:10808) → MuxConnection → WSS → CF → server → internet
 *
 * Uses Android's VpnService to redirect traffic + a local SOCKS5 proxy
 * that multiplexes all connections through one WebSocket.
 */
class XzapVpnService : VpnService() {

    companion object {
        const val TAG = "XzapVPN"
        const val CHANNEL_ID = "xzap_vpn"
        const val ACTION_CONNECT = "com.xzap.CONNECT"
        const val ACTION_DISCONNECT = "com.xzap.DISCONNECT"
        const val EXTRA_WS_URL = "ws_url"
        const val SOCKS_PORT = 10808
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var mux: MuxConnection? = null
    private val running = AtomicBoolean(false)
    private var executor: ExecutorService? = null
    private var tunForwarder: TunForwarder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_CONNECT -> {
                val wsUrl = intent.getStringExtra(EXTRA_WS_URL) ?: return START_NOT_STICKY
                connect(wsUrl)
            }
        }
        return START_STICKY
    }

    private fun connect(wsUrl: String) {
        if (running.get()) return

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))

        // Connect MUX
        mux = MuxConnection(wsUrl)
        mux!!.connect()

        // Wait for connection
        Thread {
            var attempts = 0
            while (!mux!!.isConnected() && attempts < 30) {
                Thread.sleep(500)
                attempts++
            }
            if (!mux!!.isConnected()) {
                Log.e(TAG, "Failed to connect to WSS")
                stopSelf()
                return@Thread
            }

            // Setup VPN
            setupVpn()

            // Start TUN forwarder (tun2socks)
            running.set(true)
            tunForwarder = TunForwarder(vpnInterface!!, mux!!, running)
            tunForwarder!!.start()

            updateNotification("Connected via $wsUrl")
            Log.i(TAG, "VPN + TunForwarder ready")
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

        // Exclude our own app to prevent loop
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        vpnInterface = builder.establish()
        Log.i(TAG, "VPN interface established")
    }

    // TunForwarder handles all traffic (replaces SOCKS5 proxy)

    private fun disconnect() {
        running.set(false)
        tunForwarder = null
        vpnInterface?.close()
        mux?.shutdown()
        vpnInterface = null
        mux = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN disconnected")
    }

    override fun onDestroy() { disconnect(); super.onDestroy() }
    override fun onRevoke() { disconnect(); super.onRevoke() }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "XZAP VPN", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("XZAP").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(intent).setOngoing(true).build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(1, buildNotification(text))
    }
}
