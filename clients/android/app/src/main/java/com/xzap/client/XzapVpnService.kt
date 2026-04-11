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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Android VPN service that routes traffic through XZAP tunnel.
 *
 * Architecture:
 *   App traffic → TUN interface → XzapVpnService → XZAP tunnel → Tokyo VPS → internet
 *
 * Uses a local SOCKS5-like approach: intercept TCP connections from the TUN,
 * open XZAP tunnels per-connection, and pipe data bidirectionally.
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
        const val EXTRA_TLS = "tls"

        // VPN subnet — all traffic goes through this interface
        private const val VPN_ADDRESS = "10.255.0.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_DNS = "8.8.8.8"
        private const val VPN_MTU = 1500
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnel: XzapTunnel? = null
    private val running = AtomicBoolean(false)
    private var executor: ExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                disconnect()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 8443)
                val keyB64 = intent.getStringExtra(EXTRA_KEY) ?: return START_NOT_STICKY
                val useTls = intent.getBooleanExtra(EXTRA_TLS, true)

                val key = Base64.decode(keyB64, Base64.DEFAULT)
                connect(server, port, key, useTls)
            }
        }
        return START_STICKY
    }

    private fun connect(server: String, port: Int, key: ByteArray, useTls: Boolean) {
        if (running.get()) return

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))

        val crypto = XzapCrypto(key)
        tunnel = XzapTunnel(server, port, crypto, useTls)

        // Establish VPN interface
        val builder = Builder()
            .setSession("XZAP")
            .addAddress(VPN_ADDRESS, 24)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(VPN_DNS)
            .setMtu(VPN_MTU)
            .setBlocking(true)

        // Exclude XZAP server from VPN (prevent loop)
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "Failed to establish VPN")
            stopSelf()
            return
        }

        running.set(true)
        executor = Executors.newFixedThreadPool(4)

        // Start packet processing
        executor?.submit { processPackets() }

        updateNotification("Connected to $server")
        Log.i(TAG, "VPN connected via XZAP -> $server:$port")
    }

    private fun processPackets() {
        val vpnInput = FileInputStream(vpnInterface!!.fileDescriptor)
        val vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
        val packet = ByteBuffer.allocate(VPN_MTU)

        while (running.get()) {
            try {
                // Read packet from VPN interface
                packet.clear()
                val length = vpnInput.read(packet.array())
                if (length <= 0) continue

                packet.limit(length)

                // Parse IP header to get destination
                val version = (packet.get(0).toInt() shr 4) and 0xF
                if (version != 4) continue // IPv4 only for now

                val protocol = packet.get(9).toInt() and 0xFF
                if (protocol != 6) continue // TCP only

                // For TCP, we need to handle connection state.
                // Simplified: forward raw IP packets through XZAP tunnel
                // as opaque data. The server side needs a TUN endpoint too.
                //
                // For a production app, implement a userspace TCP stack
                // or use a SOCKS5 approach with tun2socks.

                // TODO: Implement tun2socks or userspace TCP stack
                // For now, log and drop
                Log.v(TAG, "Packet: $length bytes, proto=$protocol")

            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "Packet error", e)
            }
        }

        vpnInput.close()
        vpnOutput.close()
    }

    private fun disconnect() {
        running.set(false)
        executor?.shutdownNow()
        vpnInterface?.close()
        vpnInterface = null
        tunnel = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN disconnected")
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }

    // --- Notifications ---

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "XZAP VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("XZAP")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(1, buildNotification(text))
    }
}
