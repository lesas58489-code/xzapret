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
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN service: tun2socks → SOCKS5 (SSH tunnel) → remote server → internet.
 *
 * SSH handles all encryption. No XZAP protocol, no SNI issues.
 * DPI sees only SSH traffic to Warsaw.
 */
class XzapVpnService : VpnService() {

    companion object {
        const val TAG = "XzapVPN"
        const val CHANNEL_ID = "xzap_vpn"
        const val ACTION_CONNECT = "com.xzap.CONNECT"
        const val ACTION_DISCONNECT = "com.xzap.DISCONNECT"
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"  // SSH private key (PEM)
        const val SOCKS_PORT = 10808
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var sshTunnel: SshTunnel? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 22)
                val key = intent.getStringExtra(EXTRA_KEY) ?: return START_NOT_STICKY
                connect(server, port, key)
            }
        }
        return START_STICKY
    }

    private fun connect(server: String, port: Int, privateKey: String) {
        if (running.get()) {
            disconnect()
            Thread.sleep(500)
        }

        createNotificationChannel()
        startForeground(1, buildNotification("Connecting..."))
        running.set(true)

        Thread {
            try {
                // Start SSH tunnel with SOCKS5
                sshTunnel = SshTunnel(server, port, "root", privateKey, running)
                sshTunnel!!.start(SOCKS_PORT)

                Thread.sleep(500)

                // Setup VPN + tun2socks
                setupVpn()
                startTun2Socks()

                updateNotification("Connected to $server")
                Log.i(TAG, "VPN ready (SSH tunnel)")
            } catch (e: Exception) {
                Log.e(TAG, "Connect failed: ${e.message}")
                updateNotification("Failed: ${e.message}")
                running.set(false)
            }
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
        try { engine.Engine.stop() } catch (_: Exception) {}
        sshTunnel?.stop()
        vpnInterface?.close()
        vpnInterface = null
        sshTunnel = null
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
