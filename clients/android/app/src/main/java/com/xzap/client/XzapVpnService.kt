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
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN service using tun2socks (Go) for packet handling.
 *
 * Architecture:
 *   Apps → VPN TUN → tun2socks (Go engine) → SOCKS5 (:10808) → MUX → WSS → CF → Warsaw → internet
 *
 * tun2socks handles all TCP/UDP/DNS properly (production-grade Go code).
 * Our SOCKS5 proxy forwards connections through the MUX WebSocket.
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
    private var socksServer: ServerSocket? = null

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

        mux = MuxConnection(wsUrl)
        mux!!.connect()

        Thread {
            // Wait for MUX connection
            var attempts = 0
            while (!mux!!.isConnected() && attempts < 30) {
                Thread.sleep(500)
                attempts++
            }
            if (!mux!!.isConnected()) {
                Log.e(TAG, "Failed to connect")
                stopSelf()
                return@Thread
            }

            running.set(true)

            // Start SOCKS5 proxy (MUX-backed)
            executor = Executors.newCachedThreadPool()
            executor?.submit { runSocksProxy() }

            // Wait for SOCKS5 to start
            Thread.sleep(500)

            // Setup VPN + tun2socks
            setupVpnWithTun2Socks()

            updateNotification("Connected via $wsUrl")
            Log.i(TAG, "VPN ready (tun2socks + MUX)")
        }.start()
    }

    private fun setupVpnWithTun2Socks() {
        val builder = Builder()
            .setSession("XZAP")
            .addAddress("10.255.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(1500)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        vpnInterface = builder.establish() ?: return
        val fd = vpnInterface!!.fd

        Log.i(TAG, "VPN established, fd=$fd")

        // Start tun2socks Go engine
        try {
            val key = engine.Key()
            key.mark = 0
            key.mtu = 1500
            key.device = "fd://$fd"
            key.proxy = "socks5://127.0.0.1:$SOCKS_PORT"
            key.logLevel = "warning"
            engine.Engine.insert(key)
            engine.Engine.start()
            Log.i(TAG, "tun2socks engine started")
        } catch (e: Exception) {
            Log.e(TAG, "tun2socks failed: ${e.message}")
            // Fallback info
            Log.e(TAG, "Make sure tun2socks.aar is in app/libs/")
        }
    }

    // ==================== SOCKS5 proxy (MUX-backed) ====================

    private fun runSocksProxy() {
        try {
            socksServer = ServerSocket()
            socksServer?.reuseAddress = true
            socksServer?.bind(InetSocketAddress("127.0.0.1", SOCKS_PORT))
            Log.i(TAG, "SOCKS5 on 127.0.0.1:$SOCKS_PORT")

            while (running.get()) {
                val client = socksServer?.accept() ?: break
                executor?.submit { handleSocksClient(client) }
            }
        } catch (e: Exception) {
            if (running.get()) Log.e(TAG, "SOCKS5 error", e)
        }
    }

    private fun handleSocksClient(client: Socket) {
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(2)
            if (input.read(greeting) != 2 || greeting[0] != 0x05.toByte()) return
            val methods = ByteArray(greeting[1].toInt() and 0xFF)
            input.read(methods)
            output.write(byteArrayOf(0x05, 0x00))

            // SOCKS5 CONNECT request
            val req = ByteArray(4)
            if (input.read(req) != 4) return
            if (req[1] != 0x01.toByte()) return

            val host: String
            when (req[3].toInt() and 0xFF) {
                0x01 -> {
                    val addr = ByteArray(4)
                    input.read(addr)
                    host = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                0x03 -> {
                    val len = input.read() and 0xFF
                    val domain = ByteArray(len)
                    input.read(domain)
                    host = String(domain)
                }
                0x04 -> {
                    val addr = ByteArray(16)
                    input.read(addr)
                    host = java.net.InetAddress.getByAddress(addr).hostAddress ?: return
                }
                else -> return
            }
            val portBuf = ByteArray(2)
            input.read(portBuf)
            val port = ((portBuf[0].toInt() and 0xFF) shl 8) or (portBuf[1].toInt() and 0xFF)

            // Open MUX stream
            val streamId = mux!!.openStream(host, port)
            Log.d(TAG, "[$streamId] → $host:$port")

            // SOCKS5 success
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            // Bidirectional pipe
            val t1 = Thread {
                try {
                    val buf = ByteArray(32768)
                    while (running.get()) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        mux?.sendData(streamId, buf.copyOf(n))
                    }
                } catch (_: Exception) {}
                mux?.closeStream(streamId)
            }
            val t2 = Thread {
                try {
                    while (running.get()) {
                        val data = mux?.recvData(streamId) ?: break
                        output.write(data)
                        output.flush()
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }
            t1.start(); t2.start()
            t1.join(); t2.join()
        } catch (_: Exception) {
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    // ==================== Lifecycle ====================

    private fun disconnect() {
        running.set(false)
        try { engine.Engine.stop() } catch (_: Exception) {}
        socksServer?.close()
        executor?.shutdownNow()
        vpnInterface?.close()
        mux?.shutdown()
        vpnInterface = null; mux = null
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
