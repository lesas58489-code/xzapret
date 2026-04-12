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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
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

            // Start SOCKS5 proxy
            running.set(true)
            executor = Executors.newCachedThreadPool()
            executor?.submit { runSocksProxy() }

            updateNotification("Connected via $wsUrl")
            Log.i(TAG, "VPN + SOCKS5 ready")
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

        // Route through local SOCKS5 proxy
        // Android doesn't natively support SOCKS5 in VPN, so we use
        // the VPN to redirect DNS and the proxy for actual connections
        vpnInterface = builder.establish()
        Log.i(TAG, "VPN interface established")
    }

    private fun runSocksProxy() {
        try {
            socksServer = ServerSocket()
            socksServer?.reuseAddress = true
            socksServer?.bind(InetSocketAddress("127.0.0.1", SOCKS_PORT))
            Log.i(TAG, "SOCKS5 proxy on 127.0.0.1:$SOCKS_PORT")

            while (running.get()) {
                val client = socksServer?.accept() ?: break
                executor?.submit { handleSocksClient(client) }
            }
        } catch (e: Exception) {
            if (running.get()) Log.e(TAG, "SOCKS proxy error", e)
        }
    }

    private fun handleSocksClient(client: Socket) {
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(2)
            input.read(greeting)
            if (greeting[0] != 0x05.toByte()) return
            input.skip(greeting[1].toLong())
            output.write(byteArrayOf(0x05, 0x00))

            // SOCKS5 request
            val req = ByteArray(4)
            input.read(req)
            if (req[1] != 0x01.toByte()) return // only CONNECT

            val host: String
            when (req[3].toInt()) {
                0x01 -> { // IPv4
                    val addr = ByteArray(4)
                    input.read(addr)
                    host = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                0x03 -> { // Domain
                    val len = input.read()
                    val domain = ByteArray(len)
                    input.read(domain)
                    host = String(domain)
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
            val clientToMux = Thread {
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

            val muxToClient = Thread {
                try {
                    while (running.get()) {
                        val data = mux?.recvData(streamId) ?: break
                        output.write(data)
                        output.flush()
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }

            clientToMux.start()
            muxToClient.start()
            clientToMux.join()
            muxToClient.join()

        } catch (e: Exception) {
            Log.d(TAG, "SOCKS client error: ${e.message}")
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun disconnect() {
        running.set(false)
        socksServer?.close()
        executor?.shutdownNow()
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
