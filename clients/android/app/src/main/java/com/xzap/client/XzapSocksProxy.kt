package com.xzap.client

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Local SOCKS5 proxy that forwards connections through XZAP TLS protocol.
 * Same protocol as Python run_smart_client.py — proven stable.
 *
 * Each SOCKS5 CONNECT → new TLS to server → XZAP handshake → bidirectional pipe
 */
class XzapSocksProxy(
    private val serverHost: String,
    private val serverPort: Int,
    private val key: ByteArray,
    private val running: AtomicBoolean,
) {
    companion object {
        private const val TAG = "XzapSocks"
        private const val NONCE_SIZE = 12
        private const val TAG_BITS = 128
        private const val PREFIX_SIZE = 16
        private const val BUFFER_SIZE = 65536
    }

    private val random = SecureRandom()
    private val keySpec = SecretKeySpec(key, "AES")
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null

    fun start(port: Int) {
        executor = Executors.newCachedThreadPool()
        serverSocket = ServerSocket()
        serverSocket?.reuseAddress = true
        serverSocket?.bind(InetSocketAddress("127.0.0.1", port))
        Log.i(TAG, "SOCKS5 on 127.0.0.1:$port → XZAP $serverHost:$serverPort")

        executor?.submit {
            while (running.get()) {
                try {
                    val client = serverSocket?.accept() ?: break
                    executor?.submit { handleClient(client) }
                } catch (e: Exception) {
                    if (running.get()) Log.e(TAG, "Accept error: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        serverSocket?.close()
        executor?.shutdownNow()
    }

    private fun handleClient(client: Socket) {
        try {
            val inp = client.getInputStream()
            val out = client.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(2)
            if (inp.read(greeting) != 2 || greeting[0] != 0x05.toByte()) return
            inp.skip(greeting[1].toLong() and 0xFF)
            out.write(byteArrayOf(0x05, 0x00))

            // SOCKS5 CONNECT
            val req = ByteArray(4)
            if (inp.read(req) != 4 || req[1] != 0x01.toByte()) return

            val host: String
            when (req[3].toInt() and 0xFF) {
                0x01 -> {
                    val a = ByteArray(4); inp.read(a)
                    host = a.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                0x03 -> {
                    val len = inp.read() and 0xFF
                    val d = ByteArray(len); inp.read(d)
                    host = String(d)
                }
                0x04 -> {
                    val a = ByteArray(16); inp.read(a)
                    host = java.net.InetAddress.getByAddress(a).hostAddress ?: return
                }
                else -> return
            }
            val pb = ByteArray(2); inp.read(pb)
            val port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)

            // Open XZAP TLS tunnel
            val tunnel = openXzapTunnel(host, port) ?: run {
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                client.close()
                return
            }

            // SOCKS5 success
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            Log.d(TAG, "→ $host:$port")

            // Bidirectional pipe: app ↔ XZAP tunnel
            val tunnelInp = tunnel.getInputStream()
            val tunnelOut = tunnel.getOutputStream()

            val appToTunnel = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        val data = buf.copyOf(n)
                        sendFrame(tunnelOut, data)
                    }
                } catch (_: Exception) {}
                try { tunnel.close() } catch (_: Exception) {}
            }

            val tunnelToApp = Thread {
                try {
                    while (running.get()) {
                        val data = recvFrame(tunnelInp) ?: break
                        out.write(data)
                        out.flush()
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }

            appToTunnel.start()
            tunnelToApp.start()
            appToTunnel.join()
            tunnelToApp.join()

        } catch (_: Exception) {
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun openXzapTunnel(host: String, port: Int): Socket? {
        return try {
            // TLS connection (trust all — XZAP verifies via shared key)
            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(null, arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
                override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
                override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
            }), random)

            val sock = sslCtx.socketFactory.createSocket() as SSLSocket
            sock.connect(InetSocketAddress(serverHost, serverPort), 10000)
            sock.soTimeout = 0
            sock.tcpNoDelay = true

            val tunnelOut = sock.getOutputStream()
            val tunnelInp = sock.getInputStream()

            // XZAP handshake: send CONNECT
            val req = """{"cmd":"connect","host":"$host","port":$port}""".toByteArray()
            sendFrame(tunnelOut, req)

            // Read response
            val resp = recvFrame(tunnelInp) ?: return null
            val respStr = String(resp)
            if (!respStr.contains("\"ok\":true") && !respStr.contains("\"ok\": true")) {
                sock.close()
                return null
            }

            sock
        } catch (e: Exception) {
            Log.d(TAG, "Tunnel failed $host:$port: ${e.message}")
            null
        }
    }

    // ==================== XZAP frame I/O ====================

    private fun sendFrame(out: OutputStream, data: ByteArray) {
        val encrypted = encrypt(data)
        val prefix = ByteArray(PREFIX_SIZE).also { random.nextBytes(it) }
        val payload = prefix + encrypted
        val header = ByteArray(4)
        header[0] = ((payload.size shr 24) and 0xFF).toByte()
        header[1] = ((payload.size shr 16) and 0xFF).toByte()
        header[2] = ((payload.size shr 8) and 0xFF).toByte()
        header[3] = (payload.size and 0xFF).toByte()
        synchronized(out) {
            out.write(header)
            out.write(payload)
            out.flush()
        }
    }

    private fun recvFrame(inp: InputStream): ByteArray? {
        val header = readExactly(inp, 4) ?: return null
        val length = ((header[0].toInt() and 0xFF) shl 24) or
                     ((header[1].toInt() and 0xFF) shl 16) or
                     ((header[2].toInt() and 0xFF) shl 8) or
                     (header[3].toInt() and 0xFF)
        if (length > 256 * 1024) return null
        val payload = readExactly(inp, length) ?: return null
        val encrypted = payload.copyOfRange(PREFIX_SIZE, payload.size)
        return decrypt(encrypted)
    }

    private fun readExactly(inp: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var offset = 0
        while (offset < n) {
            val read = inp.read(buf, offset, n - offset)
            if (read <= 0) return null
            offset += read
        }
        return buf
    }

    // ==================== AES-256-GCM ====================

    private fun encrypt(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        return nonce + cipher.doFinal(plaintext)
    }

    private fun decrypt(data: ByteArray): ByteArray {
        val nonce = data.copyOfRange(0, NONCE_SIZE)
        val ct = data.copyOfRange(NONCE_SIZE, data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(ct)
    }
}
