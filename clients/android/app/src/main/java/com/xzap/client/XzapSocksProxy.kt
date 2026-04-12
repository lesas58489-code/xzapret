package com.xzap.client

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * XZAP SOCKS5 proxy — 100% compatible with Python client.
 *
 * Features matching Python:
 *   ✅ AES-256-GCM encryption
 *   ✅ Random prefix 16B
 *   ✅ XZAP framing [4B len][prefix][encrypted]
 *   ✅ Fragmentation layer [4B total][1B flags][data]
 *   ✅ Micro-fragmentation for handshake (≤150B → 24-68 byte pieces)
 *   ✅ TLS with SNI rotation (Chrome-like white domains)
 *   ✅ Connection pool (8 warm TLS connections)
 *   ✅ Split tunneling (bypass list)
 *   ✅ SOCKS5 proxy
 */
class XzapSocksProxy(
    private val serverHost: String,
    private val serverPort: Int,
    private val key: ByteArray,
    private val running: AtomicBoolean,
    private val bypassDomains: Set<String> = emptySet(),
) {
    companion object {
        private const val TAG = "XzapSocks"
        private const val NONCE_SIZE = 12
        private const val TAG_BITS = 128
        private const val PREFIX_SIZE = 16
        private const val BUFFER_SIZE = 65536
        private const val FRAG_THRESHOLD = 150
        private const val FRAG_MIN = 24
        private const val FRAG_MAX = 68
        private const val POOL_SIZE = 8

        private val WHITE_DOMAINS = listOf(
            "www.youtube.com", "youtube.com",
            "www.google.com", "google.com",
            "www.cloudflare.com", "cloudflare.com",
            "www.microsoft.com", "microsoft.com",
            "www.apple.com", "apple.com",
            "www.amazon.com", "amazon.com",
            "cdn.jsdelivr.net", "ajax.googleapis.com",
        )
    }

    private val random = SecureRandom()
    private val keySpec = SecretKeySpec(key, "AES")
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private lateinit var sslFactory: SSLSocketFactory

    // Connection pool
    private val pool = ConcurrentLinkedDeque<Socket>()
    private val poolCreating = AtomicInteger(0)

    fun start(port: Int) {
        executor = Executors.newCachedThreadPool()

        // TLS context (reused — session resumption)
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
            override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
            override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
        }), random)
        sslFactory = sslCtx.socketFactory

        serverSocket = ServerSocket()
        serverSocket?.reuseAddress = true
        serverSocket?.bind(InetSocketAddress("127.0.0.1", port))
        Log.i(TAG, "SOCKS5 on :$port → XZAP $serverHost:$serverPort (pool=$POOL_SIZE)")

        // Warm pool
        executor?.submit { warmPool() }

        // Accept loop
        executor?.submit {
            while (running.get()) {
                try {
                    val client = serverSocket?.accept() ?: break
                    executor?.submit { handleClient(client) }
                } catch (e: Exception) {
                    if (running.get()) Log.e(TAG, "Accept: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        serverSocket?.close()
        while (pool.isNotEmpty()) {
            try { pool.poll()?.close() } catch (_: Exception) {}
        }
        executor?.shutdownNow()
    }

    // ==================== Connection Pool ====================

    private fun warmPool() {
        Log.i(TAG, "Pool: warming $POOL_SIZE connections")
        val threads = (1..POOL_SIZE).map {
            Thread { createPoolConnection() }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        Log.i(TAG, "Pool: ${pool.size} ready")
    }

    private fun createPoolConnection() {
        poolCreating.incrementAndGet()
        try {
            val sock = openTlsConnection()
            pool.offer(sock)
        } catch (e: Exception) {
            Log.d(TAG, "Pool create failed: ${e.message}")
        } finally {
            poolCreating.decrementAndGet()
        }
    }

    private fun getPoolConnection(): Socket {
        while (pool.isNotEmpty()) {
            val sock = pool.poll() ?: continue
            if (!sock.isClosed && sock.isConnected) {
                // Replenish in background
                executor?.submit { createPoolConnection() }
                return sock
            }
        }
        // Pool empty — create on demand
        return openTlsConnection()
    }

    // ==================== TLS with SNI rotation ====================

    private fun openTlsConnection(): Socket {
        val sni = WHITE_DOMAINS[random.nextInt(WHITE_DOMAINS.size)]
        val sock = sslFactory.createSocket() as SSLSocket
        sock.sslParameters = sock.sslParameters.apply {
            serverNames = listOf(javax.net.ssl.SNIHostName(sni))
            protocols = arrayOf("TLSv1.3", "TLSv1.2")
        }
        sock.connect(InetSocketAddress(serverHost, serverPort), 10000)
        sock.soTimeout = 0
        sock.tcpNoDelay = true
        return sock
    }

    // ==================== Split tunneling ====================

    private fun shouldBypass(hostname: String): Boolean {
        val h = hostname.lowercase()
        if (h in bypassDomains) return true
        val parts = h.split(".")
        for (i in 1 until parts.size) {
            if (parts.subList(i, parts.size).joinToString(".") in bypassDomains) return true
        }
        return false
    }

    // ==================== SOCKS5 handling ====================

    private fun handleClient(client: Socket) {
        try {
            val inp = client.getInputStream()
            val out = client.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(2)
            if (inp.read(greeting) != 2 || greeting[0] != 0x05.toByte()) return
            val methods = ByteArray(greeting[1].toInt() and 0xFF)
            inp.read(methods)
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

            // Split tunneling
            if (shouldBypass(host)) {
                handleDirect(client, inp, out, host, port)
                return
            }

            // XZAP tunnel
            val tunnel = openXzapTunnel(host, port) ?: run {
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }

            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            val tunnelInp = tunnel.getInputStream()
            val tunnelOut = tunnel.getOutputStream()

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        sendFrame(tunnelOut, buf.copyOf(n))
                    }
                } catch (_: Exception) {}
                try { tunnel.close() } catch (_: Exception) {}
            }
            val t2 = Thread {
                try {
                    while (running.get()) {
                        val data = recvFrame(tunnelInp) ?: break
                        out.write(data)
                        out.flush()
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

    private fun handleDirect(client: Socket, inp: InputStream, out: OutputStream,
                              host: String, port: Int) {
        try {
            val remote = Socket()
            remote.connect(InetSocketAddress(host, port), 10000)
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            val remoteInp = remote.getInputStream()
            val remoteOut = remote.getOutputStream()

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = inp.read(buf); if (n <= 0) break
                        remoteOut.write(buf, 0, n); remoteOut.flush()
                    }
                } catch (_: Exception) {}
                try { remote.close() } catch (_: Exception) {}
            }
            val t2 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = remoteInp.read(buf); if (n <= 0) break
                        out.write(buf, 0, n); out.flush()
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }
            t1.start(); t2.start()
            t1.join(); t2.join()
        } catch (_: Exception) {
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        }
    }

    // ==================== XZAP tunnel ====================

    private fun openXzapTunnel(host: String, port: Int): Socket? {
        return try {
            val sock = getPoolConnection()
            val tunnelOut = sock.getOutputStream()
            val tunnelInp = sock.getInputStream()

            val req = """{"cmd":"connect","host":"$host","port":$port}""".toByteArray()
            sendFrame(tunnelOut, req)

            val resp = recvFrame(tunnelInp) ?: return null
            val respStr = String(resp)
            if ("\"ok\":true" !in respStr && "\"ok\": true" !in respStr) {
                sock.close(); return null
            }
            sock
        } catch (e: Exception) {
            Log.d(TAG, "Tunnel failed $host:$port: ${e.message}")
            null
        }
    }

    // ==================== XZAP frame I/O + fragmentation ====================

    private fun sendFrame(out: OutputStream, data: ByteArray) {
        val encrypted = encrypt(data)
        val prefix = ByteArray(PREFIX_SIZE).also { random.nextBytes(it) }
        val payload = prefix + encrypted

        // XZAP frame: [4B length][payload]
        val xzapFrame = ByteArray(4 + payload.size)
        putInt(xzapFrame, 0, payload.size)
        System.arraycopy(payload, 0, xzapFrame, 4, payload.size)

        synchronized(out) {
            if (xzapFrame.size <= FRAG_THRESHOLD) {
                // Micro-fragmentation: split into 24-68 byte pieces
                writeMicroFragmented(out, xzapFrame)
            } else {
                // Bulk: single fragment
                writeBulkFragment(out, xzapFrame)
            }
            out.flush()
        }
    }

    private fun writeMicroFragmented(out: OutputStream, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val remaining = data.size - offset
            val fragSize = if (remaining <= FRAG_MAX) remaining
            else FRAG_MIN + random.nextInt(FRAG_MAX - FRAG_MIN + 1).coerceAtMost(remaining - FRAG_MIN)

            val chunk = data.copyOfRange(offset, offset + fragSize)
            val total = chunk.size + 1
            val frag = ByteArray(4 + total)
            putInt(frag, 0, total)
            frag[4] = 0x00 // FLAG_REAL
            System.arraycopy(chunk, 0, frag, 5, chunk.size)
            out.write(frag)
            offset += fragSize
        }
    }

    private fun writeBulkFragment(out: OutputStream, data: ByteArray) {
        val total = data.size + 1
        val frag = ByteArray(4 + total)
        putInt(frag, 0, total)
        frag[4] = 0x00 // FLAG_REAL
        System.arraycopy(data, 0, frag, 5, data.size)
        out.write(frag)
    }

    private fun recvFrame(inp: InputStream): ByteArray? {
        val buffer = mutableListOf<Byte>()
        while (true) {
            val fragHdr = readExactly(inp, 4) ?: return null
            val fragTotal = getInt(fragHdr, 0)
            if (fragTotal <= 0 || fragTotal > 256 * 1024) return null

            val fragPayload = readExactly(inp, fragTotal) ?: return null
            val flags = fragPayload[0].toInt() and 0xFF
            if (flags == 0x01) continue // chaff

            val fragData = fragPayload.copyOfRange(1, fragPayload.size)
            buffer.addAll(fragData.toList())

            if (buffer.size >= 4) {
                val buf = buffer.toByteArray()
                val xzapLen = getInt(buf, 0)
                if (buf.size >= 4 + xzapLen) {
                    val payload = buf.copyOfRange(4, 4 + xzapLen)
                    val encrypted = payload.copyOfRange(PREFIX_SIZE, payload.size)
                    return decrypt(encrypted)
                }
            }
        }
    }

    // ==================== Helpers ====================

    private fun putInt(buf: ByteArray, off: Int, v: Int) {
        buf[off] = ((v shr 24) and 0xFF).toByte()
        buf[off + 1] = ((v shr 16) and 0xFF).toByte()
        buf[off + 2] = ((v shr 8) and 0xFF).toByte()
        buf[off + 3] = (v and 0xFF).toByte()
    }

    private fun getInt(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 24) or
        ((buf[off + 1].toInt() and 0xFF) shl 16) or
        ((buf[off + 2].toInt() and 0xFF) shl 8) or
        (buf[off + 3].toInt() and 0xFF)

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
