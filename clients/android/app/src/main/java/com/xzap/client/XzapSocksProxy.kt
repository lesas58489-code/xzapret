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
        private const val BUFFER_SIZE = 131072  // 128KB for better throughput
        private const val FRAG_THRESHOLD = 150
        private const val FRAG_MIN = 24
        private const val FRAG_MAX = 68
        private const val POOL_SIZE = 8

        private val WHITE_DOMAINS = listOf(
            // Only NON-BLOCKED domains — DPI checks SNI
            "www.cloudflare.com", "cloudflare.com",
            "www.microsoft.com", "microsoft.com",
            "www.apple.com", "apple.com",
            "www.amazon.com", "amazon.com",
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
            "ajax.aspnetcdn.com", "cdn.shopify.com",
        )
    }

    private val random = SecureRandom()
    private val keySpec = SecretKeySpec(key, "AES")
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private lateinit var sslFactory: SSLSocketFactory

    // Thread-local cached Cipher instances (avoid Cipher.getInstance overhead)
    private val encCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }
    private val decCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }

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

        // Kill any previous instance on this port
        try { ServerSocket().apply { reuseAddress = true; bind(InetSocketAddress("127.0.0.1", port)); close() } } catch (_: Exception) {}
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
            val greeting = readExactly(inp, 2) ?: return
            if (greeting[0] != 0x05.toByte()) return
            val methodCount = greeting[1].toInt() and 0xFF
            if (methodCount > 0) readExactly(inp, methodCount) ?: return
            out.write(byteArrayOf(0x05, 0x00))

            // SOCKS5 request
            val req = readExactly(inp, 4) ?: return
            if (req[1] == 0x03.toByte()) {
                // UDP ASSOCIATE — used by tun2socks for QUIC (YouTube, Chrome etc.)
                // Strategy: accept the association (so tun2socks doesn't panic),
                // then immediately close the TCP control connection.
                // Per SOCKS5 spec, closing the control connection invalidates the relay
                // instantly → tun2socks drops the QUIC session → Chrome/Cronet marks
                // the server as QUIC-broken and falls back to TCP with zero wait time.
                skipSocksAddr(inp, req[3].toInt() and 0xFF)
                val udpSock = java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())
                val udpPort = udpSock.localPort
                try {
                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01,
                        127, 0, 0, 1,
                        ((udpPort shr 8) and 0xFF).toByte(),
                        (udpPort and 0xFF).toByte()))
                    // Hold relay for 3s, then close the control connection.
                    // Immediate close (0ms) makes Chrome fall back to TCP but causes
                    // YouTube app to retry QUIC in a loop without ever trying TCP.
                    // With 3s hold: both Chrome and YouTube app's Cronet detect
                    // "QUIC relay is up but server never responds" → mark QUIC broken
                    // → fall back to TCP. One-time 3s penalty on first connection,
                    // then all subsequent connections use TCP directly.
                    client.soTimeout = 3000
                    try { inp.read() } catch (_: Exception) {}
                    client.soTimeout = 0
                } finally {
                    udpSock.close()
                }
            }
            if (req[1] != 0x01.toByte()) {
                // BIND or unknown — general failure
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }

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

            val tunnelInp = java.io.BufferedInputStream(tunnel.getInputStream(), BUFFER_SIZE)
            val tunnelOut = tunnel.getOutputStream()  // no buffering — TLS handles it

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        sendFrame(tunnelOut, buf, n)
                    }
                } catch (_: Exception) {}
                try { tunnel.close() } catch (_: Exception) {}
            }
            val t2 = Thread {
                try {
                    val bOut = java.io.BufferedOutputStream(out, BUFFER_SIZE)
                    while (running.get()) {
                        val data = recvFrame(tunnelInp) ?: break
                        bOut.write(data)
                        bOut.flush()
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

    private fun sendFrame(out: OutputStream, data: ByteArray, len: Int = data.size) {
        val prefix = ByteArray(PREFIX_SIZE).also { random.nextBytes(it) }
        val encrypted = encrypt(data, 0, len)  // no copy — accepts offset+length

        // XZAP frame: [4B payload_len][16B prefix][nonce+ciphertext]
        // Build directly — no intermediate `payload = prefix + encrypted` copy.
        val payloadSize = PREFIX_SIZE + encrypted.size
        val xzapFrame = ByteArray(4 + payloadSize)
        putInt(xzapFrame, 0, payloadSize)
        System.arraycopy(prefix, 0, xzapFrame, 4, PREFIX_SIZE)
        System.arraycopy(encrypted, 0, xzapFrame, 4 + PREFIX_SIZE, encrypted.size)

        synchronized(out) {
            if (xzapFrame.size <= FRAG_THRESHOLD) {
                writeMicroFragmented(out, xzapFrame)
            } else {
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
        // Write 5-byte header + data separately — no copy of data into a new array.
        // TLS output stream buffers both writes into the same TLS records.
        val hdr = ByteArray(5)
        putInt(hdr, 0, data.size + 1)
        hdr[4] = 0x00 // FLAG_REAL
        out.write(hdr)
        out.write(data)
    }

    private fun recvFrame(inp: InputStream): ByteArray? {
        val buffer = java.io.ByteArrayOutputStream(4096)
        while (true) {
            val fragHdr = readExactly(inp, 4) ?: return null
            val fragTotal = getInt(fragHdr, 0)
            if (fragTotal <= 0 || fragTotal > 256 * 1024) return null

            val fragPayload = readExactly(inp, fragTotal) ?: return null
            val flags = fragPayload[0].toInt() and 0xFF
            if (flags == 0x01) continue // chaff

            buffer.write(fragPayload, 1, fragPayload.size - 1)

            val size = buffer.size()
            if (size >= 4) {
                val buf = buffer.toByteArray()
                val xzapLen = getInt(buf, 0)
                if (size >= 4 + xzapLen) {
                    return decrypt(ByteArray(xzapLen - PREFIX_SIZE).also {
                        System.arraycopy(buf, 4 + PREFIX_SIZE, it, 0, it.size)
                    })
                }
            }
        }
    }

    // ==================== Helpers ====================

    /** Read and discard SOCKS5 address (ATYP already read) + 2-byte port. */
    private fun skipSocksAddr(inp: InputStream, atyp: Int) {
        when (atyp) {
            0x01 -> readExactly(inp, 6)   // 4B IPv4 + 2B port
            0x03 -> { val len = inp.read() and 0xFF; readExactly(inp, len + 2) }  // domain + 2B port
            0x04 -> readExactly(inp, 18)  // 16B IPv6 + 2B port
        }
    }

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

    private fun encrypt(data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val cipher = encCipher.get()!!
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        val ct = cipher.doFinal(data, offset, length)  // no copy — uses offset/length
        val result = ByteArray(NONCE_SIZE + ct.size)
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE)
        System.arraycopy(ct, 0, result, NONCE_SIZE, ct.size)
        return result
    }

    private fun decrypt(data: ByteArray): ByteArray {
        val cipher = decCipher.get()!!
        cipher.init(Cipher.DECRYPT_MODE, keySpec,
            GCMParameterSpec(TAG_BITS, data, 0, NONCE_SIZE))
        return cipher.doFinal(data, NONCE_SIZE, data.size - NONCE_SIZE)
    }
}
