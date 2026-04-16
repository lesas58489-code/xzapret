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
        private const val POOL_MAX_AGE_MS = 45_000L   // discard pool connections older than 45s (mobile NAT kills idle TCP in 30-120s)
        private const val HANDSHAKE_TIMEOUT_MS = 10_000 // 10s timeout for XZAP handshake (detect stale pool sockets)
        private const val DATA_TIMEOUT_MS = 120_000     // 120s timeout for data relay (detect dead connections mid-stream)

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

    /** Pool entry with creation timestamp for age-based eviction. */
    private data class PooledSocket(val socket: Socket, val createdAt: Long = System.currentTimeMillis())

    /**
     * Stateful XZAP frame reader — correctly handles leftover bytes between frames.
     *
     * The old stateless recvFrame() created a fresh buffer per call and discarded
     * everything after the first complete XZAP frame. When the server sent 2+ frames
     * before we read them (e.g. TLS ServerHello + Certificate + ServerHelloDone in
     * rapid succession), all frames after the first were silently dropped. The TCP
     * stream then desynchronised → relay hung indefinitely waiting for data that
     * had already been lost.
     *
     * FrameReader keeps a leftover slice and prepends it on the next call, so no
     * bytes are ever dropped regardless of how many frames arrive in one batch.
     */
    private inner class FrameReader(private val inp: InputStream) {
        private val accumulator = java.io.ByteArrayOutputStream(8192)
        private var leftover: ByteArray? = null

        fun next(): ByteArray? {
            // Prepend any bytes that were buffered after the last complete frame
            leftover?.let { accumulator.write(it); leftover = null }

            while (true) {
                val fragHdr = readExactly(inp, 4) ?: return null
                val fragTotal = getInt(fragHdr, 0)
                if (fragTotal <= 0 || fragTotal > 256 * 1024) return null

                val fragPayload = readExactly(inp, fragTotal) ?: return null
                val flags = fragPayload[0].toInt() and 0xFF
                if (flags == 0x01) continue // chaff — skip

                accumulator.write(fragPayload, 1, fragPayload.size - 1)

                val size = accumulator.size()
                if (size >= 4) {
                    val bytes = accumulator.toByteArray()
                    val xzapLen = getInt(bytes, 0)
                    if (size >= 4 + xzapLen) {
                        // Extract exactly one XZAP frame
                        val frameData = ByteArray(xzapLen - PREFIX_SIZE).also {
                            System.arraycopy(bytes, 4 + PREFIX_SIZE, it, 0, it.size)
                        }
                        val result = decrypt(frameData)
                        // Preserve any bytes that belong to the *next* frame
                        val consumed = 4 + xzapLen
                        if (size > consumed) leftover = bytes.copyOfRange(consumed, size)
                        accumulator.reset()
                        return result
                    }
                }
            }
        }
    }

    private val random = SecureRandom()
    private val keySpec = SecretKeySpec(key, "AES")
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private lateinit var sslFactory: SSLSocketFactory

    // Thread-local cached Cipher instances (avoid Cipher.getInstance overhead)
    private val encCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }
    private val decCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }

    // Connection pool with age tracking
    private val pool = ConcurrentLinkedDeque<PooledSocket>()
    private val poolCreating = AtomicInteger(0)

    // Signals that at least one pool connection is ready.
    // XzapVpnService waits on this before activating the VPN so Android's
    // connectivity probe (connectivitycheck.gstatic.com) doesn't time out on
    // an empty pool — which would mark the network as NOT_VALIDATED and
    // cause YouTube app (and other apps that check NET_CAPABILITY_VALIDATED)
    // to spin indefinitely even though the tunnel works fine.
    private val poolReadyLatch = java.util.concurrent.CountDownLatch(1)
    private val poolSignaled = AtomicBoolean(false)

    fun waitReady(timeoutMs: Long): Boolean =
        poolReadyLatch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)

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
            try { pool.poll()?.socket?.close() } catch (_: Exception) {}
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
            pool.offer(PooledSocket(sock))
            // Signal first ready connection so XzapVpnService can activate VPN
            if (!poolSignaled.getAndSet(true)) poolReadyLatch.countDown()
        } catch (e: Exception) {
            Log.d(TAG, "Pool create failed: ${e.message}")
        } finally {
            poolCreating.decrementAndGet()
        }
    }

    /** Get a connection from pool, discarding stale ones (age > 45s).
     *  Java's isClosed/isConnected do NOT detect remote close — age check is essential. */
    private fun getPoolConnection(): Socket? {
        val now = System.currentTimeMillis()
        while (pool.isNotEmpty()) {
            val ps = pool.poll() ?: continue
            if (ps.socket.isClosed) continue
            if (now - ps.createdAt > POOL_MAX_AGE_MS) {
                try { ps.socket.close() } catch (_: Exception) {}
                continue
            }
            // Replenish in background
            executor?.submit { createPoolConnection() }
            return ps.socket
        }
        return null  // pool empty — caller decides
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
        sock.keepAlive = true  // detect dead connections via TCP keepalive
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
            if (greeting[0] != 0x05.toByte()) { Log.w(TAG, "bad SOCKS version: ${greeting[0]}"); return }
            val methodCount = greeting[1].toInt() and 0xFF
            if (methodCount > 0) readExactly(inp, methodCount) ?: return
            out.write(byteArrayOf(0x05, 0x00))

            // SOCKS5 request
            val req = readExactly(inp, 4) ?: return
            val cmd = req[1].toInt() and 0xFF
            Log.i(TAG, "SOCKS5 cmd=0x${cmd.toString(16)} atyp=0x${(req[3].toInt() and 0xFF).toString(16)}")
            if (req[1] == 0x03.toByte()) {
                // UDP ASSOCIATE — accept for DNS relay, drop non-DNS silently.
                // Server has no native UDP tunneling, so:
                //   DNS (port 53): relay via DNS-over-TCP through XZAP tunnel
                //   QUIC/other:    drop silently → apps fall back to TCP fast
                skipSocksAddr(inp, req[3].toInt() and 0xFF)
                val udpSock = java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())
                udpSock.soTimeout = 500
                val udpPort = udpSock.localPort
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01,
                    127, 0, 0, 1,
                    ((udpPort shr 8) and 0xFF).toByte(),
                    (udpPort and 0xFF).toByte()))

                executor?.submit {
                    try {
                        val recvBuf = ByteArray(65536)
                        while (!client.isClosed && running.get()) {
                            val pkt = java.net.DatagramPacket(recvBuf, recvBuf.size)
                            try { udpSock.receive(pkt) }
                            catch (_: java.net.SocketTimeoutException) { continue }

                            val d = pkt.data
                            if (pkt.length < 4) continue
                            val atyp = d[3].toInt() and 0xFF
                            val dstHost: String; val dstPort: Int; val payloadOff: Int
                            when (atyp) {
                                0x01 -> {
                                    if (pkt.length < 10) continue
                                    dstHost = "${d[4].toInt() and 0xFF}.${d[5].toInt() and 0xFF}" +
                                              ".${d[6].toInt() and 0xFF}.${d[7].toInt() and 0xFF}"
                                    dstPort = ((d[8].toInt() and 0xFF) shl 8) or (d[9].toInt() and 0xFF)
                                    payloadOff = 10
                                }
                                0x03 -> {
                                    val dlen = d[4].toInt() and 0xFF
                                    if (pkt.length < 7 + dlen) continue
                                    dstHost = String(d, 5, dlen)
                                    dstPort = ((d[5+dlen].toInt() and 0xFF) shl 8) or (d[6+dlen].toInt() and 0xFF)
                                    payloadOff = 7 + dlen
                                }
                                else -> continue
                            }
                            val payloadLen = pkt.length - payloadOff
                            if (payloadLen <= 0) continue

                            if (dstPort == 53) {
                                // DNS → relay via TCP through XZAP tunnel
                                val query = d.copyOfRange(payloadOff, payloadOff + payloadLen)
                                val udpHdr = d.copyOfRange(0, payloadOff)
                                val src = pkt.socketAddress as java.net.InetSocketAddress
                                executor?.submit { relayDnsQuery(dstHost, query, udpHdr, src, udpSock) }
                            }
                            // Non-DNS UDP (QUIC etc): drop → instant TCP fallback
                        }
                    } catch (_: Exception) {
                    } finally { udpSock.close() }
                }

                // Keep control connection open per SOCKS5 spec
                try { while (inp.read() != -1 && !client.isClosed && running.get()) {} }
                catch (_: Exception) {}
                return
            }
            if (req[1] != 0x01.toByte()) {
                // BIND or unknown — general failure
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }

            val host: String
            when (req[3].toInt() and 0xFF) {
                0x01 -> {
                    val a = readExactly(inp, 4) ?: return
                    host = a.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                0x03 -> {
                    val len = inp.read() and 0xFF
                    val d = readExactly(inp, len) ?: return
                    host = String(d)
                }
                0x04 -> {
                    val a = readExactly(inp, 16) ?: return
                    host = java.net.InetAddress.getByAddress(a).hostAddress ?: return
                }
                else -> return
            }
            val pb = readExactly(inp, 2) ?: return
            val port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)

            Log.i(TAG, "CONNECT $host:$port")

            // Split tunneling
            if (shouldBypass(host)) {
                Log.i(TAG, "bypass $host")
                handleDirect(client, inp, out, host, port)
                return
            }

            // XZAP tunnel
            val tunnel = openXzapTunnel(host, port) ?: run {
                Log.w(TAG, "tunnel failed $host:$port")
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }
            Log.i(TAG, "tunnel open $host:$port")

            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            // Set read timeout for data phase — detect dead connections on mobile
            // (cell tower switch, NAT timeout, server crash). Without this, relay
            // threads hang forever when the network path breaks mid-stream.
            tunnel.soTimeout = DATA_TIMEOUT_MS

            val tunnelInp = java.io.BufferedInputStream(tunnel.getInputStream(), BUFFER_SIZE)
            val tunnelOut = tunnel.getOutputStream()  // no buffering — TLS handles it
            // One FrameReader per tunnel connection — preserves leftover bytes between
            // frames so multiple server frames arriving in one batch are never dropped.
            val reader = FrameReader(tunnelInp)

            val sentBytes = java.util.concurrent.atomic.AtomicLong(0)
            val recvBytes = java.util.concurrent.atomic.AtomicLong(0)

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        sendFrame(tunnelOut, buf, n)
                        sentBytes.addAndGet(n.toLong())
                    }
                } catch (_: Exception) {}
                try { tunnel.close() } catch (_: Exception) {}
            }
            val t2 = Thread {
                try {
                    val bOut = java.io.BufferedOutputStream(out, BUFFER_SIZE)
                    while (running.get()) {
                        val data = reader.next() ?: break
                        bOut.write(data)
                        bOut.flush()
                        recvBytes.addAndGet(data.size.toLong())
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }

            t1.start(); t2.start()
            t1.join(); t2.join()
            Log.i(TAG, "done $host:$port sent=${sentBytes.get()} recv=${recvBytes.get()}")
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
        // Try pool connection first, retry with fresh on failure.
        // Pool connections may be stale (mobile NAT kills idle TCP in 30-120s)
        // and Java's isClosed/isConnected cannot detect remote close.
        for (attempt in 0..1) {
            val sock: Socket
            try {
                sock = if (attempt == 0) {
                    getPoolConnection() ?: openTlsConnection()
                } else {
                    openTlsConnection()
                }
            } catch (e: Exception) {
                Log.d(TAG, "Connect failed $host:$port attempt=$attempt: ${e.message}")
                continue
            }
            try {
                sock.soTimeout = HANDSHAKE_TIMEOUT_MS
                val tunnelOut = sock.getOutputStream()
                val tunnelInp = sock.getInputStream()

                val req = """{"cmd":"connect","host":"$host","port":$port}""".toByteArray()
                sendFrame(tunnelOut, req)

                val resp = FrameReader(tunnelInp).next() ?: run { sock.close(); throw java.io.IOException("no response") }
                val respStr = String(resp)
                if ("\"ok\":true" !in respStr && "\"ok\": true" !in respStr) {
                    sock.close(); return null  // server explicitly rejected — don't retry
                }
                return sock
            } catch (e: Exception) {
                try { sock.close() } catch (_: Exception) {}
                if (attempt == 0) {
                    Log.d(TAG, "Pool stale $host:$port, retrying fresh: ${e.message}")
                } else {
                    Log.d(TAG, "Tunnel failed $host:$port: ${e.message}")
                }
            }
        }
        return null
    }

    /** Relay a single DNS query over TCP through XZAP tunnel (DNS-over-TCP).
     *  Opens tunnel → sends [2B len][query] → reads [2B len][response] → UDP reply. */
    private fun relayDnsQuery(dnsServer: String, query: ByteArray,
                              udpHeader: ByteArray, srcAddr: java.net.InetSocketAddress,
                              udpSock: java.net.DatagramSocket) {
        val tunnel = openXzapTunnel(dnsServer, 53) ?: return
        try {
            tunnel.soTimeout = 5_000  // 5s DNS timeout
            val tOut = tunnel.getOutputStream()
            val tInp = java.io.BufferedInputStream(tunnel.getInputStream(), 4096)

            // DNS-over-TCP: prepend 2-byte length to query
            val tcpQuery = ByteArray(2 + query.size)
            tcpQuery[0] = ((query.size shr 8) and 0xFF).toByte()
            tcpQuery[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, tcpQuery, 2, query.size)
            sendFrame(tOut, tcpQuery)

            // Read DNS-over-TCP response via XZAP tunnel
            val respData = FrameReader(tInp).next() ?: return
            if (respData.size < 2) return
            val respLen = ((respData[0].toInt() and 0xFF) shl 8) or (respData[1].toInt() and 0xFF)
            val available = respData.size - 2
            if (available < respLen) return
            val dnsResp = respData.copyOfRange(2, 2 + respLen)

            // Build SOCKS5 UDP reply: [same header as request][DNS response]
            val udpReply = ByteArray(udpHeader.size + dnsResp.size)
            System.arraycopy(udpHeader, 0, udpReply, 0, udpHeader.size)
            System.arraycopy(dnsResp, 0, udpReply, udpHeader.size, dnsResp.size)
            udpSock.send(java.net.DatagramPacket(udpReply, udpReply.size, srcAddr))
        } catch (e: Exception) {
            Log.d(TAG, "DNS relay failed $dnsServer: ${e.message}")
        } finally {
            try { tunnel.close() } catch (_: Exception) {}
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
