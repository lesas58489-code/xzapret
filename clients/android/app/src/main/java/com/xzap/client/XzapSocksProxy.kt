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
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * XZAP SOCKS5 proxy with Mux transport.
 *
 * Architecture:
 *   tun2socks → SOCKS5 :10808 → XzapSocksProxy → MuxStream (one of N in MuxTunnel)
 *                                                 ↓
 *                                              one TLS to server
 *
 * A small pool of persistent mux tunnels (MAX_TUNNELS) multiplexes all SOCKS
 * connections. Opening a new HTTPS request = new stream_id in existing tunnel,
 * 0ms TLS handshake cost. Pool is replenished when a tunnel dies.
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
        private const val BUFFER_SIZE = 131072
        private const val MAX_TUNNELS = 3              // persistent mux tunnels
        private const val MAX_STREAMS_PER_TUNNEL = 100 // soft cap before spreading
        private const val TUNNEL_OPEN_TIMEOUT_MS = 10_000L
        private const val STREAM_OPEN_TIMEOUT_MS = 10_000L

        private val WHITE_DOMAINS = listOf(
            "www.cloudflare.com", "cloudflare.com",
            "www.microsoft.com", "microsoft.com",
            "www.apple.com", "apple.com",
            "www.amazon.com", "amazon.com",
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
            "ajax.aspnetcdn.com", "cdn.shopify.com",
        )
    }

    private val random = SecureRandom()
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private lateinit var sslFactory: SSLSocketFactory

    private val tunnels = ConcurrentLinkedDeque<XzapMuxTunnel>()
    private val tunnelLock = Object()
    private val udpAssociateSemaphore = java.util.concurrent.Semaphore(12)
    private val creatingTunnels = java.util.concurrent.atomic.AtomicInteger(0)

    private val poolReadyLatch = java.util.concurrent.CountDownLatch(1)
    private val poolSignaled = AtomicBoolean(false)

    fun waitReady(timeoutMs: Long): Boolean =
        poolReadyLatch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)

    fun start(port: Int) {
        executor = Executors.newCachedThreadPool()

        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
            override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, t: String) {}
            override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
        }), random)
        // Session resumption cache — speeds up tunnel reconnects (1-RTT handshake).
        // Default cache is small / short-lived. Make it big and long-lived.
        try {
            sslCtx.clientSessionContext?.sessionCacheSize = 64
            sslCtx.clientSessionContext?.sessionTimeout = 3600  // 1h
        } catch (_: Exception) {}
        sslFactory = sslCtx.socketFactory

        try { ServerSocket().apply { reuseAddress = true; bind(InetSocketAddress("127.0.0.1", port)); close() } } catch (_: Exception) {}
        serverSocket = ServerSocket()
        serverSocket?.reuseAddress = true
        serverSocket?.bind(InetSocketAddress("127.0.0.1", port))
        Log.i(TAG, "SOCKS5 on :$port → XZAP mux $serverHost:$serverPort (tunnels=$MAX_TUNNELS)")

        // Warm mux tunnels in background
        executor?.submit { warmTunnels() }

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
        for (t in tunnels) t.close()
        tunnels.clear()
        executor?.shutdownNow()
    }

    // ==================== Mux tunnel pool ====================

    private fun warmTunnels() {
        val threads = (1..MAX_TUNNELS).map { Thread { createTunnel() } }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        Log.i(TAG, "Mux pool: ${tunnels.size}/${MAX_TUNNELS} ready")
    }

    private fun createTunnel(): XzapMuxTunnel? {
        if (!running.get()) return null
        creatingTunnels.incrementAndGet()
        try {
            val sni = WHITE_DOMAINS[random.nextInt(WHITE_DOMAINS.size)]
            val t = XzapMuxTunnel(serverHost, serverPort, key, sslFactory, sni)
            return try {
                t.connect()
                tunnels.offer(t)
                if (!poolSignaled.getAndSet(true)) poolReadyLatch.countDown()
                t
            } catch (e: Exception) {
                Log.w(TAG, "tunnel create failed: ${e.message}")
                null
            }
        } finally {
            creatingTunnels.decrementAndGet()
        }
    }

    /** Pick least-loaded alive tunnel. Eagerly replaces dead ones in background. */
    private fun pickTunnel(): XzapMuxTunnel? {
        // Drop dead ones, count alive
        val iter = tunnels.iterator()
        var dead = 0
        while (iter.hasNext()) {
            val t = iter.next()
            if (!t.isAlive) { iter.remove(); dead++ }
        }
        if (dead > 0) Log.w(TAG, "$dead tunnels died, replacing")

        // Eager replacement: kick creation for every missing slot, up to MAX
        val needed = MAX_TUNNELS - tunnels.size - creatingTunnels.get()
        repeat(maxOf(0, needed)) {
            executor?.submit { createTunnel() }
        }

        // Use least-loaded
        var best: XzapMuxTunnel? = tunnels.minByOrNull { it.streamCount }
        if (best != null && best.isAlive) return best

        // Pool fully empty: wait up to 3s for background creation to finish
        val deadline = System.currentTimeMillis() + 3_000L
        while (System.currentTimeMillis() < deadline) {
            best = tunnels.firstOrNull { it.isAlive }
            if (best != null) return best
            Thread.sleep(50)
        }

        // Still empty: synchronous create as last resort
        synchronized(tunnelLock) {
            best = tunnels.firstOrNull { it.isAlive }
            if (best != null) return best
            return createTunnel()
        }
    }

    private fun openStream(host: String, port: Int): MuxStream? {
        repeat(2) {
            val tunnel = pickTunnel() ?: return null
            val stream = tunnel.openStream(host, port, STREAM_OPEN_TIMEOUT_MS)
            if (stream != null) return stream
            // Tunnel may have died mid-open; try again with a fresh pick
        }
        return null
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

            val greeting = readExactly(inp, 2) ?: return
            if (greeting[0] != 0x05.toByte()) return
            val methodCount = greeting[1].toInt() and 0xFF
            if (methodCount > 0) readExactly(inp, methodCount) ?: return
            out.write(byteArrayOf(0x05, 0x00))

            val req = readExactly(inp, 4) ?: return
            val cmd = req[1].toInt() and 0xFF

            if (cmd == 0x03) {
                handleUdpAssociate(client, inp, out, req)
                return
            }
            if (cmd != 0x01) {
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

            if (shouldBypass(host)) {
                handleDirect(client, inp, out, host, port)
                return
            }

            val stream = openStream(host, port) ?: run {
                Log.w(TAG, "stream open failed $host:$port")
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }

            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            val sentBytes = java.util.concurrent.atomic.AtomicLong(0)
            val recvBytes = java.util.concurrent.atomic.AtomicLong(0)

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get() && !stream.isClosed) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        stream.write(buf, 0, n)
                        sentBytes.addAndGet(n.toLong())
                    }
                } catch (_: Exception) {}
                try { stream.close() } catch (_: Exception) {}
            }
            val t2 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get()) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        out.write(buf, 0, n); out.flush()
                        recvBytes.addAndGet(n.toLong())
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

    private fun handleUdpAssociate(client: Socket, inp: InputStream, out: OutputStream, req: ByteArray) {
        skipSocksAddr(inp, req[3].toInt() and 0xFF)
        if (!udpAssociateSemaphore.tryAcquire()) {
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            return
        }
        val udpSock = java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())
        udpSock.soTimeout = 500
        val udpPort = udpSock.localPort
        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1,
            ((udpPort shr 8) and 0xFF).toByte(), (udpPort and 0xFF).toByte()))

        executor?.submit {
            try {
                val recvBuf = ByteArray(65536)
                // Deadline: if session idle for this long, close. DNS queries get
                // a fresh tunnel per query, so a session doing DNS won't need much.
                val deadline = System.currentTimeMillis() + 3_000L
                while (!client.isClosed && running.get() && System.currentTimeMillis() < deadline) {
                    val pkt = java.net.DatagramPacket(recvBuf, recvBuf.size)
                    try { udpSock.receive(pkt) } catch (_: java.net.SocketTimeoutException) { continue }

                    val d = pkt.data
                    if (pkt.length < 4) continue
                    val atyp = d[3].toInt() and 0xFF
                    val dstHost: String; val dstPort: Int; val payloadOff: Int
                    when (atyp) {
                        0x01 -> {
                            if (pkt.length < 10) continue
                            dstHost = "${d[4].toInt() and 0xFF}.${d[5].toInt() and 0xFF}.${d[6].toInt() and 0xFF}.${d[7].toInt() and 0xFF}"
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
                        val query = d.copyOfRange(payloadOff, payloadOff + payloadLen)
                        val udpHdr = d.copyOfRange(0, payloadOff)
                        val src = pkt.socketAddress as java.net.InetSocketAddress
                        executor?.submit { relayDnsQuery(dstHost, query, udpHdr, src, udpSock) }
                    } else {
                        // Non-DNS UDP (QUIC, WebRTC, etc): explicitly signal
                        // "UDP broken" by closing the SOCKS5 control connection.
                        // Per SOCKS5 RFC, tun2socks MUST tear down the UDP flow when
                        // control conn closes → app gets ECONNREFUSED → instant fallback
                        // to TCP. Without this, app waits up to 10s for QUIC reply.
                        Log.i(TAG, "reject UDP $dstHost:$dstPort (QUIC) → signal fallback")
                        try { client.close() } catch (_: Exception) {}
                        return@submit
                    }
                }
            } catch (_: Exception) {
            } finally {
                udpSock.close()
                udpAssociateSemaphore.release()
            }
        }
        try { while (inp.read() != -1 && !client.isClosed && running.get()) {} } catch (_: Exception) {}
    }

    private fun relayDnsQuery(dnsServer: String, query: ByteArray,
                              udpHeader: ByteArray, srcAddr: java.net.InetSocketAddress,
                              udpSock: java.net.DatagramSocket) {
        val stream = openStream(dnsServer, 53) ?: return
        try {
            val tcpQuery = ByteArray(2 + query.size)
            tcpQuery[0] = ((query.size shr 8) and 0xFF).toByte()
            tcpQuery[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, tcpQuery, 2, query.size)
            stream.write(tcpQuery)

            // Collect DNS-over-TCP response: [2B len][response]. Read everything
            // until stream closes or we have a complete response.
            val accum = java.io.ByteArrayOutputStream(1024)
            val buf = ByteArray(8192)
            while (true) {
                val n = stream.read(buf)
                if (n < 0) break
                if (n == 0) continue
                accum.write(buf, 0, n)
                val a = accum.toByteArray()
                if (a.size >= 2) {
                    val want = ((a[0].toInt() and 0xFF) shl 8) or (a[1].toInt() and 0xFF)
                    if (a.size >= 2 + want) break
                }
            }
            val a = accum.toByteArray()
            if (a.size < 2) return
            val respLen = ((a[0].toInt() and 0xFF) shl 8) or (a[1].toInt() and 0xFF)
            if (a.size < 2 + respLen) return
            val resp = a.copyOfRange(2, 2 + respLen)

            val udpReply = ByteArray(udpHeader.size + resp.size)
            System.arraycopy(udpHeader, 0, udpReply, 0, udpHeader.size)
            System.arraycopy(resp, 0, udpReply, udpHeader.size, resp.size)
            udpSock.send(java.net.DatagramPacket(udpReply, udpReply.size, srcAddr))
        } catch (_: Exception) {
        } finally {
            try { stream.close() } catch (_: Exception) {}
        }
    }

    private fun handleDirect(client: Socket, inp: InputStream, out: OutputStream,
                              host: String, port: Int) {
        try {
            val remote = Socket()
            remote.connect(InetSocketAddress(host, port), 10_000)
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
            t1.start(); t2.start(); t1.join(); t2.join()
        } catch (_: Exception) {
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        }
    }

    // ==================== Helpers ====================

    private fun skipSocksAddr(inp: InputStream, atyp: Int) {
        when (atyp) {
            0x01 -> readExactly(inp, 6)
            0x03 -> { val len = inp.read() and 0xFF; readExactly(inp, len + 2) }
            0x04 -> readExactly(inp, 18)
        }
    }

    private fun readExactly(inp: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n); var offset = 0
        while (offset < n) {
            val read = inp.read(buf, offset, n - offset)
            if (read <= 0) return null
            offset += read
        }
        return buf
    }
}
