package com.xzap.client

import android.util.Log
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * XZAP Mux tunnel — one persistent TLS connection carrying N logical streams.
 *
 * Architecture:
 *   Browser opens 30 parallel HTTPS → 30 MuxStream instances open new stream_ids
 *   in this single TLS tunnel. No new TLS handshakes. No per-request TCP connects.
 *
 * Wire format (inside one XZAP encrypted frame):
 *   [4B stream_id][1B cmd][4B payload_len][payload]
 *
 * Commands:
 *   0x01 SYN      — open stream, payload = JSON {"host":"...","port":N}
 *   0x02 SYN_ACK  — accepted (empty) or rejected
 *   0x03 DATA     — data
 *   0x04 FIN      — graceful close
 *   0x05 RST      — error
 *
 * Version handshake: stream_id=0 SYN with payload {"v":"mux1"}, server SYN_ACKs same.
 */
class XzapMuxTunnel(
    private val serverHost: String,
    private val serverPort: Int,
    private val key: ByteArray,
    private val sslFactory: SSLSocketFactory,
    private val sni: String,
) {
    companion object {
        private const val TAG = "XzapMux"
        private const val CMD_SYN = 0x01
        private const val CMD_SYN_ACK = 0x02
        private const val CMD_DATA = 0x03
        private const val CMD_FIN = 0x04
        private const val CMD_RST = 0x05
        private const val CMD_PING = 0x06
        private const val CMD_PONG = 0x07
        private const val CMD_WINDOW = 0x08  // flow control update
        private const val MUX_HDR = 9
        private const val PING_INTERVAL_MS = 5_000L
        private const val PING_TIMEOUT_MS = 10_000L   // loose timeout — any server frame counts as liveness
        private const val CONTROL_STREAM_ID = 0
        private const val STREAM_RECV_WINDOW = 256 * 1024  // per-stream inbound buffer cap
        private const val PREFIX_SIZE = 16
        private const val NONCE_SIZE = 12
        private const val TAG_BITS = 128
        private const val FRAG_THRESHOLD = 150
        private const val FRAG_MIN = 24
        private const val FRAG_MAX = 68
        private const val DATA_CHUNK = 32 * 1024
    }

    private val keySpec = SecretKeySpec(key, "AES")
    private val random = java.security.SecureRandom()
    private val encCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }
    private val decCipher = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }

    private var socket: Socket? = null
    private var sockOut: OutputStream? = null
    private var sockIn: InputStream? = null
    private val writeLock = Object()

    private val streams = ConcurrentHashMap<Int, MuxStream>()
    private val nextStreamId = AtomicInteger(1)  // 0 reserved for control
    private val alive = AtomicBoolean(false)
    private var readerThread: Thread? = null
    private var pingThread: Thread? = null
    @Volatile private var lastPongAt = 0L
    @Volatile private var lastPingAt = 0L
    @Volatile private var lastFrameAt = 0L   // any frame from server = tunnel is alive
    @Volatile var createdAt = 0L
        private set
    @Volatile var retiring = false  // marked for graceful retirement — no new streams

    val isAlive: Boolean get() = alive.get()
    val streamCount: Int get() = streams.size

    /** Establish TLS + XZAP mux version handshake. Throws on failure. */
    fun connect() {
        // Force IPv4: on some mobile carriers (e.g. Megafon RU) the Java dual-stack
        // resolver picks IPv6 for outgoing connections, but the carrier has no IPv6
        // route to IPv4 destinations like our server → ENETUNREACH from /::. By
        // resolving to an Inet4Address explicitly and opening a plain Socket first
        // (then wrapping with SSL), we avoid the dual-stack ambiguity.
        val ipv4 = resolveIPv4(serverHost) ?: throw java.net.UnknownHostException("no IPv4 for $serverHost")
        val plain = Socket()
        plain.tcpNoDelay = true
        plain.keepAlive = true
        plain.connect(InetSocketAddress(ipv4, serverPort), 10_000)
        val sock = sslFactory.createSocket(plain, serverHost, serverPort, true) as SSLSocket
        sock.sslParameters = sock.sslParameters.apply {
            serverNames = listOf(javax.net.ssl.SNIHostName(sni))
        }
        sock.startHandshake()
        sock.soTimeout = 10_000
        // Aggressive keepalive for mobile NAT (default linux is 2h idle — useless).
        trySetKeepAliveParams(sock, idleSec = 30, intervalSec = 10, count = 3)

        socket = sock
        sockOut = sock.getOutputStream()
        sockIn = java.io.BufferedInputStream(sock.getInputStream(), 131072)

        // Version handshake — send bare {"v":"mux1"} (matches server's detection path)
        val versionPayload = """{"v":"mux1"}""".toByteArray()
        sendXzapFrame(versionPayload)

        // Server replies with bare {"v":"mux1"}
        val resp = recvXzapFrame() ?: throw IOException("mux handshake: no response")
        val respStr = String(resp)
        if ("\"v\":\"mux1\"" !in respStr && "\"v\": \"mux1\"" !in respStr) {
            throw IOException("mux handshake: bad response $respStr")
        }

        sock.soTimeout = 0  // disable timeout now, data phase
        alive.set(true)
        val now = System.currentTimeMillis()
        lastPongAt = now
        lastFrameAt = now
        createdAt = now
        createdAt = now
        readerThread = Thread({ readerLoop() }, "XzapMux-reader").also { it.start() }
        pingThread = Thread({ pingLoop() }, "XzapMux-ping").also { it.isDaemon = true; it.start() }
        Log.i(TAG, "mux tunnel established → $serverHost:$serverPort")
    }

    private fun resolveIPv4(host: String): java.net.InetAddress? {
        // If host is an IPv4 literal, getByName returns Inet4Address directly.
        // If hostname, getAllByName may return mix of v4/v6 — pick first v4.
        return try {
            java.net.InetAddress.getAllByName(host).firstOrNull { it is java.net.Inet4Address }
        } catch (e: Exception) {
            null
        }
    }

    private fun trySetKeepAliveParams(sock: Socket, idleSec: Int, intervalSec: Int, count: Int) {
        // Android API 29+ supports ExtendedSocketOptions via reflection — best-effort.
        try {
            val cls = Class.forName("jdk.net.ExtendedSocketOptions")
            val keepIdle = cls.getField("TCP_KEEPIDLE").get(null) as java.net.SocketOption<Int>
            val keepIntvl = cls.getField("TCP_KEEPINTERVAL").get(null) as java.net.SocketOption<Int>
            val keepCnt = cls.getField("TCP_KEEPCOUNT").get(null) as java.net.SocketOption<Int>
            sock.setOption(keepIdle, idleSec)
            sock.setOption(keepIntvl, intervalSec)
            sock.setOption(keepCnt, count)
        } catch (_: Throwable) {
            // Not available — application-level ping will compensate
        }
    }

    private fun pingLoop() {
        while (alive.get()) {
            val beforeSleep = System.currentTimeMillis()
            try { Thread.sleep(PING_INTERVAL_MS) } catch (_: InterruptedException) { break }
            if (!alive.get()) break
            val now = System.currentTimeMillis()
            val sleptFor = now - beforeSleep

            // Doze/suspend detection: if Thread.sleep was frozen significantly
            // longer than requested, the device was asleep. TCP connections
            // have almost certainly been killed by NAT/carrier during doze.
            // Kill this tunnel proactively — pickTunnel will spawn a fresh one.
            if (sleptFor > PING_INTERVAL_MS * 3) {
                Log.w(TAG, "suspend detected (slept ${sleptFor}ms, expected ${PING_INTERVAL_MS}ms) → tunnel invalidated")
                forceClose()
                return
            }

            // Dead-peer detection: tunnel is considered dead only if NO frames
            // of any kind arrived from server within PING_TIMEOUT.
            if (now - lastFrameAt > PING_TIMEOUT_MS && lastPingAt > lastFrameAt) {
                Log.w(TAG, "ping timeout → tunnel dead (${now - lastFrameAt}ms silent)")
                forceClose()
                return
            }
            try {
                lastPingAt = now
                sendMuxFrame(CONTROL_STREAM_ID, CMD_PING, ByteArray(0))
            } catch (e: Exception) {
                Log.w(TAG, "ping send failed: ${e.message}")
                forceClose()
                return
            }
        }
    }

    private fun forceClose() {
        alive.set(false)
        try { socket?.close() } catch (_: Exception) {}
    }

    /** Open a new logical stream to host:port. Returns null on failure. */
    fun openStream(host: String, port: Int, timeoutMs: Long = 10_000): MuxStream? {
        if (!alive.get()) return null
        val sid = nextStreamId.getAndIncrement()
        val stream = MuxStream(sid, this)
        streams[sid] = stream

        val req = """{"host":"$host","port":$port}""".toByteArray()
        try {
            sendMuxFrame(sid, CMD_SYN, req)
        } catch (e: Exception) {
            streams.remove(sid)
            return null
        }

        // Wait for SYN_ACK or RST
        val result = stream.awaitAck(timeoutMs)
        if (!result) {
            streams.remove(sid)
            return null
        }

        // Engage flow control on server side with a bootstrap WINDOW(0) frame.
        // Without this, pure-upload streams deadlock at 256KB (client's initial
        // send window) because server never learns the client supports FC.
        try {
            val zero = ByteArray(4)  // delta=0
            sendMuxFrame(sid, CMD_WINDOW, zero)
        } catch (_: Exception) {}

        return stream
    }

    fun close() {
        alive.set(false)
        try { socket?.close() } catch (_: Exception) {}
        for (s in streams.values) s.onClosed()
        streams.clear()
    }

    /** Inner: reader loop demultiplexes frames to streams. */
    private fun readerLoop() {
        try {
            while (alive.get()) {
                val frame = recvXzapFrame() ?: break
                lastFrameAt = System.currentTimeMillis()  // any frame = alive signal
                if (frame.size < MUX_HDR) continue
                val sid = getInt(frame, 0)
                val cmd = frame[4].toInt() and 0xFF
                val plen = getInt(frame, 5)
                if (plen < 0 || MUX_HDR + plen > frame.size) continue
                val payload = if (plen > 0) frame.copyOfRange(MUX_HDR, MUX_HDR + plen) else ByteArray(0)

                if (sid == CONTROL_STREAM_ID) {
                    when (cmd) {
                        CMD_PING -> {
                            // Echo back — mostly for server-initiated health checks
                            try { sendMuxFrame(CONTROL_STREAM_ID, CMD_PONG, ByteArray(0)) } catch (_: Exception) {}
                        }
                        CMD_PONG -> {
                            lastPongAt = System.currentTimeMillis()
                        }
                    }
                    continue
                }
                val stream = streams[sid]
                when (cmd) {
                    CMD_SYN_ACK -> stream?.onAck(true)
                    CMD_DATA -> stream?.onData(payload)
                    CMD_WINDOW -> {
                        val delta = if (payload.size >= 4) getInt(payload, 0) else 0
                        stream?.onWindowUpdate(delta)
                    }
                    CMD_FIN, CMD_RST -> {
                        stream?.onAck(false)
                        stream?.onClosed()
                        streams.remove(sid)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "reader exit: ${e.message}")
        } finally {
            alive.set(false)
            for (s in streams.values) s.onClosed()
        }
    }

    // ============ Mux-frame layer (sid|cmd|len|payload inside one XZAP frame) ============

    internal fun sendMuxFrame(sid: Int, cmd: Int, payload: ByteArray) {
        if (!alive.get() && cmd != CMD_SYN) throw IOException("tunnel dead")
        val frame = ByteArray(MUX_HDR + payload.size)
        putInt(frame, 0, sid)
        frame[4] = cmd.toByte()
        putInt(frame, 5, payload.size)
        System.arraycopy(payload, 0, frame, MUX_HDR, payload.size)
        sendXzapFrame(frame)
    }

    internal fun sendFin(sid: Int) {
        try { sendMuxFrame(sid, CMD_FIN, ByteArray(0)) } catch (_: Exception) {}
    }

    // ============ XZAP-frame layer (encrypt + prefix + fragment) ============

    private fun sendXzapFrame(data: ByteArray) {
        val prefix = ByteArray(PREFIX_SIZE).also { random.nextBytes(it) }
        val encrypted = encrypt(data)
        val payloadSize = PREFIX_SIZE + encrypted.size
        val xzapFrame = ByteArray(4 + payloadSize)
        putInt(xzapFrame, 0, payloadSize)
        System.arraycopy(prefix, 0, xzapFrame, 4, PREFIX_SIZE)
        System.arraycopy(encrypted, 0, xzapFrame, 4 + PREFIX_SIZE, encrypted.size)

        val out = sockOut ?: throw IOException("no socket")
        synchronized(writeLock) {
            if (xzapFrame.size <= FRAG_THRESHOLD) writeMicroFrag(out, xzapFrame)
            else writeBulk(out, xzapFrame)
            out.flush()
        }
    }

    private fun writeMicroFrag(out: OutputStream, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val remaining = data.size - offset
            val fragSize = if (remaining <= FRAG_MAX) remaining
            else FRAG_MIN + random.nextInt(FRAG_MAX - FRAG_MIN + 1).coerceAtMost(remaining - FRAG_MIN)
            val chunk = data.copyOfRange(offset, offset + fragSize)
            val total = chunk.size + 1
            val frag = ByteArray(4 + total)
            putInt(frag, 0, total); frag[4] = 0x00
            System.arraycopy(chunk, 0, frag, 5, chunk.size)
            out.write(frag)
            offset += fragSize
        }
    }

    private fun writeBulk(out: OutputStream, data: ByteArray) {
        val hdr = ByteArray(5)
        putInt(hdr, 0, data.size + 1); hdr[4] = 0x00
        out.write(hdr); out.write(data)
    }

    /** Read one complete XZAP frame (handles fragmentation and chaff). */
    private val rxAcc = java.io.ByteArrayOutputStream(8192)
    private var rxLeftover: ByteArray? = null

    private fun recvXzapFrame(): ByteArray? {
        val inp = sockIn ?: return null
        rxLeftover?.let { rxAcc.write(it); rxLeftover = null }
        while (true) {
            val fragHdr = readExactly(inp, 4) ?: return null
            val fragTotal = getInt(fragHdr, 0)
            if (fragTotal <= 0 || fragTotal > 256 * 1024) return null
            val fragPayload = readExactly(inp, fragTotal) ?: return null
            val flags = fragPayload[0].toInt() and 0xFF
            if (flags == 0x01) continue  // chaff
            rxAcc.write(fragPayload, 1, fragPayload.size - 1)
            val size = rxAcc.size()
            if (size >= 4) {
                val bytes = rxAcc.toByteArray()
                val xzapLen = getInt(bytes, 0)
                if (size >= 4 + xzapLen) {
                    val encPart = ByteArray(xzapLen - PREFIX_SIZE)
                    System.arraycopy(bytes, 4 + PREFIX_SIZE, encPart, 0, encPart.size)
                    val consumed = 4 + xzapLen
                    if (size > consumed) rxLeftover = bytes.copyOfRange(consumed, size)
                    rxAcc.reset()
                    return decrypt(encPart)
                }
            }
        }
    }

    // ============ helpers ============

    private fun readExactly(inp: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n); var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r <= 0) return null
            off += r
        }
        return buf
    }

    private fun putInt(b: ByteArray, o: Int, v: Int) {
        b[o] = ((v shr 24) and 0xFF).toByte(); b[o+1] = ((v shr 16) and 0xFF).toByte()
        b[o+2] = ((v shr 8) and 0xFF).toByte(); b[o+3] = (v and 0xFF).toByte()
    }

    private fun getInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o+1].toInt() and 0xFF) shl 16) or
        ((b[o+2].toInt() and 0xFF) shl 8) or (b[o+3].toInt() and 0xFF)

    private fun encrypt(data: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val c = encCipher.get()!!
        c.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        val ct = c.doFinal(data)
        val out = ByteArray(NONCE_SIZE + ct.size)
        System.arraycopy(nonce, 0, out, 0, NONCE_SIZE)
        System.arraycopy(ct, 0, out, NONCE_SIZE, ct.size)
        return out
    }

    private fun decrypt(data: ByteArray): ByteArray {
        val c = decCipher.get()!!
        c.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, data, 0, NONCE_SIZE))
        return c.doFinal(data, NONCE_SIZE, data.size - NONCE_SIZE)
    }
}

/**
 * One logical stream. Provides InputStream/OutputStream-like interface for
 * handleClient to use in place of a real Socket.
 */
class MuxStream(val id: Int, private val tunnel: XzapMuxTunnel) {
    private val rxQueue = LinkedBlockingQueue<ByteArray>()
    private val ackSignal = java.util.concurrent.CountDownLatch(1)
    private var ackResult = false
    private val closed = AtomicBoolean(false)
    private var rxLeftover: ByteArray? = null

    // Flow control: peer's send window to us (we inform peer via WINDOW frames
    // after we've consumed bytes). Our send window to peer (peer informs us).
    private val sendWindow = AtomicInteger(256 * 1024)
    private val consumedBytes = AtomicInteger(0)
    private val sendWindowLock = Object()

    internal fun onAck(ok: Boolean) {
        ackResult = ok
        ackSignal.countDown()
    }

    internal fun onData(data: ByteArray) {
        if (!closed.get()) rxQueue.offer(data)
    }

    internal fun onWindowUpdate(delta: Int) {
        if (delta <= 0) return
        synchronized(sendWindowLock) {
            sendWindow.addAndGet(delta)
            (sendWindowLock as java.lang.Object).notifyAll()
        }
    }

    internal fun onClosed() {
        if (closed.compareAndSet(false, true)) {
            rxQueue.offer(EOF_SENTINEL)
            synchronized(sendWindowLock) { (sendWindowLock as java.lang.Object).notifyAll() }
        }
    }

    internal fun awaitAck(timeoutMs: Long): Boolean {
        if (!ackSignal.await(timeoutMs, TimeUnit.MILLISECONDS)) return false
        return ackResult
    }

    /** Read one chunk of data. Returns empty array on EOF. */
    fun read(): ByteArray {
        val chunk = rxQueue.take()
        if (chunk === EOF_SENTINEL) return ByteArray(0)
        return chunk
    }

    /** Read up to `buf.size` bytes into buf; returns bytes read or -1 on EOF. */
    fun read(buf: ByteArray): Int {
        val lo = rxLeftover
        if (lo != null) {
            val n = minOf(lo.size, buf.size)
            System.arraycopy(lo, 0, buf, 0, n)
            rxLeftover = if (n < lo.size) lo.copyOfRange(n, lo.size) else null
            creditConsumed(n)
            return n
        }
        val chunk = rxQueue.take()
        if (chunk === EOF_SENTINEL) { rxQueue.offer(EOF_SENTINEL); return -1 }
        val n = minOf(chunk.size, buf.size)
        System.arraycopy(chunk, 0, buf, 0, n)
        if (n < chunk.size) rxLeftover = chunk.copyOfRange(n, chunk.size)
        creditConsumed(n)
        return n
    }

    /** After consuming N bytes from rx queue, credit them back to peer as WINDOW frame
     *  when batch accumulates to 64KB. Prevents peer from outrunning us. */
    private fun creditConsumed(n: Int) {
        val total = consumedBytes.addAndGet(n)
        if (total >= 64 * 1024) {
            consumedBytes.addAndGet(-total)
            try {
                val buf = ByteArray(4)
                buf[0] = ((total shr 24) and 0xFF).toByte()
                buf[1] = ((total shr 16) and 0xFF).toByte()
                buf[2] = ((total shr 8) and 0xFF).toByte()
                buf[3] = (total and 0xFF).toByte()
                tunnel.sendMuxFrame(id, 0x08, buf)  // CMD_WINDOW
            } catch (_: Exception) {}
        }
    }

    fun write(data: ByteArray, off: Int = 0, len: Int = data.size) {
        if (closed.get()) throw IOException("stream closed")
        var remaining = len
        var pos = off
        while (remaining > 0 && !closed.get()) {
            // Block until we have send credit
            synchronized(sendWindowLock) {
                while (sendWindow.get() <= 0 && !closed.get()) {
                    try { (sendWindowLock as java.lang.Object).wait(5000) }
                    catch (_: InterruptedException) { return }
                }
            }
            if (closed.get()) throw IOException("stream closed")
            val allowed = minOf(remaining, sendWindow.get(), 32 * 1024)
            val slice = data.copyOfRange(pos, pos + allowed)
            tunnel.sendMuxFrame(id, 0x03, slice)  // CMD_DATA
            sendWindow.addAndGet(-allowed)
            pos += allowed
            remaining -= allowed
        }
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            tunnel.sendFin(id)
            rxQueue.offer(EOF_SENTINEL)
        }
    }

    val isClosed: Boolean get() = closed.get()

    companion object {
        private val EOF_SENTINEL = ByteArray(0)
    }
}
