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
        private const val MUX_HDR = 9
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

    val isAlive: Boolean get() = alive.get()
    val streamCount: Int get() = streams.size

    /** Establish TLS + XZAP mux version handshake. Throws on failure. */
    fun connect() {
        val sock = sslFactory.createSocket() as SSLSocket
        sock.sslParameters = sock.sslParameters.apply {
            serverNames = listOf(javax.net.ssl.SNIHostName(sni))
        }
        sock.connect(InetSocketAddress(serverHost, serverPort), 10_000)
        sock.soTimeout = 10_000
        sock.tcpNoDelay = true
        sock.keepAlive = true

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
        readerThread = Thread({ readerLoop() }, "XzapMux-reader").also { it.start() }
        Log.i(TAG, "mux tunnel established → $serverHost:$serverPort")
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
                if (frame.size < MUX_HDR) continue
                val sid = getInt(frame, 0)
                val cmd = frame[4].toInt() and 0xFF
                val plen = getInt(frame, 5)
                if (plen < 0 || MUX_HDR + plen > frame.size) continue
                val payload = if (plen > 0) frame.copyOfRange(MUX_HDR, MUX_HDR + plen) else ByteArray(0)

                val stream = streams[sid]
                when (cmd) {
                    CMD_SYN_ACK -> stream?.onAck(true)
                    CMD_DATA -> stream?.onData(payload)
                    CMD_FIN, CMD_RST -> {
                        stream?.onAck(false)  // unblock any pending openStream
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

    internal fun onAck(ok: Boolean) {
        ackResult = ok
        ackSignal.countDown()
    }

    internal fun onData(data: ByteArray) {
        if (!closed.get()) rxQueue.offer(data)
    }

    internal fun onClosed() {
        if (closed.compareAndSet(false, true)) {
            rxQueue.offer(EOF_SENTINEL)  // wake readers
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
        // Drain leftover first
        val lo = rxLeftover
        if (lo != null) {
            val n = minOf(lo.size, buf.size)
            System.arraycopy(lo, 0, buf, 0, n)
            rxLeftover = if (n < lo.size) lo.copyOfRange(n, lo.size) else null
            return n
        }
        val chunk = rxQueue.take()
        if (chunk === EOF_SENTINEL) { rxQueue.offer(EOF_SENTINEL); return -1 }
        val n = minOf(chunk.size, buf.size)
        System.arraycopy(chunk, 0, buf, 0, n)
        if (n < chunk.size) rxLeftover = chunk.copyOfRange(n, chunk.size)
        return n
    }

    fun write(data: ByteArray, off: Int = 0, len: Int = data.size) {
        if (closed.get()) throw IOException("stream closed")
        val slice = if (off == 0 && len == data.size) data else data.copyOfRange(off, off + len)
        tunnel.sendMuxFrame(id, 0x03, slice)  // CMD_DATA
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
