package com.xzap.client

import android.util.Log
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * XZAP Tunnel — connects to server, does handshake, pipes data.
 *
 * Wire format: [4B length][16B random prefix][AES-GCM encrypted data]
 * Fragmentation: [4B total][1B flags][data] for frames <= 150 bytes
 */
class XzapTunnel(
    private val serverHost: String,
    private val serverPort: Int,
    private val crypto: XzapCrypto,
    private val useTls: Boolean = true,
) {
    companion object {
        private const val TAG = "XzapTunnel"
        private const val PREFIX_SIZE = 16
        private const val MAX_FRAME = 256 * 1024
        private const val FRAG_THRESHOLD = 150
        private const val FRAG_MIN = 24
        private const val FRAG_MAX = 68
        private const val CONNECT_TIMEOUT = 15_000
    }

    private val random = SecureRandom()

    // White domains for TLS SNI masquerade
    private val whiteDomains = listOf(
        "www.youtube.com", "www.google.com", "www.cloudflare.com",
        "www.microsoft.com", "www.apple.com", "www.amazon.com",
        "cdn.jsdelivr.net", "ajax.googleapis.com",
    )

    /**
     * Open a tunnel to target host:port through the XZAP server.
     * Returns a connected Socket pair (xzapInput, xzapOutput) for piping.
     */
    fun connect(targetHost: String, targetPort: Int): TunnelConnection {
        val socket = createConnection()
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())

        // Handshake
        val req = JSONObject().apply {
            put("cmd", "connect")
            put("host", targetHost)
            put("port", targetPort)
        }.toString().toByteArray()

        sendFrame(output, req)
        val resp = JSONObject(String(recvFrame(input)))

        if (!resp.optBoolean("ok", false)) {
            socket.close()
            throw IOException("Tunnel refused: ${resp.optString("err", "unknown")}")
        }

        Log.i(TAG, "Tunnel open -> $targetHost:$targetPort")
        return TunnelConnection(socket, input, output)
    }

    private fun createConnection(): Socket {
        return if (useTls) {
            val sni = whiteDomains.random()
            val sslCtx = SSLContext.getInstance("TLS")
            // Trust all certs (verification via shared XZAP key, not certificate)
            sslCtx.init(null, arrayOf<TrustManager>(TrustAllManager()), random)
            val factory = sslCtx.socketFactory
            val socket = factory.createSocket() as SSLSocket
            socket.sslParameters = socket.sslParameters.apply {
                serverNames = listOf(javax.net.ssl.SNIHostName(sni))
                protocols = arrayOf("TLSv1.3", "TLSv1.2")
            }
            socket.connect(InetSocketAddress(serverHost, serverPort), CONNECT_TIMEOUT)
            socket.soTimeout = 0
            socket.tcpNoDelay = true
            Log.d(TAG, "TLS connected (SNI=$sni)")
            socket
        } else {
            Socket().apply {
                connect(InetSocketAddress(serverHost, serverPort), CONNECT_TIMEOUT)
                tcpNoDelay = true
            }
        }
    }

    fun sendFrame(output: DataOutputStream, data: ByteArray) {
        val encrypted = crypto.encrypt(data)
        val prefix = ByteArray(PREFIX_SIZE).also { random.nextBytes(it) }
        val payload = prefix + encrypted
        val frame = encodeInt(payload.size) + payload

        // Fragmentation layer
        if (frame.size <= FRAG_THRESHOLD) {
            writeFragmented(output, frame)
        } else {
            writeBulk(output, frame)
        }
    }

    fun recvFrame(input: DataInputStream): ByteArray {
        // Read through fragmentation layer
        val frame = readDefragmented(input)

        // Parse XZAP frame: [4B length][prefix][encrypted]
        val length = decodeInt(frame, 0)
        if (length > MAX_FRAME) throw IOException("Frame too large: $length")
        val payload = frame.copyOfRange(4, 4 + length)
        val encrypted = payload.copyOfRange(PREFIX_SIZE, payload.size)
        return crypto.decrypt(encrypted)
    }

    // --- Fragmentation layer ---

    private fun writeFragmented(output: DataOutputStream, data: ByteArray) {
        val buf = mutableListOf<Byte>()
        var offset = 0
        while (offset < data.size) {
            val remaining = data.size - offset
            val fragSize = if (remaining <= FRAG_MAX) remaining
            else random.nextInt(FRAG_MAX - FRAG_MIN + 1) + FRAG_MIN

            val chunk = data.copyOfRange(offset, offset + fragSize)
            buf.addAll(packFragment(chunk, 0x00).toList())
            offset += fragSize
        }
        synchronized(output) {
            output.write(buf.toByteArray())
            output.flush()
        }
    }

    private fun writeBulk(output: DataOutputStream, data: ByteArray) {
        val frag = packFragment(data, 0x00)
        synchronized(output) {
            output.write(frag)
            output.flush()
        }
    }

    private fun readDefragmented(input: DataInputStream): ByteArray {
        // Read one fragmentation frame: [4B total][1B flags][data]
        // Keep reading until we get a non-chaff frame
        while (true) {
            val total = input.readInt()
            if (total <= 0 || total > MAX_FRAME) throw IOException("Bad fragment: $total")
            val payload = ByteArray(total)
            input.readFully(payload)
            val flags = payload[0].toInt() and 0xFF
            val data = payload.copyOfRange(1, payload.size)

            if (flags == 0x01) continue // chaff, skip

            // Now we have the XZAP frame data, but we may need more
            // For simplicity, read ALL fragments until we have a complete XZAP frame
            // A complete frame starts with 4B length
            if (data.size >= 4) {
                val xzapLen = decodeInt(data, 0)
                if (data.size >= 4 + xzapLen) {
                    return data
                }
                // Need more fragments
                val buf = data.toMutableList()
                while (buf.size < 4 + xzapLen) {
                    val t2 = input.readInt()
                    val p2 = ByteArray(t2)
                    input.readFully(p2)
                    val f2 = p2[0].toInt() and 0xFF
                    if (f2 == 0x01) continue // chaff
                    buf.addAll(p2.copyOfRange(1, p2.size).toList())
                }
                return buf.toByteArray()
            }
        }
    }

    private fun packFragment(data: ByteArray, flags: Int): ByteArray {
        val total = data.size + 1
        return encodeInt(total) + byteArrayOf(flags.toByte()) + data
    }

    private fun encodeInt(v: Int): ByteArray =
        byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private fun decodeInt(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 24) or
        ((data[offset + 1].toInt() and 0xFF) shl 16) or
        ((data[offset + 2].toInt() and 0xFF) shl 8) or
        (data[offset + 3].toInt() and 0xFF)

    /** Trust-all X509 manager — XZAP verifies via shared key, not cert. */
    private class TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, type: String) {}
        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, type: String) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }
}


/**
 * Active tunnel connection — use sendFrame/recvFrame for data exchange.
 */
class TunnelConnection(
    val socket: Socket,
    val input: DataInputStream,
    val output: DataOutputStream,
) : AutoCloseable {

    fun sendData(tunnel: XzapTunnel, data: ByteArray) = tunnel.sendFrame(output, data)
    fun recvData(tunnel: XzapTunnel): ByteArray = tunnel.recvFrame(input)

    override fun close() {
        try { socket.close() } catch (_: Exception) {}
    }
}
