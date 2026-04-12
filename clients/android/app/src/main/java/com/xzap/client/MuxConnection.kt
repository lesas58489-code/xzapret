package com.xzap.client

import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * MUX protocol over WebSocket — all tunnels through ONE connection.
 *
 * Wire format: [4B stream_id][1B action][payload]
 *   OPEN(0x01): payload = "host:port"
 *   DATA(0x02): payload = raw bytes
 *   CLOSE(0x03): no payload
 */
class MuxConnection(private val wsUrl: String) {

    companion object {
        private const val TAG = "MuxConn"
        private const val ACT_OPEN: Byte = 0x01
        private const val ACT_DATA: Byte = 0x02
        private const val ACT_CLOSE: Byte = 0x03
        private const val HDR_SIZE = 5
        private const val RECONNECT_DELAY_MS = 2000L
    }

    private val client = OkHttpClient.Builder()
        .pingInterval(0, TimeUnit.SECONDS) // no pings — CF doesn't forward
        .readTimeout(0, TimeUnit.SECONDS)
        .connectTimeout(15, TimeUnit.SECONDS)
        .build()

    private var ws: WebSocket? = null
    private val streams = ConcurrentHashMap<Int, StreamQueue>()
    private val nextId = AtomicInteger(1)
    private val connected = AtomicBoolean(false)
    private val running = AtomicBoolean(true)

    /** Queue of received DATA for a stream. null = stream closed. */
    class StreamQueue {
        val queue = LinkedBlockingQueue<ByteArray?>()
    }

    fun connect() {
        val request = Request.Builder().url(wsUrl).build()
        ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WSS connected to $wsUrl")
                connected.set(true)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (bytes.size < HDR_SIZE) return
                val buf = ByteBuffer.wrap(bytes.toByteArray())
                val streamId = buf.int
                val action = buf.get()
                val payload = ByteArray(buf.remaining())
                buf.get(payload)

                when (action) {
                    ACT_DATA -> {
                        streams[streamId]?.queue?.put(payload)
                    }
                    ACT_CLOSE -> {
                        streams[streamId]?.queue?.put(null) // sentinel
                        streams.remove(streamId)
                    }
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "WSS failed: ${t.message}")
                connected.set(false)
                closeAllStreams()
                if (running.get()) reconnect()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "WSS closed: $code")
                connected.set(false)
                closeAllStreams()
                if (running.get()) reconnect()
            }
        })
    }

    private fun reconnect() {
        Thread.sleep(RECONNECT_DELAY_MS)
        if (running.get()) {
            Log.i(TAG, "Reconnecting...")
            connect()
        }
    }

    private fun closeAllStreams() {
        for (sq in streams.values) {
            sq.queue.put(null)
        }
        streams.clear()
    }

    fun openStream(host: String, port: Int): Int {
        val id = nextId.getAndIncrement()
        streams[id] = StreamQueue()
        sendFrame(id, ACT_OPEN, "$host:$port".toByteArray())
        return id
    }

    fun sendData(streamId: Int, data: ByteArray) {
        sendFrame(streamId, ACT_DATA, data)
    }

    fun recvData(streamId: Int, timeoutMs: Long = 30000): ByteArray? {
        return streams[streamId]?.queue?.poll(timeoutMs, TimeUnit.MILLISECONDS)
    }

    fun closeStream(streamId: Int) {
        sendFrame(streamId, ACT_CLOSE, ByteArray(0))
        streams.remove(streamId)
    }

    private fun sendFrame(streamId: Int, action: Byte, data: ByteArray) {
        val buf = ByteBuffer.allocate(HDR_SIZE + data.size)
        buf.putInt(streamId)
        buf.put(action)
        buf.put(data)
        ws?.send(buf.array().toByteString())
    }

    fun isConnected() = connected.get()

    fun shutdown() {
        running.set(false)
        ws?.close(1000, "shutdown")
        client.dispatcher.executorService.shutdown()
    }
}
