package com.xzap.client

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Minimal tun2socks: reads IP packets from VPN TUN, forwards:
 *   - TCP → MUX WebSocket streams
 *   - UDP (DNS) → direct DatagramSocket (bypasses VPN via addDisallowedApplication)
 */
class TunForwarder(
    private val vpnFd: ParcelFileDescriptor,
    private val mux: MuxConnection,
    private val running: AtomicBoolean,
) {
    companion object {
        private const val TAG = "TunFwd"
        private const val MTU = 1500
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17

        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_PSH = 0x08
        private const val TCP_ACK = 0x10
    }

    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val ipId = AtomicInteger(1)
    private lateinit var tunOut: FileOutputStream

    class TcpSession(
        val muxStreamId: Int,
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
    ) {
        @Volatile var seqNum: Long = 1000L
        @Volatile var ackNum: Long = 0L
        @Volatile var established: Boolean = false
        val lock = Any()
    }

    fun start() {
        val input = FileInputStream(vpnFd.fileDescriptor)
        tunOut = FileOutputStream(vpnFd.fileDescriptor)
        val buf = ByteArray(MTU)

        Thread({
            Log.i(TAG, "TUN reader started")
            try {
                while (running.get()) {
                    val len = input.read(buf)
                    if (len <= 0) continue
                    try {
                        handlePacket(buf, len)
                    } catch (e: Exception) {
                        Log.d(TAG, "Packet error: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "TUN reader error", e)
            }
            Log.i(TAG, "TUN reader stopped")
        }, "tun-reader").start()
    }

    private fun handlePacket(pkt: ByteArray, len: Int) {
        if (len < 20) return
        val version = (pkt[0].toInt() ushr 4) and 0xF
        if (version != 4) return

        val ipHdrLen = (pkt[0].toInt() and 0xF) * 4
        val totalLen = ((pkt[2].toInt() and 0xFF) shl 8) or (pkt[3].toInt() and 0xFF)
        val proto = pkt[9].toInt() and 0xFF

        when (proto) {
            PROTO_TCP -> if (len >= ipHdrLen + 20) handleTcp(pkt, ipHdrLen, totalLen)
            PROTO_UDP -> if (len >= ipHdrLen + 8) handleUdp(pkt, ipHdrLen, totalLen)
        }
    }

    // ==================== UDP (DNS) ====================

    private fun handleUdp(pkt: ByteArray, ipHdrLen: Int, totalLen: Int) {
        val srcIp = pkt.copyOfRange(12, 16)
        val dstIp = pkt.copyOfRange(16, 20)
        val srcPort = u16(pkt, ipHdrLen)
        val dstPort = u16(pkt, ipHdrLen + 2)
        val udpLen = u16(pkt, ipHdrLen + 4)
        val dataOffset = ipHdrLen + 8
        val dataLen = udpLen - 8
        if (dataLen <= 0 || dataOffset + dataLen > totalLen) return

        val payload = pkt.copyOfRange(dataOffset, dataOffset + dataLen)

        // Forward DNS via direct socket (bypasses VPN — app excluded)
        Thread({
            try {
                val dstAddr = InetAddress.getByAddress(dstIp)
                val sock = DatagramSocket()
                sock.soTimeout = 5000
                val outPkt = DatagramPacket(payload, payload.size, dstAddr, dstPort)
                sock.send(outPkt)

                val resp = ByteArray(4096)
                val inPkt = DatagramPacket(resp, resp.size)
                sock.receive(inPkt)
                sock.close()

                // Build UDP response packet and write to TUN
                val respData = resp.copyOf(inPkt.length)
                writeUdpPacket(dstIp, srcIp, dstPort, srcPort, respData)
            } catch (e: Exception) {
                Log.d(TAG, "UDP forward error: ${e.message}")
            }
        }, "udp-fwd").start()
    }

    private fun writeUdpPacket(srcIp: ByteArray, dstIp: ByteArray,
                                srcPort: Int, dstPort: Int, data: ByteArray) {
        val ipHdrLen = 20
        val udpHdrLen = 8
        val totalLen = ipHdrLen + udpHdrLen + data.size
        val pkt = ByteArray(totalLen)

        // IP header
        pkt[0] = 0x45.toByte()
        put16(pkt, 2, totalLen)
        put16(pkt, 4, ipId.getAndIncrement()) // IP ID
        pkt[8] = 64 // TTL
        pkt[9] = PROTO_UDP.toByte()
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        ipChecksum(pkt, 0, ipHdrLen)

        // UDP header
        put16(pkt, ipHdrLen, srcPort)
        put16(pkt, ipHdrLen + 2, dstPort)
        put16(pkt, ipHdrLen + 4, udpHdrLen + data.size)
        // UDP checksum = 0 (optional for IPv4)
        System.arraycopy(data, 0, pkt, ipHdrLen + udpHdrLen, data.size)

        synchronized(tunOut) { tunOut.write(pkt) }
    }

    // ==================== TCP ====================

    private fun handleTcp(pkt: ByteArray, ipHdrLen: Int, totalLen: Int) {
        val srcIp = pkt.copyOfRange(12, 16)
        val dstIp = pkt.copyOfRange(16, 20)
        val srcPort = u16(pkt, ipHdrLen)
        val dstPort = u16(pkt, ipHdrLen + 2)
        val seqNum = u32(pkt, ipHdrLen + 4)
        val ackNum = u32(pkt, ipHdrLen + 8)
        val tcpHdrLen = ((pkt[ipHdrLen + 12].toInt() ushr 4) and 0xF) * 4
        val flags = pkt[ipHdrLen + 13].toInt() and 0xFF
        val dataOffset = ipHdrLen + tcpHdrLen
        val dataLen = totalLen - dataOffset

        val dstIpStr = "${dstIp[0].toInt() and 0xFF}.${dstIp[1].toInt() and 0xFF}.${dstIp[2].toInt() and 0xFF}.${dstIp[3].toInt() and 0xFF}"
        val key = "$dstIpStr:$dstPort:$srcPort"

        // SYN — new connection
        if ((flags and TCP_SYN) != 0 && (flags and TCP_ACK) == 0) {
            // Close existing session if any
            sessions.remove(key)?.let { mux.closeStream(it.muxStreamId) }

            val streamId = mux.openStream(dstIpStr, dstPort)
            val session = TcpSession(streamId, srcIp, dstIp, srcPort, dstPort)
            session.ackNum = seqNum + 1
            sessions[key] = session

            Log.d(TAG, "[$streamId] SYN → $dstIpStr:$dstPort")

            synchronized(session.lock) {
                writeTcp(session, TCP_SYN or TCP_ACK, ByteArray(0))
                session.seqNum++
            }
            session.established = true
            startMuxReader(key, session)
            return
        }

        val session = sessions[key] ?: return

        // RST
        if ((flags and TCP_RST) != 0) {
            sessions.remove(key)
            mux.closeStream(session.muxStreamId)
            return
        }

        // FIN
        if ((flags and TCP_FIN) != 0) {
            synchronized(session.lock) {
                session.ackNum = seqNum + 1
                writeTcp(session, TCP_ACK or TCP_FIN, ByteArray(0))
                session.seqNum++
            }
            sessions.remove(key)
            mux.closeStream(session.muxStreamId)
            return
        }

        // ACK with data
        if ((flags and TCP_ACK) != 0 && dataLen > 0) {
            synchronized(session.lock) {
                session.ackNum = seqNum + dataLen
            }
            val data = pkt.copyOfRange(dataOffset, dataOffset + dataLen)
            mux.sendData(session.muxStreamId, data)
            synchronized(session.lock) {
                writeTcp(session, TCP_ACK, ByteArray(0))
            }
            return
        }

        // ACK only — just update state
        if ((flags and TCP_ACK) != 0) {
            // Nothing to do — app acknowledged our data
        }
    }

    private fun startMuxReader(key: String, session: TcpSession) {
        Thread({
            try {
                while (running.get() && sessions.containsKey(key)) {
                    val data = mux.recvData(session.muxStreamId, 10000) ?: break
                    synchronized(session.lock) {
                        writeTcp(session, TCP_ACK or TCP_PSH, data)
                        session.seqNum += data.size
                    }
                }
            } catch (e: Exception) {
                Log.d(TAG, "[${session.muxStreamId}] mux reader: ${e.message}")
            }
            // Send FIN if still tracked
            if (sessions.remove(key) != null) {
                synchronized(session.lock) {
                    try {
                        writeTcp(session, TCP_ACK or TCP_FIN, ByteArray(0))
                    } catch (_: Exception) {}
                }
            }
        }, "mux-$key").start()
    }

    // ==================== Packet construction ====================

    private fun writeTcp(session: TcpSession, flags: Int, data: ByteArray) {
        val ipHdrLen = 20
        val tcpHdrLen = 20
        val totalLen = ipHdrLen + tcpHdrLen + data.size
        val pkt = ByteArray(totalLen)

        // IP header (src=target, dst=app)
        pkt[0] = 0x45.toByte()
        put16(pkt, 2, totalLen)
        put16(pkt, 4, ipId.getAndIncrement())
        pkt[6] = 0x40.toByte() // DF flag
        pkt[8] = 64 // TTL
        pkt[9] = PROTO_TCP.toByte()
        System.arraycopy(session.dstIp, 0, pkt, 12, 4) // src = target
        System.arraycopy(session.srcIp, 0, pkt, 16, 4) // dst = app
        ipChecksum(pkt, 0, ipHdrLen)

        // TCP header
        put16(pkt, ipHdrLen, session.dstPort)     // src port = target port
        put16(pkt, ipHdrLen + 2, session.srcPort) // dst port = app port
        put32(pkt, ipHdrLen + 4, session.seqNum)
        put32(pkt, ipHdrLen + 8, session.ackNum)
        pkt[ipHdrLen + 12] = 0x50.toByte() // data offset = 5 words
        pkt[ipHdrLen + 13] = flags.toByte()
        put16(pkt, ipHdrLen + 14, 65535) // window

        if (data.isNotEmpty()) {
            System.arraycopy(data, 0, pkt, ipHdrLen + tcpHdrLen, data.size)
        }

        tcpChecksum(pkt, ipHdrLen, totalLen - ipHdrLen, session.dstIp, session.srcIp)

        synchronized(tunOut) { tunOut.write(pkt) }
    }

    // ==================== Helpers ====================

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun u32(buf: ByteArray, off: Int): Long =
        ((buf[off].toLong() and 0xFF) shl 24) or
        ((buf[off + 1].toLong() and 0xFF) shl 16) or
        ((buf[off + 2].toLong() and 0xFF) shl 8) or
        (buf[off + 3].toLong() and 0xFF)

    private fun put16(buf: ByteArray, off: Int, v: Int) {
        buf[off] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 1] = (v and 0xFF).toByte()
    }

    private fun put32(buf: ByteArray, off: Int, v: Long) {
        buf[off] = ((v ushr 24) and 0xFF).toByte()
        buf[off + 1] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 3] = (v and 0xFF).toByte()
    }

    private fun ipChecksum(buf: ByteArray, off: Int, len: Int) {
        buf[off + 10] = 0; buf[off + 11] = 0
        val sum = calcChecksum(buf, off, len)
        buf[off + 10] = ((sum ushr 8) and 0xFF).toByte()
        buf[off + 11] = (sum and 0xFF).toByte()
    }

    private fun tcpChecksum(buf: ByteArray, tcpOff: Int, tcpLen: Int,
                             srcIp: ByteArray, dstIp: ByteArray) {
        buf[tcpOff + 16] = 0; buf[tcpOff + 17] = 0
        val pseudo = ByteArray(12 + tcpLen)
        System.arraycopy(srcIp, 0, pseudo, 0, 4)
        System.arraycopy(dstIp, 0, pseudo, 4, 4)
        pseudo[9] = PROTO_TCP.toByte()
        put16(pseudo, 10, tcpLen)
        System.arraycopy(buf, tcpOff, pseudo, 12, tcpLen)
        val sum = calcChecksum(pseudo, 0, pseudo.size)
        buf[tcpOff + 16] = ((sum ushr 8) and 0xFF).toByte()
        buf[tcpOff + 17] = (sum and 0xFF).toByte()
    }

    private fun calcChecksum(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        var rem = len
        while (rem > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2; rem -= 2
        }
        if (rem == 1) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }
}
