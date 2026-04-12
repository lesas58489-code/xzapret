package com.xzap.client

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Minimal tun2socks: reads IP packets from TUN, forwards TCP through MUX.
 *
 * For each TCP connection:
 *   1. SYN from app → open MUX stream, send SYN-ACK back to TUN
 *   2. DATA from app → forward to MUX, ACK back to TUN
 *   3. DATA from MUX → construct TCP segment, write to TUN
 *   4. FIN → close MUX stream
 */
class TunForwarder(
    private val vpnFd: ParcelFileDescriptor,
    private val mux: MuxConnection,
    private val running: AtomicBoolean,
) {
    companion object {
        private const val TAG = "TunFwd"
        private const val MTU = 1500
        private const val TCP_PROTO = 6
        private const val UDP_PROTO = 17
        private const val IP_HEADER_MIN = 20
        private const val TCP_HEADER_MIN = 20
        private const val TCP_SYN = 0x02
        private const val TCP_ACK = 0x10
        private const val TCP_FIN = 0x01
        private const val TCP_RST = 0x04
        private const val TCP_PSH = 0x08
    }

    // Connection tracking: "dstIp:dstPort:srcPort" → TcpSession
    private val sessions = ConcurrentHashMap<String, TcpSession>()

    data class TcpSession(
        val muxStreamId: Int,
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        var seqNum: Long = 1000L,        // our seq to app
        var ackNum: Long = 0L,           // next expected from app
        var established: Boolean = false,
    )

    fun start() {
        val input = FileInputStream(vpnFd.fileDescriptor)
        val output = FileOutputStream(vpnFd.fileDescriptor)
        val packet = ByteArray(MTU)

        Thread({
            Log.i(TAG, "TUN reader started")
            try {
                while (running.get()) {
                    val len = input.read(packet)
                    if (len <= 0) continue
                    handlePacket(packet, len, output)
                }
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "TUN reader error", e)
            }
            Log.i(TAG, "TUN reader stopped")
        }, "tun-reader").start()
    }

    private fun handlePacket(packet: ByteArray, len: Int, tunOut: FileOutputStream) {
        if (len < IP_HEADER_MIN) return
        val version = (packet[0].toInt() shr 4) and 0xF
        if (version != 4) return // IPv4 only

        val ipHeaderLen = (packet[0].toInt() and 0xF) * 4
        val protocol = packet[9].toInt() and 0xFF
        val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)

        if (protocol == TCP_PROTO && len >= ipHeaderLen + TCP_HEADER_MIN) {
            handleTcp(packet, ipHeaderLen, totalLen, tunOut)
        }
        // UDP/DNS: skip for now (Android handles DNS via VPN DNS setting)
    }

    private fun handleTcp(packet: ByteArray, ipHdrLen: Int, totalLen: Int, tunOut: FileOutputStream) {
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = ((packet[ipHdrLen].toInt() and 0xFF) shl 8) or (packet[ipHdrLen + 1].toInt() and 0xFF)
        val dstPort = ((packet[ipHdrLen + 2].toInt() and 0xFF) shl 8) or (packet[ipHdrLen + 3].toInt() and 0xFF)

        val seqNum = getUint32(packet, ipHdrLen + 4)
        val ackNum = getUint32(packet, ipHdrLen + 8)
        val tcpHdrLen = ((packet[ipHdrLen + 12].toInt() shr 4) and 0xF) * 4
        val flags = packet[ipHdrLen + 13].toInt() and 0xFF
        val dataOffset = ipHdrLen + tcpHdrLen
        val dataLen = totalLen - dataOffset

        val dstIpStr = InetAddress.getByAddress(dstIp).hostAddress
        val key = "$dstIpStr:$dstPort:$srcPort"

        when {
            // SYN — new connection
            (flags and TCP_SYN) != 0 && (flags and TCP_ACK) == 0 -> {
                Log.d(TAG, "SYN $dstIpStr:$dstPort from :$srcPort")
                val streamId = mux.openStream(dstIpStr!!, dstPort)
                val session = TcpSession(
                    muxStreamId = streamId,
                    srcIp = srcIp, dstIp = dstIp,
                    srcPort = srcPort, dstPort = dstPort,
                    seqNum = 1000L,
                    ackNum = seqNum + 1,
                )
                sessions[key] = session

                // Send SYN-ACK back
                sendTcpPacket(tunOut, session, TCP_SYN or TCP_ACK, ByteArray(0))
                session.seqNum++
                session.established = true

                // Start reading from MUX → TUN
                startMuxReader(key, session, tunOut)
            }

            // DATA on established connection
            (flags and TCP_ACK) != 0 && dataLen > 0 -> {
                val session = sessions[key] ?: return
                session.ackNum = seqNum + dataLen
                val data = packet.copyOfRange(dataOffset, dataOffset + dataLen)
                mux.sendData(session.muxStreamId, data)
                // ACK
                sendTcpPacket(tunOut, session, TCP_ACK, ByteArray(0))
            }

            // FIN
            (flags and TCP_FIN) != 0 -> {
                val session = sessions.remove(key) ?: return
                session.ackNum = seqNum + 1
                sendTcpPacket(tunOut, session, TCP_ACK or TCP_FIN, ByteArray(0))
                session.seqNum++
                mux.closeStream(session.muxStreamId)
            }

            // ACK only (keepalive, window update) — ignore
            (flags and TCP_ACK) != 0 && dataLen == 0 -> {}

            // RST
            (flags and TCP_RST) != 0 -> {
                val session = sessions.remove(key) ?: return
                mux.closeStream(session.muxStreamId)
            }
        }
    }

    private fun startMuxReader(key: String, session: TcpSession, tunOut: FileOutputStream) {
        Thread({
            try {
                while (running.get() && sessions.containsKey(key)) {
                    val data = mux.recvData(session.muxStreamId, 5000) ?: break
                    synchronized(session) {
                        sendTcpPacket(tunOut, session, TCP_ACK or TCP_PSH, data)
                        session.seqNum += data.size
                    }
                }
            } catch (_: Exception) {}
            // Send FIN if still tracked
            if (sessions.remove(key) != null) {
                synchronized(session) {
                    sendTcpPacket(tunOut, session, TCP_ACK or TCP_FIN, ByteArray(0))
                }
            }
        }, "mux-read-$key").start()
    }

    private fun sendTcpPacket(tunOut: FileOutputStream, session: TcpSession, flags: Int, data: ByteArray) {
        val ipHdrLen = 20
        val tcpHdrLen = 20
        val totalLen = ipHdrLen + tcpHdrLen + data.size
        val packet = ByteArray(totalLen)

        // IP header (swap src/dst — response goes back to app)
        packet[0] = 0x45.toByte() // version=4, hdrlen=5
        packet[2] = ((totalLen shr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[8] = 64 // TTL
        packet[9] = TCP_PROTO.toByte()
        System.arraycopy(session.dstIp, 0, packet, 12, 4) // src = original dst
        System.arraycopy(session.srcIp, 0, packet, 16, 4) // dst = original src

        // IP checksum
        putChecksum(packet, 0, ipHdrLen)

        // TCP header (swap ports)
        val tcp = ipHdrLen
        packet[tcp] = ((session.dstPort shr 8) and 0xFF).toByte()
        packet[tcp + 1] = (session.dstPort and 0xFF).toByte()
        packet[tcp + 2] = ((session.srcPort shr 8) and 0xFF).toByte()
        packet[tcp + 3] = (session.srcPort and 0xFF).toByte()
        putUint32(packet, tcp + 4, session.seqNum)
        putUint32(packet, tcp + 8, session.ackNum)
        packet[tcp + 12] = 0x50.toByte() // data offset = 5 (20 bytes)
        packet[tcp + 13] = flags.toByte()
        packet[tcp + 14] = 0xFF.toByte() // window high
        packet[tcp + 15] = 0xFF.toByte() // window low

        // Copy data
        if (data.isNotEmpty()) {
            System.arraycopy(data, 0, packet, ipHdrLen + tcpHdrLen, data.size)
        }

        // TCP checksum (with pseudo header)
        putTcpChecksum(packet, ipHdrLen, totalLen - ipHdrLen, session.dstIp, session.srcIp)

        synchronized(tunOut) {
            tunOut.write(packet)
        }
    }

    private fun getUint32(buf: ByteArray, offset: Int): Long {
        return ((buf[offset].toLong() and 0xFF) shl 24) or
               ((buf[offset + 1].toLong() and 0xFF) shl 16) or
               ((buf[offset + 2].toLong() and 0xFF) shl 8) or
               (buf[offset + 3].toLong() and 0xFF)
    }

    private fun putUint32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value shr 24) and 0xFF).toByte()
        buf[offset + 1] = ((value shr 16) and 0xFF).toByte()
        buf[offset + 2] = ((value shr 8) and 0xFF).toByte()
        buf[offset + 3] = (value and 0xFF).toByte()
    }

    private fun putChecksum(buf: ByteArray, offset: Int, len: Int) {
        buf[offset + 10] = 0
        buf[offset + 11] = 0
        val sum = checksumCalc(buf, offset, len)
        buf[offset + 10] = ((sum shr 8) and 0xFF).toByte()
        buf[offset + 11] = (sum and 0xFF).toByte()
    }

    private fun putTcpChecksum(buf: ByteArray, tcpOffset: Int, tcpLen: Int, srcIp: ByteArray, dstIp: ByteArray) {
        buf[tcpOffset + 16] = 0
        buf[tcpOffset + 17] = 0

        // Pseudo header + TCP
        val pseudo = ByteArray(12 + tcpLen)
        System.arraycopy(srcIp, 0, pseudo, 0, 4)
        System.arraycopy(dstIp, 0, pseudo, 4, 4)
        pseudo[8] = 0
        pseudo[9] = TCP_PROTO.toByte()
        pseudo[10] = ((tcpLen shr 8) and 0xFF).toByte()
        pseudo[11] = (tcpLen and 0xFF).toByte()
        System.arraycopy(buf, tcpOffset, pseudo, 12, tcpLen)

        val sum = checksumCalc(pseudo, 0, pseudo.size)
        buf[tcpOffset + 16] = ((sum shr 8) and 0xFF).toByte()
        buf[tcpOffset + 17] = (sum and 0xFF).toByte()
    }

    private fun checksumCalc(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        var remaining = len
        while (remaining > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }
        if (remaining == 1) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }
}
