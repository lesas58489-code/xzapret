package com.xzap.client

import android.util.Log
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Properties
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SSH tunnel with built-in SOCKS5 proxy.
 * Equivalent to: ssh -N -D localPort user@host -p port -i key
 *
 * Each SOCKS5 CONNECT → SSH ChannelDirectTCPIP → remote server connects to target.
 * DPI sees only SSH traffic — no SNI, no TLS fingerprinting issues.
 */
class SshTunnel(
    private val host: String,
    private val sshPort: Int = 22,
    private val user: String = "root",
    private val privateKey: String,
    private val running: AtomicBoolean,
) {
    companion object {
        private const val TAG = "SshTunnel"
        private const val BUFFER_SIZE = 65536
    }

    private var session: Session? = null
    private var socksServer: ServerSocket? = null
    private var executor: ExecutorService? = null

    fun start(localPort: Int) {
        executor = Executors.newCachedThreadPool()

        // Connect SSH
        val jsch = JSch()
        jsch.addIdentity("xzap", privateKey.toByteArray(), null, null)

        session = jsch.getSession(user, host, sshPort).apply {
            val config = Properties()
            config["StrictHostKeyChecking"] = "no"
            setConfig(config)
            setServerAliveInterval(30000)
            setServerAliveCountMax(3)
            connect(15000)
        }

        Log.i(TAG, "SSH connected to $host:$sshPort")

        // Start SOCKS5 server
        socksServer = ServerSocket()
        socksServer?.reuseAddress = true
        socksServer?.bind(InetSocketAddress("127.0.0.1", localPort))
        Log.i(TAG, "SOCKS5 on 127.0.0.1:$localPort (via SSH)")

        executor?.submit {
            while (running.get() && session?.isConnected == true) {
                try {
                    val client = socksServer?.accept() ?: break
                    executor?.submit { handleSocks(client) }
                } catch (e: Exception) {
                    if (running.get()) Log.d(TAG, "Accept: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        socksServer?.close()
        session?.disconnect()
        executor?.shutdownNow()
        session = null
        Log.i(TAG, "SSH tunnel stopped")
    }

    fun isConnected(): Boolean = session?.isConnected == true

    private fun handleSocks(client: Socket) {
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

            val targetHost: String
            when (req[3].toInt() and 0xFF) {
                0x01 -> {
                    val a = ByteArray(4); inp.read(a)
                    targetHost = a.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                0x03 -> {
                    val len = inp.read() and 0xFF
                    val d = ByteArray(len); inp.read(d)
                    targetHost = String(d)
                }
                0x04 -> {
                    val a = ByteArray(16); inp.read(a)
                    targetHost = java.net.InetAddress.getByAddress(a).hostAddress ?: return
                }
                else -> return
            }
            val pb = ByteArray(2); inp.read(pb)
            val targetPort = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)

            // Open SSH channel to target
            val channel = session?.openChannel("direct-tcpip") as? ChannelDirectTCPIP ?: return
            channel.setHost(targetHost)
            channel.setPort(targetPort)
            channel.connect(10000)

            // SOCKS5 success
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            Log.d(TAG, "→ $targetHost:$targetPort")

            // Bidirectional pipe
            val chInp = channel.inputStream
            val chOut = channel.outputStream

            val t1 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get() && channel.isConnected) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        chOut.write(buf, 0, n)
                        chOut.flush()
                    }
                } catch (_: Exception) {}
                channel.disconnect()
            }
            val t2 = Thread {
                try {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (running.get() && channel.isConnected) {
                        val n = chInp.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        out.flush()
                    }
                } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }

            t1.start(); t2.start()
            t1.join(); t2.join()

        } catch (e: Exception) {
            Log.d(TAG, "SOCKS error: ${e.message}")
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }
}
