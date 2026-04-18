package com.xzap.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    companion object {
        private const val VPN_REQUEST_CODE = 100
        private const val PREFS = "xzap_prefs"
    }

    private lateinit var etServer: EditText
    private lateinit var etPort: EditText
    private lateinit var etKey: EditText
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private var connected = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServer = findViewById(R.id.et_server)
        etPort = findViewById(R.id.et_port)
        etKey = findViewById(R.id.et_key)
        btnConnect = findViewById(R.id.btn_connect)
        tvStatus = findViewById(R.id.tv_status)

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        etServer.setText(prefs.getString("server", "wss://solar-cloud.xyz/ws"))
        etPort.setText(prefs.getString("port", "8443"))
        etKey.setText(prefs.getString("key", ""))

        btnConnect.setOnClickListener {
            if (connected) disconnect() else requestVpn()
        }
    }

    private fun requestVpn() {
        var server = etServer.text.toString().trim()
        // Android keyboard autocorrect sometimes replaces 'wss://' with 'http://'.
        // Detect and undo before passing down.
        if (server.startsWith("http://", ignoreCase = true)) {
            server = "ws://" + server.removePrefix("http://")
        } else if (server.startsWith("https://", ignoreCase = true)) {
            server = "wss://" + server.removePrefix("https://")
        }
        etServer.setText(server)
        // Strip all whitespace from key (users often paste with trailing newline / spaces)
        val key = etKey.text.toString().replace(Regex("\\s"), "")
        if (server.isEmpty() || key.isEmpty()) {
            Toast.makeText(this, "Server and Key required", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val decoded = android.util.Base64.decode(key, android.util.Base64.DEFAULT)
            if (decoded.size != 32) {
                Toast.makeText(this, "Key must decode to 32 bytes, got ${decoded.size}", Toast.LENGTH_LONG).show()
                return
            }
        } catch (e: IllegalArgumentException) {
            Toast.makeText(this, "Invalid key (not valid base64)", Toast.LENGTH_LONG).show()
            return
        }
        etKey.setText(key)
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
            .putString("server", server)
            .putString("port", etPort.text.toString())
            .putString("key", key)
            .apply()

        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            startVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_CONNECT
            putExtra(XzapVpnService.EXTRA_SERVER, etServer.text.toString().trim())
            putExtra(XzapVpnService.EXTRA_PORT, etPort.text.toString().trim().toIntOrNull() ?: 8443)
            putExtra(XzapVpnService.EXTRA_KEY, etKey.text.toString().trim())
            putExtra(XzapVpnService.EXTRA_TLS_PROFILE, "chrome131")
        }
        startService(intent)
        connected = true
        btnConnect.text = "Disconnect"
        tvStatus.text = "Status: Connected"
        tvStatus.setTextColor(0xFF00CC00.toInt())
    }

    private fun disconnect() {
        startService(Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_DISCONNECT
        })
        connected = false
        btnConnect.text = "Connect"
        tvStatus.text = "Status: Disconnected"
        tvStatus.setTextColor(0xFFCC0000.toInt())
    }
}
