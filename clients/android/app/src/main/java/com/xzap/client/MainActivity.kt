package com.xzap.client

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
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
    private lateinit var cbTls: CheckBox
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView

    private var connected = false
    private lateinit var prefs: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServer = findViewById(R.id.et_server)
        etPort = findViewById(R.id.et_port)
        etKey = findViewById(R.id.et_key)
        cbTls = findViewById(R.id.cb_tls)
        btnConnect = findViewById(R.id.btn_connect)
        tvStatus = findViewById(R.id.tv_status)

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        loadSettings()

        btnConnect.setOnClickListener {
            if (connected) disconnect() else requestVpn()
        }
    }

    private fun requestVpn() {
        val server = etServer.text.toString().trim()
        val key = etKey.text.toString().trim()

        if (server.isEmpty() || key.isEmpty()) {
            Toast.makeText(this, "Server and Key required", Toast.LENGTH_SHORT).show()
            return
        }

        saveSettings()

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
            putExtra(XzapVpnService.EXTRA_TLS, cbTls.isChecked)
        }
        startService(intent)

        connected = true
        btnConnect.text = "Disconnect"
        tvStatus.text = "Status: Connected"
        tvStatus.setTextColor(0xFF00CC00.toInt())
    }

    private fun disconnect() {
        val intent = Intent(this, XzapVpnService::class.java).apply {
            action = XzapVpnService.ACTION_DISCONNECT
        }
        startService(intent)

        connected = false
        btnConnect.text = "Connect"
        tvStatus.text = "Status: Disconnected"
        tvStatus.setTextColor(0xFFCC0000.toInt())
    }

    private fun saveSettings() {
        prefs.edit()
            .putString("server", etServer.text.toString())
            .putString("port", etPort.text.toString())
            .putString("key", etKey.text.toString())
            .putBoolean("tls", cbTls.isChecked)
            .apply()
    }

    private fun loadSettings() {
        etServer.setText(prefs.getString("server", ""))
        etPort.setText(prefs.getString("port", "8443"))
        etKey.setText(prefs.getString("key", ""))
        cbTls.isChecked = prefs.getBoolean("tls", true)
    }
}
