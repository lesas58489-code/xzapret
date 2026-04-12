package com.xzap.client

import android.app.Activity
import android.content.Intent
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
        private const val DEFAULT_WS_URL = "wss://solar-cloud.xyz:2053/ws"
    }

    private lateinit var etWsUrl: EditText
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private var connected = false
    private lateinit var prefs: android.content.SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etWsUrl = findViewById(R.id.et_server)
        btnConnect = findViewById(R.id.btn_connect)
        tvStatus = findViewById(R.id.tv_status)

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        etWsUrl.setText(prefs.getString("ws_url", DEFAULT_WS_URL))

        btnConnect.setOnClickListener {
            if (connected) disconnect() else requestVpn()
        }
    }

    private fun requestVpn() {
        val wsUrl = etWsUrl.text.toString().trim()
        if (wsUrl.isEmpty()) {
            Toast.makeText(this, "WebSocket URL required", Toast.LENGTH_SHORT).show()
            return
        }
        prefs.edit().putString("ws_url", wsUrl).apply()

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
            putExtra(XzapVpnService.EXTRA_WS_URL, etWsUrl.text.toString().trim())
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
