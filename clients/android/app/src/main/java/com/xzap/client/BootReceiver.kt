package com.xzap.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log

/**
 * Запускает VPN после ребута телефона, если в Prefs стоит autoConnect=true.
 *
 * Если VpnService.prepare() вернул не-null (согласие на VPN отозвано — например,
 * пользователь поставил другой VPN-приложение) — UI из BroadcastReceiver
 * показать нельзя, поэтому вешаем sticky-нотификацию которая открывает
 * MainActivity, где prepare() будет вызван заново со стандартным диалогом.
 */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "XzapBoot"
        private const val NOTIF_CHANNEL = "xzap_boot"
        private const val NOTIF_ID = 99
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON") {
            return
        }
        if (!Prefs.isAutoConnect(context)) {
            Log.i(TAG, "boot ignored: autoConnect=off")
            return
        }
        Log.i(TAG, "boot completed, autoConnect=on — starting VPN")

        val consent = VpnService.prepare(context)
        if (consent != null) {
            Log.w(TAG, "VPN consent missing — posting sticky notification")
            postReconnectNotification(context)
            return
        }

        val svcIntent = Intent(context, XzapVpnService::class.java).apply {
            this.action = XzapVpnService.ACTION_CONNECT
            putExtra(XzapVpnService.EXTRA_SERVER, BuildConfig.XZAP_SERVERS)
            putExtra(XzapVpnService.EXTRA_PORT, BuildConfig.XZAP_PORT)
            putExtra(XzapVpnService.EXTRA_KEY, BuildConfig.XZAP_KEY)
            putExtra(XzapVpnService.EXTRA_TLS_PROFILE, "chrome131")
            putExtra(XzapVpnService.EXTRA_WS_FALLBACK, BuildConfig.XZAP_WS_FALLBACK)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(svcIntent)
        } else {
            context.startService(svcIntent)
        }
    }

    private fun postReconnectNotification(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(NOTIF_CHANNEL, "XZAP boot", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val pi = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(ctx, NOTIF_CHANNEL)
            .setContentTitle("XZAP")
            .setContentText("Согласие на VPN отозвано — нажмите для подключения")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        nm.notify(NOTIF_ID, n)
    }
}
