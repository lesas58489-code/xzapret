package com.xzap.client

import android.content.Context
import android.content.SharedPreferences

/**
 * Тонкий враппер над SharedPreferences для пользовательских тумблеров и
 * списков. Persistent across процесса (нужно для BootReceiver и для того,
 * чтобы UI/Сервис видели одни и те же значения).
 */
object Prefs {
    private const val FILE = "xzap_prefs"

    private const val KEY_AUTO_CONNECT    = "auto_connect"
    private const val KEY_KILL_SWITCH     = "kill_switch"
    private const val KEY_BYPASS_PACKAGES = "bypass_packages"

    private fun sp(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun isAutoConnect(ctx: Context): Boolean = sp(ctx).getBoolean(KEY_AUTO_CONNECT, false)
    fun setAutoConnect(ctx: Context, v: Boolean) { sp(ctx).edit().putBoolean(KEY_AUTO_CONNECT, v).apply() }

    fun isKillSwitch(ctx: Context): Boolean = sp(ctx).getBoolean(KEY_KILL_SWITCH, false)
    fun setKillSwitch(ctx: Context, v: Boolean) { sp(ctx).edit().putBoolean(KEY_KILL_SWITCH, v).apply() }

    /** Доп. пакеты, которые пользователь добавил в bypass через UI (Phase A). */
    fun getBypassPackages(ctx: Context): Set<String> =
        sp(ctx).getStringSet(KEY_BYPASS_PACKAGES, emptySet())?.toSet() ?: emptySet()

    fun setBypassPackages(ctx: Context, pkgs: Set<String>) {
        sp(ctx).edit().putStringSet(KEY_BYPASS_PACKAGES, pkgs).apply()
    }
}
