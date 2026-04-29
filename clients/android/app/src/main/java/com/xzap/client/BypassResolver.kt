package com.xzap.client

import android.content.Context

/**
 * Источники списка пакетов, которые НЕ должны идти через TUN.
 *
 * Архитектура с прицелом на Phase B (UsageStats-driven heuristics) и
 * Phase C (cloud-pushed list). Сейчас — два источника: статический
 * BYPASS_APPS из XzapVpnService и пользовательский из Prefs.
 *
 * Когда придёт C — добавится CloudBypassSource(JsonEndpoint), фоновый
 * sync, мердж по версии. Когда B — добавится HeuristicBypassSource,
 * пишущий «авто-найденные» пакеты в отдельный prefs-ключ.
 *
 * Composite склеивает все источники без дублей. Иммутабелен — пересоздаётся
 * при каждом пересборе TUN (Builder в Android всё равно immutable post-establish).
 */
interface BypassSource {
    fun packages(): Set<String>
}

class StaticDefaultsSource(private val packages: Set<String>) : BypassSource {
    override fun packages(): Set<String> = packages
}

class UserPrefsSource(private val ctx: Context) : BypassSource {
    override fun packages(): Set<String> = Prefs.getBypassPackages(ctx)
}

class CompositeBypassSource(private val sources: List<BypassSource>) : BypassSource {
    override fun packages(): Set<String> = sources.flatMap { it.packages() }.toSet()
}

object BypassResolver {
    /** Builds the active resolver. Called once per TUN establish. */
    fun build(ctx: Context, staticDefaults: Set<String>): BypassSource =
        CompositeBypassSource(listOf(
            StaticDefaultsSource(staticDefaults),
            UserPrefsSource(ctx),
            // future: CloudBypassSource(ctx), HeuristicBypassSource(ctx)
        ))
}
