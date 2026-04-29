package com.xzap.client.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/**
 * Dialog для редактирования пользовательского списка bypass-пакетов.
 * Изменения применяются при следующем reconnect (Builder в Android immutable
 * после establish — рантайм-добавление в текущую TUN не работает).
 *
 * Phase A — ручной ввод. Phase B добавит «Auto-suggest» из UsageStats,
 * Phase C — выбор из cloud-pushed списка.
 */
@Composable
fun BypassAppsDialog(
    initial: Set<String>,
    onApply: (Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    var pkgs by remember { mutableStateOf(initial.toMutableSet()) }
    var input by remember { mutableStateOf("") }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(
            modifier = Modifier
                .fillMaxWidth(0.92f)
                .clip(RoundedCornerShape(18.dp))
                .background(XzapColors.Surface2)
                .padding(20.dp),
        ) {
            Column {
                Text(
                    "Приложения мимо туннеля",
                    style = TextStyle(color = XzapColors.Fg, fontSize = 17.sp, fontWeight = FontWeight.SemiBold),
                )
                Spacer(Modifier.size(4.dp))
                Text(
                    "Эти приложения идут напрямую, без VPN. Изменения применяются при следующем подключении.",
                    style = TextStyle(color = XzapColors.TextTertiary, fontSize = 12.sp),
                )
                Spacer(Modifier.size(16.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = input,
                        onValueChange = { input = it },
                        modifier = Modifier.weight(1f),
                        placeholder = { Text("ru.cdek.sender") },
                        singleLine = true,
                    )
                    Spacer(Modifier.size(8.dp))
                    Button(onClick = {
                        val v = input.trim()
                        if (v.isNotEmpty()) {
                            pkgs = (pkgs + v).toMutableSet()
                            input = ""
                        }
                    }) { Text("+") }
                }
                Spacer(Modifier.size(12.dp))
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 80.dp, max = 280.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(pkgs.toList().sorted()) { pkg ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(XzapColors.Surface3)
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                pkg,
                                modifier = Modifier.weight(1f),
                                style = TextStyle(color = XzapColors.Fg, fontSize = 13.sp),
                            )
                            Box(
                                modifier = Modifier
                                    .size(28.dp)
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(XzapColors.Border)
                                    .clickable { pkgs = (pkgs - pkg).toMutableSet() },
                                contentAlignment = Alignment.Center,
                            ) { Text("×", style = TextStyle(color = XzapColors.Fg, fontSize = 16.sp)) }
                        }
                    }
                }
                Spacer(Modifier.size(16.dp))
                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDismiss) { Text("Отмена") }
                    Spacer(Modifier.size(8.dp))
                    Button(onClick = { onApply(pkgs); onDismiss() }) { Text("Сохранить") }
                }
            }
        }
    }
}
