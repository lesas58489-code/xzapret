# Troubleshooting & Lessons Learned

Реальные баги, с которыми мы столкнулись, и как они решились. Симптомы → причина → фикс. Накапливается со временем.

## Симптомы → диагноз

### «На телефоне не работает интернет вообще, VPN иконка горит»

**Возможные причины (по убыванию вероятности):**

1. **Scanner-style app устроил DoS пула** ⭐
   - В `xzap_debug.txt` (logcat) много `pool: cold (timed out waiting for first tunnel)` к destinations типа `port 22`, странные порты, рандомные IP по миру
   - Виновник — обычно SSH-клиент (Termius, JuiceSSH), nmap-like, BitTorrent client с DHT, или Fing
   - **Фикс**: удалить app или добавить package в `BYPASS_APPS` в `XzapVpnService.kt`
   - Подтверждённый случай (2026-04-26): Termius

2. **Scanner-style app на ДРУГОМ устройстве за тем же router-NAT**
   - Stream log на сервере показывает empty SNI (`ssl_preread_server_name=`) от user IP с большим объёмом
   - Это другое устройство (телефон друзей/сосед) с XZAP-подобным клиентом флудит
   - **Фикс**: Отключи второе устройство, или дай ему отдельный ключ через `manage_keys.py add` (тогда серверный логи разделятся по `User 'X' connected`)

3. **VpnService consent revoked**
   - `adb shell ip a | grep tun` показывает только `tunl0 DOWN` — нет нашего `tun0`
   - establish() вернул null после reboot phone
   - **Фикс**: Settings → Apps → XZAP → Force Stop → Open → Connect → Allow VPN dialog
   - **Кодовый фикс уже применён** (commit e696f4d): retry establish() ×3 с 300ms задержкой

4. **Megafon DPI temporarily blackholing**
   - Pool dial fails с `uTLS handshake: read tcp4 ... i/o timeout`
   - Длится 30-90с, потом восстанавливается
   - **Фикс**: подождать. Если затягивается — toggle airplane mode (получить новый CGNAT IP)

### «Cold-start 3-4 минуты»

- **Phone reboot recently** + new APK install: первые 1-3 мин tun2socks/Pool warmup. Это норма.
- **Scanner app** забивает пул — см. выше
- **Другое устройство со старым APK** на том же WiFi → NAT collision — отключить
- **Server connect_target таймаут 10с** на dead IP (фикс был commit 2b4f607: уменьшено до 3с)

### «Сайт не открывается, висит загрузка»

Если конкретный сайт (а не все):

- **Target IP unreachable from server**: проверь `journalctl -u xzap.service | grep "CONNECT_FAILED"`. Некоторые IP (старые Google CDN, отозванные)  не достижимы с польского хостинга.
- **DNS race**: app кеширует старый IP. Очисти cache в Chrome или подожди.

Если ВСЕ сайты — это другое (см. первый раздел).

### «Стрим YouTube периодически висит»

- Force-close streams на retire'е тоннелей. Если RetireGrace был коротким — обрывает YouTube chunks.
- **Текущий RetireGrace 60с** (после reverts) — должен покрывать большинство случаев.
- Если затягивается — Megafon DPI делает packet drop на active flow. Phase D3 chaff помогает шатать pattern.

### «adb logcat пустой»

- `-b crash` буфер показывает только crashes. Используй `-b main` для обычных логов.
- `--pid=$(adb shell pidof -s com.xzap.client)` падает если pidof empty — значит app не запущен.
- **Команда для логов**:
  ```powershell
  & "$env:LOCALAPPDATA\Android\sdk\platform-tools\adb.exe" logcat -b main -T 1000 \
    --pid=$(& "$env:LOCALAPPDATA\Android\sdk\platform-tools\adb.exe" shell pidof -s com.xzap.client) \
    > "$env:USERPROFILE\Desktop\xzap_main.log"
  ```

### «ssh-add показывает ключ, ssh всё равно просит passphrase»

- Если используешь `ssh -i ~/.ssh/key` с **флагом `-i`** — ssh читает файл напрямую, минуя агента → требует passphrase.
- **Фикс**: убери `-i` (агент даст ключ автоматом), или используй `~/.ssh/config`:
  ```
  Host sweden
    HostName 202.155.11.110
    User root
  ```
  Потом `ssh sweden` без пароля.

### «git pull на сервере fails: cannot pull with rebase: You have unstaged changes»

- На production сервере `keys.json` модифицируется локально (`manage_keys.py add`), и git считает его dirty.
- **Pattern**:
  ```bash
  git stash push keys.json
  git pull --rebase
  git stash pop
  ```

## Lessons learned (что пробовали и отменили)

### Phase A: Aggressive tunnel rotation (MaxAge 60с)

**Hypothesis**: уменьшим connection lifetime до 60с — будет ближе к browser pattern (0.5-32s), DPI меньше флагает.

**Что произошло**:
- Force-close 7 раз/5мин обрывал streams (YouTube chunks, WebSocket)
- Pool churn: 18 tunnel EXIT/тест vs 0 без rotation
- Когда RetireGrace подняли до 120с (чтобы избежать force-close) — connection lifetime вернулся к старым ~200с (выигрыш обнулился)
- UX subjectively хуже: «не все сайты, висы 5 мин»

**Reverted**: commit a0ea7e7. MaxAge снова 10мин.

**Lesson**: rotation сама по себе не решает DPI-фингерпринтинг. Нужен реальный traffic shaper, не просто короче connections.

### Phase D2: Light chaff (12% × 140-700B)

**Hypothesis**: добавим chaff, изменим byte-pattern, DPI запутается.

**Что произошло**: A/B comparison показал **identical** packet sizes, in/out ratio. 1.2% byte overhead был ниже detection threshold.

**Reverted**: commit 5d7c693.

**Lesson**: theatre-level changes невидимы. Если не видно в pcap measurement — DPI тоже не увидит.

### Phase D: Drain amplification

**Hypothesis**: Split bulk write на 2-3 chunks, каждый отдельный TLS record для variability.

**Что произошло**: throughput упал в 3 раза. Каждый `await drain()` ждёт TCP-ACK от клиента → 3× RTT cost per write.

**Reverted**: commit 396eb91.

**Lesson**: На asyncio один drain в конце write — обязательное правило. Multiple drains = latency amplification.

### Client D3 mirror full strength (chaff 35%, 800-4000B)

**Hypothesis**: симметричный chaff в обе стороны.

**Что произошло**: TIMEOUTs ×28 (с 48 до 1363), RTT p90 6× медленнее. Megafon uplink 1-3 Mbps не вытягивает 20-50% chaff overhead.

**Reverted**: было commit 1e03b43.

**Lesson**: client-side chaff должен быть **bandwidth-proportional**, не fixed bytes. В Phase D3-proportional (commit b2707e2) chaff = `payload × 3-10%` — bandwidth-invariant by construction.

### Single SNI = direct.solar-cloud.xyz with matching LE cert

**Hypothesis**: один SNI совпадающий с реальным IP/cert — DPI не флагает mismatch.

**Что произошло**: Megafon DPI всё равно режет (specific signature on direct.solar-cloud.xyz?). Browser показывает "no internet". Откатили на bypass.txt rotation — заработало.

**Reverted**: commit e27f142.

**Lesson**: на Megafon SNI=vk.com/ya.ru с self-signed cert (mismatch) работает **лучше**, чем «честный» single SNI с matching cert. Counter-intuitive but empirical.

### TCP Fast Open (TFO=3)

**Hypothesis**: TFO ускоряет TCP handshake на 1 RTT.

**Что произошло**: Russian middleboxes (Megafon, возможно Инфолада) дропают пакеты с TFO cookies — нестандартное поле в TCP-header.

**Reverted**: TFO выключен на Warsaw (sysctl), теперь default state на новых серверах.

**Lesson**: для Russian carriers — стандартный TCP only.

### BBR congestion control

**Hypothesis**: BBR быстрее cubic на потерянных линках (Megafon).

**Что произошло**: некоторые Google/AWS IP стали недостижимы (TCP probe failed, hence 90 CONNECT_FAILED/тест).

**Reverted**: вернули cubic.

**Lesson**: на маршрутах с обилием middleboxes BBR может ломать peering. Стандартный cubic надёжнее.

## Diagnostic commands cheatsheet

### Сервер: текущая активность

```bash
# Сколько подключений по юзерам
journalctl -u xzap.service --since "5 minutes ago" --no-pager \
  | grep "User .vitaly" | grep -oE "User .[^.]*. connected" | sort | uniq -c

# Top failing destinations
journalctl -u xzap.service --since "5 minutes ago" --no-pager \
  | grep CONNECT_FAILED | grep -oE "[0-9.]+:[0-9]+" | sort | uniq -c | sort -rn | head -10

# SNI routing breakdown
tail -200 /var/log/nginx/stream.log | awk '{print $5}' | sort | uniq -c | sort -rn
```

### Клиент: парсинг logcat

```bash
# Расшифровать UTF-16 (Windows logcat через PowerShell иногда так пишет)
iconv -f UTF-16 -t UTF-8 xzap_debug.txt > xzap_debug_utf8.txt

# Pool config (видно при cold-start)
grep "pool cfg:" xzap_debug_utf8.txt

# Stream RTT distribution
grep "ACK ok=true" xzap_debug_utf8.txt | grep -oE "rtt=[0-9.]+(ms|s)" | sort
```

### Pcap A/B-замер

```bash
# Capture на сервере
tcpdump -i eth0 -s 0 -w /tmp/cap.pcap "tcp port 443"
# (5-7 минут пользовательской активности)
pkill tcpdump

# Filter to user IP
tcpdump -r /tmp/cap.pcap -w /tmp/user.pcap "host $USER_IP"

# Stats
tshark -r /tmp/user.pcap -q -z conv,tcp | head -20

# Python detailed analysis (см. /tmp/analyze.py пример в ops docs)
```

## Memory artefacts

Сохранённые отдельно lessons (`~/.claude/projects/-root-xzapret/memory/`):

- `feedback_scanner_apps.md` — Termius/SSH-клиенты убивают мукс-пул, сразу проверяй установленные apps.
