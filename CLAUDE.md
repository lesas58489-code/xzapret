# XZAPRET — Project Notes for Claude

## Overview

XZAP — кастомный anti-DPI протокол для обхода блокировок в России.
Не форк Xray/VLESS/MTProto. Самостоятельный протокол. Сегодня основной
клиент — Android (Go core через AAR), сервер — Python.

**Repo:** `https://github.com/lesas58489-code/xzapret.git`

---

## Servers

| Сервер | IP | Роль | SSH |
|--------|----|------|-----|
| **Warsaw** | `151.244.111.186` | **Основной production** (xzap, nginx-stream, LE cert) | `ssh -i ~/.ssh/warsaw root@151.244.111.186` (с Tokyo) |
| **Tokyo** | `151.245.104.38` | Dev машина (компилирует AAR), xzap-сервер dormant | текущий sshd для Claude |

**Текущее на Warsaw** (`apr 26 2026`):
- nginx-stream `:443` — SNI router → 127.0.0.1:9443 (xzap) или 4443 (CF-WS, реликт)
- nginx :80 — раздаёт `/var/www/html/xzap.apk` (свежий APK для скачивания на телефон)
- nginx :8888 — `python3 -m http.server` для приёма APK от Windows билдера
- xzap.service на 127.0.0.1:9443 с **Let's Encrypt cert** для `direct.solar-cloud.xyz`
- xzap-ws.service на 127.0.0.1:8080 — WS вариант (CF-fronted, не используется в основном пути)
- BBR отключён (cubic), TFO=0 (Russian middleboxes ломают TFO)

**Tokyo** сейчас идле — xzap.service / xzap-ws.service inactive. Запущен только
xray на :443 (decoy/тест). Если понадобится — есть git, gomobile, NDK для сборки AAR.

---

## Architecture (актуально)

```
[Phone app] ──tun2socks──→ [Go SOCKS5 :10808] ──MUX──→ [XZAP frame] ──TLS──→
                                                            ↓
                                                     [nginx-stream :443]
                                                            ↓ SNI route
                                                    [127.0.0.1:9443 xzap.service]
                                                            ↓
                                                     [keystore.identify by AES key]
                                                            ↓
                                                    [mux session per TLS conn]
                                                            ↓
                                                    [target host:port] ← internet
```

**Слои на проводе (изнутри наружу):**

1. **Mux frame** — `[4B sid][1B cmd][4B plen][payload]`. cmd: SYN/SYN_ACK/DATA/FIN/RST/PING/PONG/WINDOW.
2. **XZAP tunnel frame** — `[4B len][16B random_prefix][12B nonce][AES-256-GCM ciphertext][16B GCM tag]`.
3. **Fragmentation layer** — `[4B total_len][1B flags][data]`. flags: REAL/CHAFF/OVERLAP. Смягчает паттерны.
4. **TLS** (uTLS Chrome 131 fingerprint) с SNI из `lists/bypass.txt` (rotation).
5. **TCP** к Warsaw:443.

**Phase D3 chaff** (active 2026-04-26):
- Server-side (`xzap/transport/fragmented.py`): 35% bulk writes получают 1-3 chaff-фрагмента 800-4000B. ~20% download bandwidth tax. Browser-friendly.
- Client-side Go (`core/go/transport/fragmented.go`): 40% bulk writes получают 1 chaff size = `payload × 3-10%` (proportional). Floor 64B, ceiling 2048B. ~3-7% upload tax. Bandwidth-invariant.

---

## Server (Warsaw)

### Systemd units
```
/etc/systemd/system/xzap.service
ExecStart=/usr/bin/python3 run_server.py --host 127.0.0.1 --port 9443 --tls \
  --cert /etc/letsencrypt/live/direct.solar-cloud.xyz/fullchain.pem \
  --tls-key /etc/letsencrypt/live/direct.solar-cloud.xyz/privkey.pem
LimitNOFILE=524288, LimitNPROC=65536
```

### Commands
```bash
systemctl status xzap.service
systemctl restart xzap.service
journalctl -u xzap.service -f                    # live
journalctl -u xzap.service --since "5 minutes ago" --no-pager | grep "User .*. connected"
tail -f /var/log/nginx/stream.log                # SNI routing trace
```

### nginx config
- `/etc/nginx/stream-xzap.conf` — SNI router на :443 (включается через `include` в nginx.conf)
- Мап: `direct.solar-cloud.xyz` → 9443. Bypass-list domains (`vk.com`, `ya.ru`, ...) тоже → 9443. CF apex → 4443. Default → 9443.
- `/etc/nginx/sites-enabled/xzap` — CF WS-фасад на 4443 (для `solar-cloud.xyz` через CF edge).

### Sysctl persistence
`/etc/sysctl.d/99-xzap-relay.conf`:
- `tcp_congestion_control = cubic` (BBR пробовали — Russian middleboxes плохо)
- `tcp_fastopen = 0` (Russian middleboxes ломают TFO cookies)
- `rmem_max / wmem_max = 16MB`
- `tcp_max_syn_backlog = 4096`
- `ip_local_port_range = 1024 65535`

### Key management (`keys.json`)
```json
{
  "users": {
    "vitaly":      "3lk041pKJjzXvnxtQWbGaMeP4F8xGcY4hDPEWryTbkc=",  // legacy / друзья
    "vitaly_main": "HR9xOxIYd5p8rdLCM0sw+a4qwP8bPQuwEa29yCrXjFY="  // основной телефон
  }
}
```
Сервер пробует каждый ключ для дешифровки первого XZAP-фрейма — так идентифицирует пользователя. В логах: `User 'vitaly_main' connected from ...`.

```bash
cd /root/xzapret
python3 manage_keys.py add username
# выведет base64 — ввести в поле Key на телефоне
```

**`keys.json` локально не в git** — каждый сервер свой набор. На Warsaw модифицирован относительно git, при `git pull` нужен stash/pop.

### TLS
- **LE cert** для `direct.solar-cloud.xyz` (auto-renew через certbot.timer, нужен открытый :80)
- Self-signed для других SNI — клиент `InsecureSkipVerify: true` (валидация через AES-key)
- DNS: `direct.solar-cloud.xyz` A-record → 151.244.111.186 (Porkbun NS, не CF)

---

## Wire Protocol (детали)

### Mux frame (внутри XZAP-frame)
```
[4B sid][1B cmd][4B plen][payload]
  cmd:
    0x01 SYN      — open stream, payload = JSON {"host":"...","port":N}
    0x02 SYN_ACK
    0x03 DATA
    0x04 FIN
    0x05 RST
    0x06 PING
    0x07 PONG
    0x08 WINDOW   — flow control credit (4B BE delta)
```

### Mux version handshake
```
Client → Server: XZAP frame plaintext = {"v":"mux1"}
Server → Client: same
```

После этого — мукс-фреймы поверх одного TLS.

### XZAP tunnel frame
```
[4B payload_len][16B random_prefix][12B nonce][ciphertext][16B GCM tag]
```

### Fragmentation layer (over TLS)
```
[4B total_len][1B flags][data]
  flags:
    0x00 REAL
    0x01 CHAFF (drop)
    0x02 OVERLAP (cut overlap_size from start)
```

Малые фреймы (≤150B) дробятся на 24-68B куски. Большие — bulk + опциональный chaff (Phase D3).

---

## SNI Domains

**Источник: `lists/bypass.txt`** — российские сайты, которые российский DPI **не блокирует** независимо от destination IP. Это важно: foreign CDN-домены (CloudFlare, Microsoft, Apple) на Megafon наоборот **триггерят** DPI.

Список:
```
vk.com, ok.ru, yandex.ru, yandex.net, mail.ru, rambler.ru,
avito.ru, sberbank.ru, gosuslugi.ru, mos.ru, rbc.ru, lenta.ru,
ria.ru, rt.com, tinkoff.ru, ozon.ru, wildberries.ru,
kinopoisk.ru, 2gis.ru, dzen.ru
```

Зеркалится в:
- `xzap/tls.py` (Python клиент/сервер)
- `core/go/client.go` `whiteSNIs` (Android Go core)
- `/etc/nginx/stream-xzap.conf` map (Warsaw, для роутинга)

**Также используется** `direct.solar-cloud.xyz` — наш собственный домен с LE cert. Mismatch-cert в bypass.txt SNIs работает (клиент игнорирует), но идеологически чище был бы single SNI = direct.solar-cloud.xyz. Эксперимент `815f3e5` показал — Megafon DPI **режет** single-SNI с matching cert (наблюдательный паттерн известен), а bypass.txt rotation проходит. Так что текущая стратегия — bypass.txt rotation как primary.

---

## Clients

### Android (`clients/android/`) — основной

**Стек (актуально):**
```
[App] → tun2socks (Go) → SOCKS5 :10808 (Go core) → mux → XZAP frame → uTLS → Warsaw
```

Старый Kotlin `XzapSocksProxy.kt` УДАЛЁН (commit 4f88e9c, апрель 2026).
Весь клиент теперь — Go-библиотека `core/go/`, скомпилированная в AAR через gomobile bind.

**Ключевые файлы:**
| Файл | Роль |
|------|------|
| `clients/android/app/src/main/java/com/xzap/client/XzapVpnService.kt` | VPN entrypoint, запускает Go core + tun2socks |
| `clients/android/app/src/main/java/com/xzap/client/MainActivity.kt` | UI: Server / Port / Key |
| `clients/android/app/libs/xzapcore.aar` | Go core (uTLS + mux + tun2socks в одной AAR) |
| `core/go/client.go` | Client config, makeDialer, whiteSNIs |
| `core/go/pool.go` | Pool of mux tunnels with rotation |
| `core/go/mux.go` | Mux protocol implementation |
| `core/go/socks5.go` | Local SOCKS5 server :10808 |
| `core/go/transport/tls.go` | uTLS dialer with random Chrome131 fingerprint |
| `core/go/transport/fragmented.go` | Fragmentation + Phase D3 client chaff |
| `core/go/mobile/android.go` | Bridge for gomobile bind |
| `clients/android/build_xzapcore.sh` | gomobile bind скрипт (запускается на Linux/Tokyo, не Windows) |

**Pool config (`core/go/pool.go` DefaultPoolConfig):**
- MaxTunnels: 6
- MaxAge: 10 минут (аггрессивная ротация ломает throughput, не помогает DPI)
- RetireGrace: 60с (graceful drain streams перед force-close)
- RotateEvery: 30с тики
- WarmupDelay: 2 минуты (rotator dormant до этого)
- StreamDialTO: 10с (на каждый stream open)

**Важные правки:**
- `pick() spawns ≤ 1 background dial` (commit 84f19df) — burst dials триггерили DPI flag.
- Cold-path 5с×3 attempts + 0.5с backoff (vs steady-state 15с×2). При первом тоннеле быстрый retry.
- `excludeRoute()` для RFC1918 + multicast (commit f6d8695, Android 13+) — LAN traffic не идёт в тоннель.

**Параметры подключения (UI):**
- Server: `151.244.111.186`
- Port: `443` (раньше было 8443; теперь :443 → nginx-stream → :9443 xzap)
- Key: см. keys.json

**Bypass apps (split tunnel — без VPN):**
Российские apps (vk, sberbank, gosuslugi и т.д.) + MIUI/GMS системные сервисы. Список в `XzapVpnService.kt` `BYPASS_APPS`.

### Сборка APK на Windows

1. **Скачать AAR** с Warsaw: `scp root@warsaw:/tmp/xzapcore.aar C:\Users\sokolov\xzapret\xzapret\clients\android\app\libs\xzapcore.aar`
2. Android Studio → Build → Clean Project → Rebuild → Build APK
3. APK: `app/build/outputs/apk/debug/app-debug.apk`
4. **Загрузить на сервер** для установки на телефон: `scp app-debug.apk root@warsaw:/tmp/xzap.apk`
5. На сервере: `cp /tmp/xzap.apk /var/www/html/xzap.apk` (для скачивания через nginx :80)
6. На телефоне Chrome → `http://151.244.111.186/xzap.apk` → установить

### Сборка AAR на Tokyo

```bash
cd /root/xzapret
export ANDROID_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
export PATH="$PATH:/root/go/bin"
gomobile bind -target=android -androidapi 24 -ldflags="-s -w" \
  -o clients/android/app/libs/xzapcore.aar ./mobile
# Затем scp на Warsaw в /tmp/xzapcore.aar
```

### Windows клиент (`clients/windows/`) — legacy

`xzap_client.pyw` — tkinter GUI, SOCKS5 на 1080. Сейчас **не на основной разработке**.

---

## Diagnostic logs (Phase C)

**Client (Go) каждый stream open пишет:**
```
mux: stream=N ACK ok=true dest=host:port rtt=Xms tunAge=Ys streamsBefore=Z
mux: stream=N TIMEOUT dest=host:port waited=Xs ctx=deadline tunAge=Ys
```

**Server (Python) каждый mux SYN пишет:**
```
mux SYN sid=N host:port OK connect=Xms → SYN_ACK     # успех
mux SYN sid=N host:port CONNECT_FAILED dt=Xms → RST   # target unreachable
```

**Pool decisions (rotator) каждые 30с:**
```
rotator: fresh=N retiring=N dead=N items=N, ...
pool: retiring tunnel age=... streams=...
```

Корреляция: для каждого client-side TIMEOUT можно найти server-side OK/FAILED по host:port. Отвечает на вопрос:
- **OK connect=2000ms** на сервере → SYN_ACK ушёл, потерялся в пути обратно → DPI?
- **CONNECT_FAILED dt=3000ms** → server не достучался до target (target dead или unreachable from Warsaw)
- **Нет записи на сервере** вовсе → SYN не дошёл от клиента

**Server-side connect_target timeout = 3с** (commit 2b4f607). Раньше 10с — фейлы на dead DNS забивали server-side capacity.

---

## CF-fronted WSS (альтернативный путь, не используется)

Раньше использовалось: `wss://solar-cloud.xyz/ws` через Cloudflare CDN. Cloudflare Free tier дропает long-lived WS бинарный трафик после 25+ попыток (проверено эмпирически). Платный CF Pro/Business не лучше — лимит на WS общий. Spectrum (Enterprise $$$) поддерживает raw TCP но не для нашего бюджета.

Сейчас CF-путь технически доступен (xzap-ws.service на :8080, nginx 4443 → CF), но не используется.

---

## ufw rules (Warsaw)

```
22/tcp        ALLOW Anywhere   # SSH
80/tcp        ALLOW Anywhere   # nginx (LE cert renewal + APK download)
443/tcp       ALLOW Anywhere   # main XZAP entry
8888/tcp      ALLOW Anywhere   # http.server для приёма APK от Windows (можно стянуть до Tolyatti IP)
2053/tcp      ALLOW Anywhere   # nginx CF WebSocket (legacy)
```

Default INPUT = DROP. Outbound = ACCEPT.

---

## Структура проекта

```
xzap/                       # Python протокол (сервер + Python клиент)
  client.py                 # XZAPClient
  tunnel.py                 # XZAPTunnelClient/Server
  mux.py                    # MuxServerSession (over XZAP frame)
  crypto.py                 # AES-256-GCM / ChaCha20
  fragmentation.py          # Fragment / FragmentBuffer (low-level)
  transport/
    fragmented.py           # FragmentedReader/Writer + D3 chaff (server-side)
    tcp.py                  # XZAPListener
    ws.py                   # WS transport
    ws_tunnel.py            # WS adapter
  tls.py                    # TLS + SNI rotation
  keystore.py               # Multi-user key storage
  socks5.py                 # SOCKS5Proxy (для Python клиента)

core/go/                    # Android client (compiles to AAR via gomobile)
  client.go                 # Client config, makeDialer, whiteSNIs
  pool.go                   # Pool of mux tunnels
  mux.go                    # Mux protocol
  socks5.go                 # Local SOCKS5
  frame.go                  # XZAP frame read/write
  crypto.go                 # AES-256-GCM
  transport/
    tls.go                  # uTLS dialer
    fragmented.go           # Fragmentation + D3-proportional chaff (client-side)
    ws.go                   # WS dialer (legacy)
  cmd/                      # CLI for Linux/macOS
  mobile/android.go         # gomobile bind entrypoint
  xzapcore.aar              # built artefact (gitignored)

clients/
  android/                  # Android VPN app (Kotlin shell + Go AAR)
  windows/                  # Windows tkinter client (legacy)
  ios/                      # (заготовка)
  macos/                    # (заготовка)

run_server.py               # Server runner (TCP / TLS / WS)
manage_keys.py              # CLI for keystore
keys.json                   # Per-server user keys (gitignored on Warsaw)
xzap.key                    # Legacy single-user key
xzap_cert.pem / .key        # Self-signed cert (legacy, fallback)
lists/
  bypass.txt                # Russian sites — used as SNI rotation list
  xzap.txt                  # Sites that go through XZAP (бывает не нужно — VPN всё прогоняет)
```

---

## Что было пробовано и **не** работает (lessons learned)

- **Single SNI=direct.solar-cloud.xyz** + matching LE cert: Megafon DPI флагает, тишина в браузере. Bypass.txt rotation работает.
- **Aggressive pool rotation** (MaxAge 60с): pool churn создаёт burst dials, RetireGrace 30с force-close streams (visible UX hangs). 120с grace убирает hangs но обнуляет lifetime-выигрыш. Откатано к 10мин MaxAge.
- **Phase D2 (light chaff 12%)**: незаметно на проводе (1.2% overhead — ниже detection порога). Убрано.
- **Phase D с многократным `await drain()`**: Throughput падает в 3 раза (drain ждёт TCP-ACK). Single-buffer single-drain работает.
- **Client D3 mirror full strength** (35%/2400B avg): на Megafon uplink (1-3 Mbps) ×28 timeouts. Proportional version (3-10% от payload) — норм.
- **TFO=3 (TCP Fast Open)**: middleboxes на Megafon дропают TCP с TFO cookies. Отключено.

---

## Полезные команды

### Перезапуск сервера после правок
```bash
ssh -i ~/.ssh/warsaw root@151.244.111.186
git -C /root/xzapret stash push keys.json
git -C /root/xzapret pull --rebase
git -C /root/xzapret stash pop
systemctl restart xzap.service
systemctl is-active xzap.service
```

### Live monitoring
```bash
journalctl -u xzap.service -f                       # все события
tail -f /var/log/nginx/stream.log                   # SNI routing
ss -tn state established '( sport = :443 )'         # active conns
```

### Capture pcap для анализа
```bash
tcpdump -i eth0 -s 0 -w /tmp/cap.pcap "tcp port 443"
# через 5-10 минут
pkill tcpdump
tcpdump -r /tmp/cap.pcap -w /tmp/user.pcap "host <user_IP>"
tshark -r /tmp/user.pcap -q -z conv,tcp | head
python3 /tmp/analyze.py    # есть скрипт со статистиками
```

### Деплой кода
```bash
# Tokyo (где разработка)
git -C /root/xzapret commit -am "..." && git -C /root/xzapret push

# Warsaw (production)
ssh -i ~/.ssh/warsaw root@151.244.111.186 \
  'git -C /root/xzapret stash push keys.json && \
   git -C /root/xzapret pull --rebase && \
   git -C /root/xzapret stash pop && \
   systemctl restart xzap.service'
```
