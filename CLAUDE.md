# XZAPRET — Project Notes for Claude

## Overview

XZAP — кастомный anti-DPI протокол для обхода блокировок в России.
Не форк Xray/VLESS/MTProto. Самостоятельный протокол.

**Repo:** `https://github.com/lesas58489-code/xzapret.git`
**Server dir:** `/root/xzapret` (Tokyo, `151.245.104.38`)

---

## Servers

| Сервер | IP | Роль | SSH |
|--------|----|------|-----|
| **Tokyo** | `151.245.104.38` | XZAP TLS сервер (:8443), git repo, systemd | `root@151.245.104.38` (текущий) |
| **Warsaw** | `151.244.111.186` | Резервный/тестовый сервер | `ssh -i ~/.ssh/warsaw root@151.244.111.186` |

Warsaw доступен с Tokyo: `ssh -i ~/.ssh/warsaw root@151.244.111.186`
Ключ: `~/.ssh/warsaw` (на Tokyo).

---

## Architecture

```
[Client SOCKS5 proxy]
       ↓
[XZAP fragmentation layer]   [4B len][1B flags][data chunks, 24-68B]
       ↓
[XZAP tunnel frame]          [4B len][16B random prefix][AES-256-GCM encrypted]
       ↓
[TLS transport]              SNI = white domain (cloudflare.com, microsoft.com, ...)
       ↓
[Server :8443 --tls]         Tokyo, self-signed cert, keys.json auth
       ↓
[Target host:port]           internet
```

---

## Server

### Systemd unit
```
/etc/systemd/system/xzap.service
ExecStart=/usr/bin/python3 run_server.py --port 8443 --tls
WorkingDirectory=/root/xzapret
```

### Commands
```bash
systemctl status xzap.service
systemctl restart xzap.service
journalctl -u xzap.service -f        # live logs
tail -f /var/log/xzap_server.log     # file log
```

### Key management (`keys.json`)
```json
{
  "users": {
    "vitaly": "3lk041pKJjzXvnxtQWbGaMeP4F8xGcY4hDPEWryTbkc="
  }
}
```
Сервер пробует каждый ключ для дешифровки первого фрейма — так идентифицирует пользователя.

Добавить нового пользователя:
```bash
cd /root/xzapret
python3 -c "from xzap.keystore import KeyStore; k=KeyStore(); print(k.add_user('newuser'))"
```

### TLS
- Self-signed cert: `xzap_cert.pem` / `xzap_tls_key.pem`
- Клиент НЕ верифицирует сертификат (проверка через AES-ключ)
- SNI masquerade: клиент шлёт SNI белого домена, сервер принимает любой

---

## Wire Protocol (детали)

### Fragmentation layer (внешний слой)
```
[4B total_len][1B flags][data]
  total_len = len(data) + 1   (включает байт flags)
  flags:
    0x00 = REAL
    0x01 = CHAFF  (получатель выбрасывает)
    0x02 = OVERLAP (получатель отрезает overlap_size байт с начала)
```

Мелкие пакеты (≤150B) фрагментируются на куски 24-68B.
Крупные пакеты — один bulk-фрагмент.

### XZAP tunnel frame (внутренний слой, после сборки фрагментов)
```
[4B payload_len][16B random_prefix][12B nonce][ciphertext][16B GCM tag]
  payload_len = 16 + 12 + len(ciphertext) + 16
```

### Handshake
```
Client → Server: encrypted {"cmd":"connect","host":"example.com","port":443}
Server → Client: encrypted {"ok":true}   OR   {"ok":false,"err":"..."}
Data phase: bidirectional encrypted+fragmented frames
```

---

## SNI Domains (белый список)

Домены в `xzap/tls.py` и `XzapSocksProxy.kt` должны совпадать:
```
www.cloudflare.com, cloudflare.com
www.microsoft.com, microsoft.com
www.apple.com, apple.com
www.amazon.com, amazon.com
cdn.jsdelivr.net, cdnjs.cloudflare.com
ajax.aspnetcdn.com, cdn.shopify.com
s3.amazonaws.com, fonts.gstatic.com
```

**НЕЛЬЗЯ использовать** YouTube, Google, Yandex, VK — DPI их блокирует
независимо от реального IP назначения.

---

## Clients

### Windows (`clients/windows/`)

**Файл:** `xzap_client.pyw` — GUI на tkinter, SOCKS5 прокси

**Сборка в .exe:**
```bat
cd C:\...\xzapret
pip install pyinstaller cryptography websockets aiohttp
clients\windows\build.bat
# Результат: dist\XZAP Client.exe
```

**Настройки:**
- Host: `151.245.104.38`
- Port: `8443`
- Key: `3lk041pKJjzXvnxtQWbGaMeP4F8xGcY4hDPEWryTbkc=`
- TLS: ✅ включён

**Работает:** несколько дней без ошибок. Chrome + YouTube через SOCKS5 127.0.0.1:1080.

### Android (`clients/android/`)

**Стек:** `XzapVpnService` → `tun2socks.aar` → SOCKS5 :10808 → `XzapSocksProxy` → XZAP TLS → сервер

**Ключевые файлы:**
| Файл | Роль |
|------|------|
| `XzapVpnService.kt` | VPN entrypoint, запускает прокси + tun2socks |
| `XzapSocksProxy.kt` | SOCKS5 сервер + XZAP TLS клиент (AES-256-GCM + фрагментация + SNI ротация) |
| `MuxConnection.kt` | WebSocket мультиплексор (альтернативный транспорт, не используется в VPN) |
| `TunForwarder.kt` | Кастомный TUN reader (альтернатива tun2socks, не используется) |
| `MainActivity.kt` | UI: поля Server / Port / Key (base64) |
| `libs/tun2socks.aar` | Go-библиотека: перехват IP-пакетов → SOCKS5 |

**Полный список функций Android клиента (`XzapSocksProxy.kt` + `XzapVpnService.kt`):**

| # | Функция | Реализация |
|---|---------|------------|
| 1 | VPN (весь трафик) | tun2socks Go engine + Android `VpnService` |
| 2 | AES-256-GCM шифрование | `javax.crypto` + `SecretKeySpec` (thread-local `Cipher`) |
| 3 | Random prefix 16B | `SecureRandom` на каждый фрейм |
| 4 | XZAP framing `[4B len][prefix][encrypted]` | `XzapSocksProxy.sendFrame` / `recvFrame` |
| 5 | Микро-фрагментация handshake (24–68 байт) | `writeMicroFragmented` (пакеты ≤150B) |
| 6 | Chaff detection (skip flag `0x01`) | `recvFrame` + `skip chaff` |
| 7 | TLS с SNI (маскировка под белые домены) | `SSLSocket` + `SNIHostName` |
| 8 | TLS session resumption | Shared `SSLContext` (Java default) |
| 9 | Connection pool (8 warm TLS) | `ConcurrentLinkedDeque` + background replenish |
| 10 | XZAP handshake CONNECT/OK | `openXzapTunnel` + JSON cmd/response |
| 11 | SOCKS5 proxy (localhost:10808) | `handleClient` + full SOCKS5 v5 protocol |
| 12 | Split Tunneling (bypass list) | `shouldBypass` + direct TCP pipe |
| 13 | Direct bypass (российские сайты) | HTTP/HTTPS direct → raw TCP pipe |
| 14 | IPv4/IPv6/Domain SOCKS5 addressing | ATYP `0x01`/`0x03`/`0x04` parsing |
| 15 | TCP_NODELAY | На каждом TLS соединении |
| 16 | SO_REUSEADDR | При bind SOCKS5 порта |
| 17 | Auto-disconnect cleanup | `onDestroy` / `onRevoke` → stop engine + proxy |
| 18 | Foreground notification | Persistent "Connected" notification |
| 19 | Settings persistence | `SharedPreferences` (server/port/key) |
| 20 | DNS over VPN | `8.8.8.8` + `1.1.1.1` через tun2socks |
| 21 | App self-exclusion | `addDisallowedApplication` (prevent loop) |

**Зависимости (`build.gradle.kts`):**
```kotlin
implementation(files("libs/tun2socks.aar"))
implementation("com.squareup.okhttp3:okhttp:4.12.0")
// androidx.core, appcompat, material — стандартные
```

**Параметры подключения (вводятся в UI):**
- Server: `151.245.104.38`
- Port: `8443`
- Key: `3lk041pKJjzXvnxtQWbGaMeP4F8xGcY4hDPEWryTbkc=`

**Bypass (через VPN без XZAP — российские сайты):**
vk.com, ok.ru, yandex.ru, mail.ru, avito.ru, sberbank.ru, tinkoff.ru,
ozon.ru, wildberries.ru, kinopoisk.ru, 2gis.ru, dzen.ru, gosuslugi.ru и т.д.

**Сборка APK на Windows:**
1. `git pull` в папке проекта
2. Android Studio → **File → Open** → выбрать `clients/android/`
3. Android Studio скачает Gradle и зависимости автоматически
4. **Build → Build Bundle(s) / APK(s) → Build APK(s)**
5. APK: `app/build/outputs/apk/debug/app-debug.apk`

**Требования:** Android Studio + Android SDK (уже установлены, сборки проходили раньше)

**Проблема с SSH (апрель 2026):** SSH-тоннель (`SshTunnel.kt` / JSch) не работал на Android —
Chrome и YouTube не открывались. DPI в России легко распознаёт SSH трафик на мобильных сетях.
Возврат на XZAP TLS решил проблему (совместимый протокол с Windows клиентом).

---

## MuxServer (Cloudflare WebSocket, альтернатива)

Второй транспорт — WebSocket через Cloudflare CDN (`wss://solar-cloud.xyz/`).

**Сервер:** `mux_server.py` (был `xzap-bridge.service`, остановлен 2026-04-12)
**Клиент (Python):** `mux_client.py --ws-url wss://solar-cloud.xyz/`
**Протокол:** `[4B stream_id][1B action][payload]` — OPEN/DATA/CLOSE

Преимущество: трафик идёт через Cloudflare CDN, заблокировать невозможно без блокировки всего CF.
Сейчас не используется (XZAP TLS достаточно, пока сервер не блокируют по IP).

---

## Структура проекта

```
xzap/                     # Python протокол (сервер + Python клиент)
  client.py               # XZAPClient — полный клиент с multi-path, adaptive
  tunnel.py               # XZAPTunnelClient/Server — handshake + pipe
  crypto.py               # AES-256-GCM / ChaCha20-Poly1305
  fragmentation.py        # Fragmenter / FragmentBuffer
  transport/
    fragmented.py         # FragmentedReader/Writer (wire format)
    tcp.py                # XZAPListener
    ws.py                 # WebSocket транспорт
  tls.py                  # TLS + SNI rotation
  keystore.py             # Multi-user key management
  socks5.py               # SOCKS5Proxy (asyncio)
  adaptive.py             # Adaptive obfuscation (уровни 0-3)

clients/
  android/                # Android VPN app (Kotlin)
  windows/                # Windows SOCKS5 proxy (Python + tkinter)
  ios/                    # (заготовка)
  macos/                  # (заготовка)

run_server.py             # Запуск сервера (TCP / TLS / WS)
mux_server.py             # WebSocket mux сервер (Cloudflare)
mux_client.py             # WebSocket mux клиент (Python, Windows/Linux)
manage_keys.py            # CLI управление ключами
keys.json                 # Пользовательские ключи
xzap.key                  # Legacy single-user ключ (32 bytes raw)
lists/
  bypass.txt              # Российские домены (прямое соединение)
  xzap.txt                # Домены через XZAP
```

---

## Добавить нового пользователя Android (другой телефон)

```bash
cd /root/xzapret
python3 manage_keys.py add username2
# Выводит base64-ключ → вводить в поле Key на телефоне
```

---

## Перезапуск сервера после изменений

```bash
cd /root/xzapret
git pull  # если правки с Windows/другого места
systemctl restart xzap.service
systemctl status xzap.service
```
