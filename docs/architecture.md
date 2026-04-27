# Архитектура XZAP

Многослойная архитектура: каждый слой решает одну задачу. Ниже — слои сверху вниз (от приложения до железа), потом потоки данных, sequence diagrams для ключевых сценариев.

## Слои (verbose)

```
┌──────────────────────────────────────────────────────────────────┐
│                  Android applications                            │
│                  (Chrome, YouTube, Telegram, ...)                │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ TCP packets (any)
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  XzapVpnService (Kotlin)                         │
│   • VpnService.Builder.establish() — создаёт tun0 интерфейс      │
│   • addRoute("0.0.0.0", 0) — все TCP идут в tun                  │
│   • addDisallowedApplication(BYPASS_APPS) — банки/маркетплейсы   │
│     минуют VPN полностью (ru.sberbankmobile, ru.tinkoff, ...)    │
│   • excludeRoute(RFC1918, multicast) — LAN не туннелируется      │
│   • foreground notification + retry establish() x3               │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ tun fd (file descriptor)
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  tun2socks (Go, в составе AAR)                   │
│   • Читает IP-пакеты из tun fd                                   │
│   • Эмулирует TCP state machine для каждой сессии                │
│   • Открывает SOCKS5 connection к 127.0.0.1:10808                │
│   • Bridge между app's TCP socket ↔ SOCKS5 stream                │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ SOCKS5 CONNECT host:port
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Go SOCKS5 server (core/go/socks5.go)            │
│   • Listen 127.0.0.1:10808                                       │
│   • На каждый CONNECT вызывает Pool.OpenStream(host, port)       │
│   • Pipe bytes между client TCP ↔ mux stream                     │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ mux Stream (bidirectional)
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Mux Pool (core/go/pool.go)                      │
│   • Maintains 6 mux tunnels (steady-state)                       │
│   • Round-robin dial across configured servers                   │
│   • Cold-path: 5s × 3 attempts, steady-path: 15s × 2             │
│   • Rotator: retire tunnels older than MaxAge=10min              │
│   • pick() returns least-loaded fresh tunnel                     │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ mux frame [4B sid][1B cmd][4B plen][payload]
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  XZAP tunnel frame (encrypted)                   │
│   [4B payload_len][16B random_prefix][12B nonce][ciphertext]     │
│   [16B GCM tag]                                                  │
│   • Plaintext: один или несколько mux frames + chaff             │
│   • AES-256-GCM с per-user key                                   │
│   • random_prefix добавляется на каждый фрейм (anti-replay)      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ XZAP frame bytes
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Fragmentation layer                             │
│   [4B total_len][1B flags][data]                                 │
│   • flags: 0x00 REAL / 0x01 CHAFF / 0x02 OVERLAP                 │
│   • Малые фреймы (≤150B) → 24-68B микро-фрагменты                │
│   • Bulk → один real fragment + опц. chaff (Phase D3)            │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ fragments
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  uTLS (Chrome 131 fingerprint)                   │
│   • TLS 1.3 ClientHello byte-identical to Chrome 131             │
│   • SNI = random pick from bypass.txt list (vk.com, ya.ru, ...)  │
│   • Server cert не валидируется (auth через AES key)             │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ TLS records
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                  TCP socket → Internet                           │
│   • Phone NAT → carrier (Megafon / Infolada / ...)               │
│   • DPI inspect along the way                                    │
│   • To: 202.155.11.110:443 (Sweden) or 151.244.111.186 (Warsaw)  │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                       ┌─────────────────────┐
                       │   nginx-stream :443 │
                       │   SNI router        │
                       └─────────┬───────────┘
                                 │ proxy_pass 127.0.0.1:9443
                                 ▼
                       ┌─────────────────────┐
                       │   xzap.service      │
                       │   (Python, port     │
                       │   9443, LE cert)    │
                       └─────────┬───────────┘
                                 │ Reverse stack: TLS → fragmentation → XZAP frame
                                 │ → mux frame → SYN(host,port)
                                 ▼
                       ┌─────────────────────┐
                       │   asyncio.open      │
                       │   _connection(host, │
                       │   port) → target    │
                       └─────────┬───────────┘
                                 │ pipe bytes
                                 ▼
                              [Internet]
```

## Pool design

Pool — главный state в клиенте. Поддерживает заданное количество живых mux-тоннелей, каждый из которых = одно TLS-соединение к серверу.

```
              Pool struct
              ┌─────────────────────────────────────┐
              │  items: [t1, t2, t3, t4, t5, t6]    │
              │  ready chan struct{}                │
              │  cfg.MaxTunnels = 6                 │
              │  cfg.MaxAge = 10min                 │
              │  cfg.RotateEvery = 30s              │
              └─────────────────────────────────────┘
                       ▲                   ▲
                       │                   │
              warmup goroutine     rotator goroutine
              (создаёт init pool)  (тикает каждые 30с,
                                    retire old, spawn new)

Lifecycle одного тоннеля:
  ┌───────┐    ┌──────┐    ┌──────────┐    ┌────────┐    ┌───────┐
  │ DIAL  │───→│ MUX  │───→│  ACTIVE  │───→│RETIRING│───→│ CLOSE │
  │ TLS   │    │ HSK  │    │(< MaxAge)│    │(grace) │    │       │
  └───────┘    └──────┘    └──────────┘    └────────┘    └───────┘
   ~200ms      ~200ms       up to MaxAge   up to 60s
   (Sweden)    (1 RTT)      ~10 min        wait streams
                                            drain
```

### Round-robin multi-server

При `ServerHost = "202.155.11.110,151.244.111.186"` pool dialer ротирует:

```
Tunnel 1 → 202.155.11.110:443  (Sweden)
Tunnel 2 → 151.244.111.186:443 (Warsaw)
Tunnel 3 → 202.155.11.110:443
Tunnel 4 → 151.244.111.186:443
Tunnel 5 → 202.155.11.110:443
Tunnel 6 → 151.244.111.186:443

Steady state: ~3 на каждом сервере. Rotator каждые 30с retire'ит
один из самых старых, заменяет — round-robin продолжается.

Если сервер 1 недоступен → createOne fail → попытка на нём
повторится (cold-path: 5s × 3 = ~15s) → выбирает next в rotation.
```

## Sequence: cold-start

```
Phone reboot. User taps Connect.

┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Phone    │  │ tun2socks│  │ SOCKS5   │  │ Pool     │  │ Server   │
│ Chrome   │  │          │  │          │  │          │  │ Sweden   │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │              │              │              │
     │             │              │  Start()     │              │
     │             │              │   ────────→  │              │
     │             │              │              │ warmup:      │
     │             │              │              │  createOne() │
     │             │              │              │ ─────TLS────→│
     │             │              │              │ ←──TLS ACK──│
     │             │              │              │ mux SYN     │
     │             │              │              │ ─────────→ │
     │             │              │              │ ←─────────── SYN_ACK
     │             │              │              │ ↓            │
     │             │              │              │ READY ✓      │
     │             │              │              │ (ready chan  │
     │             │              │              │  closed)     │
     │             │              │              │              │
     │ HTTP GET    │              │              │              │
     │ vk.com:443  │              │              │              │
     │  ─────────→│              │              │              │
     │             │ SOCKS5       │              │              │
     │             │ CONNECT      │              │              │
     │             │  ──────────→│              │              │
     │             │              │ OpenStream  │              │
     │             │              │  ─────────→ │              │
     │             │              │              │ pick()       │
     │             │              │              │ → tunnel 1   │
     │             │              │              │ mux SYN sid=1│
     │             │              │              │ → vk.com:443 │
     │             │              │              │ ──────────→ │
     │             │              │              │ ←─SYN_ACK── │
     │             │              │              │ stream open  │
     │             │              │ ←──── ok ────│              │
     │             │ ←── data ────│              │              │
     │ ← html ────│              │              │              │
     │             │              │              │              │
   end-to-end: ~200-500ms на хорошей сети, до 25s на плохой Megafon
```

## Sequence: stream open detail

```
Client                                            Server
   │                                                 │
   │ 1. encrypt({"v":"mux1"}) + frame + TLS write    │
   │  ───────────────────────────────────────────→  │
   │                                                 │ recv frame, decrypt
   │                                                 │ "mux1" → mux mode
   │                                                 │ encrypt({"v":"mux1"})
   │ ←───────────────────────────────────────────── │
   │ "mux1" → mux ready                              │
   │                                                 │
   │ 2. mux SYN sid=N {"host":"vk.com","port":443}   │
   │  ───────────────────────────────────────────→  │
   │                                                 │ asyncio.open_connection(
   │                                                 │   "vk.com", 443) timeout=3s
   │                                                 │ ← TCP connect OK in Xms
   │                                                 │ sid → MuxStream object
   │ ←─── mux SYN_ACK sid=N (plen=0) ────────────── │
   │                                                 │
   │ 3. (parallel) bidirectional data flow           │
   │ mux DATA sid=N <TLS ClientHello to vk.com>      │
   │  ───────────────────────────────────────────→  │
   │                                                 │ writer.write(data)
   │                                                 │ → vk.com socket
   │                                                 │ ←── ServerHello
   │ ←─── mux DATA sid=N <ServerHello+...> ──────── │
   │                                                 │
   │ ...flow continues until app closes connection...│
   │                                                 │
   │ mux FIN sid=N (plen=0)                          │
   │  ───────────────────────────────────────────→  │
   │                                                 │ stream.close()
   │                                                 │ remove from streams[]
```

## Phase D3 chaff structure

Server-side (xzap/transport/fragmented.py):

```
async def write(data):
    if len(data) ≤ 150:
        # Малое — микро-фрагментировать на 24-68B куски
        # (без chaff на этом пути)
        await write_fragmented(data)
        return

    # Bulk path
    buf = pack_fragment(data, FLAG_REAL)

    # 35% шанс добавить 1-3 chaff фрагмента 800-4000B
    if random() < 0.35:
        for i in range(randint(1, 3)):
            chaff = os.urandom(randint(800, 4000))
            buf += pack_fragment(chaff, FLAG_CHAFF)

    writer.write(buf)        # ОДИН TCP write
    await writer.drain()     # ОДИН drain — нет latency amplification
```

Client-side (core/go/transport/fragmented.go) — **proportional**:

```
func Write(p):
    if len(p) ≤ 150:
        return writeFragmented(p)  # без chaff

    buf := append(buf, packFragment(p, FLAG_REAL))

    # 40% шанс добавить 1 chaff фрагмент пропорциональный размеру
    if random() < 0.40:
        chaffPct := uniform(0.03, 0.10)        # 3-10% от размера
        size := clamp(int(len(p)*chaffPct), 64, 2048)
        chaff := os.urandom(size)
        buf := append(buf, packFragment(chaff, FLAG_CHAFF))

    Conn.Write(buf)            # ОДИН Write
```

Почему **proportional** в клиенте: Megafon uplink 1-3 Mbps. Fixed-size chaff
800-4000B на каждый небольшой HTTP-GET = 20-50% overhead → cascade timeouts.
Proportional = ~3-10% всегда → bandwidth-invariant.

## Wire-pattern shaping (что видит DPI)

До D3 chaff:
```
Time→
TCP: ████████████████████ ░ ████████████████ ░ ████████████
     Equal-sized packets, regular timing — characteristic of tunnel
```

С D3 chaff:
```
Time→
TCP: ███████ ▓▓ █████████████ ▓▓▓ ██████████ ▓ █████████████
     ▓ = chaff bytes mixed in. Размеры пакетов варьируются,
     in/out ratio shifts toward browser pattern (downloads dominant).
```

## Multi-user keystore

При TLS connect клиент шлёт **первый зашифрованный фрейм** = mux version handshake (`{"v":"mux1"}`). Сервер **пробует каждый ключ** для дешифровки:

```
KeyStore.identify(encrypted_frame):
    for username, key in users:
        try:
            crypto = Crypto(key)
            plaintext = crypto.decrypt(encrypted_frame[16:])
            json.loads(plaintext)   # парсится → ключ правильный
            return crypto, username
        except:
            continue
    return None, None  # ни один ключ не подошёл
```

При ~3 ключах — overhead minimal (3 × AES-GCM decrypt + JSON parse попытки на новый TLS-connect, ≈300μs). Идентификация позволяет:
- Логировать активность по `User 'vitaly_main' connected`
- Per-user policies (можно расширить — bandwidth limits, deny lists)
- Лёгкий ban: удалить ключ из `keys.json`, restart, юзер мгновенно потерял доступ

## DPI evasion strategy

Слои защиты в порядке от поверхностной до глубокой:

| Слой | Что прячет | Зачем |
|---|---|---|
| **uTLS Chrome131 fingerprint** | TLS ClientHello sig (JA3) | DPI на JA3-fingerprint thinks it's Chrome |
| **SNI rotation (bypass.txt)** | Имя домена в TLS handshake | DPI видит «vk.com», не флагает |
| **Cert не валидируется** | Несоответствие cert ↔ SNI | Server отдаёт LE cert для своего домена, мисматч с SNI клиент игнорирует |
| **AES-256-GCM** | Внутренние данные | Брутфорс невозможен |
| **Random prefix 16B** | Pattern в зашифрованных bytes | Anti-replay + рандомизация first bytes |
| **Fragmentation 24-68B** | TCP-уровень byte distribution | Малые фреймы выглядят как DNS/control |
| **Phase D3 chaff** | Total bytes/sec, in/out ratio | Меньше «equal upload+download» tunnel signature |
| **Multi-server** | Single-IP traffic concentration | Per-IP DPI suspicion разделяется надвое |
| **bypass.txt routing** (TODO) | Domain whitelist | Прямые сайты на тоннель не нагружаются |

## Что НЕ закрыто

- **Connection lifetime**: 175-560s vs browser 0.5-32s. Если DPI делает корреляцию по времени — мы отличимы. Phase A (rotation) пробовали, ломалось UX.
- **Single TLS flow с большим upload**: один tunnel может нести 20MB одновременно. Browser — много коротких. Архитектурное.
- **Asymmetry**: мы примерно симметричны in/out, browser имеет ratio 3.20+ (downloads >> uploads). D3 чуть-чуть сдвигает.
- **TLS-record control**: Python ssl-уровень не даёт прямого контроля размера TLS records. Низкоуровневая работа.

Это всё закроется только полным **traffic shaper** в Phase D++ (мес. работы) или сменой транспорта на UDP/QUIC.
