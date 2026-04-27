# Wire Protocol — байт-уровень

Все байты на каждом слое. Реальные hexdump'ы примеров. Это документ для тех кто пишет другую реализацию (iOS, Linux desktop, custom server) или хочет понять что именно идёт по проводу.

## Слои

```
[Mux frame ⊂ XZAP frame ⊂ Fragmentation ⊂ TLS ⊂ TCP]

App data → mux frames → packed in XZAP frame (encrypted) → wrapped in
fragments → written through TLS → sent over TCP.
```

Каждый слой добавляет header. Снизу вверх (как читает receiver):

| Слой | Header | Содержимое |
|---|---|---|
| TCP | 20+ B | стандарт, не описываем |
| TLS | record headers внутри | uTLS Chrome 131 fingerprint |
| Fragmentation | 5 B | `[4B total_len][1B flags]` |
| XZAP frame | 32 B | `[4B len][16B prefix][12B nonce][...][16B tag]` |
| Mux frame | 9 B | `[4B sid][1B cmd][4B plen]` |

## Layer 1: Fragmentation

### Wire format
```
Offset  Size  Field
0       4     total_len    big-endian uint32 (включает flags + data)
4       1     flags        bitfield
5       N     data         payload
```

`total_len = len(data) + 1`. Receiver читает первые 4 байта, потом ровно `total_len` байт следом.

### Flags
| Bit | Hex | Name | Receiver action |
|---|---|---|---|
| 0 | 0x00 | REAL | append `data` to accumulator |
| 0 | 0x01 | CHAFF | drop fragment |
| 1 | 0x02 | OVERLAP | strip first `overlap_size` bytes from `data` (used historically, now `overlap=0`) |

### Когда применяется
- Каждое исходящее application-payload идёт через `FragmentedWriter.write()`.
- Если payload `≤ 150 байт` → дробится на 24-68B микро-фрагменты, каждый — отдельный `[4B][1B][...]`.
- Если payload `> 150 байт` → один большой fragment + опц. chaff (Phase D3).

### Hexdump пример

Пакет 256 байт XZAP-данных, сервер добавляет chaff 1024 байта:

```
TCP segment payload (4 байта × 5 = 20 байт первых хедеров):

00000000  00 00 01 01  00  ee 8a c1 0c 25 e1 5b 32 ...   ← real fragment len=257, flag=00 REAL
            length     flag        XZAP frame bytes (256B)
00000105  00 00 04 01  01  d3 b1 9f 22 8a 7a 11 fe ...   ← chaff fragment len=1025, flag=01 CHAFF
            length     flag        random bytes (1024B)
00000506  ...
```

Receiver видит 2 fragments. Первый — flag=REAL, складывает 256 байт XZAP frame в buffer. Второй — flag=CHAFF, дропает.

Если оба ушли в одном TCP-segment (что часто бывает), это **видно DPI как один TCP-segment с переменным размером**. Без chaff было бы строго 261 байт; с chaff — 1290 байт.

## Layer 2: XZAP tunnel frame

### Wire format

```
Offset  Size  Field
0       4     payload_len   big-endian uint32
4       16    random_prefix per-frame nonce-like, anti-replay
20      12    aead_nonce    AES-GCM nonce
32      N     ciphertext    AES-256-GCM(plaintext)
32+N    16    aead_tag      GCM authentication tag

payload_len = 16 + 12 + N + 16 (полный размер от offset 4 до конца frame)
```

Total frame size = 4 + payload_len bytes.

### Encryption

```
key      = pre-shared 32-byte AES key (per-user)
plaintext = mux-frame bytes (см. Layer 3)
nonce    = random 12 bytes per frame (must not repeat)
aad      = none (NULL)

(ciphertext, tag) = AES-256-GCM-encrypt(key, nonce, plaintext, aad=NULL)
```

`random_prefix` — 16 байт случайных, **не используются** для дешифровки. Только для:
1. Затруднить pattern-matching на первый байт зашифрованных данных
2. Дать сложность DPI ML-классификатору отличить tunnel от random-bytes

### Hexdump пример

Plaintext = `{"v":"mux1"}` (12 bytes).

После шифровки (32 + 12 + 16 = 60 байт payload):
```
00000000  00 00 00 3c                           ← payload_len = 60
00000004  6a 8d 5f c2 91 4b 78 1a              ← random_prefix (16B)
          d3 ef 02 75 b1 88 e5 49
00000014  cc 7e 4a 91 b3 18 65 da              ← aead_nonce (12B)
          7f 21 88 a4
00000020  9a 4f c1 88 6e d3 27 b9              ← ciphertext (12B for 12B input)
          51 7a 28 cd
0000002c  3c 9b a1 ee 47 21 88 6f              ← aead_tag (16B)
          d2 5c b3 ee 91 88 27 c4
```

Receiver:
1. Читает 4 байта длины → 60
2. Читает 60 байт payload  
3. Skip prefix (offset 4-19)
4. Получает nonce (offset 20-31)
5. Получает ciphertext+tag (offset 32-end)
6. Decrypt с AES-key для этого юзера
7. Plaintext = `{"v":"mux1"}`

### Multi-user identification

При первом фрейме на новой TLS-connection сервер не знает кто юзер. **Стратегия: пробует каждый ключ из keystore**:

```python
def identify(encrypted_payload):
    nonce = encrypted_payload[16:28]
    ciphertext_and_tag = encrypted_payload[28:]
    for username, key in keystore.users.items():
        try:
            crypto = AESGCM(key)
            plaintext = crypto.decrypt(nonce, ciphertext_and_tag, None)
            json.loads(plaintext)  # верификация что валидный JSON
            return username, key
        except (InvalidTag, ValueError):
            continue
    return None, None  # не один ключ не подошёл
```

С 3-5 пользователями — overhead ~300μs на новый connect (3-5 × AES decrypt × short plaintext). Незначительно.

## Layer 3: Mux frame

### Wire format
```
Offset  Size  Field
0       4     stream_id     big-endian uint32 (0 = control)
4       1     cmd           команда (см. таблицу)
5       4     payload_len   big-endian uint32
9       N     payload       зависит от cmd
```

Total frame size = 9 + payload_len bytes. Hardcoded max payload = 256KB.

### Commands

| Hex | Name | Direction | Payload |
|---|---|---|---|
| 0x01 | SYN | client→server | JSON `{"host":"vk.com","port":443}` |
| 0x02 | SYN_ACK | server→client | empty |
| 0x03 | DATA | both | raw application bytes |
| 0x04 | FIN | both | empty |
| 0x05 | RST | both | optional reason string |
| 0x06 | PING | both (control sid=0) | empty |
| 0x07 | PONG | both (control sid=0) | empty |
| 0x08 | WINDOW | both | 4 bytes BE uint32 = additional credit |

### Special: stream_id = 0 (control stream)

Reserved для:
- Mux version handshake (`{"v":"mux1"}` SYN/SYN_ACK при первом frame в TLS connection)
- PING/PONG keepalive (каждые 10s, timeout 30s — если PONG не приходит, tunnel считается мёртвым)

### Stream lifecycle

```
Client:  SYN sid=N {"host":"X","port":Y}
Server:                                    ─→ asyncio.open_connection(X, Y)
                                              if success in 3s timeout:
Server:                                    ←─ SYN_ACK sid=N
                                              if fail:
Server:                                    ←─ RST sid=N "connect failed"

Client:  WINDOW sid=N delta=0 (bootstrap, начинает flow control)

Client:  DATA sid=N <bytes> ──┐
Server:                       ├──→ writer.write(<bytes>) → target
Server:  DATA sid=N <bytes> ←─┤
Client:                       └─── stream.OnData(<bytes>) → app

(loop until either side closes)

Client:  FIN sid=N
Server:                                    stream.close() target connection
                                           remove sid from streams[]
```

### Hexdump examples

**SYN to vk.com:443**
```
00 00 00 01    sid = 1
01             cmd = 0x01 SYN
00 00 00 22    payload_len = 34
{"host":"vk.com","port":443}     ← 34 bytes JSON
```

**SYN_ACK reply**
```
00 00 00 01    sid = 1
02             cmd = 0x02 SYN_ACK
00 00 00 00    payload_len = 0
(no payload)
```

**DATA: TLS ClientHello to vk.com (256 bytes hypothetical)**
```
00 00 00 01    sid = 1
03             cmd = 0x03 DATA
00 00 01 00    payload_len = 256
16 03 01 00 ... TLS ClientHello bytes ...
```

**WINDOW credit (1 KB)**
```
00 00 00 01    sid = 1
08             cmd = 0x08 WINDOW
00 00 00 04    payload_len = 4
00 00 04 00    delta = 1024 (bytes of buffer freed)
```

### Flow control

Each stream has:
- `sendWin` (atomic int32) — how many more bytes peer can send
- Initial = 256 KB
- Peer decreases on each DATA, replenishes via WINDOW frames

Receiver sends WINDOW(delta) after consuming `delta` bytes from local buffer:

```go
// Pseudocode (Go client)
func (s *muxStream) Read(p []byte) (int, error) {
    n := copy(p, rxBuf)
    rxBuf = rxBuf[n:]
    consumed.Add(int32(n))
    if total := consumed.Load(); total >= 64*1024 {
        consumed.Store(0)
        sendFrame(sid, WINDOW, encode_int32(total))
    }
    return n, nil
}
```

Это keeps server-side memory bounded — server не может flood'ить клиента.

## Handshake sequence (full session)

```
Client                                                       Server
  │                                                            │
  │── TCP SYN ──────────────────────────────────────────────→ │
  │←── TCP SYN+ACK ────────────────────────────────────────── │
  │── TCP ACK ────────────────────────────────────────────── │
  │                                                            │
  │── TLS ClientHello (uTLS Chrome 131, SNI=vk.com) ────────→ │
  │←── TLS ServerHello + Cert (LE for relay-X.solar-...) ──── │
  │── TLS Finished + ChangeCipherSpec ──────────────────────→ │
  │←── TLS Finished + ChangeCipherSpec ────────────────────── │
  │                                                            │
  │ ── (TLS established, all subsequent bytes encrypted) ───── │
  │                                                            │
  │── XZAP_frame_1: encrypt({"v":"mux1"}) ──────────────────→ │
  │                                                            │ keystore.identify(frame)
  │                                                            │ → user='vitaly_main', key=...
  │                                                            │ peek mux frame: sid=0 cmd=SYN
  │                                                            │ payload={"v":"mux1"}
  │                                                            │ → enter mux mode for this conn
  │                                                            │
  │←── XZAP_frame: encrypt({"v":"mux1"}) ──────────────────── │
  │                                                            │
  │ (mux mode now bidirectional)                               │
  │                                                            │
  │── XZAP_frame: mux SYN sid=1 → vk.com:443 ──────────────→ │
  │                                                            │ asyncio.open_connection
  │                                                            │ ← TCP to vk.com OK in 50ms
  │←── XZAP_frame: mux SYN_ACK sid=1 ───────────────────── │
  │                                                            │
  │── XZAP_frame: mux WINDOW sid=1 delta=0 ────────────────→ │
  │                                                            │
  │── XZAP_frame: mux DATA sid=1 <TLS ClientHello to vk> ──→ │
  │                                                            │ target.write(bytes)
  │                                                            │ ← target ServerHello
  │←── XZAP_frame: mux DATA sid=1 <ServerHello+...> ─────── │
  │                                                            │
  │ (... bidirectional flow until app closes ...)              │
  │                                                            │
  │── XZAP_frame: mux FIN sid=1 ────────────────────────────→ │
  │                                                            │ target.close()
  │                                                            │
  │ (control stream PING/PONG every 10s in background)         │
  │ ── XZAP_frame: mux sid=0 PING ────────────────────────→ │
  │ ←── XZAP_frame: mux sid=0 PONG ────────────────────────── │
  │                                                            │
  │ (next stream: SYN sid=2, sid=3, ... up to 2^32-1)          │
```

## Constants reference

### Размеры
| Constant | Value | Где |
|---|---|---|
| `MAX_FRAG_SIZE` | 65,536 + headers | XZAP frame max (server limits) |
| `MAX_MUX_PAYLOAD` | 262,144 (256KB) | mux frame max |
| `INITIAL_WINDOW` | 262,144 (256KB) | initial flow-control window per stream |
| `WINDOW_GRANT_THRESHOLD` | 65,536 (64KB) | client отдаёт WINDOW credit каждые 64KB consumed |
| `FRAG_THRESHOLD` | 150 | байт ≤ → micro-fragment 24-68B |
| `MICRO_FRAG_MIN` / `MAX` | 24 / 68 | размер micro-fragments |
| `CHAFF_MIN` / `MAX` (server) | 800 / 4000 | size range серверного chaff |
| `CHAFF_MIN` / `MAX` (client floor/ceiling) | 64 / 2048 | clamp на client chaff |
| `MUX_HDR_SIZE` | 9 | размер mux frame header |
| `XZAP_OVERHEAD` | 32 + tag | random_prefix + nonce + tag |

### Тайминги
| Constant | Value | Описание |
|---|---|---|
| `PING_INTERVAL` | 10s | client шлёт PING каждые 10s |
| `PING_TIMEOUT` | 30s | если no frame from server > 30s после PING → tunnel dead |
| `STREAM_DIAL_TO` (client ctx) | 10s | таймаут на mux SYN→ACK round-trip |
| `TARGET_CONNECT_TO` (server) | 3s | таймаут на target tcp connect (asyncio.open_connection) |
| `COLD_PATH_DIAL_TO` | 5s | per-attempt timeout первой dial-цепочки |
| `STEADY_PATH_DIAL_TO` | 15s | per-attempt таймаут после первого тоннеля |
| `MAX_AGE` | 10 min | tunnel max lifetime before retire |
| `RETIRE_GRACE` | 60s | grace period для draining streams перед force-close |
| `ROTATE_EVERY` | 30s | rotator tick interval |
| `WARMUP_DELAY` | 2 min | rotator dormant в первые 2 min |

### Phase D3 chaff
| Side | chance | size |
|---|---|---|
| Server (Python) | 0.35 | 800-4000B random, 1-3 fragments |
| Client (Go) | 0.40 | `payload × uniform(0.03, 0.10)`, clamped [64, 2048], 1 fragment |

## Encryption: подробности

### AES-256-GCM
```
key       = 32 bytes (per-user secret, base64 в keys.json)
nonce     = 12 bytes random per-frame
aad       = NULL
plaintext = mux-frame bytes (variable)
ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
```

Результат `ciphertext_and_tag` = `len(plaintext) + 16` байт.

Python:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
crypto = AESGCM(key)
ct = crypto.encrypt(nonce, plaintext, None)  # nonce + ct + tag
```

Go:
```go
import "crypto/cipher"
import "crypto/aes"
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
ct := gcm.Seal(nil, nonce, plaintext, nil)
```

### Why no AAD
Можно было бы добавить AAD = previous_msg_id, и получить anti-replay. Сейчас anti-replay не делаем — random_prefix (16B) обеспечивает уникальность каждого frame, но не защищает от воспроизведения. Trade-off: simplicity vs (минимальный) attack surface.

Если AAD понадобится — backward-compat нарушится. Реализовать через flag в первый байт plaintext (`{"v":"mux2","aad":"..."}`).

## Inspecting in pcap

`tshark` команды для разбора:

```bash
# Все пакеты от user IP
tshark -r capture.pcap -Y 'ip.src == 178.176.87.163' -T fields \
  -e frame.time_relative -e tcp.dstport -e frame.len

# TLS handshakes (ClientHello)
tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields \
  -e frame.number -e tls.handshake.extensions_server_name

# Conversations summary
tshark -r capture.pcap -q -z conv,tcp | head
```

Внутрь TLS-encrypted XZAP-frames без ключа залезть нельзя. Но **wire-level patterns** (sizes, timings, flow durations) видны как описано в `architecture.md`.
