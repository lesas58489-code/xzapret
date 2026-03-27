# xzapret Protocol (XZAP) — Specification v1.0 (Draft, March 2026)

## 1. Overview

XZAP — самостоятельный открытый протокол анти-DPI нового поколения.
Цель: сделать цензуру вычислительно невозможной даже при 900+ Тбит/с DPI + ML.

Не является форком Xray, VLESS, MTProto или zapret.

## 2. Architecture Layers

```
┌─────────────────────────────────────────────┐
│            Application Layer                │
│         (SOCKS5 / HTTP Proxy / TUN)         │
├─────────────────────────────────────────────┤
│         Crypto & Authorization Layer        │
│  Auth key (256-bit) / DH 2048 + Reality     │
│  UUID + server publicKey                    │
│  AES-256-GCM | ChaCha20-Poly1305            │
│  msg_key + salt (anti-replay)               │
├─────────────────────────────────────────────┤
│     Obfuscation & Fragmentation Layer       │
│  Micro-fragmentation: 8–64 bytes/chunk      │
│  Multi-SNI: 4–16 parallel connections       │
│  Adaptive strategy (retransmit-based)       │
│  Fake ClientHello rotation                  │
│  Disorder + overlap + autottl + badseq      │
├─────────────────────────────────────────────┤
│            Transport Layer                  │
│  Primary: TCP + Reality + uTLS              │
│  Fallback: QUIC (TUIC-like)                 │
│  64-byte random prefix + CTR obfuscation    │
└─────────────────────────────────────────────┘
```

## 3. Message Format

Every message carries an MTProto-style header:

```
Offset  Size    Field
0       8       msg_id      (uint64, monotonic timestamp-based)
8       4       seqno       (uint32, sequential)
12      2       length      (uint16, payload length)
14      16      msg_key     (HMAC-SHA256 truncated, integrity check)
30      N       payload     (encrypted)
```

Total header size: **30 bytes**.

### 3.1 msg_id Generation

```
msg_id = (unix_time_ms << 20) | (random & 0xFFFFF)
```

Must be monotonically increasing per session. Server rejects out-of-order msg_id
(anti-replay).

### 3.2 msg_key Derivation

```
msg_key = HMAC-SHA256(auth_key[88:120], plaintext)[0:16]
```

Used for integrity verification before decryption.

## 4. Crypto & Authorization Layer

### 4.1 Key Exchange

1. Client generates ephemeral X25519 keypair.
2. Server has static X25519 keypair (publicKey distributed out-of-band).
3. Shared secret = X25519(client_private, server_public).
4. Auth key = HKDF-SHA256(shared_secret, salt=UUID, info="xzap-auth", len=256).

### 4.2 Encryption

Two algorithms supported (client choice in handshake):

| Algorithm         | Key    | Nonce  | Tag    |
|-------------------|--------|--------|--------|
| AES-256-GCM       | 32 B   | 12 B   | 16 B   |
| ChaCha20-Poly1305 | 32 B   | 12 B   | 16 B   |

Encrypted payload format:
```
[12 bytes nonce][N bytes ciphertext + 16 bytes tag]
```

AAD (Additional Authenticated Data) = msg_id || seqno || length.

### 4.3 Anti-Replay

- msg_id must be unique and monotonically increasing.
- Server maintains sliding window of last 1024 msg_ids.
- salt rotated every 60 seconds.

## 5. Obfuscation & Fragmentation Layer

### 5.1 Micro-Fragmentation

Each encrypted message is split into fragments of **8–64 bytes** (random size per fragment).

Fragment wire format:
```
Offset  Size    Field
0       8       msg_id      (parent message)
8       2       frag_index  (uint16)
10      2       frag_total  (uint16)
12      N       frag_data   (8–64 bytes)
```

Fragment header: **12 bytes**.

### 5.2 Fragment Delivery Techniques

- **disorder**: fragments sent out of order (random shuffle)
- **overlap**: `overlap=1` — each fragment overlaps by 1 byte with the next
- **autottl**: random TTL per fragment to evade stateful DPI
- **badseq/badsum**: decoy packets with invalid TCP seq/checksum (dropped by receiver, confuse DPI)

### 5.3 Multi-SNI / Multi-Path

Client maintains **4–16 parallel TCP/QUIC connections**, each with a different
SNI from the whitelist (e.g., youtube.com, google.com, cloudflare.com).

Fragment routing:
```
path_index = (msg_id + frag_index) % num_paths
```

### 5.4 Fake ClientHello Rotation

During handshake and periodically during data phase, client injects fake TLS
ClientHello records from a built-in pool of captured dumps (yandex.ru, vk.com,
avito.ru, etc.).

Rotation interval: every 30–120 seconds (random).

## 6. Adaptive Strategy

Client and server monitor connection quality and automatically escalate
obfuscation:

```
if retransmits > 3:
    repeats = min(repeats + 1, 3)
    fragment_count *= 2
    tls_mod = "rnd,rndsni,padencap"

if retransmits == 0 for 60s:
    de-escalate one level
```

### 6.1 Escalation Levels

| Level | Repeats | Fragment Size | Extra                |
|-------|---------|---------------|----------------------|
| 0     | 1       | 32–64 B       | none                 |
| 1     | 2       | 16–48 B       | disorder             |
| 2     | 3       | 8–32 B        | disorder + overlap   |
| 3     | 3       | 8–16 B        | full (+ badseq/sum)  |

## 7. Transport Layer

### 7.1 TCP + Reality + uTLS

- uTLS fingerprint: chrome / edge / firefox / random (rotation per connection).
- Reality: server validates real TLS handshake against target domain.
- 64-byte random prefix prepended to every connection.

### 7.2 QUIC Fallback

- QUIC with same fragmentation and obfuscation.
- Used when TCP is throttled or blocked.

### 7.3 Proxy Modes

- SOCKS5 proxy (default)
- HTTP CONNECT proxy
- TUN device (full traffic capture, requires root on some platforms)

## 8. Handshake Flow

```
Client                                          Server
  │                                               │
  │── [1] 4-8 parallel ClientHello ──────────────>│
  │   (uTLS fingerprint, SNI=white domain)        │
  │   (+ fake ClientHello interleaved)            │
  │   (+ micro-fragmented)                        │
  │                                               │
  │<── [2] Reality ServerHello ──────────────────│
  │   (only on 1 connection, matched by UUID)     │
  │                                               │
  │── [3] X25519 key exchange ──────────────────>│
  │   (encrypted with Reality session key)        │
  │                                               │
  │<── [4] Auth OK + algo confirmation ─────────│
  │                                               │
  │══ [5] Data phase (all paths active) ════════│
  │   (fragments routed round-robin)              │
```

## 9. Security Considerations

- Forward secrecy via ephemeral X25519 per session.
- No distinguishable patterns: random sizes, random timing, random paths.
- Active probing resistance: server responds only to valid UUID + Reality.
- Replay protection: msg_id monotonicity + sliding window.
- Censorship cost: O(n * paths * fragments) per message to analyze.
