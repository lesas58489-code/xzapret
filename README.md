# XZAPRET

XZAP — самостоятельный anti-DPI протокол для обхода блокировок в России. Не форк Xray/VLESS/MTProto.

## Кратко

```
[Phone]──tun2socks──→[SOCKS5]──mux──→[XZAP frame]──TLS──→[Internet]
                                          ↑
                                  AES-256-GCM + chaff +
                                  white-list SNI rotation
```

Клиент Android (Go core через AAR) перехватывает весь TCP-трафик через VpnService, упаковывает в мукс-фреймы поверх XZAP-протокола, шифрует AES-256-GCM, оборачивает в TLS с белыми SNI (vk.com, yandex.ru и т.д.) и отправляет на ретранслятор. Ретранслятор расшифровывает, проксирует на target в открытый интернет.

Текущий production: 2 сервера в Швеции и Польше с round-robin failover.

## Quick start (5 шагов до подключения)

1. **Скачай APK** на телефон: `http://151.244.111.186/xzap.apk`
2. **Установи APK** (разреши установку из неизвестных источников один раз)
3. **Открой XZAP**, в полях:
   - **Server**: `202.155.11.110,151.244.111.186` (multi-server, через запятую)
   - **Port**: `443`
   - **Key**: попроси у админа (per-user AES-256, base64)
4. **Connect** — Android покажет диалог «Allow VPN connection» — Allow
5. Должна появиться **VPN-иконка** в notification bar. Готово, весь трафик идёт через XZAP

## Документация

| Документ | Содержание |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Слои протокола, диаграммы потока, pool design, multi-server, Phase D3 chaff |
| [docs/wire-protocol.md](docs/wire-protocol.md) | Байт-уровень: формат фреймов, handshake, mux команды |
| [docs/deploy-server.md](docs/deploy-server.md) | Как поднять новый ретранслятор с нуля |
| [docs/build-android.md](docs/build-android.md) | Как собрать AAR + APK |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Известные баги, фиксы, lessons learned |
| [docs/operations.md](docs/operations.md) | Daily ops: мониторинг, добавить юзера, A/B замеры |
| [CLAUDE.md](CLAUDE.md) | Quick reference для Claude Code (current infra state) |
| [SPEC.md](SPEC.md) | Формальная спецификация протокола v1 |

## Структура репозитория

```
xzap/                       # Python протокол: сервер + Python клиент
core/go/                    # Android client: компилируется в AAR через gomobile
clients/
  android/                  # Android VPN app (Kotlin shell + Go AAR)
  windows/                  # Windows tkinter client (legacy)
docs/                       # Документация (этот директорий)
lists/
  bypass.txt                # Российские домены — используются как SNI rotation
  xzap.txt                  # Заблокированные сайты — для информации
run_server.py               # Server entrypoint
manage_keys.py              # CLI для управления keystore
```

## Серверы

| Узел | IP | Роль |
|---|---|---|
| Sweden | `202.155.11.110` | Production relay, primary (RTT 51ms из Тольятти) |
| Warsaw | `151.244.111.186` | Production relay, backup (RTT 63ms) |
| Tokyo | `151.245.104.38` | Dev машина: AAR build, репозиторий |

## Лицензия и контакты

Внутренний проект, не публичный. Доступ — у автора.
