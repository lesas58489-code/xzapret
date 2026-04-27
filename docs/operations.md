# Operations

Ежедневная работа с XZAP-инфраструктурой: мониторинг, управление пользователями, A/B-замеры, обновления.

## SSH-конфигурация

Рекомендуемый `~/.ssh/config` (на Linux dev-машине и на Windows клиентской):

```
Host tokyo
  HostName 151.245.104.38
  User root
  ServerAliveInterval 60

Host warsaw
  HostName 151.244.111.186
  User root
  IdentityFile ~/.ssh/warsaw
  ServerAliveInterval 60

Host sweden
  HostName 202.155.11.110
  User root
  IdentityFile ~/.ssh/sweden
  ServerAliveInterval 60

# Pattern for future relays
Host relay-*
  User root
  IdentityFile ~/.ssh/relay-default
  ServerAliveInterval 60
```

После этого:
```bash
ssh sweden                  # вместо: ssh -i ~/.ssh/sweden root@202.155.11.110
ssh sweden 'systemctl is-active xzap.service'
scp file.txt warsaw:/tmp/   # вместо: scp -i ... root@151.244.111.186:/tmp/
```

### ssh-agent (Windows)

Чтобы не вводить passphrase каждый раз:

```powershell
# Включить автостарт ssh-agent service
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent

# Добавить ключи в агент (один раз ввести passphrase, агент запомнит до reboot)
ssh-add $env:USERPROFILE\.ssh\warsaw
ssh-add $env:USERPROFILE\.ssh\sweden

# Проверить
ssh-add -l
```

**Важно**: использовать ssh БЕЗ флага `-i`. Флаг `-i` заставляет ssh читать файл напрямую (с passphrase), агент игнорируется. Просто `ssh sweden` (с config выше) — агент работает.

### ssh-agent (Linux)

```bash
# Запустить агент
eval "$(ssh-agent -s)"

# Добавить ключи
ssh-add ~/.ssh/warsaw
ssh-add ~/.ssh/sweden
```

В `~/.bashrc` для постоянного агента:
```bash
if [ -z "$SSH_AUTH_SOCK" ]; then
    eval "$(ssh-agent -s)" >/dev/null
    ssh-add ~/.ssh/warsaw 2>/dev/null
    ssh-add ~/.ssh/sweden 2>/dev/null
fi
```

## Мониторинг

### Daily health-check

Один shot командой по всем серверам:

```bash
for srv in warsaw sweden; do
  echo "=== $srv ==="
  ssh $srv 'systemctl is-active xzap.service nginx.service fail2ban.service; \
            free -m | head -2; uptime; df -h / | tail -1'
done
```

Должно выводить `active active active` × 3, RAM use < 50%, disk < 70%.

### Кто сейчас подключён

```bash
# Уникальные юзеры за последние 5 минут
ssh sweden 'journalctl -u xzap.service --since "5 minutes ago" --no-pager \
  | grep "User .*. connected" \
  | grep -oE "User .[^.]*. connected" | sort | uniq -c'
```

Пример вывода:
```
   42 User 'vitaly' connected         ← друзья со старым ключом
   18 User 'vitaly_main' connected    ← основной телефон
```

### Активные TLS-соединения

```bash
ssh sweden 'ss -tn state established "( sport = :443 )" | wc -l'
```

В steady-state: ~5-15 соединений на каждом сервере (зависит от количества активных юзеров и pool config). Если >100 — что-то странное (DDoS / scanner).

### CONNECT_FAILED — недостижимые цели

Сервер бьёт RST если не может достучаться до target за 3с. Высокий счёт = scanner-app у юзера или dead-DNS массовые retry:

```bash
ssh sweden 'journalctl -u xzap.service --since "5 minutes ago" --no-pager \
  | grep CONNECT_FAILED \
  | grep -oE "[0-9.]+:[0-9]+ CONNECT" | sort | uniq -c | sort -rn | head -10'
```

Если один IP занимает 50+ записей — почти точно scanner-app у юзера. См. `docs/troubleshooting.md` Termius case.

### SNI distribution в логе nginx

```bash
ssh sweden 'tail -200 /var/log/nginx/stream.log | awk "{print \$5}" | sort | uniq -c | sort -rn | head'
```

Должно быть распределение по bypass.txt доменам (vk.com, ya.ru, и т.д.). Если много `ssl_preread_server_name=` (пустых) — кто-то шлёт TLS без SNI extension.

### Tunnel rotations / closures

```bash
ssh sweden 'journalctl -u xzap.service --since "30 minutes ago" --no-pager \
  | grep -E "retiring|EXIT" | tail -20'
```

В норме: одно retiring каждые ~30с (если pool full). Если много EXIT за короткое время — DPI-blackhole на клиенте.

## User management

### Add user

```bash
ssh sweden 'cd /root/xzapret && python3 manage_keys.py add username'
```

Выведет base64 ключ. Этот ключ юзер вводит в Android UI поле Key.

### Remove user

```bash
ssh sweden 'cd /root/xzapret && python3 manage_keys.py remove username'
ssh sweden 'systemctl restart xzap.service'
```

После restart юзер уже не сможет подключиться. **Активные сессии будут продолжать работать** до следующего dial — потом сервер не сможет идентифицировать ключ → close.

### List users

```bash
ssh sweden 'cd /root/xzapret && python3 manage_keys.py list'
# или прямо
ssh sweden 'cat /root/xzapret/keys.json'
```

### Sync keys across all servers

После добавления юзера на одном сервере, нужно синхронизировать на остальные. Варианты:

**Вариант A: вручную** (для одного нового юзера):
```bash
KEYS=$(ssh sweden 'cat /root/xzapret/keys.json')
ssh warsaw "echo '$KEYS' > /root/xzapret/keys.json && systemctl restart xzap.service"
```

**Вариант B: rsync скрипт** (положить на dev-машину):
```bash
#!/bin/bash
# sync-keys.sh — sync keys.json from canonical source to all relays
SRC=warsaw   # canonical source
TARGETS=(sweden)  # all other relays

scp $SRC:/root/xzapret/keys.json /tmp/keys.json
for tgt in "${TARGETS[@]}"; do
  scp /tmp/keys.json $tgt:/root/xzapret/keys.json
  ssh $tgt 'systemctl restart xzap.service'
  echo "$tgt updated"
done
rm /tmp/keys.json
```

**Вариант C: cron каждый час** (если часто добавляешь):
На canonical сервере (Warsaw):
```bash
# /etc/cron.hourly/push-keys
#!/bin/bash
for tgt in 202.155.11.110; do
  rsync -e "ssh -i /root/.ssh/sync-key" /root/xzapret/keys.json root@$tgt:/root/xzapret/keys.json
  ssh -i /root/.ssh/sync-key root@$tgt 'systemctl reload xzap.service' 2>/dev/null
done
```

(Понадобится отдельный SSH-ключ только для sync.)

### Rotate user key

Нет специальной команды — просто remove + add под тем же именем:

```bash
ssh sweden 'cd /root/xzapret && python3 manage_keys.py remove username && python3 manage_keys.py add username'
ssh sweden 'systemctl restart xzap.service'
# Затем sync на остальные сервера + дать новый ключ юзеру
```

## Обновление кода (deploy)

После git push на dev-машине нужно пуллить на каждом production-сервере. **Важно**: keys.json локально модифицирован → нужен stash/pop.

### Стандартный pattern

```bash
ssh sweden <<'EOF'
git -C /root/xzapret stash push keys.json
git -C /root/xzapret pull --rebase
git -C /root/xzapret stash pop
systemctl restart xzap.service
sleep 1
systemctl is-active xzap.service
EOF
```

Если конфликт в keys.json при pop — значит код в git тоже трогает keys.json (плохой коммит, не должно быть). Решить вручную: `git checkout --ours keys.json` или восстановить из бэкапа.

### Один shot на все relays

```bash
for srv in warsaw sweden; do
  echo "=== $srv ==="
  ssh $srv "git -C /root/xzapret stash push keys.json 2>/dev/null; \
            git -C /root/xzapret pull --rebase; \
            git -C /root/xzapret stash pop 2>/dev/null; \
            systemctl restart xzap.service && \
            sleep 1 && \
            systemctl is-active xzap.service"
done
```

### Verification после update

```bash
# HEAD должен быть свежий
ssh sweden 'git -C /root/xzapret log --oneline -1'

# Сервис активен
ssh sweden 'systemctl is-active xzap.service'

# Юзеры загружены (число должно совпадать с keys.json)
ssh sweden 'journalctl -u xzap.service -n 50 --no-pager | grep "users loaded"'
```

## A/B измерения с pcap

Когда тестируем эффект какого-то изменения (chaff level, pool config, etc.). Чистый A/B = два captures на одной сети с одинаковым сценарием активности, разница только в исследуемой переменной.

### Подготовка анализатора

Положить на сервер один раз (или Tokyo):

```bash
cat > /tmp/analyze.py <<'PYEOF'
import sys
from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
import statistics

def analyze(pcap_path, label, our_ip):
    pkts = rdpcap(pcap_path)
    flows = defaultdict(lambda: {"pkts": [], "bytes_in": 0, "bytes_out": 0,
                                  "first_ts": None, "last_ts": None})
    for p in pkts:
        if not p.haslayer(TCP) or not p.haslayer(IP): continue
        src, dst = p[IP].src, p[IP].dst
        sport, dport = p[TCP].sport, p[TCP].dport
        if src == our_ip:
            flow = (src, sport, dst, dport); direction = "out"
        else:
            flow = (dst, dport, src, sport); direction = "in"
        f = flows[flow]
        f["pkts"].append((p.time, len(p), direction, p[TCP].flags))
        f["bytes_in" if direction == "in" else "bytes_out"] += len(p)
        if f["first_ts"] is None: f["first_ts"] = p.time
        f["last_ts"] = p.time
    flows = {k: v for k, v in flows.items() if len(v["pkts"]) >= 10}
    print(f"\n=== {label} ===")
    print(f"flows: {len(flows)}")
    if not flows: return
    durs = sorted(float(f["last_ts"] - f["first_ts"]) for f in flows.values())
    bin_  = sorted(f["bytes_in"] for f in flows.values())
    bout = sorted(f["bytes_out"] for f in flows.values())
    print(f"duration: median={durs[len(durs)//2]:.1f}s max={durs[-1]:.1f}s")
    print(f"bytes_in median={bin_[len(bin_)//2]} max={bin_[-1]}")
    print(f"bytes_out median={bout[len(bout)//2]} max={bout[-1]}")
    sizes = sorted(p[1] for f in flows.values() for p in f["pkts"] if p[1] > 50)
    print(f"data-packet size: p50={sizes[len(sizes)//2]} p90={sizes[len(sizes)*9//10]}")
    ratios = sorted((f["bytes_in"] / max(f["bytes_out"], 1)) for f in flows.values())
    print(f"in/out ratio median={ratios[len(ratios)//2]:.2f}")

if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2], sys.argv[3])
PYEOF
```

Использование: `python3 /tmp/analyze.py /tmp/capture.pcap "label" "Server_IP"`.

### Выполнение A/B

1. **Деплой версии A** на сервер. Verify работает.
2. **Capture A**:
   ```bash
   ssh sweden 'rm -f /tmp/A.pcap; nohup tcpdump -i eth0 -s 0 -w /tmp/A.pcap "tcp port 443" >/dev/null 2>&1 &'
   ```
3. **Тест 5-7 минут** — пользователь делает идентичные действия (Chrome+YouTube+browse).
4. **Stop**:
   ```bash
   ssh sweden 'pkill tcpdump; ls -lh /tmp/A.pcap'
   ```
5. **Деплой версию B** (изменить параметр + restart).
6. **Capture B** → A.pcap → B.pcap → `pkill tcpdump`.
7. **Filter и анализ**:
   ```bash
   USER_IP=$(ssh sweden 'tshark -r /tmp/A.pcap -q -z ip_hosts,tree | grep -E "^ [0-9]" | head -2 | tail -1 | awk "{print \$1}"')
   echo "User IP: $USER_IP"
   ssh sweden "tcpdump -r /tmp/A.pcap -w /tmp/A_user.pcap 'host $USER_IP'"
   ssh sweden "tcpdump -r /tmp/B.pcap -w /tmp/B_user.pcap 'host $USER_IP'"
   ssh sweden "python3 /tmp/analyze.py /tmp/A_user.pcap 'A: baseline' 'SERVER_IP'"
   ssh sweden "python3 /tmp/analyze.py /tmp/B_user.pcap 'B: with change' 'SERVER_IP'"
   ```

### Что искать в выводе

| Метрика | Если изменилась → возможно |
|---|---|
| `flows` | Сильно отличается → разная активность user, не fair compare |
| `duration median` | Меньше → tunnel rotation работает или pool churn |
| `bytes_in median` | Больше в B → client стал больше отправлять (Phase D3 client mirror?) |
| `bytes_out median` | Больше в B → server больше отправляет (Phase D3 server) |
| `data-packet size p50` | Сильно вырос → chaff добавляет байт (intent работает) |
| `in/out ratio median` | Сдвиг в сторону browser (3.20+) — прогресс |

Browser reference (для сравнения):
- duration median: 0.5s
- in/out ratio median: 3.20
- packet size p50: 195

Текущее наше состояние ~ 100-200s duration, ratio 0.5-2.0, p50 150-700. Browser pattern мы НЕ имитируем полностью — это известно (см. `architecture.md` "What's NOT closed").

## Логи

### Локации логов

| Сервис | Где |
|---|---|
| xzap.service | journalctl -u xzap.service |
| nginx access (HTTP) | /var/log/nginx/access.log |
| nginx stream (SNI routing) | /var/log/nginx/stream.log |
| nginx errors | /var/log/nginx/error.log + /var/log/nginx/stream_error.log |
| fail2ban | journalctl -u fail2ban |
| auth (SSH attempts) | /var/log/auth.log |
| Let's Encrypt renew | /var/log/letsencrypt/letsencrypt.log |

### logrotate

Для nginx логи стандартно ротейтятся через `/etc/logrotate.d/nginx`. Для xzap — journalctl сам управляет (max 10% disk by default, см. `journalctl --disk-usage`).

Если нужно ограничить:
```bash
cat > /etc/systemd/journald.conf.d/xzap.conf <<EOF
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=7d
EOF
systemctl restart systemd-journald
```

### Поиск конкретных событий

```bash
# Когда юзер впервые подключился
ssh sweden 'journalctl -u xzap.service --no-pager | grep "User .vitaly_main. connected" | head -1'

# Все CONNECT_FAILED за день
ssh sweden 'journalctl -u xzap.service --since "1 day ago" --no-pager | grep -c CONNECT_FAILED'

# fail2ban — кого банили
ssh sweden 'journalctl -u fail2ban --since "1 day ago" --no-pager | grep "Ban "'

# SSH brute-force попытки
ssh sweden 'grep "Failed password" /var/log/auth.log | wc -l'
```

## Аварийное восстановление

### "Сервер упал, не пингуется"

1. Зайти в hosting panel (UltraHost / Hetzner / etc.) — посмотреть статус VM
2. Console через panel (если есть) — посмотреть `dmesg` / `journalctl -xe`
3. Если VM uplink ОК но не отвечает — soft reboot через panel
4. Если совсем нет — restore из snapshot (если делал бэкапы)

### "xzap.service постоянно crash'ит"

```bash
ssh sweden 'journalctl -u xzap.service --since "10 minutes ago" --no-pager | tail -50'
```

Поиск exception. Чаще всего — некорректный keys.json или cert path неправильный (если certbot обновил а конфиг systemd ссылается на устаревший symlink).

```bash
# Проверить cert
ssh sweden 'ls -la /etc/letsencrypt/live/relay-X.solar-cloud.xyz/'

# Тест keys.json
ssh sweden 'python3 -c "import json; print(len(json.load(open(\"/root/xzapret/keys.json\"))[\"users\"]))"'

# Откат на предыдущий commit если что-то сломал свежим pull'ом
ssh sweden 'git -C /root/xzapret log --oneline -10'
ssh sweden 'git -C /root/xzapret reset --hard <hash> && systemctl restart xzap.service'
```

### "DPI начал блочить наши IP"

Симптомы: TLS handshake i/o timeout массово, невозможно установить тоннель ни с какого устройства.

1. **Проверить с другой сети** — VPN-кофейня, мобильный hotspot, etc. Если оттуда работает — таргетный block для одной сети.
2. **Если global block** (с разных сетей не идёт):
   - Поднять новый relay на другом IP (см. `deploy-server.md`)
   - Добавить новый IP в Server поле Android UI
   - Старый IP не удалять (DPI снимет block через дни/недели обычно)
3. **Долгосрочное**: distribute relay parking — несколько серверов в разных AS у разных провайдеров.

### "Юзер потерял доступ к ключу / устройство украли"

Срочно ротировать ключ:

```bash
ssh warsaw 'cd /root/xzapret && python3 manage_keys.py remove username'
# (плюс новый: python3 manage_keys.py add username)
# Sync на все relays
# Дать новый ключ юзеру вне кражи
```

После remove + restart xzap.service — старые сессии не закроются мгновенно, но новые dial'ы для этого ключа будут отбиваться. Активные TLS-conn умрут на следующем PING/PONG (30с).

Для **немедленной** disconnect — `systemctl restart xzap.service` (kill all current connections).

## Backup

Что бекапить (минимум):

| Что | Где | Как часто |
|---|---|---|
| `keys.json` | каждый relay | После каждого `manage_keys.py add/remove`. Хранить на dev-машине шифрованный |
| LE certs | `/etc/letsencrypt/` | Не критично (можно перевыпустить через certbot), но snapshot перед major changes |
| nginx-stream config | `/etc/nginx/stream-xzap.conf` | После каждой ручной правки |
| systemd unit `xzap.service` | `/etc/systemd/system/xzap.service` | После правок |
| Sysctl tuning | `/etc/sysctl.d/99-xzap-relay.conf` | После правок |

Простейший backup-скрипт на dev:
```bash
#!/bin/bash
# /root/backup-relays.sh
DATE=$(date +%Y-%m-%d)
mkdir -p /root/backups/$DATE
for srv in warsaw sweden; do
  ssh $srv "tar czf - \
    /root/xzapret/keys.json \
    /etc/nginx/stream-xzap.conf \
    /etc/systemd/system/xzap.service \
    /etc/sysctl.d/99-xzap-relay.conf \
    2>/dev/null" > /root/backups/$DATE/$srv.tar.gz
done
echo "backup done in /root/backups/$DATE"
```

Cron:
```
0 4 * * * /root/backup-relays.sh
```

## Что НЕ делать

- **Не правь файлы вручную на одном relay** забывая про остальные. Использовать git deploy pattern.
- **Не коммить keys.json** в git с реальными ключами. Они уже в `git status` как «modified» — оставить так.
- **Не отключать fail2ban** даже временно — даже на 5 минут SSH становится мишенью brute-force.
- **Не запускай tcpdump на eth0 без time-bound'а** — забьёт диск. Использовать `-G` для rotation или ручной `pkill tcpdump`.
- **Не делай git push --force в main** — другой relay/dev в это время может быть в pull'е.
- **Не модифицируй RetireGrace ниже 30с** без serious тестирования — force-close YouTube streams ломает UX (см. `troubleshooting.md` Phase A lessons).
