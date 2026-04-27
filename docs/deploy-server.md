# Deploy a new XZAP relay server

Полный процесс поднятия нового сервера с нуля, проверено на Sweden VPS (2026-04-26).
Время: ~30 минут от чистого VPS до production-ready relay.

## Prerequisites

| Что | Минимум | Рекомендуется |
|---|---|---|
| OS | Ubuntu 22.04 / 24.04 LTS | Ubuntu 24.04 LTS |
| vCPU | 1 | 2 |
| RAM | 512 MB | 1 GB |
| Disk | 10 GB | 20 GB |
| Bandwidth | 1 TB/мес | unlimited / 5+ TB |
| Hosting | Любой со статичным IP | Hetzner FSN/HEL, OVH FR, PQ.HOSTING, Vultr |

**Важно**: hosting должен:
- Принимать твой способ оплаты (после 2022 многие EU-провайдеры закрыли РФ-карты)
- Не блокировать SSL/TLS на 443 (некоторые budget-хостеры режут под антипиратку — нам мешает)
- Иметь достаточный peering к РФ (RTT <100ms из Москвы желательно)

См. альтернативы в README.md или troubleshooting.md «Где брать VPS если Hetzner не пускает».

## Шаг 0 — что нужно подготовить заранее

1. **VPS** с SSH-доступом по password (для первоначального key install) или сразу с key
2. **Домен** под управлением, у которого ты можешь добавить A-запись (Porkbun / CloudFlare / любой registrar). У нас все relays идут под `*.solar-cloud.xyz`
3. **GitHub PAT** для клонирования private repo (или способ подсовывать код — rsync, git-bundle, etc.)
4. **Email** для Let's Encrypt notifications
5. **Tokyo dev server** (если есть централизованная разработка) — оттуда удобно деплоить и держать SSH-ключи

Для нового сервера присвоим имя — пусть это `relay-xx` (xx = код локации, например `se`, `de`, `fr`).

## Шаг 1 — SSH-ключ доступа

Если хостинг даёт пароль root, первое — добавить SSH-ключ и убрать password auth.

### С Tokyo (или dev-машины):

```bash
# Если новый ключ
ssh-keygen -t ed25519 -f ~/.ssh/relay-xx -N "" -C "xzap-relay-xx-$(date +%Y%m%d)"

# Скопировать на сервер по паролю (sshpass для одного раза)
apt-get install -y sshpass
sshpass -p 'TEMP_ROOT_PASSWORD' ssh-copy-id -i ~/.ssh/relay-xx.pub \
  -o StrictHostKeyChecking=accept-new root@RELAY_IP

# Тест passwordless
ssh -i ~/.ssh/relay-xx root@RELAY_IP hostname
```

### С Windows клиентской машины:

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\relay-xx -C "vitaly-windows"
# Скопируй publické содержимое и попроси админа добавить в authorized_keys
cat $env:USERPROFILE\.ssh\relay-xx.pub
```

Админ на сервере:
```bash
echo "ssh-ed25519 AAAA... vitaly-windows" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## Шаг 2 — Harden SSH (key-only, fail2ban)

```bash
# Disable password auth
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sshd -t && systemctl reload ssh

# fail2ban
apt-get install -y fail2ban
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
# Whitelist your trusted IPs (Tokyo, home WiFi, other relays)
ignoreip = 127.0.0.1/8 ::1 151.245.104.38 151.244.111.186 178.163.89.251

[sshd]
enabled = true
port = 22
EOF
systemctl enable --now fail2ban
fail2ban-client status sshd
```

## Шаг 3 — DNS

Добавь A-запись `relay-xx.solar-cloud.xyz` → RELAY_IP в authoritative DNS provider.
В нашем случае это **Porkbun** (CloudFlare более не authoritative для solar-cloud.xyz).

В Porkbun → DNS for solar-cloud.xyz → Add Record:
- **Type**: A
- **Host**: `relay-xx`
- **Answer**: `RELAY_IP`
- **TTL**: 300

Проверка пропагации:
```bash
dig relay-xx.solar-cloud.xyz @maceio.ns.porkbun.com +short
# Должен вернуть RELAY_IP. Обычно за 1 минуту.
```

## Шаг 4 — Пакеты и репозиторий

```bash
ssh root@RELAY_IP <<'REMOTE'
apt-get update -qq
apt-get install -y nginx libnginx-mod-stream certbot python3-pip python3-cryptography git tcpdump tshark ufw

# Clone repo (заменить TOKEN на свой GH PAT для private repo)
cd /root && git clone https://TOKEN@github.com/lesas58489-code/xzapret.git
cd xzapret && git log --oneline -3
REMOTE
```

Если repo public — без token. Если private — token обязателен.

## Шаг 5 — sysctl tuning

Скопировать настройки сети для Russian-carrier-friendly transport:

```bash
ssh root@RELAY_IP "cat > /etc/sysctl.d/99-xzap-relay.conf" <<'EOF'
# XZAP relay tuning — Russian carriers compatibility
net.ipv4.tcp_congestion_control = cubic
net.core.default_qdisc = fq_codel

# Buffer sizes — 16MB max
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096

# Wider port range for many concurrent upstream conns
net.ipv4.ip_local_port_range = 1024 65535

# TIME_WAIT recycling
net.ipv4.tcp_tw_reuse = 1

# CRITICAL: TFO=0 — Russian middleboxes drop packets with TFO cookies
net.ipv4.tcp_fastopen = 0

# Reasonable keepalive (default 7200s is too long)
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOF

ssh root@RELAY_IP 'sysctl --system 2>&1 | tail -3'
```

## Шаг 6 — ufw (firewall)

```bash
ssh root@RELAY_IP <<'REMOTE'
ufw allow 22/tcp
ufw allow 80/tcp     # HTTP для LE cert renewal + APK download
ufw allow 443/tcp    # main XZAP entry
echo y | ufw enable
ufw status numbered
REMOTE
```

Default INPUT = DROP, всё остальное закрыто.

## Шаг 7 — Let's Encrypt cert

Требует чтобы Шаг 3 (DNS) уже отработал.

```bash
ssh root@RELAY_IP <<'REMOTE'
mkdir -p /var/www/html
certbot certonly --webroot -w /var/www/html -d relay-xx.solar-cloud.xyz \
  --email YOUR@EMAIL --agree-tos --non-interactive
# Должен вывести "Successfully received certificate"
ls -la /etc/letsencrypt/live/relay-xx.solar-cloud.xyz/
REMOTE
```

Auto-renew работает автоматически через `certbot.timer` (systemd) — каждый день, обновит за 30 дней до expiry.

## Шаг 8 — nginx-stream config (SNI router :443)

```bash
ssh root@RELAY_IP "cat > /etc/nginx/stream-xzap.conf" <<'EOF'
# SNI-based routing on :443 → xzap on 9443
stream {
    log_format basic '$remote_addr [$time_local] ssl_preread_server_name=$ssl_preread_server_name -> $backend';
    access_log /var/log/nginx/stream.log basic;
    error_log /var/log/nginx/stream_error.log warn;

    map $ssl_preread_server_name $backend {
        # Self domain
        relay-xx.solar-cloud.xyz        127.0.0.1:9443;

        # bypass.txt SNI rotation list
        vk.com                          127.0.0.1:9443;
        ok.ru                           127.0.0.1:9443;
        yandex.ru                       127.0.0.1:9443;
        yandex.net                      127.0.0.1:9443;
        mail.ru                         127.0.0.1:9443;
        rambler.ru                      127.0.0.1:9443;
        avito.ru                        127.0.0.1:9443;
        sberbank.ru                     127.0.0.1:9443;
        gosuslugi.ru                    127.0.0.1:9443;
        mos.ru                          127.0.0.1:9443;
        rbc.ru                          127.0.0.1:9443;
        lenta.ru                        127.0.0.1:9443;
        ria.ru                          127.0.0.1:9443;
        rt.com                          127.0.0.1:9443;
        tinkoff.ru                      127.0.0.1:9443;
        ozon.ru                         127.0.0.1:9443;
        wildberries.ru                  127.0.0.1:9443;
        kinopoisk.ru                    127.0.0.1:9443;
        "2gis.ru"                       127.0.0.1:9443;
        dzen.ru                         127.0.0.1:9443;

        default                         127.0.0.1:9443;
    }

    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_pass $backend;
        ssl_preread on;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
EOF

# Include в nginx.conf если ещё не
ssh root@RELAY_IP "grep -q 'stream-xzap.conf' /etc/nginx/nginx.conf || \
  sed -i '/^events {/i include /etc/nginx/stream-xzap.conf;' /etc/nginx/nginx.conf
nginx -t && systemctl reload nginx"
```

## Шаг 9 — xzap.service (systemd unit)

```bash
ssh root@RELAY_IP "cat > /etc/systemd/system/xzap.service" <<'EOF'
[Unit]
Description=XZAP Tunnel Server (TLS, SNI-routed via nginx-stream)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/xzapret
ExecStart=/usr/bin/python3 run_server.py --host 127.0.0.1 --port 9443 --tls --cert /etc/letsencrypt/live/relay-xx.solar-cloud.xyz/fullchain.pem --tls-key /etc/letsencrypt/live/relay-xx.solar-cloud.xyz/privkey.pem
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xzap
LimitNOFILE=524288
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF

ssh root@RELAY_IP 'systemctl daemon-reload && systemctl enable --now xzap.service && sleep 2 && systemctl is-active xzap.service'
```

## Шаг 10 — Sync keys.json

С существующего production-сервера (чтобы те же юзеры работали везде):

```bash
# Получить keys.json от Warsaw
WARSAW_KEYS=$(ssh root@151.244.111.186 'cat /root/xzapret/keys.json')

# Положить на новый
ssh root@RELAY_IP "cat > /root/xzapret/keys.json" <<EOF
$WARSAW_KEYS
EOF

ssh root@RELAY_IP 'systemctl restart xzap.service && sleep 1 && journalctl -u xzap.service --since "5 seconds ago" --no-pager | grep "users loaded"'
```

Должен показать «X users loaded» (число должно совпадать с Warsaw).

## Шаг 11 — Smoke test

```bash
# С локалки (любая Linux/Mac/WSL):
echo | timeout 5 openssl s_client -connect relay-xx.solar-cloud.xyz:443 \
  -servername relay-xx.solar-cloud.xyz 2>&1 | grep -E "subject=|issuer=|Verification"
# Должно: subject=CN = relay-xx.solar-cloud.xyz / Let's Encrypt / Verification: OK

# Bypass-SNI должен тоже подхватываться (разный SNI, тот же сервер):
echo | timeout 5 openssl s_client -connect relay-xx.solar-cloud.xyz:443 \
  -servername vk.com 2>&1 | grep "subject="
# Тоже отдаст cert для relay-xx (mismatch с SNI, но клиент ignor'ит)

# Проверить что в server-логе видно
ssh root@RELAY_IP 'tail -3 /var/log/nginx/stream.log'
```

## Шаг 12 — Добавить в Android client config

В UI Android в поле Server добавь IP нового сервера через запятую:

```
Server: 202.155.11.110,151.244.111.186,RELAY_IP
Port: 443
```

Pool сразу начнёт ротировать на 3 узла. Никаких других изменений на клиенте не нужно.

## Один-shot всё-сразу скрипт

Сохрани как `deploy-relay.sh` на dev-машине:

```bash
#!/bin/bash
# Usage: ./deploy-relay.sh <relay_ip> <relay_subdomain> <email>
# Example: ./deploy-relay.sh 1.2.3.4 relay-de info@example.com

set -e
IP="$1"; SUB="$2"; EMAIL="$3"
[ -z "$IP" ] && { echo "Usage: $0 <ip> <subdomain> <email>"; exit 1; }

# Assumes ~/.ssh/relay key exists and is added on the IP
SSH="ssh -i ~/.ssh/relay -o StrictHostKeyChecking=accept-new root@$IP"

echo "=== Шаг 1: пакеты ==="
$SSH "apt-get update -qq && apt-get install -y nginx libnginx-mod-stream certbot python3-pip python3-cryptography git tcpdump fail2ban ufw"

echo "=== Шаг 2: clone repo ==="
$SSH "[ -d /root/xzapret ] || git clone https://TOKEN@github.com/lesas58489-code/xzapret.git /root/xzapret"

echo "=== Шаг 3: sysctl ==="
$SSH "curl -sf https://raw.githubusercontent.com/lesas58489-code/xzapret/main/docs/snippets/sysctl-relay.conf > /etc/sysctl.d/99-xzap-relay.conf && sysctl --system"

echo "=== Шаг 4: ufw ==="
$SSH "ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && echo y | ufw enable"

echo "=== Шаг 5: harden SSH ==="
$SSH "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh"

echo "=== Шаг 6: LE cert ==="
$SSH "mkdir -p /var/www/html && certbot certonly --webroot -w /var/www/html -d $SUB.solar-cloud.xyz --email $EMAIL --agree-tos --non-interactive"

echo "=== Шаг 7: nginx-stream + xzap.service ==="
$SSH "sed 's/relay-xx/$SUB/g' /root/xzapret/docs/snippets/stream-xzap.conf > /etc/nginx/stream-xzap.conf"
$SSH "sed 's/relay-xx/$SUB/g' /root/xzapret/docs/snippets/xzap.service > /etc/systemd/system/xzap.service"
$SSH "grep -q 'stream-xzap.conf' /etc/nginx/nginx.conf || sed -i '/^events {/i include /etc/nginx/stream-xzap.conf;' /etc/nginx/nginx.conf"
$SSH "nginx -t && systemctl reload nginx && systemctl daemon-reload && systemctl enable --now xzap.service"

echo "=== Шаг 8: keys.json sync ==="
WARSAW_KEYS=$(ssh -i ~/.ssh/warsaw root@151.244.111.186 'cat /root/xzapret/keys.json')
echo "$WARSAW_KEYS" | $SSH "cat > /root/xzapret/keys.json"
$SSH "systemctl restart xzap.service"

echo "=== Готово. Verify: ==="
echo | timeout 5 openssl s_client -connect $SUB.solar-cloud.xyz:443 -servername $SUB.solar-cloud.xyz 2>&1 | grep -E "subject=|Verification"
```

Snippets лежат в `docs/snippets/` (см. ниже).

## Verification checklist

После деплоя должно быть:

- [ ] `systemctl is-active xzap.service` → `active`
- [ ] `systemctl is-active nginx.service` → `active`
- [ ] `ss -tlnp | grep -E ":443|:9443"` → nginx на 0.0.0.0:443, xzap на 127.0.0.1:9443
- [ ] `dig relay-xx.solar-cloud.xyz +short` → правильный IP (с public resolver)
- [ ] `openssl s_client -connect relay-xx.solar-cloud.xyz:443 -servername relay-xx.solar-cloud.xyz` → Let's Encrypt cert, Verification OK
- [ ] `journalctl -u xzap.service | grep "users loaded"` → ожидаемое число юзеров
- [ ] `ufw status` → 22, 80, 443 ALLOW; всё остальное closed
- [ ] `fail2ban-client status sshd` → enabled
- [ ] Из telephone (новый APK с этим IP в Server-листе) — connect работает

## Decommission relay (если надо снять)

```bash
# Убрать IP из Server-поля Android UI
# Опционально на сервере:
systemctl stop xzap.service && systemctl disable xzap.service
ufw delete allow 443/tcp
# DNS-запись удалить в Porkbun
```

Никаких state'а внутри clients не остаётся — просто перестают ходить туда новые tunnel'ы.

## Troubleshooting deploy

### certbot fails with "connection timed out"
- Проверь что :80 открыт в ufw (`ufw status | grep 80`)
- Проверь что DNS пропагирован (`dig` отдаёт правильный IP)
- Проверь что nginx :80 default site работает (`curl http://relay-xx.solar-cloud.xyz`)

### xzap.service starts then immediately fails
- `journalctl -u xzap.service` → искать exception
- Часто: cert path неверный (опечатка в subdomain)
- Или: keys.json malformed

### nginx fails to load with stream config
- `nginx -T 2>&1 | grep error`
- Чаще всего: `libnginx-mod-stream` не установлен
- Исправить: `apt-get install -y libnginx-mod-stream && systemctl restart nginx`

### Подключение из Android клиента falls с TLS handshake timeout
- Сетевой block (Russian DPI блочит конкретный IP/range)
- Проверь с другого источника (Tokyo) — успех = клиентская сеть, fail = сервер
- Альтернатива: VPN-кофейня, mobile data switch
