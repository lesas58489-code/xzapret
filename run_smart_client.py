"""
XZAP Smart Client — запуск локального SOCKS5-прокси с умной маршрутизацией.

Использование:
  python3 run_smart_client.py --server your-vps.com --port 8443

  # С WebSocket транспортом:
  python3 run_smart_client.py --server your-vps.com --port 443 --transport ws

  # С указанием ключа:
  export XZAP_KEY="base64-ключ-с-сервера"
  python3 run_smart_client.py --server your-vps.com

После запуска настройте браузер/систему:
  SOCKS5 прокси → 127.0.0.1:1080
"""

import asyncio
import argparse
import base64
import logging
import os
from pathlib import Path

from xzap.client import XZAPClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
# Suppress noisy Windows IocpProactor socket shutdown errors
logging.getLogger("asyncio").setLevel(logging.CRITICAL)


def load_key(key_file: str) -> bytes | None:
    """Загрузить ключ из env, файла или вернуть None."""
    # 1. Из переменной окружения
    env_key = os.environ.get("XZAP_KEY")
    if env_key:
        return base64.b64decode(env_key)
    # 2. Из файла
    p = Path(key_file)
    if p.exists():
        return p.read_bytes()
    return None


async def main(args):
    key = load_key(args.key_file)
    if not key:
        print(f"Ошибка: ключ не найден!")
        print(f"  Укажите через: export XZAP_KEY=\"base64-ключ\"")
        print(f"  Или положите файл: {args.key_file}")
        print(f"  Ключ генерируется на сервере: python3 run_server.py --gen-key")
        return

    client = XZAPClient(
        server_host=args.server,
        server_port=args.port,
        key=key,
        transport_type=args.transport,
        use_tls=args.tls,
        ws_url=getattr(args, 'ws_url', None),
    )

    # Загружаем списки доменов
    await client.router.load_lists(
        bypass_file="lists/bypass.txt",
        xzap_file="lists/xzap.txt",
    )

    # Демонстрация маршрутизации
    test_domains = [
        "youtube.com", "vk.com", "instagram.com",
        "discord.com", "gosuslugi.ru", "google.com",
    ]
    if args.ws_url:
        print(f"\nСервер: {args.ws_url} [WebSocket/CDN]")
    else:
        tls_label = " + TLS/SNI" if args.tls else ""
        print(f"\nСервер: {args.server}:{args.port} [{args.transport}{tls_label}]")
    print(f"\nМаршрутизация:")
    print("-" * 42)
    for domain in test_domains:
        use_xzap = client.router.should_use_xzap(domain)
        label = "→ XZAP " if use_xzap else "→ DIRECT"
        print(f"  {domain:<30} {label}")

    # Connection pool (pre-establish TLS connections)
    await client.init_pool()

    # Запускаем SOCKS5-прокси
    proxy = client.make_socks5("127.0.0.1", args.socks_port)
    await proxy.start()

    print(f"\nSOCKS5 прокси: 127.0.0.1:{args.socks_port}")
    print("Ctrl+C для остановки\n")

    await proxy.serve_forever()


def cli():
    parser = argparse.ArgumentParser(description="XZAP Client")
    parser.add_argument("--server", required=True, help="XZAP server address")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--transport", choices=["tcp", "ws"], default="tcp")
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--tls", action="store_true",
                        help="Use TLS with random SNI (white domains)")
    parser.add_argument("--ws-url", default=None,
                        help="WebSocket URL (e.g. wss://solar-cloud.xyz/tunnel)")
    parser.add_argument("--key-file", default="xzap.key")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        asyncio.run(main(cli()))
    except KeyboardInterrupt:
        print("\nОстановлено.")
