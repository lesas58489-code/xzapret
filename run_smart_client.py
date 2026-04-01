"""
XZAP Smart Client — запуск локального SOCKS5-прокси с умной маршрутизацией.

Использование:
  python3 run_smart_client.py

После запуска настройте браузер/систему:
  SOCKS5 прокси → 127.0.0.1:1080

Российские сайты (lists/bypass.txt) → прямое соединение
Заблокированные сайты (lists/xzap.txt) → через XZAP-туннель
"""

import asyncio
import logging
from xzap.client import XZAPClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

XZAP_SERVER = "your-server.example.com"  # замените на адрес вашего сервера
XZAP_PORT = 443
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 1080


async def main():
    client = XZAPClient(XZAP_SERVER, XZAP_PORT)

    # Загружаем списки доменов
    await client.router.load_lists(
        bypass_file="lists/bypass.txt",
        xzap_file="lists/xzap.txt",
    )

    # Демонстрация маршрутизации
    test_domains = [
        "www.youtube.com", "vk.com", "mail.ru",
        "instagram.com", "discord.com", "gosuslugi.ru",
    ]
    print("\nМаршрутизация доменов:")
    print("-" * 42)
    for domain in test_domains:
        use_xzap = client.router.should_use_xzap(domain)
        label = "→ XZAP " if use_xzap else "→ DIRECT"
        print(f"  {domain:<30} {label}")

    # Запускаем SOCKS5-прокси
    proxy = client.make_socks5(SOCKS5_HOST, SOCKS5_PORT)
    await proxy.start()

    print(f"\nSOCKS5 прокси запущен: {SOCKS5_HOST}:{SOCKS5_PORT}")
    print("Настройте браузер: SOCKS5 → 127.0.0.1:1080")
    print("Ctrl+C для остановки\n")

    await proxy.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nОстановлено.")
