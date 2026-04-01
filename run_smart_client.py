"""
Пример умного клиента XZAP с split tunneling.
Российские сайты идут напрямую, заблокированные — через XZAP.
"""

import asyncio
import logging
from xzap.client import XZAPClient

logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")


async def main():
    client = XZAPClient(
        server_host="your-server.example.com",  # замените на адрес своего сервера
        server_port=443,
    )

    # Загружаем списки доменов
    await client.router.load_lists(
        bypass_file="lists/bypass.txt",  # российские сайты — напрямую
        xzap_file="lists/xzap.txt",      # заблокированные — через XZAP
    )

    # Тест маршрутизации
    test_domains = [
        "www.youtube.com",
        "vk.com",
        "mail.ru",
        "instagram.com",
        "sub.avito.ru",
        "discord.com",
    ]

    print("\nМаршрутизация доменов:")
    print("-" * 40)
    for domain in test_domains:
        use_xzap = client.router.should_use_xzap(domain)
        route = "→ XZAP" if use_xzap else "→ DIRECT"
        print(f"  {domain:<30} {route}")


if __name__ == "__main__":
    asyncio.run(main())
