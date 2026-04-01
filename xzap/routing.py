"""
XZAP Routing — умная маршрутизация (split tunneling).
Решает для каждого домена/IP: идти напрямую или через XZAP.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set, Dict

log = logging.getLogger("xzap.routing")


@dataclass
class RouteRule:
    domain: str
    use_xzap: bool  # True = через XZAP, False = напрямую


class XZAPRouter:
    def __init__(self):
        self.bypass_domains: Set[str] = set()   # российские и «хорошие» сайты
        self.xzap_domains: Set[str] = set()     # заблокированные сайты
        self._cache: Dict[str, bool] = {}       # domain → use_xzap

    async def load_lists(self, bypass_file: str | Path = None,
                         xzap_file: str | Path = None):
        """Загружает списки доменов из файлов (по одному домену на строку)."""
        if bypass_file:
            p = Path(bypass_file)
            if p.exists():
                lines = p.read_text(encoding="utf-8").splitlines()
                self.bypass_domains.update(
                    line.strip().lower() for line in lines if line.strip()
                )
                log.info("Loaded %d bypass domains", len(self.bypass_domains))

        if xzap_file:
            p = Path(xzap_file)
            if p.exists():
                lines = p.read_text(encoding="utf-8").splitlines()
                self.xzap_domains.update(
                    line.strip().lower() for line in lines if line.strip()
                )
                log.info("Loaded %d xzap domains", len(self.xzap_domains))

        self._cache.clear()

    def should_use_xzap(self, hostname: str) -> bool:
        """True = идти через XZAP, False = напрямую."""
        hostname = hostname.lower().strip()

        if hostname in self._cache:
            return self._cache[hostname]

        # Точное совпадение
        if hostname in self.xzap_domains:
            self._cache[hostname] = True
            return True
        if hostname in self.bypass_domains:
            self._cache[hostname] = False
            return False

        # Проверка родительских доменов (www.youtube.com → youtube.com → com)
        parts = hostname.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.xzap_domains:
                self._cache[hostname] = True
                return True
            if parent in self.bypass_domains:
                self._cache[hostname] = False
                return False

        # По умолчанию — через XZAP (безопаснее)
        self._cache[hostname] = True
        return True

    async def open_direct(self, hostname: str, port: int):
        """Прямое подключение, минуя XZAP."""
        log.debug("DIRECT → %s:%d", hostname, port)
        return await asyncio.open_connection(hostname, port)
