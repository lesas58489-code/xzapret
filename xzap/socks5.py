"""
XZAP SOCKS5 Proxy — локальный SOCKS5 сервер.
Приложения (браузер, curl и др.) подключаются к localhost:1080.
Маршрутизатор решает: прямое TCP или через XZAP-туннель.

Протокол SOCKS5 (RFC 1928):
  1. Handshake: версия + метод аутентификации
  2. CONNECT запрос с целевым хостом/портом
  3. Ответ: успех/отказ
  4. Двунаправленная передача данных
"""

import asyncio
import struct
import logging
from typing import Callable, Awaitable
from .routing import XZAPRouter

log = logging.getLogger("xzap.socks5")

# SOCKS5 константы
VER = 5
CMD_CONNECT = 1
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_FAILURE = 1
REP_CMD_NOT_SUPPORTED = 7
REP_ATYP_NOT_SUPPORTED = 8

# Тип callback для XZAP-туннеля
XZAPConnectFn = Callable[[str, int], Awaitable[tuple]]


class SOCKS5Proxy:
    """Локальный SOCKS5 прокси с умной маршрутизацией."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1080,
                 router: XZAPRouter = None, xzap_connect: XZAPConnectFn = None):
        self.host = host
        self.port = port
        self.router = router or XZAPRouter()
        self.xzap_connect = xzap_connect  # None = XZAP пока недоступен
        self._server: asyncio.Server | None = None
        self._connections = 0

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        log.info("SOCKS5 proxy on %s:%d", self.host, self.port)

    async def serve_forever(self):
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ──────────────────────────────────────────────
    # Обработка одного клиентского подключения
    # ──────────────────────────────────────────────

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        self._connections += 1
        peer = writer.get_extra_info("peername")
        try:
            await self._handshake(reader, writer)
            hostname, port = await self._read_connect_request(reader, writer)
            if hostname is None:
                return

            use_xzap = self.router.should_use_xzap(hostname)
            label = "XZAP" if use_xzap else "DIRECT"
            log.info("[%s] %s:%d", label, hostname, port)

            if use_xzap and self.xzap_connect:
                remote_r, remote_w = await self.xzap_connect(hostname, port)
            else:
                remote_r, remote_w = await asyncio.open_connection(hostname, port)

            # Сообщаем клиенту об успехе
            await self._reply(writer, REP_SUCCESS, hostname, port)

            # Двунаправленный pipe
            await asyncio.gather(
                _pipe(reader, remote_w),
                _pipe(remote_r, writer),
                return_exceptions=True,
            )

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            log.debug("Error from %s: %s", peer, e)
        finally:
            _close(writer)
            self._connections -= 1

    # ──────────────────────────────────────────────
    # SOCKS5 протокол
    # ──────────────────────────────────────────────

    async def _handshake(self, reader, writer):
        """Шаг 1: согласование метода аутентификации (no auth)."""
        ver, nmethods = await reader.readexactly(2)
        if ver != VER:
            raise ValueError(f"Not SOCKS5 (ver={ver})")
        await reader.readexactly(nmethods)  # список методов — игнорируем
        writer.write(bytes([VER, 0x00]))    # выбираем «no auth»
        await writer.drain()

    async def _read_connect_request(self, reader, writer) -> tuple[str | None, int]:
        """Шаг 2: читаем CONNECT-запрос, возвращаем (hostname, port)."""
        ver, cmd, _, atyp = await reader.readexactly(4)

        if ver != VER or cmd != CMD_CONNECT:
            await self._reply(writer, REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0)
            return None, 0

        if atyp == ATYP_IPV4:
            raw = await reader.readexactly(4)
            hostname = ".".join(str(b) for b in raw)
        elif atyp == ATYP_DOMAIN:
            n = (await reader.readexactly(1))[0]
            hostname = (await reader.readexactly(n)).decode("utf-8")
        elif atyp == ATYP_IPV6:
            import ipaddress
            raw = await reader.readexactly(16)
            hostname = str(ipaddress.IPv6Address(raw))
        else:
            await self._reply(writer, REP_ATYP_NOT_SUPPORTED, "0.0.0.0", 0)
            return None, 0

        port = struct.unpack(">H", await reader.readexactly(2))[0]
        return hostname, port

    async def _reply(self, writer, rep: int, hostname: str, port: int):
        """Шаг 3: отправляем ответ SOCKS5."""
        host_b = hostname.encode()
        reply = bytes([VER, rep, 0x00, ATYP_DOMAIN, len(host_b)])
        reply += host_b + struct.pack(">H", port)
        writer.write(reply)
        await writer.drain()


# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    """Копируем данные src → dst до EOF."""
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    except Exception:
        pass
    finally:
        _close(dst)


def _close(writer: asyncio.StreamWriter):
    try:
        writer.close()
    except Exception:
        pass
