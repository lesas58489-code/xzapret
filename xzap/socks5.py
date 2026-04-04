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


class SOCKS5Proxy:
    """Локальный SOCKS5 прокси с умной маршрутизацией."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1080,
                 router: XZAPRouter = None,
                 xzap_connect=None):
        """
        xzap_connect: async (hostname, port) -> XZAPTunnelStream
            Возвращает объект с методами read() -> bytes и write(bytes).
        """
        self.host = host
        self.port = port
        self.router = router or XZAPRouter()
        self.xzap_connect = xzap_connect
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
                # Через XZAP-туннель
                try:
                    stream = await asyncio.wait_for(
                        self.xzap_connect(hostname, port), timeout=15
                    )
                except Exception as e:
                    log.error("XZAP tunnel failed for %s:%d: %s", hostname, port, e)
                    await self._reply(writer, REP_FAILURE, hostname, port)
                    return

                await self._reply(writer, REP_SUCCESS, hostname, port)

                # Pipe: клиент ↔ XZAP tunnel stream
                await asyncio.gather(
                    _pipe_reader_to_stream(reader, stream),
                    _pipe_stream_to_writer(stream, writer),
                    return_exceptions=True,
                )
            else:
                # Прямое TCP подключение
                try:
                    remote_r, remote_w = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port), timeout=10
                    )
                except Exception as e:
                    log.error("Direct connect failed for %s:%d: %s", hostname, port, e)
                    await self._reply(writer, REP_FAILURE, hostname, port)
                    return

                await self._reply(writer, REP_SUCCESS, hostname, port)

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
        ver, nmethods = await reader.readexactly(2)
        if ver != VER:
            raise ValueError(f"Not SOCKS5 (ver={ver})")
        await reader.readexactly(nmethods)
        writer.write(bytes([VER, 0x00]))
        await writer.drain()

    async def _read_connect_request(self, reader, writer) -> tuple[str | None, int]:
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
        host_b = hostname.encode()
        reply = bytes([VER, rep, 0x00, ATYP_DOMAIN, len(host_b)])
        reply += host_b + struct.pack(">H", port)
        writer.write(reply)
        await writer.drain()


# ──────────────────────────────────────────────
# Pipe функции
# ──────────────────────────────────────────────

async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    """TCP → TCP pipe."""
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    except Exception:
        pass
    finally:
        _close(dst)


async def _pipe_reader_to_stream(reader: asyncio.StreamReader, stream):
    """TCP reader → XZAP tunnel stream (write)."""
    try:
        while chunk := await reader.read(65536):
            await stream.write(chunk)
    except Exception:
        pass
    finally:
        try:
            await stream.close()
        except Exception:
            pass


async def _pipe_stream_to_writer(stream, writer: asyncio.StreamWriter):
    """XZAP tunnel stream (read) → TCP writer."""
    try:
        while True:
            data = await stream.read()
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        _close(writer)


def _close(writer: asyncio.StreamWriter):
    try:
        writer.close()
    except Exception:
        pass
