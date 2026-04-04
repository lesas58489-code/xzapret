"""
XZAP Tunnel Protocol — туннелирование TCP-соединений через XZAP.

Простой протокол поверх TCP с шифрованием:
  1. Клиент подключается к XZAP-серверу
  2. Отправляет зашифрованный CONNECT-запрос: {"cmd":"connect","host":"...","port":N}
  3. Сервер подключается к цели и отвечает: {"ok":true} или {"ok":false,"err":"..."}
  4. Далее — зашифрованные фреймы: [4B length][encrypted data]

Фрагментация НЕ используется в tunnel mode для надёжности.
"""

import asyncio
import json
import struct
import os
import logging
from .crypto import XZAPCrypto, ALGO_AES_GCM

log = logging.getLogger("xzap.tunnel")

# Frame format: [4 bytes length (big-endian)][encrypted payload]
FRAME_HDR = 4
MAX_FRAME_SIZE = 256 * 1024  # 256 KB


async def _send_frame(writer: asyncio.StreamWriter, crypto: XZAPCrypto,
                       data: bytes):
    """Encrypt data and send as a length-prefixed frame."""
    encrypted = crypto.encrypt(data)
    writer.write(struct.pack(">I", len(encrypted)) + encrypted)
    await writer.drain()


async def _recv_frame(reader: asyncio.StreamReader,
                       crypto: XZAPCrypto) -> bytes:
    """Read a length-prefixed frame and decrypt."""
    hdr = await reader.readexactly(FRAME_HDR)
    length = struct.unpack(">I", hdr)[0]
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length}")
    encrypted = await reader.readexactly(length)
    return crypto.decrypt(encrypted)


class XZAPTunnelClient:
    """Открывает туннель к target_host:target_port через XZAP-сервер."""

    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect_tunnel(self, target_host: str, target_port: int):
        """
        Подключается к XZAP-серверу и открывает туннель к target.
        Возвращает XZAPTunnelStream с методами read/write/close.
        """
        self._reader, self._writer = await asyncio.open_connection(
            self.server_host, self.server_port
        )

        # Отправляем CONNECT-запрос
        req = json.dumps({
            "cmd": "connect",
            "host": target_host,
            "port": target_port,
        }).encode()
        await _send_frame(self._writer, self.crypto, req)

        # Читаем ответ сервера
        response_raw = await _recv_frame(self._reader, self.crypto)
        response = json.loads(response_raw)
        if not response.get("ok"):
            err = response.get("err", "unknown error")
            raise ConnectionError(f"XZAP tunnel refused: {err}")

        log.info("Tunnel open → %s:%d", target_host, target_port)
        return XZAPTunnelStream(self._reader, self._writer, self.crypto)


class XZAPTunnelStream:
    """Поток данных поверх открытого XZAP-туннеля."""

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 crypto: XZAPCrypto):
        self._reader = reader
        self._writer = writer
        self._crypto = crypto

    async def write(self, data: bytes):
        await _send_frame(self._writer, self._crypto, data)

    async def read(self) -> bytes:
        return await _recv_frame(self._reader, self._crypto)

    async def close(self):
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass


class XZAPTunnelServer:
    """
    Серверная сторона туннеля.
    Принимает зашифрованные фреймы, обрабатывает CONNECT,
    проксирует данные к реальному хосту.
    """

    def __init__(self, crypto: XZAPCrypto, obfuscator=None):
        self.crypto = crypto
        # obfuscator kept for API compatibility, not used in tunnel

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter):
        """Обработчик одного туннельного соединения."""
        addr = writer.get_extra_info("peername")
        log.debug("Tunnel connection from %s", addr)

        try:
            # Читаем CONNECT-запрос
            ctrl = await _recv_frame(reader, self.crypto)
            req = json.loads(ctrl)
            if req.get("cmd") != "connect":
                await _send_frame(writer, self.crypto,
                                   json.dumps({"ok": False, "err": "bad cmd"}).encode())
                return

            target_host = req["host"]
            target_port = int(req["port"])

            # Подключаемся к цели
            try:
                target_r, target_w = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=10,
                )
            except Exception as e:
                await _send_frame(writer, self.crypto,
                                   json.dumps({"ok": False, "err": str(e)}).encode())
                return

            await _send_frame(writer, self.crypto,
                               json.dumps({"ok": True}).encode())
            log.info("Tunnelling → %s:%d", target_host, target_port)

            # Двунаправленный pipe: XZAP-клиент ↔ реальный хост
            async def xzap_to_target():
                try:
                    while True:
                        data = await _recv_frame(reader, self.crypto)
                        log.debug("xzap→target: %d bytes", len(data))
                        target_w.write(data)
                        await target_w.drain()
                except Exception as e:
                    log.debug("xzap→target ended: %s", e)

            async def target_to_xzap():
                try:
                    while chunk := await target_r.read(65536):
                        log.debug("target→xzap: %d bytes", len(chunk))
                        await _send_frame(writer, self.crypto, chunk)
                    log.debug("target→xzap: EOF")
                except Exception as e:
                    log.debug("target→xzap ended: %s", e)

            await asyncio.gather(
                xzap_to_target(),
                target_to_xzap(),
            )

        except Exception as e:
            log.debug("Tunnel error: %s", e)
        finally:
            writer.close()
