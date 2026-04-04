"""
XZAP Tunnel Protocol — туннелирование TCP-соединений через XZAP.

Протокол:
  1. Клиент подключается к XZAP-серверу (MultiPathTransport)
  2. Первое зашифрованное сообщение: JSON {"cmd":"connect","host":"...","port":N}
  3. Сервер подключается к цели и отвечает: {"ok":true} или {"ok":false,"err":"..."}
  4. Далее — сырые данные через XZAP-канал

XZAPTunnelClient: создаёт туннель к конкретному хосту.
XZAPTunnelServer: на сервере принимает туннельные запросы и проксирует их.
"""

import asyncio
import json
import logging
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .fragmentation import Fragmenter, FragmentBuffer
from .obfuscation import Obfuscator
from .message import XZAPMessage
from .transport import XZAPConnection

log = logging.getLogger("xzap.tunnel")

_CTRL_MAXLEN = 4096  # максимальная длина управляющего сообщения


class XZAPTunnelClient:
    """Открывает туннель к target_host:target_port через XZAP-сервер."""

    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.fragmenter = Fragmenter(
            overlap=0, padding_chance=0, chaff_chance=0, disorder=False,
        )
        self.obfuscator = Obfuscator(num_paths=1)
        self._conn: XZAPConnection | None = None
        self._seqno = 0
        self._recv_buf = FragmentBuffer()

    async def connect_tunnel(self, target_host: str, target_port: int):
        """
        Подключается к XZAP-серверу и открывает туннель к target.
        Возвращает (XZAPTunnelStream) — объект с методами read/write.
        """
        self._conn = XZAPConnection(self.server_host, self.server_port)
        await self._conn.connect()

        # Отправляем CONNECT-запрос
        await self._send_msg(json.dumps({
            "cmd": "connect",
            "host": target_host,
            "port": target_port,
        }).encode())

        # Читаем ответ сервера
        response_raw = await self._recv_msg()
        response = json.loads(response_raw)
        if not response.get("ok"):
            err = response.get("err", "unknown error")
            raise ConnectionError(f"XZAP tunnel refused: {err}")

        log.info("Tunnel open → %s:%d", target_host, target_port)
        return XZAPTunnelStream(self)

    async def _send_msg(self, data: bytes):
        msg = XZAPMessage(data, seqno=self._seqno)
        self._seqno += 1
        encrypted = self.crypto.encrypt(msg.payload, aad=msg.aad())
        msg.payload = encrypted
        packed = self.obfuscator.add_prefix(msg.pack())
        frags = self.fragmenter.fragment(msg.msg_id, packed)
        for frag in frags:
            await self._conn.send(frag.pack())

    async def _recv_msg(self) -> bytes:
        """Получаем одно полное сообщение (собираем из фрагментов)."""
        from .fragmentation import Fragment
        while True:
            raw = await self._conn.recv()
            frag = Fragment.unpack(raw)
            assembled = self._recv_buf.add(frag)
            if assembled is not None:
                assembled = self.obfuscator.strip_prefix(assembled)
                msg = XZAPMessage.unpack(assembled)
                return self.crypto.decrypt(msg.payload, aad=msg.aad())


class XZAPTunnelStream:
    """Поток данных поверх открытого XZAP-туннеля."""

    def __init__(self, tunnel: XZAPTunnelClient):
        self._tunnel = tunnel

    async def write(self, data: bytes):
        await self._tunnel._send_msg(data)

    async def read(self) -> bytes:
        return await self._tunnel._recv_msg()

    async def close(self):
        if self._tunnel._conn:
            await self._tunnel._conn.close()


class XZAPTunnelServer:
    """
    Серверная сторона туннеля.
    Принимает зашифрованные сообщения, обрабатывает CONNECT,
    проксирует данные к реальному хосту.
    """

    def __init__(self, crypto: XZAPCrypto, obfuscator: Obfuscator):
        self.crypto = crypto
        self.obfuscator = obfuscator

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter):
        """Обработчик одного туннельного соединения."""
        fragmenter = Fragmenter(
            overlap=0, padding_chance=0, chaff_chance=0, disorder=False,
        )
        recv_buf = FragmentBuffer()
        seqno = 0

        async def recv_msg() -> bytes:
            from .fragmentation import Fragment
            while True:
                # length-prefixed fragment
                header = await reader.readexactly(2)
                length = int.from_bytes(header, "big")
                raw = await reader.readexactly(length)
                frag = Fragment.unpack(raw)
                assembled = recv_buf.add(frag)
                if assembled is not None:
                    assembled = self.obfuscator.strip_prefix(assembled)
                    msg = XZAPMessage.unpack(assembled)
                    return self.crypto.decrypt(msg.payload, aad=msg.aad())

        async def send_msg(data: bytes):
            nonlocal seqno
            msg = XZAPMessage(data, seqno=seqno)
            seqno += 1
            encrypted = self.crypto.encrypt(msg.payload, aad=msg.aad())
            msg.payload = encrypted
            packed = self.obfuscator.add_prefix(msg.pack())
            frags = fragmenter.fragment(msg.msg_id, packed)
            for frag in frags:
                frag_raw = frag.pack()
                writer.write(len(frag_raw).to_bytes(2, "big") + frag_raw)
            await writer.drain()

        try:
            # Читаем CONNECT-запрос
            ctrl = await recv_msg()
            req = json.loads(ctrl)
            if req.get("cmd") != "connect":
                await send_msg(json.dumps({"ok": False, "err": "bad cmd"}).encode())
                return

            target_host = req["host"]
            target_port = int(req["port"])

            # Подключаемся к цели
            try:
                target_r, target_w = await asyncio.open_connection(
                    target_host, target_port
                )
            except Exception as e:
                await send_msg(json.dumps({"ok": False, "err": str(e)}).encode())
                return

            await send_msg(json.dumps({"ok": True}).encode())
            log.info("Tunnelling → %s:%d", target_host, target_port)

            # Двунаправленный pipe: XZAP-клиент ↔ реальный хост
            async def xzap_to_target():
                try:
                    while True:
                        data = await recv_msg()
                        log.debug("xzap→target: %d bytes", len(data))
                        target_w.write(data)
                        await target_w.drain()
                except Exception as e:
                    log.debug("xzap→target ended: %s", e)

            async def target_to_xzap():
                try:
                    while chunk := await target_r.read(65536):
                        log.debug("target→xzap: %d bytes", len(chunk))
                        await send_msg(chunk)
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
