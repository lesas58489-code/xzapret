"""
XZAP Server — listens for connections, reassembles fragments, decrypts messages.

Поддерживает два транспорта (transport_type):
  "tcp" — обычный TCP (по умолчанию)
  "ws"  — WebSocket (выглядит как HTTPS, проходит через прокси и CDN)
"""

import asyncio
import logging

from .message import XZAPMessage
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .fragmentation import Fragment, FragmentBuffer
from .obfuscation import Obfuscator
from .transport import XZAPListener

log = logging.getLogger("xzap.server")


class XZAPServer:
    def __init__(self, host: str, port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM,
                 transport_type: str = "tcp",
                 on_message=None):
        self.host = host
        self.port = port
        self.transport_type = transport_type
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.obfuscator = Obfuscator()
        self.on_message = on_message  # async callback(plaintext: bytes)

        if transport_type == "tcp":
            self.listener = XZAPListener(host, port)
        elif transport_type == "ws":
            from .transport.ws import WSTransport
            self.listener = WSTransport(host=host, port=port, path="/xzap")
        else:
            raise ValueError(f"Unknown transport_type: {transport_type!r}")

    async def start(self):
        if self.transport_type == "tcp":
            await self.listener.start(self._handle_tcp)
        else:
            await self.listener.serve(self._handle_ws)
        log.info("XZAP server ready [%s] on %s:%d",
                 self.transport_type, self.host, self.port)

    async def serve_forever(self):
        await self.listener.serve_forever()

    async def stop(self):
        await self.listener.stop()

    # ──────────────────────────────────────────────
    # TCP handler
    # ──────────────────────────────────────────────

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        log.info("TCP connection from %s", addr)
        recv_buf = FragmentBuffer()
        try:
            while True:
                header = await reader.readexactly(2)
                length = int.from_bytes(header, "big")
                raw = await reader.readexactly(length)
                plaintext = self._process_fragment(raw, recv_buf)
                if plaintext is not None and self.on_message:
                    await self.on_message(plaintext)
        except asyncio.IncompleteReadError:
            log.info("TCP disconnected: %s", addr)
        except Exception as e:
            log.error("TCP error from %s: %s", addr, e)
        finally:
            writer.close()

    # ──────────────────────────────────────────────
    # WebSocket handler
    # ──────────────────────────────────────────────

    async def _handle_ws(self, conn):
        """Обработчик WS-соединения. conn — _WSServerConn с send/recv."""
        recv_buf = FragmentBuffer()
        try:
            while True:
                raw = await conn.recv()
                plaintext = self._process_fragment(raw, recv_buf)
                if plaintext is not None and self.on_message:
                    await self.on_message(plaintext)
        except Exception as e:
            log.debug("WS connection closed: %s", e)

    # ──────────────────────────────────────────────
    # Общая логика: разбор фрагмента → plaintext
    # ──────────────────────────────────────────────

    def _process_fragment(self, raw: bytes,
                           recv_buf: FragmentBuffer) -> bytes | None:
        fragment = Fragment.unpack(raw)
        assembled = recv_buf.add(fragment)
        if assembled is None:
            return None
        assembled = self.obfuscator.strip_prefix(assembled)
        msg = XZAPMessage.unpack(assembled)
        plaintext = self.crypto.decrypt(msg.payload, aad=msg.aad())
        log.debug("Message seqno=%d (%dB)", msg.seqno, len(plaintext))
        return plaintext
