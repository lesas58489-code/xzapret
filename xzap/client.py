"""
XZAP Client — connects to server, encrypts, fragments, and sends data
across multiple SNI paths with adaptive obfuscation.
"""

import asyncio
import logging

from .message import XZAPMessage
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .fragmentation import Fragmenter, FragmentBuffer
from .obfuscation import Obfuscator
from .adaptive import AdaptiveStrategy
from .transport import MultiPathTransport
from .routing import XZAPRouter

log = logging.getLogger("xzap.client")


class XZAPClient:
    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM,
                 num_paths: int = 4):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.obfuscator = Obfuscator(num_paths=num_paths)
        self.adaptive = AdaptiveStrategy()
        self.fragmenter = Fragmenter()
        self.recv_buffer = FragmentBuffer()
        self.transport: MultiPathTransport | None = None
        self.router = XZAPRouter()
        self._seqno = 0

    async def connect(self):
        """Establish multi-path connections to server."""
        self.transport = MultiPathTransport(
            self.server_host, self.server_port, self.obfuscator.active_snis
        )
        await self.transport.connect_all()
        log.info("Connected via %d paths", self.transport.num_paths)

    async def send(self, data: bytes):
        """Encrypt, fragment, and send data across paths."""
        if not self.transport:
            raise RuntimeError("Not connected — call connect() first")

        cfg = self.adaptive.config

        # Update fragmenter sizes from adaptive strategy
        self.fragmenter.min_size = cfg.min_frag
        self.fragmenter.max_size = cfg.max_frag

        # Encrypt
        msg = XZAPMessage(data, seqno=self._seqno)
        self._seqno += 1
        encrypted = self.crypto.encrypt(msg.payload, aad=msg.aad())
        msg.payload = encrypted
        packed = msg.pack()

        # Add random prefix
        packed = self.obfuscator.add_prefix(packed)

        # Fragment
        fragments = self.fragmenter.fragment(msg.msg_id, packed)
        if cfg.disorder:
            fragments = self.fragmenter.disorder(fragments)

        # Send with repeats (adaptive)
        for _repeat in range(cfg.repeats):
            for frag in fragments:
                path_idx = Fragmenter.assign_path(
                    msg.msg_id, frag.index, self.transport.num_paths
                )
                try:
                    await self.transport.send_on_path(path_idx, frag.pack())
                except Exception as e:
                    log.warning("Send failed on path %d: %s", path_idx, e)
                    self.adaptive.on_retransmit()
                else:
                    self.adaptive.on_success()

        log.debug("Sent msg seqno=%d (%d fragments, level=%d)",
                  msg.seqno, len(fragments), self.adaptive.level)

    async def smart_connect(self, hostname: str, port: int = 443):
        """Умное подключение: прямое или через XZAP в зависимости от домена.
        Возвращает (reader, writer, is_xzap).
        """
        use_xzap = self.router.should_use_xzap(hostname)
        if not use_xzap:
            reader, writer = await self.router.open_direct(hostname, port)
            return reader, writer, False

        # Через XZAP
        log.debug("XZAP route → %s:%d", hostname, port)
        if not self.transport:
            await self.connect()
        # Возвращаем заглушку — полная интеграция прокси в следующем шаге
        raise NotImplementedError(
            "XZAP proxy integration (SOCKS5/HTTP CONNECT) will be added next"
        )

    async def close(self):
        if self.transport:
            await self.transport.close_all()
            log.info("Disconnected")
