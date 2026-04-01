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
from .tunnel import XZAPTunnelClient

log = logging.getLogger("xzap.client")


class XZAPClient:
    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM,
                 num_paths: int = 4, transport_type: str = "tcp"):
        self.server_host = server_host
        self.server_port = server_port
        self.transport_type = transport_type
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.obfuscator = Obfuscator(num_paths=num_paths)
        self.adaptive = AdaptiveStrategy()
        self.fragmenter = Fragmenter()
        self.recv_buffer = FragmentBuffer()
        self.transport = None
        self.router = XZAPRouter()
        self._seqno = 0

    async def connect(self):
        """Establish multi-path connections to server."""
        if self.transport_type == "ws":
            from .transport.ws import WSMultiPathTransport, build_ws_urls
            urls = build_ws_urls(
                self.server_host, self.server_port,
                self.obfuscator.active_snis,
            )
            self.transport = WSMultiPathTransport(urls)
        else:
            self.transport = MultiPathTransport(
                self.server_host, self.server_port, self.obfuscator.active_snis
            )
        await self.transport.connect_all()
        log.info("Connected [%s] via %d paths",
                 self.transport_type, self.transport.num_paths)

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

    async def proxy_connect(self, hostname: str, port: int):
        """Открывает туннель к hostname:port через XZAP-сервер.
        Возвращает XZAPTunnelStream с методами read/write.
        """
        tunnel = XZAPTunnelClient(
            self.server_host, self.server_port,
            key=self.crypto.key, algo=self.crypto.algo,
        )
        stream = await tunnel.connect_tunnel(hostname, port)
        log.debug("Tunnel open → %s:%d", hostname, port)
        return stream

    def make_socks5(self, host: str = "127.0.0.1", port: int = 1080):
        """Создаёт SOCKS5-прокси, привязанный к этому клиенту."""
        from .socks5 import SOCKS5Proxy

        async def xzap_connect(hostname, port):
            stream = await self.proxy_connect(hostname, port)
            # Оборачиваем XZAPTunnelStream в asyncio StreamReader/Writer
            return _stream_to_asyncio(stream)

        return SOCKS5Proxy(
            host=host, port=port,
            router=self.router,
            xzap_connect=xzap_connect,
        )

    async def close(self):
        if self.transport:
            await self.transport.close_all()
            log.info("Disconnected")


def _stream_to_asyncio(stream):
    """Адаптер XZAPTunnelStream → (asyncio.StreamReader, asyncio.StreamWriter)."""
    import asyncio

    r_transport, w_transport = None, None
    reader = asyncio.StreamReader()

    class _Writer:
        def write(self, data):
            asyncio.ensure_future(stream.write(data))

        async def drain(self):
            pass

        def close(self):
            asyncio.ensure_future(stream.close())

        async def wait_closed(self):
            await stream.close()

    # Запускаем фоновую задачу: читаем из туннеля → кладём в reader
    async def _feed():
        try:
            while True:
                data = await stream.read()
                if not data:
                    break
                reader.feed_data(data)
        except Exception:
            pass
        finally:
            reader.feed_eof()

    asyncio.ensure_future(_feed())
    return reader, _Writer()
