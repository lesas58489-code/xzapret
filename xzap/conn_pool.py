"""
XZAP Connection Pool — pre-established TLS connections.
TTL-based: connections expire after 240s (server timeout 300s).
Lazy replenish on get(). Dead connections cleaned on access.
"""

import asyncio
import logging
import time
from collections import deque

log = logging.getLogger("xzap.pool")

CONN_TTL = 240  # must be < server handshake timeout (300s)


class ConnectionPool:

    def __init__(self, server_host: str, server_port: int,
                 use_tls: bool = False, pool_size: int = 8):
        self.server_host = server_host
        self.server_port = server_port
        self.use_tls = use_tls
        self.pool_size = pool_size
        self._pool: deque = deque()  # (reader, writer, raw_writer, created_at)
        self._creating = 0

    async def start(self):
        log.info("Pool: warming %d connections (TTL=%ds)", self.pool_size, CONN_TTL)
        tasks = [self._create_one() for _ in range(self.pool_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("Pool: %d ready", len(self._pool))

    async def get(self):
        now = time.monotonic()
        while self._pool:
            reader, writer, raw_writer, created = self._pool.popleft()
            # Skip dead or expired
            if raw_writer.is_closing() or (now - created) > CONN_TTL:
                try:
                    raw_writer.close()
                except Exception:
                    pass
                continue
            # Good connection — replenish in background
            asyncio.create_task(self._create_one())
            return reader, writer, raw_writer
        # Empty — create on demand
        return await self._open_connection()

    async def _create_one(self):
        self._creating += 1
        try:
            r, w, rw = await asyncio.wait_for(self._open_connection(), timeout=10)
            self._pool.append((r, w, rw, time.monotonic()))
        except Exception:
            pass
        finally:
            self._creating -= 1

    async def _open_connection(self):
        from .transport.fragmented import wrap_connection
        if self.use_tls:
            from .tls import open_tls_connection, random_sni
            raw_reader, raw_writer = await open_tls_connection(
                self.server_host, self.server_port, sni=random_sni(),
            )
        else:
            raw_reader, raw_writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )
        sock = raw_writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        reader, writer = wrap_connection(raw_reader, raw_writer)
        return reader, writer, raw_writer
