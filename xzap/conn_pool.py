"""
XZAP Connection Pool — pre-established TLS connections.
Simple version: 8 connections, lazy replenish on get().
"""

import asyncio
import logging
from collections import deque

log = logging.getLogger("xzap.pool")


class ConnectionPool:

    def __init__(self, server_host: str, server_port: int,
                 use_tls: bool = False, pool_size: int = 8):
        self.server_host = server_host
        self.server_port = server_port
        self.use_tls = use_tls
        self.pool_size = pool_size
        self._pool: deque = deque()
        self._creating = 0

    async def start(self):
        log.info("Pool: warming %d connections", self.pool_size)
        tasks = [self._create_one() for _ in range(self.pool_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("Pool: %d ready", len(self._pool))

    async def get(self):
        while self._pool:
            reader, writer, raw_writer = self._pool.popleft()
            if not raw_writer.is_closing():
                # Replenish in background
                asyncio.create_task(self._create_one())
                return reader, writer, raw_writer
        # Empty — create on demand
        return await self._open_connection()

    async def _create_one(self):
        self._creating += 1
        try:
            conn = await asyncio.wait_for(self._open_connection(), timeout=10)
            self._pool.append(conn)
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
