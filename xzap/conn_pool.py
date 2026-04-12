"""
XZAP Connection Pool — pre-established TLS connections for instant tunneling.

Instead of TCP+TLS+fragmentation handshake per request (~600ms),
grab a warm connection from the pool (~0ms).

Pool replenishes in background. Target size: 8 connections.
"""

import asyncio
import logging
from collections import deque

log = logging.getLogger("xzap.pool")


class ConnectionPool:
    """Pool of pre-established TLS+fragmented connections to XZAP server."""

    def __init__(self, server_host: str, server_port: int,
                 use_tls: bool = False, pool_size: int = 8):
        self.server_host = server_host
        self.server_port = server_port
        self.use_tls = use_tls
        self.pool_size = pool_size
        self._pool: deque = deque()
        self._creating = 0  # connections being created
        self._lock = asyncio.Lock()
        self._replenish_task = None

    async def start(self):
        """Pre-fill the pool."""
        log.info("Pool: warming %d connections to %s:%d",
                 self.pool_size, self.server_host, self.server_port)
        tasks = [self._create_one() for _ in range(self.pool_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("Pool: %d connections ready", len(self._pool))

    async def get(self):
        """Get a (reader, writer, raw_writer) tuple from the pool.
        If pool is empty, create one on demand.
        """
        # Try to get from pool
        async with self._lock:
            while self._pool:
                conn = self._pool.popleft()
                reader, writer, raw_writer = conn
                # Check if still alive
                if not raw_writer.is_closing():
                    self._schedule_replenish()
                    return reader, writer, raw_writer
                # Dead connection, skip

        # Pool empty — create on demand
        log.debug("Pool empty, creating on demand")
        return await self._open_connection()

    def _schedule_replenish(self):
        """Schedule background replenishment."""
        if self._replenish_task is None or self._replenish_task.done():
            self._replenish_task = asyncio.create_task(self._replenish())

    async def _replenish(self):
        """Fill pool back to target size."""
        await asyncio.sleep(0.1)  # small delay to batch
        needed = self.pool_size - len(self._pool) - self._creating
        if needed <= 0:
            return
        tasks = [self._create_one() for _ in range(needed)]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _create_one(self):
        """Create one connection and add to pool."""
        self._creating += 1
        try:
            conn = await self._open_connection()
            async with self._lock:
                self._pool.append(conn)
        except Exception as e:
            log.debug("Pool: failed to create connection: %s", e)
        finally:
            self._creating -= 1

    async def _open_connection(self):
        """Open TCP+TLS+fragmented connection."""
        from .transport.fragmented import wrap_connection

        if self.use_tls:
            from .tls import open_tls_connection, random_sni
            sni = random_sni()
            raw_reader, raw_writer = await open_tls_connection(
                self.server_host, self.server_port, sni=sni,
            )
        else:
            raw_reader, raw_writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )

        sock = raw_writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Fragmentation layer
        reader, writer = wrap_connection(raw_reader, raw_writer)
        return reader, writer, raw_writer

    async def close(self):
        """Close all pooled connections."""
        async with self._lock:
            while self._pool:
                _, _, raw_writer = self._pool.popleft()
                try:
                    raw_writer.close()
                except Exception:
                    pass
