"""
XZAP Connection Pool — pre-established TLS connections for instant tunneling.

Optimizations:
  - 16 warm connections (enough for heavy page loads)
  - Replenish when pool drops below 50% (not when empty)
  - Continuous background replenishment
  - Keepalive: prune dead connections every 30s
"""

import asyncio
import logging
import time
from collections import deque

log = logging.getLogger("xzap.pool")

CONN_TTL = 90  # seconds — must be < server handshake timeout (120s)


class ConnectionPool:
    """Pool of pre-established TLS+fragmented connections to XZAP server."""

    def __init__(self, server_host: str, server_port: int,
                 use_tls: bool = False, pool_size: int = 10):
        self.server_host = server_host
        self.server_port = server_port
        self.use_tls = use_tls
        self.pool_size = pool_size
        self._pool: deque = deque()  # (reader, writer, raw_writer, created_at)
        self._creating = 0
        self._lock = asyncio.Lock()
        self._keepalive_task = None

    async def start(self):
        """Pre-fill the pool."""
        log.info("Pool: warming %d connections to %s:%d",
                 self.pool_size, self.server_host, self.server_port)
        tasks = [self._create_one() for _ in range(self.pool_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("Pool: %d connections ready", len(self._pool))
        # Start background keepalive/replenish loop
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def get(self):
        """Get a warm connection. Falls back to on-demand if pool empty."""
        now = time.monotonic()
        async with self._lock:
            while self._pool:
                reader, writer, raw_writer, created = self._pool.popleft()
                if raw_writer.is_closing() or (now - created) > CONN_TTL:
                    try:
                        raw_writer.close()
                    except Exception:
                        pass
                    continue
                return reader, writer, raw_writer

        # Pool empty — create on demand
        log.debug("Pool empty, creating on demand")
        return await self._open_connection()

    async def _keepalive_loop(self):
        """Background: prune dead connections + replenish every 5 seconds."""
        while True:
            await asyncio.sleep(5)
            try:
                # Prune dead + expired connections
                now = time.monotonic()
                async with self._lock:
                    alive = deque()
                    while self._pool:
                        r, w, rw, created = self._pool.popleft()
                        if not rw.is_closing() and (now - created) < CONN_TTL:
                            alive.append((r, w, rw, created))
                        else:
                            try:
                                rw.close()
                            except Exception:
                                pass
                    self._pool = alive

                # Replenish if below target
                needed = self.pool_size - len(self._pool) - self._creating
                if needed > 0:
                    tasks = [self._create_one() for _ in range(needed)]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    if needed >= 4:
                        log.info("Pool: replenished +%d (total %d)",
                                 needed, len(self._pool))
            except Exception as e:
                log.debug("Pool keepalive error: %s", e)

    async def _create_one(self):
        """Create one connection and add to pool."""
        self._creating += 1
        try:
            conn = await asyncio.wait_for(
                self._open_connection(), timeout=10
            )
            async with self._lock:
                self._pool.append((*conn, time.monotonic()))
        except Exception as e:
            log.debug("Pool: create failed: %s", e)
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

        reader, writer = wrap_connection(raw_reader, raw_writer)
        return reader, writer, raw_writer

    async def close(self):
        if self._keepalive_task:
            self._keepalive_task.cancel()
        async with self._lock:
            while self._pool:
                _, _, raw_writer = self._pool.popleft()
                try:
                    raw_writer.close()
                except Exception:
                    pass
