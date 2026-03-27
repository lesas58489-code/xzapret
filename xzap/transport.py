"""
XZAP Transport Layer.

Async TCP transport with multi-path support.
Each path = separate TCP connection with its own SNI.
"""

import asyncio
import logging

log = logging.getLogger("xzap.transport")


class XZAPConnection:
    """Single TCP connection to server (one SNI path)."""

    def __init__(self, host: str, port: int, sni: str = ""):
        self.host = host
        self.port = port
        self.sni = sni
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._connected = False

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port
        )
        self._connected = True
        log.debug("Connected to %s:%d (SNI=%s)", self.host, self.port, self.sni)

    async def send(self, data: bytes):
        if not self._connected:
            raise RuntimeError("Not connected")
        # Length-prefix each chunk: [2B len][data]
        header = len(data).to_bytes(2, "big")
        self.writer.write(header + data)
        await self.writer.drain()

    async def recv(self) -> bytes:
        if not self._connected:
            raise RuntimeError("Not connected")
        header = await self.reader.readexactly(2)
        length = int.from_bytes(header, "big")
        return await self.reader.readexactly(length)

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected


class MultiPathTransport:
    """Manages multiple parallel TCP connections (multi-SNI paths)."""

    def __init__(self, host: str, port: int, snis: list[str]):
        self.paths = [XZAPConnection(host, port, sni) for sni in snis]

    async def connect_all(self):
        await asyncio.gather(*(p.connect() for p in self.paths))

    async def send_on_path(self, path_index: int, data: bytes):
        await self.paths[path_index % len(self.paths)].send(data)

    async def recv_from_path(self, path_index: int) -> bytes:
        return await self.paths[path_index % len(self.paths)].recv()

    async def close_all(self):
        await asyncio.gather(*(p.close() for p in self.paths))

    @property
    def num_paths(self) -> int:
        return len(self.paths)


class XZAPListener:
    """Server-side TCP listener."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server: asyncio.Server | None = None

    async def start(self, handler):
        """Start listening. handler(reader, writer) called per connection."""
        self._server = await asyncio.start_server(handler, self.host, self.port)
        addr = self._server.sockets[0].getsockname()
        log.info("XZAP server listening on %s:%d", *addr)

    async def serve_forever(self):
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
