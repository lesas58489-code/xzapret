"""
WebSocket ↔ XZAP Tunnel adapter.

Allows running the XZAP tunnel protocol over WebSocket connections
(for CDN like Cloudflare). No fragmentation needed — CDN handles transport.

Architecture:
  Client → wss://domain.xyz/tunnel → Cloudflare CDN → ws://VPS:8080/tunnel → target
"""

import asyncio
import logging

log = logging.getLogger("xzap.transport.ws_tunnel")


class WSReader:
    """Adapts WebSocket recv() to StreamReader-like readexactly()."""

    def __init__(self, ws):
        self._ws = ws
        self._buffer = bytearray()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buffer) < n:
            try:
                msg = await self._ws.recv()
                if isinstance(msg, str):
                    msg = msg.encode()
                self._buffer.extend(msg)
            except Exception:
                raise asyncio.IncompleteReadError(
                    bytes(self._buffer), n
                )
        result = bytes(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return result

    async def read(self, n: int) -> bytes:
        if not self._buffer:
            try:
                msg = await self._ws.recv()
                if isinstance(msg, str):
                    msg = msg.encode()
                self._buffer.extend(msg)
            except Exception:
                return b""
        result = bytes(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return result


class WSWriter:
    """Adapts WebSocket send() to StreamWriter-like write()/drain()."""

    def __init__(self, ws):
        self._ws = ws

    def write(self, data: bytes):
        """Returns a coroutine — _send_frame will await it."""
        return self._ws.send(data)

    async def drain(self):
        pass  # WebSocket sends are immediate

    def close(self):
        pass

    async def wait_closed(self):
        try:
            await self._ws.close()
        except Exception:
            pass

    def get_extra_info(self, key):
        if key == "peername":
            return getattr(self._ws, 'remote_address', None)
        return None
