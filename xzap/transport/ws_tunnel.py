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

# Exceptions that mean "connection closed normally"
_CLOSE_ERRORS = (
    asyncio.IncompleteReadError,
    ConnectionResetError,
    BrokenPipeError,
    OSError,
)


class WSReader:
    """Adapts WebSocket recv() to StreamReader-like readexactly().
    Works with both aiohttp (msg.data) and websockets (raw bytes) APIs.
    """

    def __init__(self, ws):
        self._ws = ws
        self._buffer = bytearray()
        # aiohttp WS uses receive() → WSMessage; websockets uses recv() → bytes
        self._is_aiohttp = hasattr(ws, 'receive')

    async def _recv_bytes(self) -> bytes:
        """Read one message as bytes from either aiohttp or websockets WS."""
        if self._is_aiohttp:
            import aiohttp
            msg = await self._ws.receive()
            if msg.type == aiohttp.WSMsgType.BINARY:
                return msg.data
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING,
                            aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                raise ConnectionError("WS closed")
            return b""
        else:
            msg = await self._ws.recv()
            return msg if isinstance(msg, bytes) else msg.encode()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buffer) < n:
            try:
                data = await self._recv_bytes()
                if data:
                    self._buffer.extend(data)
            except Exception as e:
                log.debug("WS recv error: %s", e)
                raise asyncio.IncompleteReadError(bytes(self._buffer), n)
        result = bytes(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return result

    async def read(self, n: int) -> bytes:
        if not self._buffer:
            try:
                data = await self._recv_bytes()
                if data:
                    self._buffer.extend(data)
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
        # aiohttp uses send_bytes, websockets uses send
        if hasattr(self._ws, 'send_bytes'):
            return self._ws.send_bytes(data)
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
