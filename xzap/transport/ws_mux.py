"""
WebSocket Multiplexer — all XZAP tunnels over ONE persistent WebSocket.

Instead of opening a new WebSocket per SOCKS5 connection (slow through CDN),
maintain a single persistent WebSocket and multiplex tunnels with stream IDs.

Wire format per message:
  [4B stream_id][payload]

stream_id=0 is reserved for control messages.
Each stream maps to one XZAP tunnel (one SOCKS5 connection).
"""

import asyncio
import struct
import logging
import time
from typing import Dict, Optional

log = logging.getLogger("xzap.ws_mux")


class MuxClient:
    """Client-side multiplexer — one WebSocket, many tunnels."""

    def __init__(self, ws_url: str, ping_interval: int = 20):
        self.ws_url = ws_url
        self.ping_interval = ping_interval
        self._ws = None
        self._streams: Dict[int, MuxStream] = {}
        self._next_id = 1
        self._lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task] = None
        self._connected = asyncio.Event()

    async def ensure_connected(self):
        """Connect if not already connected."""
        if self._ws is not None and not getattr(self._ws, 'closed', True) is True:
            return
        async with self._lock:
            if self._ws is not None:
                try:
                    # Check if still alive
                    if not getattr(self._ws, 'closed', False):
                        return
                except Exception:
                    pass
            await self._connect()

    async def _connect(self):
        import websockets
        log.info("MUX connecting to %s", self.ws_url)
        self._ws = await websockets.connect(
            self.ws_url,
            max_size=2 ** 20,
            ping_interval=self.ping_interval,
            ping_timeout=10,
            compression=None,
            open_timeout=15,
            close_timeout=5,
        )
        self._connected.set()
        # Start background reader
        if self._reader_task is None or self._reader_task.done():
            self._reader_task = asyncio.create_task(self._read_loop())
        log.info("MUX connected")

    async def _read_loop(self):
        """Read messages from WebSocket and dispatch to streams."""
        try:
            while True:
                try:
                    msg = await self._ws.recv()
                except Exception as e:
                    log.info("MUX read error: %s", e)
                    break

                if isinstance(msg, str):
                    msg = msg.encode()
                if len(msg) < 4:
                    continue

                stream_id = struct.unpack(">I", msg[:4])[0]
                payload = msg[4:]

                stream = self._streams.get(stream_id)
                if stream:
                    stream._recv_buffer.append(payload)
                    stream._data_ready.set()
        except Exception as e:
            log.debug("MUX reader ended: %s", e)
        finally:
            # Signal all streams that connection is dead
            self._connected.clear()
            for stream in self._streams.values():
                stream._closed = True
                stream._data_ready.set()

    def create_stream(self) -> "MuxStream":
        """Create a new multiplexed stream."""
        stream_id = self._next_id
        self._next_id += 1
        stream = MuxStream(self, stream_id)
        self._streams[stream_id] = stream
        return stream

    async def send_message(self, stream_id: int, data: bytes):
        """Send data on a specific stream."""
        msg = struct.pack(">I", stream_id) + data
        try:
            await self._ws.send(msg)
        except Exception as e:
            log.debug("MUX send error stream=%d: %s", stream_id, e)
            raise

    def remove_stream(self, stream_id: int):
        self._streams.pop(stream_id, None)

    async def close(self):
        if self._reader_task:
            self._reader_task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass


class MuxStream:
    """One multiplexed stream — looks like a reader/writer pair."""

    def __init__(self, mux: MuxClient, stream_id: int):
        self._mux = mux
        self.stream_id = stream_id
        self._recv_buffer: list[bytes] = []
        self._byte_buffer = bytearray()
        self._data_ready = asyncio.Event()
        self._closed = False

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes from this stream."""
        while len(self._byte_buffer) < n:
            if self._recv_buffer:
                self._byte_buffer.extend(self._recv_buffer.pop(0))
                continue
            if self._closed:
                raise asyncio.IncompleteReadError(bytes(self._byte_buffer), n)
            self._data_ready.clear()
            await self._data_ready.wait()
        result = bytes(self._byte_buffer[:n])
        self._byte_buffer = self._byte_buffer[n:]
        return result

    async def read(self, n: int) -> bytes:
        """Read up to n bytes."""
        if not self._byte_buffer and not self._recv_buffer:
            if self._closed:
                return b""
            self._data_ready.clear()
            await self._data_ready.wait()
        if self._recv_buffer:
            self._byte_buffer.extend(self._recv_buffer.pop(0))
        result = bytes(self._byte_buffer[:n])
        self._byte_buffer = self._byte_buffer[n:]
        return result

    def write(self, data: bytes):
        """Returns coroutine — compatible with _send_frame."""
        return self._mux.send_message(self.stream_id, data)

    async def drain(self):
        pass

    def close(self):
        self._closed = True
        self._mux.remove_stream(self.stream_id)

    async def wait_closed(self):
        pass

    def get_extra_info(self, key):
        return None


class MuxServer:
    """Server-side demultiplexer — dispatches streams to tunnel handler."""

    def __init__(self):
        self._streams: Dict[int, MuxServerStream] = {}

    async def handle(self, websocket, tunnel_handler):
        """Handle one multiplexed WebSocket connection."""
        addr = getattr(websocket, 'remote_address', '?')
        log.info("MUX server connection from %s", addr)

        try:
            async for msg in websocket:
                if isinstance(msg, str):
                    msg = msg.encode()
                if len(msg) < 4:
                    continue

                stream_id = struct.unpack(">I", msg[:4])[0]
                payload = msg[4:]

                if stream_id not in self._streams:
                    # New stream — spawn tunnel handler
                    stream = MuxServerStream(websocket, stream_id)
                    self._streams[stream_id] = stream
                    asyncio.create_task(
                        self._handle_stream(stream, tunnel_handler)
                    )

                stream = self._streams.get(stream_id)
                if stream:
                    stream._recv_buffer.append(payload)
                    stream._data_ready.set()

        except Exception as e:
            log.debug("MUX server error: %s", e)
        finally:
            # Close all streams
            for stream in self._streams.values():
                stream._closed = True
                stream._data_ready.set()
            self._streams.clear()
            log.info("MUX server connection closed from %s", addr)

    async def _handle_stream(self, stream: "MuxServerStream", tunnel_handler):
        try:
            await tunnel_handler(stream, stream)
        except Exception as e:
            log.debug("MUX stream %d error: %s", stream.stream_id, e)
        finally:
            stream._closed = True
            self._streams.pop(stream.stream_id, None)


class MuxServerStream:
    """Server-side stream — same interface as MuxStream."""

    def __init__(self, ws, stream_id: int):
        self._ws = ws
        self.stream_id = stream_id
        self._recv_buffer: list[bytes] = []
        self._byte_buffer = bytearray()
        self._data_ready = asyncio.Event()
        self._closed = False

    async def readexactly(self, n: int) -> bytes:
        while len(self._byte_buffer) < n:
            if self._recv_buffer:
                self._byte_buffer.extend(self._recv_buffer.pop(0))
                continue
            if self._closed:
                raise asyncio.IncompleteReadError(bytes(self._byte_buffer), n)
            self._data_ready.clear()
            await self._data_ready.wait()
        result = bytes(self._byte_buffer[:n])
        self._byte_buffer = self._byte_buffer[n:]
        return result

    def write(self, data: bytes):
        msg = struct.pack(">I", self.stream_id) + data
        return self._ws.send(msg)

    async def drain(self):
        pass

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, key):
        if key == "peername":
            return getattr(self._ws, 'remote_address', None)
        if key == "socket":
            return None
        return None
