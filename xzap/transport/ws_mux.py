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
from typing import Dict, Optional

import aiohttp

log = logging.getLogger("xzap.ws_mux")


class MuxClient:
    """Client-side multiplexer — one aiohttp WebSocket, many tunnels.
    Uses aiohttp instead of websockets library for Windows IocpProactor compat.
    """

    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._streams: Dict[int, MuxStream] = {}
        self._next_id = 1
        self._lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task] = None

    async def ensure_connected(self):
        """Connect if not already connected."""
        if self._ws is not None and not self._ws.closed:
            return
        async with self._lock:
            if self._ws is not None and not self._ws.closed:
                return
            await self._connect()

    async def _connect(self):
        log.info("MUX connecting to %s", self.ws_url)
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=None, connect=15)
            self._session = aiohttp.ClientSession(timeout=timeout)

        self._ws = await self._session.ws_connect(
            self.ws_url,
            max_msg_size=2 ** 20,
            heartbeat=20,       # aiohttp handles ping/pong internally
            compress=0,         # no compression
            autoclose=False,    # we manage close ourselves
            autoping=True,      # auto-respond to server pings
        )
        # Start background reader
        if self._reader_task is None or self._reader_task.done():
            self._reader_task = asyncio.create_task(self._read_loop())
        log.info("MUX connected")

    async def _read_loop(self):
        """Read messages from WebSocket and dispatch to streams."""
        try:
            while True:
                msg = await self._ws.receive()

                if msg.type == aiohttp.WSMsgType.BINARY:
                    data = msg.data
                    if len(data) < 4:
                        continue
                    stream_id = struct.unpack(">I", data[:4])[0]
                    payload = data[4:]
                    stream = self._streams.get(stream_id)
                    if stream:
                        stream._recv_buffer.append(payload)
                        stream._data_ready.set()

                elif msg.type in (aiohttp.WSMsgType.CLOSE,
                                   aiohttp.WSMsgType.CLOSING,
                                   aiohttp.WSMsgType.CLOSED):
                    log.info("MUX WebSocket closed by server")
                    break

                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log.info("MUX WebSocket error: %s", self._ws.exception())
                    break

        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.info("MUX reader ended: %s", e)
        finally:
            # Signal all streams that connection is dead
            for stream in list(self._streams.values()):
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
            await self._ws.send_bytes(msg)
        except Exception as e:
            log.debug("MUX send error stream=%d: %s", stream_id, e)
            raise

    def remove_stream(self, stream_id: int):
        self._streams.pop(stream_id, None)

    async def close(self):
        if self._reader_task:
            self._reader_task.cancel()
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session and not self._session.closed:
            await self._session.close()


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
