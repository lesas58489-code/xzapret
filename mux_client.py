#!/usr/bin/env python3
"""
XZAP Mux Client — SOCKS5 proxy with WebSocket multiplexing.

All browser connections go through ONE persistent WSS to Cloudflare.
Split tunneling: bypass domains go direct, rest through tunnel.

Usage:
  set XZAP_WS_URL=wss://solar-cloud.xyz/
  python mux_client.py
"""

import asyncio
import argparse
import logging
import os
import struct
from pathlib import Path
from typing import Optional

import aiohttp

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080
BUFFER_SIZE = 32768
RECONNECT_DELAY = 2.0

ACT_OPEN = 0x01
ACT_DATA = 0x02
ACT_CLOSE = 0x03
HDR_SIZE = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mux-client")


class DomainRouter:
    """Split tunneling: bypass domains go direct."""

    def __init__(self):
        self.bypass: set[str] = set()

    def load(self, path: str):
        p = Path(path)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    self.bypass.add(line)
            log.info("Loaded %d bypass domains", len(self.bypass))

    def should_bypass(self, hostname: str) -> bool:
        hostname = hostname.lower()
        if hostname in self.bypass:
            return True
        parts = hostname.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in self.bypass:
                return True
        return False


class MuxClient:
    def __init__(self, ws_url: str, router: DomainRouter):
        self.ws_url = ws_url
        self.router = router
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._streams: dict[int, asyncio.Queue] = {}
        self._next_id = 1
        self._connected = asyncio.Event()
        self._ws_lock = asyncio.Lock()

    def _alloc_id(self) -> int:
        sid = self._next_id
        self._next_id += 1
        if self._next_id > 0xFFFFFFFF:
            self._next_id = 1
        return sid

    async def send_frame(self, stream_id: int, action: int, data: bytes = b""):
        frame = struct.pack(">IB", stream_id, action) + data
        async with self._ws_lock:
            try:
                await self._ws.send_bytes(frame)
                if action == ACT_DATA:
                    log.debug("[%d] sent %d bytes", stream_id, len(data))
            except Exception as e:
                log.warning("[%d] send error: %s", stream_id, e)

    async def connect_ws(self):
        while True:
            try:
                if self._session is None or self._session.closed:
                    self._session = aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=None, connect=15)
                    )
                self._ws = await self._session.ws_connect(
                    self.ws_url,
                    max_msg_size=2 ** 20,
                    compress=0,
                    autoping=True,
                    heartbeat=None,  # CF doesn't forward WS PING/PONG
                )
                log.info("WSS connected to %s", self.ws_url)
                self._connected.set()
                return
            except Exception as e:
                log.warning("WSS connect failed: %s, retry in %.0fs", e, RECONNECT_DELAY)
                await asyncio.sleep(RECONNECT_DELAY)

    async def ws_reader(self):
        """Background: read WS frames, dispatch to stream queues."""
        while True:
            try:
                await self._connected.wait()
                async for msg in self._ws:
                    if msg.type == aiohttp.WSMsgType.BINARY and len(msg.data) >= HDR_SIZE:
                        stream_id, action = struct.unpack(">IB", msg.data[:HDR_SIZE])
                        payload = msg.data[HDR_SIZE:]

                        if action == ACT_DATA:
                            q = self._streams.get(stream_id)
                            if q:
                                await q.put(payload)
                                log.debug("[%d] recv %d bytes", stream_id, len(payload))
                            else:
                                log.warning("[%d] DATA dropped (unknown stream, %d bytes)", stream_id, len(payload))
                        elif action == ACT_CLOSE:
                            log.debug("[%d] CLOSE from server", stream_id)
                            q = self._streams.pop(stream_id, None)
                            if q:
                                await q.put(None)

                    elif msg.type in (aiohttp.WSMsgType.CLOSE,
                                      aiohttp.WSMsgType.ERROR):
                        break

            except Exception as e:
                log.warning("WS reader error: %s", e)

            log.info("WSS disconnected, reconnecting...")
            self._connected.clear()
            # Kill all active streams
            for q in self._streams.values():
                await q.put(None)
            self._streams.clear()
            await self.connect_ws()

    async def handle_socks(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        """Handle one SOCKS5 connection."""
        try:
            # SOCKS5 greeting
            head = await reader.readexactly(2)
            if head[0] != 0x05:
                writer.close()
                return
            await reader.readexactly(head[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            # SOCKS5 request
            req = await reader.readexactly(4)
            ver, cmd, _, atyp = req
            if cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return

            if atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 0x03:
                dlen = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(dlen)).decode()
            elif atyp == 0x04:
                import ipaddress
                host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
            else:
                writer.close()
                return

            port = struct.unpack(">H", await reader.readexactly(2))[0]

            # Split tunneling: bypass domains go direct
            if self.router.should_bypass(host):
                log.info("[DIRECT] %s:%d", host, port)
                await self._handle_direct(reader, writer, host, port)
                return

            # Tunnel through WS mux
            await self._connected.wait()

            stream_id = self._alloc_id()
            q: asyncio.Queue = asyncio.Queue()
            self._streams[stream_id] = q

            log.info("[MUX:%d] %s:%d", stream_id, host, port)
            await self.send_frame(stream_id, ACT_OPEN, f"{host}:{port}".encode())

            # SOCKS5 success
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()

            # Bidirectional pipe
            t1 = asyncio.create_task(self._pipe_browser_to_ws(stream_id, reader))
            t2 = asyncio.create_task(self._pipe_ws_to_browser(stream_id, q, writer))
            done, pending = await asyncio.wait(
                [t1, t2], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
            self._streams.pop(stream_id, None)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug("SOCKS error: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_direct(self, reader, writer, host, port):
        """Direct TCP connection (bypass tunnel)."""
        try:
            remote_r, remote_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
        except Exception:
            writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
            await writer.drain()
            writer.close()
            return

        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()

        async def pipe(src, dst):
            try:
                while chunk := await src.read(BUFFER_SIZE):
                    dst.write(chunk)
                    await dst.drain()
            except Exception:
                pass

        t1 = asyncio.create_task(pipe(reader, remote_w))
        t2 = asyncio.create_task(pipe(remote_r, writer))
        done, pending = await asyncio.wait(
            [t1, t2], return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
        try:
            remote_w.close()
        except Exception:
            pass

    async def _pipe_browser_to_ws(self, stream_id: int, reader: asyncio.StreamReader):
        try:
            while chunk := await reader.read(BUFFER_SIZE):
                await self.send_frame(stream_id, ACT_DATA, chunk)
        except Exception:
            pass
        finally:
            await self.send_frame(stream_id, ACT_CLOSE)

    async def _pipe_ws_to_browser(self, stream_id: int, q: asyncio.Queue,
                                   writer: asyncio.StreamWriter):
        try:
            while True:
                data = await q.get()
                if data is None:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass

    async def run(self):
        await self.connect_ws()
        asyncio.create_task(self.ws_reader())

        server = await asyncio.start_server(
            self.handle_socks, SOCKS_HOST, SOCKS_PORT
        )
        log.info("SOCKS5 proxy on %s:%d", SOCKS_HOST, SOCKS_PORT)
        log.info("Tunnel: %s", self.ws_url)
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="XZAP Mux Client")
    parser.add_argument("--ws-url", default=os.environ.get("XZAP_WS_URL", "wss://solar-cloud.xyz/"))
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--bypass", default="lists/bypass.txt")
    args = parser.parse_args()

    global SOCKS_PORT
    SOCKS_PORT = args.socks_port

    router = DomainRouter()
    router.load(args.bypass)

    client = MuxClient(args.ws_url, router)
    asyncio.run(client.run())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped")
