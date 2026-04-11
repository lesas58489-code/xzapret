#!/usr/bin/env python3
"""
XZAP Mux Server — multiplexed TCP proxy over WebSocket.

One WS from cloudflared, many TCP streams inside.
Protocol: [4B stream_id][1B action][payload]
  OPEN(0x01): payload = "host:port"
  DATA(0x02): payload = raw bytes
  CLOSE(0x03): no payload

cloudflared config.yml:
  ingress:
    - hostname: solar-cloud.xyz
      service: http://localhost:8080
    - service: http_status:404
"""

import asyncio
import logging
import struct

from aiohttp import web, WSMsgType

WS_HOST = "127.0.0.1"
WS_PORT = 8080
BUFFER_SIZE = 32768

ACT_OPEN = 0x01
ACT_DATA = 0x02
ACT_CLOSE = 0x03
HDR_SIZE = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mux-server")


class MuxSession:
    def __init__(self, ws: web.WebSocketResponse):
        self.ws = ws
        self.streams: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.tasks: dict[int, asyncio.Task] = {}

    async def send_frame(self, stream_id: int, action: int, data: bytes = b""):
        frame = struct.pack(">IB", stream_id, action) + data
        try:
            await self.ws.send_bytes(frame)
        except Exception:
            pass

    async def handle_open(self, stream_id: int, payload: bytes):
        target = payload.decode("utf-8", errors="replace")
        sep = target.rfind(":")
        if sep == -1:
            await self.send_frame(stream_id, ACT_CLOSE)
            return

        host, port = target[:sep], int(target[sep + 1:])
        log.info("[%d] OPEN → %s:%d", stream_id, host, port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
        except Exception as e:
            log.warning("[%d] connect failed: %s", stream_id, e)
            await self.send_frame(stream_id, ACT_CLOSE)
            return

        self.streams[stream_id] = (reader, writer)
        self.tasks[stream_id] = asyncio.create_task(
            self._tcp_reader(stream_id, reader)
        )

    async def _tcp_reader(self, stream_id: int, reader: asyncio.StreamReader):
        total = 0
        try:
            while chunk := await reader.read(BUFFER_SIZE):
                await self.send_frame(stream_id, ACT_DATA, chunk)
                total += len(chunk)
        except Exception:
            pass
        finally:
            log.info("[%d] tcp→ws %d bytes", stream_id, total)
            await self.send_frame(stream_id, ACT_CLOSE)
            self._close_stream(stream_id)

    async def handle_data(self, stream_id: int, payload: bytes):
        pair = self.streams.get(stream_id)
        if pair:
            try:
                pair[1].write(payload)
                await pair[1].drain()
            except Exception:
                self._close_stream(stream_id)

    def _close_stream(self, stream_id: int):
        pair = self.streams.pop(stream_id, None)
        task = self.tasks.pop(stream_id, None)
        if pair:
            try:
                pair[1].close()
            except Exception:
                pass
        if task and not task.done():
            task.cancel()

    async def run(self):
        try:
            async for msg in self.ws:
                if msg.type == WSMsgType.BINARY and len(msg.data) >= HDR_SIZE:
                    stream_id, action = struct.unpack(">IB", msg.data[:HDR_SIZE])
                    payload = msg.data[HDR_SIZE:]

                    if action == ACT_OPEN:
                        await self.handle_open(stream_id, payload)
                    elif action == ACT_DATA:
                        await self.handle_data(stream_id, payload)
                    elif action == ACT_CLOSE:
                        self._close_stream(stream_id)

                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except Exception as e:
            log.error("Session error: %s", e)
        finally:
            for sid in list(self.streams):
                self._close_stream(sid)


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(
        max_msg_size=2 ** 20,
        autoping=True,
        heartbeat=30,  # detect dead connections
        compress=False,
    )
    await ws.prepare(request)

    log.info("Client connected: %s", request.remote)
    session = MuxSession(ws)
    await session.run()
    log.info("Client disconnected: %s", request.remote)
    return ws


def main():
    app = web.Application()
    app.router.add_get("/{path:.*}", ws_handler)
    log.info("Mux server on %s:%d", WS_HOST, WS_PORT)
    web.run_app(app, host=WS_HOST, port=WS_PORT, print=lambda s: log.info(s))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped")
