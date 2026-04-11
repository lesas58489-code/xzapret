#!/usr/bin/env python3
"""
XZAP WebSocket Bridge — transparent WS↔TCP proxy.

cloudflared (WSS) → this bridge (WS on :8080) → XZAP server (TCP on :8443)

Each WebSocket connection creates a TCP connection to the XZAP server
and transparently proxies binary data in both directions.
"""

import asyncio
import logging

from aiohttp import web, WSMsgType

WS_HOST = "127.0.0.1"
WS_PORT = 8080
XZAP_HOST = "127.0.0.1"
XZAP_PORT = 8444  # plain TCP XZAP (no TLS — cloudflared handles encryption)
BUFFER_SIZE = 65536

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("xzap-bridge")


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(
        max_msg_size=2 ** 20,
        autoping=True,
        compress=False,
    )
    await ws.prepare(request)

    peer = request.remote
    log.info("[%s] WS connected", peer)

    # Connect to XZAP server
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(XZAP_HOST, XZAP_PORT),
            timeout=5.0,
        )
    except Exception as e:
        log.error("[%s] cannot connect to XZAP: %s", peer, e)
        await ws.close(message=b"backend unavailable")
        return ws

    log.info("[%s] → XZAP connected", peer)

    async def ws_to_tcp():
        """WS binary frames → TCP."""
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        except Exception as e:
            log.debug("[%s] ws→tcp: %s", peer, e)

    async def tcp_to_ws():
        """TCP → WS binary frames."""
        try:
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                await ws.send_bytes(data)
        except Exception as e:
            log.debug("[%s] tcp→ws: %s", peer, e)

    t1 = asyncio.create_task(ws_to_tcp())
    t2 = asyncio.create_task(tcp_to_ws())
    done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

    for t in pending:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    if not ws.closed:
        await ws.close()

    log.info("[%s] session closed", peer)
    return ws


def main():
    app = web.Application()
    # Accept WebSocket on any path (cloudflared sends to /)
    app.router.add_get("/{path:.*}", ws_handler)

    log.info("WS bridge: %s:%d → XZAP %s:%d", WS_HOST, WS_PORT, XZAP_HOST, XZAP_PORT)
    web.run_app(app, host=WS_HOST, port=WS_PORT, print=lambda s: log.info(s))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Shutting down")
