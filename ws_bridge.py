#!/usr/bin/env python3
"""
XZAP WebSocket Bridge — серверная сторона.

cloudflared (WSS) → этот мост (WS на 127.0.0.1:8080) → XZAP (TCP на 127.0.0.1:8443)

Запуск:
    python3 xzap_ws_bridge.py

cloudflared config.yml:
    ingress:
      - hostname: xzap.example.com
        service: ws://localhost:8080
      - service: http_status:404

Каждое WS-соединение создаёт TCP-соединение к XZAP-серверу
и прозрачно проксирует бинарные данные в обе стороны.
"""

import asyncio
import logging
import signal
import sys

try:
    import websockets
    from websockets.server import serve
except ImportError:
    print("pip install websockets")
    sys.exit(1)

# --- Настройки ---
WS_HOST = "127.0.0.1"
WS_PORT = 8080
XZAP_HOST = "127.0.0.1"
XZAP_PORT = 8443  # твой XZAP TLS listener
BUFFER_SIZE = 65536
LOG_LEVEL = logging.INFO

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("xzap-ws-bridge")


async def pipe_ws_to_tcp(ws, writer, peer: str):
    """WS binary frames → TCP."""
    try:
        async for msg in ws:
            if isinstance(msg, bytes):
                writer.write(msg)
                await writer.drain()
            # текстовые фреймы игнорируем
    except websockets.ConnectionClosed:
        pass
    except Exception as e:
        log.debug(f"[{peer}] ws→tcp error: {e}")
    finally:
        writer.close()


async def pipe_tcp_to_ws(reader, ws, peer: str):
    """TCP → WS binary frames."""
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            await ws.send(data)
    except (websockets.ConnectionClosed, ConnectionResetError):
        pass
    except Exception as e:
        log.debug(f"[{peer}] tcp→ws error: {e}")


async def handle_client(ws):
    peer = ws.remote_address
    log.info(f"[{peer}] WS connected")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(XZAP_HOST, XZAP_PORT),
            timeout=5.0,
        )
    except Exception as e:
        log.error(f"[{peer}] cannot connect to XZAP: {e}")
        await ws.close(1011, "backend unavailable")
        return

    log.info(f"[{peer}] → XZAP connected")

    tasks = [
        asyncio.create_task(pipe_ws_to_tcp(ws, writer, str(peer))),
        asyncio.create_task(pipe_tcp_to_ws(reader, ws, str(peer))),
    ]

    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    for t in pending:
        t.cancel()

    writer.close()
    try:
        await ws.close()
    except Exception:
        pass

    log.info(f"[{peer}] session closed")


async def main():
    stop = asyncio.get_event_loop().create_future()

    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, stop.set_result, None)

    async with serve(
        handle_client,
        WS_HOST,
        WS_PORT,
        # cloudflared сам терминирует TLS, тут plain WS
        ping_interval=None,     # cloudflared не пробрасывает WS PING/PONG
        ping_timeout=None,
        max_size=2**20,         # 1MB макс фрейм
        compression=None,       # XZAP уже шифрован, сжатие бесполезно
    ):
        log.info(f"WS bridge listening on {WS_HOST}:{WS_PORT}")
        log.info(f"Forwarding to XZAP at {XZAP_HOST}:{XZAP_PORT}")
        await stop

    log.info("Shutting down")


if __name__ == "__main__":
    asyncio.run(main())
