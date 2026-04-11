"""
XZAP WebSocket Server — for Cloudflare Tunnel (cloudflared).

Uses aiohttp on both client and server for consistent WebSocket handling.
cloudflared connects locally, no TLS needed.

Usage:
  python3 run_ws_server.py --port 8080
"""

import asyncio
import argparse
import json
import logging
import os
import struct
from pathlib import Path

from aiohttp import web, WSMsgType

from xzap.crypto import XZAPCrypto
from xzap.tunnel import _send_frame, _recv_frame

log = logging.getLogger("xzap")

KEY_FILE = "xzap.key"


def load_key(path: str) -> bytes:
    p = Path(path)
    if p.exists():
        return p.read_bytes()
    key = os.urandom(32)
    p.write_bytes(key)
    log.info("Generated new key → %s", path)
    return key


class MuxServerStream:
    """Server-side multiplexed stream — reader/writer interface."""

    def __init__(self, ws: web.WebSocketResponse, stream_id: int):
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
        return self._ws.send_bytes(msg)

    async def drain(self):
        pass

    def close(self):
        self._closed = True
        self._data_ready.set()

    async def wait_closed(self):
        pass

    def get_extra_info(self, key):
        return None


async def handle_stream(stream: MuxServerStream, crypto: XZAPCrypto):
    """Handle one multiplexed tunnel stream."""
    target_host = None
    target_port = None
    try:
        ctrl = await asyncio.wait_for(
            _recv_frame(stream, crypto), timeout=30
        )
        req = json.loads(ctrl)

        if req.get("cmd") != "connect":
            await _send_frame(stream, crypto,
                              json.dumps({"ok": False, "err": "bad cmd"}).encode())
            return

        target_host = req["host"]
        target_port = int(req["port"])

        try:
            target_r, target_w = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=10,
            )
        except Exception:
            await _send_frame(stream, crypto,
                              json.dumps({"ok": False, "err": "connect failed"}).encode())
            return

        await _send_frame(stream, crypto,
                          json.dumps({"ok": True}).encode())
        log.info("MUX [%d] → %s:%d", stream.stream_id, target_host, target_port)

        async def mux_to_target():
            sent = 0
            try:
                while True:
                    data = await _recv_frame(stream, crypto)
                    target_w.write(data)
                    await target_w.drain()
                    sent += len(data)
            except (asyncio.CancelledError, asyncio.IncompleteReadError):
                pass
            except Exception:
                pass
            return sent

        async def target_to_mux():
            recv = 0
            try:
                while chunk := await target_r.read(65536):
                    await _send_frame(stream, crypto, chunk)
                    recv += len(chunk)
            except (asyncio.CancelledError, asyncio.IncompleteReadError):
                pass
            except Exception:
                pass
            return recv

        t1 = asyncio.create_task(mux_to_target())
        t2 = asyncio.create_task(target_to_mux())
        done, pending = await asyncio.wait(
            [t1, t2], return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

        sent = t1.result() if t1.done() and not t1.cancelled() else 0
        recv = t2.result() if t2.done() and not t2.cancelled() else 0
        log.info("MUX [%d] DONE %s:%d sent=%d recv=%d",
                 stream.stream_id, target_host, target_port, sent, recv)

        try:
            target_w.close()
            await target_w.wait_closed()
        except Exception:
            pass

    except Exception as e:
        if target_host:
            log.debug("MUX [%d] error %s:%d: %s",
                      stream.stream_id, target_host, target_port, e)
    finally:
        stream.close()


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    """Handle one multiplexed WebSocket connection (aiohttp)."""
    crypto = request.app["crypto"]

    ws = web.WebSocketResponse(
        max_msg_size=2 ** 20,
        heartbeat=None,   # cloudflared doesn't forward WS pings — disable
        autoping=True,
        compress=False,
    )
    await ws.prepare(request)

    addr = request.remote
    log.info("MUX connection from %s", addr)

    streams: dict[int, MuxServerStream] = {}

    try:
        async for msg in ws:
            if msg.type == WSMsgType.BINARY:
                data = msg.data
                if len(data) < 4:
                    continue

                stream_id = struct.unpack(">I", data[:4])[0]
                payload = data[4:]

                if stream_id not in streams:
                    stream = MuxServerStream(ws, stream_id)
                    streams[stream_id] = stream
                    asyncio.create_task(handle_stream(stream, crypto))

                stream = streams.get(stream_id)
                if stream and not stream._closed:
                    stream._recv_buffer.append(payload)
                    stream._data_ready.set()

            elif msg.type == WSMsgType.ERROR:
                log.info("MUX WS error: %s", ws.exception())
                break

    except Exception as e:
        log.debug("MUX handler error: %s", e)
    finally:
        # Close all streams
        for stream in streams.values():
            stream.close()
        streams.clear()
        log.info("MUX connection closed from %s", addr)

    return ws


def main():
    parser = argparse.ArgumentParser(description="XZAP WebSocket Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--path", default="/tunnel")
    parser.add_argument("--key-file", default=KEY_FILE)
    # Legacy flags (ignored)
    parser.add_argument("--ssl-cert", default=None)
    parser.add_argument("--ssl-key", default=None)
    parser.add_argument("--no-tls", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    key = load_key(args.key_file)

    import base64
    print(f"Key (base64): {base64.b64encode(key).decode()}")
    print(f"Listening: {args.host}:{args.port}{args.path}")
    print()

    crypto = XZAPCrypto(key=key)

    app = web.Application()
    app["crypto"] = crypto
    app.router.add_get(args.path, ws_handler)

    web.run_app(app, host=args.host, port=args.port,
                print=lambda s: log.info(s))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
