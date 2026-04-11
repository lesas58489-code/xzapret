"""
XZAP WebSocket Server — for Cloudflare CDN proxy.

Cloudflare terminates TLS and forwards WebSocket to this server.
No TLS here — Cloudflare handles it.

Architecture:
  Browser → SOCKS5 (localhost) → XZAP client
    → wss://solar-cloud.xyz/tunnel (Cloudflare CDN, port 443)
    → Cloudflare proxy
    → ws://VPS:8080/tunnel (this server)
    → target website

Usage:
  python3 run_ws_server.py --port 8080
"""

import asyncio
import argparse
import logging
import os
from pathlib import Path

import websockets
import websockets.server

from xzap.crypto import XZAPCrypto
from xzap.tunnel import _send_frame, _recv_frame
from xzap.transport.ws_mux import MuxServer, MuxServerStream

import json
import struct

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


async def handle_mux_stream(stream: MuxServerStream, crypto: XZAPCrypto):
    """Handle one multiplexed stream — same as TCP tunnel handler."""
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
        log.info("MUX Tunnelling [%d] → %s:%d", stream.stream_id, target_host, target_port)

        async def mux_to_target():
            sent = 0
            try:
                while True:
                    data = await _recv_frame(stream, crypto)
                    target_w.write(data)
                    await target_w.drain()
                    sent += len(data)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            finally:
                log.info("mux→target DONE [%d] %s:%d sent=%d",
                         stream.stream_id, target_host, target_port, sent)

        async def target_to_mux():
            recv = 0
            try:
                while chunk := await target_r.read(65536):
                    await _send_frame(stream, crypto, chunk)
                    recv += len(chunk)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            finally:
                log.info("target→mux DONE [%d] %s:%d recv=%d",
                         stream.stream_id, target_host, target_port, recv)

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
        try:
            target_w.close()
            await target_w.wait_closed()
        except Exception:
            pass

    except Exception as e:
        log.debug("MUX stream %d error: %s", stream.stream_id, e)
    finally:
        stream.close()


async def handle_mux_ws(websocket, crypto: XZAPCrypto):
    """Handle one multiplexed WebSocket — dispatch streams to tunnel handlers."""
    mux = MuxServer()

    async def stream_handler(reader, writer):
        await handle_mux_stream(reader, crypto)

    await mux.handle(websocket, stream_handler)


async def run(host: str, port: int, key: bytes, ws_path: str,
              ssl_cert: str = None, ssl_key: str = None):
    crypto = XZAPCrypto(key=key)

    async def handler(websocket):
        # Check path
        path = getattr(websocket, 'request', None)
        if path and hasattr(path, 'path'):
            req_path = path.path
        elif hasattr(websocket, 'path'):
            req_path = websocket.path
        else:
            req_path = ws_path

        if req_path != ws_path:
            log.warning("Wrong path: %s", req_path)
            await websocket.close(1008, "Not found")
            return

        await handle_mux_ws(websocket, crypto)

    # TLS for Cloudflare "Full" SSL mode (self-signed cert is OK)
    ssl_ctx = None
    if ssl_cert and ssl_key:
        import ssl
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(ssl_cert, ssl_key)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        log.info("TLS enabled (cert=%s)", ssl_cert)

    async with websockets.server.serve(
        handler, host, port,
        max_size=2 ** 20,
        ping_interval=None,  # Cloudflare handles keepalive
        ping_timeout=None,
        compression=None,
        ssl=ssl_ctx,
    ):
        mode = "WSS (TLS)" if ssl_ctx else "WS"
        log.info("XZAP %s server on %s:%d%s (for Cloudflare)", mode, host, port, ws_path)
        await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(description="XZAP WebSocket Server (Cloudflare)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/tunnel")
    parser.add_argument("--ssl-cert", default="xzap_cert.pem")
    parser.add_argument("--ssl-key", default="xzap_tls_key.pem")
    parser.add_argument("--no-tls", action="store_true",
                        help="Disable TLS (for cloudflared local connection)")
    parser.add_argument("--key-file", default=KEY_FILE)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    key = load_key(args.key_file)

    import base64
    print(f"Key (base64): {base64.b64encode(key).decode()}")
    print(f"WebSocket: ws://{args.host}:{args.port}{args.path}")
    print(f"Cloudflare: wss://solar-cloud.xyz{args.path}")
    print()

    ssl_cert = None if args.no_tls else args.ssl_cert
    ssl_key = None if args.no_tls else args.ssl_key
    asyncio.run(run(args.host, args.port, key, args.path,
                    ssl_cert=ssl_cert, ssl_key=ssl_key))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
