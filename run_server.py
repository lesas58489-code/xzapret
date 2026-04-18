"""
XZAP Server — запуск на VPS.

Использование:
  python3 run_server.py --port 8443
  python3 run_server.py --port 443 --tls        # TLS с SNI-маскировкой
  python3 run_server.py --gen-key                # Сгенерировать ключ
"""

import asyncio
import argparse
import logging
import os
from pathlib import Path

from xzap.crypto import XZAPCrypto
from xzap.obfuscation import Obfuscator
from xzap.tunnel import XZAPTunnelServer
from xzap.transport.tcp import XZAPListener

log = logging.getLogger("xzap")

KEY_FILE = "xzap.key"


def generate_key(path: str) -> bytes:
    key = os.urandom(32)
    Path(path).write_bytes(key)
    log.info("Generated new key → %s (%d bytes)", path, len(key))
    return key


def load_key(path: str) -> bytes:
    p = Path(path)
    if p.exists():
        key = p.read_bytes()
        log.info("Loaded key from %s", path)
        return key
    return generate_key(path)


async def run_tcp_server(host: str, port: int, key: bytes):
    """TCP-сервер (без TLS)."""
    crypto = XZAPCrypto(key=key)
    tunnel_handler = XZAPTunnelServer(crypto)
    listener = XZAPListener(host, port)
    await listener.start(tunnel_handler.handle)
    log.info("XZAP TCP server ready on %s:%d", host, port)
    await listener.serve_forever()


async def run_tls_server(host: str, port: int, key: bytes,
                          cert_file: str, key_file_tls: str):
    """TLS-сервер — DPI видит HTTPS к белому домену."""
    import ssl as _ssl
    from xzap.tls import generate_self_signed_cert, create_server_context
    from xzap.memory import MemoryManager

    # Generate cert if not exists
    generate_self_signed_cert(cert_file, key_file_tls)

    from xzap.keystore import KeyStore

    # Multi-user keys (keys.json) or single key (legacy)
    keystore = KeyStore("keys.json")
    if keystore.users:
        tunnel_handler = XZAPTunnelServer(keystore=keystore)
        log.info("Multi-user mode: %d users", len(keystore.users))
    else:
        crypto = XZAPCrypto(key=key)
        tunnel_handler = XZAPTunnelServer(crypto=crypto)

    ssl_ctx = create_server_context(cert_file, key_file_tls)

    # Memory manager
    mem = MemoryManager(gc_interval=60, cleanup_interval=300, max_rss_mb=200)
    await mem.start()

    # backlog=4096 — default 100 overflows on mux-client bursts (proactive
    # rotator opens 1 new TCP per tunnel per 15s; several clients at once
    # easily exceed 100 pending SYNs → kernel RSTs them → clients see
    # ECONNREFUSED). 4096 matches net.core.somaxconn default on modern Linux.
    server = await asyncio.start_server(
        tunnel_handler.handle, host, port, ssl=ssl_ctx, backlog=4096,
    )
    addr = server.sockets[0].getsockname()
    log.info("XZAP TLS server ready on %s:%d (SNI masquerade)", *addr)
    async with server:
        await server.serve_forever()


async def run_ws_server(host: str, port: int, key: bytes):
    """WebSocket-сервер."""
    from xzap.transport.ws import WSTransport
    crypto = XZAPCrypto(key=key)
    tunnel_handler = XZAPTunnelServer(crypto)
    ws = WSTransport(host=host, port=port, path="/ws")
    await ws.serve(tunnel_handler.handle)
    log.info("XZAP WS server ready on %s:%d/xzap", host, port)
    await ws.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="XZAP Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--transport", choices=["tcp", "ws"], default="tcp")
    parser.add_argument("--tls", action="store_true",
                        help="Enable TLS (SNI masquerade)")
    parser.add_argument("--cert", default="xzap_cert.pem")
    parser.add_argument("--tls-key", default="xzap_tls_key.pem")
    parser.add_argument("--key-file", default=KEY_FILE)
    parser.add_argument("--gen-key", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    key = load_key(args.key_file)

    if args.gen_key:
        import base64
        print(f"\nKey (base64): {base64.b64encode(key).decode()}")
        print(f"Saved to: {args.key_file}")
        print(f"\nНа клиенте: export XZAP_KEY=\"{base64.b64encode(key).decode()}\"")
        return

    import base64
    mode = "TLS" if args.tls else args.transport.upper()
    print(f"Key (base64): {base64.b64encode(key).decode()}")
    print(f"Mode: {mode}")
    print(f"Listening: {args.host}:{args.port}")
    print()

    if args.tls:
        asyncio.run(run_tls_server(args.host, args.port, key,
                                    args.cert, args.tls_key))
    elif args.transport == "ws":
        asyncio.run(run_ws_server(args.host, args.port, key))
    else:
        asyncio.run(run_tcp_server(args.host, args.port, key))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
