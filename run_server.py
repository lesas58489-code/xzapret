"""
XZAP Server — запуск на VPS.

Принимает подключения от XZAP-клиентов, расшифровывает туннельные запросы,
проксирует трафик к целевым сайтам.

Использование:
  python3 run_server.py

Или с указанием порта и транспорта:
  python3 run_server.py --port 443 --transport ws --key-file xzap.key
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path

from xzap.crypto import XZAPCrypto
from xzap.obfuscation import Obfuscator
from xzap.tunnel import XZAPTunnelServer
from xzap.transport.tcp import XZAPListener

log = logging.getLogger("xzap")

KEY_FILE = "xzap.key"


def generate_key(path: str) -> bytes:
    """Генерирует 256-бит ключ и сохраняет в файл."""
    key = os.urandom(32)
    Path(path).write_bytes(key)
    log.info("Generated new key → %s (%d bytes)", path, len(key))
    return key


def load_key(path: str) -> bytes:
    """Загружает ключ из файла или генерирует новый."""
    p = Path(path)
    if p.exists():
        key = p.read_bytes()
        log.info("Loaded key from %s", path)
        return key
    return generate_key(path)


async def run_tcp_server(host: str, port: int, key: bytes):
    """TCP-сервер с поддержкой туннелирования."""
    crypto = XZAPCrypto(key=key)
    obfuscator = Obfuscator()
    tunnel_handler = XZAPTunnelServer(crypto, obfuscator)
    listener = XZAPListener(host, port)
    await listener.start(tunnel_handler.handle)
    log.info("XZAP TCP server ready on %s:%d", host, port)
    await listener.serve_forever()


async def run_ws_server(host: str, port: int, key: bytes):
    """WebSocket-сервер с поддержкой туннелирования."""
    from xzap.transport.ws import WSTransport
    crypto = XZAPCrypto(key=key)
    obfuscator = Obfuscator()
    tunnel_handler = XZAPTunnelServer(crypto, obfuscator)

    ws = WSTransport(host=host, port=port, path="/xzap")
    await ws.serve(tunnel_handler.handle)
    log.info("XZAP WS server ready on %s:%d/xzap", host, port)
    await ws.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="XZAP Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--transport", choices=["tcp", "ws"], default="tcp")
    parser.add_argument("--key-file", default=KEY_FILE)
    parser.add_argument("--gen-key", action="store_true",
                        help="Generate new key and print base64")
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
        print(f"\nНа клиенте используйте этот же ключ:")
        print(f"  export XZAP_KEY=\"{base64.b64encode(key).decode()}\"")
        return

    import base64
    print(f"Key (base64): {base64.b64encode(key).decode()}")
    print(f"Transport: {args.transport}")
    print(f"Listening: {args.host}:{args.port}")
    print()

    if args.transport == "ws":
        asyncio.run(run_ws_server(args.host, args.port, key))
    else:
        asyncio.run(run_tcp_server(args.host, args.port, key))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
