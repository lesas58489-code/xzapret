"""
XZAP Tunnel Protocol — туннелирование TCP через XZAP.

Слои:
  1. Plaintext data
  2. AES-256-GCM / ChaCha20 encryption
  3. Random prefix (64 bytes) prepended to each frame
  4. TCP: [4B length][64B random prefix][encrypted data]

Handshake:
  1. Client → Server: encrypted {"cmd":"connect","host":"...","port":N}
  2. Server → Client: encrypted {"ok":true} or {"ok":false,"err":"..."}
  3. Bidirectional encrypted data pipe

Micro-fragmentation будет добавлена поверх как отдельный слой
после стабилизации базового туннеля.
"""

import asyncio
import json
import struct
import os
import logging
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .transport.fragmented import wrap_connection

log = logging.getLogger("xzap.tunnel")

PREFIX_SIZE = 16
MAX_FRAME_SIZE = 256 * 1024


async def _send_frame(writer, crypto, data):
    """Encrypt, add random prefix, send as [4B len][prefix][encrypted]."""
    encrypted = crypto.encrypt(data)
    prefix = os.urandom(PREFIX_SIZE)
    payload = prefix + encrypted
    frame = struct.pack(">I", len(payload)) + payload
    await writer.write(frame)


async def _recv_frame(reader, crypto):
    """Read [4B len][prefix][encrypted], strip prefix, decrypt.
    Works with both raw StreamReader and FragmentedReader.
    """
    hdr = await reader.readexactly(4)
    length = struct.unpack(">I", hdr)[0]
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length}")
    payload = await reader.readexactly(length)
    encrypted = payload[PREFIX_SIZE:]  # strip random prefix
    return crypto.decrypt(encrypted)


class XZAPTunnelClient:
    """Открывает туннель к target через XZAP-сервер."""

    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM,
                 use_tls: bool = False):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.use_tls = use_tls

    async def connect_tunnel(self, target_host: str, target_port: int):
        if self.use_tls:
            from .tls import open_tls_connection, random_sni
            sni = random_sni()
            raw_reader, raw_writer = await open_tls_connection(
                self.server_host, self.server_port, sni=sni,
            )
        else:
            raw_reader, raw_writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )
        sock = raw_writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Wrap TCP in fragmented transport
        reader, writer = wrap_connection(raw_reader, raw_writer,
                                          overlap=4, chaff_chance=0.2,
                                          delay_ms=(0, 0))

        # Handshake
        req = json.dumps({
            "cmd": "connect",
            "host": target_host,
            "port": target_port,
        }).encode()
        await _send_frame(writer, self.crypto, req)

        response = json.loads(await _recv_frame(reader, self.crypto))
        if not response.get("ok"):
            raise ConnectionError(f"XZAP tunnel refused: {response.get('err')}")

        log.info("Tunnel open → %s:%d", target_host, target_port)
        return XZAPTunnelStream(reader, writer, self.crypto, raw_writer)


class XZAPTunnelStream:
    """Поток данных поверх XZAP-туннеля."""

    def __init__(self, reader, writer, crypto, raw_writer=None):
        self._reader = reader
        self._writer = writer
        self._crypto = crypto
        self._raw_writer = raw_writer or writer

    async def write(self, data: bytes):
        await _send_frame(self._writer, self._crypto, data)

    async def read(self) -> bytes:
        return await _recv_frame(self._reader, self._crypto)

    async def close(self):
        try:
            self._raw_writer.close()
            await self._raw_writer.wait_closed()
        except Exception:
            pass


class XZAPTunnelServer:
    """Серверная сторона туннеля."""

    def __init__(self, crypto: XZAPCrypto, obfuscator=None):
        self.crypto = crypto

    async def handle(self, raw_reader, raw_writer):
        addr = raw_writer.get_extra_info("peername")
        log.debug("Tunnel connection from %s", addr)
        sock = raw_writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Wrap TCP in fragmented transport
        reader, writer = wrap_connection(raw_reader, raw_writer,
                                          overlap=4, chaff_chance=0.2,
                                          delay_ms=(0, 0))

        try:
            # Handshake
            ctrl = await _recv_frame(reader, self.crypto)
            req = json.loads(ctrl)
            if req.get("cmd") != "connect":
                await _send_frame(writer, self.crypto,
                                   json.dumps({"ok": False, "err": "bad cmd"}).encode())
                return

            target_host = req["host"]
            target_port = int(req["port"])

            try:
                target_r, target_w = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=10,
                )
            except Exception as e:
                await _send_frame(writer, self.crypto,
                                   json.dumps({"ok": False, "err": str(e)}).encode())
                return

            await _send_frame(writer, self.crypto,
                               json.dumps({"ok": True}).encode())
            log.info("Tunnelling → %s:%d", target_host, target_port)

            async def xzap_to_target():
                try:
                    while True:
                        data = await _recv_frame(reader, self.crypto)
                        log.debug("xzap→target: %d bytes", len(data))
                        target_w.write(data)
                        await target_w.drain()
                except Exception as e:
                    log.debug("xzap→target ended: %s", e)

            async def target_to_xzap():
                try:
                    while chunk := await target_r.read(65536):
                        log.debug("target→xzap: %d bytes", len(chunk))
                        await _send_frame(writer, self.crypto, chunk)
                    log.debug("target→xzap: EOF")
                except Exception as e:
                    log.debug("target→xzap ended: %s", e)

            await asyncio.gather(
                xzap_to_target(),
                target_to_xzap(),
            )

        except Exception as e:
            log.debug("Tunnel error: %s", e)
        finally:
            raw_writer.close()
