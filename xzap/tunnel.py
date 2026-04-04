"""
XZAP Tunnel Protocol — туннелирование TCP через полный XZAP стек.

Слои (в порядке отправки):
  1. Plaintext data
  2. XZAPMessage (msg_id, seqno, msg_key)
  3. AES-256-GCM / ChaCha20 encryption
  4. 64-byte random prefix
  5. Micro-fragmentation (24-68 bytes, chaff, padding, disorder)
  6. TCP: [2B length][fragment] per fragment

Handshake использует простые encrypted фреймы (без фрагментации)
для надёжности. Фрагментация включается после CONNECT OK.
"""

import asyncio
import json
import struct
import os
import logging
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .message import XZAPMessage
from .fragmentation import Fragmenter, FragmentBuffer, Fragment
from .obfuscation import Obfuscator

log = logging.getLogger("xzap.tunnel")

MAX_FRAME_SIZE = 256 * 1024


# ──────────────────────────────────────────────
# Simple frames — used for handshake only
# ──────────────────────────────────────────────

async def _send_simple(writer, crypto, data):
    """Handshake frame: [4B len][encrypted]."""
    encrypted = crypto.encrypt(data)
    writer.write(struct.pack(">I", len(encrypted)) + encrypted)
    await writer.drain()


async def _recv_simple(reader, crypto):
    """Read handshake frame."""
    hdr = await reader.readexactly(4)
    length = struct.unpack(">I", hdr)[0]
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length}")
    return crypto.decrypt(await reader.readexactly(length))


# ──────────────────────────────────────────────
# XZAP frames — full protocol stack for data phase
# ──────────────────────────────────────────────

class XZAPFrameSender:
    """Отправка данных через полный XZAP стек."""

    def __init__(self, writer: asyncio.StreamWriter, crypto: XZAPCrypto,
                 fragmenter: Fragmenter, obfuscator: Obfuscator):
        self._writer = writer
        self._crypto = crypto
        self._fragmenter = fragmenter
        self._obfuscator = obfuscator
        self._seqno = 0

    async def send(self, data: bytes):
        """data → XZAPMessage → encrypt → prefix → fragment → TCP."""
        msg = XZAPMessage(data, seqno=self._seqno)
        self._seqno += 1

        # Encrypt
        encrypted = self._crypto.encrypt(msg.payload, aad=msg.aad())
        msg.payload = encrypted
        packed = msg.pack()

        # Random prefix
        packed = self._obfuscator.add_prefix(packed)

        # Fragment (with chaff, padding, disorder)
        fragments = self._fragmenter.fragment(msg.msg_id, packed)

        # Send all fragments as [2B len][fragment]
        for frag in fragments:
            frag_raw = frag.pack()
            self._writer.write(len(frag_raw).to_bytes(2, "big") + frag_raw)
        await self._writer.drain()


class XZAPFrameReceiver:
    """Приём данных через полный XZAP стек."""

    def __init__(self, reader: asyncio.StreamReader, crypto: XZAPCrypto,
                 obfuscator: Obfuscator):
        self._reader = reader
        self._crypto = crypto
        self._obfuscator = obfuscator
        self._buf = FragmentBuffer()

    async def recv(self) -> bytes:
        """TCP → fragments → reassemble → strip prefix → XZAPMessage → decrypt."""
        while True:
            hdr = await self._reader.readexactly(2)
            length = int.from_bytes(hdr, "big")
            raw = await self._reader.readexactly(length)

            frag = Fragment.unpack(raw)
            assembled = self._buf.add(frag)
            if assembled is not None:
                # Strip random prefix
                assembled = self._obfuscator.strip_prefix(assembled)
                # Unpack message
                msg = XZAPMessage.unpack(assembled)
                # Decrypt
                return self._crypto.decrypt(msg.payload, aad=msg.aad())


# ──────────────────────────────────────────────
# Tunnel Client
# ──────────────────────────────────────────────

class XZAPTunnelClient:
    """Открывает туннель к target через XZAP-сервер с полным стеком."""

    def __init__(self, server_host: str, server_port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = XZAPCrypto(key=key, algo=algo)

    async def connect_tunnel(self, target_host: str, target_port: int):
        reader, writer = await asyncio.open_connection(
            self.server_host, self.server_port
        )
        # Disable Nagle for low-latency fragment delivery
        sock = writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Handshake: simple encrypted frames
        req = json.dumps({
            "cmd": "connect",
            "host": target_host,
            "port": target_port,
        }).encode()
        await _send_simple(writer, self.crypto, req)

        response = json.loads(await _recv_simple(reader, self.crypto))
        if not response.get("ok"):
            raise ConnectionError(f"XZAP tunnel refused: {response.get('err')}")

        log.info("Tunnel open → %s:%d", target_host, target_port)

        # Data phase: full XZAP stack
        fragmenter = Fragmenter(
            min_size=24, max_size=68,
            overlap=0,              # overlap ломает reassembly
            padding_chance=0.4,     # random padding
            chaff_chance=0.3,       # fake fragments
            chaff_per_message=2,
            disorder=True,          # shuffle fragments
        )
        obfuscator = Obfuscator(num_paths=1)

        sender = XZAPFrameSender(writer, self.crypto, fragmenter, obfuscator)
        receiver = XZAPFrameReceiver(reader, self.crypto, obfuscator)

        return XZAPTunnelStream(sender, receiver, writer)


class XZAPTunnelStream:
    """Поток данных поверх XZAP-туннеля."""

    def __init__(self, sender: XZAPFrameSender,
                 receiver: XZAPFrameReceiver,
                 writer: asyncio.StreamWriter):
        self._sender = sender
        self._receiver = receiver
        self._writer = writer

    async def write(self, data: bytes):
        await self._sender.send(data)

    async def read(self) -> bytes:
        return await self._receiver.recv()

    async def close(self):
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass


# ──────────────────────────────────────────────
# Tunnel Server
# ──────────────────────────────────────────────

class XZAPTunnelServer:
    """Серверная сторона туннеля с полным XZAP стеком."""

    def __init__(self, crypto: XZAPCrypto, obfuscator=None):
        self.crypto = crypto

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        log.debug("Tunnel connection from %s", addr)
        # Disable Nagle for low-latency fragment delivery
        sock = writer.get_extra_info("socket")
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            # Handshake: simple encrypted frames
            ctrl = await _recv_simple(reader, self.crypto)
            req = json.loads(ctrl)
            if req.get("cmd") != "connect":
                await _send_simple(writer, self.crypto,
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
                await _send_simple(writer, self.crypto,
                                    json.dumps({"ok": False, "err": str(e)}).encode())
                return

            await _send_simple(writer, self.crypto,
                                json.dumps({"ok": True}).encode())
            log.info("Tunnelling → %s:%d", target_host, target_port)

            # Data phase: full XZAP stack
            fragmenter = Fragmenter(
                min_size=24, max_size=68,
                overlap=0,
                padding_chance=0.4,
                chaff_chance=0.3,
                chaff_per_message=2,
                disorder=True,
            )
            obfuscator = Obfuscator(num_paths=1)

            sender = XZAPFrameSender(writer, self.crypto, fragmenter, obfuscator)
            receiver = XZAPFrameReceiver(reader, self.crypto, obfuscator)

            async def xzap_to_target():
                try:
                    while True:
                        data = await receiver.recv()
                        log.debug("xzap→target: %d bytes", len(data))
                        target_w.write(data)
                        await target_w.drain()
                except Exception as e:
                    log.debug("xzap→target ended: %s", e)

            async def target_to_xzap():
                try:
                    while chunk := await target_r.read(16384):
                        log.debug("target→xzap: %d bytes", len(chunk))
                        await sender.send(chunk)
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
            writer.close()
