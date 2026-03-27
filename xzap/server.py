"""
XZAP Server — listens for connections, reassembles fragments,
decrypts messages.
"""

import asyncio
import logging

from .message import XZAPMessage, HEADER_SIZE
from .crypto import XZAPCrypto, ALGO_AES_GCM
from .fragmentation import Fragment, FragmentBuffer
from .obfuscation import Obfuscator
from .transport import XZAPListener

log = logging.getLogger("xzap.server")


class XZAPServer:
    def __init__(self, host: str, port: int,
                 key: bytes = None, algo: str = ALGO_AES_GCM,
                 on_message=None):
        self.host = host
        self.port = port
        self.crypto = XZAPCrypto(key=key, algo=algo)
        self.obfuscator = Obfuscator()
        self.recv_buffer = FragmentBuffer()
        self.listener = XZAPListener(host, port)
        self.on_message = on_message  # callback(plaintext: bytes)

    async def start(self):
        await self.listener.start(self._handle_connection)
        log.info("XZAP server ready on %s:%d", self.host, self.port)

    async def serve_forever(self):
        await self.listener.serve_forever()

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        log.info("New connection from %s", addr)
        try:
            while True:
                # Read length-prefixed fragment
                header = await reader.readexactly(2)
                length = int.from_bytes(header, "big")
                raw = await reader.readexactly(length)

                # Parse fragment
                fragment = Fragment.unpack(raw)

                # Try to reassemble
                assembled = self.recv_buffer.add(fragment)
                if assembled is None:
                    continue

                # Strip random prefix
                assembled = self.obfuscator.strip_prefix(assembled)

                # Unpack message
                msg = XZAPMessage.unpack(assembled)

                # Decrypt
                plaintext = self.crypto.decrypt(msg.payload, aad=msg.aad())

                log.debug("Received msg seqno=%d (%dB)", msg.seqno, len(plaintext))

                if self.on_message:
                    await self.on_message(plaintext)

        except asyncio.IncompleteReadError:
            log.info("Connection closed by %s", addr)
        except Exception as e:
            log.error("Error handling %s: %s", addr, e)
        finally:
            writer.close()

    async def stop(self):
        await self.listener.stop()
