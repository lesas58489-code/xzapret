"""
XZAP Fragmented Transport — микрофрагментация поверх TCP.

Этот слой находится НИЖЕ tunnel protocol и ВЫШЕ raw TCP:

  Application data
       ↓
  Tunnel (encrypt + prefix)
       ↓
  FragmentedTransport (split into 24-68 byte TCP segments)
       ↓
  Raw TCP socket

Каждый вызов write() разбивает данные на мелкие куски (24-68 байт),
каждый кусок отправляется как отдельный TCP write + flush.

Для DPI это выглядит как множество мелких пакетов с рандомными данными,
что затрудняет анализ и pattern matching.

Дополнительно:
  - Random delay между фрагментами (0-5 мс)
  - Chaff (мусорные) пакеты вставляются между реальными
  - Random padding на каждый фрагмент

Wire format per fragment:
  [2B total_len][1B flags][data]
  flags: 0x00 = real data, 0x01 = chaff (receiver drops)
"""

import asyncio
import os
import random
import struct
import logging

log = logging.getLogger("xzap.transport.fragmented")

FLAG_REAL = 0x00
FLAG_CHAFF = 0x01

# Fragment header: [2B total_len][1B flags] = 3 bytes
FRAG_HDR = 3


class FragmentedWriter:
    """Обёртка над asyncio.StreamWriter: фрагментирует данные при записи."""

    def __init__(self, writer: asyncio.StreamWriter,
                 min_frag: int = 24, max_frag: int = 68,
                 chaff_chance: float = 0.2,
                 delay_ms: tuple[int, int] = (0, 3)):
        self._writer = writer
        self.min_frag = min_frag
        self.max_frag = max_frag
        self.chaff_chance = chaff_chance
        self.delay_min, self.delay_max = delay_ms

    async def write(self, data: bytes):
        """Разбивает data на микрофрагменты и отправляет."""
        offset = 0
        while offset < len(data):
            # Random fragment size
            frag_size = random.randint(
                self.min_frag, min(self.max_frag, len(data) - offset)
            )
            # Avoid tiny tail
            remaining = len(data) - offset - frag_size
            if 0 < remaining < self.min_frag:
                frag_size = len(data) - offset

            chunk = data[offset:offset + frag_size]
            offset += frag_size

            # Maybe insert chaff before real fragment
            if random.random() < self.chaff_chance:
                await self._send_chaff()

            # Send real fragment
            await self._send_fragment(chunk, FLAG_REAL)

            # Small random delay between fragments
            if self.delay_max > 0 and offset < len(data):
                delay = random.randint(self.delay_min, self.delay_max) / 1000.0
                if delay > 0:
                    await asyncio.sleep(delay)

    async def _send_fragment(self, data: bytes, flags: int):
        """Send [2B len][1B flags][data]."""
        total = len(data) + 1  # data + flags byte
        self._writer.write(struct.pack(">HB", total, flags) + data)
        await self._writer.drain()

    async def _send_chaff(self):
        """Send a chaff (garbage) fragment."""
        size = random.randint(self.min_frag, self.max_frag)
        await self._send_fragment(os.urandom(size), FLAG_CHAFF)

    def close(self):
        self._writer.close()

    async def wait_closed(self):
        await self._writer.wait_closed()

    def get_extra_info(self, key):
        return self._writer.get_extra_info(key)


class FragmentedReader:
    """Обёртка над asyncio.StreamReader: собирает фрагменты при чтении."""

    def __init__(self, reader: asyncio.StreamReader):
        self._reader = reader
        self._buffer = bytearray()

    async def readexactly(self, n: int) -> bytes:
        """Читает ровно n байт, собирая из фрагментов."""
        while len(self._buffer) < n:
            await self._read_fragment()
        result = bytes(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return result

    async def read(self, n: int) -> bytes:
        """Читает до n байт."""
        if not self._buffer:
            await self._read_fragment()
        result = bytes(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return result

    async def _read_fragment(self):
        """Read one fragment: [2B len][1B flags][data]. Drop chaff."""
        while True:
            hdr = await self._reader.readexactly(2)
            total = struct.unpack(">H", hdr)[0]
            payload = await self._reader.readexactly(total)

            flags = payload[0]
            data = payload[1:]

            if flags == FLAG_CHAFF:
                # Drop chaff silently
                continue

            # Real data — add to buffer
            self._buffer.extend(data)
            return


def wrap_connection(reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter,
                    **kwargs) -> tuple[FragmentedReader, FragmentedWriter]:
    """Оборачивает TCP-соединение в фрагментированный транспорт."""
    return FragmentedReader(reader), FragmentedWriter(writer, **kwargs)
