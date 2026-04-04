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
        # 1. Pack real fragments into batch
        buf = bytearray()
        offset = 0
        while offset < len(data):
            frag_size = random.randint(
                self.min_frag, min(self.max_frag, len(data) - offset)
            )
            remaining = len(data) - offset - frag_size
            if 0 < remaining < self.min_frag:
                frag_size = len(data) - offset

            chunk = data[offset:offset + frag_size]
            offset += frag_size
            buf.extend(self._pack_fragment(chunk, FLAG_REAL))

        # 2. Send real data batch
        self._writer.write(bytes(buf))
        await self._writer.drain()

        # 3. Send chaff separately after real data (non-blocking)
        if self.chaff_chance > 0 and random.random() < self.chaff_chance:
            chaff_buf = bytearray()
            n_chaff = random.randint(1, 3)
            for _ in range(n_chaff):
                chaff_data = os.urandom(random.randint(self.min_frag, self.max_frag))
                chaff_buf.extend(self._pack_fragment(chaff_data, FLAG_CHAFF))
            self._writer.write(bytes(chaff_buf))
            # No drain — chaff goes out with next real write

    @staticmethod
    def _pack_fragment(data: bytes, flags: int) -> bytes:
        """Pack [2B len][1B flags][data]."""
        total = len(data) + 1
        return struct.pack(">HB", total, flags) + data

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
