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

Anti-DPI техники:
  - Micro-fragmentation: каждый write() разбивается на 24-68 байт
  - Overlap: каждый фрагмент (кроме первого) повторяет N байт предыдущего
  - Chaff: мусорные пакеты вставляются после реальных данных
  - Random fragment sizes

Wire format per fragment:
  [4B total_len][1B flags][data]
  flags:
    bit 0 (0x01): chaff — receiver drops
    bit 1 (0x02): overlap — receiver strips first overlap_size bytes
"""

import asyncio
import os
import random
import struct
import logging

log = logging.getLogger("xzap.transport.fragmented")

FLAG_REAL = 0x00
FLAG_CHAFF = 0x01
FLAG_OVERLAP = 0x02

FRAG_HDR = 5


class FragmentedWriter:
    """Обёртка над asyncio.StreamWriter: фрагментирует данные при записи."""

    def __init__(self, writer: asyncio.StreamWriter,
                 min_frag: int = 24, max_frag: int = 68,
                 overlap: int = 0,
                 chaff_chance: float = 0.0,
                 delay_ms: tuple[int, int] = (0, 3),
                 frag_threshold: int = 150):
        self._writer = writer
        self.min_frag = min_frag
        self.max_frag = max_frag
        self.overlap = overlap
        self.chaff_chance = chaff_chance
        self.delay_min, self.delay_max = delay_ms
        self.frag_threshold = frag_threshold  # fragment only if data <= this

    async def write(self, data: bytes):
        """Отправляет данные. Мелкие пакеты фрагментируются, крупные — как есть."""
        if len(data) <= self.frag_threshold:
            await self._write_fragmented(data)
            return

        # Phase D3 — substantial chaff (D2 at 1.2% was below detection):
        #   chaff_chance% of bulk writes get 1-3 fake fragments of 800-4000B.
        #   Expected overhead at chaff=0.35: ~20% bandwidth tax — visible
        #   in pcap analysis but acceptable UX cost (mobile burst tolerated).
        # Single TCP write + single drain — no UX latency penalty.
        buf = bytearray()
        buf.extend(self._pack_fragment(data, FLAG_REAL))

        if self.chaff_chance > 0 and random.random() < self.chaff_chance:
            n_chaff = random.randint(1, 3)
            for _ in range(n_chaff):
                chaff_size = random.randint(800, 4000)
                buf.extend(self._pack_fragment(os.urandom(chaff_size), FLAG_CHAFF))

        self._writer.write(bytes(buf))
        await self._writer.drain()

    async def _write_fragmented(self, data: bytes):
        """Фрагментирует мелкие данные с overlap и chaff."""
        buf = bytearray()
        offset = 0
        is_first = True

        while offset < len(data):
            frag_size = random.randint(
                self.min_frag, min(self.max_frag, len(data) - offset)
            )
            remaining = len(data) - offset - frag_size
            if 0 < remaining < self.min_frag:
                frag_size = len(data) - offset

            if not is_first and self.overlap > 0 and offset >= self.overlap:
                overlap_start = offset - self.overlap
                chunk = data[overlap_start:offset + frag_size]
                buf.extend(self._pack_fragment(chunk, FLAG_OVERLAP))
            else:
                chunk = data[offset:offset + frag_size]
                buf.extend(self._pack_fragment(chunk, FLAG_REAL))

            offset += frag_size
            is_first = False

        # Send real data batch
        self._writer.write(bytes(buf))
        await self._writer.drain()

        # Send chaff separately (non-blocking)
        if self.chaff_chance > 0 and random.random() < self.chaff_chance:
            chaff_buf = bytearray()
            n_chaff = random.randint(1, 3)
            for _ in range(n_chaff):
                chaff_data = os.urandom(random.randint(self.min_frag, self.max_frag))
                chaff_buf.extend(self._pack_fragment(chaff_data, FLAG_CHAFF))
            self._writer.write(bytes(chaff_buf))

    @staticmethod
    def _pack_fragment(data: bytes, flags: int) -> bytes:
        """Pack [4B len][1B flags][data]."""
        total = len(data) + 1
        return struct.pack(">IB", total, flags) + data

    def close(self):
        self._writer.close()

    async def wait_closed(self):
        await self._writer.wait_closed()

    def get_extra_info(self, key):
        return self._writer.get_extra_info(key)


class FragmentedReader:
    """Обёртка над asyncio.StreamReader: собирает фрагменты при чтении."""

    def __init__(self, reader: asyncio.StreamReader, overlap: int = 0):
        self._reader = reader
        self._buffer = bytearray()
        self.overlap = overlap

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
        """Read one fragment: [4B len][1B flags][data]."""
        while True:
            hdr = await self._reader.readexactly(4)
            total = struct.unpack(">I", hdr)[0]
            if total == 0:
                raise asyncio.IncompleteReadError(b"", 2)
            payload = await self._reader.readexactly(total)

            flags = payload[0]
            data = payload[1:]

            if flags == FLAG_CHAFF:
                continue

            if flags == FLAG_OVERLAP and self.overlap > 0:
                data = data[self.overlap:]

            self._buffer.extend(data)
            return


def wrap_connection(reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter,
                    overlap: int = 0,
                    **kwargs) -> tuple[FragmentedReader, FragmentedWriter]:
    """Оборачивает TCP-соединение в фрагментированный транспорт."""
    return (
        FragmentedReader(reader, overlap=overlap),
        FragmentedWriter(writer, overlap=overlap, **kwargs),
    )
