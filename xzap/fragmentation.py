"""
XZAP Micro-Fragmentation Layer.

Splits encrypted messages into tiny fragments (8–64 bytes),
applies disorder, overlap, and routes across multi-path connections.

Fragment wire format (12-byte header + data):
  [8B msg_id][2B frag_index][2B frag_total][NB frag_data]
"""

import struct
import os
import random

FRAG_HEADER_FMT = ">QHH"  # msg_id(8) + frag_index(2) + frag_total(2)
FRAG_HEADER_SIZE = 12

MIN_FRAG = 8
MAX_FRAG = 64


class Fragment:
    """Single fragment of an XZAP message."""

    __slots__ = ("msg_id", "index", "total", "data")

    def __init__(self, msg_id: int, index: int, total: int, data: bytes):
        self.msg_id = msg_id
        self.index = index
        self.total = total
        self.data = data

    def pack(self) -> bytes:
        header = struct.pack(FRAG_HEADER_FMT, self.msg_id, self.index, self.total)
        return header + self.data

    @classmethod
    def unpack(cls, raw: bytes) -> "Fragment":
        if len(raw) < FRAG_HEADER_SIZE:
            raise ValueError("Fragment too short")
        msg_id, idx, total = struct.unpack(FRAG_HEADER_FMT, raw[:FRAG_HEADER_SIZE])
        data = raw[FRAG_HEADER_SIZE:]
        return cls(msg_id, idx, total, data)

    def __repr__(self):
        return f"Fragment({self.index}/{self.total}, {len(self.data)}B)"


class Fragmenter:
    """Split data into micro-fragments and reassemble."""

    def __init__(self, min_size: int = MIN_FRAG, max_size: int = MAX_FRAG):
        self.min_size = min_size
        self.max_size = max_size

    def fragment(self, msg_id: int, data: bytes) -> list[Fragment]:
        """Split data into random-sized fragments."""
        # First pass: determine chunk boundaries
        chunks = []
        offset = 0
        while offset < len(data):
            size = random.randint(self.min_size, min(self.max_size, len(data) - offset))
            if len(data) - offset - size < self.min_size and len(data) - offset > size:
                size = len(data) - offset  # avoid tiny tail
            chunks.append(data[offset:offset + size])
            offset += size

        total = len(chunks)
        return [Fragment(msg_id, i, total, chunk) for i, chunk in enumerate(chunks)]

    def disorder(self, fragments: list[Fragment]) -> list[Fragment]:
        """Shuffle fragment order (DPI confusion)."""
        shuffled = fragments.copy()
        random.shuffle(shuffled)
        return shuffled

    @staticmethod
    def reassemble(fragments: list[Fragment]) -> bytes:
        """Reassemble fragments in correct order."""
        sorted_frags = sorted(fragments, key=lambda f: f.index)
        return b"".join(f.data for f in sorted_frags)

    @staticmethod
    def assign_path(msg_id: int, frag_index: int, num_paths: int) -> int:
        """Determine which SNI path a fragment should use."""
        return (msg_id + frag_index) % num_paths


class FragmentBuffer:
    """Server-side buffer that collects fragments until a message is complete."""

    def __init__(self):
        self._pending: dict[int, dict[int, Fragment]] = {}

    def add(self, fragment: Fragment) -> bytes | None:
        """Add fragment. Returns reassembled data if message is complete, else None."""
        mid = fragment.msg_id
        if mid not in self._pending:
            self._pending[mid] = {}
        self._pending[mid][fragment.index] = fragment

        if len(self._pending[mid]) == fragment.total:
            frags = list(self._pending.pop(mid).values())
            return Fragmenter.reassemble(frags)
        return None

    @property
    def pending_count(self) -> int:
        return len(self._pending)
