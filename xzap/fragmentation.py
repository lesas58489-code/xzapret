"""
XZAP Micro-Fragmentation Layer v3.0 — High-Performance.

Features:
  - Micro-fragments: 24–68 bytes (random size)
  - Overlap: fragments overlap by N bytes (confuses DPI reassembly)
  - Dynamic padding: random padding appended to fragments
  - Chaff (fake fragments): garbage fragments with fake msg_id
  - Hash-based path assignment: SHA256(msg_id:frag_index) % num_paths
  - Sharded FragmentBuffer: 4096 shards for lock-free parallel processing
  - TTL: incomplete messages auto-dropped after 2 seconds
  - Anti-DoS: max 400 fragments per message

Fragment wire format (13-byte header + data):
  [8B msg_id][2B frag_index][2B frag_total][1B flags][NB frag_data]

Flags byte:
  bit 0: is_chaff (fake fragment, receiver must drop)
  bit 1: has_padding (last N bytes are random padding)
"""

import struct
import os
import random
import hashlib
import time

FRAG_HEADER_FMT = ">QHHB"  # msg_id(8) + index(2) + total(2) + flags(1) = 13
FRAG_HEADER_SIZE = 13

FLAG_CHAFF = 0x01
FLAG_PADDED = 0x02


# ──────────────────────────────────────────────
# Fragment
# ──────────────────────────────────────────────

class Fragment:
    """Single fragment of an XZAP message."""

    __slots__ = ("msg_id", "index", "total", "data", "path_id",
                 "is_chaff", "has_padding", "padding_len", "timestamp")

    def __init__(self, msg_id: int, index: int, total: int, data: bytes,
                 path_id: int = 0, is_chaff: bool = False,
                 has_padding: bool = False, padding_len: int = 0):
        self.msg_id = msg_id
        self.index = index
        self.total = total
        self.data = data
        self.path_id = path_id
        self.is_chaff = is_chaff
        self.has_padding = has_padding
        self.padding_len = padding_len
        self.timestamp = 0.0

    def pack(self) -> bytes:
        flags = 0
        if self.is_chaff:
            flags |= FLAG_CHAFF
        if self.has_padding:
            flags |= FLAG_PADDED
        header = struct.pack(FRAG_HEADER_FMT,
                             self.msg_id, self.index, self.total, flags)
        if self.has_padding:
            # Append padding length as last byte
            return header + self.data + bytes([self.padding_len])
        return header + self.data

    @classmethod
    def unpack(cls, raw: bytes) -> "Fragment":
        if len(raw) < FRAG_HEADER_SIZE:
            raise ValueError("Fragment too short")
        msg_id, idx, total, flags = struct.unpack(
            FRAG_HEADER_FMT, raw[:FRAG_HEADER_SIZE]
        )
        is_chaff = bool(flags & FLAG_CHAFF)
        has_padding = bool(flags & FLAG_PADDED)
        data = raw[FRAG_HEADER_SIZE:]
        padding_len = 0
        if has_padding and len(data) > 0:
            padding_len = data[-1]
            data = data[:-(padding_len + 1)]  # strip padding + padding_len byte
        return cls(msg_id, idx, total, data, is_chaff=is_chaff,
                   has_padding=has_padding, padding_len=padding_len)

    def __repr__(self):
        kind = "CHAFF" if self.is_chaff else f"{self.index}/{self.total}"
        return f"Fragment({kind}, {len(self.data)}B, path={self.path_id})"


# ──────────────────────────────────────────────
# Fragmenter
# ──────────────────────────────────────────────

class Fragmenter:
    """Split data into micro-fragments with overlap, padding, chaff, and disorder."""

    def __init__(self, min_size: int = 24, max_size: int = 68,
                 overlap: int = 4,
                 padding_chance: float = 0.45, padding_max: int = 96,
                 chaff_chance: float = 0.35, chaff_per_message: int = 3,
                 chaff_size_min: int = 140, chaff_size_max: int = 920,
                 disorder: bool = True):
        self.min_size = min_size
        self.max_size = max_size
        self.overlap = overlap
        self.padding_chance = padding_chance
        self.padding_max = padding_max
        self.chaff_chance = chaff_chance
        self.chaff_per_message = chaff_per_message
        self.chaff_size_min = chaff_size_min
        self.chaff_size_max = chaff_size_max
        self._disorder = disorder

    def fragment(self, msg_id: int, data: bytes,
                 num_paths: int = 8) -> list[Fragment]:
        """Split data into random-sized fragments with overlap and padding."""
        if not data:
            return []

        fragments: list[Fragment] = []
        offset = 0

        while offset < len(data):
            size = random.randint(
                self.min_size, min(self.max_size, len(data) - offset)
            )
            # Avoid tiny tail
            remaining = len(data) - offset - size
            if 0 < remaining < self.min_size:
                size = len(data) - offset

            # Overlap: include bytes from previous chunk
            if offset > 0 and self.overlap > 0:
                overlap_start = max(0, offset - self.overlap)
                chunk = data[overlap_start:offset + size]
            else:
                chunk = data[offset:offset + size]

            # Dynamic padding
            padding_len = 0
            has_padding = False
            if random.random() < self.padding_chance:
                padding_len = random.randint(1, min(self.padding_max, 255))
                chunk = chunk + os.urandom(padding_len)
                has_padding = True

            frag = Fragment(
                msg_id=msg_id,
                index=len(fragments),
                total=0,  # set below
                data=chunk,
                path_id=self.assign_path(msg_id, len(fragments), num_paths),
                has_padding=has_padding,
                padding_len=padding_len,
            )
            fragments.append(frag)
            offset += size

        # Set total on all real fragments
        total = len(fragments)
        for f in fragments:
            f.total = total

        # Chaff (fake) fragments
        if random.random() < self.chaff_chance:
            n_chaff = random.randint(1, self.chaff_per_message)
            for _ in range(n_chaff):
                chaff_size = random.randint(self.chaff_size_min, self.chaff_size_max)
                chaff = Fragment(
                    msg_id=random.randint(1_000_000, 9_999_999),
                    index=0,
                    total=1,
                    data=os.urandom(chaff_size),
                    path_id=random.randint(0, max(num_paths - 1, 0)),
                    is_chaff=True,
                )
                fragments.append(chaff)

        # Full disorder (can be disabled for tunnel mode)
        if self._disorder:
            random.shuffle(fragments)
        return fragments

    def disorder(self, fragments: list[Fragment]) -> list[Fragment]:
        """Shuffle fragment order (DPI confusion)."""
        shuffled = fragments.copy()
        random.shuffle(shuffled)
        return shuffled

    @staticmethod
    def reassemble(fragments: list[Fragment]) -> bytes:
        """Reassemble real fragments in correct order (drops chaff)."""
        real = [f for f in fragments if not f.is_chaff]
        real.sort(key=lambda f: f.index)
        return b"".join(f.data for f in real)

    @staticmethod
    def assign_path(msg_id: int, frag_index: int, num_paths: int) -> int:
        """Hash-based path assignment (more uniform than modulo)."""
        h = hashlib.sha256(f"{msg_id}:{frag_index}".encode()).digest()
        return int.from_bytes(h[:4], "big") % num_paths


# ──────────────────────────────────────────────
# FragmentBuffer — sharded, with TTL and anti-DoS
# ──────────────────────────────────────────────

class FragmentBuffer:
    """
    Server-side buffer that collects fragments until a message is complete.

    Performance features:
      - 4096 shards: msg_id % NUM_SHARDS → independent dict per shard
      - TTL: incomplete messages dropped after MAX_AGE_SEC
      - Anti-DoS: messages with > MAX_FRAGS_PER_MSG fragments dropped
      - Pre-allocation: first fragment pre-allocates list[total]
      - Chaff auto-dropped on receive
    """

    NUM_SHARDS = 4096
    MAX_AGE_SEC = 2.0
    MAX_FRAGS_PER_MSG = 400
    CLEANUP_INTERVAL = 1.0

    def __init__(self):
        self._shards: list[dict[int, list[Fragment | None]]] = [
            {} for _ in range(self.NUM_SHARDS)
        ]
        self._timestamps: list[dict[int, float]] = [
            {} for _ in range(self.NUM_SHARDS)
        ]
        self._last_cleanup = time.monotonic()

    def add(self, fragment: Fragment) -> bytes | None:
        """Add fragment. Returns reassembled data if complete, else None.
        Chaff fragments are silently dropped.
        """
        if fragment.is_chaff:
            return None

        if fragment.total > self.MAX_FRAGS_PER_MSG:
            return None

        now = time.monotonic()
        sid = fragment.msg_id % self.NUM_SHARDS
        shard = self._shards[sid]
        ts = self._timestamps[sid]
        mid = fragment.msg_id

        # Pre-allocate on first fragment for this msg_id
        if mid not in shard:
            shard[mid] = [None] * fragment.total
            ts[mid] = now

        buf = shard[mid]

        # Bounds check
        if fragment.index >= len(buf):
            return None

        buf[fragment.index] = fragment

        # Check if complete
        if all(slot is not None for slot in buf):
            result = b"".join(f.data for f in buf)
            del shard[mid]
            del ts[mid]
            return result

        # Periodic cleanup
        if now - self._last_cleanup > self.CLEANUP_INTERVAL:
            self._cleanup(now)

        return None

    def _cleanup(self, now: float):
        """Remove expired incomplete messages across all shards."""
        self._last_cleanup = now
        for sid in range(self.NUM_SHARDS):
            ts = self._timestamps[sid]
            expired = [mid for mid, t in ts.items()
                       if now - t > self.MAX_AGE_SEC]
            for mid in expired:
                self._shards[sid].pop(mid, None)
                ts.pop(mid, None)

    @property
    def pending_count(self) -> int:
        return sum(len(s) for s in self._shards)
