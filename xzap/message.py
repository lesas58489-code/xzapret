"""
XZAP Message Format — MTProto-style header with msg_id, seqno, msg_key.

Wire format (30-byte header + payload):
  [8B msg_id][4B seqno][2B length][16B msg_key][NB payload]
"""

import struct
import os
import time
import hmac
import hashlib

HEADER_SIZE = 30
HEADER_FMT = ">QIH"  # msg_id(8) + seqno(4) + length(2) = 14 bytes + 16 msg_key


def generate_msg_id() -> int:
    """Monotonic msg_id: (unix_ms << 20) | random_20bit."""
    ts_ms = int(time.time() * 1000)
    rnd = int.from_bytes(os.urandom(3), "big") & 0xFFFFF
    return (ts_ms << 20) | rnd


def compute_msg_key(auth_key: bytes, plaintext: bytes) -> bytes:
    """msg_key = HMAC-SHA256(auth_key[88:120], plaintext)[:16]."""
    key_slice = auth_key[88:120] if len(auth_key) >= 120 else auth_key[:32]
    return hmac.new(key_slice, plaintext, hashlib.sha256).digest()[:16]


class XZAPMessage:
    """Single XZAP protocol message."""

    def __init__(self, payload: bytes, seqno: int = 0, msg_id: int = None,
                 msg_key: bytes = None):
        self.msg_id = msg_id or generate_msg_id()
        self.seqno = seqno
        self.payload = payload
        self.msg_key = msg_key or os.urandom(16)

    def pack(self) -> bytes:
        """Serialize message to bytes."""
        header = struct.pack(HEADER_FMT, self.msg_id, self.seqno, len(self.payload))
        return header + self.msg_key + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> "XZAPMessage":
        """Deserialize message from bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Data too short: {len(data)} < {HEADER_SIZE}")
        msg_id, seqno, length = struct.unpack(HEADER_FMT, data[:14])
        msg_key = data[14:30]
        payload = data[30:30 + length]
        if len(payload) < length:
            raise ValueError(f"Payload truncated: {len(payload)} < {length}")
        return cls(payload, seqno=seqno, msg_id=msg_id, msg_key=msg_key)

    def aad(self) -> bytes:
        """Additional Authenticated Data for encryption."""
        return struct.pack(HEADER_FMT, self.msg_id, self.seqno, len(self.payload))

    def __repr__(self):
        return (f"XZAPMessage(msg_id={self.msg_id}, seqno={self.seqno}, "
                f"payload={len(self.payload)}B)")
