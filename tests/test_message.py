"""Tests for XZAP message pack/unpack."""

import pytest
from xzap.message import XZAPMessage, HEADER_SIZE, generate_msg_id


def test_msg_id_unique():
    ids = {generate_msg_id() for _ in range(1000)}
    assert len(ids) == 1000


def test_pack_unpack():
    payload = b"Hello XZAP protocol!"
    msg = XZAPMessage(payload, seqno=42)
    packed = msg.pack()

    assert len(packed) == HEADER_SIZE + len(payload)

    restored = XZAPMessage.unpack(packed)
    assert restored.msg_id == msg.msg_id
    assert restored.seqno == 42
    assert restored.payload == payload
    assert restored.msg_key == msg.msg_key


def test_pack_unpack_empty():
    msg = XZAPMessage(b"", seqno=0)
    packed = msg.pack()
    restored = XZAPMessage.unpack(packed)
    assert restored.payload == b""
    assert restored.seqno == 0


def test_pack_unpack_large():
    payload = b"\xab" * 65000
    msg = XZAPMessage(payload, seqno=999)
    packed = msg.pack()
    restored = XZAPMessage.unpack(packed)
    assert restored.payload == payload


def test_unpack_too_short():
    with pytest.raises(ValueError, match="too short"):
        XZAPMessage.unpack(b"\x00" * 10)


def test_aad():
    msg = XZAPMessage(b"test", seqno=1)
    aad = msg.aad()
    assert len(aad) == 14  # 8 + 4 + 2
