"""Tests for XZAP micro-fragmentation layer v3.0."""

import os
import time
import pytest
from xzap.fragmentation import (
    Fragmenter, Fragment, FragmentBuffer, FRAG_HEADER_SIZE,
    FLAG_CHAFF, FLAG_PADDED,
)


class TestFragment:
    def test_pack_unpack_basic(self):
        frag = Fragment(msg_id=12345, index=2, total=10, data=b"hello")
        raw = frag.pack()
        assert len(raw) == FRAG_HEADER_SIZE + 5
        restored = Fragment.unpack(raw)
        assert restored.msg_id == 12345
        assert restored.index == 2
        assert restored.total == 10
        assert restored.data == b"hello"
        assert not restored.is_chaff
        assert not restored.has_padding

    def test_pack_unpack_chaff(self):
        frag = Fragment(msg_id=999, index=0, total=1, data=b"garbage",
                        is_chaff=True)
        raw = frag.pack()
        restored = Fragment.unpack(raw)
        assert restored.is_chaff
        assert restored.data == b"garbage"

    def test_pack_unpack_padded(self):
        real_data = b"real_payload"
        padding = os.urandom(10)
        frag = Fragment(msg_id=1, index=0, total=1,
                        data=real_data + padding,
                        has_padding=True, padding_len=10)
        raw = frag.pack()
        restored = Fragment.unpack(raw)
        assert restored.data == real_data
        assert restored.has_padding
        assert restored.padding_len == 10

    def test_unpack_too_short(self):
        with pytest.raises(ValueError):
            Fragment.unpack(b"\x00" * 5)


class TestFragmenter:
    def test_fragment_and_reassemble(self):
        f = Fragmenter(min_size=24, max_size=48, chaff_chance=0, overlap=0,
                       padding_chance=0)
        data = os.urandom(500)
        frags = f.fragment(msg_id=1, data=data)
        real = [fr for fr in frags if not fr.is_chaff]
        assert len(real) >= 500 // 48
        result = Fragmenter.reassemble(frags)
        assert result == data

    def test_fragment_with_overlap(self):
        f = Fragmenter(min_size=10, max_size=10, overlap=4, chaff_chance=0,
                       padding_chance=0)
        data = b"A" * 40
        frags = f.fragment(msg_id=1, data=data)
        # With overlap, fragments are larger than chunk_size
        real = [fr for fr in frags if not fr.is_chaff]
        assert len(real) >= 3

    def test_chaff_generation(self):
        f = Fragmenter(chaff_chance=1.0, chaff_per_message=3)
        frags = f.fragment(msg_id=1, data=os.urandom(200))
        chaff = [fr for fr in frags if fr.is_chaff]
        assert len(chaff) >= 1
        assert len(chaff) <= 3
        # Chaff has different msg_id
        real_ids = {fr.msg_id for fr in frags if not fr.is_chaff}
        for c in chaff:
            assert c.msg_id not in real_ids

    def test_no_chaff_when_disabled(self):
        f = Fragmenter(chaff_chance=0)
        frags = f.fragment(msg_id=1, data=os.urandom(200))
        assert all(not fr.is_chaff for fr in frags)

    def test_padding_applied(self):
        f = Fragmenter(padding_chance=1.0, padding_max=50, chaff_chance=0,
                       overlap=0)
        frags = f.fragment(msg_id=1, data=os.urandom(100))
        real = [fr for fr in frags if not fr.is_chaff]
        assert any(fr.has_padding for fr in real)

    def test_disorder_built_in(self):
        """Fragments should come out shuffled."""
        f = Fragmenter(min_size=8, max_size=16, chaff_chance=0,
                       padding_chance=0, overlap=0)
        data = os.urandom(500)
        frags = f.fragment(msg_id=1, data=data)
        indices = [fr.index for fr in frags]
        # Shuffled → not sorted (probabilistic, but near-certain for 500B)
        assert indices != sorted(indices) or len(frags) <= 2

    def test_assign_path_hash_based(self):
        paths = {Fragmenter.assign_path(100, i, 4) for i in range(20)}
        assert len(paths) > 1  # not all on same path

    def test_all_fragments_have_correct_total(self):
        f = Fragmenter(chaff_chance=0, padding_chance=0, overlap=0)
        frags = f.fragment(msg_id=42, data=os.urandom(500))
        real = [fr for fr in frags if not fr.is_chaff]
        for fr in real:
            assert fr.total == len(real)
            assert fr.msg_id == 42


class TestFragmentBuffer:
    def test_reassemble_complete(self):
        buf = FragmentBuffer()
        frags = [
            Fragment(msg_id=1, index=0, total=3, data=b"AAA"),
            Fragment(msg_id=1, index=1, total=3, data=b"BBB"),
            Fragment(msg_id=1, index=2, total=3, data=b"CCC"),
        ]
        assert buf.add(frags[0]) is None
        assert buf.add(frags[1]) is None
        result = buf.add(frags[2])
        assert result == b"AAABBBCCC"
        assert buf.pending_count == 0

    def test_out_of_order(self):
        buf = FragmentBuffer()
        frags = [
            Fragment(msg_id=1, index=2, total=3, data=b"CCC"),
            Fragment(msg_id=1, index=0, total=3, data=b"AAA"),
            Fragment(msg_id=1, index=1, total=3, data=b"BBB"),
        ]
        assert buf.add(frags[0]) is None
        assert buf.add(frags[1]) is None
        result = buf.add(frags[2])
        assert result == b"AAABBBCCC"

    def test_chaff_dropped(self):
        buf = FragmentBuffer()
        chaff = Fragment(msg_id=999, index=0, total=1, data=b"fake",
                         is_chaff=True)
        assert buf.add(chaff) is None
        assert buf.pending_count == 0

    def test_multiple_messages(self):
        buf = FragmentBuffer()
        buf.add(Fragment(msg_id=1, index=0, total=2, data=b"A"))
        buf.add(Fragment(msg_id=2, index=0, total=2, data=b"X"))
        assert buf.pending_count == 2
        r1 = buf.add(Fragment(msg_id=1, index=1, total=2, data=b"B"))
        assert r1 == b"AB"
        assert buf.pending_count == 1
        r2 = buf.add(Fragment(msg_id=2, index=1, total=2, data=b"Y"))
        assert r2 == b"XY"
        assert buf.pending_count == 0

    def test_too_many_fragments_rejected(self):
        buf = FragmentBuffer()
        frag = Fragment(msg_id=1, index=0, total=500, data=b"x")
        assert buf.add(frag) is None
        assert buf.pending_count == 0

    def test_ttl_cleanup(self):
        buf = FragmentBuffer()
        buf.MAX_AGE_SEC = 0.01  # 10ms for test
        buf.CLEANUP_INTERVAL = 0.0
        buf.add(Fragment(msg_id=1, index=0, total=3, data=b"A"))
        assert buf.pending_count == 1
        time.sleep(0.05)
        # Trigger cleanup via add
        buf.add(Fragment(msg_id=2, index=0, total=2, data=b"B"))
        # msg_id=1 should be cleaned up
        assert buf.pending_count == 1  # only msg_id=2 remains

    def test_sharding(self):
        """Different msg_ids should land in different shards."""
        buf = FragmentBuffer()
        buf.add(Fragment(msg_id=0, index=0, total=2, data=b"A"))
        buf.add(Fragment(msg_id=4096, index=0, total=2, data=b"B"))
        # Both msg_id=0 and msg_id=4096 map to shard 0
        shard_0_count = len(buf._shards[0])
        assert shard_0_count == 2
        # msg_id=1 maps to shard 1
        buf.add(Fragment(msg_id=1, index=0, total=2, data=b"C"))
        assert len(buf._shards[1]) == 1
