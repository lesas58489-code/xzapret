"""Tests for XZAP micro-fragmentation layer."""

import os
import pytest
from xzap.fragmentation import Fragmenter, Fragment, FragmentBuffer, FRAG_HEADER_SIZE


class TestFragment:
    def test_pack_unpack(self):
        frag = Fragment(msg_id=12345, index=2, total=10, data=b"hello")
        raw = frag.pack()
        assert len(raw) == FRAG_HEADER_SIZE + 5
        restored = Fragment.unpack(raw)
        assert restored.msg_id == 12345
        assert restored.index == 2
        assert restored.total == 10
        assert restored.data == b"hello"

    def test_unpack_too_short(self):
        with pytest.raises(ValueError):
            Fragment.unpack(b"\x00" * 5)


class TestFragmenter:
    def test_fragment_small(self):
        f = Fragmenter(min_size=8, max_size=16)
        data = b"A" * 50
        frags = f.fragment(msg_id=1, data=data)
        assert len(frags) >= 2
        assert all(isinstance(fr, Fragment) for fr in frags)
        reassembled = Fragmenter.reassemble(frags)
        assert reassembled == data

    def test_fragment_large(self):
        f = Fragmenter(min_size=32, max_size=64)
        data = os.urandom(10_000)
        frags = f.fragment(msg_id=99, data=data)
        assert len(frags) >= 10_000 // 64
        assert Fragmenter.reassemble(frags) == data

    def test_fragment_exact_size(self):
        f = Fragmenter(min_size=10, max_size=10)
        data = b"X" * 30
        frags = f.fragment(msg_id=1, data=data)
        assert len(frags) == 3
        assert Fragmenter.reassemble(frags) == data

    def test_disorder_and_reassemble(self):
        f = Fragmenter(min_size=8, max_size=16)
        data = os.urandom(200)
        frags = f.fragment(msg_id=1, data=data)
        disordered = f.disorder(frags)
        # Order should differ (probabilistic, but very likely for 200B)
        assert Fragmenter.reassemble(disordered) == data

    def test_assign_path(self):
        paths = [Fragmenter.assign_path(100, i, 4) for i in range(8)]
        assert set(paths) == {0, 1, 2, 3}

    def test_all_fragments_have_correct_total(self):
        f = Fragmenter()
        frags = f.fragment(msg_id=42, data=os.urandom(500))
        for fr in frags:
            assert fr.total == len(frags)
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
