"""Tests for XZAP crypto layer."""

import os
import pytest
from xzap.crypto import XZAPCrypto, XZAPKeyExchange, ALGO_AES_GCM, ALGO_CHACHA20


class TestXZAPCrypto:
    def test_aes_gcm_roundtrip(self):
        crypto = XZAPCrypto(algo=ALGO_AES_GCM)
        plaintext = b"XZAP protocol test message"
        ct = crypto.encrypt(plaintext)
        assert crypto.decrypt(ct) == plaintext

    def test_chacha20_roundtrip(self):
        crypto = XZAPCrypto(algo=ALGO_CHACHA20)
        plaintext = b"XZAP protocol test message"
        ct = crypto.encrypt(plaintext)
        assert crypto.decrypt(ct) == plaintext

    def test_aes_gcm_with_aad(self):
        crypto = XZAPCrypto(algo=ALGO_AES_GCM)
        plaintext = b"secret data"
        aad = b"msg_id+seqno+length"
        ct = crypto.encrypt(plaintext, aad=aad)
        assert crypto.decrypt(ct, aad=aad) == plaintext

    def test_wrong_key_fails(self):
        crypto1 = XZAPCrypto()
        crypto2 = XZAPCrypto()  # different key
        ct = crypto1.encrypt(b"test")
        with pytest.raises(Exception):
            crypto2.decrypt(ct)

    def test_wrong_aad_fails(self):
        crypto = XZAPCrypto()
        ct = crypto.encrypt(b"test", aad=b"correct")
        with pytest.raises(Exception):
            crypto.decrypt(ct, aad=b"wrong")

    def test_ciphertext_different_each_time(self):
        crypto = XZAPCrypto()
        ct1 = crypto.encrypt(b"same")
        ct2 = crypto.encrypt(b"same")
        assert ct1 != ct2  # random nonce

    def test_large_payload(self):
        crypto = XZAPCrypto()
        data = os.urandom(100_000)
        assert crypto.decrypt(crypto.encrypt(data)) == data


class TestKeyExchange:
    def test_derive_shared_key(self):
        client_kx = XZAPKeyExchange()
        server_kx = XZAPKeyExchange()
        uuid = os.urandom(16)

        client_auth = client_kx.derive_auth_key(server_kx.public_bytes(), uuid)
        server_auth = server_kx.derive_auth_key(client_kx.public_bytes(), uuid)

        assert client_auth == server_auth
        assert len(client_auth) == 256

    def test_different_uuid_different_key(self):
        client_kx = XZAPKeyExchange()
        server_kx = XZAPKeyExchange()

        key1 = client_kx.derive_auth_key(server_kx.public_bytes(), b"uuid-1__________")
        key2 = client_kx.derive_auth_key(server_kx.public_bytes(), b"uuid-2__________")
        assert key1 != key2
