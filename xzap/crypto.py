"""
XZAP Crypto & Authorization Layer.

Supports AES-256-GCM and ChaCha20-Poly1305.
Key exchange via X25519 + HKDF-SHA256.
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

ALGO_AES_GCM = "aes-256-gcm"
ALGO_CHACHA20 = "chacha20-poly1305"
NONCE_SIZE = 12
KEY_SIZE = 32
AUTH_KEY_SIZE = 256


class XZAPKeyExchange:
    """X25519 key exchange + HKDF key derivation."""

    def __init__(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def derive_auth_key(self, peer_public_bytes: bytes, uuid: bytes) -> bytes:
        """Derive 256-byte auth_key from X25519 shared secret."""
        peer_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AUTH_KEY_SIZE,
            salt=uuid,
            info=b"xzap-auth",
        )
        return hkdf.derive(shared_secret)


class XZAPCrypto:
    """Encrypt/decrypt payloads with AES-256-GCM or ChaCha20-Poly1305."""

    def __init__(self, key: bytes = None, algo: str = ALGO_AES_GCM):
        self.algo = algo
        self.key = key or os.urandom(KEY_SIZE)
        self._cached_cipher = None

    def _cipher(self):
        if self._cached_cipher is None:
            if self.algo == ALGO_AES_GCM:
                self._cached_cipher = AESGCM(self.key)
            else:
                self._cached_cipher = ChaCha20Poly1305(self.key)
        return self._cached_cipher

    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        """Returns nonce || ciphertext || tag."""
        nonce = os.urandom(NONCE_SIZE)
        ct = self._cipher().encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, data: bytes, aad: bytes = None) -> bytes:
        """Expects nonce || ciphertext || tag."""
        if len(data) < NONCE_SIZE:
            raise ValueError("Ciphertext too short")
        nonce, ct = data[:NONCE_SIZE], data[NONCE_SIZE:]
        return self._cipher().decrypt(nonce, ct, aad)
