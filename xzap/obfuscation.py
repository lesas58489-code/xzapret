"""
XZAP Obfuscation Layer.

- Multi-SNI: parallel connections to white domains
- Fake ClientHello rotation from built-in dump pool
- 64-byte random prefix on every connection
- Decoy packets (badseq/badsum)
"""

import os
import random
import struct

WHITE_DOMAINS = [
    "youtube.com", "google.com", "cloudflare.com", "microsoft.com",
    "apple.com", "amazon.com", "facebook.com", "instagram.com",
    "yandex.ru", "vk.com", "avito.ru", "mail.ru",
    "ok.ru", "rambler.ru", "lenta.ru", "rbc.ru",
]

# Minimal fake TLS ClientHello templates (SNI varies)
# In production, these would be full captured dumps
_TLS_RECORD_HEADER = bytes([0x16, 0x03, 0x01])  # TLS 1.0 handshake


def _build_fake_client_hello(sni: str) -> bytes:
    """Build a minimal fake TLS ClientHello with given SNI."""
    sni_bytes = sni.encode("ascii")
    # SNI extension: type(0x00,0x00) + lengths + hostname
    sni_ext = (
        b"\x00\x00"  # extension type: server_name
        + struct.pack(">H", len(sni_bytes) + 5)  # extension length
        + struct.pack(">H", len(sni_bytes) + 3)  # server name list length
        + b"\x00"  # host name type
        + struct.pack(">H", len(sni_bytes))  # host name length
        + sni_bytes
    )
    # ClientHello body (simplified)
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    cipher_suites = b"\x13\x01\x13\x02\x13\x03\xc0\x2c\xc0\x2b"  # TLS 1.3 + common
    body = (
        b"\x03\x03"  # TLS 1.2 version
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + struct.pack(">H", len(cipher_suites)) + cipher_suites
        + b"\x01\x00"  # compression: null
        + struct.pack(">H", len(sni_ext)) + sni_ext
    )
    # Handshake header
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    # TLS record
    record = _TLS_RECORD_HEADER + struct.pack(">H", len(handshake)) + handshake
    return record


class FakeClientHelloPool:
    """Pool of pre-built fake ClientHello records for rotation."""

    def __init__(self, domains: list[str] = None):
        self.domains = domains or WHITE_DOMAINS[:8]
        self._pool = [_build_fake_client_hello(d) for d in self.domains]

    def get_random(self) -> bytes:
        return random.choice(self._pool)

    def get_for_domain(self, domain: str) -> bytes:
        return _build_fake_client_hello(domain)

    def rotate(self):
        """Re-randomize the pool (new random bytes in each ClientHello)."""
        self._pool = [_build_fake_client_hello(d) for d in self.domains]


class Obfuscator:
    """Multi-SNI path manager + obfuscation utilities."""

    def __init__(self, num_paths: int = 4, domains: list[str] = None):
        self.num_paths = num_paths
        self.all_domains = domains or WHITE_DOMAINS
        self.active_snis = random.sample(
            self.all_domains, min(num_paths, len(self.all_domains))
        )
        self.fake_pool = FakeClientHelloPool()

    def rotate_sni(self) -> list[str]:
        """Select new set of SNI domains."""
        self.active_snis = random.sample(
            self.all_domains, min(self.num_paths, len(self.all_domains))
        )
        return self.active_snis

    def add_prefix(self, data: bytes) -> bytes:
        """Prepend 64-byte random prefix."""
        return os.urandom(64) + data

    def strip_prefix(self, data: bytes) -> bytes:
        """Remove 64-byte prefix."""
        return data[64:]

    def make_decoy(self, size: int = 64) -> bytes:
        """Generate a decoy packet (random data, to be sent with bad checksum)."""
        return os.urandom(size)

    def get_path_sni(self, msg_id: int, frag_index: int) -> str:
        """Get SNI for a specific fragment."""
        idx = (msg_id + frag_index) % len(self.active_snis)
        return self.active_snis[idx]
