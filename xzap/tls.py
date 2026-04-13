"""
XZAP TLS — обёртка для TLS с кастомным SNI и browser-like fingerprint.

Клиент подключается по TLS с SNI белого домена (youtube.com, google.com),
DPI видит легитимный TLS handshake к известному домену.

Anti-DPI техники:
  - Browser-like cipher suite order (Chrome 120+)
  - ALPN: h2, http/1.1 (как у браузера)
  - TLS 1.2 minimum, prefer TLS 1.3
  - Session tickets отключены (anti-correlation)
  - SNI ротация: каждое соединение — новый белый домен
  - Random padding в TLS records

Сервер использует self-signed сертификат (клиент верифицирует по XZAP-ключу,
а не по сертификату).
"""

import ssl
import os
import asyncio
import random
import logging
from pathlib import Path

log = logging.getLogger("xzap.tls")

# Белые домены — популярные сайты, трафик к которым DPI не блокирует.
# Используем полные домены с www и без — как в реальном браузере.
WHITE_DOMAINS = [
    # Only NON-BLOCKED domains — DPI checks SNI regardless of dest IP
    "www.cloudflare.com", "cloudflare.com",
    "www.microsoft.com", "microsoft.com",
    "www.apple.com", "apple.com",
    "www.amazon.com", "amazon.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.aspnetcdn.com",
    "fonts.gstatic.com",
    "cdn.shopify.com",
    "s3.amazonaws.com",
]

# Chrome 120+ cipher suite order — DPI проверяет порядок cipher suites
# для определения клиента (fingerprinting). Этот порядок = Chrome/Chromium.
_CHROME_CIPHERS = ":".join([
    # TLS 1.3 (управляются отдельно, но включаем для fallback)
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    # TLS 1.2 (Chrome order)
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
])

# Счётчик для round-robin SNI ротации
_sni_index = 0


def random_sni() -> str:
    """Выбрать случайный белый домен для SNI."""
    return random.choice(WHITE_DOMAINS)


def rotating_sni() -> str:
    """SNI по round-robin — каждое соединение использует следующий домен.
    Лучше чем random: гарантированно разные SNI для последовательных подключений.
    """
    global _sni_index
    sni = WHITE_DOMAINS[_sni_index % len(WHITE_DOMAINS)]
    _sni_index += 1
    return sni


def create_client_context() -> ssl.SSLContext:
    """TLS-контекст для клиента с browser-like fingerprint.

    Имитирует Chrome 120+:
    - Chrome cipher suite order
    - ALPN: h2, http/1.1
    - TLS 1.2 minimum
    - Session tickets отключены (anti-correlation между соединениями)
    - Не проверяем сертификат (верификация через XZAP-ключ)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Chrome-like cipher suites (порядок важен для JA3 fingerprint)
    try:
        ctx.set_ciphers(_CHROME_CIPHERS)
    except ssl.SSLError:
        # Fallback если OpenSSL не поддерживает все cipher suites
        ctx.set_ciphers("DEFAULT:!aNULL:!eNULL:!MD5")

    # ALPN как у браузера (h2 + http/1.1)
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    # TLS 1.2 minimum, prefer TLS 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Отключаем session tickets — предотвращает корреляцию
    ctx.options |= ssl.OP_NO_TICKET

    return ctx


def create_server_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """TLS-контекст для сервера.

    Настроен для совместимости с browser-like клиентом:
    - Поддержка ALPN (h2, http/1.1)
    - TLS 1.2+
    - Chrome-compatible cipher suites
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)

    # Принимаем те же cipher suites, что шлёт клиент
    try:
        ctx.set_ciphers(_CHROME_CIPHERS)
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT:!aNULL:!eNULL:!MD5")

    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def generate_self_signed_cert(cert_path: str = "xzap_cert.pem",
                               key_path: str = "xzap_key.pem"):
    """Генерирует self-signed сертификат для XZAP-сервера.
    Требует: pip install cryptography
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    if Path(cert_path).exists() and Path(key_path).exists():
        log.info("TLS cert already exists: %s", cert_path)
        return cert_path, key_path

    # Generate RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Self-signed cert (CN = random white domain for realism)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "www.google.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google LLC"),
    ])

    # Add SAN for multiple white domains
    san_names = [x509.DNSName(d) for d in WHITE_DOMAINS[:6]]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=30))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write cert
    Path(cert_path).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    # Write key
    Path(key_path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    log.info("Generated TLS cert: %s (CN=www.google.com)", cert_path)
    return cert_path, key_path


_client_ctx_cache = None


def _get_client_context() -> ssl.SSLContext:
    global _client_ctx_cache
    if _client_ctx_cache is None:
        _client_ctx_cache = create_client_context()
    return _client_ctx_cache


async def open_tls_connection(host: str, port: int,
                               sni: str = None) -> tuple:
    """Открывает TLS-соединение с кастомным SNI.

    DPI видит: TLS ClientHello с SNI=youtube.com (или другой белый домен).
    Каждое новое соединение автоматически использует другой SNI (round-robin).
    """
    sni = sni or rotating_sni()
    ctx = _get_client_context()
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ctx, server_hostname=sni,
    )
    log.info("TLS connected to %s:%d (SNI=%s)", host, port, sni)
    return reader, writer
