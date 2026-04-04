"""
Integration tests: client ↔ server через localhost.

Тестирует полный цикл:
  encrypt → fragment → send → receive → reassemble → decrypt
"""

import asyncio
import os
import pytest
from xzap.crypto import XZAPCrypto, XZAPKeyExchange, ALGO_AES_GCM, ALGO_CHACHA20
from xzap.message import XZAPMessage
from xzap.fragmentation import Fragmenter, FragmentBuffer, Fragment
from xzap.obfuscation import Obfuscator
from xzap.transport.tcp import XZAPConnection, XZAPListener
from xzap.routing import XZAPRouter
from xzap.socks5 import SOCKS5Proxy


# ──────────────────────────────────────────────
# Helper: простой echo-сервер на TCP
# ──────────────────────────────────────────────

async def _start_echo_server(host="127.0.0.1", port=0):
    """TCP echo server: читает length-prefixed сообщения, шлёт обратно."""
    async def handler(reader, writer):
        try:
            while True:
                hdr = await reader.readexactly(2)
                length = int.from_bytes(hdr, "big")
                data = await reader.readexactly(length)
                writer.write(len(data).to_bytes(2, "big") + data)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, host, port)
    addr = server.sockets[0].getsockname()
    return server, addr[0], addr[1]


async def _start_raw_echo_server(host="127.0.0.1", port=0):
    """Raw TCP echo: читает данные, шлёт обратно."""
    async def handler(reader, writer):
        try:
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handler, host, port)
    addr = server.sockets[0].getsockname()
    return server, addr[0], addr[1]


# ──────────────────────────────────────────────
# Test 1: TCP transport — send/recv через localhost
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tcp_transport_roundtrip():
    server, host, port = await _start_echo_server()
    try:
        conn = XZAPConnection(host, port)
        await conn.connect()
        assert conn.connected

        msg = b"Hello XZAP transport!"
        await conn.send(msg)
        response = await conn.recv()
        assert response == msg

        await conn.close()
        assert not conn.connected
    finally:
        server.close()
        await server.wait_closed()


# ──────────────────────────────────────────────
# Test 2: Crypto roundtrip через «сеть»
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crypto_over_tcp():
    """Encrypt на клиенте, передать по TCP, decrypt на сервере."""
    key = os.urandom(32)
    client_crypto = XZAPCrypto(key=key, algo=ALGO_AES_GCM)
    server_crypto = XZAPCrypto(key=key, algo=ALGO_AES_GCM)

    server, host, port = await _start_echo_server()
    try:
        conn = XZAPConnection(host, port)
        await conn.connect()

        plaintext = b"Secret XZAP message with crypto!"
        ciphertext = client_crypto.encrypt(plaintext)
        await conn.send(ciphertext)

        echoed = await conn.recv()
        decrypted = server_crypto.decrypt(echoed)
        assert decrypted == plaintext

        await conn.close()
    finally:
        server.close()
        await server.wait_closed()


# ──────────────────────────────────────────────
# Test 3: Key exchange → shared key → encrypt/decrypt
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_key_exchange_and_encrypt():
    """X25519 key exchange, derive shared auth_key, encrypt/decrypt."""
    client_kx = XZAPKeyExchange()
    server_kx = XZAPKeyExchange()
    uuid = os.urandom(16)

    client_auth = client_kx.derive_auth_key(server_kx.public_bytes(), uuid)
    server_auth = server_kx.derive_auth_key(client_kx.public_bytes(), uuid)
    assert client_auth == server_auth

    # Use first 32 bytes of auth_key as encryption key
    enc_key = client_auth[:32]
    client_crypto = XZAPCrypto(key=enc_key, algo=ALGO_CHACHA20)
    server_crypto = XZAPCrypto(key=enc_key, algo=ALGO_CHACHA20)

    plaintext = b"Authenticated and encrypted XZAP message!"
    ct = client_crypto.encrypt(plaintext)
    assert server_crypto.decrypt(ct) == plaintext


# ──────────────────────────────────────────────
# Test 4: Full pipeline — encrypt → fragment → send → reassemble → decrypt
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_pipeline():
    """Полный цикл: message → encrypt → fragment → TCP → reassemble → decrypt."""
    key = os.urandom(32)
    crypto = XZAPCrypto(key=key)
    fragmenter = Fragmenter(min_size=24, max_size=48, chaff_chance=0,
                            overlap=0, padding_chance=0)
    obfuscator = Obfuscator(num_paths=1)
    recv_buf = FragmentBuffer()

    server, host, port = await _start_echo_server()
    try:
        conn = XZAPConnection(host, port)
        await conn.connect()

        # Клиентская сторона: формируем и отправляем
        plaintext = b"Full pipeline test with fragmentation and crypto!"
        msg = XZAPMessage(plaintext, seqno=0)
        encrypted = crypto.encrypt(msg.payload, aad=msg.aad())
        msg.payload = encrypted
        packed = obfuscator.add_prefix(msg.pack())

        fragments = fragmenter.fragment(msg.msg_id, packed, num_paths=1)
        real_frags = [f for f in fragments if not f.is_chaff]

        for frag in real_frags:
            await conn.send(frag.pack())

        # Серверная сторона: получаем и собираем
        for _ in range(len(real_frags)):
            raw = await conn.recv()
            frag = Fragment.unpack(raw)
            assembled = recv_buf.add(frag)
            if assembled is not None:
                assembled = obfuscator.strip_prefix(assembled)
                recv_msg = XZAPMessage.unpack(assembled)
                decrypted = crypto.decrypt(recv_msg.payload, aad=recv_msg.aad())
                assert decrypted == plaintext
                break
        else:
            pytest.fail("Message not fully reassembled")

        await conn.close()
    finally:
        server.close()
        await server.wait_closed()


# ──────────────────────────────────────────────
# Test 5: Chaff фрагменты отбрасываются при сборке
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chaff_filtered_in_pipeline():
    """Chaff fragments should be silently dropped by FragmentBuffer."""
    key = os.urandom(32)
    crypto = XZAPCrypto(key=key)
    fragmenter = Fragmenter(min_size=24, max_size=48, chaff_chance=1.0,
                            chaff_per_message=3, overlap=0, padding_chance=0)
    obfuscator = Obfuscator(num_paths=1)
    recv_buf = FragmentBuffer()

    plaintext = b"Message with chaff!"
    msg = XZAPMessage(plaintext, seqno=0)
    encrypted = crypto.encrypt(msg.payload, aad=msg.aad())
    msg.payload = encrypted
    packed = obfuscator.add_prefix(msg.pack())

    fragments = fragmenter.fragment(msg.msg_id, packed, num_paths=1)
    chaff_count = sum(1 for f in fragments if f.is_chaff)
    assert chaff_count >= 1, "Expected at least 1 chaff fragment"

    # Simulate receiving all fragments (including chaff)
    assembled = None
    for frag in fragments:
        raw = frag.pack()
        unpacked = Fragment.unpack(raw)
        result = recv_buf.add(unpacked)
        if result is not None:
            assembled = result

    assert assembled is not None, "Message should be assembled despite chaff"
    assembled = obfuscator.strip_prefix(assembled)
    recv_msg = XZAPMessage.unpack(assembled)
    decrypted = crypto.decrypt(recv_msg.payload, aad=recv_msg.aad())
    assert decrypted == plaintext


# ──────────────────────────────────────────────
# Test 6: Routing — bypass vs xzap
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_routing_logic():
    router = XZAPRouter()
    router.bypass_domains = {"vk.com", "yandex.ru", "gosuslugi.ru"}
    router.xzap_domains = {"youtube.com", "discord.com", "instagram.com"}

    assert not router.should_use_xzap("vk.com")
    assert not router.should_use_xzap("www.vk.com")
    assert not router.should_use_xzap("api.yandex.ru")
    assert router.should_use_xzap("youtube.com")
    assert router.should_use_xzap("www.youtube.com")
    assert router.should_use_xzap("discord.com")
    # Unknown domain → XZAP (default safe)
    assert router.should_use_xzap("unknown-site.org")


# ──────────────────────────────────────────────
# Test 7: SOCKS5 proxy handshake + CONNECT через localhost
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_socks5_proxy_direct():
    """SOCKS5 proxy → прямое подключение к echo-серверу."""
    # Запускаем raw echo-сервер
    echo_srv, echo_host, echo_port = await _start_raw_echo_server()

    # Запускаем SOCKS5 proxy (все домены — direct)
    router = XZAPRouter()
    router.bypass_domains = {"127.0.0.1"}
    proxy = SOCKS5Proxy(host="127.0.0.1", port=0, router=router)
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]

    try:
        # Подключаемся к SOCKS5
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

        # Handshake
        writer.write(bytes([0x05, 0x01, 0x00]))  # VER=5, 1 method, no auth
        await writer.drain()
        resp = await reader.readexactly(2)
        assert resp == bytes([0x05, 0x00])  # VER=5, no auth

        # CONNECT to echo server (ATYP=IPv4)
        ip_parts = [int(x) for x in echo_host.split(".")]
        connect_req = bytes([
            0x05, 0x01, 0x00, 0x01,  # VER, CMD=CONNECT, RSV, ATYP=IPv4
            *ip_parts,
            (echo_port >> 8) & 0xFF, echo_port & 0xFF,
        ])
        writer.write(connect_req)
        await writer.drain()

        # Read CONNECT response
        resp = await reader.read(256)
        assert resp[0] == 0x05  # VER
        assert resp[1] == 0x00  # REP=success

        # Now data flows through to echo server
        test_data = b"Hello through SOCKS5 proxy!"
        writer.write(test_data)
        await writer.drain()

        echoed = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        assert echoed == test_data

        writer.close()
    finally:
        await proxy.stop()
        echo_srv.close()
        await echo_srv.wait_closed()


# ──────────────────────────────────────────────
# Test 8: Множественные сообщения подряд
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_multiple_messages_pipeline():
    """Send 10 messages, each encrypted+fragmented, reassemble all."""
    key = os.urandom(32)
    crypto = XZAPCrypto(key=key)
    fragmenter = Fragmenter(min_size=16, max_size=32, chaff_chance=0,
                            overlap=0, padding_chance=0)
    obfuscator = Obfuscator(num_paths=1)
    recv_buf = FragmentBuffer()

    server, host, port = await _start_echo_server()
    try:
        conn = XZAPConnection(host, port)
        await conn.connect()

        received = []
        for i in range(10):
            plaintext = f"Message #{i}: {os.urandom(8).hex()}".encode()

            msg = XZAPMessage(plaintext, seqno=i)
            encrypted = crypto.encrypt(msg.payload, aad=msg.aad())
            msg.payload = encrypted
            packed = obfuscator.add_prefix(msg.pack())
            fragments = fragmenter.fragment(msg.msg_id, packed, num_paths=1)

            # Send all fragments
            for frag in fragments:
                await conn.send(frag.pack())

            # Receive and reassemble
            assembled = None
            for _ in range(len(fragments)):
                raw = await conn.recv()
                frag = Fragment.unpack(raw)
                result = recv_buf.add(frag)
                if result is not None:
                    assembled = result
                    break

            assert assembled is not None
            assembled = obfuscator.strip_prefix(assembled)
            recv_msg = XZAPMessage.unpack(assembled)
            decrypted = crypto.decrypt(recv_msg.payload, aad=recv_msg.aad())
            assert decrypted == plaintext
            received.append(decrypted)

        assert len(received) == 10

        await conn.close()
    finally:
        server.close()
        await server.wait_closed()
