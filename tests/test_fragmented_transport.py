"""Tests for FragmentedTransport — micro-fragmentation over TCP."""

import asyncio
import os
import pytest
from xzap.transport.fragmented import (
    FragmentedReader, FragmentedWriter, wrap_connection,
    FLAG_REAL, FLAG_CHAFF,
)


@pytest.mark.asyncio
async def test_basic_roundtrip():
    """Send data through fragmented transport, receive intact."""
    results = []

    async def server(reader, writer):
        fr, fw = wrap_connection(reader, writer, chaff_chance=0)
        data = await fr.readexactly(100)
        results.append(data)
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    r, w = await asyncio.open_connection("127.0.0.1", port)
    fr, fw = wrap_connection(r, w, chaff_chance=0)

    test_data = os.urandom(100)
    await fw.write(test_data)

    await asyncio.sleep(0.3)
    assert results[0] == test_data

    w.close()
    srv.close()
    await srv.wait_closed()


@pytest.mark.asyncio
async def test_large_data():
    """Send 10KB through fragmented transport."""
    results = []

    async def server(reader, writer):
        fr, fw = wrap_connection(reader, writer, chaff_chance=0)
        data = await fr.readexactly(10000)
        results.append(data)
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    r, w = await asyncio.open_connection("127.0.0.1", port)
    fr, fw = wrap_connection(r, w, chaff_chance=0, delay_ms=(0, 0))

    test_data = os.urandom(10000)
    await fw.write(test_data)

    await asyncio.sleep(0.5)
    assert results[0] == test_data

    w.close()
    srv.close()
    await srv.wait_closed()


@pytest.mark.asyncio
async def test_with_chaff():
    """Chaff fragments should be silently dropped by receiver."""
    results = []

    async def server(reader, writer):
        fr, fw = wrap_connection(reader, writer, chaff_chance=0)
        data = await fr.readexactly(50)
        results.append(data)
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    r, w = await asyncio.open_connection("127.0.0.1", port)
    # High chaff chance
    fr, fw = wrap_connection(r, w, chaff_chance=0.8, delay_ms=(0, 0))

    test_data = os.urandom(50)
    await fw.write(test_data)

    await asyncio.sleep(0.5)
    assert results[0] == test_data

    w.close()
    srv.close()
    await srv.wait_closed()


@pytest.mark.asyncio
async def test_bidirectional():
    """Send data in both directions simultaneously."""
    server_received = []
    client_received = []

    async def server(reader, writer):
        fr, fw = wrap_connection(reader, writer, chaff_chance=0.2, delay_ms=(0, 0))
        # Read from client
        data = await fr.readexactly(200)
        server_received.append(data)
        # Send to client
        await fw.write(os.urandom(300))
        await asyncio.sleep(0.2)
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    r, w = await asyncio.open_connection("127.0.0.1", port)
    fr, fw = wrap_connection(r, w, chaff_chance=0.2, delay_ms=(0, 0))

    test_data = os.urandom(200)
    await fw.write(test_data)

    response = await fr.readexactly(300)
    client_received.append(response)

    await asyncio.sleep(0.3)
    assert server_received[0] == test_data
    assert len(client_received[0]) == 300

    w.close()
    srv.close()
    await srv.wait_closed()
