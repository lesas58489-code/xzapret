"""
XZAP Mux — multiplexing multiple logical streams over one XZAP tunnel.

Problem: browser page load opens 30+ parallel HTTPS connections.
Old model (one SOCKS = one TLS tunnel) = 30 TLS handshakes to server,
30 separate TCP connections, operator sees burst, slow first-byte.

Mux model: one persistent TLS tunnel carries N logical streams.
New HTTPS connection = new stream_id in existing tunnel → 0ms latency,
0 new TLS handshakes.

Wire format (one mux frame = payload of one XZAP encrypted frame):
  [4B stream_id][1B cmd][4B payload_len][payload]

Commands:
  0x01 SYN      — open stream; payload = JSON {"host":"...","port":N}
  0x02 SYN_ACK  — stream accepted (payload empty) or rejected (payload = error)
  0x03 DATA     — stream data
  0x04 FIN      — graceful close (no more data from sender)
  0x05 RST      — abort with error

Version handshake:
  First frame from client has stream_id=0, cmd=SYN, payload={"v":"mux1"}.
  Server replies stream_id=0, cmd=SYN_ACK, payload={"v":"mux1"}.
  Legacy clients send {"cmd":"connect",...} — server autodetects and
  falls back to XZAPTunnelServer.handle_legacy path.
"""

import asyncio
import json
import struct
import logging

log = logging.getLogger("xzap.mux")

CMD_SYN = 0x01
CMD_SYN_ACK = 0x02
CMD_DATA = 0x03
CMD_FIN = 0x04
CMD_RST = 0x05
CMD_PING = 0x06
CMD_PONG = 0x07
CMD_WINDOW = 0x08

MUX_HDR_SIZE = 9  # 4 + 1 + 4
MAX_PAYLOAD = 256 * 1024
MUX_VERSION = "mux1"
CONTROL_STREAM_ID = 0
INITIAL_WINDOW = 256 * 1024  # per-stream send window


def pack_frame(stream_id: int, cmd: int, payload: bytes = b"") -> bytes:
    return struct.pack(">IBI", stream_id, cmd, len(payload)) + payload


def unpack_header(hdr: bytes) -> tuple[int, int, int]:
    return struct.unpack(">IBI", hdr)


class MuxStream:
    """One logical stream inside a mux tunnel. Relays between XZAP side
    and a real TCP target connection."""

    def __init__(self, stream_id: int, mux: "MuxServerSession"):
        self.id = stream_id
        self.mux = mux
        self.target_reader: asyncio.StreamReader | None = None
        self.target_writer: asyncio.StreamWriter | None = None
        self.closed = False
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._target_task: asyncio.Task | None = None
        # Flow control is opt-in: disabled until we see the client send its first
        # WINDOW frame. Old clients (no FC support) never send one → we never block.
        # New clients send their first WINDOW frame after consuming 64KB → FC engages.
        self._fc_enabled = False
        self._send_window = INITIAL_WINDOW
        self._window_event = asyncio.Event()
        self._window_event.set()
        self._consumed = 0  # bytes consumed from client → credit back periodically

    async def connect_target(self, host: str, port: int) -> bool:
        try:
            self.target_reader, self.target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10,
            )
            return True
        except Exception as e:
            log.debug("stream %d target connect failed %s:%d: %s", self.id, host, port, e)
            return False

    async def run(self):
        """Pump: read from target → send DATA frames; consume incoming → write to target."""
        async def target_to_mux():
            try:
                while not self.closed:
                    chunk = await self.target_reader.read(32 * 1024)
                    if not chunk:
                        break
                    # Respect client's send window only when FC is engaged
                    if not self._fc_enabled:
                        await self.mux.send_frame(self.id, CMD_DATA, chunk)
                        continue
                    pos = 0
                    while pos < len(chunk):
                        if self._send_window <= 0:
                            self._window_event.clear()
                            try:
                                await asyncio.wait_for(self._window_event.wait(), timeout=30)
                            except asyncio.TimeoutError:
                                return
                        take = min(len(chunk) - pos, self._send_window, 32 * 1024)
                        await self.mux.send_frame(self.id, CMD_DATA, chunk[pos:pos+take])
                        self._send_window -= take
                        pos += take
            except Exception:
                pass
            finally:
                try:
                    await self.mux.send_frame(self.id, CMD_FIN)
                except Exception:
                    pass
                await self.close(notify=False)

        async def mux_to_target():
            try:
                while True:
                    chunk = await self._incoming.get()
                    if chunk is None:
                        break
                    self.target_writer.write(chunk)
                    await self.target_writer.drain()
                    # Credit client only if they asked for FC (engaged).
                    if self._fc_enabled:
                        self._consumed += len(chunk)
                        if self._consumed >= 64 * 1024:
                            credit = self._consumed
                            self._consumed = 0
                            try:
                                await self.mux.send_frame(self.id, CMD_WINDOW,
                                                           credit.to_bytes(4, "big"))
                            except Exception:
                                pass
            except Exception:
                pass
            finally:
                try:
                    if self.target_writer:
                        self.target_writer.close()
                except Exception:
                    pass

        await asyncio.gather(target_to_mux(), mux_to_target(), return_exceptions=True)

    def on_window_update(self, delta: int):
        # First WINDOW frame = FC opt-in. Keep the INITIAL_WINDOW and just
        # *add* delta. Client sends bootstrap WINDOW(0) right after SYN_ACK
        # to opt-in without changing the initial window.
        if not self._fc_enabled:
            self._fc_enabled = True
        if delta > 0:
            self._send_window += delta
        self._window_event.set()

    async def feed(self, data: bytes):
        """Called by mux dispatcher when DATA frame arrives for this stream."""
        if not self.closed:
            await self._incoming.put(data)

    async def close(self, notify: bool = True):
        if self.closed:
            return
        self.closed = True
        await self._incoming.put(None)
        if self.target_writer:
            try:
                self.target_writer.close()
            except Exception:
                pass
        self.mux.streams.pop(self.id, None)
        if notify:
            await self.mux.send_frame(self.id, CMD_FIN)


class MuxServerSession:
    """One mux session = one XZAP tunnel carrying N streams.
    Wraps a FragmentedReader/Writer pair with a crypto layer.
    The tunnel.py handler calls into us after handshake."""

    def __init__(self, reader, writer, crypto, send_frame_coro, username=None):
        """
        reader, writer: FragmentedReader/Writer from tunnel.py
        crypto: XZAPCrypto instance
        send_frame_coro: coroutine fn that sends one (encrypted + framed) payload
                         over the XZAP tunnel. tunnel.py's _send_frame.
        """
        self._reader = reader
        self._writer = writer
        self._crypto = crypto
        self._send_xzap_frame = send_frame_coro
        self.username = username
        self.streams: dict[int, MuxStream] = {}
        self._write_lock = asyncio.Lock()

    async def send_frame(self, stream_id: int, cmd: int, payload: bytes = b""):
        frame = pack_frame(stream_id, cmd, payload)
        async with self._write_lock:
            await self._send_xzap_frame(self._writer, self._crypto, frame)

    async def run(self, first_decrypted_frame: bytes):
        """Entered after version handshake is confirmed.
        first_decrypted_frame is the already-decrypted bytes of the client's
        first mux frame (the version SYN). We process it, reply SYN_ACK, and
        then loop."""
        # Ack the version
        await self.send_frame(CONTROL_STREAM_ID, CMD_SYN_ACK,
                              json.dumps({"v": MUX_VERSION}).encode())
        log.info("Mux session established user=%s", self.username)

        try:
            while True:
                # Read one more XZAP frame, decode as mux frame
                try:
                    frame_bytes = await _recv_xzap_frame(self._reader, self._crypto)
                except Exception:
                    break
                await self._process_mux_frame(frame_bytes)
        finally:
            # Tear down all streams
            for s in list(self.streams.values()):
                await s.close(notify=False)

    async def _process_mux_frame(self, data: bytes):
        if len(data) < MUX_HDR_SIZE:
            log.warning("mux: frame too small (%d bytes) head=%s", len(data), data[:16].hex())
            return
        stream_id, cmd, plen = unpack_header(data[:MUX_HDR_SIZE])
        if plen > MAX_PAYLOAD:
            log.warning("mux: payload too large (%d bytes)", plen)
            return
        payload = data[MUX_HDR_SIZE:MUX_HDR_SIZE + plen]
        # DIAG: log every non-control-ping frame to trace why stream opens fail
        if not (stream_id == CONTROL_STREAM_ID and cmd in (CMD_PING, CMD_PONG)):
            log.info("mux RX sid=%d cmd=0x%02x plen=%d", stream_id, cmd, plen)

        # Control stream (id=0): ping/pong — keepalive heartbeat
        if stream_id == CONTROL_STREAM_ID:
            if cmd == CMD_PING:
                try:
                    await self.send_frame(CONTROL_STREAM_ID, CMD_PONG, b"")
                    log.debug("mux tx: PONG sent")
                except Exception as e:
                    log.warning("mux: PONG send failed: %s", e)
            return

        if cmd == CMD_SYN:
            await self._handle_syn(stream_id, payload)
        elif cmd == CMD_DATA:
            s = self.streams.get(stream_id)
            if s:
                await s.feed(payload)
        elif cmd == CMD_WINDOW:
            s = self.streams.get(stream_id)
            if s and len(payload) >= 4:
                delta = int.from_bytes(payload[:4], "big")
                s.on_window_update(delta)
        elif cmd in (CMD_FIN, CMD_RST):
            s = self.streams.get(stream_id)
            if s:
                await s.close(notify=False)

    async def _handle_syn(self, stream_id: int, payload: bytes):
        try:
            req = json.loads(payload)
            host = req["host"]; port = int(req["port"])
        except Exception as e:
            log.warning("mux SYN sid=%d BAD-JSON err=%s payload=%r", stream_id, e, payload[:80])
            await self.send_frame(stream_id, CMD_RST, b"bad syn")
            return

        log.info("mux SYN sid=%d → %s:%d", stream_id, host, port)
        # Run connect_target as a background task so the mux frame reader loop
        # is not blocked on slow/hung target connects. Other streams' SYN, DATA,
        # PING all keep flowing while this one waits for its upstream.
        asyncio.create_task(self._open_stream_async(stream_id, host, port))

    async def _open_stream_async(self, stream_id: int, host: str, port: int):
        stream = MuxStream(stream_id, self)
        if not await stream.connect_target(host, port):
            log.info("mux SYN sid=%d %s:%d CONNECT_FAILED → RST", stream_id, host, port)
            await self.send_frame(stream_id, CMD_RST, b"connect failed")
            return
        self.streams[stream_id] = stream
        log.info("mux SYN sid=%d %s:%d OK → SYN_ACK", stream_id, host, port)
        await self.send_frame(stream_id, CMD_SYN_ACK)
        await stream.run()


# These need to match tunnel.py's _send_frame/_recv_frame. We import them
# at use-site to avoid circular deps.
async def _recv_xzap_frame(reader, crypto):
    from .tunnel import _recv_frame
    return await _recv_frame(reader, crypto)
