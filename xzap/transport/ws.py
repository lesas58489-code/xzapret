"""
XZAP WebSocket Transport.

Обёртка поверх websockets: клиент и сервер.
Каждое WebSocket-сообщение = один фрагмент XZAP (bytes).

Преимущества WS-транспорта:
  - Выглядит как обычный HTTPS/WSS трафик (порт 443)
  - Проходит через большинство корпоративных прокси и CDN
  - Поддерживает multiplexing через один TCP-сокет
"""

import asyncio
import logging

log = logging.getLogger("xzap.transport.ws")

try:
    import websockets
    import websockets.server
    import websockets.client
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False


def _require_ws():
    if not _WS_AVAILABLE:
        raise ImportError(
            "websockets не установлен. Запустите: pip3 install websockets>=14.0"
        )


class WSConnection:
    """Одно WebSocket-соединение (клиентская сторона)."""

    def __init__(self, url: str):
        self.url = url
        self._ws = None

    async def connect(self):
        _require_ws()
        self._ws = await websockets.client.connect(
            self.url,
            max_size=2 ** 20,       # 1 МБ макс. сообщение
            ping_interval=20,
            ping_timeout=10,
        )
        log.debug("WS connected to %s", self.url)

    async def send(self, data: bytes):
        if self._ws is None:
            raise RuntimeError("Not connected")
        await self._ws.send(data)

    async def recv(self) -> bytes:
        if self._ws is None:
            raise RuntimeError("Not connected")
        msg = await self._ws.recv()
        return msg if isinstance(msg, bytes) else msg.encode()

    async def close(self):
        if self._ws:
            await self._ws.close()
            self._ws = None

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed


class WSMultiPathTransport:
    """Несколько параллельных WS-соединений (multi-SNI через WS)."""

    def __init__(self, urls: list[str]):
        self.paths = [WSConnection(url) for url in urls]

    async def connect_all(self):
        await asyncio.gather(*(p.connect() for p in self.paths))

    async def send_on_path(self, path_index: int, data: bytes):
        await self.paths[path_index % len(self.paths)].send(data)

    async def recv_from_path(self, path_index: int) -> bytes:
        return await self.paths[path_index % len(self.paths)].recv()

    async def close_all(self):
        await asyncio.gather(*(p.close() for p in self.paths))

    @property
    def num_paths(self) -> int:
        return len(self.paths)


class WSTransport:
    """Серверный WebSocket-транспорт."""

    def __init__(self, host: str = "0.0.0.0", port: int = 443,
                 path: str = "/xzap"):
        self.host = host
        self.port = port
        self.path = path
        self._server = None

    async def serve(self, handler):
        """
        Запустить WS-сервер. handler(ws_conn) вызывается на каждое соединение.
        ws_conn имеет методы send(bytes) и recv() -> bytes.
        """
        _require_ws()

        async def _ws_handler(websocket):
            peer = websocket.remote_address
            # Проверяем путь
            if hasattr(websocket, 'path') and websocket.path != self.path:
                log.warning("Wrong path %s from %s", websocket.path, peer)
                await websocket.close(1008, "Wrong path")
                return
            log.info("WS connection from %s", peer)
            conn = _WSServerConn(websocket)
            try:
                await handler(conn)
            except Exception as e:
                log.debug("WS handler error from %s: %s", peer, e)

        self._server = await websockets.server.serve(
            _ws_handler,
            self.host,
            self.port,
            max_size=2 ** 20,
            ping_interval=20,
        )
        log.info("WS server on %s:%d%s", self.host, self.port, self.path)

    async def serve_forever(self):
        if self._server:
            await self._server.wait_closed()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class _WSServerConn:
    """Обёртка над серверным WebSocket для совместимости с TCP-интерфейсом."""

    def __init__(self, ws):
        self._ws = ws

    async def send(self, data: bytes):
        await self._ws.send(data)

    async def recv(self) -> bytes:
        msg = await self._ws.recv()
        return msg if isinstance(msg, bytes) else msg.encode()

    async def close(self):
        await self._ws.close()


def build_ws_urls(server_host: str, server_port: int,
                  snis: list[str], path: str = "/xzap",
                  tls: bool = True) -> list[str]:
    """Сформировать WS URL для каждого SNI-пути."""
    scheme = "wss" if tls else "ws"
    return [
        f"{scheme}://{server_host}:{server_port}{path}?sni={sni}"
        for sni in snis
    ]
