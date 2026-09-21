import asyncio
import contextlib
from contextlib import asynccontextmanager

import pytest_asyncio

from app.db.session import get_engine
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _es_lifecycle():
    await bootstrap_es()
    yield
    await get_es().close()
    await get_engine().dispose()


# --- WebSocket harnesses ------------------------------------------------
#
# Neither of these is a convenience. A progress handler's defining property
# is what it does when its CLIENT goes away, and a fake socket that only
# knows `accept` and `send_json` cannot express that at all -- which is why
# the leak these test for survived the original suite.


@asynccontextmanager
async def null_capture(interface: str, timeout_seconds: int, capture_container=None):
    """A capture that captures nothing and claims nothing.

    Stands in for `runs._capture` so a test never execs docker. Yields an
    object whose `outcome` stays None, which is what the orchestrator reads
    as "this run made no claim about network activity" -- distinct from
    having looked and failed, which is an `unknown` fact.

    Lives here rather than in `runs.py`: production no longer needs a second
    capture implementation, because `tcpdump.Capture` handles an unconfigured
    target itself. This is only the stub.
    """

    class _Inert:
        outcome = None

    yield _Inert()



class FakeWebSocket:
    """A WebSocket whose client half the test controls.

    Implements exactly what `stream_progress` uses of Starlette's `WebSocket`:
    `accept`, `receive`, `send_json`, `close`, and `headers`. `receive` blocks
    like a connected client that sends nothing, until `disconnect()` puts the
    `websocket.disconnect` message an ASGI server delivers when the browser
    goes away. A fake without `receive` cannot be disconnected, so a handler
    tested against one is never asked the only question that matters.

    `headers` carries the handshake, which is where the Clerk token arrives:
    a browser cannot set an Authorization header on a WebSocket, so the token
    is offered as a subprotocol (see `app.auth.websocket_token`). Empty by
    default, which is an unauthenticated client -- accepted while
    `CLERK_ISSUER` is unset and refused once it is set, exactly as a real one
    would be.
    """

    def __init__(self, headers: dict[str, str] | None = None) -> None:
        self.headers = headers or {}
        self.closed_with: int | None = None
        self.accepted = False
        self.sent: list[dict] = []
        self._incoming: asyncio.Queue = asyncio.Queue()

    async def accept(self, subprotocol: str | None = None) -> None:
        # `subprotocol` mirrors Starlette: the server must echo one of the
        # protocols the client offered, or the browser fails the handshake.
        self.accepted = True
        self.accepted_subprotocol = subprotocol

    async def close(self, code: int = 1000) -> None:
        self.closed_with = code

    async def receive(self) -> dict:
        return await self._incoming.get()

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)

    def disconnect(self, code: int = 1000) -> None:
        self._incoming.put_nowait({"type": "websocket.disconnect", "code": code})


class ASGIWebSocketSession:
    """One live WebSocket conversation with the app, driven message by message."""

    def __init__(
        self, task: "asyncio.Task", to_app: asyncio.Queue, from_app: asyncio.Queue
    ) -> None:
        self.task = task
        self.opening: dict = {}
        self._to_app = to_app
        self._from_app = from_app

    @property
    def accepted(self) -> bool:
        return self.opening.get("type") == "websocket.accept"

    async def receive(self, timeout: float = 5.0) -> dict:
        return await asyncio.wait_for(self._from_app.get(), timeout=timeout)

    def disconnect(self, code: int = 1000) -> None:
        self._to_app.put_nowait({"type": "websocket.disconnect", "code": code})


@asynccontextmanager
async def asgi_websocket(app, path: str, protocols: list[str] | None = None):
    """Open `path` on `app` over raw ASGI, and always end the handler after.

    Not `httpx.ASGITransport`, which speaks HTTP only, and deliberately not a
    bare `TestClient`: that opens a fresh anyio portal per request and poisons
    the cached aiohttp session for every later async test in this suite. This
    drives the real app object, so the route is matched and its path
    parameters are parsed and validated exactly as they are in production --
    which is the whole point when the thing under test is how a path
    parameter is typed.

    The `finally` disconnects and joins the handler however the body ended, so
    a failing assertion cannot leave a live handler -- and its subscriber --
    behind to corrupt the next test.
    """
    to_app: asyncio.Queue = asyncio.Queue()
    from_app: asyncio.Queue = asyncio.Queue()
    to_app.put_nowait({"type": "websocket.connect"})
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        # `protocols` is how a browser offers a Clerk token on a handshake --
        # it cannot set an Authorization header on a WebSocket. Both the raw
        # header and the parsed `subprotocols` key are set because Starlette
        # populates the latter from the former and `app.auth` reads the
        # former; a scope with only one of them is not a real handshake.
        "headers": (
            [(b"host", b"test")]
            + ([(b"sec-websocket-protocol", ", ".join(protocols).encode())] if protocols else [])
        ),
        "client": ("127.0.0.1", 51234),
        "server": ("test", 80),
        "subprotocols": list(protocols or []),
    }

    task = asyncio.create_task(app(scope, to_app.get, from_app.put))
    session = ASGIWebSocketSession(task, to_app, from_app)
    try:
        session.opening = await session.receive()
        yield session
    finally:
        session.disconnect()
        try:
            await asyncio.wait_for(task, timeout=5)
        except TimeoutError:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
