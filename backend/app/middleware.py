"""Refuse NUL bytes in a request's path or query, for every route at once.

Postgres cannot store a NUL character in text, so a `%00` that reached any query
carrying a caller-supplied string failed inside asyncpg and surfaced as a 500 --
found by stress-testing three routes (annotations by session id, the Threat
Intelligence search, and an annotation's body). A NUL is never a legitimate
character in a session id, a search term or an IP, so it is refused here, once,
with a 400 that says why, instead of being guarded route by route.

Request BODIES are not inspected here; a JSON body is validated by the route that
reads it (see `annotations.normalise`).
"""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketClose


class RejectNulBytes:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and (
            "\x00" in scope.get("path", "") or b"%00" in scope.get("query_string", b"")
        ):
            if scope["type"] == "http":
                response = JSONResponse(
                    {"detail": "NUL bytes are not accepted in a path or query."},
                    status_code=400,
                )
                await response(scope, receive, send)
            else:
                await WebSocketClose(code=1008)(scope, receive, send)
            return
        await self.app(scope, receive, send)
