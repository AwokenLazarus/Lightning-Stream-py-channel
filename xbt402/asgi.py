"""Starlette ASGI app + middleware speaking x402 v2 `xbt-channel` headers."""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route


def _raw_path(scope) -> str:
    """The request target as sent (percent-escapes intact), like http.server's self.path: the payer's
    payload.auth and receipt digest cover these exact bytes, not Starlette's decoded path."""
    raw = scope.get("raw_path") or scope["path"].encode()
    q = scope.get("query_string") or b""
    return (raw + (b"?" + q if q else b"")).decode("latin-1")


class Xbt402Middleware:
    """ASGI middleware: every request goes through `provider.serve` (402 / open / close / pay)."""

    def __init__(self, app, provider):
        self.app, self.provider = app, provider

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        body = await request.body()
        path = _raw_path(request.scope)
        status, hdrs, out = self.provider.serve(
            request.method, path, {k: v for k, v in request.headers.items()},
            body, str(request.url),
        )
        await Response(out, status_code=status, headers=hdrs)(scope, receive, send)


def asgi_app(provider) -> Starlette:
    """Standalone Starlette app: one catch-all route into the provider."""

    async def catchall(request: Request):
        body = await request.body()
        path = _raw_path(request.scope)
        status, hdrs, out = provider.serve(
            request.method, path, {k: v for k, v in request.headers.items()},
            body, str(request.url),
        )
        return Response(out, status_code=status, headers=hdrs)

    return Starlette(routes=[
        Route("/", catchall, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
        Route("/{path:path}", catchall, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
    ])


def serve_asgi(provider, host: str, port: int):
    """Run uvicorn in the current thread (call from a daemon thread in demos)."""
    import uvicorn
    uvicorn.run(asgi_app(provider), host=host, port=port, log_level="error")
