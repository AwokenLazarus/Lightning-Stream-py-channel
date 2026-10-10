"""Starlette ASGI app + middleware speaking x402 v2 `xbt-channel` headers.

Limits (AGP-081, review T1). The app bounds what an ASGI app can see: the request body, duplicate
payment headers, a `#` in the target. It cannot bound connections. `XbtChannelProvider.http_server`
caps them (64 in all, 48 per address) and cuts off a header or a body that does not finish (10 s,
30 s); an ASGI server owns its sockets, and uvicorn has no such deadline and no such cap: a
connection that sends nothing, or half a header, stays open (300 idle sockets were still open after
40 s). So this path needs those limits in front of it: a reverse proxy with header and body timeouts
and per-client connection limits, or an ASGI server configured with them. `serve_asgi` therefore
listens on loopback only; an embedder that runs `asgi_app` or `Xbt402Middleware` under its own server
takes on the same duty.
"""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from .x402_channel import FRAGMENT_REFUSED, MAX_BODY, unsafe_headers

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _raw_path(scope) -> str:
    """The request target as sent (percent-escapes intact), like http.server's self.path: the payer's
    payload.auth and receipt digest cover these exact bytes, not Starlette's decoded path."""
    raw = scope.get("raw_path") or scope["path"].encode()
    q = scope.get("query_string") or b""
    return (raw + (b"?" + q if q else b"")).decode("latin-1")


async def _bounded_body(request: Request, limit: int = MAX_BODY):
    """The body, or None if it is over `limit` (provider/route max_body, default MAX_BODY)
    or its framing is ambiguous (duplicate PAYMENT-SIGNATURE headers: which one would the
    provider read?)."""
    if len(request.headers.getlist("payment-signature")) > 1:
        return None
    cl = request.headers.get("content-length")
    if cl is not None and (not cl.isdigit() or int(cl) > limit):
        return None
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return body


async def _serve(provider, request: Request) -> Response:
    path = _raw_path(request.scope)
    if "#" in path:                         # as provider.serve does, before the body is read
        return Response(FRAGMENT_REFUSED, status_code=400)
    limit = provider.body_limit(path) if hasattr(provider, "body_limit") else MAX_BODY
    body = await _bounded_body(request, limit)
    if body is None:
        return Response(b"bad request framing or body over MAX_BODY", status_code=400)
    status, hdrs, out = provider.serve(request.method, path,
                                       {k: v for k, v in request.headers.items()}, body, str(request.url))
    if unsafe_headers(hdrs):
        return Response(b"handler returned a header with CR/LF", status_code=500)
    return Response(out, status_code=status, headers=hdrs)


class Xbt402Middleware:
    """ASGI middleware: every request goes through `provider.serve` (402 / open / close / pay)."""

    def __init__(self, app, provider):
        self.app, self.provider = app, provider

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        await (await _serve(self.provider, Request(scope, receive)))(scope, receive, send)


def asgi_app(provider) -> Starlette:
    """Standalone Starlette app: one catch-all route into the provider."""

    async def catchall(request: Request):
        return await _serve(provider, request)

    return Starlette(routes=[
        Route("/", catchall, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
        Route("/{path:path}", catchall, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
    ])


def serve_asgi(provider, host: str, port: int):
    """Run uvicorn in the current thread (call from a daemon thread in demos). `host` is a loopback
    address (ValueError otherwise): this server has no deadlines and no connection cap (the module
    docstring), so whatever is public is the proxy in front of it."""
    if host not in LOOPBACK:
        raise ValueError(f"serve_asgi listens on loopback only, not {host!r}: put a reverse proxy in front")
    import uvicorn
    uvicorn.run(asgi_app(provider), host=host, port=port, log_level="error")
