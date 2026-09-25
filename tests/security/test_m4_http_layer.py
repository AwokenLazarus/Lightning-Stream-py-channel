"""M4 (Medium) header injection and request smuggling in the reference HTTP layer.

The xbt402 headers themselves are safe (PAYMENT-* values are base64). But v1's http_server:
- passes the wrapped handler's headers straight to BaseHTTPRequestHandler.send_header, which does
  not check for CR/LF, so a handler that reflects request data (here: the decoded path) injects
  response headers;
- ignores Transfer-Encoding and trusts Content-Length, so behind a proxy that honors chunked
  framing one request smuggles another (CL.TE desync), which then runs on another user's connection;
- reads `Content-Length: -1` as "read to EOF", pinning a server thread per connection.
Wave 2 adds an ASGI transport (Starlette): it reads the whole body with no bound, and whether a
CR/LF header is refused depends on which ASGI server runs it. Fixed in serve() itself (an unbilled
500 for a CR/LF/NUL header, whatever the transport) and in both transports' framing.
Servers bind 127.0.0.1 on ports XBT402_TEST_PORT_BASE + 20..23 (see sechelp.PORT_OFFSETS).
"""
import asyncio
import socket
import threading
import time
import unittest
import urllib.parse

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, port_for
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests

INNER = b"GET /v1/smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
SIZE = f"{len(INNER):x}\r\n".encode()
SMUGGLE = (b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(SIZE)).encode()
           + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + SIZE + INNER + b"\r\n0\r\n\r\n")
P0, P1, P2, P3 = (port_for("m4", i) for i in range(4))
EVIL_PATH = "/v1/x%0d%0aSet-Cookie:%20pwn=1"


def echo(method, path, body):
    return 200, {"X-Echo": urllib.parse.unquote(path)}, b"ok"


def start(prov, port):
    httpd = prov.http_server(port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def exchange(port, raw, wait=1.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.sendall(raw)
    data, end = b"", time.time() + wait
    try:
        while time.time() < end:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data


def paid_get(mod, cm, prov, node, path, auth):
    p, payer = make_channel(cm, prov, node)
    pl = {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()}
    if auth:
        pl = authed(mod, cm, payer, p.payee_pub, pl, path=path)
    hdr = mod.b64json({"x402Version": 2, "accepted": prov.requirements(150), "payload": pl})
    return f"GET {path} HTTP/1.1\r\nHost: x\r\nPAYMENT-SIGNATURE: {hdr}\r\nConnection: close\r\n\r\n".encode()


class HttpLayer(Repro, unittest.TestCase):
    def serve(self, mod, port, handler=None):
        node = FakeNode()
        prov = make_provider(mod, node)
        if handler:
            prov.handler = handler
        httpd = start(prov, port)
        httpd.handle_error = lambda *a: None            # the tests hang up early on purpose
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return prov, node

    def test_repro_crlf_header_injection(self):
        prov, node = self.serve(xc, P0, echo)
        data = exchange(P0, paid_get(xc, ch, prov, node, EVIL_PATH, auth=False))
        self.reproduces(b"\r\nSet-Cookie: pwn=1\r\n" in data.split(b"\r\n\r\n")[0] + b"\r\n",
                        "handler-reflected CR/LF became a Set-Cookie response header")

    def test_repro_cl_te_smuggling(self):
        self.serve(xc, P1)
        data = exchange(P1, SMUGGLE)
        self.reproduces(data.count(b"HTTP/1.1 402") >= 2 and b"smuggled" in data,
                        "one chunked POST (to a TE-honoring proxy) was served as two requests")

    def test_repro_negative_content_length_pins_thread(self):
        self.serve(xc, P2)
        data = exchange(P2, b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", wait=1.0)
        self.reproduces(data == b"", "Content-Length: -1 got no answer: the thread reads until the client hangs up")

    def test_fixed(self):
        xp, cp = load("x402_channel"), load("channel")
        prov, node = self.serve(xp, P3, echo)
        data = exchange(P3, paid_get(xp, cp, prov, node, EVIL_PATH, auth=True))
        self.assertTrue(data.startswith(b"HTTP/1.0 500") or data.startswith(b"HTTP/1.1 500"), data[:60])
        self.assertNotIn(b"Set-Cookie", data)
        data = exchange(P3, SMUGGLE)
        self.assertIn(b" 501 ", data.split(b"\r\n")[0])
        self.assertNotIn(b"smuggled", data)
        data = exchange(P3, b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n")
        self.assertIn(b" 400 ", data.split(b"\r\n")[0])
        data = exchange(P3, b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n")
        self.assertIn(b" 413 ", data.split(b"\r\n")[0])
        data = exchange(P3, b"GET /v1/x HTTP/1.1\r\nHost: x\r\nPAYMENT-SIGNATURE: a\r\nPAYMENT-SIGNATURE: b\r\n\r\n")
        self.assertIn(b" 400 ", data.split(b"\r\n")[0])


    def test_repro_serve_passes_crlf_headers_to_any_transport(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        prov.handler = echo
        p, payer = make_channel(ch, prov, node)
        pl = {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()}
        hdr = xc.b64json({"x402Version": 2, "accepted": prov.requirements(150), "payload": pl})
        st, hdrs, _ = prov.serve("GET", EVIL_PATH, {"PAYMENT-SIGNATURE": hdr}, b"")
        self.reproduces(st == 200 and "\r\n" in hdrs["X-Echo"],
                        "serve() hands a CR/LF handler header to whatever transport runs it, and bills the call")

    def test_fixed_serve_refuses_crlf_headers(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        prov.handler = echo
        p, payer = make_channel(cp, prov, node)
        pl = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": 1, "cum": "20000",
                                                 "sig": payer.sign_state(20_000).hex()}, path=EVIL_PATH)
        hdr = xp.b64json({"x402Version": 2, "accepted": prov.requirements(150), "payload": pl})
        st, hdrs, out = prov.serve("GET", EVIL_PATH, {"PAYMENT-SIGNATURE": hdr}, b"")
        self.assertEqual(st, 500)
        self.assertFalse(xp.unsafe_headers(hdrs))
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 0)     # not billed

    def test_fixed_asgi_bounds_the_body(self):
        try:
            asgi = load("asgi")
        except ImportError:
            self.skipTest("starlette not installed for this python (the demo's venv has it)")
        xp = load("x402_channel")
        app = asgi.asgi_app(make_provider(xp, FakeNode()))
        self.assertEqual(asgi_call(app, b"x" * (xp.MAX_BODY + 1))[0], 400)
        self.assertEqual(asgi_call(app, b"", [(b"payment-signature", b"a"), (b"payment-signature", b"b")])[0], 400)
        self.assertEqual(asgi_call(app, b"x")[0], 402)


def asgi_call(app, body, headers=()):
    """One request straight into an ASGI app; returns (status, headers)."""
    sent, chunks = [], [body[i:i + 65536] for i in range(0, len(body), 65536)] or [b""]

    async def receive():
        c = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": c, "more_body": bool(chunks)}

    async def send(msg):
        sent.append(msg)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
             "path": "/v1/x", "raw_path": b"/v1/x", "query_string": b"", "root_path": "",
             "headers": [(b"host", b"x")] + list(headers), "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1)}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], start["headers"]


if __name__ == "__main__":
    unittest.main()
