"""AGP-020: MAX_BODY is configurable per provider and per route.

Default stays 1 MiB. A larger configured body is accepted; above the configured
limit the request is refused unbilled. ASGI and http.server both use
provider.body_limit(path). M4 CL/TE hardening still holds.
Servers bind 127.0.0.1 on ports XBT402_TEST_PORT_BASE + 50..51 (see sechelp.PORT_OFFSETS).
"""
import socket
import threading
import time
import unittest

from sechelp import PRICE, FakeNode, authed, load, make_channel, make_provider, port_for

P0, P1 = (port_for("agp020", i) for i in range(2))


def start(prov, port):
    httpd = prov.http_server(port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def exchange(port, raw, wait=2.0):
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


def asgi_call(app, body, path="/v1/x", headers=()):
    import asyncio
    sent, chunks = [], [body[i:i + 65536] for i in range(0, len(body), 65536)] or [b""]

    async def receive():
        c = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": c, "more_body": bool(chunks)}

    async def send(msg):
        sent.append(msg)

    raw = path.encode()
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": path, "raw_path": raw, "query_string": b"", "root_path": "",
             "headers": [(b"host", b"x")] + list(headers), "server": ("127.0.0.1", 80),
             "client": ("127.0.0.1", 1)}
    asyncio.run(app(scope, receive, send))
    start_msg = next(m for m in sent if m["type"] == "http.response.start")
    return start_msg["status"], start_msg["headers"]


class ConfigurableMaxBody(unittest.TestCase):
    def setUp(self):
        self.xp, self.cp = load("x402_channel"), load("channel")
        self.calls = []

        def api(method, path, body):
            self.calls.append((path, len(body)))
            return 200, {"Content-Type": "text/plain"}, b"ok"

        self.api = api

    def _prov(self, **kw):
        node = FakeNode()
        prov = make_provider(self.xp, node)
        if "max_body" in kw:
            prov.max_body = int(kw["max_body"])
        if "route_max_body" in kw:
            prov.route_max_body = dict(kw["route_max_body"])
        prov.handler = self.api
        return prov, node

    def _paid(self, prov, node, path, body, seq=1, cum=20_000):
        p, payer = make_channel(self.cp, prov, node)
        pl = authed(self.xp, self.cp, payer, p.payee_pub,
                    {"chan": p.channel_id, "seq": seq, "cum": str(cum),
                     "sig": payer.sign_state(cum).hex()},
                    method="POST", path=path, body=body)
        hdr = {"PAYMENT-SIGNATURE": self.xp.b64json(
            {"x402Version": 2, "accepted": prov.requirements(PRICE), "payload": pl})}
        return p, hdr

    def test_default_is_one_mib(self):
        self.assertEqual(self.xp.MAX_BODY, 1 << 20)
        prov, _ = self._prov()
        self.assertEqual(prov.max_body, 1 << 20)
        self.assertEqual(prov.body_limit("/v1/x"), 1 << 20)
        self.assertEqual(prov.body_limit("/forward?n=1"), 1 << 20)

    def test_serve_accepts_a_larger_configured_body_and_bills(self):
        limit = self.xp.MAX_BODY + 1000
        body = b"x" * (self.xp.MAX_BODY + 100)
        prov, node = self._prov(max_body=limit)
        p, hdr = self._paid(prov, node, "/v1/x", body)
        st, _, out = prov.serve("POST", "/v1/x", hdr, body)
        self.assertEqual(st, 200)
        self.assertEqual(out, b"ok")
        self.assertEqual(self.calls, [("/v1/x", len(body))])
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, PRICE * 1000)

    def test_serve_refuses_above_configured_limit_unbilled(self):
        limit = 2048
        body = b"x" * (limit + 1)
        prov, node = self._prov(max_body=limit)
        p, hdr = self._paid(prov, node, "/v1/x", body)
        st, _, _ = prov.serve("POST", "/v1/x", hdr, body)
        self.assertEqual(st, 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 0)

    def test_serve_max_body_kwarg_overrides_provider(self):
        body = b"x" * 100
        prov, node = self._prov(max_body=10_000)
        p, hdr = self._paid(prov, node, "/v1/x", body)
        st, _, _ = prov.serve("POST", "/v1/x", hdr, body, max_body=50)
        self.assertEqual(st, 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 0)

    def test_route_option_larger_than_provider_default(self):
        body = b"x" * 3000
        prov, node = self._prov(max_body=1024, route_max_body={"/forward": 4096})
        self.assertEqual(prov.body_limit("/forward"), 4096)
        self.assertEqual(prov.body_limit("/v1/x"), 1024)
        p, hdr = self._paid(prov, node, "/forward", body)
        st, _, _ = prov.serve("POST", "/forward", hdr, body)
        self.assertEqual(st, 200)
        self.assertEqual(self.calls, [("/forward", 3000)])
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, PRICE * 1000)
        self.calls.clear()
        p2, hdr2 = self._paid(prov, node, "/v1/x", body)
        st2, _, _ = prov.serve("POST", "/v1/x", hdr2, body)
        self.assertEqual(st2, 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(prov.ledger.channels[p2.channel_id].spent_msat, 0)

    def test_default_still_refuses_one_mib_plus_one(self):
        body = b"x" * (self.xp.MAX_BODY + 1)
        prov, node = self._prov()
        p, hdr = self._paid(prov, node, "/v1/x", body)
        st, _, _ = prov.serve("POST", "/v1/x", hdr, body)
        self.assertEqual(st, 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 0)

    def test_asgi_and_httpserver_agree_on_raised_limit(self):
        try:
            asgi = load("asgi")
        except ImportError:
            self.skipTest("starlette not installed for this python (the demo's venv has it)")
        limit = 4096
        ok, over = b"x" * 3000, b"x" * 4097
        prov, _ = self._prov(max_body=limit)
        app = asgi.asgi_app(prov)
        self.assertEqual(asgi_call(app, ok)[0], 402)          # unpaid, but the body was accepted
        self.assertEqual(asgi_call(app, over)[0], 400)
        self.assertEqual(self.calls, [])                      # 402 never reached the handler

        httpd = start(prov, P0)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        req = (b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: 3000\r\n"
               b"Connection: close\r\n\r\n" + ok)
        data = exchange(P0, req)
        self.assertTrue(data.startswith(b"HTTP/1.0 402") or data.startswith(b"HTTP/1.1 402"), data[:80])
        req = (b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: 4097\r\n"
               b"Connection: close\r\n\r\n" + over)
        data = exchange(P0, req)
        self.assertIn(b" 413 ", data.split(b"\r\n")[0])

    def test_asgi_route_limit(self):
        try:
            asgi = load("asgi")
        except ImportError:
            self.skipTest("starlette not installed for this python")
        body = b"x" * 3000
        prov, _ = self._prov(max_body=1024, route_max_body={"/forward": 4096})
        app = asgi.asgi_app(prov)
        self.assertEqual(asgi_call(app, body, path="/forward")[0], 402)
        self.assertEqual(asgi_call(app, body, path="/v1/x")[0], 400)

    def test_m4_cl_te_still_holds_with_a_raised_cap(self):
        """A higher max_body does not re-open Transfer-Encoding or a negative Content-Length."""
        prov, _ = self._prov(max_body=self.xp.MAX_BODY * 2)
        httpd = start(prov, P1)
        httpd.handle_error = lambda *a: None
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        inner = b"GET /v1/smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        size = f"{len(inner):x}\r\n".encode()
        smuggle = (b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(size)).encode()
                   + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + size + inner + b"\r\n0\r\n\r\n")
        data = exchange(P1, smuggle)
        self.assertIn(b" 501 ", data.split(b"\r\n")[0])
        self.assertNotIn(b"smuggled", data)
        data = exchange(P1, b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n")
        self.assertIn(b" 400 ", data.split(b"\r\n")[0])
        data = exchange(P1, b"POST /v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n")
        self.assertIn(b" 413 ", data.split(b"\r\n")[0])


if __name__ == "__main__":
    unittest.main()
