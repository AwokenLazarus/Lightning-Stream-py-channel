"""L6 (Low) the facilitator endpoints shadowed a paid API's routes of the same name.

Wave 2's provider answered POST /verify, POST /settle and GET /supported by exact path before it
looked at the paid route, so an API with its own /verify (a very ordinary name) never saw a
request: a payer who signed and sent a state for it got a facilitator error instead. Fixed: the
facilitator lives under /x402/ only (/x402/verify, /x402/settle, /x402/supported), in serve()
and so in both transports (http.server and ASGI).
Servers bind 127.0.0.1 on port XBT402_TEST_PORT_BASE + 10 (see sechelp.PORT_OFFSETS).
"""
import json
import threading
import unittest
import urllib.request

from sechelp import PRICE, FakeNode, Repro, authed, base, load, make_channel, make_provider, port_for
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests

BODY = b'{"doc": "an API document to verify"}'


def api(method, path, body):
    return 200, {"Content-Type": "text/plain"}, b"api " + method.encode() + b" " + path.encode()


def paid_header(xm, cm, prov, p, payer, method, path, body, seq=1, origin=""):
    pl = {"chan": p.channel_id, "seq": seq, "cum": str(1000 * seq), "sig": payer.sign_state(1000 * seq).hex()}
    if hasattr(cm, "channel_auth_key"):            # unpatched wave 2 has no request auth (H3)
        pl = authed(xm, cm, payer, p.payee_pub, pl, method=method, path=origin + path, body=body)
    return xm.b64json({"x402Version": 2, "accepted": prov.requirements(PRICE), "payload": pl})


class RouteShadowing(Repro, unittest.TestCase):
    def provider(self, xm, cm, billing="prepay"):
        node = FakeNode()
        prov = make_provider(xm, node, billing=billing)
        prov.handler = api
        p, payer = make_channel(cm, prov, node)
        return prov, p, payer

    def test_repro_api_verify_route_is_shadowed(self):
        prov, p, payer = self.provider(xc, ch)
        st, _, out = prov.serve("POST", "/verify", {}, BODY)
        hdr = paid_header(xc, ch, prov, p, payer, "POST", "/verify", BODY)
        st2, _, out2 = prov.serve("POST", "/verify", {"PAYMENT-SIGNATURE": hdr}, BODY)
        st3, _, out3 = prov.serve("GET", "/supported", {}, b"")
        self.reproduces(st == 400 and st2 == 400 and not out2.startswith(b"api") and b"kinds" in out3,
                        f"the API's own POST /verify never runs (unpaid {st}, paid {st2} {out2[:40]!r}); "
                        f"GET /supported answers the facilitator list")

    def test_fixed_api_routes_reach_the_api(self):
        xm, cm = load("x402_channel"), load("channel")
        prov, p, payer = self.provider(xm, cm)
        for i, (method, path, body) in enumerate((("POST", "/verify", BODY), ("POST", "/settle", BODY),
                                                  ("GET", "/supported", b"")), 1):
            st, _, out = prov.serve(method, path, {}, body)
            self.assertEqual((st, json.loads(out)["error"]), (402, "payment_required"), path)
            hdr = paid_header(xm, cm, prov, p, payer, method, path, body, seq=i)
            st, h, out = prov.serve(method, path, {"PAYMENT-SIGNATURE": hdr}, body)
            self.assertEqual((st, out), (200, f"api {method} {path}".encode()), path)
            self.assertIn("PAYMENT-RESPONSE", h)
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 3 * PRICE * 1000)

    def test_fixed_facilitator_under_x402(self):
        xm, cm = load("x402_channel"), load("channel")
        prov, p, payer = self.provider(xm, cm)
        st, _, out = prov.serve("GET", "/x402/supported", {}, b"")
        self.assertEqual((st, json.loads(out)["kinds"][0]["scheme"]), (200, "batch-settlement"))
        sig = payer.sign_state(2000).hex()
        acc = prov.requirements(PRICE)
        st, _, out = prov.serve("POST", "/x402/verify", {}, json.dumps(xm.facilitator_request(
            acc, {"chan": p.channel_id, "cum": "2000", "sig": sig})).encode())
        self.assertEqual((st, json.loads(out)["isValid"]), (200, True))
        self.assertEqual(prov.ledger.channels[p.channel_id].best_cum, 2000)
        st, _, out = prov.serve("POST", "/x402/verify", {}, json.dumps(xm.facilitator_request(
            acc, {"chan": p.channel_id, "cum": "0"})).encode())
        self.assertEqual((st, json.loads(out)["invalidReason"]), (200, "invalid_batch_settlement_xbt_signature"))
        self.assertEqual(prov.serve("GET", "/x402/verify", {}, b"")[0], 405)

    def check_transport(self, send, origin):
        """`send(method, path, body, headers) -> (status, body)` over a real transport reached at `origin`."""
        xm, cm = load("x402_channel"), load("channel")
        prov, p, payer = self.provider(xm, cm)
        st, out = send(prov, "POST", "/verify", BODY, {})
        self.assertEqual(st, 402)
        hdr = paid_header(xm, cm, prov, p, payer, "POST", "/verify", BODY, origin=origin)
        self.assertEqual(send(prov, "POST", "/verify", BODY, {"PAYMENT-SIGNATURE": hdr}), (200, b"api POST /verify"))
        st, out = send(prov, "GET", "/x402/supported", b"", {})
        self.assertEqual((st, json.loads(out)["kinds"][0]["network"]), (200, prov.network))
        sig = payer.sign_state(3000).hex()
        st, out = send(prov, "POST", "/x402/verify", json.dumps(xm.facilitator_request(
            prov.requirements(PRICE), {"chan": p.channel_id, "cum": "3000", "sig": sig})).encode(), {})
        self.assertEqual((st, json.loads(out)["extra"]["cum"]), (200, "3000"))

    def test_fixed_http_server_transport(self):
        servers = {}

        def send(prov, method, path, body, headers):
            if "port" not in servers:
                httpd = prov.http_server(port_for("l6"))
                threading.Thread(target=httpd.serve_forever, daemon=True).start()
                self.addCleanup(httpd.server_close)
                self.addCleanup(httpd.shutdown)
                servers["port"] = port_for("l6")
            req = urllib.request.Request(f"http://127.0.0.1:{servers['port']}{path}", body or None, headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
        self.check_transport(send, f"http://127.0.0.1:{port_for('l6')}")

    def test_fixed_asgi_transport(self):
        try:
            from starlette.testclient import TestClient
            asgi = load("asgi")
        except ImportError as e:
            self.skipTest(f"starlette/httpx not installed: {e}")
        clients = {}

        def send(prov, method, path, body, headers):
            if "c" not in clients:
                clients["c"] = TestClient(asgi.asgi_app(prov))
            r = clients["c"].request(method, path, content=body, headers=headers)
            return r.status_code, r.content
        self.check_transport(send, "http://testserver")


if __name__ == "__main__":
    unittest.main()
