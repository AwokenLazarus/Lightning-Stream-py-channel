"""AGP-068 (review T1-T4): the same names as the Rust http_limits and lifecycle tests.

HTTP cases talk to the reference server on 127.0.0.1:0. Binding cases call Provider.serve.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "security"))
from sechelp import FakeNode, make_channel  # noqa: E402

import xbt402.channel as channel  # noqa: E402
from xbt402.channel import ChannelError, Payer, channel_auth_key  # noqa: E402
from xbt402.x402_channel import (  # noqa: E402
    MAX_RESPONSE, XbtChannelClient, XbtChannelProvider, b64json, body_hash, receipt_of,
    request_auth, request_digest_v2, unb64json,
)

O = "https://api.example"
PRICE = 150
NET = "bip122:" + "11" * 16


def provider(node, handler=None, ledger=None):
    path = ledger or tempfile.mktemp(suffix=".json")
    return XbtChannelProvider(node, 0xB0B, NET, path, lambda m, p: PRICE,
                              handler or (lambda m, p, b: (200, {}, b"ok")), billing="postpay")


def paid(prov, payer, params, seq, cum, sig, method, url, body):
    key = channel_auth_key(payer.secret, bytes.fromhex(params.payee_pub))
    pl = {"chan": params.channel_id, "seq": seq, "cum": cum}
    if sig:
        pl["sig"] = sig
    pl["auth"] = request_auth(key, params.channel_id, seq, cum, pl.get("sig"),
                              request_digest_v2(method, url, body))
    hdr = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": prov.requirements(PRICE), "payload": pl})}
    return hdr


def error_of(status, out):
    if status != 402:
        return ""
    return json.loads(out).get("error", "")


class HttpLimits(unittest.TestCase):
    def setUp(self):
        self.prov = provider(FakeNode())
        self.srv = self.prov.http_server(0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()

    def addr(self):
        return ("127.0.0.1", self.port)

    def get(self, wait):
        s = socket.create_connection(self.addr(), timeout=wait)
        s.settimeout(wait)
        s.sendall(b"GET /x402/supported HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
        out = b""
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                out += b
        except socket.timeout:
            pass
        s.close()
        return out.decode("iso-8859-1", "replace")

    def test_slow_bodies_do_not_stall_the_server(self):
        slow = []
        for _ in range(8):
            s = socket.create_connection(self.addr())
            s.sendall(b"POST /slow HTTP/1.1\r\nHost: h\r\nContent-Length: 100000\r\n\r\n")
            slow.append(s)
        time.sleep(0.3)
        t = time.monotonic()
        text = self.get(3)
        self.assertTrue(text.startswith("HTTP/1.1 200"), text[:80])
        self.assertLess(time.monotonic() - t, 3)
        for s in slow:
            s.close()

    def test_slow_heads_do_not_stall_the_server_and_are_cut_off(self):
        slow = []
        for _ in range(32):
            s = socket.create_connection(self.addr())
            s.sendall(b"GET /slow HTTP/1.1\r\nHost: h\r\nX-Drip: ")
            slow.append(s)
        self.assertTrue(self.get(3).startswith("HTTP/1.1 200"))
        s = slow[0]
        s.settimeout(20)
        t = time.monotonic()
        try:
            while s.recv(4096):
                pass
        except socket.timeout:
            pass
        self.assertLess(time.monotonic() - t, 15, "a slow head held its connection")
        for c in slow:
            c.close()

    def test_an_endless_header_line_is_refused(self):
        s = socket.create_connection(self.addr())
        s.settimeout(3)
        s.sendall(b"GET / HTTP/1.1\r\nHost: h\r\nX-Long: ")
        chunk = b"a" * (64 * 1024)
        sent = 0
        while sent < 4 << 20:
            try:
                s.sendall(chunk)
            except OSError:
                break
            sent += len(chunk)
        out = b""
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                out += b
        except socket.timeout:
            pass
        text = out.decode("iso-8859-1", "replace")
        self.assertTrue(text.startswith("HTTP/1.1 431"), text[:80])
        self.assertTrue(self.get(3).startswith("HTTP/1.1 200"))
        s.close()


class ClientBody(unittest.TestCase):
    def _serve(self, head, body=b""):
        ln = socket.socket()
        ln.bind(("127.0.0.1", 0))
        ln.listen(1)
        port = ln.getsockname()[1]

        def run():
            c, _ = ln.accept()
            c.settimeout(2)
            try:
                c.recv(4096)
            except OSError:
                pass
            c.sendall(head)
            if body:
                c.sendall(body)
            c.close()
            ln.close()

        threading.Thread(target=run, daemon=True).start()
        return f"http://127.0.0.1:{port}/x"

    def test_an_oversized_response_is_an_error_not_a_truncated_body(self):
        n = MAX_RESPONSE + 1
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n".encode()
        url = self._serve(head)
        with self.assertRaises(ChannelError) as err:
            XbtChannelClient.http("GET", url)
        self.assertEqual(err.exception.code, "response_too_large")

    def test_a_body_cut_short_is_an_error(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n"
        url = self._serve(head, b"short")
        with self.assertRaises(Exception):
            XbtChannelClient.http("GET", url)


class Binding(unittest.TestCase):
    def test_a_payment_is_bound_to_one_request_and_one_origin(self):
        node = FakeNode()
        prov = provider(node)
        params, payer = make_channel(channel, prov, node)
        # make_channel's module is xbt402.channel via the package; sechelp.derive needs the module
        sig = payer.sign_state(546).hex()
        h = paid(prov, payer, params, 10, "546", sig, "GET", f"{O}/q?a|b", b"")
        st, _, out = prov.serve("GET", "/q?a", h, b"b|", f"{O}/q?a")
        self.assertEqual((st, error_of(st, out)), (402, "bad_auth"))
        self.assertNotEqual(request_digest_v2("GET", f"{O}/q?a|b", b""),
                            request_digest_v2("GET", f"{O}/q?a", b"b|"))
        for seq, other in ((11, "http://api.example"), (12, "https://evil.example"), (13, "https://api.example:8443")):
            h = paid(prov, payer, params, seq, "546", sig, "GET", f"{O}/v1/q", b"")
            st, _, out = prov.serve("GET", "/v1/q", h, b"", f"{other}/v1/q")
            self.assertEqual((st, error_of(st, out)), (402, "bad_auth"), other)
        h = paid(prov, payer, params, 20, "546", sig, "GET", "https://API.example:443/v1/q", b"")
        st, _, out = prov.serve("GET", "/v1/q", h, b"", f"{O}/v1/q")
        self.assertEqual(st, 200, out)

    def test_concurrent_calls_get_the_numbers_of_their_own_reservation(self):
        entered, release = threading.Event(), threading.Event()

        def handler(m, path, body):
            if path == "/slow":
                entered.set()
                release.wait(5)
            return 200, {}, path.encode()

        node = FakeNode()
        prov = provider(node, handler)
        params, payer = make_channel(channel, prov, node)
        sig = payer.sign_state(546).hex()
        # one settled call, so the next two reserve 300000 and 450000 msat
        h = paid(prov, payer, params, 1, "546", sig, "GET", f"{O}/v1/q", b"")
        st, _, out = prov.serve("GET", "/v1/q", h, b"", f"{O}/v1/q")
        self.assertEqual(st, 200, out)
        ha = paid(prov, payer, params, 10, "546", sig, "GET", f"{O}/slow", b"")
        hb = paid(prov, payer, params, 11, "546", sig, "GET", f"{O}/fast", b"")
        box = {}

        def run():
            box["a"] = prov.serve("GET", "/slow", ha, b"", f"{O}/slow")

        threading.Thread(target=run).start()
        self.assertTrue(entered.wait(2))
        rb = prov.serve("GET", "/fast", hb, b"", f"{O}/fast")
        release.set()
        for _ in range(50):
            if "a" in box:
                break
            time.sleep(0.05)
        ra = receipt_of(unb64json(box["a"][1]["PAYMENT-RESPONSE"]))
        rb = receipt_of(unb64json(rb[1]["PAYMENT-RESPONSE"]))
        self.assertEqual((ra["seq"], ra["spentMsat"]), (10, "300000"))
        self.assertEqual((rb["seq"], rb["spentMsat"]), (11, "450000"))

    def test_a_seq_spent_on_a_refusal_survives_a_restart(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "ledger.json")
        node = FakeNode()
        prov = provider(node, ledger=path)
        params, payer = make_channel(channel, prov, node)
        # postpay: the first call is free of state; the next owes it and carries none, so it is refused
        h0 = paid(prov, payer, params, 1, "0", None, "GET", f"{O}/v1/q", b"")
        self.assertEqual(prov.serve("GET", "/v1/q", h0, b"", f"{O}/v1/q")[0], 200)
        h = paid(prov, payer, params, 7, "0", None, "GET", f"{O}/v1/q", b"")
        st, _, out = prov.serve("GET", "/v1/q", h, b"", f"{O}/v1/q")
        self.assertEqual(error_of(st, out), "insufficient_payment")
        prov2 = provider(node, ledger=path)
        self.assertEqual(prov2.ledger.channels[params.channel_id].seq, 7)
        st, _, out = prov2.serve("GET", "/v1/q", h, b"", f"{O}/v1/q")
        self.assertEqual(error_of(st, out), "bad_auth")

    def test_the_receipt_covers_the_response(self):
        node = FakeNode()
        prov = provider(node)
        params, payer = make_channel(channel, prov, node)
        sig = payer.sign_state(546).hex()
        h = paid(prov, payer, params, 1, "546", sig, "GET", f"{O}/v1/q", b"")
        st, hdrs, out = prov.serve("GET", "/v1/q", h, b"", f"{O}/v1/q")
        self.assertEqual(st, 200)
        rec = receipt_of(unb64json(hdrs["PAYMENT-RESPONSE"]))
        self.assertEqual(rec["status"], 200)
        self.assertEqual(rec["bodyHash"], body_hash(out))
        c = XbtChannelClient(prov.network, lambda a, s: ("", 0), lambda: 1000)
        from xbt402.x402_channel import ClientChannel
        ch = ClientChannel(payer=Payer(params, payer.secret), origin=O, accepted=prov.requirements(PRICE), price=PRICE)
        ch.payer.sign_state(546)            # the state this call's receipt acknowledges
        resp = unb64json(hdrs["PAYMENT-RESPONSE"])
        c._receipt(ch, resp, "GET", "/v1/q", b"", (200, out))
        with self.assertRaises(ChannelError) as err:
            c._receipt(ch, resp, "GET", "/v1/q", b"", (200, b"something else"))
        self.assertEqual(err.exception.code, "bad_receipt")

    def test_an_altered_conditional_answer_keeps_the_hash_lock(self):
        import xbt402.x402_channel as xc
        from condhelp import ORIGIN as CO, PLAIN, Rig, spends
        r = Rig(xc)
        serve = r.prov.serve

        def tamper(method, path, headers, body, url=""):
            st, h, out = serve(method, path, headers, body, url)
            if st == 200 and path == "/v1/cond":
                out = json.dumps(dict(json.loads(out), cipher="00" * 11)).encode()
            return st, h, out
        r.prov.serve = tamper
        r.client.request("GET", CO + "/v1/x")
        with self.assertRaises(ChannelError) as err:
            r.client.request_conditional("GET", CO + "/v1/cond")
        self.assertEqual(err.exception.code, "bad_receipt")
        self.assertTrue(r.cch.pending_cond, "the hash lock was dropped with the answer")
        r.close_at_margin()                 # the provider closes with the hash lock; its claim reveals k
        claim = next(hx for hx in r.node.sent if spends(hx, r.chan.closed_txid))
        self.assertEqual(r.client.recover_conditional(CO, claim), PLAIN)


if __name__ == "__main__":
    unittest.main()
