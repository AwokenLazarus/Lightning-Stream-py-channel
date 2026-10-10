"""AGP-080: the closure audit's (AGP-077) B1 side paths.
  * X1: a seller-supplied openUrl / closeUrl stays on the seller's origin (`origin + "@evil.example/open"`
    named another host), in the client, the routed client and the hub; the client transport does not
    follow redirects (the B2 wallet pays through it, so a 3xx from an allowlisted origin reached any host);
  * WM: the library Payer advances its watermark on a 0xA3 state, so it never signs a plain state
    below one (B1's Payer signs no conditional states: those are B2's and the Rust signer's).
Same names as b2 tests/test_agp080_closure.py and xbt-rs crates/xbt-signer/tests/agp080_closure.rs.
"""
import hashlib
import http.server
import os
import socket
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError, ChannelParams, Payer  # noqa: E402
from xbt402.tx import address_to_spk  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"


def secret(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")


def free_port():
    """A loopback port below the ephemeral range (32768+), bound once to prove it is free."""
    for port in range(22080, 22980):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 22080-22979")


class SellerUrls(unittest.TestCase):
    OFF = ("@evil.example/open", "//evil.example/open", "http://evil.example/open", ".evil.example/open",
           "/open\\@evil.example", "/open\n/x", " /open", ":8080/open", "", "open", None, 7)

    def test_x1_a_seller_url_off_the_origin_is_refused(self):
        for bad in self.OFF:
            with self.subTest(bad), self.assertRaises(ChannelError) as e:
                xc.same_origin_url(O, bad)
            self.assertEqual(e.exception.code, "seller_url")
        self.assertEqual(xc.same_origin_url(O, "/x402/xbt-channel/open"), O + "/x402/xbt-channel/open")
        self.assertEqual(xc.same_origin_url(O, O + "/open?a=1"), O + "/open?a=1")

    def test_x1_an_open_url_off_the_origin_funds_nothing_and_asks_no_one(self):
        import tempfile
        node = FakeNode()
        prov = XbtChannelProvider(node, secret("x1 payee"), NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: 150,
                                  lambda m, p, b: (200, {}, b"{}"))
        funded, asked = [], []
        client = XbtChannelClient(NET, lambda addr, sats: funded.append(sats) or ("ab" * 32, 0), lambda: node.height)

        def http(method, url, body=b"", headers=None):
            asked.append(url)
            if not url.startswith(O + "/"):
                return 200, {}, b'{"preflight": true}'
            st, h, out = prov.serve(method, "/" + url.split("/", 3)[3], headers or {}, body or b"", url)
            h = {k.upper(): v for k, v in h.items()}
            if st == 402:
                pr = xc.unb64json(h["PAYMENT-REQUIRED"])
                pr["accepts"][0]["extra"]["openUrl"] = "@evil.example/open"
                h["PAYMENT-REQUIRED"] = xc.b64json(pr)
            return st, h, out

        client.http = http
        with self.assertRaises(ChannelError) as e:
            client.request("GET", O + "/v1/x")
        self.assertEqual(e.exception.code, "seller_url")
        self.assertEqual((funded, asked), ([], [O + "/v1/x"]), "nothing funded, only the origin asked")


class Redirects(unittest.TestCase):
    def serve(self, handler):
        port = free_port()
        srv = http.server.HTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return port

    def test_x1_a_redirect_is_not_followed(self):
        hits = []

        class Catcher(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"no")

            do_POST = do_GET  # noqa: N815

            def log_message(self, *_a):
                pass

        other = self.serve(Catcher)

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(int(self.path.rsplit("/", 1)[1]))
                self.send_header("Location", f"http://127.0.0.1:{other}/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET  # noqa: N815

            def log_message(self, *_a):
                pass

        origin = f"http://127.0.0.1:{self.serve(Redirector)}"
        for code in (301, 302, 303, 307, 308):
            for method in ("GET", "POST"):
                with self.subTest(code=code, method=method):
                    st, hdrs, _ = XbtChannelClient.http(method, f"{origin}/r/{code}", b"x" if method == "POST" else b"")
                    self.assertEqual(st, code, "the 3xx is the answer")
                    self.assertIn("LOCATION", hdrs)
        self.assertEqual(hits, [], "a redirect was followed off the origin")


class Watermark(unittest.TestCase):
    def test_wm_the_payer_advances_its_watermark_on_a3_and_conditional_states(self):
        a, b = secret("wm payer"), secret("wm payee")
        p = ChannelParams.derive(ecc.pubkey(b).hex(), ecc.pubkey(a).hex(), 5_000, 600, network=NET)
        p.funding_txid, p.funding_vout, p.capacity = "11" * 32, 0, 100_000
        payer = Payer(p, a)
        payer.sign_state(1_000)
        payer.sign_state_a3(5_000)
        self.assertEqual(payer.signed, 5_000, "the 0xA3 state is the highest amount signed")
        for stale in (payer.sign_state, payer.sign_state_a3):
            with self.assertRaises(ChannelError) as e:
                stale(4_000)
            self.assertEqual(e.exception.code, "stale_amount")
        payer.sign_state_a3(5_000)                       # the same amount again is not lower
        self.assertFalse(hasattr(payer, "sign_conditional"), "B1's Payer signs no conditional states; if it "
                         "gains one, it must advance `signed` too (test it here)")

    def test_wm_a_signer_backed_payer_advances_too(self):
        a, b = secret("wm payer"), secret("wm payee")
        p = ChannelParams.derive(ecc.pubkey(b).hex(), ecc.pubkey(a).hex(), 5_000, 600, network=NET)
        p.funding_txid, p.funding_vout, p.capacity = "11" * 32, 0, 100_000
        local = Payer(p, a)

        class Backend:
            def sign_state_a3(self, chan, amount):
                return Payer(p, a).sign_state_a3(amount).hex()

            def sign_state(self, chan, amount):
                return local.sign_state(amount).hex()

        payer = Payer(p, backend=Backend())
        payer.sign_state_a3(5_000)
        with self.assertRaises(ChannelError):
            payer.sign_state(4_000)


if __name__ == "__main__":
    unittest.main()
