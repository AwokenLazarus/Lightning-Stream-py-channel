"""M3 (Medium) a malicious provider drains the client without serving.

The client SDK accepts, on every 402, the provider's claimed `spentMsat` if it is at most one call
above its receipts, and replaces the channel's `accepted` terms with the latest 402 (including a
higher `amount`, up to max_price). A provider that answers every request with 402 and "one more
call" gets a fresh, higher state signed twice per request and never serves or signs a receipt.
The v1 note's "at most one call" holds per request, not per channel: N requests, N calls lost.
Unchanged in wave 2. Fixed: the price is pinned at open and the one call of slack is per channel.
Ports XBT402_TEST_PORT_BASE + 30..31 (see sechelp.PORT_OFFSETS).
"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sechelp import FakeNode, Repro, base, load, make_provider, port_for
ch, ecc, xc = base("channel"), base("ecc"), base("x402_channel")   # unpatched wave 2: the repro tests
wire = load("x402_channel")   # the fake server's base64-JSON helpers (the same in every tree)

PORT = port_for("m3")


class Greedy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    claimed, reqs, extra = 0, None, None

    def do_GET(self):
        paid = int(wire.unb64json(self.headers["PAYMENT-SIGNATURE"])["payload"]["cum"])
        Greedy.claimed = paid * 1000 + (Greedy.extra or 900_000)   # "you owe one more call"
        body = {"x402Version": 2, "error": "insufficient_payment", "resource": {"url": self.path},
                "accepts": [Greedy.reqs], "channel": {"chan": "x", "cum": "0", "seq": 0,
                                                       "spentMsat": str(Greedy.claimed)}}
        out = json.dumps(body).encode()
        self.send_response(402)
        self.send_header("PAYMENT-REQUIRED", wire.b64json(body))
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class ClientDrain(Repro, unittest.TestCase):
    def test_repro_402_loop_drains_without_receipts(self):
        prov = make_provider(xc, FakeNode())
        opened = prov.requirements(150)
        Greedy.reqs = {**opened, "amount": "900"}             # raise the price mid-channel
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Greedy)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        a = 0xA1
        p = ch.ChannelParams.derive(prov.pay_to, ecc.pubkey(a).hex(), 3000, 600)
        p.funding_txid, p.funding_vout, p.capacity = "ab" * 32, 0, 200_000
        client = xc.XbtChannelClient(prov.network, None, lambda: 1000)
        origin = f"http://127.0.0.1:{PORT}"
        client.channels[origin] = xc.ClientChannel(ch.Payer(p, a), origin, opened)
        for i in range(10):
            client.request("GET", f"{origin}/v1/x?{i}")
        c = client.channels[origin]
        self.reproduces(c.payer.signed >= 10 * 900 and not c.receipts and c.accepted["amount"] == "900",
                        f"10 requests, 0 served, 0 receipts: the client signed {c.payer.signed} sat "
                        f"(price silently raised 150 -> 900)")


    def test_fixed_price_pinned_and_slack_per_channel(self):
        xp, cp, e = load("x402_channel"), load("channel"), load("ecc")
        prov = make_provider(xp, FakeNode())
        opened = prov.requirements(150)
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT + 1), Greedy)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        origin = f"http://127.0.0.1:{PORT + 1}"

        def client():
            p = cp.ChannelParams.derive(prov.pay_to, e.pubkey(0xA1).hex(), 3000, 600, network=prov.network)
            p.funding_txid, p.funding_vout, p.capacity = "ab" * 32, 0, 200_000
            c = xp.XbtChannelClient(prov.network, None, lambda: 1000)
            c.channels[origin] = xp.ClientChannel(cp.Payer(p, 0xA1), origin, opened, price=150)
            return c

        self.addCleanup(setattr, Greedy, "extra", None)
        Greedy.reqs = {**opened, "amount": "900"}               # price raised mid-channel: refused
        c = client()
        with self.assertRaises(cp.ChannelError) as err:
            c.request("GET", f"{origin}/v1/x")
        self.assertEqual(err.exception.code, "bad_offer")
        self.assertEqual(c.channels[origin].payer.signed, 0)

        Greedy.reqs = opened                                      # same price, but never serves
        Greedy.extra = 150_000
        c, refused = client(), 0
        for i in range(10):
            try:
                self.assertEqual(c.request("GET", f"{origin}/v1/x?{i}")[0], 402)   # the one call of slack
            except cp.ChannelError as err:
                self.assertEqual(err.code, "bad_offer")
                refused += 1
        self.assertEqual(refused, 9)
        self.assertLessEqual(c.channels[origin].payer.signed, 2 * 150 + 546)   # one call of slack, dust floor


if __name__ == "__main__":
    unittest.main()
