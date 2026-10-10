"""AGP-081: the closure audit's (AGP-077) transport and channel side paths, B1 side.
  * T4c: a call that carried a payment takes its answer only with the receipt, plain and conditional;
  * T2: a URL or request target with a `#` is refused by the payer before anything is signed or sent
    and by the provider (and the hub, both HTTP adapters) before anything is authenticated or routed;
    the digest is unchanged;
  * T1: the reference server caps connections per client address; the ASGI runner has none of the
    reference server's limits and listens on loopback only;
  * a payer opens at minExpiryBlocks + minConf + closeMarginBlocks, each from the offer (AGP-076), in
    the client's open and rollover and in the hub's ch2.
Same names as xbt-rs crates/xbt402/tests/lifecycle.rs (AGP-081) where the case exists there.
"""
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import os
import select
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
from sechelp import FakeNode  # noqa: E402

from xbt402 import funding  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError, ChannelParams  # noqa: E402
from xbt402.route import TERMS_PATH  # noqa: E402
from xbt402.route_client import RoutePayer  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"
PRICE = 150


def secret(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")


def split(url):
    return "/".join(url.split("/")[:3]), "/" + "/".join(url.split("/")[3:])


class Meddle:
    """`XbtChannelClient.http` straight into provider.serve, as someone between payer and provider:
    an answer to `/strip...` loses its PAYMENT-RESPONSE and gets another body (a conditional answer
    keeps its key); a request to `/frag...` reaches the provider with `#junk` appended to its target;
    `/down...` is answered 502 by the way there, with no receipt. `offer(extra)` may edit the `extra`
    of a 402. Counts the requests it carried."""

    def __init__(self, prov, offer=None):
        self.prov, self.offer, self.sent = prov, offer, []

    def __call__(self, method, url, body=b"", headers=None):
        self.sent.append((method, url))
        path = split(url)[1]
        if path.startswith("/down"):
            return 502, {}, b"upstream down"
        if path.startswith("/frag"):
            path, url = path + "#junk", url + "#junk"
        st, h, out = self.prov.serve(method, path, dict(headers or {}), body or b"", url)
        h = {k.upper(): v for k, v in h.items()}
        if st == 402 and self.offer and "PAYMENT-REQUIRED" in h:
            pr = xc.unb64json(h["PAYMENT-REQUIRED"])
            self.offer(pr["accepts"][0]["extra"])
            h["PAYMENT-REQUIRED"], out = xc.b64json(pr), json.dumps(pr).encode()
        if path.startswith("/strip") and st == 200:
            h.pop("PAYMENT-RESPONSE", None)
            try:
                keeps_key = "preimage" in json.loads(out)
            except ValueError:
                keeps_key = False
            if not keeps_key:
                out = b"a forged answer"
        return st, h, out


def rig(handler=None, offer=None, **client):
    """node, provider, client, the transport between them, and the sats the client's wallet funded."""
    node = FakeNode()
    prov = XbtChannelProvider(node, secret("agp081 payee"), NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: PRICE,
                              handler or (lambda m, p, b: (200, {}, b"ok")))
    funded = []
    c = XbtChannelClient(NET, lambda addr, sats: funded.append(sats) or (os.urandom(32).hex(), 0), node.getblockcount,
                         on_open=lambda ch: node.add_funding(ch.payer.params), **client)
    c.http = Meddle(prov, offer)
    return node, prov, c, c.http, funded


def code_of(test, fn, *args):
    with test.assertRaises(ChannelError) as e:
        fn(*args)
    return e.exception.code


# --- T4c: a paid answer needs its receipt ---------------------------------------------------------------
class ReceiptRequired(unittest.TestCase):
    def test_a_paid_answer_without_a_receipt_is_refused(self):
        _, _, c, _, _ = rig()
        c.request("GET", O + "/v1/q")
        ch = c.channels[O]
        before = (ch.spent_msat, len(ch.receipts), ch.acked_cum)
        with self.assertRaises(ChannelError, msg="a forged body with no receipt was taken as the paid answer") as e:
            c.request("GET", O + "/strip/q")
        self.assertEqual((e.exception.code, str(e.exception)), ("bad_receipt", "bad_receipt: paid call returned no receipt"))
        self.assertEqual((ch.spent_msat, len(ch.receipts), ch.acked_cum), before,
                         "nothing is adopted from an answer without a receipt")
        # an error answer carries no receipt when the provider itself (or the way to it) failed: it
        # comes back as it is
        signed = ch.payer.signed
        st, _, out = c.request("GET", O + "/down/q")
        self.assertEqual((st, out), (502, b"upstream down"))
        self.assertEqual((ch.spent_msat, len(ch.receipts), ch.acked_cum), before)
        # the provider did serve the stripped call. The payer holds no receipt for it and signs nothing
        # on its account: the next receipt counts two calls, which the receipt check refuses as before
        self.assertEqual(code_of(self, c.request, "GET", O + "/v1/q"), "bad_receipt")
        self.assertEqual(ch.payer.signed, signed, "the next call signed a higher state for the refused answer")
        self.assertEqual((ch.spent_msat, len(ch.receipts), ch.acked_cum), before)

    def test_a_first_answer_without_a_receipt_is_refused(self):
        # the paid retry right after a 402 (the channel is opened in the same call)
        _, _, c, _, _ = rig()
        self.assertEqual(code_of(self, c.request, "GET", O + "/strip/q"), "bad_receipt")
        self.assertEqual(c.channels[O].receipts, [])

    def test_an_unpaid_answer_needs_no_receipt(self):
        # no payment went with the request (the provider asked for none): nothing to receipt
        _, prov, c, net, _ = rig()
        serve = prov.serve
        prov.serve = lambda m, p, h, b, url="": (200, {}, b"free") if p == "/free" else serve(m, p, h, b, url)
        self.assertEqual(c.request("GET", O + "/free")[2], b"free")
        self.assertEqual(c.channels, {})

    def test_a_conditional_answer_without_a_receipt_is_refused(self):
        _, prov, c, _, _ = rig()
        prov.offer_conditional("/strip/report", 1_000, b"deliverable")
        c.request("GET", O + "/v1/q")
        ch = c.channels[O]
        signed = ch.payer.signed
        with self.assertRaises(ChannelError, msg="a hash-locked sale was folded with no receipt") as e:
            c.request_conditional("GET", O + "/strip/report")
        self.assertEqual(e.exception.code, "bad_receipt")
        self.assertTrue(ch.pending_cond, "the hash lock stays pending: the provider's claim still reveals k")
        self.assertEqual(ch.payer.signed, signed, "the increment was folded into a plain state")

    def test_the_mcp_tool_reports_a_missing_receipt_as_a_refusal(self):
        from xbt402.mcp_server import xbt402_pay
        _, _, c, _, _ = rig()
        r = xbt402_pay(c, O + "/strip/q")
        self.assertEqual((r["paid"], r.get("error")), (False, "bad_receipt"), r)
        self.assertNotIn("a forged answer", json.dumps(r))


# --- T2: a `#` fragment ---------------------------------------------------------------------------------
class Fragment(unittest.TestCase):
    def test_a_target_with_a_fragment_is_refused_by_the_payer(self):
        _, prov, c, net, _ = rig()
        prov.offer_conditional("/v1/report", 1_000, b"deliverable")
        c.request("GET", O + "/v1/q")
        ch = c.channels[O]
        before = (len(net.sent), ch.seq, ch.payer.signed)
        for url in (O + "/v1/q#x", O + "/v1/q?a=1#x", O + "#x", O + "/v1/q#"):
            with self.subTest(url):
                self.assertEqual(code_of(self, c.request, "GET", url), "bad_request")
        self.assertEqual(code_of(self, c.request_conditional, "GET", O + "/v1/report#x"), "bad_request")
        self.assertEqual((len(net.sent), ch.seq, ch.payer.signed), before,
                         "nothing is sent, numbered or signed for a URL the binding does not cover whole")
        # an origin that was never paid is not opened for one either
        self.assertEqual(code_of(self, c.request, "GET", "https://other.example/v1/q#x"), "bad_request")
        self.assertNotIn("https://other.example", c.channels)
        # nor is a seller's own open or close URL taken with one
        from xbt402.x402_channel import same_origin_url
        for given in ("/x402/xbt-channel/open#x", O + "/x402/xbt-channel/open#x"):
            self.assertEqual(code_of(self, same_origin_url, O, given), "seller_url")
        # the digest itself is unchanged (published vectors): it still drops the fragment
        self.assertEqual(xc.request_digest_v2("GET", O + "/v1/q#x", b""), xc.request_digest_v2("GET", O + "/v1/q", b""))

    def test_a_target_with_a_fragment_is_refused_by_the_routed_payer(self):
        node, net, _, _, pay, shards = R.world()
        sh = next(iter(shards.values()))
        sent = len(net.calls)
        self.assertEqual(code_of(self, pay.shard, sh.url + "#x"), "bad_request")
        bad = dataclasses.replace(sh, url=sh.url + "#x")
        self.assertEqual(code_of(self, pay.call, bad, "POST", b"{}"), "bad_request")
        self.assertEqual((len(net.calls), bad.seq), (sent, sh.seq), "a routed call was numbered or sent")
        with self.assertRaises(ChannelError) as e:
            RoutePayer(R.HUB + "#x", R.NET, node.getblockcount, fund=node.fund_address, http=net.http)
        self.assertEqual(e.exception.code, "bad_request")

    def test_the_mcp_tool_and_the_httpx_transport_refuse_a_fragment(self):
        from xbt402.mcp_server import xbt402_pay
        _, _, c, net, _ = rig()
        r = xbt402_pay(c, O + "/v1/q#x")
        self.assertEqual((r["paid"], r.get("error"), net.sent), (False, "bad_request", []), r)
        try:
            from xbt402.client_httpx import xbt402_httpx
        except ImportError:
            self.skipTest("httpx not installed for this python (the demo's venv has it)")
        with xbt402_httpx(c) as h:
            self.assertEqual(code_of(self, h.get, O + "/v1/q#x"), "bad_request")
        self.assertEqual(net.sent, [])

    def test_a_target_with_a_fragment_is_refused_by_the_provider(self):
        served = []

        def handler(m, p, b):
            served.append(p)
            return 200, {}, b"x"
        _, prov, c, _, _ = rig(handler)
        c.request("GET", O + "/v1/q")
        # the payer signs for /frag/q; on the way `#junk` is appended: the digest dropped it, the
        # handler was routed on it
        try:
            st = c.request("GET", O + "/frag/q")[0]
        except ChannelError:
            st = 400
        self.assertFalse([p for p in served if "#" in p], f"a payment was served on a target the payer never sent: {served}")
        self.assertEqual(st, 400)
        # refused before anything is looked at: unpaid, control and facilitator paths alike
        for m, p in (("GET", "/v1/q#x"), ("POST", "/x402/xbt-channel/open#x"), ("POST", "/x402/xbt-channel/lock#x"),
                     ("POST", "/x402/xbt-channel/close#x"), ("GET", "/x402/supported#x"), ("GET", "/#"),
                     ("GET", "/v1/q?a=1#x")):
            with self.subTest(p):
                self.assertEqual(prov.serve(m, p, {}, b"{}", O + p)[0], 400)

    def test_a_target_with_a_fragment_is_refused_by_the_hub(self):
        _, _, hub, _, pay, shards = R.world()
        for m, p in (("POST", "/x402/route#x"), ("POST", "/x402/route?a#x"), ("GET", "/x402/route#"),
                     ("POST", "/x402/xbt-channel/close#x"), ("POST", "/x402/xbt-channel/rollover#x")):
            with self.subTest(p):
                self.assertEqual(hub.serve(m, p, {"PAYMENT-SIGNATURE": "x"}, b"{}", R.HUB + p)[0], 400)
        # a lock is sent on bound to provider + /x402/xbt-channel/lock: no `#` in the provider either
        sh = next(iter(shards.values()))
        R.stream(pay, sh, 3)

        def tamper(pl, route):
            route["provider"] = sh.origin + "#x"
        st, doc = R.route_request(pay, sh, tamper=tamper)
        self.assertEqual((st, doc.get("error")), (400, "bad_payload"), doc)

    def test_a_target_with_a_fragment_is_refused_by_both_http_adapters(self):
        _, prov, _, _, _ = rig()
        srv = prov.http_server(0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        for target in ("/x402/supported#x", "/v1/q#x"):
            with socket.create_connection(srv.server_address, timeout=3) as s:
                s.sendall(f"GET {target} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".encode())
                self.assertTrue(s.recv(4096).startswith(b"HTTP/1.1 400"), target)
        try:
            from xbt402 import asgi
        except ImportError:
            self.skipTest("starlette not installed for this python (the demo's venv has it)")
        for raw, query in ((b"/v1/q#x", b""), (b"/v1/q", b"a=1#x")):
            self.assertEqual(asgi_status(asgi.asgi_app(prov), raw, query), 400, (raw, query))
            self.assertEqual(asgi_status(asgi.Xbt402Middleware(None, prov), raw, query), 400, (raw, query))
        self.assertEqual(asgi_status(asgi.asgi_app(prov), b"/v1/q", b"a=1"), 402)


def asgi_status(app, raw_path, query):
    """One GET straight into an ASGI app; returns the status."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": raw_path.decode(), "raw_path": raw_path, "query_string": query, "root_path": "",
             "headers": [(b"host", b"x")], "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1)}
    asyncio.run(app(scope, receive, send))
    return next(m for m in sent if m["type"] == "http.response.start")["status"]


# --- T1: per-address connection cap ---------------------------------------------------------------------
class ConnectionCap(unittest.TestCase):
    def serve(self, **kw):
        prov = rig()[1]
        srv = prov.http_server(0, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    def hold(self, srv, n, source):
        """`n` connections from loopback address `source`, each with a head that never finishes."""
        socks = []
        for _ in range(n):
            s = socket.create_connection(srv.server_address, timeout=3, source_address=(source, 0))
            self.addCleanup(s.close)
            with contextlib.suppress(OSError):  # a connection over the cap is closed at once
                s.sendall(b"GET /slow HTTP/1.1\r\nHost: h\r\nX-Drip: ")
            socks.append(s)
        return socks

    def refused(self, socks, expect):
        """How many of `socks` the server answered 503 and closed: waits for `expect` of them, then
        a moment more for one too many."""
        n, left, end = 0, list(socks), time.monotonic() + 10
        while left and time.monotonic() < end:
            ready = select.select(left, [], [], 0.3 if n >= expect else 2.0)[0]
            for s in ready:
                try:
                    self.assertTrue(s.recv(4096).startswith(b"HTTP/1.1 503"))
                except ConnectionResetError:    # closed with our head unread: the 503 can be lost to the reset
                    pass
                left.remove(s)
                n += 1
            if not ready:
                break
        return n

    def get(self, srv, source="127.0.0.1"):
        with socket.create_connection(srv.server_address, timeout=3, source_address=(source, 0)) as s:
            try:
                s.sendall(b"GET /x402/supported HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
                return s.recv(4096)[:12].decode()
            except ConnectionResetError:
                return "reset"

    def test_one_address_cannot_hold_every_connection(self):
        srv = self.serve()
        socks = self.hold(srv, xc.MAX_CONNECTIONS + 8, "127.0.0.2")
        self.assertEqual(self.get(srv), "HTTP/1.1 200", "one address held every connection of the server")
        over = len(socks) - xc.MAX_PER_ADDRESS
        self.assertEqual(self.refused(socks, over), over)
        self.assertEqual(self.get(srv, "127.0.0.2"), "HTTP/1.1 503")         # that address is at its cap
        # a closed connection gives its slot back to its address
        for s in socks:
            s.close()
        self.assertTrue(R.wait(lambda: self.get(srv, "127.0.0.2") == "HTTP/1.1 200"))

    def test_the_global_cap_still_holds_over_many_addresses(self):
        srv = self.serve()
        socks, i = [], 2
        while len(socks) < xc.MAX_CONNECTIONS:               # each address up to its own cap
            socks += self.hold(srv, min(xc.MAX_PER_ADDRESS, xc.MAX_CONNECTIONS - len(socks)), f"127.0.0.{i}")
            i += 1
        self.assertEqual(self.refused(socks, 0), 0)
        self.assertEqual(self.get(srv), "HTTP/1.1 503")

    def test_the_per_address_cap_is_a_server_parameter(self):
        srv = self.serve(max_per_address=0)                 # off: the only peer is a reverse proxy
        socks = self.hold(srv, xc.MAX_PER_ADDRESS + 8, "127.0.0.2")
        self.assertEqual(self.refused(socks, 0), 0)
        self.assertEqual(self.get(srv, "127.0.0.2"), "HTTP/1.1 200")
        srv = self.serve(max_per_address=2)
        self.assertEqual(self.refused(self.hold(srv, 5, "127.0.0.2"), 3), 3)

    def test_an_address_is_its_ipv4_or_its_ipv6_64(self):
        key = xc.address_key
        self.assertEqual(key("::ffff:203.0.113.7"), key("203.0.113.7"))
        self.assertNotEqual(key("203.0.113.7"), key("203.0.113.8"))
        self.assertEqual(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff:ffff:ffff:fffe"))
        self.assertNotEqual(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"))
        self.assertEqual(key("fe80::1%eth0"), key("fe80::2%eth0"))
        self.assertEqual(key("not an address"), "not an address")

    def test_the_asgi_runner_listens_on_loopback_only(self):
        try:
            from xbt402 import asgi
        except ImportError:
            self.skipTest("starlette not installed for this python (the demo's venv has it)")
        prov = rig()[1]
        with mock.patch("uvicorn.run") as run:              # never a listener, whatever the tree does
            for host in ("0.0.0.0", "::", "192.0.2.1", "example.com"):
                with self.subTest(host), self.assertRaises(ValueError):
                    asgi.serve_asgi(prov, host, 0)
            run.assert_not_called()
            asgi.serve_asgi(prov, "127.0.0.1", 0)
            self.assertEqual(run.call_count, 1)


# --- a payer opens at minExpiryBlocks + minConf + closeMarginBlocks -------------------------------------
def without(*keys):
    def edit(extra):
        for k in keys:
            extra.pop(k, None)
    return edit


class TermsEdit:
    """A provider or hub app whose /terms and 402 offers lose or get `extra` fields."""

    def __init__(self, app, edit):
        self.app, self.edit = app, edit

    def serve(self, method, path, headers, body, url=""):
        st, h, out = self.app.serve(method, path, headers, body, url)
        if st == 200 and path == TERMS_PATH:
            doc = json.loads(out)
            self.edit(doc["extra"])
            return st, h, json.dumps(doc).encode()
        if st == 402:
            doc = json.loads(out)
            self.edit(doc["accepts"][0]["extra"])
            return st, {**h, "PAYMENT-REQUIRED": xc.b64json(doc)}, json.dumps(doc).encode()
        return st, h, out


SHORT_CH2 = {"ch2_expiry_blocks": 100, "ch2_max_expiry_blocks": 2_000}    # a hub that asks for less than any floor


class OpenExpiry(unittest.TestCase):
    def test_payers_open_at_min_expiry_plus_min_conf_plus_close_margin(self):
        blocks = funding.open_expiry_blocks
        # three margins, three answers: a slack that mirrors one provider's default fails two of them
        self.assertEqual(blocks(1_008, 1_008, 8_640, 1, 144), 1_153)
        self.assertEqual(blocks(1_008, 1_008, 8_640, 1, 36), 1_045)
        self.assertEqual(blocks(1_008, 1_008, 8_640, 3, 5), 1_016)
        self.assertEqual(blocks(1_008, 1_008, 8_640, 0, 0), 1_008)
        # what the payer wants above the floor is kept, and the offer's max bounds both
        self.assertEqual(blocks(2_016, 1_008, 8_640, 1, 144), 2_016)
        self.assertEqual(blocks(9_000, 1_008, 8_640, 1, 144), 8_639)
        self.assertEqual(blocks(100, 1_008, 1_100, 1, 144), 1_099)
        big = 2 ** 64 - 1
        self.assertEqual(blocks(100, big, big, big, big), big - 1)
        self.assertEqual(blocks(100, 10, 0, 1, 5), 0)
        # an offer's fields have no default but minConf
        ex = {"minExpiryBlocks": 1_008, "maxExpiryBlocks": 8_640, "closeMarginBlocks": 144, "minConf": 3}
        self.assertEqual(funding.offer_expiry_blocks(ex, 1_008), 1_155)
        self.assertEqual(funding.offer_expiry_blocks({k: v for k, v in ex.items() if k != "minConf"}, 1_008), 1_153)
        self.assertEqual(funding.offer_expiry_blocks({**ex, "minExpiryBlocks": "1008"}, 1_008), 1_155)
        for k in ("minExpiryBlocks", "maxExpiryBlocks", "closeMarginBlocks"):
            for bad in ("missing", -1, "x", None, 1.5, [144]):
                e = {**ex, k: bad}
                if bad == "missing":
                    del e[k]
                with self.subTest(k=k, bad=bad):
                    self.assertEqual(code_of(self, funding.offer_expiry_blocks, e, 1_008), "bad_offer")
        self.assertEqual(code_of(self, funding.offer_expiry_blocks, {**ex, "minConf": "x"}, 1_008), "bad_offer")
        self.assertEqual(code_of(self, funding.offer_expiry_blocks, {**ex, "minConf": -1}, 1_008), "bad_offer")

    def test_the_client_opens_at_the_offers_floor(self):
        # the reference provider: minExpiryBlocks 1008, minConf 1, closeMarginBlocks 144
        node, _, c, _, _ = rig(expiry_blocks=100)
        c.request("GET", O + "/v1/q")
        self.assertEqual(c.channels[O].payer.params.expiry - node.height, 1_008 + 1 + 144)

    def test_an_open_on_an_offer_without_a_close_margin_is_refused_before_funding(self):
        for k in ("closeMarginBlocks", "minExpiryBlocks", "maxExpiryBlocks"):
            _, _, c, net, funded = rig(offer=without(k))
            with self.subTest(k):
                self.assertEqual(code_of(self, c.request, "GET", O + "/v1/q"), "bad_offer")
                self.assertEqual((funded, c.channels, c.opened_sats), ([], {}, 0))
                self.assertEqual(net.sent, [("GET", O + "/v1/q")], "the provider was asked to open")

    def test_a_rollover_on_an_offer_without_a_close_margin_is_refused(self):
        node, _, c, _, _ = rig(expiry_blocks=100)
        c.request("GET", O + "/v1/q")
        c.request("GET", O + "/v1/q")
        ch = c.channels[O]
        with mock.patch.object(ChannelParams, "derive", wraps=ChannelParams.derive) as derive:
            self.assertEqual(code_of(self, c._rollover, ch), "exhausted")     # the tx is built, then "close and reopen"
            self.assertEqual([a.args[2] for a in derive.call_args_list], [node.height + 1_008 + 1 + 144],
                             "the next channel's expiry")
            del ch.accepted["extra"]["closeMarginBlocks"]
            self.assertEqual(code_of(self, c._rollover, ch), "bad_offer")
            self.assertEqual(derive.call_count, 1, "a next channel was derived on an offer without a close margin")

    def test_a_routed_open_on_an_offer_without_a_close_margin_is_refused_before_funding(self):
        node, net = R.RouteNode(), R.Net()
        hub = R.hub(node, net)
        net.apps[R.HUB] = TermsEdit(hub, without("closeMarginBlocks"))
        funded = []
        pay = RoutePayer(R.HUB, R.NET, node.getblockcount, fund=lambda a, s: funded.append(s) or node.fund_address(a, s),
                         http=net.http)
        self.assertEqual(code_of(self, pay.open), "bad_offer")
        self.assertEqual((funded, pay.ch), ([], None))

    def ch2_blocks(self, **extra):
        node, net = R.RouteNode(), R.Net()
        origin = "http://p0.test"
        net.apps[origin] = TermsEdit(R.provider(node, net, origin), lambda ex: ex.update(extra))
        oc = R.hub(node, net, **SHORT_CH2).connect(origin)
        return oc.p().expiry - node.height

    def test_the_hub_opens_a_ch2_at_the_terms_floor(self):
        # routehelp's provider: minExpiryBlocks 500, minConf 1, closeMarginBlocks 36
        self.assertEqual(self.ch2_blocks(), 500 + 1 + 36)
        self.assertEqual(self.ch2_blocks(closeMarginBlocks=144), 500 + 1 + 144)
        self.assertEqual(self.ch2_blocks(closeMarginBlocks=5, minConf=0), 500 + 5)

    def hostile(self, edit):
        node, net = R.RouteNode(), R.Net()
        origin = "http://evil.test"
        net.apps[origin] = TermsEdit(R.provider(node, net, origin), edit)
        hub = R.hub(node, net)
        funded = []
        hub.fund = lambda a, s: funded.append(a) or node.fund_address(a, s)
        with self.assertRaises(ChannelError) as e:
            hub.connect(origin)
        self.assertEqual(e.exception.code, "bad_terms", str(e.exception))
        self.assertEqual((funded, hub.out.chans, hub.committed_sat()), ([], {}, 0))
        self.assertFalse([c for c in net.calls if c[0] == "POST"], "the provider was asked to open")
        return str(e.exception)

    def test_a_ch2_on_terms_without_a_close_margin_is_refused_before_funding(self):
        self.assertIn("malformed /terms", self.hostile(without("closeMarginBlocks")))
        self.assertIn("malformed /terms", self.hostile(lambda ex: ex.update(closeMarginBlocks=None)))
        self.assertIn("malformed /terms", self.hostile(lambda ex: ex.update(closeMarginBlocks=-1)))
        self.assertIn("minExpiryBlocks + minConf + closeMarginBlocks",
                      self.hostile(lambda ex: ex.update(closeMarginBlocks=1_000_000)))

    def test_the_hub_rolls_a_ch2_over_at_the_terms_floor(self):
        w = RolloverWorld(self, hkw=SHORT_CH2)
        w.near_margin()
        ev = w.hub.rollover(w.oc())
        self.assertEqual(ev["event"], "ch2_rollover", ev)
        self.assertEqual(w.oc().p().expiry - w.node.height, 500 + 1 + 36)


class RolloverWorld:
    """routehelp's world with one provider whose ch2 carries a signed state."""

    def __init__(self, test, hkw=None):
        self.node, self.net, self.hub, provs, self.pay, shards = R.world(hkw=hkw)
        (self.origin, self.prov), = provs.items()
        R.stream(self.pay, shards[self.origin], 10)
        test.assertEqual(self.pay.lock(shards[self.origin])["status"], "paid")

    def oc(self):
        return self.hub.out.chans[self.origin]

    def near_margin(self):
        self.node.height = self.oc().p().expiry - 40              # the provider co-signs near its close margin


if __name__ == "__main__":
    unittest.main()
