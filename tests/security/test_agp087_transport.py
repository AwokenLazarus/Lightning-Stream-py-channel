"""AGP-087 second closure audit, transport area (T1-T4), B1: tests written by the auditor.
A failing test here is a finding, not a regression."""
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode  # noqa: E402

from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"
PRICE = 150


def secret(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")


def split(url):
    return "/".join(url.split("/")[:3]), "/" + "/".join(url.split("/")[3:])


class Net:
    """Someone between payer and provider. `plan[n]` is what happens to the n-th paid request
    (1-based): "lose" (served, the answer never arrives), "replay" (never reaches the provider; the
    answer before, with its receipt, comes back)."""

    def __init__(self, prov, plan):
        self.prov, self.plan, self.n, self.last, self.served = prov, plan, 0, None, 0

    def __call__(self, method, url, body=b"", headers=None):
        paid = "PAYMENT-SIGNATURE" in (headers or {})
        what = None
        if paid:
            self.n += 1
            what = self.plan.get(self.n)
        if what == "replay":
            return self.last
        st, h, out = self.prov.serve(method, split(url)[1], dict(headers or {}), body or b"", url)
        h = {k.upper(): v for k, v in h.items()}
        if paid and st == 200:
            self.served += 1
            self.last = (st, h, out)
        if what == "lose":
            raise OSError("timed out reading the answer")
        return st, h, out


def rig(plan):
    node = FakeNode()
    n = [0]

    def handler(m, p, b):
        n[0] += 1
        return 200, {}, json.dumps({"answer": p, "n": n[0]}).encode()

    prov = XbtChannelProvider(node, secret("agp087 payee"), NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: PRICE, handler)
    c = XbtChannelClient(NET, lambda addr, sats: (os.urandom(32).hex(), 0), node.getblockcount,
                         on_open=lambda ch: node.add_funding(ch.payer.params))
    c.http = Net(prov, plan)
    return prov, c, c.http


def outcome(c, url):
    try:
        return str(c.request("GET", url)[0])
    except ChannelError as e:
        return e.code
    except OSError:
        return "transport_error"


class Receipt(unittest.TestCase):
    def test_an_earlier_answer_replayed_with_its_receipt_is_refused(self):
        """T4: the receipt names the request, the status and the body; the payer does not check it is
        for the seq it just sent. An identical request gets the answer before, receipt and all."""
        prov, c, net = rig({3: "replay"})
        a = json.loads(c.request("GET", O + "/v1/price")[2])["n"]
        b = json.loads(c.request("GET", O + "/v1/price")[2])["n"]
        self.assertNotEqual(a, b)
        served = net.served
        try:
            st, _, out = c.request("GET", O + "/v1/price")
        except ChannelError as e:
            self.assertEqual(e.code, "bad_receipt")
            return
        self.assertEqual(net.served, served)
        self.fail(f"the payer took answer n={json.loads(out)['n']} again as the answer to a new paid request "
                  f"(seq {c.channels[O].seq} sent, receipt seq {c.channels[O].receipts[-1]['seq']})")

    def test_one_lost_answer_does_not_cost_the_answers_after_it(self):
        """AGP-081 'Noticed, not changed': one answer lost while the first state (546 sat) still covers
        the next calls. Every call after it is served, charged and thrown away, then the channel stops."""
        prov, c, net = rig({2: "lose"})
        c.request("GET", O + "/v1/q")
        self.assertEqual(outcome(c, O + "/v1/q"), "transport_error")
        out = [outcome(c, O + "/v1/q") for _ in range(8)]
        ch = c.channels[O]
        st = prov.ledger.channels[ch.payer.params.channel_id]
        self.assertEqual([o for o in out if o != "200"], [],
                         f"after ONE lost answer: {out}; the provider served {net.served} paid calls, holds spent "
                         f"{st.spent_msat} msat under a signed state of {st.best_cum} sat; the payer has receipts for {ch.spent_msat} msat")


class ClientBody(unittest.TestCase):
    def raw_server(self, data):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        self.addCleanup(srv.close)

        def run():
            while True:
                try:
                    s, _ = srv.accept()
                except OSError:
                    return
                s.recv(4096)
                s.sendall(data)
                s.close()

        threading.Thread(target=run, daemon=True).start()
        return "http://127.0.0.1:%d" % srv.getsockname()[1]

    def test_a_chunked_body_cut_short_is_an_error(self):
        """T3 one step to the side: no Content-Length to compare with."""
        for data in (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nwor",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"):
            url = self.raw_server(data)
            try:
                st, _, out = XbtChannelClient.http("GET", url + "/c")
            except Exception:
                continue
            self.fail(f"a cut chunked body came back as a good one: {out!r}")


if __name__ == "__main__":
    unittest.main()
