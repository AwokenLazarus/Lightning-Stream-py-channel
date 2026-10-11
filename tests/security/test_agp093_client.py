"""AGP-093 third closure audit, CLIENT area, B1: tests written by the auditor against fix wave 4
(AGP-090). As xbt-rs `crates/xbt402/tests/agp093_client.rs` (same names where B1 has the code). No
fix is in this file.

`test_hole_*` fail today and state the claim that should hold. `test_ok_*` are controls (the honest
path in the same rig) and `test_limit_*` pin a number a reader must be told; both pass.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402
from xbt402.tx import address_to_spk  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"
OPEN_PATH = "/x402/xbt-channel/open"
PRICE = 150


def split(url):
    return "/".join(url.split("/")[:3]), "/" + "/".join(url.split("/")[3:])


class Rig:
    """A provider (replaceable: a seller can restart with another key), a wallet whose `fund` can
    refuse, and a transport `edit` can change: edit(path, req, headers, forward) -> answer, where
    forward() asks the provider."""

    def __init__(self, edit=None, short=False, **client):
        self.node = FakeNode()
        self.n, self.short = 0, short
        self.prov = self.provider(b"provider payTo")
        self.sends, self.refuses, self.edit = [], False, edit
        if client.get("signer") is True:
            client["signer"] = ChannelSigner(self.fund)     # the signer funds: the same wallet
        self.c = XbtChannelClient(NET, self.fund, self.node.getblockcount, **client)
        self.c.http = self.http

    def provider(self, seed: bytes):
        """`short`: a seller whose offer asks for 144 + 1 + 36 blocks at least (the default asks for
        1,008 + 1 + 144, which is above the payer's own 1,008)."""
        key = int.from_bytes(hashlib.sha256(seed).digest(), "big")

        def handler(m, p, b):
            self.n += 1
            return 200, {}, json.dumps({"m": m, "answer": p, "n": self.n}).encode()
        kw = {"close_margin": 36, "policy": FundingPolicy(min_expiry_blocks=144, close_margin=36)} if self.short else {}
        return XbtChannelProvider(self.node, key, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: PRICE, handler, **kw)

    def fund(self, addr, sats):
        if self.refuses:
            raise ChannelError("wallet_error", "insufficient funds")
        txid = hashlib.sha256(f"funding {len(self.sends) + 1}".encode()).hexdigest()
        self.node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                               "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
        self.sends.append((txid, addr, sats))
        return txid, 0

    def http(self, method, url, body=b"", headers=None):
        path = split(url)[1]
        req = json.loads(body) if body and path == OPEN_PATH else None

        def forward():
            st, h, out = self.prov.serve(method, path, dict(headers or {}), body or b"", url)
            return st, {k.upper(): v for k, v in h.items()}, out
        return self.edit(path, req, headers or {}, forward) if self.edit else forward()

    def get(self, path="/v1/q", method="GET"):
        try:
            return self.c.request(method, O + path)[0]
        except ChannelError as e:
            return e.code


def paid(path, headers):
    return path.startswith("/v1/") and "PAYMENT-SIGNATURE" in headers


class OpenStages(unittest.TestCase):
    def test_hole_a_keyed_channel_is_not_funded_on_terms_the_seller_no_longer_offers(self):
        """HOLE (Low, new in wave 4). The preflight (review C2) is asked when the channel is keyed. A
        keyed channel whose `fund` call failed is funded by a later call on the terms saved then, with
        no new preflight, for as long as its expiry allows (827 blocks against a seller whose offer
        asks for 144 + 1 + 36). A seller that changed its payTo key meanwhile refuses the funded open:
        the capacity is locked until expiry by a seller whose preflight would have said no."""
        r = Rig(short=True)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        self.assertEqual((r.c.channels[O].stage, len(r.sends)), ("keyed", 0))
        # the wallet is topped up; the seller came back with another payTo key; 10 blocks went by
        r.refuses = False
        r.prov = r.provider(b"provider payTo after a key rotation")
        r.node.height += 10
        out = r.get()
        ch = r.c.channels[O]
        self.assertEqual(len(r.sends), 0,
                         f"the client funded {r.sends[0][2] if r.sends else 0} sat to a channel with the seller's old payTo, "
                         f"with no preflight on the day it funded; the call answered {out!r}, the channel is {ch.stage!r} and "
                         f"its coins are locked until block {ch.payer.params.expiry} (tip {r.node.height})")

    def test_ok_a_keyed_channel_is_funded_by_the_retry_when_the_seller_is_unchanged(self):
        r = Rig(short=True)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        r.refuses = False
        r.node.height += 10
        self.assertEqual(r.get(), 200)
        self.assertEqual((len(r.sends), r.c.channels[O].stage), (1, "open"))

    def test_hole_one_failed_funding_call_does_not_end_a_signer_backed_clients_business_with_a_seller(self):
        """HOLE (Medium for availability, new in wave 4; nothing is lost). The reference provider's
        offer asks for 1,008 + 1 + 144 blocks at least, above the payer's own 1,008, so a keyed
        channel is "too near its expiry to fund" as soon as the tip has moved by one block. With a
        signer the stale record is never set aside: one failed `fund` call and one block later every
        call to that seller fails open_unresolved until the embedder calls forget_unfunded."""
        r = Rig(signer=True)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        r.refuses = False
        r.node.height += 1
        out = []
        for _ in range(20):
            r.node.height += 1
            out.append(r.get())
        self.assertIn(200, out, f"one failed funding call, and 20 later calls with a funded wallet all fail: {out[:3]} "
                                f"(funded {len(r.sends)} channels)")

    def test_hole_failed_funding_calls_do_not_end_a_clients_business_with_a_seller(self):
        """The same with a local key: each failed `fund` call a block apart leaves one kept key, and
        at 16 kept keys the origin is refused for good."""
        r = Rig()
        r.refuses = True
        failed = []
        for _ in range(40):
            failed.append(r.get())
            r.node.height += 1
        r.refuses = False
        out = []
        for _ in range(20):
            r.node.height += 1
            out.append(r.get())
        self.assertIn(200, out, f"after {failed.count('wallet_error')} failed funding calls "
                                f"({len(r.c.unfunded.get(O, []))} keys kept), 20 calls with a funded wallet all fail: {out[:3]}")

    def test_hole_a_refusing_seller_is_funded_once_however_its_origin_is_spelled(self):
        """HOLE (Low, left from before; a way round the new rule "an origin with a channel on the
        books is never funded again"). The book is keyed by the origin as the caller's URL spells it,
        while the request binding reads HTTPS://API.example:443 and https://u@api.example as the
        origin https://api.example. A seller that refuses every funded open and gets its URLs called
        in several spellings is funded once per spelling, up to budget_sats."""
        def edit(path, req, headers, forward):
            if path == OPEN_PATH and not (req or {}).get("preflight"):
                return 400, {}, json.dumps({"error": "bad_funding", "detail": "no"}).encode()
            return forward()
        r = Rig(edit)
        for o in ["https://api.example", "https://API.example", "https://api.example:443", "https://u@api.example",
                  "HTTPS://api.example"]:
            self.assertEqual(xc.request_url(o + "/v1/q")[1], "api.example")
            with self.assertRaises(ChannelError) as e:
                r.c.request("GET", o + "/v1/q")
            self.assertEqual(e.exception.code, "bad_funding", o)
        self.assertEqual(len(r.sends), 1, f"one seller, {len(r.sends)} channels funded ({r.c.opened_sats} sat): "
                                          f"{sorted(r.c.channels)}")

    def test_limit_a_refused_funded_channel_blocks_its_origin_until_the_embedder_removes_it(self):
        """LIMIT. A seller that answers the preflight yes and every funded open no: one channel is
        funded, no close can be signed for it, and the record stays "funded" past the expiry: nothing
        in the client clears it."""
        def edit(path, req, headers, forward):
            if path == OPEN_PATH and not (req or {}).get("preflight"):
                return 400, {}, json.dumps({"error": "bad_funding", "detail": "no"}).encode()
            return forward()
        r = Rig(edit)
        self.assertEqual([r.get() for _ in range(5)], ["bad_funding"] * 5)
        ch = r.c.channels[O]
        self.assertEqual((len(r.sends), r.c.opened_sats, ch.stage), (1, 200_000, "funded"))
        with self.assertRaises(ChannelError) as e:
            r.c.close(O)
        self.assertEqual(e.exception.code, "no_channel")
        self.assertEqual(ch.payer.params.expiry, 1_000 + 1_153)
        r.node.height = ch.payer.params.expiry + 5_000
        self.assertEqual(r.get(), "bad_funding")
        self.assertEqual((len(r.sends), r.c.channels[O].stage), (1, "funded"))


class Slack(unittest.TestCase):
    def greedy(self):
        """A seller (or whoever sits between) that serves nothing: mode 1 answers every paid request
        with a 503 and no receipt and never shows it to the provider; mode 2 answers the next paid
        request with an unsigned 402 naming `claim` msat."""
        s = {"mode": 0, "claim": 0, "last": None}

        def edit(path, req, headers, forward):
            if paid(path, headers) and s["mode"] == 1:
                return 503, {}, b"try later"
            if paid(path, headers) and s["mode"] == 2:
                s["mode"] = 1
                pr = json.loads(json.dumps(s["last"]))
                pr["channel"] = {"spentMsat": str(s["claim"])}
                return 402, {"PAYMENT-REQUIRED": xc.b64json(pr)}, b""
            st, h, out = forward()
            if st == 402:
                s["last"] = xc.unb64json(h["PAYMENT-REQUIRED"])
            return st, h, out
        return s, Rig(edit)

    def test_limit_a_seller_that_answers_errors_is_believed_for_one_quote_per_request(self):
        """LIMIT (AGP-090 stated limit 2, with its number). The provider is believed for one quote for
        every paid request it answered without a receipt: ten requests answered 503 and never served,
        then one unsigned 402 naming ten more calls, and the client signs for all ten. Before wave 4
        the bound was one call over the channel's life."""
        s, r = self.greedy()
        self.assertEqual(r.get(), 200)
        ch = r.c.channels[O]
        self.assertEqual((ch.payer.signed, ch.spent_msat), (0, PRICE * 1000))
        s["mode"] = 1
        self.assertEqual([r.get() for _ in range(10)], [503] * 10)
        self.assertEqual(ch.unanswered_msat, 10 * PRICE * 1000)
        s["claim"], s["mode"] = 11 * PRICE * 1000, 2
        self.assertEqual(r.get(), 503)
        served = r.prov.ledger.channels[ch.payer.params.channel_id].spent_msat
        self.assertEqual(served, PRICE * 1000, "the provider served one call")
        self.assertEqual((ch.spent_msat, ch.payer.signed), (11 * PRICE * 1000, 11 * PRICE),
                         "the payer adopted ten unserved calls on an unsigned 402")
        s["claim"], s["mode"] = 14 * PRICE * 1000, 2
        self.assertEqual(r.get(), "bad_offer")

    def test_hole_two_forged_refusals_do_not_end_the_channel(self):
        """HOLE (Low, the remainder of the audit's item 9 for someone between payer and provider). A
        402 is unsigned, and the client takes one as the provider's word that the request was not
        charged (_refused). Whoever sits between lets the provider serve a paid request and answers
        the payer with a bare 402: the charge is real and the payer has taken its quote off the
        books. The channel's one call of slack absorbs that once; the second time every call is
        bad_offer, for good."""
        s = {"forge": 0, "last": None}

        def edit(path, req, headers, forward):
            st, h, out = forward()
            if st == 402:
                s["last"] = xc.unb64json(h["PAYMENT-REQUIRED"])
            if paid(path, headers) and st == 200 and s["forge"]:
                s["forge"] -= 1
                pr = json.loads(json.dumps(s["last"]))
                pr.pop("channel", None)
                return 402, {"PAYMENT-REQUIRED": xc.b64json(pr)}, b""
            return st, h, out
        r = Rig(edit)
        self.assertEqual([r.get() for _ in range(4)], [200] * 4)
        ch = r.c.channels[O]
        s["forge"] = 1
        self.assertEqual((r.get(), r.get()), (402, 200))
        self.assertEqual([r.get() for _ in range(2)], [200] * 2)
        s["forge"] = 1
        out = [r.get() for _ in range(12)]
        charged = r.prov.ledger.channels[ch.payer.params.channel_id].spent_msat // (PRICE * 1000)
        self.assertIn(200, out[1:], f"after a second forged refusal no call succeeds: {out}; the provider charged {charged} "
                                    f"calls, the payer kept {len(ch.receipts)} answers")

    def test_ok_a_402_cannot_roll_the_state_back_or_move_the_seq(self):
        s, r = self.greedy()
        self.assertEqual([r.get() for _ in range(6)], [200] * 6)
        ch = r.c.channels[O]
        seq, spent = ch.seq, ch.spent_msat
        s["claim"], s["mode"] = 0, 2
        self.assertEqual(r.get(), 503)
        self.assertEqual((ch.spent_msat, ch.payer.signed, ch.seq), (spent, spent // 1000, seq + 2))


if __name__ == "__main__":
    unittest.main()
