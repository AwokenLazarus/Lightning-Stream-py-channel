"""AGP-090 (fix wave 4, channel client and transport), B1: the neighbours of the paths the second
closure audit named. As xbt-rs `crates/xbt402/tests/agp090_client.rs` (same names where B1 has the
code). Each test failed before the fix it names.

The rules:
- open: a channel's key is on the books before its funding leaves, its refund before the provider is
  asked to open it, and an origin with a channel on the books is not funded again;
- receipts: a receipt is for the seq just sent, and the provider's spent total grows by at most one
  quote for each paid request it has not answered (a 402 is an answer: not charged), plus one call of
  slack over the channel's life.
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
from xbt402 import funding  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402
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
    """A provider, a wallet whose `fund` can fail before or after it sent, and a transport `edit` can
    change: edit(path, req, headers, answer) -> answer, or raises."""

    def __init__(self, edit=None, billing="postpay", **client):
        self.node = FakeNode()
        self.n = 0
        key = int.from_bytes(hashlib.sha256(b"provider payTo").digest(), "big")

        def handler(m, p, b):
            self.n += 1
            return (204 if p.startswith("/v1/empty") else 200), {}, json.dumps({"m": m, "answer": p, "n": self.n}).encode()
        self.prov = XbtChannelProvider(self.node, key, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: PRICE, handler,
                                       billing=billing)
        self.sends, self.refuses, self.errors_after_send, self.edit = [], False, False, edit
        if client.get("signer") is True:
            client["signer"] = ChannelSigner(self.fund)     # the signer funds: the same wallet
        self.c = XbtChannelClient(NET, self.fund, self.node.getblockcount, **client)
        self.c.http = self.http

    def fund(self, addr, sats):
        if self.refuses:
            raise ChannelError("wallet_error", "insufficient funds")
        txid = hashlib.sha256(f"funding {len(self.sends) + 1}".encode()).hexdigest()
        self.node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                               "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
        self.sends.append((txid, addr, sats))
        if self.errors_after_send:
            raise ChannelError("wallet_error", "timed out")
        return txid, 0

    def http(self, method, url, body=b"", headers=None):
        path = split(url)[1]
        req = json.loads(body) if body and path == OPEN_PATH else None
        st, h, out = self.prov.serve(method, path, dict(headers or {}), body or b"", url)
        answer = st, {k.upper(): v for k, v in h.items()}, out
        return self.edit(path, req, headers or {}, answer) if self.edit else answer

    def get(self, path="/v1/q", method="GET"):
        try:
            return self.c.request(method, O + path)[0]
        except ChannelError as e:
            return e.code
        except OSError:
            return "transport_error"


def funded_open(path, req):
    return path == OPEN_PATH and not (req or {}).get("preflight")


def refuses_funded_opens(path, req, headers, answer):
    if funded_open(path, req):
        return 400, {}, json.dumps({"error": "bad_funding", "detail": "no"}).encode()
    return answer


def paid(path, headers):
    return path.startswith("/v1/") and "PAYMENT-SIGNATURE" in headers


class Open(unittest.TestCase):
    def test_a_fund_call_that_errors_after_it_sent_leaves_the_key_on_the_books(self):
        r = Rig()
        r.errors_after_send = True
        self.assertEqual(r.get(), "wallet_error")
        ch = r.c.channels[O]
        self.assertEqual((ch.stage, ch.payer.params.funding_txid), ("keyed", ""))
        # the script the coins went to is the one this key refunds
        self.assertEqual(address_to_spk(r.sends[0][1], "bcrt"), ch.payer.params.spk)
        self.assertTrue(ch.payer.secret)

    def test_a_retry_after_a_failed_fund_call_pays_the_same_key(self):
        r = Rig()
        r.errors_after_send = True
        self.assertEqual(r.get(), "wallet_error")
        key = r.c.channels[O].payer.params.payer_pub
        r.errors_after_send = False
        self.assertEqual(r.get(), 200)
        self.assertEqual((len(r.sends), r.sends[0][1] == r.sends[1][1]), (2, True), "both sends went to one script")
        self.assertEqual(r.c.channels[O].payer.params.payer_pub, key)

    def test_a_funded_open_whose_answer_was_lost_is_finished_and_funds_nothing(self):
        lost = [True]

        def edit(path, req, headers, answer):
            if funded_open(path, req) and lost[0]:
                raise OSError("timed out")
            return answer
        r = Rig(edit)
        self.assertEqual(r.get(), "transport_error")
        ch = r.c.channels[O]
        self.assertEqual((ch.stage, ch.payer.params.funding_txid), ("funded", r.sends[0][0]))
        self.assertIn(bytes.fromhex(r.sends[0][0])[::-1].hex(), ch.refund_hex)
        lost[0] = False
        # the provider opened it the first time: its duplicate_channel is the yes that was lost
        self.assertEqual(r.get(), 200)
        self.assertEqual((len(r.sends), len(r.prov.ledger.channels), ch.stage), (1, 1, "open"))

    def test_a_conditional_call_whose_funded_open_is_refused_is_funded_once(self):
        r = Rig(refuses_funded_opens)
        r.prov.offer_conditional("/v1/secret", 600, b"the deliverable")
        for _ in range(4):
            with self.assertRaises(ChannelError) as e:
                r.c.request_conditional("GET", O + "/v1/secret")
            self.assertEqual(e.exception.code, "bad_funding")
        self.assertEqual((len(r.sends), r.c.channels[O].stage), (1, "funded"))

    def test_nothing_is_signed_for_a_channel_that_is_not_open(self):
        r = Rig(refuses_funded_opens)
        self.assertEqual(r.get(), "bad_funding")
        with self.assertRaises(ChannelError) as e:
            r.c.close(O)
        self.assertEqual(e.exception.code, "no_channel")
        ch = r.c.channels[O]
        self.assertEqual((ch.payer.signed, ch.seq, ch.last_sig), (0, 0, ""))

    def test_a_stale_unfunded_channel_keeps_its_key_and_the_next_call_opens_anew(self):
        r = Rig()
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        old = r.c.channels[O].payer.params.payer_pub
        r.refuses = False
        r.node.height += 900        # 1,008 blocks asked; the offer's floor is 144 + 1 + 36
        self.assertEqual(r.get(), "open_unresolved")
        self.assertEqual((len(r.sends), [c.payer.params.payer_pub for c in r.c.unfunded[O]]), (0, [old]))
        self.assertEqual(r.get(), 200)
        self.assertNotEqual(r.c.channels[O].payer.params.payer_pub, old)
        self.assertEqual(len(r.sends), 1)
        self.assertEqual(r.c.forget_unfunded(O), 1)
        self.assertEqual((r.c.unfunded, r.c.channels[O].stage), ({}, "open"))

    def test_a_stale_unfunded_channel_with_a_signer_waits_for_the_embedder(self):
        r = Rig(signer=True)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        key = r.c.channels[O].payer.params.payer_pub
        r.refuses = False
        r.node.height += 900
        for _ in range(3):
            self.assertEqual(r.get(), "open_unresolved")
        self.assertEqual((len(r.sends), r.c.channels[O].payer.params.payer_pub), (0, key), "the signer's issued key was not replaced")
        self.assertEqual(r.c.forget_unfunded(O), 1)
        self.assertEqual(r.get(), 200)


class Expiry(unittest.TestCase):
    def test_the_owners_bound_holds_whatever_the_offer_says(self):
        def ex(lo, hi):
            return {"minExpiryBlocks": lo, "maxExpiryBlocks": hi, "closeMarginBlocks": 144}
        self.assertEqual(funding.offer_expiry_blocks(ex(1_008, 8_640), 1_008, 4_032), 1_153)
        self.assertEqual(funding.offer_expiry_blocks(ex(3_887, 8_640), 1_008, 4_032), 4_032)
        for lo in (3_888, 2_000_000, 2 ** 64 - 1):
            with self.assertRaises(ChannelError) as e:
                funding.offer_expiry_blocks(ex(lo, 2 ** 64 - 1), 1_008, 4_032)
            self.assertEqual(e.exception.code, "bad_offer", lo)
        self.assertEqual(funding.offer_expiry_blocks(ex(144, 100_000), 50_000, 4_032), 4_032)
        self.assertEqual(funding.offer_expiry_blocks(ex(2_000_000, 3_000_000), 1_008, 2_100_000), 2_000_145)
        # the default bound is the owner's four weeks
        self.assertEqual(funding.OWNER_MAX_EXPIRY_BLOCKS, 4_032)
        with self.assertRaises(ChannelError):
            funding.offer_expiry_blocks(ex(5_000, 9_000), 1_008)


class Receipts(unittest.TestCase):
    def test_lost_answers_are_paid_for_once_and_the_channel_goes_on(self):
        for billing in ("postpay", "prepay"):
            n = [0]

            def edit(path, req, headers, answer):
                if paid(path, headers) and answer[0] == 200:
                    n[0] += 1
                    if n[0] in (3, 4, 9):
                        raise OSError("timed out reading the answer")
                return answer
            r = Rig(edit, billing=billing)
            out = [r.get() for _ in range(14)]
            self.assertEqual(len([o for o in out if o != 200]), 3, f"{billing}: only the lost answers fail: {out}")
            self.assertEqual(out[9:], [200] * 5, billing)
            ch = r.c.channels[O]
            st = r.prov.ledger.channels[ch.payer.params.channel_id]
            self.assertEqual(st.spent_msat, 14 * PRICE * 1000, f"{billing}: the provider served and charged 14 calls")
            self.assertEqual((ch.spent_msat, ch.unanswered_msat), (st.spent_msat, 0), f"{billing}: the payer's receipts say the same")
            r.c.close(O)
            self.assertEqual(r.prov.ledger.channels[ch.payer.params.channel_id].best_cum, 14 * PRICE,
                             f"{billing}: the close pays each served call once")

    def test_a_provider_cannot_claim_more_calls_than_the_payer_sent(self):
        lose, forge, last = [False], [False], [None]

        def edit(path, req, headers, answer):
            if answer[0] == 402:
                last[0] = xc.unb64json(answer[1]["PAYMENT-REQUIRED"])
            if paid(path, headers) and lose[0]:
                raise OSError("timed out")
            if paid(path, headers) and forge[0]:
                pr = dict(last[0], channel={"spentMsat": str(20 * PRICE * 1000)})
                return 402, {"PAYMENT-REQUIRED": xc.b64json(pr)}, b""
            return answer
        r = Rig(edit)
        self.assertEqual(r.get(), 200)
        # two answers are lost (the first state, 546 sat, still covers them: no 402 comes); the payer
        # then loses its count of them. One uncounted call is the channel's slack; two are not
        lose[0] = True
        self.assertEqual([r.get(), r.get()], ["transport_error"] * 2)
        lose[0] = False
        ch = r.c.channels[O]
        ch.unanswered_msat = 0
        signed = ch.payer.signed
        self.assertEqual(r.get(), "bad_receipt", "three calls' growth for one request sent")
        forge[0] = True
        self.assertEqual(r.get(), "bad_offer")
        self.assertEqual(ch.payer.signed, signed, "nothing more was signed on either claim")

    def test_a_provider_that_refuses_every_call_cannot_claim_them(self):
        on, last, claimed = [False], [None], [0]

        def edit(path, req, headers, answer):
            if answer[0] == 402:
                last[0] = xc.unb64json(answer[1]["PAYMENT-REQUIRED"])
            if on[0] and paid(path, headers):
                claimed[0] += 1
                pr = dict(last[0], channel={"spentMsat": str((1 + claimed[0]) * PRICE * 1000)})
                return 402, {"PAYMENT-REQUIRED": xc.b64json(pr)}, b""
            return answer
        r = Rig(edit)
        self.assertEqual(r.get(), 200)
        on[0] = True
        out = [r.get() for _ in range(10)]
        self.assertEqual(out.count("bad_offer"), 9, out)
        ch = r.c.channels[O]
        self.assertTrue(ch.spent_msat <= 2 * PRICE * 1000 and ch.payer.signed <= 546 + 2 * PRICE,
                        f"one honest call and one call of slack: {ch.spent_msat} msat, {ch.payer.signed} sat signed")

    def test_a_paid_answer_without_a_body_is_checked_on_its_status(self):
        def edit(path, req, headers, answer):
            st, h, out = answer
            # the provider as its HTTP server frames it: no body for a HEAD or a 204, whatever the
            # handler returned (and the receipt signed)
            if "HEAD" in headers.get("X-Method", "") or st == 204 or (paid(path, headers) and path == "/v1/cut"):
                out = b""
            if paid(path, headers) and path == "/v1/head-with-body":
                out = b"not what was signed"
            return st, h, out
        r = Rig(edit)
        self.assertEqual(r.get(), 200)
        head = lambda path: r.c.request("HEAD", O + path, headers={"X-Method": "HEAD"})[0]  # noqa: E731
        self.assertEqual(head("/v1/q"), 200)
        self.assertEqual(r.get("/v1/empty"), 204)
        self.assertEqual(r.get("/v1/cut"), "bad_receipt", "a GET cut to nothing is not a HEAD")
        with self.assertRaises(ChannelError) as e:
            head("/v1/head-with-body")
        self.assertEqual(e.exception.code, "bad_receipt")


class Binding(unittest.TestCase):
    def test_a_bare_target_is_bound_byte_for_byte(self):
        for a, b in (("/A?next=http://h/x", "/a?next=http://h/x"), ("/a?next=http://H/x", "/a?next=http://h/x"),
                     ("/a?next=http://user@h/x", "/a?next=http://h/x"), ("/a?next=http://h:080/x", "/a?next=http://h:80/x")):
            self.assertNotEqual(xc.request_digest_v2("GET", a, b""), xc.request_digest_v2("GET", b, b""), (a, b))
        self.assertEqual(xc.request_url("/a?next=http://H:080/x"), ("", "", "", "/a?next=http://H:080/x"))
        for bare in ("/a?next=http://h/x", "?x=a://b", "://h/x", "1a://h/x", "a b://h/x", ""):
            self.assertEqual(xc.url_origin(bare), "", bare)
        self.assertEqual(xc.request_url("HTTP://Api.Example:080/a?next=http://H/x"), ("http", "api.example", "80", "/a?next=http://H/x"))
        self.assertEqual(xc.url_origin("coap+tcp://h:1/x?y=z://w"), "coap+tcp://h:1")
        self.assertEqual(xc.same_origin_url("https://a.example", "/open?next=http://h/x"), "https://a.example/open?next=http://h/x")
        with self.assertRaises(ChannelError):
            xc.same_origin_url("https://a.example", "x+y://evil.example/open")

    def test_no_two_bare_targets_are_split_alike(self):
        alphabet = "/:aA?@0"
        targets, last = ["/"], ["/"]
        for _ in range(5):
            last = [t + c for t in last for c in alphabet]
            targets += last
        self.assertEqual(len({xc.request_url(t) for t in targets}), len(targets))
        self.assertTrue(any("://" in t for t in targets))

    def test_a_payment_for_one_bare_target_is_not_served_on_another(self):
        seen = []
        node = FakeNode()
        prov = XbtChannelProvider(node, int.from_bytes(hashlib.sha256(b"provider payTo").digest(), "big"), NET,
                                  tempfile.mktemp(suffix=".sqlite"), lambda m, p: PRICE,
                                  lambda m, p, b: (seen.append(p), (200, {}, b"x"))[1])
        c = XbtChannelClient(NET, lambda addr, sats: (os.urandom(32).hex(), 0), node.getblockcount,
                             on_open=lambda ch: node.add_funding(ch.payer.params))
        c.http = lambda method, url, body=b"", headers=None: (lambda r: (r[0], {k.upper(): v for k, v in r[1].items()}, r[2]))(
            prov.serve(method, split(url)[1], dict(headers or {}), body or b"", url))
        c.request("GET", O + "/v1/q")
        ch = c.channels[O]
        chan = ch.payer.params.channel_id
        sig = ch.payer.sign_state(546).hex()
        pl = {"chan": chan, "seq": 50, "cum": "546", "sig": sig}
        pl["auth"] = xc.request_auth(ch.auth_key, chan, 50, "546", sig, xc.request_digest_v2("GET", "/a?next=http://h/x", b""))
        h = {"PAYMENT-SIGNATURE": xc.b64json({"x402Version": 2, "accepted": ch.accepted, "payload": pl})}
        st, _, _ = prov.serve("GET", "/A?next=HTTP://h/x", h, b"", "")
        self.assertEqual((st, [p for p in seen if p.startswith("/A")]), (402, []))


if __name__ == "__main__":
    unittest.main()
