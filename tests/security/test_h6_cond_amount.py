"""H6 (High) the client signs a hash-locked increment of whatever size the provider names.

`XbtChannelClient.request_conditional` checked the 402's `amount` against `max_price` but signed the
conditional state for `extra.conditional.amount` unchecked: any amount up to the channel's capacity,
outside the per-call cap and the daily budget. Since AGP-001 (M6) the provider closes with that state
and claims the hash lock with its own k, so one conditional call to a malicious provider takes the
whole channel on-chain, deliverable or not. `_receipt` also raised its per-call cap to the last 402's
`conditional.amount`, so a plain call could be charged that much and the client paid it on the next
call: M3's drain, back through the conditional quote. (Root cause since wave 2; AGP-001 made the
conditional state closable and made the SDK send its fold.)

Fix: a conditional amount above `max_price` (or the daily budget) is refused before anything is
signed (`too_expensive`); plain receipts are held to the price pinned at open, conditional receipts
to the conditional amount of that call.
"""
import unittest

from condhelp import ORIGIN, Rig, outputs
from sechelp import V11, FakeNode, Repro, load, make_provider, v11

GREEDY = 150_000          # of a 200,000-sat channel; the client's per-call cap is 1,000


def inflating_provider(xm, node, charge=50_000):
    """Advertises 150 sat a call, plus a `conditional` quote on a plain path, and charges `charge`."""
    prov = make_provider(xm, node)
    prov.price = lambda m, p: charge
    real = prov.requirements

    def requirements(price):
        r = real(150)
        r["extra"]["conditional"] = {"hash": "00" * 32, "amount": str(charge), "csvDelta": 10}
        return r
    prov.requirements = requirements
    return prov


def plain_client(xm, prov, node):
    client = xm.XbtChannelClient(prov.network, fund=lambda a, s: ("ab" * 32, 0), height=node.getblockcount,
                                 max_price=1_000, on_open=lambda ch: node.add_funding(ch.payer.params))

    def http(method, url, body=b"", headers=None):
        st, h, out = prov.serve(method, "/" + url.split("/", 3)[3], headers or {}, body or b"", url)
        return st, {k.upper(): v for k, v in h.items()}, out
    client.http = http
    return client


class CondAmount(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_one_conditional_call_takes_the_channel(self):
        r = Rig(v11("x402_channel"), cond_price=GREEDY)
        r.client.request("GET", ORIGIN + "/v1/x")
        r.fold = False
        st, _, _, plain = r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        r.close_at_margin()
        cp = r.prov._cond_state(r.chan)[0]
        locked = sum(o.value for o in outputs(r.node.sent[0]) if o.script_pubkey == cp.spk)
        self.reproduces(st == 200 and locked == GREEDY and len(r.node.sent) == 2,
                        f"max_price 1,000 sat, yet one conditional call signed {locked:,} sat into the hash "
                        f"lock and the provider claimed it")

    def test_repro_conditional_quote_lifts_the_plain_call_cap(self):
        xm, node = v11("x402_channel"), FakeNode()
        prov = inflating_provider(xm, node)
        client = plain_client(xm, prov, node)
        client.request("GET", "http://api.test/v1/x")
        client.request("GET", "http://api.test/v1/x")
        signed = client.channels["http://api.test"].payer.signed
        self.reproduces(signed >= 50_000, f"a 150-sat offer with max_price 1,000: the client signed {signed:,} sat "
                                          f"after two plain calls")

    def test_fixed_conditional_amount_capped_before_signing(self):
        from xbt402.channel import ChannelError
        r = Rig(load("x402_channel"), cond_price=GREEDY)
        r.client.request("GET", ORIGIN + "/v1/x")
        with self.assertRaises(ChannelError) as e:
            r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual(e.exception.code, "too_expensive")
        self.assertEqual(r.chan.cond_sig, "")                       # nothing hash-locked was ever signed
        self.assertLess(r.cch.payer.signed, 1_000)

    def test_fixed_conditional_amount_counts_against_daily_budget(self):
        from xbt402.channel import ChannelError
        r = Rig(load("x402_channel"), daily_budget=900)
        r.client.request("GET", ORIGIN + "/v1/x")
        with self.assertRaises(ChannelError) as e:
            r.client.request_conditional("GET", ORIGIN + "/v1/cond")   # 1,000 sat > what is left today
        self.assertEqual(e.exception.code, "budget")
        self.assertEqual(r.chan.cond_sig, "")

    def test_fixed_plain_receipt_held_to_the_pinned_price(self):
        from xbt402.channel import ChannelError
        xm, node = load("x402_channel"), FakeNode()
        prov = inflating_provider(xm, node)
        client = plain_client(xm, prov, node)
        with self.assertRaises(ChannelError) as e:
            client.request("GET", "http://api.test/v1/x")
        self.assertEqual(e.exception.code, "bad_receipt")
        with self.assertRaises(ChannelError):
            client.request("GET", "http://api.test/v1/x")
        self.assertLess(client.channels["http://api.test"].payer.signed, 1_000)

    def test_control_honest_conditional_call_still_works(self):
        r = Rig(load("x402_channel"))
        r.client.request("GET", ORIGIN + "/v1/x")
        st, _, _, plain = r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual(st, 200)
        self.assertEqual(r.chan.best_cum, r.cch.payer.signed)          # folded


if __name__ == "__main__":
    unittest.main()
