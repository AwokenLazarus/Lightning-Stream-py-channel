"""AGP-096, fix wave 5, the library client (B1): the tests of the fixes to the third closure audit's
items 4 (the library's side), 6 and 18 that the audit's own file (test_agp093_client.py) does not
hold. As xbt-rs `crates/xbt402/tests/agp096_client.rs` (same names where B1 has the code; B1's client
keeps no ledger, so the upgrade and write-ahead tests are Rust only). Each failed on branch agp-093
before its fix. The rig is the audit's.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from test_agp093_client import NET, O, OPEN_PATH, Rig  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError, ChannelParams  # noqa: E402
from xbt402.funding import offer_expiry_blocks, offer_expiry_floor, offer_retry_floor  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402
from xbt402.x402_channel import MAX_KEPT, b64json, unb64json  # noqa: E402


def offers(change):
    """A transport edit that rewrites the offer of every 402 with change(acc)."""
    def edit(path, req, headers, forward):
        st, h, out = forward()
        if st == 402:
            pr = unb64json(h["PAYMENT-REQUIRED"])
            change(pr["accepts"][0])
            h = {**h, "PAYMENT-REQUIRED": b64json(pr)}
        return st, h, out
    return edit


class FailedFunding(unittest.TestCase):
    def test_a_failed_funding_call_is_retried_on_the_same_channel_at_the_shipped_terms(self):
        """The reference provider asks for 1,008 + 1 + 144 blocks, the payer for 1,008, so a channel is
        derived with exactly the offer's floor. A `fund` call that failed is retried on the same
        channel for as long as half of the offer's confirmation margin is left (72 blocks)."""
        for signer in (False, True):
            for later in (1, 72):
                r = Rig(signer=signer) if signer else Rig()
                r.refuses = True
                self.assertEqual(r.get(), "wallet_error")
                derived = r.c.channels[O].payer.params
                self.assertEqual(derived.expiry, 1_000 + 1_153)
                script = derived.script
                r.refuses = False
                r.node.height += later
                self.assertEqual(r.get(), 200, f"signer {signer}, {later} blocks later")
                p = r.c.channels[O].payer.params
                self.assertEqual((len(r.sends), r.c.channels[O].stage, p.script), (1, "open", script))
                self.assertEqual(r.c.unfunded, {}, "nothing was set aside")

    def test_a_keyed_channel_too_old_to_fund_is_derived_again_and_funded_by_the_same_call(self):
        for signer in (False, True):
            r = Rig(signer=signer) if signer else Rig()
            r.refuses = True
            self.assertEqual(r.get(), "wallet_error")
            old = r.c.channels[O].payer.params
            r.refuses = False
            r.node.height += 73
            self.assertEqual(r.get(), 200, f"signer {signer}")
            p = r.c.channels[O].payer.params
            self.assertEqual((len(r.sends), p.expiry, p.payer_pub), (1, r.node.height + 1_153, old.payer_pub))
            self.assertEqual([c.payer.params for c in r.c.unfunded[O]], [old])
            # had the failed call sent after all, the script it paid still has its key
            old.funding_txid, old.funding_vout = "ab" * 32, 0
            if signer:
                self.assertTrue(r.c.signer.sign_refund(r.c.signer.attach(O, old)))
            else:
                self.assertTrue(old.refund_tx(r.c.unfunded[O][0].payer.secret))

    def test_no_number_of_failed_fundings_ends_a_clients_business_with_a_seller(self):
        for signer in (False, True):
            r = Rig(signer=signer) if signer else Rig()
            r.refuses = True
            for _ in range(40):
                self.assertEqual(r.get(), "wallet_error", f"signer {signer}")
                r.node.height += 100
            key = r.c.channels[O].payer.params.payer_pub
            self.assertEqual(len(r.c.unfunded[O]), MAX_KEPT)
            self.assertTrue(all(c.payer.params.payer_pub == key for c in r.c.unfunded[O]),
                            "every script kept pays the channel's key")
            r.refuses = False
            self.assertEqual(r.get(), 200, f"signer {signer}")
            self.assertEqual((len(r.sends), r.c.channels[O].payer.params.payer_pub), (1, key))

    def test_sixteen_kept_keys_from_before_are_never_dropped(self):
        """The state AGP-090 refused for good: sixteen kept channels, each with its own key, and a
        stale keyed one. The next call opens, and none of the sixteen keys is dropped."""
        r = Rig()
        r.refuses = True
        kept = []
        for _ in range(17):
            other = Rig()
            other.node, other.refuses = r.node, True
            other.c.height = r.node.getblockcount
            other.prov = r.prov
            self.assertEqual(other.get(), "wallet_error")
            kept.append(other.c.channels[O])
        keys = [c.payer.params.payer_pub for c in kept]
        self.assertEqual(len(set(keys)), 17)
        r.c.channels[O], r.c.unfunded[O] = kept[16], kept[:16]
        r.node.height += 500
        for _ in range(5):
            self.assertEqual(r.get(), "wallet_error")
            r.node.height += 500
        now = [c.payer.params.payer_pub for c in r.c.unfunded[O]]
        self.assertTrue(all(k in now for k in keys), "a key of its own is never dropped")
        self.assertEqual(len(now), 17)
        r.refuses = False
        self.assertEqual(r.get(), 200)
        self.assertEqual(len(r.sends), 1)

    def test_channels_keyed_while_the_wallet_was_empty_are_not_all_funded_past_the_budget(self):
        r = Rig()
        origins = [f"https://a{i}.example" for i in range(1, 7)]

        def get(o):
            try:
                return r.c.request("GET", o + "/v1/q")[0]
            except ChannelError as e:
                return e.code
        r.refuses = True
        self.assertEqual([get(o) for o in origins], ["wallet_error"] * 6)
        self.assertEqual((len(r.c.channels), r.c.opened_sats), (6, 0))
        r.refuses = False
        out = [get(o) for o in origins]
        self.assertEqual(out[5], "budget", out)
        self.assertEqual((len(r.sends), r.c.opened_sats), (5, 1_000_000), out)


class Terms(unittest.TestCase):
    def test_a_keyed_channel_whose_seller_changed_its_key_is_opened_on_the_new_terms_by_the_next_call(self):
        r = Rig(short=True)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        old = r.c.channels[O].payer.params
        r.refuses = False
        r.prov = r.provider(b"provider payTo after a key rotation")
        r.node.height += 10
        self.assertEqual(r.get(), "open_unresolved")
        derived = r.c.channels[O].payer.params
        self.assertEqual((len(r.sends), r.c.channels[O].stage, derived.payer_pub), (0, "keyed", old.payer_pub))
        self.assertNotEqual(derived.payee_pub, old.payee_pub, "derived again from the offer of the day")
        self.assertEqual(r.get(), 200)
        self.assertEqual((len(r.sends), r.c.channels[O].payer.params.payee_pub), (1, derived.payee_pub))
        self.assertEqual([c.payer.params for c in r.c.unfunded[O]], [old])

    def test_a_keyed_channel_is_not_funded_at_a_price_the_seller_has_raised(self):
        price = [150]
        r = Rig(offers(lambda acc: acc.__setitem__("amount", str(price[0]))))
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        r.refuses = False
        price[0] = 300
        self.assertEqual(r.get(), "open_unresolved")
        self.assertEqual(len(r.sends), 0)
        self.assertEqual((r.get(), r.get()), (200, 200))
        self.assertEqual((len(r.sends), r.c.channels[O].price), (1, 300))

    def test_a_seller_that_changes_its_offer_on_every_call_fills_nothing_and_pushes_nothing_out(self):
        """What fills `unfunded`: only channels the wallet was asked to fund. A seller that raises its
        price on every call makes the client derive its channel again each time, and none of those is
        kept: twenty changes do not push out the channel whose `fund` call failed."""
        price = [150]
        r = Rig(offers(lambda acc: acc.__setitem__("amount", str(price[0]))))
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        asked = r.c.channels[O].payer.params
        r.refuses = False
        for _ in range(20):
            price[0] += 1
            self.assertEqual(r.get(), "open_unresolved")
        self.assertEqual((len(r.sends), [c.payer.params for c in r.c.unfunded[O]]), (0, [asked]))
        self.assertEqual((r.get(), len(r.sends)), (200, 1))

    def test_a_preflight_that_gets_no_answer_leaves_the_keyed_channel_for_the_next_call(self):
        lost, asked = [False], [0]

        def edit(path, req, headers, forward):
            if path == OPEN_PATH and (req or {}).get("preflight"):
                asked[0] += 1
                if lost[0]:
                    raise TimeoutError("timed out")
            return forward()
        r = Rig(edit)
        r.refuses = True
        self.assertEqual(r.get(), "wallet_error")
        script = r.c.channels[O].payer.params.script
        r.refuses, lost[0] = False, True
        with self.assertRaises(TimeoutError):
            r.c.request("GET", O + "/v1/q")
        self.assertEqual((len(r.sends), asked[0], r.c.channels[O].payer.params.script, r.c.unfunded), (0, 2, script, {}))
        lost[0] = False
        self.assertEqual(r.get(), 200)
        self.assertEqual((len(r.sends), asked[0], r.c.channels[O].payer.params.script), (1, 3, script))


class Origin(unittest.TestCase):
    def test_one_channel_serves_every_spelling_of_its_origin(self):
        r = Rig()
        for o in ["HTTPS://API.example:443", "https://api.example", "https://u:p@api.example", "https://API.EXAMPLE",
                  "https://api.example:443"]:
            self.assertEqual(r.c.request("GET", o + "/v1/q")[0], 200, o)
        self.assertEqual((len(r.sends), list(r.c.channels), len(r.c.channels[O].receipts)), (1, [O], 5))
        # another port, another scheme and another host are other sellers
        self.assertEqual(xc.split_url("https://api.example:8443/x"), ("https://api.example:8443", "/x"))
        self.assertEqual(xc.split_url("http://api.example/x")[0], "http://api.example")
        self.assertEqual(xc.split_url("https://api.example.evil.test/x")[0], "https://api.example.evil.test")
        self.assertEqual(xc.split_url("https://api.example?a=b"), ("https://api.example", "/?a=b"))
        self.assertEqual(xc.split_url("/v1/q"), ("/v1/q", "/"))     # not absolute: split as before
        self.assertEqual(r.c.close("HTTPS://API.example:443")["chan"], r.c.channels[O].payer.params.channel_id)


class Window(unittest.TestCase):
    def test_an_offer_with_a_window_of_one_block_is_refused_before_anything_is_funded(self):
        """A seller whose offer has a window of one block and that answers the preflight yes (the
        audit's item 4, through the library client): refused bad_offer before a key is made or
        anything is funded. It used to be funded, in a channel that expired one block later."""
        def edit(path, req, headers, forward):
            if path == OPEN_PATH and (req or {}).get("preflight"):
                return 200, {}, json.dumps({"preflight": True}).encode()
            st, h, out = forward()
            if st == 402:
                pr = unb64json(h["PAYMENT-REQUIRED"])
                pr["accepts"][0]["extra"].update(minExpiryBlocks=1, maxExpiryBlocks=2, closeMarginBlocks=0)
                h = {**h, "PAYMENT-REQUIRED": b64json(pr)}
            return st, h, out
        r = Rig(edit)
        self.assertEqual([r.get() for _ in range(3)], ["bad_offer"] * 3)
        self.assertEqual((len(r.sends), r.c.channels), (0, {}))

    def test_the_owners_floor_holds_whatever_the_offer_says(self):
        def ex(lo, hi, margin):
            return {"minExpiryBlocks": lo, "maxExpiryBlocks": hi, "closeMarginBlocks": margin}
        for hi in (0, 1, 2, 144):
            with self.assertRaises(ChannelError) as e:
                offer_expiry_blocks(ex(1, hi, 0), 1_008, 4_032)
            self.assertEqual(e.exception.code, "bad_offer", hi)
        self.assertEqual(offer_expiry_blocks(ex(1, 145, 0), 1_008, 4_032), 144)
        with self.assertRaises(ChannelError):
            offer_expiry_blocks(ex(1_008, 1_100, 144), 1_008, 4_032)      # a window below the offer's own floor
        self.assertEqual(offer_expiry_blocks(ex(1_008, 1_154, 144), 1_008, 4_032), 1_153)
        # an owner who asks for less than a day gets it, down to the offer's floor
        self.assertEqual(offer_expiry_blocks(ex(1, 30, 0), 20, 4_032), 20)
        self.assertEqual(offer_expiry_blocks(ex(1, 30, 0), 0, 4_032), 2)
        with self.assertRaises(ChannelError):
            offer_expiry_blocks(ex(1, 15, 0), 20, 4_032)

    def test_a_retry_keeps_the_larger_half_of_the_margin_for_the_funding(self):
        def ex(margin):
            return {"minExpiryBlocks": 1_008, "maxExpiryBlocks": 8_640, "closeMarginBlocks": margin}
        self.assertEqual((offer_expiry_floor(ex(144)), offer_retry_floor(ex(144))), (1_153, 1_081))
        self.assertEqual([offer_retry_floor(ex(m)) for m in (36, 5, 1, 0)], [1_027, 1_012, 1_010, 1_009])


class SignerKeys(unittest.TestCase):
    def test_an_issued_key_is_never_replaced_and_binds_every_channel_that_pays_it(self):
        s = ChannelSigner()
        k = s.new_key(O)
        self.assertEqual(s.new_key(O), k, "asking again answers the key already issued")
        pay_to = ChannelSigner().new_key("payee")

        def params(pub, expiry, txid):
            p = ChannelParams.derive(pay_to, pub, expiry, 600, network=NET)
            p.capacity, p.funding_txid, p.funding_vout = 50_000, txid, 0
            return p
        one, two = params(k, 2_000, "11" * 32), params(k, 2_001, "22" * 32)
        c2 = s.attach(O, two)
        s.sign_state(c2, 700)
        c1 = s.attach(O, one)                    # the script that was derived first is bound too
        self.assertNotEqual(c1, c2)
        self.assertTrue(s.sign_refund(c1))
        self.assertEqual(s.attach(O, two), c2)   # binding a channel again keeps what was signed on it
        with self.assertRaises(ChannelError) as e:
            s.sign_state(c2, 600)
        self.assertEqual(e.exception.code, "stale_amount")
        self.assertNotEqual(s.new_key(O), k, "the key is used: the next open gets its own")
        self.assertTrue(s.sign_refund(c1))
        for origin, pub in (("https://b.example", k), (O, ChannelSigner().new_key(O)), ("https://c.example", ChannelSigner().new_key(O))):
            with self.assertRaises(ChannelError) as e:
                s.attach(origin, params(pub, 2_002, "33" * 32))
            self.assertEqual(e.exception.code, "bad_key")


if __name__ == "__main__":
    unittest.main()
