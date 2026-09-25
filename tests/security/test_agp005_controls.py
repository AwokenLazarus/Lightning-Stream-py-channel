"""AGP-005 controls: v1.1 attack surfaces checked and found not vulnerable.

- Network string edge cases in the v2 tweak: case, Unicode normalisation, whitespace and length give
  unrelated keys or a refusal, never a collision, and a provider opens only on its own exact string.
- Cross-network replay: a state signed for one network's channel does not verify on another's.
- Facilitator bodies: swapping `paymentRequirements` against `paymentPayload.accepted` (amount,
  extra) changes nothing, since neither side's amount is ever credited; a foreign payTo or network in
  either is refused. `invalidReason` is always a bare code.
- A reorg that drops both the conditional close and its claim: the watcher sends the same close
  again, then the claim.
"""
import json
import os
import re
import unicodedata
import unittest

from condhelp import ORIGIN, Rig, spends
from sechelp import FakeNode, load, make_channel, make_provider

NET = "bip122:" + "11" * 16


class NetworkStrings(unittest.TestCase):
    def setUp(self):
        self.ch, self.e = load("channel"), load("ecc")
        self.pay_to, self.a = self.e.pubkey(0xC0FFEE), self.e.pubkey(0xA1)

    def key(self, net):
        return self.ch.channel_payee_pub(net, self.pay_to, self.a, 5000)

    def test_variants_derive_unrelated_keys(self):
        cafe = "bip122:café"
        variants = [NET, NET.upper(), NET + " ", " " + NET, unicodedata.normalize("NFC", cafe),
                    unicodedata.normalize("NFD", cafe), "bip122:" + "11" * 15]
        self.assertEqual(len({self.key(n) for n in variants}), len(variants))

    def test_length_bounds(self):
        ChannelError = self.ch.ChannelError
        for bad in ("", "x" * 256, "é" * 128):            # 0 and 256 UTF-8 bytes
            with self.assertRaises(ChannelError):
                self.key(bad)
        self.key("x" * 255)

    def test_preimage_is_injective(self):
        pre = self.ch.payee_tweak_preimage
        # the same bytes split differently between NET and payTo never give the same preimage
        self.assertNotEqual(pre("ab", b"\x02" + b"c" * 32, self.a, 1), pre("a", b"b\x02" + b"c" * 31, self.a, 1))

    def test_provider_opens_only_on_its_exact_network(self):
        xm, node = load("x402_channel"), FakeNode()
        prov = make_provider(xm, node)
        for other in (NET.upper(), NET + " ", unicodedata.normalize("NFD", NET)):
            if other == NET:
                continue
            p = self.ch.ChannelParams.derive(prov.pay_to, self.a.hex(), 3000, prov.close_fee, network=other)
            p.funding_txid, p.capacity = os.urandom(32).hex(), 100_000
            node.add_funding(p)
            c = {"txid": p.funding_txid, "vout": 0, "capacity": 100_000, "expiry": 3000,
                 "payerPub": p.payer_pub, "redeemScript": p.script.hex()}
            with self.assertRaises(self.ch.ChannelError) as e:          # its network claim is refused...
                prov.open({"x402Version": 2, "network": other, "channel": c})
            self.assertEqual(e.exception.code, "wrong_network")
            with self.assertRaises(self.ch.ChannelError) as e:          # ...and so is its key under ours
                prov.open({"x402Version": 2, "network": NET, "channel": c})
            self.assertEqual(e.exception.code, "bad_funding")

    def test_state_does_not_replay_across_networks(self):
        xm, ch = load("x402_channel"), self.ch
        provs = []
        for net in (NET, "bip122:" + "22" * 16):
            node = FakeNode()
            prov = make_provider(xm, node)
            prov.network = net
            provs.append((prov, make_channel(ch, prov, node, txid="ee" * 32)))
        (pa, (p_a, payer_a)), (pb, (p_b, _)) = provs
        self.assertNotEqual(p_a.script, p_b.script)
        sig = payer_a.sign_state(1_000)
        with self.assertRaises(ch.ChannelError):
            pb._payee(pb.ledger.channels[p_b.channel_id]).verify_state(1_000, sig)


class FacilitatorBodies(unittest.TestCase):
    def setUp(self):
        self.r = Rig(load("x402_channel"))
        for _ in range(2):
            self.r.client.request("GET", ORIGIN + "/v1/x")
        self.p = self.r.cch.payer

    def body(self, cum, req=None, acc=None):
        xm = self.r.xm
        pl = {"chan": self.p.params.channel_id, "cum": str(cum), "sig": self.p.sign_state(cum).hex()}
        b = xm.facilitator_request(self.r.prov.requirements(150), pl)
        if req:
            b["paymentRequirements"].update(req)
        if acc:
            b["paymentPayload"]["accepted"] = {**b["paymentPayload"]["accepted"], **acc}
        return b

    def test_amount_swap_changes_nothing(self):
        prov = self.r.prov
        v = prov.facilitator_verify(self.body(1_000, req={"amount": "1"}, acc={"amount": "999999999"}))
        self.assertEqual((v["isValid"], v["extra"]["cum"]), (True, "1000"))
        self.assertEqual(self.r.chan.best_cum, 1_000)
        self.assertEqual(self.r.chan.spent_msat, 300_000)              # nothing credited from either amount

    def test_foreign_payto_or_network_in_either_refused(self):
        cum = 1_000
        for side in ("req", "acc"):
            for field, val in (("payTo", "02" + "11" * 32), ("network", "bip122:" + "22" * 16),
                               ("scheme", "exact")):
                cum += 1
                v = self.r.prov.facilitator_verify(self.body(cum, **{side: {field: val}}))
                self.assertEqual(v, {"isValid": False, "invalidReason": "invalid_xbt_channel_scheme_or_network"})

    def test_invalid_reason_is_a_bare_code(self):
        prov, xm = self.r.prov, self.r.xm
        chan = self.p.params.channel_id
        bad = [{"x402Version": 1}, {"x402Version": 2, "paymentPayload": []},
               xm.facilitator_request(prov.requirements(150), {"chan": chan, "cum": "5000"}),
               xm.facilitator_request(prov.requirements(150), {"chan": chan, "cum": "5000", "sig": "00"}),
               xm.facilitator_request(prov.requirements(150), {"chan": "ff" * 32 + ":0", "cum": "1", "sig": "00"}),
               xm.facilitator_request(prov.requirements(150), {"chan": chan, "cum": "1e9", "sig": "zz"})]
        for b in bad:
            v = prov.facilitator_verify(b)
            self.assertEqual(set(v), {"isValid", "invalidReason"})
            self.assertRegex(v["invalidReason"], r"^invalid_[a-z_]+$")
            s = prov.facilitator_settle(b)
            self.assertEqual(set(s), {"success", "errorReason", "transaction", "network"})
            self.assertTrue(re.fullmatch(r"(invalid_[a-z_]+|unexpected_settle_error)", s["errorReason"]))


class ReorgAcrossCloseAndClaim(unittest.TestCase):
    def test_close_and_claim_resent_after_reorg(self):
        r = Rig(load("x402_channel"))
        r.client.request("GET", ORIGIN + "/v1/x")
        r.fold = False
        r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        r.close_at_margin()
        close_hex, claim_hex = r.node.sent
        close_txid = r.chan.closed_txid
        # the block holding both goes away; its transactions do not come back to the mempool
        r.node.txs.pop(close_txid)
        r.node.txs.pop(r.chan.extra["claim_txid"])
        r.node.spent = set()
        r.prov.close_due()
        self.assertEqual(r.node.sent[2], close_hex)                      # the very same close
        self.assertTrue(spends(r.node.sent[3], close_txid))              # then the claim
        self.assertEqual(r.chan.closed_txid, close_txid)


if __name__ == "__main__":
    unittest.main()
