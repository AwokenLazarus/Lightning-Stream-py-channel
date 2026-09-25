"""L8 (Low) the hash-lock claim pays a fixed fee and is never bumped, though it has a deadline.

The claim pays `claim_fee` (300 sat, about 2.2 sat/vB for its ~137 vB). `_claim` returned as soon as
the hash-lock output was spent in the mempool view, so a claim stuck under a fee spike was never
replaced. After csvDelta (10) blocks the payer's branch opens, and the payer can replace the stuck
claim with a better-paying refund of condAmount. Loss is bounded by condAmount (one call).

Fix: while the claim is unconfirmed and the close is buried, the watcher re-signs the claim with a
fee that doubles for every block of the close's depth (capped so the output stays above dust) and
replaces it (the claim signals RBF, and only the provider's key signs it).
"""
import unittest

from condhelp import ORIGIN, Rig, spends, outputs
from sechelp import V11, Repro, load, v11


def stuck_claim(xm, depth, cond_price=5_000):
    r = Rig(xm, cond_price=cond_price, max_price=cond_price)
    r.client.request("GET", ORIGIN + "/v1/x")
    r.fold = False
    r.client.request_conditional("GET", ORIGIN + "/v1/cond")
    r.close_at_margin()
    r.node.txs[r.chan.closed_txid]["confirmations"] = depth       # the close is buried, the claim is not
    for _ in range(3):
        r.prov.close_due()
    claims = [hx for hx in r.node.sent if spends(hx, r.chan.closed_txid)]
    cond = r.prov._cond_state(r.chan)[0].cond_amount
    return r, [cond - outputs(hx)[0].value for hx in claims]


class ClaimFee(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_claim_never_bumped(self):
        r, fees = stuck_claim(v11("x402_channel"), depth=6)
        self.reproduces(fees == [r.prov.claim_fee], f"close 6 blocks deep, csvDelta 10, claim still at {fees} sat fee")

    def test_fixed_claim_fee_escalates_with_depth(self):
        r, fees = stuck_claim(load("x402_channel"), depth=3)
        self.assertEqual(fees, [300, 2400])                          # 300 << 3, sent once per new fee
        self.assertEqual(r.chan.extra["claim_fee"], 2400)

    def test_fixed_fee_capped_above_dust(self):
        r, fees = stuck_claim(load("x402_channel"), depth=9)
        self.assertEqual(fees[-1], 5_000 - 546)                     # the claimed output stays at dust

    def test_control_unconfirmed_close_not_bumped(self):
        r, fees = stuck_claim(load("x402_channel"), depth=0)          # close unconfirmed: nothing to bump yet
        self.assertEqual(fees, [300])


if __name__ == "__main__":
    unittest.main()
