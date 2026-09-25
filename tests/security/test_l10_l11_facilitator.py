"""L10, L11 (Low) the x402 facilitator answers describe payments that do not exist.

L10: `close()` (and so `/x402/settle`) applied a close request's `payload` even after the channel had
closed, and answered with the new `cum`. A second settle with a higher signed state therefore returned
`success: true, amount: <higher>` with the *same* close txid, which pays the old amount. Idempotent in
the txid, not in what it reports: a resource server that books `SettlementResponse.amount` books
money that never moves. The ledger's `best_cum` also drifted above what the close pays.

L11: `/x402/verify` answered `isValid: true` for a correctly signed state on a channel that was
closed, closing (tip past expiry - closeMarginBlocks) or suspended (funding reorged out). In x402 a
VerifyResponse with isValid is what a resource server serves on; this one described a state that can
never settle.

Fix: after the close, `close()` and `/x402/settle` report the recorded close (`close_paid`) and ignore
payloads. `/x402/verify` still records a higher state while the channel is open or closing, but
answers `isValid: false` with `invalid_xbt_channel_closing` / `invalid_xbt_channel_unconfirmed` for a
state the channel can no longer settle.
"""
import unittest

from condhelp import ORIGIN, Rig, outputs
from sechelp import V11, Repro, load, v11


def settle(r, cum=None):
    xm, p = r.xm, r.cch.payer
    chan = p.params.channel_id
    req = {"chan": chan, "sig": xm.ecc.sign(p.secret, xm.close_message(chan)).hex()}
    if cum:
        req["payload"] = {"chan": chan, "cum": str(cum), "sig": p.sign_state(cum).hex()}
    return r.prov.facilitator_settle(xm.facilitator_request(r.prov.requirements(150), req))


def verify(r, cum):
    xm, p = r.xm, r.cch.payer
    pl = {"chan": p.params.channel_id, "cum": str(cum), "sig": p.sign_state(cum).hex()}
    return r.prov.facilitator_verify(xm.facilitator_request(r.prov.requirements(150), pl))


def paid_calls(xm):
    r = Rig(xm)
    for _ in range(2):
        r.client.request("GET", ORIGIN + "/v1/x")
    return r


def on_chain(r):
    return sum(o.value for o in outputs(r.node.sent[0]) if o.script_pubkey.hex() == r.chan.params.payee_spk)


class SettleAfterClose(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_second_settle_reports_money_that_never_moves(self):
        r = paid_calls(v11("x402_channel"))
        first, second = settle(r, 1_000), settle(r, 6_000)
        self.reproduces(first["transaction"] == second["transaction"] and second["amount"] == "6000"
                        and on_chain(r) == 1_000,
                        f"same close {second['transaction'][:12]}…, which pays {on_chain(r)} sat, "
                        f"reported as amount {second['amount']}")

    def test_fixed_settle_reports_the_recorded_close(self):
        r = paid_calls(load("x402_channel"))
        first, second = settle(r, 1_000), settle(r, 6_000)
        self.assertEqual(first, second)
        self.assertEqual((second["amount"], on_chain(r)), ("1000", 1_000))
        self.assertEqual(r.chan.best_cum, 1_000)
        close = r.prov.close({"chan": r.chan.params.channel_id,
                              "sig": r.xm.ecc.sign(r.cch.payer.secret,
                                                   r.xm.close_message(r.chan.params.channel_id)).hex()})
        self.assertEqual(close["cum"], "1000")

    def test_fixed_conditional_close_amount(self):
        r = Rig(load("x402_channel"))
        r.client.request("GET", ORIGIN + "/v1/x")
        r.fold = False
        r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        res = settle(r)                                   # no plain state at all: the hash lock pays more
        self.assertTrue(r.chan.extra["cond_close"])
        self.assertEqual(res["amount"], "1000")              # uncond 0 + condAmount, before the claim fee


class VerifyOnDeadChannel(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_verify_valid_after_close(self):
        r = paid_calls(v11("x402_channel"))
        settle(r, 1_000)
        v = verify(r, 7_000)
        self.reproduces(v["isValid"] is True and r.chan.closed_txid,
                        "isValid: true for a state on a channel that is already closed")

    def test_fixed_closed(self):
        r = paid_calls(load("x402_channel"))
        settle(r, 1_000)
        self.assertEqual(verify(r, 7_000), {"isValid": False, "invalidReason": "invalid_xbt_channel_closing"})
        self.assertEqual(r.chan.best_cum, 1_000)

    def test_fixed_closing_records_but_invalid(self):
        r = paid_calls(load("x402_channel"))
        r.node.height = r.chan.params.expiry - r.prov.close_margin
        r.prov._height_at = 0
        self.assertEqual(verify(r, 2_000)["invalidReason"], "invalid_xbt_channel_closing")
        self.assertEqual(r.chan.best_cum, 2_000)                       # still the provider's to close with

    def test_fixed_suspended(self):
        r = paid_calls(load("x402_channel"))
        r.node.reorg_out(r.chan.params.funding_txid)
        r.prov.close_due()
        self.assertTrue(r.chan.suspended)
        self.assertEqual(verify(r, 2_000)["invalidReason"], "invalid_xbt_channel_unconfirmed")

    def test_control_open_channel_valid(self):
        r = paid_calls(load("x402_channel"))
        self.assertTrue(verify(r, 2_000)["isValid"])


if __name__ == "__main__":
    unittest.main()
