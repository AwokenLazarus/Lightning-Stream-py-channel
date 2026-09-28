"""AGP-029: under v1.2 payee-pays, the close answer and /x402/settle reported the provider's net close
output as `cum` / `amount` and counted the close fee as unpaid: a 1,500 state with a 600 fee closed
as `cum: 900`, `unpaidMsat: 600000`, so a payer that trusts `unpaidMsat` thinks it owes the fee. The
on-chain amounts were right; the report was not (found by AGP-025).

Fix: `cum` / `amount` are the gross state (what the payer paid), `unpaidMsat` = spent - gross, and a
payee-pays answer adds `payeeFee` and `payeeNet` (the provider's outputs). A payer-pays (v1.1) answer
is byte-for-byte what it was.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import PRICE, FakeNode, make_provider  # noqa: E402

import xbt402.x402_channel as xc  # noqa: E402
from xbt402 import ecc  # noqa: E402
from xbt402.mcp_server import xbt_close  # noqa: E402
from xbt402.tx import Tx, address_to_spk  # noqa: E402

ORIGIN = "http://prov.test"
FEE = 600


class Rig:
    """A provider (price 150) and the reference client, over serve() and a fake node."""

    def __init__(self, fee_payer):
        self.node = node = FakeNode()
        self.prov = make_provider(xc, node)
        self.prov.close_fee_payer = fee_payer

        def fund(addr, sats):
            txid = os.urandom(32).hex()
            node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                              "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
            return txid, 0
        self.cl = xc.XbtChannelClient(self.prov.network, fund, node.getblockcount)
        self.cl.http = lambda m, url, body=b"", headers=None: self.prov.serve(
            m, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)

    def calls(self, n):
        for _ in range(n):
            st, _, _ = self.cl.request("GET", ORIGIN + "/v1/x")
            assert st == 200, st
        return self

    @property
    def ch(self):
        return self.cl.channels[ORIGIN]

    @property
    def st(self):
        return self.prov.ledger.channels[self.ch.payer.params.channel_id]

    def settle(self):
        p = self.ch.payer
        chan = p.params.channel_id
        req = {"chan": chan, "sig": ecc.sign(p.secret, xc.close_message(chan)).hex()}
        return self.prov.facilitator_settle(xc.facilitator_request(self.prov.requirements(PRICE), req))

    def payee_out(self):
        tx = Tx.parse(bytes.fromhex(self.st.extra["close_hex"]))
        return sum(o.value for o in tx.outputs if o.script_pubkey.hex() == self.st.params.payee_spk)


class PayeePaysCloseReport(unittest.TestCase):
    def test_close_reports_the_gross_cum_and_the_payee_fee(self):
        r = Rig("payee").calls(10)                        # 10 x 150 = 1,500 spent
        self.assertEqual(r.st.spent_msat, 1_500_000)
        res = r.cl.close(ORIGIN)                          # the final state pays exactly what is owed
        self.assertEqual(res, {"chan": r.st.params.channel_id, "txid": r.st.closed_txid, "cum": "1500",
                               "unpaidMsat": "0", "payeeFee": "600", "payeeNet": "900"})
        self.assertEqual(r.payee_out(), 900)              # on chain the provider pays its own fee

    def test_settle_reports_gross_amount_and_the_fee_in_extra(self):
        r = Rig("payee").calls(10)
        r.cl.close(ORIGIN)
        res = r.settle()                                  # the same close, via the facilitator
        self.assertEqual(res["amount"], "1500")
        self.assertEqual(res["extra"], {"chan": r.st.params.channel_id, "unpaidMsat": "0",
                                        "payeeFee": "600", "payeeNet": "900"})

    def test_a_short_state_is_unpaid_by_the_shortfall_only(self):
        r = Rig("payee").calls(10)
        res = r.settle()                                  # closes on the best state the client signed
        best = r.st.best_cum
        self.assertLess(best, 1_500)
        self.assertEqual((res["amount"], res["extra"]["unpaidMsat"], res["extra"]["payeeNet"]),
                         (str(best), str((1_500 - best) * 1000), str(best - FEE)))
        self.assertEqual(r.payee_out(), best - FEE)

    def test_mcp_close_tool_passes_the_fee_fields(self):
        r = Rig("payee").calls(10)
        out = xbt_close(r.cl, ORIGIN)
        self.assertEqual((out["cum"], out["unpaidMsat"], out["payeeFee"], out["payeeNet"]), (1500, 0, 600, 900))

    def test_ledger_without_close_paid_reports_the_same(self):
        """A channel recorded before close_paid existed falls back to the best state: gross already."""
        r = Rig("payee").calls(10)
        r.cl.close(ORIGIN)
        st = r.st
        before = r.prov._close_report(st)
        del st.extra["close_paid"]
        self.assertEqual(r.prov._close_report(st), before)


class PayerPaysUnchanged(unittest.TestCase):
    def test_v11_close_and_settle_bytes(self):
        r = Rig("payer").calls(10)
        res = r.cl.close(ORIGIN)
        chan, txid = r.st.params.channel_id, r.st.closed_txid
        self.assertEqual(json.dumps(res), json.dumps({"chan": chan, "txid": txid, "cum": "1500", "unpaidMsat": "0"}))
        self.assertEqual(r.payee_out(), 1_500)
        s = r.settle()
        self.assertEqual(json.dumps(s), json.dumps(
            {"success": True, "transaction": txid, "network": r.prov.network, "payer": r.st.params.payer_pub,
             "amount": "1500", "extra": {"chan": chan, "unpaidMsat": "0"}}))
        out = xbt_close(r.cl, ORIGIN)
        self.assertNotIn("payeeFee", out)


if __name__ == "__main__":
    unittest.main()
