"""AGP-023: xbt402 v1.2 closeFeePayer. A provider may offer that the payee pays its own settlement
close fee; channels keep payer-pays (v1.1) unless it does.

A state for cumulative amount cum pays
    payer-pays (v1.1): payee cum,              payer capacity - closeFee - cum
    payee-pays (v1.2): payee cum - closeFee,   payer capacity - cum
The security claims tested here:
  * the payer's output never depends on the close fee under payee-pays, and the payer's 0x21
    signature commits to the fee payer (a state signed under one mode is invalid under the other),
    so a payee cannot lower the payer's output, by relabelling the mode or otherwise;
  * dust: a payee-pays state is at least dust + closeFee (min_amount), so the payee output clears
    dust after its fee; the payer's change below dust is dropped into the fee as in v1.1;
  * CPFP and the 0xA3 fee-input variant: output 0 (the payer's change, capacity - cum) stays
    committed; the payee bumps from its own output or inputs;
  * the M6 hash-locked conditional state: the fee comes out of the payee's unconditional output,
    never the hash-lock output, so a payer that reclaims the lock through CSV pays nothing of it;
  * the provider settles on its net payout (settleMultiple x closeFee); a v1.1 client still opens
    payer-pays channels with every v1.1 byte unchanged.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode, make_provider  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402.channel import (DUST, SIGHASH_SINGLE_ACP_UNIFIED, ChannelError,  # noqa: E402
                            ChannelParams, Payee, Payer, channel_payee_secret, cpfp_child, settle_due)
from xbt402.conditional import ConditionalParams, sha256  # noqa: E402
from xbt402.tx import TxIn, TxOut, p2wpkh_spk  # noqa: E402
from xbt402.x402_channel import XbtChannelClient  # noqa: E402

NET = "bip122:" + "11" * 16
PAYTO, PAYER = 0xB0B, 0xA11CE
CAP, FEE = 200_000, 600


def params(payer="payee", fee=FEE, cap=CAP, txid="ab" * 32):
    p = ChannelParams.derive(ecc.pubkey(PAYTO).hex(), ecc.pubkey(PAYER).hex(), 5_000, fee, network=NET,
                             close_fee_payer=payer)
    p.funding_txid, p.funding_vout, p.capacity = txid, 0, cap
    return p


def payee_of(p):
    return Payee(p, channel_payee_secret(NET, PAYTO, bytes.fromhex(p.payer_pub), p.expiry))


def outs(tx, p):
    """{payee, payer} values of a state tx (0 when absent)."""
    v = {"payee": 0, "payer": 0}
    for o in tx.outputs:
        if o.script_pubkey.hex() == p.payee_spk:
            v["payee"] += o.value
        elif o.script_pubkey.hex() == p.payer_spk:
            v["payer"] += o.value
    return v


class StateFormat(unittest.TestCase):
    def test_payer_output_is_capacity_minus_cum_whatever_the_fee(self):
        for fee in (0, 600, 5_000):
            p = params(fee=fee)
            for cum in (DUST + fee, 12_345, CAP - DUST):
                o = outs(p.state_tx(cum), p)
                self.assertEqual(o, {"payee": cum - fee, "payer": CAP - cum})
                self.assertEqual(sum(x.value for x in p.state_tx(cum).outputs), CAP - fee)   # the fee is fee

    def test_v11_payer_pays_is_byte_for_byte_unchanged(self):
        p = params("payer")
        tx = p.state_tx(12_345)
        self.assertEqual([(o.value, o.script_pubkey.hex()) for o in tx.outputs],
                         [(12_345, p.payee_spk), (CAP - FEE - 12_345, p.payer_spk)])
        self.assertNotIn("close_fee_payer", p.to_dict())                  # v1.1 records serialise as before
        self.assertEqual(ChannelParams(**p.to_dict()).close_fee_payer, "payer")
        self.assertEqual((p.min_amount, p.max_amount), (DUST, CAP - FEE))
        q = params("payee")
        self.assertEqual(ChannelParams(**q.to_dict()).close_fee_payer, "payee")
        self.assertEqual((q.min_amount, q.max_amount), (DUST + FEE, CAP))

    def test_dust_bounds(self):
        p = params()
        with self.assertRaises(ChannelError) as e:
            p.state_tx(DUST + FEE - 1)                    # the payee output would be dust after its fee
        self.assertEqual(e.exception.code, "bad_amount")
        self.assertEqual(outs(p.state_tx(DUST + FEE), p)["payee"], DUST)
        self.assertEqual(outs(p.state_tx(CAP - DUST + 1), p), {"payee": CAP - DUST + 1 - FEE, "payer": 0})  # dropped
        self.assertEqual(outs(p.state_tx(CAP), p), {"payee": CAP - FEE, "payer": 0})
        with self.assertRaises(ChannelError):
            p.state_tx(CAP + 1)
        with self.assertRaises(ChannelError) as e:
            params("nobody")
        self.assertEqual(e.exception.code, "bad_fee_payer")

    def test_the_payer_signature_commits_to_the_fee_payer(self):
        """A payee holding a payer-pays signature cannot close as payee-pays (or the reverse), and
        cannot move a sat from the payer's output to its own: every such tx needs a new signature."""
        pp, pe = params("payer"), params("payee")
        cum = 20_000
        sig_payer = Payer(pp, PAYER).sign_state(cum)
        sig_payee = Payer(pe, PAYER).sign_state(cum)
        payee_of(pp).verify_state(cum, sig_payer)
        payee_of(pe).verify_state(cum, sig_payee)
        for p, sig in ((pe, sig_payer), (pp, sig_payee)):
            with self.assertRaises(ChannelError) as e:
                payee_of(p).verify_state(cum, sig)
            self.assertEqual(e.exception.code, "bad_sig")
        tx = pe.state_tx(cum)                              # the payee takes 1 sat of the payer's output
        tx.outputs[0].value += 1
        tx.outputs[1].value -= 1
        self.assertFalse(ecc.verify(bytes.fromhex(pe.payer_pub), pe.sighash(tx), sig_payee[:-1]))
        # the only close the payee can complete is the signed one, paying the payer capacity - cum
        payee = payee_of(pe)
        payee.accept(cum, sig_payee)
        self.assertEqual(outs(payee.close_tx(), pe), {"payee": cum - FEE, "payer": CAP - cum})

    def test_a3_fee_input_and_cpfp_come_from_the_payee(self):
        p = params()
        cum = 30_000
        tx = p.state_tx_a3(cum)
        self.assertEqual((tx.outputs[0].value, tx.outputs[0].script_pubkey.hex()), (CAP - cum, p.payer_spk))
        self.assertEqual(tx.outputs[1].value, cum - FEE)
        sig = Payer(p, PAYER).sign_state_a3(cum)
        self.assertEqual(sig[-1], SIGHASH_SINGLE_ACP_UNIFIED)
        payee = payee_of(p)
        payee.accept(cum, Payer(p, PAYER).sign_state(cum))
        extra_secret = 0xFEE
        prev = TxOut(5_000, p2wpkh_spk(ecc.pubkey(extra_secret)))
        full = payee.close_tx_with_fee_input(prev, TxIn(bytes(32), 0), extra_secret, prev.script_pubkey, 1_000, sig)
        self.assertEqual((full.outputs[0].value, full.outputs[0].script_pubkey.hex()), (CAP - cum, p.payer_spk))
        close = payee.close_tx()
        child = cpfp_child(close.txid(), 0, cum - FEE, bytes.fromhex(p.payee_spk), payee.secret, 500)
        self.assertEqual(child.outputs[0].value, cum - FEE - 500)

    def test_rollover_takes_the_fee_from_the_payee(self):
        p = params()
        nxt = params(txid="cd" * 32)
        amount = 15_000
        cap2 = p.rollover_next_capacity(amount)
        self.assertEqual(cap2, CAP - amount)
        tx = p.rollover_tx(amount, nxt.spk, cap2)
        self.assertEqual([o.value for o in tx.outputs], [amount - FEE, CAP - amount])
        self.assertEqual(params("payer").rollover_next_capacity(amount), CAP - FEE - amount)
        with self.assertRaises(ChannelError):
            p.rollover_tx(DUST + FEE - 1, nxt.spk, CAP - DUST - FEE + 1)
        with self.assertRaises(ChannelError):
            p.rollover_tx(amount, nxt.spk, cap2 + 1)          # a sat of the payee's fee share to the payer

    def test_conditional_state_fee_from_the_unconditional_output(self):
        h = sha256(b"k")
        p = params()
        cp = ConditionalParams(p, h, 1_000)
        with self.assertRaises(ChannelError) as e:
            cp.state_tx(0)                     # payee-pays: no unconditional output to take the fee from
        self.assertEqual(e.exception.code, "bad_amount")
        uncond = DUST + FEE + 100
        tx = cp.state_tx(uncond)
        vals = [(o.value, o.script_pubkey) for o in tx.outputs]
        self.assertEqual(vals, [(uncond - FEE, bytes.fromhex(p.payee_spk)), (1_000, cp.spk),
                                (CAP - uncond - 1_000, bytes.fromhex(p.payer_spk))])
        cpp = ConditionalParams(params("payer"), h, 1_000)                 # v1.1 unchanged
        self.assertEqual([o.value for o in cpp.state_tx(0).outputs], [1_000, CAP - 1_000 - FEE])

    def test_settle_threshold_is_on_the_net_payout(self):
        self.assertTrue(settle_due(params("payer"), 12_000, 20))
        self.assertFalse(settle_due(params("payee"), 12_000, 20))           # nets 11,400 < 12,000
        self.assertFalse(settle_due(params("payee"), 12_599, 20))
        self.assertTrue(settle_due(params("payee"), 12_600, 20))
        self.assertFalse(settle_due(params("payee"), 0, 0))                 # nothing to settle


class ProviderTerms(unittest.TestCase):
    def setUp(self):
        import xbt402.x402_channel as xc
        self.node = FakeNode()
        self.prov = make_provider(xc, self.node)

    def _open(self, fee_payer=None, a=0x1234):
        p = ChannelParams.derive(self.prov.pay_to, ecc.pubkey(a).hex(), self.node.height + 2_000, self.prov.close_fee,
                                 network=self.prov.network, close_fee_payer=fee_payer or "payer")
        p.funding_txid, p.funding_vout, p.capacity = os.urandom(32).hex(), 0, 200_000
        self.node.add_funding(p)
        c = {"txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub,
             "redeemScript": p.script.hex()}
        if fee_payer:
            c["closeFeePayer"] = fee_payer
        return p, self.prov.open({"x402Version": 2, "network": self.prov.network, "channel": c})

    def test_plain_402_is_v11_and_terms_name_the_fee_payer(self):
        self.assertNotIn("closeFeePayer", self.prov.requirements(150)["extra"])
        t = self.prov.terms()["extra"]
        self.assertEqual((t["closeFeePayer"], t["settleMultiple"]), ("payer", 20))
        self.assertIn("rolloverGraceBlocks", t)
        self.assertNotIn("routes", t)
        self.prov.close_fee_payer = "payee"
        self.assertEqual(self.prov.terms()["extra"]["closeFeePayer"], "payee")

    def test_open_accepts_payee_pays_only_where_offered(self):
        with self.assertRaises(ChannelError) as e:
            self._open("payee")                                  # not offered
        self.assertEqual(e.exception.code, "bad_fee_payer")
        self.prov.close_fee_payer = "payee"
        p, r = self._open("payee", a=0x2)
        self.assertEqual((r["closeFeePayer"], r["minCum"], r["maxCum"]), ("payee", str(DUST + 600), "200000"))
        self.assertEqual(self.prov.ledger.channels[p.channel_id].params.close_fee_payer, "payee")
        p, r = self._open(None, a=0x3)                           # a v1.1 client: payer-pays is always fine
        self.assertNotIn("closeFeePayer", r)
        self.assertEqual(self.prov.ledger.channels[p.channel_id].params.close_fee_payer, "payer")

    def test_plain_payee_pays_when_the_provider_offers_it(self):
        """A provider may offer payee-pays on plain channels too: the reference client follows the
        402, floors its first state at dust + closeFee and checks the provider's echo."""
        self.prov.close_fee_payer = "payee"
        acc = self.prov.requirements(150)
        self.assertEqual(acc["extra"]["closeFeePayer"], "payee")
        node = self.node

        def fund(addr, sats):
            from xbt402.tx import address_to_spk
            txid = os.urandom(32).hex()
            node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                              "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
            return txid, 0
        cl = XbtChannelClient(self.prov.network, fund, node.getblockcount)
        cl.http = lambda m, url, body=b"", headers=None: self.prov.serve(m, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)
        st, _, _ = cl.request("GET", "http://prov.test/v1/x")
        self.assertEqual(st, 200)
        ch = cl.channels["http://prov.test"]
        self.assertEqual(ch.payer.params.close_fee_payer, "payee")
        self.assertEqual(ch.payer.signed, 0)                            # postpay: the first call is free
        cl.request("GET", "http://prov.test/v1/x")
        self.assertEqual(ch.payer.signed, DUST + 600)                   # the payee-pays floor
        st2 = self.prov.ledger.channels[ch.payer.params.channel_id]
        self.assertEqual(st2.best_cum, DUST + 600)
        self.assertEqual(outs(self.prov._close_tx(st2)[0], st2.params)["payee"], DUST)


if __name__ == "__main__":
    unittest.main()
