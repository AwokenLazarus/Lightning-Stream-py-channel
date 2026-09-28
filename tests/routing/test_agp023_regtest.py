"""AGP-023 on a real chain (Knots 29.4.2 regtest, RDTS + #419; ports XBT402_TEST_PORT_BASE + 15/16,
datadir run/agp023-<pid>, wiped after): every transaction shape of a payee-pays (xbt402 v1.2) channel
is standard and consensus-valid, and pays exactly what the state format says.
  1. a 0x21 close: the payee gets cum - closeFee, the payer capacity - cum; a CPFP child spends the
     payee output (the payee bumps its own close);
  2. a 0xA3 close completed with a fee input by the payee: output 0 (the payer's change) as signed;
  3. a rollover: the payee gets amount - closeFee, the next channel capacity - amount;
  4. the M6 conditional state: the close pays uncond - closeFee to the payee and the whole
     condAmount to the hash lock; the claim with k confirms;
  5. the whole routed path: the hub's payee-pays ch2 through a provider close, mined.
"""
import os
import secrets
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "security"))
sys.path.insert(0, HERE)

from sechelp import ROOT, RegtestNode, port_for  # noqa: E402

import routehelp as R  # noqa: E402
import test_agp021_regtest as T21  # noqa: E402
from xbt402 import ecc  # noqa: E402
from xbt402.channel import (DUST, ChannelParams, Payee, Payer, channel_payee_secret, cpfp_child)  # noqa: E402
from xbt402.conditional import ConditionalParams, sha256  # noqa: E402
from xbt402.route import AMSAT_PER_SAT  # noqa: E402
from xbt402.tx import TxIn, TxOut, p2wpkh_spk, segwit_address  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

BIN = T21.BIN
DD = os.path.join(ROOT, "run", f"agp023-{os.getpid()}")
SAT = 100_000_000
FEE = 600
CAP = 50_000


@unittest.skipUnless(os.path.exists(os.path.join(BIN, "bitcoind")), "Knots 29.4.2 binary not installed")
class PayeePaysOnChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regtest = RegtestNode(BIN, DD, port_for("agp023_rpc"), port_for("agp023_p2p"),
                                  XBT402_BLOCKS="300", XBT402_MATURITY_PAD="6800")
        cls.node = T21.Node(cls.regtest.start(cls))
        cls.net = network_id(cls.node.getblockhash(101))
        R.NET = cls.net

    def channel(self, cap=CAP):
        """A funded, confirmed payee-pays channel: (params, payer secret, Payee)."""
        pay_to, a = secrets.randbelow(ecc.N - 1) + 1, secrets.randbelow(ecc.N - 1) + 1
        p = ChannelParams.derive(ecc.pubkey(pay_to).hex(), ecc.pubkey(a).hex(), self.node.height + 500, FEE,
                                 network=self.net, close_fee_payer="payee")
        txid, vout = self.node.fund_address(segwit_address("bcrt", p.spk), cap)
        p.funding_txid, p.funding_vout, p.capacity = txid, vout, cap
        payee = Payee(p, channel_payee_secret(self.net, pay_to, bytes.fromhex(p.payer_pub), p.expiry))
        return p, a, payee

    def values(self, txid):
        tx = self.node.getrawtransaction(txid, True)
        self.assertGreaterEqual(tx.get("confirmations", 0), 1)
        return [(round(o["value"] * SAT), o["scriptPubKey"]["hex"]) for o in tx["vout"]]

    def test_1_close_and_cpfp(self):
        p, a, payee = self.channel()
        cum = 20_000
        payee.accept(cum, Payer(p, a).sign_state(cum))
        close = payee.close_tx()
        self.node.sendrawtransaction(close.hex())
        child = cpfp_child(close.txid(), 0, cum - FEE, bytes.fromhex(p.payee_spk), payee.secret, 400)
        self.node.sendrawtransaction(child.hex())
        self.node.mine()
        self.assertEqual(self.values(close.txid()), [(cum - FEE, p.payee_spk), (CAP - cum, p.payer_spk)])
        self.assertEqual(self.values(child.txid()), [(cum - FEE - 400, p.payee_spk)])

    def test_2_a3_close_with_the_payees_fee_input(self):
        p, a, payee = self.channel()
        cum = 12_000
        payee.accept(cum, Payer(p, a).sign_state(cum))
        sig_a3 = Payer(p, a).sign_state_a3(cum)
        k = secrets.randbelow(ecc.N - 1) + 1
        spk = p2wpkh_spk(ecc.pubkey(k))
        txid, vout = self.node.fund_address(segwit_address("bcrt", spk), 10_000)
        full = payee.close_tx_with_fee_input(TxOut(10_000, spk), TxIn(bytes.fromhex(txid)[::-1], vout), k, spk,
                                             1_500, sig_a3)
        self.node.sendrawtransaction(full.hex())
        self.node.mine()
        v = self.values(full.txid())
        self.assertEqual(v[0], (CAP - cum, p.payer_spk))              # the committed output, exactly as signed
        self.assertEqual(v[1], (cum - FEE, p.payee_spk))

    def test_3_rollover(self):
        p, a, payee = self.channel()
        amount = 9_000
        nxt = ChannelParams.derive(ecc.pubkey(7).hex(), ecc.pubkey(a).hex(), self.node.height + 900, FEE,
                                   network=self.net, close_fee_payer="payee")
        cap2 = p.rollover_next_capacity(amount)
        tx = p.rollover_tx(amount, nxt.spk, cap2)
        from xbt402.channel import SIGHASH_ALL_UNIFIED
        z = p.sighash(tx)
        tx.inputs[0].witness = [ecc.sign(a, z) + bytes([SIGHASH_ALL_UNIFIED]),
                                ecc.sign(payee.secret, z) + bytes([SIGHASH_ALL_UNIFIED]), b"\x01", p.script]
        self.node.sendrawtransaction(tx.hex())
        self.node.mine()
        self.assertEqual(self.values(tx.txid()), [(amount - FEE, p.payee_spk), (CAP - amount, nxt.spk.hex())])

    def test_4_conditional_close_and_claim(self):
        p, a, payee = self.channel()
        k = sha256(b"agp023 conditional k")
        cp = ConditionalParams(p, sha256(k), 2_000, 10)
        uncond = DUST + FEE + 1_000
        tx = cp.state_tx(uncond)
        from xbt402.channel import SIGHASH_ALL_UNIFIED
        z = cp.sighash(tx)
        tx.inputs[0].witness = [ecc.sign(a, z) + bytes([SIGHASH_ALL_UNIFIED]),
                                ecc.sign(payee.secret, z) + bytes([SIGHASH_ALL_UNIFIED]), b"\x01", p.script]
        self.node.sendrawtransaction(tx.hex())
        claim = cp.claim_tx(tx.txid(), 1, k, payee.secret, bytes.fromhex(p.payee_spk), 300)
        self.node.sendrawtransaction(claim.hex())
        self.node.mine()
        self.assertEqual(self.values(tx.txid()), [(uncond - FEE, p.payee_spk), (2_000, cp.spk.hex()),
                                                  (CAP - uncond - 2_000, p.payer_spk)])
        self.assertEqual(self.values(claim.txid()), [(1_700, p.payee_spk)])

    def test_5_routed_ch2_close_pays_the_provider_net(self):
        node, net = self.node, R.Net()
        node.tc = self
        h = R.hub(node, net, secret=int.from_bytes(os.urandom(16), "big"))
        prov = R.provider(node, net, "http://p.test", amsat_per_call=40 * AMSAT_PER_SAT)
        h.connect("http://p.test", capacity=30_000)
        h.watch_tick()
        oc = h.out.chans["http://p.test"]
        self.assertEqual((oc.state, oc.p().close_fee_payer), ("open", "payee"))
        pay = R.payer(node, net)
        pay.open()
        sh = pay.shard("http://p.test/v1/chunk")
        R.stream(pay, sh, 40)
        self.assertEqual(pay.lock(sh)["status"], "paid")
        c2 = h.close_ch2(oc)
        node.mine()
        st2 = next(s for s in prov.ledger.channels.values() if s.closed_txid == c2["txid"])
        self.assertEqual(self.values(c2["txid"]), [(st2.best_cum - FEE, st2.params.payee_spk),
                                                   (30_000 - st2.best_cum, st2.params.payer_spk)])


if __name__ == "__main__":
    unittest.main()
