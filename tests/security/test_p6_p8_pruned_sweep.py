"""Pruned nodes and the payee sweep (the mainnet test channel's readiness patches).

P6: a pruned node cannot run txindex, so `getrawtransaction` of a confirmed transaction fails there
("No such mempool transaction. Use -txindex or provide a block hash"). The funding check read the
funding with it, so no channel could ever open against a pruned node once the funding confirmed.
It now reads the output with `gettxout`, which answers for any unspent output (and says whether it
is a coinbase), and a funding output that is already spent is refused. CPFP from a close uses the
provider's own record of the close instead of looking it up.

P8: nothing could move the payee output of a close, P2WPKH(P) with p = payTo_secret + t. The CPFP
child pays back to the same key. `sweep_payee` spends it to a witness v0 destination, signed 0x21,
without ever returning or storing p, and it is idempotent.
"""
import json
import os
import unittest

from sechelp import FakeNode, make_channel, make_provider
from xbt402 import channel as ch
from xbt402 import ecc
from xbt402 import x402_channel as xc
from xbt402.channel import ChannelError, channel_payee_secret
from xbt402.tx import (HRP, SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxOut, address_to_spk,
                       p2wpkh_script_code, segwit_address, unified_sighash)

A = 0xA11CE
DEST = bytes.fromhex("0014" + "77" * 20)


class PrunedNode(FakeNode):
    """No txindex: getrawtransaction only finds mempool transactions (0 confirmations)."""

    def getrawtransaction(self, txid, verbose=True):
        tx = self.txs.get(txid.lower())
        if not tx or tx["confirmations"] > 0:
            raise RuntimeError("No such mempool transaction. Use -txindex or provide a block hash "
                               "to enable blockchain transaction queries.")
        return tx

    def confirm_all(self):
        for t in self.txs.values():
            t["confirmations"] = max(1, t["confirmations"])


def closed_channel(node, cum=5_000, capacity=10_000):
    prov = make_provider(xc, node)
    prov.policy.min_capacity = 0
    p, payer = make_channel(ch, prov, node, a=A, capacity=capacity, expiry_in=1_014)
    st = prov._channel(p.channel_id)
    prov._apply(st, {"cum": cum, "sig": payer.sign_state(cum).hex()})
    r = prov.close({"chan": p.channel_id, "sig": ecc.sign(A, xc.close_message(p.channel_id)).hex()})
    return prov, p, r["txid"]


class PrunedFunding(unittest.TestCase):
    def test_open_on_a_pruned_node_reads_the_funding_with_gettxout(self):
        node = PrunedNode()
        prov = make_provider(xc, node)
        p, _ = make_channel(ch, prov, node, a=A, capacity=200_000, confs=3)
        with self.assertRaises(RuntimeError):
            node.getrawtransaction(p.funding_txid)                    # what the old check called
        self.assertIn(p.channel_id, prov.ledger.channels)

    def test_spent_funding_output_is_refused(self):
        node = PrunedNode()
        prov = make_provider(xc, node)
        p = ch.ChannelParams.derive(prov.pay_to, ecc.pubkey(A).hex(), node.height + 2000, prov.close_fee, "",
                                    network=prov.network)
        p.funding_txid, p.funding_vout, p.capacity = os.urandom(32).hex(), 0, 200_000
        node.add_funding(p)
        node.spent.add((p.funding_txid, 0))
        with self.assertRaises(ChannelError) as cm:
            prov.open({"x402Version": 2, "network": prov.network, "channel": {
                "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
                "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.assertEqual(cm.exception.code, "unknown_funding")

    def test_coinbase_funding_is_still_refused(self):
        node = PrunedNode()
        prov = make_provider(xc, node)
        p = ch.ChannelParams.derive(prov.pay_to, ecc.pubkey(A).hex(), node.height + 2000, prov.close_fee, "",
                                    network=prov.network)
        p.funding_txid, p.funding_vout, p.capacity = os.urandom(32).hex(), 0, 200_000
        node.add_funding(p, coinbase=True)
        with self.assertRaises(ChannelError) as cm:
            prov.open({"x402Version": 2, "network": prov.network, "channel": {
                "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
                "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.assertEqual(cm.exception.code, "coinbase_funding")

    def test_cpfp_after_the_close_confirmed_needs_no_txindex(self):
        node = PrunedNode()
        prov, p, close_txid = closed_channel(node)
        node.confirm_all()
        child = Tx.parse(bytes.fromhex(node.sent[-1])) if prov.cpfp(close_txid, 300) else None
        self.assertEqual(child.inputs[0].txid[::-1].hex(), close_txid)
        self.assertEqual(child.outputs[0].value, 5_000 - 300)


class PayeeSweep(unittest.TestCase):
    def setUp(self):
        self.node = PrunedNode()
        self.prov, self.p, self.close_txid = closed_channel(self.node)
        self.node.confirm_all()

    def test_sweep_spends_the_payee_output_to_the_destination_signed_0x21(self):
        r = self.prov.sweep_payee(self.p.channel_id, DEST, 300)
        tx = Tx.parse(bytes.fromhex(self.node.sent[-1]))
        self.assertEqual(r["txid"], tx.txid())
        self.assertEqual((r["value"], r["fee"], r["swept"]), (5_000, 300, 4_700))
        self.assertEqual(len(tx.inputs), 1)
        close = Tx.parse(bytes.fromhex(self.node.sent[0]))
        vout = tx.inputs[0].vout
        self.assertEqual(tx.inputs[0].txid[::-1].hex(), self.close_txid)
        self.assertEqual(close.outputs[vout].script_pubkey.hex(), self.p.payee_spk)
        self.assertEqual([(o.script_pubkey, o.value) for o in tx.outputs], [(DEST, 4_700)])
        sig, pub = tx.inputs[0].witness
        self.assertEqual(sig[-1], SIGHASH_ALL_UNIFIED)
        self.assertEqual(pub.hex(), self.p.payee_pub)
        prev = [TxOut(5_000, bytes.fromhex(self.p.payee_spk))]
        h = unified_sighash(tx, prev, 0, ST_WITNESS_V0, p2wpkh_script_code(pub), SIGHASH_ALL_UNIFIED)
        self.assertTrue(ecc.verify(pub, h, sig[:-1]))

    def test_the_channel_secret_is_never_returned_or_stored(self):
        r = self.prov.sweep_payee(self.p.channel_id, DEST, 300)
        secret = channel_payee_secret(self.prov.network, self.prov.secret, bytes.fromhex(self.p.payer_pub),
                                      self.p.expiry)
        blob = json.dumps(r)
        for path in (self.prov.ledger.path, self.prov.ledger.path + "-wal"):
            if os.path.exists(path):
                with open(path, "rb") as f:
                    raw = f.read()
                blob += raw.hex() + raw.decode("latin-1")
        self.assertNotIn(f"{secret:064x}", blob)
        self.assertNotIn(f"{self.prov.secret:064x}", blob)

    def test_idempotent(self):
        first = self.prov.sweep_payee(self.p.channel_id, DEST, 300)
        again = self.prov.sweep_payee(self.p.channel_id, bytes.fromhex("0014" + "88" * 20), 500)
        self.assertTrue(again["already"])
        self.assertEqual(again["txid"], first["txid"])
        self.assertEqual(sum(1 for hx in self.node.sent if Tx.parse(bytes.fromhex(hx)).txid() == first["txid"]), 1)

    def test_refusals(self):
        with self.assertRaises(ChannelError) as cm:          # P2TR is not a v0 destination
            self.prov.sweep_payee(self.p.channel_id, bytes.fromhex("5120" + "99" * 32), 300)
        self.assertEqual(cm.exception.code, "bad_dest")
        with self.assertRaises(ChannelError) as cm:
            self.prov.sweep_payee(self.p.channel_id, DEST, 5_000 - 500)
        self.assertEqual(cm.exception.code, "bad_amount")
        node = PrunedNode()
        prov = make_provider(xc, node)
        p, _ = make_channel(ch, prov, node, a=A)
        with self.assertRaises(ChannelError) as cm:
            prov.sweep_payee(p.channel_id, DEST, 300)
        self.assertEqual(cm.exception.code, "not_closed")

    def test_an_output_already_spent_is_not_swept_again(self):
        vout = next(n for n, o in enumerate(Tx.parse(bytes.fromhex(self.node.sent[0])).outputs)
                    if o.script_pubkey.hex() == self.p.payee_spk)
        self.node.spent.add((self.close_txid, vout))
        with self.assertRaises(ChannelError) as cm:
            self.prov.sweep_payee(self.p.channel_id, DEST, 300)
        self.assertEqual(cm.exception.code, "payee_spent")


class AddressNetwork(unittest.TestCase):
    def test_hrp_is_checked_when_given(self):
        spk = bytes.fromhex("0014" + "55" * 20)
        self.assertEqual(address_to_spk(segwit_address("bc", spk), HRP["main"]), spk)
        self.assertEqual(address_to_spk(segwit_address("bcrt", spk), HRP["regtest"]), spk)
        with self.assertRaises(ValueError):
            address_to_spk(segwit_address("bcrt", spk), HRP["main"])
        with self.assertRaises(ValueError):
            address_to_spk(segwit_address("bc", spk), HRP["regtest"])
        self.assertEqual(address_to_spk(segwit_address("bcrt", spk)), spk)     # no hrp: any network


if __name__ == "__main__":
    unittest.main()
