"""0xA3 fee-input variant and rollover tx shape."""
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelError, ChannelParams, Payee, Payer
from xbt402.tx import SIGHASH_SINGLE_ACP_UNIFIED, TxIn, TxOut, p2wpkh_spk, unified_sighash, ST_WITNESS_V0


def params(capacity=100_000):
    return ChannelParams(
        payer_pub=ecc.pubkey(0x1111).hex(), payee_pub=ecc.pubkey(0x2222).hex(), expiry=1000,
        payer_spk=p2wpkh_spk(ecc.pubkey(0x1111)).hex(), payee_spk=p2wpkh_spk(ecc.pubkey(0x2222)).hex(),
        close_fee=380, funding_txid="ab" * 32, funding_vout=1, capacity=capacity)


class A3Test(unittest.TestCase):
    def test_a3_sig_verifies_after_extra_input(self):
        p = params()
        payer, payee = Payer(p, 0x1111), Payee(p, 0x2222)
        sig = payer.sign_state_a3(2000)
        self.assertEqual(sig[-1], SIGHASH_SINGLE_ACP_UNIFIED)
        payee.best_amount, payee.best_sig = 2000, payer.sign_state(2000)
        extra_prev = TxOut(10_000, p2wpkh_spk(ecc.pubkey(0x3333)))
        extra_in = TxIn(b"\xcd" * 32, 0)
        tx = payee.close_tx_with_fee_input(extra_prev, extra_in, 0x3333,
                                           p2wpkh_spk(ecc.pubkey(0x3333)), 500, sig)
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual(tx.outputs[0].value, 2000)
        prevouts = [p.funding_prevout(), extra_prev]
        h = unified_sighash(tx, prevouts, 0, ST_WITNESS_V0, p.script, SIGHASH_SINGLE_ACP_UNIFIED)
        self.assertTrue(ecc.verify(bytes.fromhex(p.payer_pub), h, sig[:-1]))

    def test_rollover_shape(self):
        p = params()
        next_spk = p2wpkh_spk(ecc.pubkey(0x4444))
        tx = p.rollover_tx(3000, next_spk, 80_000)
        self.assertEqual(tx.outputs[0].value, 3000)
        self.assertEqual(tx.outputs[1].value, 80_000)
        self.assertEqual(tx.outputs[1].script_pubkey, next_spk)
        with self.assertRaises(ChannelError):
            p.rollover_tx(3000, next_spk, 200_000)


if __name__ == "__main__":
    unittest.main()
