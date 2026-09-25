"""Offline channel rules: signatures, monotonic states, amount bounds, close/refund shape."""
import unittest

from xbt402 import ecc
from xbt402.channel import DUST, ChannelError, ChannelParams, Payee, Payer
from xbt402.tx import SIGHASH_ALL, Tx, p2wpkh_spk

PAYER, PAYEE = 0x1111, 0x2222


def params(capacity=100_000):
    return ChannelParams(
        payer_pub=ecc.pubkey(PAYER).hex(), payee_pub=ecc.pubkey(PAYEE).hex(), expiry=1000,
        payer_spk=p2wpkh_spk(ecc.pubkey(PAYER)).hex(), payee_spk=p2wpkh_spk(ecc.pubkey(PAYEE)).hex(),
        fee_rate=2, funding_txid="ab" * 32, funding_vout=1, capacity=capacity)


class ChannelTest(unittest.TestCase):
    def setUp(self):
        self.p = params()
        self.payer, self.payee = Payer(self.p, PAYER), Payee(self.p, PAYEE)

    def test_ecdsa_roundtrip(self):
        msg = bytes(range(32))
        sig = ecc.sign(PAYER, msg)
        self.assertTrue(ecc.verify(ecc.pubkey(PAYER), msg, sig))
        self.assertFalse(ecc.verify(ecc.pubkey(PAYEE), msg, sig))

    def test_pay_increments_and_close(self):
        for amt in (1000, 1250, 1500):
            self.assertEqual(self.payee.accept(amt, self.payer.sign_state(amt)), 250 if amt > 1000 else 1000)
        tx = self.payee.close_tx()
        self.assertEqual(tx.outputs[0].value, 1500)
        self.assertEqual(tx.outputs[1].value, 100_000 - 1500 - self.p.close_fee)
        self.assertEqual(len(tx.inputs[0].witness), 4)
        self.assertEqual(Tx.parse(bytes.fromhex(tx.hex())).txid(), tx.txid())

    def test_replayed_state_is_free_and_stale_rejected(self):
        s = self.payer.sign_state(2000)
        self.payee.accept(2000, s)
        self.assertEqual(self.payee.accept(2000, s), 0)
        old = Payer(self.p, PAYER).sign_state(1000)
        with self.assertRaises(ChannelError) as e:
            self.payee.accept(1000, old)
        self.assertEqual(e.exception.code, "stale_amount")

    def test_forged_amount_rejected(self):
        s = self.payer.sign_state(1000)
        with self.assertRaises(ChannelError) as e:
            self.payee.accept(5000, s)   # payee claims more than was signed
        self.assertEqual(e.exception.code, "bad_sig")

    def test_legacy_sighash_rejected(self):
        s = self.payer.sign_state(1000)[:-1] + bytes([SIGHASH_ALL])
        with self.assertRaises(ChannelError) as e:
            self.payee.accept(1000, s)
        self.assertEqual(e.exception.code, "bad_sighash")

    def test_bounds(self):
        with self.assertRaises(ChannelError):
            self.p.state_tx(DUST - 1)
        with self.assertRaises(ChannelError):
            self.p.state_tx(self.p.max_amount + 1)
        full = self.p.state_tx(self.p.max_amount)
        self.assertEqual(len(full.outputs), 1)          # no payer dust
        near = self.p.state_tx(self.p.max_amount - 100)
        self.assertEqual(len(near.outputs), 1)          # 100-sat remainder goes to fee

    def test_refund_locktime(self):
        r = self.p.refund_tx(PAYER)
        self.assertEqual(r.locktime, 1000)
        self.assertEqual(r.inputs[0].witness[1], b"")
        self.assertLess(r.inputs[0].sequence, 0xFFFFFFFF)

    def test_payer_never_signs_lower(self):
        self.payer.sign_state(3000)
        with self.assertRaises(ChannelError):
            self.payer.sign_state(2000)


if __name__ == "__main__":
    unittest.main()
