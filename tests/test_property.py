"""Property: on-chain payee total is never above the signed max, never below served-minus-one-call."""
import random
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelParams, Payee, Payer
from xbt402.tx import p2wpkh_spk

PRICE = 150


def params(capacity=200_000):
    return ChannelParams(
        payer_pub=ecc.pubkey(0x1111).hex(), payee_pub=ecc.pubkey(0x2222).hex(), expiry=5000,
        payer_spk=p2wpkh_spk(ecc.pubkey(0x1111)).hex(), payee_spk=p2wpkh_spk(ecc.pubkey(0x2222)).hex(),
        close_fee=600, funding_txid="ab" * 32, funding_vout=0, capacity=capacity)


class PropertyTest(unittest.TestCase):
    def test_random_call_sequences(self):
        rng = random.Random(402)
        for _ in range(40):
            p = params()
            payer, payee = Payer(p, 0x1111), Payee(p, 0x2222)
            served = 0
            billing = rng.choice(["postpay", "prepay"])
            n = rng.randint(1, 80)
            for i in range(n):
                if billing == "prepay":
                    need = (served + 1) * PRICE
                else:
                    need = served * PRICE
                if need < 546:
                    need = 546
                if need > p.max_amount:
                    break
                if need > payer.signed:
                    payee.accept(need, payer.sign_state(need))
                served += 1
            if payee.best_amount == 0:
                continue
            on_chain = payee.close_tx().outputs[0].value
            signed_max = payer.signed
            served_minus_one = max(0, (served - 1) * PRICE)
            self.assertLessEqual(on_chain, signed_max)
            self.assertGreaterEqual(on_chain, min(served_minus_one, signed_max) if served_minus_one >= 546 else 0)
            self.assertLessEqual(on_chain, p.max_amount)


if __name__ == "__main__":
    unittest.main()
