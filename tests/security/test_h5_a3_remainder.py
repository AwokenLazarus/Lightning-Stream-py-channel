"""H5 (High) the 0xA3 fee-input state gives the payee the payer's whole remainder.

Wave 2 added the v1.1 fee-input variant: the payer signs SIGHASH_SINGLE|ANYONECANPAY|UNIFIED (0xA3)
over a state whose only output is the payee's `amount`. SINGLE commits to output 0 alone, so the
payer's signature says nothing about where the rest of the capacity goes: the payee adds an output
paying itself `capacity - amount - fee` and the payer's signature still verifies. (Wave 2's own
test completes it with the remainder as miner fee: 98,500 of 100,000 sat.) The x402 flow never asks
for an 0xA3 state, but ChannelSigner.sign_state_a3 (and B2's `xbt402_sign_state_a3`) sign one for
any caller, and the policy hook sees only `amount`: a budget of 2,000 sat signs away the channel.
Fixed: output 0 of an 0xA3 state is the payer's change, which SINGLE then commits to.
"""
import unittest

from sechelp import Repro, base, load
ch, ecc = base("channel"), base("ecc")   # unpatched wave 2: the repro tests

A, P = 0x1111, 0x2222


def params(cm, e, capacity=100_000):
    tx = cm.p2wpkh_spk
    return cm.ChannelParams(payer_pub=e.pubkey(A).hex(), payee_pub=e.pubkey(P).hex(), expiry=1000,
                            payer_spk=tx(e.pubkey(A)).hex(), payee_spk=tx(e.pubkey(P)).hex(), close_fee=380,
                            funding_txid="ab" * 32, funding_vout=1, capacity=capacity)


def payer_sig_still_valid(cm, e, p, sig, tx, extra_prevouts=()):
    h = cm.unified_sighash(tx, [p.funding_prevout(), *extra_prevouts], 0, cm.ST_WITNESS_V0, p.script, cm.SIGHASH_SINGLE_ACP_UNIFIED)
    return e.verify(bytes.fromhex(p.payer_pub), h, sig[:-1])


class A3Remainder(Repro, unittest.TestCase):
    def test_repro_payee_takes_the_remainder(self):
        p = params(ch, ecc)
        sig = ch.Payer(p, A).sign_state_a3(2000)                       # "pay 2,000 sat"
        tx = p.state_tx_a3(2000)
        tx.outputs.append(ch.TxOut(p.capacity - 2000 - 300, bytes.fromhex(p.payee_spk)))
        took = sum(o.value for o in tx.outputs if o.script_pubkey.hex() == p.payee_spk)
        self.reproduces(payer_sig_still_valid(ch, ecc, p, sig, tx) and took == p.capacity - 300,
                        f"payer signed 0xA3 for 2,000 sat; the payee's completion takes {took} of {p.capacity}")

    def test_repro_signer_policy_sees_only_amount(self):
        seen = []
        s = base("signer").ChannelSigner(policy=lambda origin, sats: seen.append(sats))
        p = params(ch, ecc)
        s._secrets[p.channel_id], s._params[p.channel_id], s._signed[p.channel_id] = A, p, 50_000
        s.sign_state_a3(p.channel_id, 2000)
        self.reproduces(seen == [2000], "the signer approved an 0xA3 state below its signed 50,000 with policy seeing 2,000")

    def test_fixed_payer_change_is_committed(self):
        cm, e = load("channel"), load("ecc")
        p = params(cm, e)
        sig = cm.Payer(p, A).sign_state_a3(2000)
        tx = p.state_tx_a3(2000)
        self.assertEqual((tx.outputs[0].value, tx.outputs[0].script_pubkey.hex()), (p.capacity - 380 - 2000, p.payer_spk))
        stolen = p.state_tx_a3(2000)
        stolen.outputs[0] = cm.TxOut(546, bytes.fromhex(p.payer_spk))
        stolen.outputs.append(cm.TxOut(p.capacity - 546 - 2000 - 300, bytes.fromhex(p.payee_spk)))
        self.assertFalse(payer_sig_still_valid(cm, e, p, sig, stolen))
        fee_bumped = p.state_tx_a3(2000)                                    # what 0xA3 is for
        fee_bumped.inputs.append(cm.TxIn(b"\xcd" * 32, 0))
        fee_bumped.outputs.append(cm.TxOut(9_000, bytes.fromhex(p.payee_spk)))
        self.assertTrue(payer_sig_still_valid(cm, e, p, sig, fee_bumped,
                                              [cm.TxOut(10_000, bytes.fromhex(p.payee_spk))]))
        with self.assertRaises(cm.ChannelError):                           # no change: no 0xA3 state
            cm.Payer(p, A).sign_state_a3(p.max_amount)

    def test_fixed_signer_is_monotonic_for_a3(self):
        cm, e = load("channel"), load("ecc")
        s = load("signer").ChannelSigner()
        p = params(cm, e)
        s._secrets[p.channel_id], s._params[p.channel_id], s._signed[p.channel_id] = A, p, 50_000
        with self.assertRaises(cm.ChannelError):
            s.sign_state_a3(p.channel_id, 2000)
        s.sign_state_a3(p.channel_id, 60_000)
        self.assertEqual(s._signed[p.channel_id], 60_000)


if __name__ == "__main__":
    unittest.main()
