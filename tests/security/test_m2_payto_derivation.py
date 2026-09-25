"""M2 (Medium) payTo key-derivation misuse.

P = payTo + t*G with t = H(payTo || A || expiry) is non-hardened, like BIP32 public derivation:
t is public, so ANY one per-channel secret p gives the master payTo_secret = p - t, and with it
every other channel's key. Per-channel secrets must never leave the signer (no export to a closing
service, watchtower or log). Also, t does not commit to the network, so a payTo reused on regtest,
testnet and mainnet derives the same channel key for the same (A, expiry).
"""
import unittest

from sechelp import Repro, base
ch, ecc = base("channel"), base("ecc")   # unpatched wave 2: the repro tests

PAYTO = 0xC0FFEE1234


class PayToDerivation(Repro, unittest.TestCase):
    def test_repro_one_channel_secret_reveals_the_master(self):
        pay_to = ecc.pubkey(PAYTO)
        a1, a2 = ecc.pubkey(0xA1), ecc.pubkey(0xA2)
        leaked = ch.channel_payee_secret(PAYTO, a1, 5000)                   # e.g. handed to a closer
        master = (leaked - ch._payee_tweak(pay_to, a1, 5000)) % ecc.N        # public data only
        other = ch.channel_payee_secret(master, a2, 7000)
        self.reproduces(master == PAYTO and ecc.pubkey(other) == ch.channel_payee_pub(pay_to, a2, 7000),
                        "one leaked channel secret -> payTo master secret -> every other channel key")

    def test_repro_channel_key_is_network_agnostic(self):
        p = ch.ChannelParams.derive(ecc.pubkey(PAYTO).hex(), ecc.pubkey(0xA1).hex(), 5000, 600)
        self.reproduces(p.payee_pub == ch.ChannelParams.derive(ecc.pubkey(PAYTO).hex(), ecc.pubkey(0xA1).hex(),
                                                               5000, 600).payee_pub,
                        "the tweak has no network: same payTo, A, expiry -> same P on every chain")

    def test_control_tweak_binds_payer_and_expiry(self):
        pay_to = ecc.pubkey(PAYTO)
        keys = {ch.channel_payee_pub(pay_to, ecc.pubkey(a), e) for a in (1, 2, 3) for e in (1000, 1001)}
        self.assertEqual(len(keys), 6)


if __name__ == "__main__":
    unittest.main()
