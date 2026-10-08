"""M2 (Medium) payTo key-derivation misuse.

P = payTo + t*G with t = H(payTo || A || expiry) is non-hardened, like BIP32 public derivation:
t is public, so ANY one per-channel secret p gives the master payTo_secret = p - t, and with it
every other channel's key. Per-channel secrets must never leave the signer (no export to a closing
service, watchtower or log). Also, t does not commit to the network, so a payTo reused on regtest,
testnet and mainnet derives the same channel key for the same (A, expiry).

Fixed in v1.1 (AGP-004), the cross-network half only: t = H("xbt-channel/payee/v2", len8(NET) || NET ||
payTo || A || LE32(expiry)) with NET the CAIP-2 network string, advertised as extra.derivation "v2". A
v1.0-derived redeemScript no longer matches and its open is refused. The non-hardened half stays by
design (one-round-trip open): per-channel secrets must still never leave the provider.
"""
import os
import unittest

from sechelp import FakeNode, Repro, base, load, make_provider
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


MAINNET = "bip122:0000000000000050c1e5f69672f45929"
TESTNET = "bip122:" + "22" * 16
REGTEST = "bip122:" + "11" * 16          # sechelp.make_provider's network


class PayToDerivationV11(unittest.TestCase):
    def setUp(self):
        self.cp, self.xp, self.e = load("channel"), load("x402_channel"), load("ecc")

    def test_fixed_cross_network_keys_differ(self):
        cp, e = self.cp, self.e
        pay_to, a = e.pubkey(PAYTO), e.pubkey(0xA1)
        keys = {n: cp.channel_payee_pub(n, pay_to, a, 5000) for n in (REGTEST, TESTNET, MAINNET)}
        self.assertEqual(len(set(keys.values())), 3, "same payTo, A, expiry on three networks -> three keys")
        for n, key in keys.items():                        # and each network's secret matches its key
            self.assertEqual(e.pubkey(cp.channel_payee_secret(n, PAYTO, a, 5000)), key)
        v10 = base("channel").channel_payee_pub(pay_to, a, 5000)
        self.assertNotIn(v10, keys.values(), "no network's v1.1 key equals the v1.0 key")
        params = {n: cp.ChannelParams.derive(pay_to.hex(), a.hex(), 5000, 600, network=n) for n in keys}
        self.assertEqual(len({p.spk for p in params.values()}), 3, "so three funding addresses")

    def test_fixed_tweak_preimage_is_length_prefixed(self):
        cp, e = self.cp, self.e
        pre = cp.payee_tweak_preimage(MAINNET, e.pubkey(PAYTO), e.pubkey(0xA1), 5000)
        self.assertEqual(pre[0], len(MAINNET))
        self.assertEqual(pre[1:1 + len(MAINNET)], MAINNET.encode())
        self.assertEqual(pre[-4:], (5000).to_bytes(4, "little"))
        for bad in ("", "x" * 256, None):
            with self.assertRaises(cp.ChannelError):
                cp.channel_payee_pub(bad, e.pubkey(PAYTO), e.pubkey(0xA1), 5000)

    def _open(self, prov, node, p):
        p.funding_txid, p.funding_vout, p.capacity = os.urandom(32).hex(), 0, 200_000
        node.add_funding(p)
        return prov.open({"x402Version": 2, "network": prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})

    def test_fixed_v10_derived_key_refused_by_v11_provider(self):
        node = FakeNode()
        prov = make_provider(self.xp, node)
        a, expiry = self.e.pubkey(0xA1).hex(), node.height + 2000
        v10 = base("channel").ChannelParams.derive(prov.pay_to, a, expiry, prov.close_fee)
        with self.assertRaises(self.cp.ChannelError) as err:
            self._open(prov, node, v10)
        self.assertEqual(err.exception.code, "bad_funding")
        other = self.cp.ChannelParams.derive(prov.pay_to, a, expiry, prov.close_fee, network=MAINNET)
        with self.assertRaises(self.cp.ChannelError) as err:     # v1.1, but derived for another network
            self._open(prov, node, other)
        self.assertEqual(err.exception.code, "bad_funding")
        self.assertEqual(prov.ledger.channels, {})
        ok = self.cp.ChannelParams.derive(prov.pay_to, a, expiry, prov.close_fee, network=prov.network)
        self.assertEqual(self._open(prov, node, ok)["chan"], ok.channel_id)   # control

    def test_fixed_client_refuses_other_derivations_before_funding(self):
        prov = make_provider(self.xp, FakeNode())
        self.assertEqual(prov.requirements(150)["extra"]["derivation"], "v3")
        funded = []
        c = self.xp.XbtChannelClient(prov.network, lambda addr, sats: funded.append(addr), lambda: 1000)
        for derivation in (None, "v1", "v2"):
            acc = prov.requirements(150)
            acc["extra"].pop("derivation")
            if derivation:
                acc["extra"]["derivation"] = derivation
            with self.assertRaises(self.cp.ChannelError) as err:
                c._pick({"accepts": [acc]})
            self.assertEqual(err.exception.code, "bad_offer")
        self.assertEqual(funded, [])


if __name__ == "__main__":
    unittest.main()
