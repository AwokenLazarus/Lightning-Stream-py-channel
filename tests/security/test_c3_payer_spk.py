"""C3 (Critical) fee griefing at close: an unchecked payerSpk makes every close invalid.

`payerSpk` from the open request goes into every state's change output unchecked. A 35-byte (or
any non-standard) script makes the close non-standard (`bare-pubkey`) and, under RDTS,
consensus-invalid (`bad-txns-vout-script-toolarge`, regtest_confirm.py F3). The provider serves
up to capacity - closeFee - 546 on states it can never settle, and the payer refunds at expiry.
With v1's watcher (H1) the failing close also stops every other channel from closing.
"""
import unittest

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests

SPK35 = "21" + "02" + "11" * 32 + "ac"        # P2PK, 35 bytes: over the RDTS 34-byte output cap


class PayerSpk(Repro, unittest.TestCase):
    def test_repro_provider_opens_and_serves_with_oversized_payer_spk(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p, payer = make_channel(ch, prov, node, payer_spk=SPK35)
        st = pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()})[0]
        close = prov._payee(prov.ledger.channels[p.channel_id]).close_tx()
        self.reproduces(st == 200 and len(close.outputs[1].script_pubkey) == 35,
                        "served on a channel whose every close carries a 35-byte output (invalid under RDTS)")

    def test_fixed_only_segwit_payouts(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        for spk in (SPK35, "6a", "51", "0014" + "11" * 19, "5120" + "11" * 31, "zz", "0020" + "11" * 33):
            with self.assertRaises(cp.ChannelError) as e:
                make_channel(cp, prov, node, payer_spk=spk)
            self.assertEqual(e.exception.code, "bad_payer_spk", spk)
        for spk in ("0014" + "11" * 20, "0020" + "22" * 32, "5120" + "33" * 32, "0014" + "AA" * 20):
            p, payer = make_channel(cp, prov, node, payer_spk=spk)
            pl = authed(xp, cp, payer, p.payee_pub,
                        {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()})
            self.assertEqual(pay(xp, prov, pl)[0], 200, spk)


if __name__ == "__main__":
    unittest.main()
