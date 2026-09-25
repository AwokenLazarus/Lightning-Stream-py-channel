"""H2 (High) a reorg of the funding.

v1 credits the whole capacity at minConf = 1 and never looks at the funding again. If the funding
block is reorged out and its inputs double-spent, the provider keeps serving on a channel that no
longer exists, and its close is refused (regtest_confirm.py F4: `bad-txns-inputs-missingorspent`).
XBT's hashrate is small next to BTC's, and an attacker can open many max-capacity channels in the
block it plans to orphan.
"""
import unittest

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests


class FundingReorg(Repro, unittest.TestCase):
    def test_repro_serves_after_funding_vanishes(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p, payer = make_channel(ch, prov, node, confs=1)
        node.reorg_out(p.funding_txid)
        prov.close_due()                                   # even a watcher tick does not notice
        st = pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()})[0]
        self.reproduces(st == 200, "served 20,000 sat of calls on a funding that is no longer on the chain")

    def test_fixed_watcher_suspends_reorged_channel(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        p, payer = make_channel(cp, prov, node, confs=1)
        pl = lambda seq, cum: authed(xp, cp, payer, p.payee_pub, {  # noqa: E731
            "chan": p.channel_id, "seq": seq, "cum": str(cum), "sig": payer.sign_state(cum).hex()})
        self.assertEqual(pay(xp, prov, pl(1, 1000))[0], 200)
        node.reorg_out(p.funding_txid)
        prov.close_due()
        self.assertEqual(pay(xp, prov, pl(2, 2000))[1], "unconfirmed")
        node.add_funding(p, confirmations=1)               # mined again: service resumes
        prov.close_due()
        self.assertEqual(pay(xp, prov, pl(3, 3000))[0], 200)

    def test_fixed_large_channels_need_more_confirmations(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        with self.assertRaises(cp.ChannelError) as e:
            make_channel(cp, prov, node, capacity=2_000_000, confs=1)
        self.assertEqual(e.exception.code, "unconfirmed")
        make_channel(cp, prov, node, capacity=2_000_000, confs=3)


if __name__ == "__main__":
    unittest.main()
