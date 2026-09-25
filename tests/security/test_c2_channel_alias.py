"""C2 (Critical) state replay across channels: one outpoint, many channel ids.

The provider keys its ledger by the txid string the payer sends, and bitcoind resolves a txid in
any letter case (regtest_confirm.py F2). Opening the same funding as `abcd…:0` and `ABCD…:0` gives
two ledger rows, and one signed state is credited on each: the payer pays once, spends the credit
2 (up to 2^letters) times, and the payee can close only once.

Control (holds in v1): a state signature never replays onto a *different* outpoint, because
UnifiedSighash commits to the outpoint, amount and scriptPubKey.
"""
import unittest

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests

TXID = "ab" * 32


class ChannelAlias(Repro, unittest.TestCase):
    def test_repro_one_outpoint_two_rows_one_payment_twice(self):
        node = FakeNode()
        prov = make_provider(xc, node, billing="prepay")
        p, payer = make_channel(ch, prov, node, txid=TXID, open_as=[TXID, TXID.upper()])
        sig = payer.sign_state(15_000).hex()
        served = 0
        for t in (TXID, TXID.upper()):
            for seq in range(1, 101):            # 100 prepaid calls = 15,000 sat of credit, per row
                served += pay(xc, prov, {"chan": f"{t}:0", "seq": seq, "cum": "15000", "sig": sig})[0] == 200
        self.reproduces(len(prov.ledger.channels) == 2 and served == 200,
                        f"{served} calls x 150 sat served on one 15,000-sat state (2 rows for 1 outpoint)")

    def test_fixed_one_row_per_outpoint(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node, billing="prepay")
        p, payer = make_channel(cp, prov, node, txid=TXID)
        with self.assertRaises(cp.ChannelError) as e:
            make_channel(cp, prov, node, txid=TXID, open_as=[TXID.upper()])
        self.assertEqual(e.exception.code, "duplicate_channel")
        sig = payer.sign_state(15_000).hex()
        served = 0
        for seq, t in enumerate([TXID] * 100 + [TXID.upper()] * 100, 1):
            pl = authed(xp, cp, payer, p.payee_pub, {"chan": f"{t}:0", "seq": seq, "cum": "15000", "sig": sig})
            pl["chan"] = f"{t}:0"
            served += pay(xp, prov, pl)[0] == 200
        self.assertEqual(served, 100)       # the credit is spent once, whatever the spelling
        self.assertEqual(list(prov.ledger.channels), [f"{TXID}:0"])

    def test_fixed_rejects_malformed_ids(self):
        cp = load("channel")
        for bad in ("ab" * 31 + ":0", "zz" * 32 + ":0", TXID, TXID + ":-1", TXID + ": 0", None, 5):
            with self.assertRaises(cp.ChannelError):
                cp.canonical_chan(bad)
        self.assertEqual(cp.canonical_chan(TXID.upper() + ":007"), TXID + ":7")

    def test_control_state_sig_does_not_replay_onto_another_outpoint(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p1, payer = make_channel(ch, prov, node, txid="01" * 32)
        p2 = ch.ChannelParams(**{**p1.to_dict(), "funding_txid": "02" * 32})
        node.add_funding(p2)
        prov.open({"network": prov.network, "channel": {"txid": p2.funding_txid, "vout": 0, "capacity": p2.capacity,
                   "expiry": p2.expiry, "payerPub": p2.payer_pub, "redeemScript": p2.script.hex()}})
        sig = payer.sign_state(20_000).hex()
        self.assertEqual(pay(xc, prov, {"chan": p1.channel_id, "seq": 1, "cum": "20000", "sig": sig})[0], 200)
        self.assertEqual(pay(xc, prov, {"chan": p2.channel_id, "seq": 1, "cum": "20000", "sig": sig})[1], "bad_sig")


if __name__ == "__main__":
    unittest.main()
