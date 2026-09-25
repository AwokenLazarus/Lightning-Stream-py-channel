"""M5 (Medium) per-call cost grows with the number of channels (verification/ledger DoS).

Wave 2 moved the ledger to SQLite, one row per channel, but Ledger.save() still upserts EVERY
row (and checkpoints the WAL) on every paid call, under the one global lock (which the open path also
holds across a node RPC). Paid calls are O(channels), not O(1). Channels cost an attacker only fees:
the capacity comes back by refund at expiry. So cheap 20,000-sat channels slow every other payer's
calls. Fixed: a call saves only its own row.
"""
import unittest

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests


def rows_written(prov, call):
    """INSERT/UPSERT statements the ledger runs during `call`."""
    n = [0]
    prov.ledger._db.set_trace_callback(lambda sql: n.__setitem__(0, n[0] + sql.lstrip().startswith("INSERT")))
    try:
        call()
    finally:
        prov.ledger._db.set_trace_callback(None)
    return n[0]


class LedgerCost(Repro, unittest.TestCase):
    def test_repro_every_call_rewrites_all_channels(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        for i in range(200):
            make_channel(ch, prov, node, a=0x100 + i, capacity=20_000)
        p, payer = make_channel(ch, prov, node, a=0xA1)
        n = rows_written(prov, lambda: pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "20000",
                                                       "sig": payer.sign_state(20_000).hex()}))
        self.reproduces(n >= 201, f"one paid call upserted {n} channel rows (201 channels)")

    def test_fixed_a_call_writes_its_own_row(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        for i in range(200):
            make_channel(cp, prov, node, a=0x100 + i, capacity=20_000)
        p, payer = make_channel(cp, prov, node, a=0xA1)
        pl = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": 1, "cum": "20000",
                                                 "sig": payer.sign_state(20_000).hex()})
        st = [None]
        n = rows_written(prov, lambda: st.__setitem__(0, pay(xp, prov, pl)[0]))
        self.assertEqual(st[0], 200)
        self.assertLessEqual(n, 2)
        self.assertEqual(xp.Ledger(prov.ledger.path).channels[p.channel_id].best_cum, 20_000)


if __name__ == "__main__":
    unittest.main()
