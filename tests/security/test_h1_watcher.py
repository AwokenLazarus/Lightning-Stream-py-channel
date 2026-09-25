"""H1 (High) watcher failure.

Wave 2's (and v1's) close_due() loops over every channel and lets the first broadcast error escape, so one channel
whose close the node refuses (C1, C3, a reorged funding, a node hiccup) stops the provider from
closing every channel after it. Past expiry each of those payers can take back all it paid. Wave 2
added a Watcher thread that survives the exception, but it silently retries the same failing channel
first on every tick, so the rest still never close. A close is also recorded as done once
sendrawtransaction returns and never looked at again (an evicted close is never resent).
"""
import unittest

from sechelp import FakeNode, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests


def two_due_channels(xm, cm, node, prov, auth=False):
    out = []
    for i, a in enumerate((0xA1, 0xA2)):
        p, payer = make_channel(cm, prov, node, a=a, txid=f"{i + 1:02x}" * 32)
        pl = {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": payer.sign_state(20_000).hex()}
        if auth:
            pl = authed(xm, cm, payer, p.payee_pub, pl)
        assert pay(xm, prov, pl)[0] == 200
        out.append(p)
    node.height = out[0].expiry - 100               # inside closeMarginBlocks (144): both are due
    node.fail[bytes.fromhex(out[0].funding_txid)[::-1].hex()] = "bad-txns-vout-script-toolarge"
    return out


class Watcher(Repro, unittest.TestCase):
    def test_repro_one_bad_close_blocks_all_others(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p1, p2 = two_due_channels(xc, ch, node, prov)
        try:
            prov.close_due()
            raised = False
        except Exception:  # noqa: BLE001
            raised = True
        self.reproduces(raised and not node.sent and not prov.ledger.channels[p2.channel_id].closed_txid,
                        "close_due() died on channel 1; channel 2 was never closed")

    def test_repro_watcher_thread_retries_the_same_failure_forever(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p1, p2 = two_due_channels(xc, ch, node, prov)
        w = base("watcher").Watcher(prov)
        for _ in range(5):                       # five ticks of wave 2's Watcher loop body
            try:
                w.tick()
            except Exception:  # noqa: BLE001 - _loop swallows it silently
                pass
        self.reproduces(not node.sent and not prov.ledger.channels[p2.channel_id].closed_txid,
                        "wave 2's Watcher survives, but every tick dies on channel 1: channel 2 never closes")

    def test_fixed_isolates_failures_and_retries(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        p1, p2 = two_due_channels(xp, cp, node, prov, auth=True)
        closed = prov.close_due()
        self.assertEqual(len(closed), 1)
        self.assertTrue(prov.ledger.channels[p2.channel_id].closed_txid)
        self.assertIn("close_failed", prov.ledger.channels[p1.channel_id].close_error)
        node.fail.clear()                              # e.g. the node recovered
        self.assertEqual(len(prov.close_due()), 1)
        self.assertEqual(prov.ledger.channels[p1.channel_id].close_error, "")

    def test_fixed_watcher_thread_closes_the_rest(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        p1, p2 = two_due_channels(xp, cp, node, prov, auth=True)
        load("watcher").Watcher(prov).tick()
        self.assertTrue(prov.ledger.channels[p2.channel_id].closed_txid)
        self.assertTrue(hasattr(prov, "watch"))

    def test_fixed_rebroadcasts_an_evicted_close(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        p1, p2 = two_due_channels(xp, cp, node, prov, auth=True)
        prov.close_due()
        sent = len(node.sent)
        prov.close_due()
        self.assertEqual(len(node.sent), sent)         # close still in the mempool: nothing to do
        node.spent.clear()                             # the close was evicted: the funding is unspent again
        prov.close_due()
        self.assertEqual(len(node.sent), sent + 1)


if __name__ == "__main__":
    unittest.main()
