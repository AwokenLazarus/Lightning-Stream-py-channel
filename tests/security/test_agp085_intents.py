"""AGP-085, item 7 (AGP-084's stated limit 2): a replaced intent was forgotten. `close` and `rollover`
write `close_intent`, then send. A rollover the node errored on, then a second spend the node errored
on too (the operator's close, the client's next rollover), then the first one reaches the chain: the
ledger held only the second, so the first was never recorded and the channel stayed open on the
books. Now the replaced ones are kept (`close_intents`) until the chain settles one of them. Same
names as xbt-rs crates/xbt402/tests/lifecycle.rs.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import test_agp084_hub_leftovers as L  # noqa: E402  (errored_spend, rollover_req, down, code_of)

from xbt402.x402_channel import MAX_KEPT_INTENTS  # noqa: E402


class ReplacedIntent(unittest.TestCase):
    def test_a_replaced_intent_is_still_recorded_when_it_confirms(self):
        for close in (True, False):
            with self.subTest(close=close):
                r, first = L.errored_spend(True)
                chan = r.st.params.channel_id
                L.down(r.node, True)
                code = L.code_of(r.prov.close_channel, chan) if close else L.code_of(r.prov.rollover, L.rollover_req(r, 750))
                self.assertEqual(code, "close_failed")
                L.down(r.node, False)
                self.assertNotEqual(r.st.extra["close_intent"]["txid"], first["txid"], "a second spend was signed")
                self.assertTrue(not r.st.closed_txid and not r.node.sent)
                r.node.sendrawtransaction(first["hex"])
                due = r.prov.close_due()
                self.assertEqual(r.st.closed_txid, first["txid"],
                                 f"the spend on the chain is the channel's close ({due}, {r.st.close_error!r})")
                self.assertEqual(r.st.extra.get("rollover_to"), f"{first['txid']}:1")
                self.assertEqual((due, len(r.node.sent)), ([first["txid"]], 1), "nothing else was sent")

    def test_unresolved_intents_are_bounded(self):
        # each failed rollover leaves one more signed spend to watch for: past the bound the provider
        # signs no further one (the client closes, or waits for the node)
        r, _ = L.errored_spend(True)
        L.down(r.node, True)
        codes = [L.code_of(r.prov.rollover, L.rollover_req(r, 750)) for _ in range(12)]
        L.down(r.node, False)
        self.assertEqual(codes[-1], "channel_closing", codes)
        # AGP-088: one slot short of the bound, kept for the payee's own close
        self.assertEqual((len(r.st.extra["close_intents"]), codes.count("close_failed")), (7, 7), codes)
        self.assertEqual(len({i["txid"] for i in r.st.extra["close_intents"]}), 7)
        # the close still goes through, and is the channel's close: the bound holds with it
        out = r.prov.close_channel(r.st.params.channel_id)
        self.assertEqual(r.st.closed_txid, out["txid"])
        self.assertEqual(len(r.st.extra["close_intents"]), MAX_KEPT_INTENTS)


if __name__ == "__main__":
    unittest.main()
