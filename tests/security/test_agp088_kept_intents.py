"""AGP-088 (fix wave 4): a test of the fix to the second closure audit's item on kept close intents,
one step beside the audit's own test (test_agp087_close_intents.py). xbt-rs has the same test
(crates/xbt402-interop/tests/agp088_hub.rs).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import test_agp084_errored_spend as L  # noqa: E402  (errored_spend, down, code_of)

from xbt402.x402_channel import MAX_KEPT_INTENTS  # noqa: E402


class Leftovers(unittest.TestCase):
    def test_once_the_kept_intents_are_full_no_request_moves_the_state(self):
        # The audit's closes one sat apart, then the two other ways a payer raises the state while the
        # node refuses broadcasts: /x402/verify, and the watcher's own close after it
        r, _ = L.errored_spend(False)
        L.down(r.node, True)
        for i in range(1, 13):
            L.code_of(r.cl.close, L.O, cum=r.st.best_cum + 1)
        kept = lambda: len(r.st.extra.get("close_intents") or [])  # noqa: E731
        self.assertEqual(kept(), MAX_KEPT_INTENTS - 1, "one slot is left for the payee's own close")
        best, latest = r.st.best_cum, r.st.extra["close_intent"]["txid"]
        acc = r.ch.accepted
        pl = {"chan": r.st.params.channel_id, "cum": str(best + 5), "sig": r.ch.payer.sign_state(best + 5).hex()}
        out = r.prov.facilitator_verify({"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": acc, "payload": pl},
                                         "paymentRequirements": acc})
        self.assertEqual((r.st.best_cum, out["isValid"]), (best, False), "/x402/verify raised the state under a full set of unresolved closes")
        for _ in range(3):
            try:
                r.prov.close_due()
            except Exception:  # noqa: BLE001 - the node is down
                pass
        self.assertEqual(kept(), MAX_KEPT_INTENTS - 1, "the watcher's close made another")
        L.down(r.node, False)
        self.assertEqual(r.prov.close_due(), [latest])
        self.assertEqual((r.st.closed_txid, r.st.best_cum), (latest, best))


if __name__ == "__main__":
    unittest.main()
