"""AGP-087: a test of the second closure audit of the external review, on the provider's kept close
intents. xbt-rs has the same test (crates/xbt402-interop/tests/agp087_hub_a.rs).

A test named `test_hole_*` FAILS on master 21b21db: it shows a hole.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import test_agp084_errored_spend as L  # noqa: E402  (errored_spend, down, code_of)

from xbt402.x402_channel import MAX_KEPT_INTENTS  # noqa: E402


class CloseIntents(unittest.TestCase):
    def test_hole_unresolved_close_intents_are_not_bounded_for_closes_at_rising_amounts(self):
        # AGP-085 bounds the kept intents by refusing the 9th ROLLOVER. A close is never refused, and a
        # close whose payload raises the state by one sat is another transaction: each one the node
        # errors on is kept, so the payer grows the provider's ledger (and the watcher's work per tick)
        # by one signed transaction per sat while the node refuses broadcasts.
        r, _ = L.errored_spend(False)
        L.down(r.node, True)
        best = r.st.best_cum
        codes = [L.code_of(r.cl.close, L.O, cum=best + i) for i in range(1, 13)]
        L.down(r.node, False)
        kept = len(r.st.extra.get("close_intents") or [])
        self.assertFalse(r.st.closed_txid)
        self.assertEqual(set(codes), {"close_failed"}, codes)
        self.assertLessEqual(kept, MAX_KEPT_INTENTS,
                             f"{kept} unresolved spends are kept beside the latest after 12 closes one sat apart (bound {MAX_KEPT_INTENTS})")


if __name__ == "__main__":
    unittest.main()
