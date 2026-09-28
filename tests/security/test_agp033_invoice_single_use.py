"""AGP-033: a RoutePayer invoice is single-use (race found by the Rust port, AGP-026).

A lock can complete while the client still holds a ROUTE-STATE from before it, carrying the same
invoice. Locking that paid invoice again is answered from the hub's route_done with the saved
secret. A floor lock (cum <= signed) checks only t·G == T, so it counts d + f twice. The client
and hub routed totals then diverge (B1 harness: client 10 vs hub 7) and later locks void with
bad_amount. Resync does not apply: nothing was given up.

The Rust port fixed it with ShardState.last_locked (xbt-rs agp-026
a_paid_invoice_is_never_locked_again_even_a_floor_lock). B1 mirrors that: never lock an invoice
that already has a completed lock.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402.route import AMSAT_PER_SAT  # noqa: E402


class PaidInvoiceSingleUse(unittest.TestCase):
    def setUp(self):
        self.node, self.net, self.hub, self.provs, self.pay, self.shards = R.world(1)
        self.origin = next(iter(self.provs))
        self.sh = self.shards[self.origin]

    def st1(self):
        return self.hub.inbound.ledger.channels[self.pay.chan]

    def test_a_paid_invoice_is_never_locked_again_even_a_floor_lock(self):
        # same sequence AGP-026 used on unfixed B1: stream 10, lock (client 5 / hub 5), stream 4,
        # lock (client 7 / hub 7, one of them a floor lock), then the stale paid invoice + 3 sat more
        R.stream(self.pay, self.sh, 10)
        r1 = self.pay.lock(self.sh)
        self.assertEqual(r1["status"], "paid", r1)
        self.assertEqual((self.pay.routed, self.st1().extra["routed_sat"]), (5, 5))

        R.stream(self.pay, self.sh, 4)
        old_inv = dict(self.sh.invoice)
        r2 = self.pay.lock(self.sh)
        self.assertEqual(r2["status"], "paid", r2)
        self.assertEqual((self.pay.routed, self.st1().extra["routed_sat"]), (7, 7))
        self.assertEqual(self.pay.stats["floor_locks"], 1)
        self.assertEqual(self.sh.last_locked, r2["lockId"])

        self.sh.invoice = old_inv
        self.sh.accrued_amsat += 3 * AMSAT_PER_SAT
        self.assertIsNone(self.pay.lock(self.sh), "locked a paid invoice")
        self.assertEqual(self.pay.routed, 7)
        self.assertEqual(self.st1().extra["routed_sat"], 7)
        self.assertEqual(self.pay.signed, self.st1().best_cum)

        # a fresh ROUTE-STATE brings a new invoice and routing stays in step
        R.stream(self.pay, self.sh, 5)
        self.assertNotEqual(self.sh.invoice.get("lockId"), old_inv.get("lockId"))
        self.assertEqual(self.pay.lock(self.sh)["status"], "paid")
        self.assertEqual(self.pay.routed, self.st1().extra["routed_sat"])
        self.assertEqual(self.pay.signed, self.st1().best_cum)

    def test_pending_lock_holds_the_invoice_and_blocks_a_second(self):
        R.stream(self.pay, self.sh, 10)
        self.hub.withhold = "all"
        self.assertEqual(self.pay.lock(self.sh)["status"], "pending")
        stuck_id = self.pay.pending["lockId"]
        self.sh.accrued_amsat += 3 * AMSAT_PER_SAT
        self.assertIsNone(self.pay.lock(self.sh), "a second lock while one is pending")
        self.assertEqual(self.pay.pending["lockId"], stuck_id)
        self.assertEqual(self.pay.routed, 0)
        self.assertFalse((self.st1().extra or {}).get("route_done"))


if __name__ == "__main__":
    unittest.main()
