"""AGP-093, area HUB: tests of the third closure audit of the external review (fix wave 4, AGP-088).
xbt-rs has the same tests (crates/xbt402-interop/tests/agp093_hub.rs), and one more (the reorg of a
close one block deep: RouteNode cannot take a block back).

Tests named `test_hole_*` FAIL on 66684ce: each one shows a hole or a limit nobody wrote down. The
others pass and are the control of the hole beside them. The harness is test_agp088_hub.py's.
"""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402
import test_agp084_hub_leftovers as L  # noqa: E402
import test_agp088_hub as H  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402.route import HUB_ROUTE_PATH, HUB_VIEW_PATH  # noqa: E402

CLOSE_PATH = H.CLOSE_PATH


class W(H.W):
    def keeps_locks(self, i):
        """p`i` answers the hub's lock with a 400 after its inner provider completed it: it keeps the
        pre-signature and its t, and refuses the hub's close requests."""
        self.provs[i].refuse = self.provs[i].deaf = True

    def refused(self, i):
        r = self.lock(i)
        assert (r["status"], r.get("error")) == ("refused", "route_failed"), r

    def pay_until_paid(self, i):
        r = None
        for _ in range(4):
            R.stream(self.pay, self.shards[i], 10)
            r = self.pay.lock(self.shards[i])
            if r and r["status"] == "paid":
                break
        return r


def two_held_locks_on_two_ch2s_of_one_provider(tc, legacy):
    """Two written-off locks on one ch1 under one lockId, each over its own ch2 of the SAME provider
    (the ch2 the first lock blocks, and the next ch2 that replaced it). `legacy`: as a hub from before
    AGP-088 wrote them (no `ch2` on the ch1 locks; 21b21db admitted the second lock, it had no
    lock_held). Returns the world, the first ch2's record, the provider's state of it before the lock."""
    w = W([None], pkw={"held_probe_secs": 0.0})
    w.paid(0)
    o = w.origins[0]
    w.hub.connect_next(o)
    w.node.confirm_all()
    w.hub.watch_tick()
    tc.assertEqual(w.hub.out.next_chans[o].state, "open", "control: the next ch2 is open")
    a = w.oc(0)
    before = copy.deepcopy(w.st2(0))
    w.keeps_locks(0)
    w.refused(0)
    lid = w.stale1()[0]["lockId"]
    w.hub.watch_tick()                            # the provider that refused gets its next ch2
    tc.assertTrue(w.oc(0) is not a and w.oc(0).state == "open", "control: the next ch2 took over")
    w.refused(0)
    tc.assertEqual(len(w.oc(0).stale), 1, "control: the second lock is written off on the second ch2")
    st1 = w.st1()
    with w.hub.inbound.ledger.lock:
        st1.extra["stale_locks"][1]["lockId"] = lid
        if legacy:
            for s in st1.extra["stale_locks"]:
                s.pop("ch2", None)
        w.hub.inbound.ledger.save(st1)
    with w.hub.out.lock:
        w.oc(0).stale[0]["lockId"] = lid
        w.hub.out.save()
    stale = w.stale1()
    tc.assertTrue(len(stale) == 2 and all(s["lockId"] == lid and isinstance(s.get("hold"), dict) and s["provider"] == o for s in stale),
                  "control: one lockId, one provider, both held")
    tc.assertTrue(all(("ch2" not in s) == legacy for s in stale))
    tc.assertEqual(L.code_of(w.pay.close), "lock_pending", "control: ch1 cannot close below the two locks")
    return w, a, before


def first_ch2_closes_without_t(tc, w, a, before):
    """The provider closes its first ch2 at the state before the lock (no t) and that close confirms;
    then the client closes ch1 and the provider closes its second ch2 with the pre-signature it kept.
    (written-off locks left on ch1 after the first close, the ch1 close's refusal code or "", what ch1
    collected, the lock the second ch2 paid)."""
    prov = w.provs[0].inner
    with prov.ledger.lock:
        prov.ledger.channels[before.params.channel_id] = before
        prov.ledger.save(before)
    c0 = T.close_now(prov, before)
    w.hub.watch_tick()
    w.node.mine(1)
    tc.assertTrue(w.node.confirmed(c0))
    acts = w.hub.watch_tick() + w.hub.watch_tick()
    tc.assertTrue(any(x.get("event") == "lock_released" and x["held"] for x in acts), acts)
    left = len(w.stale1())
    tc.assertEqual(len(w.oc(0).stale), 1, "control: the second ch2 still holds its written-off lock, its pre-signature is out")
    lock = dict(w.oc(0).stale[0])
    code = L.code_of(w.pay.close)
    st_b = w.st2(0)
    T.close_now(prov, st_b)
    w.hub.watch_tick()
    w.node.mine(1)
    w.hub.watch_tick()
    tc.assertEqual(st_b.best_cum, lock["cum"], "control: the second ch2 closed at the lock's state")
    return left, code, w.st1().best_cum, lock["d"]


class LocksFromBeforeTheCh2Field(unittest.TestCase):
    def test_with_the_ch2_field_the_lock_of_the_unresolved_ch2_stays_on_ch1(self):
        w, a, before = two_held_locks_on_two_ch2s_of_one_provider(self, False)
        left, code, _, _ = first_ch2_closes_without_t(self, w, a, before)
        self.assertEqual((left, code), (1, "lock_pending"))
        self.assertEqual(w.stale1(), [], "the second ch2's close showed t and completed its lock on ch1")

    def test_hole_two_locks_from_a_ledger_before_agp088_to_one_provider_are_released_together(self):
        w, a, before = two_held_locks_on_two_ch2s_of_one_provider(self, True)
        held = [T.d_plus_f(s) for s in w.stale1()]
        left, code, collected, lock_d = first_ch2_closes_without_t(self, w, a, before)
        self.assertTrue(left == 1 and code == "lock_pending",
                        f"the first ch2 closed without t and {2 - left} of the 2 locks under one lockId left ch1 (holds of {held} sat "
                        f"given back); ch1 then closed ({code or 'ok'}) at {collected} sat, and the second ch2 paid its lock of "
                        f"{lock_d} sat with the pre-signature the provider kept: {lock_d} sat uncollected")


class WhoEmptiesMaxHeldLocks(unittest.TestCase):
    def test_hole_a_held_lock_completed_below_the_best_state_still_counts_against_max_held_locks(self):
        # default client (max_held_locks 2). Two providers keep a lock each and then close their ch2
        # with t, the later lock first. The hub completes both and holds nothing; the client learns of
        # the first completion (the hub's best state, with its secret) and never of the second
        w = W([None, None, None, None], pkw={"held_probe_secs": 0.0})
        w.paid(3)
        for i in (0, 1):
            w.keeps_locks(i)
            w.refused(i)
        self.assertEqual(len(w.stale1()), 2, "control: two locks held")
        w.provider_closes(1)
        self.assertTrue(H.has(w.hub.watch_tick(), "secret_from_close", ch1_completed=True))
        r = w.pay_until_paid(3)
        self.assertEqual(r and r["status"], "paid", f"control: the completion is adopted and p3 is paid above one hold: {r}")
        w.provider_closes(0)
        self.assertTrue(H.has(w.hub.watch_tick(), "secret_from_close", ch1_completed=True))
        self.assertEqual(w.stale1(), [], "control: the hub holds no lock on ch1")
        r = w.pay_until_paid(3)
        self.assertEqual(r and r["status"], "paid", f"control: {r}")
        w.keeps_locks(2)
        w.refused(2)
        self.assertEqual(len(w.stale1()), 1, "control: one lock held")
        routes, views = w.route_calls(HUB_ROUTE_PATH), w.route_calls(HUB_VIEW_PATH)
        r = w.pay_until_paid(3)
        self.assertEqual(r and r["status"], "paid",
                         f"the hub holds 1 lock and max_held_locks is {w.pay.max_held_locks}: the client signed nothing for p3 "
                         f"({w.route_calls(HUB_ROUTE_PATH) - routes} lock requests, {w.route_calls(HUB_VIEW_PATH) - views} view requests "
                         f"in 4 tries); the lock p0 completed below the best state is still held at the client")


class TheCapCountsArchivedCh2s(unittest.TestCase):
    def test_hole_a_ch2_replaced_because_its_pay_to_changed_is_funded_past_the_liquidity_cap(self):
        w = W([None], hkw={"liquidity_cap_sat": 100_000})
        w.paid(0)
        old = w.oc(0)
        self.assertEqual(w.hub.committed_sat(), 100_000, "control: at the cap")
        self.assertEqual(L.code_of(w.hub.connect_next, w.origins[0]), "liquidity_cap", "control: the cap refuses a second ch2")
        w.provs[0].pay_to = ecc.pubkey(0x7777).hex()
        code = L.code_of(w.hub.connect, w.origins[0])
        for _ in range(3):
            w.hub.watch_tick()
        p = old.p()
        unspent = w.node.gettxout(p.funding_txid, p.funding_vout, True) is not None
        rec = next((r for r in w.hub.out.archived if r["params"]["payer_pub"] == old.params["payer_pub"]), None)
        self.assertLessEqual(w.hub.committed_sat(), 100_000,
                             f"connect answered {code or 'ok'}: {w.hub.committed_sat()} sat committed under a cap of 100000; the first "
                             f"ch2 is unspent ({unspent}), archived as {rec and rec['state']}, retired {rec and rec.get('retired')}, and "
                             f"{w.route_calls(CLOSE_PATH)} close requests went to the provider")


if __name__ == "__main__":
    unittest.main()
