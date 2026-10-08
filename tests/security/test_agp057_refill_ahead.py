"""AGP-057: the ch2 lifecycle under load. In process (routehelp: FakeNode + a fake HTTP transport).
    A the zero-conf cap of a rollover child (cmp CMP-149: `cum 134687 > the provider's zero-conf cap
      132120`). A child's cum starts at 0: nothing the parent carried counts against the cap. The hub
      refused on its own `confirmed` flag, which is the watcher's last look: a child that confirmed since
      that tick was refused until the next one. Now the hub looks at the chain before it refuses. A child
      that is really unconfirmed is still refused at the provider's cap (its risk bound; sized with
      rollover_zero_conf_max).
    B make-before-break refill. A rollover adds no coins, so a ch2 line runs out and was then closed and
      refilled, and the refill opens only at minConf: a block without routing to that provider. The hub
      now funds the origin's NEXT ch2 while the live one still has refill_ahead_locks x the largest lock
      of room, and switches to it with the first lock the live one cannot take: no refused lock.
The Rust port has the same tests (xbt-rs crates/xbt402-interop/tests/hub_refill_ahead.rs)."""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.hub import LIVE, RouteHub  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, ROUTE_LOCK_PATH  # noqa: E402
from sechelp import crashed

LOCK = 2_000                                   # 50 calls at 40 sat
CAP = 40_000                                   # ch2 capacity in the refill tests: 20 locks
MIN_CAP = 20_000                               # the provider's minCapacity (routehelp)


class W:
    """One hub, one client, one provider. The hub's wallet fundings start unconfirmed (as a real wallet's
    do); `block()` is a block and a tick of every watcher."""

    def __init__(self, hkw=None, **pkw):
        self.node, self.net = R.RouteNode(), R.Net()
        self.hub = R.hub(self.node, self.net, **(hkw or {}))
        self.funded = []
        self.hub.fund = self.fund
        self.o = "http://m0.test"
        self.prov = R.provider(self.node, self.net, self.o, 0x5757,
                               **{"settle_multiple": 2, "amsat_per_call": 40 * AMSAT_PER_SAT, **pkw})
        self.hub.connect(self.o)
        self.block()
        self.pay = R.payer(self.node, self.net, capacity=2_000_000)
        self.pay.open()
        self.sh = self.pay.shard(self.o + "/v1/chunk")

    def fund(self, address, sats):
        self.funded.append(sats)
        return self.node.fund_address(address, sats, confirmations=0)

    def lock(self, calls=50):
        R.stream(self.pay, self.sh, calls)
        return self.pay.lock(self.sh)

    def paid(self, n=1, calls=50):
        for _ in range(n):
            r = self.lock(calls)
            assert r["status"] == "paid", r

    def block(self):
        self.node.mine()
        self.prov.close_due()
        return self.hub.watch_tick()

    @property
    def live(self):
        return self.hub.out.chans[self.o]

    @property
    def nxt(self):
        return self.hub.out.next_chans.get(self.o)

    def events(self, *names):
        return [e for e in self.hub.events if e["event"] in names]

    def locks_sent(self):
        return sum(1 for c in self.net.calls if c[1] == self.o and c[2] == ROUTE_LOCK_PATH)

    def records(self):
        return (list(self.hub.out.archived) + [c.__dict__ for c in self.hub.out.chans.values()]
                + [c.__dict__ for c in self.hub.out.next_chans.values()])

    def refused(self):
        return self.pay.stats["refused"], self.hub.stats["refused"]


# --- A the zero-conf cap -----------------------------------------------------------------------------------

class ZeroConfCap(unittest.TestCase):
    """Settle floor on (k = 4): the ch2 rolls over after 4 locks, and the provider's cap on the child is
    2 x 4 x the largest lock = 8 locks."""

    def world(self):
        w = W(hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4)
        w.paid(4)
        w.hub.watch_tick()                                         # due: rolled over, the child open unconfirmed
        self.assertEqual(len(w.events("ch2_rollover")), 1)
        self.assertEqual((w.live.state, w.live.zero_conf["maxCum"], w.live.zero_conf["confirmed"]), ("open", 8 * LOCK, False))
        return w

    def test_a_childs_cum_starts_at_zero_nothing_is_carried_into_the_cap(self):
        w = self.world()
        child = w.live
        st = w.prov.ledger.channels[child.p().channel_id]
        self.assertEqual((child.signed, child.routed, st.best_cum, (st.extra or {}).get("routed_sat", 0)), (0, 0, 0, 0))
        for i in range(8):                                         # exactly the cap's 8 locks fit, no block
            w.paid()
            self.assertEqual((child.signed, child.routed), ((i + 1) * LOCK, (i + 1) * LOCK))
        self.assertEqual(child.signed, child.zero_conf["maxCum"])
        self.assertEqual(w.refused(), ({}, {}))

    def test_a_child_that_is_unconfirmed_is_refused_at_the_cap_before_anything_is_sent(self):
        w = self.world()
        w.paid(8)
        sent = w.locks_sent()
        r = w.lock()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_blocked"), r)
        self.assertIn(f"cum {9 * LOCK} > the provider's zero-conf cap {8 * LOCK}", r["detail"])
        self.assertEqual((w.locks_sent(), w.live.signed, w.live.pending, w.live.stale), (sent, 8 * LOCK, {}, []))
        self.assertEqual(w.hub.stats["refused"], {})               # the hub's own check: the provider refused nothing

    def test_a_child_that_confirmed_since_the_watchers_last_tick_is_not_refused(self):
        """cmp's refusals: the rollover is in a block, the hub's flag is still the last tick's."""
        w = self.world()
        w.paid(8)
        w.node.mine()                                              # no watcher tick, at the hub or the provider
        self.assertFalse(w.live.zero_conf["confirmed"])
        w.paid()                                                   # the 9th lock, above the cap
        self.assertEqual((w.live.signed, w.live.zero_conf["confirmed"]), (9 * LOCK, True))
        self.assertEqual([e["chan"] for e in w.events("ch2_zero_conf_confirmed")], [w.live.p().channel_id])
        self.assertEqual(w.refused(), ({}, {}))

    def test_the_close_margin_bound_looks_at_the_chain_too(self):
        w = self.world()
        w.paid()
        with w.hub.out.lock:                                       # the provider's `until` is behind the tip
            w.live.zero_conf = {**w.live.zero_conf, "until": w.node.height}
        r = w.lock()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_blocked"), r)
        self.assertIn("unconfirmed at the parent's close margin", r["detail"])
        w.node.confirm_all()                                       # it confirmed; no tick
        time.sleep(0.35)                                           # the refused lock's window is over
        w.paid()
        self.assertTrue(w.live.zero_conf["confirmed"])

    def test_a_node_that_does_not_answer_leaves_the_bound_standing(self):
        w = self.world()
        w.paid(8)
        w.node.mine()

        class Down:
            def __init__(self, node):
                self._n = node

            def __getattr__(self, k):
                return getattr(self._n, k)

            def gettxout(self, *a):
                raise OSError("node down")
        w.hub.rpc = Down(w.node)
        r = w.lock()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_blocked"), r)
        self.assertIn("zero-conf cap", r["detail"])
        self.assertEqual([e["step"] for e in w.events("ch2_watch_error")], ["zero_conf"])
        self.assertEqual((w.live.signed, w.live.pending), (8 * LOCK, {}))

    def test_a_block_that_comes_while_the_provider_checks_the_child_does_not_refuse_the_open(self):
        """The provider read the child's funding unconfirmed, then the block with the rollover came: the
        parent is spent in a block, so the child is no zero-conf child any more, and it is confirmed. The
        open was refused `unconfirmed` and routing waited for the hub's next tick (rollover_load cmp-lag)."""
        w = W(hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4)

        class Racy:
            armed = False

            def __init__(self, node):
                self._n = node

            def __getattr__(self, k):
                return getattr(self._n, k)

            def gettxout(self, txid, vout, include_mempool=True):
                out = self._n.gettxout(txid, vout, include_mempool)
                if self.armed and include_mempool and out and not out.get("confirmations"):
                    self.armed = False
                    self._n.mine()                                 # the block arrives right after this read
                return out
        w.prov.rpc = racy = Racy(w.node)
        w.paid(4)
        racy.armed = True
        w.hub.watch_tick()                                         # rolled over; the open meets the block
        self.assertEqual((len(w.events("ch2_rollover")), racy.armed), (1, False))
        self.assertEqual((w.live.state, w.live.zero_conf, bool(w.live.rolled_from)), ("open", {}, True))
        w.paid()
        self.assertEqual(w.refused(), ({}, {}))

    def test_a_child_the_providers_watcher_left_suspended_is_looked_at_before_a_lock_is_refused(self):
        """The provider's watcher meets the block the same way (rollover_load high-nofloor: `provider
        refused the lock: unconfirmed`): the child is left suspended although it confirmed."""
        w = self.world()
        st = w.prov.ledger.channels[w.live.p().channel_id]
        st.suspended = True                                        # as the racing watcher tick leaves it
        r = w.lock()                                               # still unconfirmed: refused, as it must be
        self.assertEqual((r["status"], r["error"], r["detail"]), ("refused", "route_failed", "provider refused the lock: unconfirmed"), r)
        # the provider holds that lock's pre-signature, so this ch2 takes no more routes (AGP-064 H2)
        self.assertEqual(w.lock()["error"], "route_blocked")
        w = self.world()
        st = w.prov.ledger.channels[w.live.p().channel_id]
        st.suspended = True
        w.node.mine()                                              # confirmed; no watcher tick anywhere
        time.sleep(0.35)
        w.paid()
        self.assertEqual((st.suspended, st.extra["zero_conf"]["confirmed"]), (False, True))
        # a plain channel whose funding left the chain stays refused: only an unconfirmed child is looked at
        st.suspended = True
        r = w.lock()
        self.assertEqual((r["status"], r["detail"]), ("refused", "provider refused the lock: unconfirmed"), r)

    def test_an_explicit_provider_cap_sizes_it_for_slow_blocks(self):
        w = W(hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4, rollover_zero_conf_max=16 * LOCK)
        w.paid(4)
        w.hub.watch_tick()
        self.assertEqual(w.live.zero_conf["maxCum"], 16 * LOCK)
        w.paid(16)                                                 # no block all the while
        self.assertEqual((w.live.signed, w.refused()), (16 * LOCK, ({}, {})))


# --- B make-before-break refill ----------------------------------------------------------------------------

AHEAD = {"refill_ahead_locks": 3, "ch2_capacity": CAP}


class RefillAhead(unittest.TestCase):
    def test_a_line_that_runs_out_under_rollovers_never_pauses(self):
        """Every lock is due at the provider's threshold, so the ch2 rolls over each block and its line
        shrinks by a lock each time. The next ch2 is funded 3 locks before the line ends, opens at
        minConf, and takes over when the live one is too small to roll over: 40 locks, none refused."""
        w = W(hkw=AHEAD)
        first = w.live.p().channel_id
        for i in range(40):
            w.paid()
            w.block()
            self.assertLessEqual(len(w.hub.out.next_chans), 1)
            self.assertLessEqual(w.hub.committed_sat(), 2 * CAP)
        self.assertEqual(w.refused(), ({}, {}))
        ahead, switch = w.events("ch2_refill_ahead"), w.events("ch2_switch")
        self.assertGreaterEqual(len(switch), 3)
        self.assertEqual(len(ahead), len(switch) + (1 if w.nxt is not None else 0))
        self.assertEqual((ahead[0]["live"] != first, ahead[0]["maxLock"], ahead[0]["capacity"]), (True, LOCK, CAP))
        self.assertLess(ahead[0]["room"], 3 * LOCK)
        self.assertEqual({e["why"] for e in switch}, {"closed"})
        self.assertEqual(len(w.funded), 1 + len(ahead))            # one wallet funding per ch2, none twice
        # money: every lock is on exactly one ch2, and the provider was paid all of them
        self.assertEqual(sum(int(r["routed"]) for r in w.records()), 40 * LOCK)
        self.assertEqual(w.prov.routes.sessions[w.sh.session].paid_sat, 40 * LOCK)
        self.assertTrue(all(not r["pending"] and not r["stale"] for r in w.records()))

    def test_without_it_the_refill_follows_the_close_and_routing_waits_for_a_block(self):
        """The baseline (refill_ahead_locks 0): the same line, and a lock refused when it ends."""
        w = W(hkw={**AHEAD, "refill_ahead_locks": 0})
        seen = []
        for _ in range(14):
            r = w.lock()
            seen.append(r["status"])
            if r["status"] != "paid":
                self.assertEqual(r["error"], "route_blocked", r)
                self.assertIn("its ch2 is funded", r["detail"])
            w.block()
        self.assertEqual(seen.count("refused"), 1)
        self.assertEqual((w.events("ch2_refill_ahead"), w.events("ch2_switch"), w.hub.out.next_chans), ([], [], {}))

    def test_the_next_ch2_is_funded_at_n_locks_of_room_and_opens_only_once_confirmed(self):
        w = W(hkw=AHEAD, settle_multiple=100)                      # a threshold above the capacity: no rollover
        for i in range(7):                                         # 14,000 used: 6,000 of room above minCapacity
            w.paid()
            self.assertEqual(w.hub.watch_tick(), [], i)
        w.paid()                                                   # 16,000 used: 4,000 < 3 locks
        acts = w.hub.watch_tick()
        self.assertEqual([a["event"] for a in acts], ["ch2_refill_ahead"])
        self.assertEqual((acts[0]["room"], acts[0]["live"], acts[0]["next"]),
                         (CAP - 8 * LOCK - MIN_CAP, w.live.p().channel_id, w.nxt.p().channel_id))
        self.assertEqual((w.nxt.state, w.nxt.p().capacity, w.nxt.rolled_from, w.live.state), ("funded", CAP, "", "open"))
        self.assertEqual(w.hub.committed_sat(), 2 * CAP)           # the liquidity accounting counts both
        self.assertEqual(w.hub.out.live_keys(w.live.pay_to), [w.o])  # one origin, counted once for its payTo
        self.assertEqual(w.hub.watch_tick(), [])                   # unconfirmed: not opened, and not funded twice
        self.assertNotIn(w.nxt.p().channel_id, w.prov.ledger.channels)
        w.paid()                                                   # the live one goes on meanwhile
        acts = w.block()
        self.assertIn({"event": "ch2_open", "provider": w.o, "next": True}, acts)
        self.assertEqual((w.nxt.state, w.nxt.zero_conf), ("open", {}))
        self.assertIn(w.nxt.p().channel_id, w.prov.ledger.channels)
        self.assertEqual((len(w.funded), w.refused()), (2, ({}, {})))

    def test_the_lock_the_live_ch2_cannot_take_goes_over_the_next_one(self):
        """No rollover (the provider's threshold is above the capacity): the live ch2 is used to its last
        sat, the 21st lock switches, and the retired ch2 is closed by the watcher: the provider is paid
        its 40,000 and the hub's accounting drops it once the close is out."""
        w = W(hkw=AHEAD, settle_multiple=100)
        w.paid(8)
        w.block()                                                  # funded ahead
        w.block()                                                  # open
        old, nxt = w.live, w.nxt
        self.assertEqual(nxt.state, "open")
        w.paid(12)
        self.assertEqual((old.signed, w.live is old, w.events("ch2_switch")), (CAP, True, []))
        w.paid()                                                   # 42,000 > capacity
        self.assertIs(w.live, nxt)
        self.assertEqual((nxt.signed, nxt.routed, nxt.max_lock, w.hub.out.next_chans), (LOCK, LOCK, LOCK, {}))
        sw = w.events("ch2_switch")
        self.assertEqual([(e["from"], e["to"], e["why"]) for e in sw], [(old.p().channel_id, nxt.p().channel_id, "exhausted")])
        rec = w.hub.out.archived[-1]
        self.assertEqual((rec["state"], rec["retired"], rec["signed"]), ("open", True, CAP))
        self.assertEqual(w.hub.committed_sat(), 2 * CAP)           # still the hub's coins until its close is out
        self.assertEqual(w.hub.routing_extra()["providers"], [w.o])
        acts = w.hub.watch_tick()
        close = [a for a in acts if a["event"] == "ch2_close"]
        self.assertEqual([(a["chan"], a["amount"], a["payeeNet"]) for a in close], [(old.p().channel_id, CAP, CAP - 600)])
        self.assertEqual((w.hub.out.archived[-1]["state"], w.hub.committed_sat()), ("closing", CAP))
        self.assertTrue(w.prov.ledger.channels[old.p().channel_id].closed_txid)
        w.block()
        self.assertEqual((w.hub.out.archived[-1]["state"], w.hub.out.archived[-1]["final"]), ("closed", True))
        w.paid(3)
        self.assertEqual(w.refused(), ({}, {}))
        self.assertEqual(sum(int(r["routed"]) for r in w.records()), 24 * LOCK)

    def test_a_live_ch2_too_small_to_roll_over_is_kept_until_the_next_one_is_open(self):
        """N = 1: the next ch2 is funded only when the live one is at the provider's minCapacity, so it is
        still unconfirmed when the live one is due and too small to roll over. Closing it then would pause
        routing until the next one opens; it still takes locks, so it is kept until then."""
        w = W(hkw={**AHEAD, "refill_ahead_locks": 1, "settle_lock_multiple": 11})
        w.paid(10)                                                 # what a child would keep is the minCapacity
        self.assertEqual([a["event"] for a in w.hub.watch_tick()], ["ch2_refill_ahead"])
        self.assertEqual((w.live.signed, w.nxt.state), (10 * LOCK, "funded"))
        w.paid()
        acts = w.hub.watch_tick()                                  # due, too small to roll over, no block
        self.assertEqual([a["event"] for a in acts], ["ch2_wait_next"])
        self.assertEqual((w.live.state, w.live.signed, w.nxt.state), ("open", 11 * LOCK, "funded"))
        w.paid()                                                   # the live one goes on
        w.block()                                                  # the next one confirms and opens
        self.assertEqual((w.live.signed, w.nxt.state, w.events("ch2_close")), (12 * LOCK, "open", []))
        acts = w.hub.watch_tick()                                  # now it is closed, and the next one takes over
        self.assertEqual([a["event"] for a in acts], ["ch2_close"])
        self.assertEqual((acts[0]["amount"], acts[0]["next"], w.live.state, w.live.p().capacity),
                         (12 * LOCK, w.live.p().channel_id, "open", CAP))
        w.paid()
        self.assertEqual(w.refused(), ({}, {}))

    def test_an_exhausted_ch2_without_a_next_one_fails_as_before(self):
        w = W(hkw={**AHEAD, "refill_ahead_locks": 0}, settle_multiple=100)
        w.paid(20)
        r = w.lock()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        self.assertIn("exhausted", r["detail"])

    def test_a_next_ch2_not_open_yet_does_not_take_the_lock(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        w.paid(8)
        w.hub.watch_tick()                                         # funded, unconfirmed
        self.assertEqual(w.nxt.state, "funded")
        w.paid(12)
        r = w.lock()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        self.assertEqual((w.nxt.state, w.nxt.signed, w.events("ch2_switch")), ("funded", 0, []))

    def test_an_unconfirmed_rollover_child_at_its_cap_hands_over_to_an_open_next_ch2(self):
        """A and B together: the child is at the provider's zero-conf cap and no block comes; the next ch2
        (confirmed) takes the lock instead of a refusal."""
        w = W(hkw={"refill_ahead_locks": 40, "ch2_capacity": 100_000, "settle_lock_multiple": 4}, settle_lock_multiple=4)
        w.paid()
        w.block()                                                  # 40 locks of room wanted: funded ahead at once
        w.block()
        self.assertEqual(w.nxt.state, "open")
        w.paid(3)
        w.hub.watch_tick()                                         # 4 locks: rolled over, the child unconfirmed
        child, nxt = w.live, w.nxt
        self.assertEqual((child.zero_conf["confirmed"], child.zero_conf["maxCum"]), (False, 8 * LOCK))
        w.paid(8)
        w.paid()                                                   # the 9th: above the cap, no block
        self.assertIs(w.live, nxt)
        self.assertIn("zero-conf cap", w.events("ch2_switch")[0]["why"])
        self.assertEqual((child.signed, nxt.signed, w.refused()), (8 * LOCK, LOCK, ({}, {})))
        w.block()                                                  # the retired child is closed on its 16,000
        self.assertEqual([(e["chan"], e["amount"]) for e in w.events("ch2_close")], [(child.p().channel_id, 8 * LOCK)])

    def test_an_idle_provider_does_not_keep_two_ch2s(self):
        w = W(hkw={**AHEAD, "settle_idle": 0.3}, settle_multiple=100)
        w.paid(8)
        w.block()
        w.block()
        old, nxt = w.live, w.nxt
        self.assertEqual((nxt.state, w.hub.committed_sat()), ("open", 2 * CAP))
        time.sleep(0.35)
        acts = w.hub.watch_tick()                                  # no lock for settle_idle: the next one takes over
        self.assertIn({"event": "ch2_switch", "provider": w.o, "why": "idle"}, acts)
        self.assertIs(w.live, nxt)
        self.assertEqual([a["chan"] for a in acts if a["event"] == "ch2_close"], [old.p().channel_id])
        self.assertEqual(w.hub.committed_sat(), CAP)
        self.assertEqual(w.hub.watch_tick(), [])                   # and nothing is funded ahead for an idle provider
        w.paid()
        self.assertEqual(w.refused(), ({}, {}))


class Bounds(unittest.TestCase):
    def test_at_most_one_next_ch2_per_origin(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        with self.assertRaises(ChannelError) as e:                 # nothing routed yet is fine: the live one is open
            w.hub.connect_next("http://nobody.test")
        self.assertEqual(e.exception.code, "no_live_ch2")
        a = w.hub.connect_next(w.o)
        self.assertIs(w.hub.connect_next(w.o), a)
        self.assertEqual((len(w.funded), list(w.hub.out.next_chans)), (2, [w.o]))
        with self.assertRaises(ChannelError) as e:
            w.hub._fund_ch2(w.o, a.terms, CAP, w.node.height + 1_000, ahead=True)
        self.assertEqual((e.exception.code, len(w.funded)), ("ch2_funding", 2))
        self.assertIs(w.hub.connect(w.o), w.live)                  # connect still returns the live one

    def test_the_liquidity_cap_counts_both_and_a_refused_refill_is_tried_once_a_block(self):
        w = W(hkw={**AHEAD, "liquidity_cap_sat": 2 * CAP - 1}, settle_multiple=100)
        w.paid(8)
        acts = w.hub.watch_tick()
        self.assertEqual([a["event"] for a in acts], ["ch2_refill_ahead_failed"])
        self.assertIn("liquidity_cap", acts[0]["error"])
        self.assertEqual((w.hub.watch_tick(), w.hub.out.next_chans, len(w.funded)), ([], {}, 1))
        w.paid()                                                   # the live ch2 is not disturbed
        self.assertEqual([a["event"] for a in w.block()], ["ch2_refill_ahead_failed"])
        w.hub.liquidity_cap_sat = 2 * CAP
        self.assertEqual([a["event"] for a in w.block()], ["ch2_refill_ahead"])
        self.assertEqual(w.hub.committed_sat(), 2 * CAP)

    def test_an_embedders_own_refill_path_is_not_bypassed(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        calls = []
        w.hub.refill = lambda origin: calls.append(("refill", origin))
        self.assertIsNone(w.hub.refill_ahead)                      # its path, lock and cap: nothing funded on our own
        w.paid(8)
        self.assertEqual((w.hub.watch_tick(), w.hub.out.next_chans), ([], {}))
        w.hub.refill_ahead = lambda origin: calls.append(("ahead", origin)) or w.hub.connect_next(origin)
        self.assertEqual([a["event"] for a in w.hub.watch_tick()], ["ch2_refill_ahead"])
        self.assertEqual((calls, w.nxt.state), ([("ahead", w.o)], "funded"))

    def test_a_blocked_provider_gets_no_next_ch2_and_no_switch(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        w.paid(8)
        w.block()
        w.block()
        self.assertEqual(w.nxt.state, "open")
        with w.hub.out.lock:
            w.live.blocked = "the provider did not reveal a lock in time"
        r = w.lock()
        self.assertEqual((r["status"], r["error"], r["detail"]), ("refused", "route_blocked", w.live.blocked), r)
        self.assertEqual((w.events("ch2_switch"), w.hub.routing_extra()["providers"]), ([], []))
        # and under the mutex too (the block may be set between the route's first look and its lock)
        st1 = w.hub.inbound.ledger.channels[w.pay.chan]
        self.assertIsNone(w.hub._switch_for(w.o, w.live, st1, LOCK, ("route_blocked", w.live.blocked)))
        self.assertEqual((w.nxt.state, w.events("ch2_switch")), ("open", []))


class Lifecycle(unittest.TestCase):
    def test_a_fund_hook_that_fails_after_it_broadcast_is_reconciled(self):
        w = W(hkw=AHEAD, settle_multiple=100)

        def fund(address, sats):
            w.node.fund_address(address, sats, confirmations=0)
            raise OSError("wallet RPC timed out")
        w.hub.fund = fund
        w.paid(8)
        acts = w.hub.watch_tick()
        self.assertEqual([a["event"] for a in acts], ["ch2_refill_ahead_failed"])
        self.assertEqual((w.nxt.state, w.live.state), ("funding", "open"))       # written ahead: the key is on disk
        self.assertIn("ch2_funding_recovered", [a["event"] for a in w.hub.watch_tick()])
        self.assertEqual(w.nxt.state, "funded")
        w.block()
        self.assertEqual(w.nxt.state, "open")

    def test_a_funding_that_never_appears_is_dropped_and_funded_again(self):
        w = W(hkw={**AHEAD, "funding_timeout_blocks": 2}, settle_multiple=100)
        good = w.hub.fund

        def fund(address, sats):
            raise OSError("wallet locked")
        w.hub.fund = fund
        w.paid(8)
        w.hub.watch_tick()
        self.assertEqual(w.nxt.state, "funding")
        w.block()
        self.assertEqual(w.nxt.state, "funding")
        w.hub.fund = good
        acts = w.block()
        self.assertEqual([a["event"] for a in acts], ["ch2_funding_dropped", "ch2_refill_ahead"])
        self.assertEqual((w.nxt.state, w.hub.out.archived[-1]["state"], w.hub.out.archived[-1]["final"]),
                         ("funded", "dropped", True))
        self.assertEqual(w.live.state, "open")

    def test_the_book_keeps_the_next_ch2_over_a_restart(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        w.paid(8)
        w.block()
        w.block()
        d = os.path.dirname(w.hub.out.path)
        crashed(d)
        h2 = RouteHub(w.node, 0x4B4B, R.NET, d, w.fund, http=w.net.http, **{**AHEAD, "settle_lock_multiple": 0},
                      policy=w.hub.inbound.policy, close_margin=36, delta=36, ch2_expiry_blocks=1_000, max_lock_sat=20_000)
        self.assertEqual({k: (c.state, c.p().channel_id) for k, c in h2.out.next_chans.items()},
                         {w.o: ("open", w.nxt.p().channel_id)})
        self.assertEqual((h2.committed_sat(), h2.watch_tick()), (2 * CAP, []))

    def test_a_next_ch2_never_used_is_refunded_at_its_expiry_and_leaves(self):
        w = W(hkw=AHEAD, settle_multiple=100)
        w.paid(8)
        w.block()
        w.block()
        nxt = w.nxt
        self.assertEqual(nxt.state, "open")
        w.node.height = nxt.p().expiry                             # unsigned: refunded at expiry
        w.node.confirm_all()
        acts = w.hub.watch_tick()
        self.assertIn(nxt.p().channel_id, [a["chan"] for a in acts if a["event"] == "ch2_refund"])
        self.assertEqual((nxt.state, "refunded" in LIVE), ("refunded", False))
        self.assertIn(nxt.p().channel_id, [f"{r['params']['funding_txid']}:{r['params']['funding_vout']}" for r in w.hub.out.archived])
        # the live ch2 still wants one: a fresh next ch2 is funded in its place, never two
        self.assertEqual([a["event"] for a in acts if a["event"].startswith("ch2_refill")], ["ch2_refill_ahead"])
        self.assertEqual((w.nxt is nxt, w.nxt.state, len(w.hub.out.next_chans)), (False, "funded", 1))


if __name__ == "__main__":
    unittest.main()
