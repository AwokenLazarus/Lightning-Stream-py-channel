"""AGP-064: hub routing safety, from the external review's H1 and H2 (in-process: FakeNode + a fake
HTTP transport). xbt-rs has the same tests (crates/xbt402-interop/tests/hub_routing_safety.rs).

H1: a ch1 close while a lock is in flight (route() writes the lock and lets go of ch1's ledger before
it forwards) would close ch1 below the lock, and the hub would pay the provider for free.
H2: a lock written off after its ch2 pre-signature left was superseded by the client's next lock, so
a t the provider used later (a slow honest provider, or one that answers 400 and keeps the
pre-signature) paid the provider and not the hub.
"""
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.hub import HubConfig  # noqa: E402
from xbt402.route import ROUTE_LOCK_PATH  # noqa: E402

# 300 sat a call: a lock (10 calls) is well above ch1's dust floor, so each one raises ch1's state
PRICE = 300 * 10 ** 21


class Wrapped:
    """A provider as the hub sees it over the net: its answer to /lock can be held at a gate (the
    provider took the lock; the hub is still waiting: a lock in flight) or replaced by a 400 (the
    provider keeps the pre-signature)."""

    def __init__(self, inner):
        self.inner, self.cv, self.refuse = inner, threading.Condition(), False
        self.armed = self.entered = self.opened = False

    def arm(self):
        with self.cv:
            self.armed, self.entered, self.opened = True, False, False

    def wait_entered(self):
        with self.cv:
            assert self.cv.wait_for(lambda: self.entered, 10), "the hub never reached the provider"

    def open(self):
        with self.cv:
            self.opened = True
            self.cv.notify_all()

    def serve(self, method, path, headers, body, url):
        r = self.inner.serve(method, path, headers, body, url)
        if path == ROUTE_LOCK_PATH and not R.is_lock_check(path, body):   # (AGP-094: the lock, not the hub's check of it)
            with self.cv:
                if self.armed:
                    self.entered = True
                    self.cv.notify_all()
                    self.cv.wait_for(lambda: self.opened, 10)
                    self.armed = False
            if self.refuse and r[0] == 200:
                return 400, {"Content-Type": "application/json"}, b'{"error":"refused","detail":"no"}'
        return r


class W:
    def __init__(self, blocks):
        """One provider per entry of `blocks`, its ch2 open for that many blocks (None: the hub's default)."""
        self.node, self.net = R.RouteNode(), R.Net()
        self.hub = R.hub(self.node, self.net, reveal_timeout=0.3)
        self.origins, self.provs = [], []
        for i, b in enumerate(blocks):
            o = f"http://p{i}.test"
            w = Wrapped(R.provider(self.node, self.net, o, amsat_per_call=PRICE))
            self.net.apps[o] = w
            self.hub.connect(o, expiry_blocks=b)
            self.origins.append(o)
            self.provs.append(w)
        self.node.confirm_all()
        self.hub.watch_tick()
        self.pay = R.payer(self.node, self.net)
        self.pay.open()
        self.shards = [self.pay.shard(o + "/v1/chunk") for o in self.origins]

    def st1(self):
        return self.hub.inbound.ledger.channels[self.pay.chan]

    def st2(self, i):
        """p`i`'s side of its ch2 (the open one, else the last one)."""
        chans = list(self.provs[i].inner.ledger.channels.values())
        return next((s for s in chans if not s.closed_txid), chans[-1])

    def routed(self):
        return int((self.st1().extra or {}).get("routed_sat", 0))

    def stale1(self):
        return list((self.st1().extra or {}).get("stale_locks", []))

    def counters(self):
        return self.pay.routed, self.pay.fee_units, self.pay.fee_paid, self.pay.signed

    def lock(self, i):
        R.stream(self.pay, self.shards[i], 10)
        return self.pay.lock(self.shards[i])

    def paid(self, i):
        r = self.lock(i)
        assert r["status"] == "paid", r

    def lock_in_flight(self, i):
        """p`i`'s next lock, held at p`i`'s /lock (in flight) on another thread: join() gives its answer."""
        R.stream(self.pay, self.shards[i], 10)
        prov = self.provs[i]
        prov.arm()
        out = {}
        t = threading.Thread(target=lambda: out.update(r=self.pay.lock(self.shards[i])), daemon=True)
        t.start()
        prov.wait_entered()

        def join():
            t.join(10)
            return out["r"]
        return join

    def lock_calls(self):
        return sum(1 for c in self.net.calls if c[2] == ROUTE_LOCK_PATH)


def d_plus_f(lock):
    return lock["d"] + lock["f"]


def close_now(provider, st):
    """The operator's close: no check, no wait."""
    with provider.ledger.lock:
        return provider._close_locked(st)


class H1(unittest.TestCase):
    def test_h1_close_while_a_lock_is_in_flight_is_refused_either_order(self):
        # lock first: the close arrives while the hub forwards, and is refused
        w = W([None])
        w.paid(0)
        before = w.st1().best_cum
        join = w.lock_in_flight(0)
        self.assertTrue(w.st1().extra.get("route_lock"), "the lock is written before the forward")
        with self.assertRaises(ChannelError) as e:
            w.pay.close()
        self.assertFalse(w.st1().closed_txid, f"ch1 closed at {before} below a lock in flight")
        self.assertEqual(e.exception.code, "lock_pending")
        w.provs[0].open()
        r = join()
        self.assertEqual(r["status"], "paid", r)
        st1 = w.st1()
        self.assertTrue(st1.best_cum > before and st1.best_cum >= w.routed(), "ch1 holds the lock now")
        closed = w.pay.close()
        self.assertEqual(int(closed["cum"]), st1.best_cum, closed)

        # close first: the lock is refused, and nothing reaches the provider
        w = W([None])
        w.paid(0)
        R.stream(w.pay, w.shards[0], 10)
        w.pay.close()
        n, best2 = w.lock_calls(), w.st2(0).best_cum
        r = w.pay.lock(w.shards[0])
        self.assertEqual((r["status"], r["error"]), ("refused", "channel_closing"), r)
        self.assertEqual((w.lock_calls(), w.st2(0).best_cum), (n, best2))

    def test_h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_open(self):
        # a hub that wrote its ch1 lock and never forwarded it (here the withholding hook; in life a stop
        # between the two write-aheads): nothing can complete it, so the close drops it and goes ahead
        w = W([None])
        w.paid(0)
        best = w.st1().best_cum
        w.hub.withhold = "all"
        R.stream(w.pay, w.shards[0], 10)
        n = w.lock_calls()
        self.assertEqual(w.pay.lock(w.shards[0])["status"], "pending")
        self.assertTrue(w.st1().extra.get("route_lock"))
        self.assertEqual(w.lock_calls(), n, "the lock never left the hub")
        w.hub.withhold = ""
        closed = w.pay.close()
        self.assertEqual(int(closed["cum"]), best, closed)
        self.assertTrue(any(e.get("event") == "orphan_lock_dropped" for e in w.hub.events))

    def test_h1_a_lock_completed_after_ch1_closed_below_it_is_not_counted(self):
        # the operator's close does not wait: the lock still completes (the provider is paid), but the
        # hub does not record sats that are not on ch1
        w = W([None])
        w.paid(0)
        join = w.lock_in_flight(0)
        routed0, n0 = w.routed(), w.hub.stats["routed"]
        close_now(w.hub.inbound, w.st1())
        w.provs[0].open()
        join()
        self.assertEqual(w.routed(), routed0, "a lock above the ch1 close was added to routed_sat")
        self.assertEqual(w.hub.stats["routed"], n0, "a lock above the ch1 close was counted as routed")
        self.assertEqual(w.hub.stats["uncollected"], 1)

    def test_h1_the_margin_close_lets_a_lock_in_flight_finish(self):
        w = W([None])
        w.paid(0)
        join = w.lock_in_flight(0)
        w.node.height = w.st1().params.expiry - 36                 # inside ch1's close margin
        self.assertEqual(w.hub.inbound.close_due(), [], "ch1 closed at its margin below a lock in flight")
        w.provs[0].open()
        self.assertEqual(join()["status"], "paid")
        self.assertEqual(len(w.hub.inbound.close_due()), 1)
        st1 = w.st1()
        self.assertTrue(st1.closed_txid and st1.best_cum >= w.routed(), "closed with the lock")
        # a lock in flight never holds the margin close past half the margin
        w = W([None])
        w.paid(0)
        join = w.lock_in_flight(0)
        w.node.height = w.st1().params.expiry - 18
        self.assertEqual(len(w.hub.inbound.close_due()), 1)
        w.provs[0].open()
        join()


class H2(unittest.TestCase):
    def test_h2_a_slow_provider_stays_in_the_base_and_a_later_route_sits_above_it(self):
        # p0 completes the lock but its answer is lost: the hub writes it off at revealTimeout. The client
        # routes again (to p1); then p0 closes ch2 with t. The hub must have collected both.
        w = W([None, None])
        routed0 = w.routed()
        w.net.drop[w.origins[0]] = lambda m, p: p == ROUTE_LOCK_PATH
        r = w.lock(0)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        stale = w.stale1()
        self.assertEqual(len(stale), 1)
        first = d_plus_f(stale[0])
        self.assertEqual(w.counters()[0], w.routed(), "the client adopts the hold")
        r = w.lock(1)
        self.assertEqual(r["status"], "paid", r)
        second = r["amount"] + r["fee"]
        self.assertEqual(w.routed(), routed0 + first + second)
        best = w.st1().best_cum
        self.assertGreaterEqual(best, routed0 + first + second, "ch1's state does not cover both locks")
        # p0 closes with the lock it completed: the hub reads t, and the base already counted it
        st2 = w.st2(0)
        self.assertGreater(st2.best_cum, 0)
        close_now(w.provs[0].inner, st2)
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        self.assertEqual(w.stale1(), [])
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.routed(), routed0 + first + second, "nothing given back for a lock that was paid")
        self.assertEqual(w.st1().best_cum, best)

    def test_h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover(self):
        # p0 takes the lock, keeps the pre-signature and answers 400: written off with no block before.
        # The client reroutes the same amount to p1, and p0 closes ch2 later with t.
        w = W([None, None])
        routed0 = w.routed()
        w.provs[0].refuse = True
        r = w.lock(0)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        first = d_plus_f(w.stale1()[0])
        self.assertEqual(w.counters()[0], routed0 + first, "the client adopts the hold")
        # no lock over that ch2, and no rollover of it, until it resolves
        w.provs[0].refuse = False
        again = w.lock(0)
        self.assertEqual((again["status"], again["error"]), ("refused", "route_blocked"), again)
        oc = w.hub.out.chans[w.origins[0]]
        self.assertEqual(len(oc.stale), 1)
        with self.assertRaises(ChannelError) as e:
            w.hub.rollover(oc)
        self.assertEqual(e.exception.code, "lock_pending")
        acts = w.hub.watch_tick()
        self.assertFalse(any(a.get("event") == "ch2_rollover" for a in acts), acts)
        # AGP-073: the watcher does not wait for p0 to close that ch2 (or for its refund): it asks now
        self.assertTrue(any(a.get("event") == "ch2_close" and a.get("why") == "written_off" for a in acts), acts)
        # the reroute is quoted above the held lock
        r = w.lock(1)
        self.assertEqual(r["status"], "paid", r)
        second = r["amount"] + r["fee"]
        self.assertGreaterEqual(w.st1().best_cum, routed0 + first + second)
        acts += w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        self.assertEqual(w.routed(), routed0 + first + second)

    def test_h2_a_refunded_ch2_gives_the_unpaid_hold_back(self):
        # the lock is written off, ch2 is never closed, the hub's refund confirms at expiry: the lock was
        # not paid, so its hold leaves the base and the client resyncs onto it (its next locks use the
        # dust floor of what it signed ahead)
        w = W([None, 3_000])                                       # p1's ch2 outlives p0's refund
        routed0 = w.routed()
        w.net.drop[w.origins[0]] = lambda m, p: p == ROUTE_LOCK_PATH
        self.assertEqual(w.lock(0)["error"], "route_failed")
        stale = w.stale1()
        lid, first = stale[0]["lockId"], d_plus_f(stale[0])
        signed = w.st1().best_cum
        oc = w.hub.out.chans[w.origins[0]]
        w.node.height = oc.p().expiry + 10
        w.hub.watch_tick()
        w.node.confirm_all()
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "ch2_refund_confirmed" for a in acts), acts)
        self.assertTrue(any(a.get("event") == "lock_released" and a["lockId"] == lid and a["held"] for a in acts), acts)
        self.assertEqual(w.routed(), routed0, "the unpaid hold left the base")
        self.assertEqual(w.stale1(), [])
        self.assertEqual(w.st1().extra["released"], [lid])
        self.assertEqual(w.counters()[0], routed0 + first, "the client still counts it")
        # the client's next lock is refused for its amount, with the release in the view: it adopts it
        r = w.lock(1)
        self.assertEqual(r["status"], "resynced", r)
        self.assertEqual(w.counters()[0], routed0)
        self.assertEqual(w.counters()[3], signed)
        r = w.pay.lock(w.shards[1])
        self.assertEqual(r["status"], "paid", r)
        self.assertEqual(w.counters()[0], w.routed())

    def test_h2_a_void_whose_pre_signature_never_left_holds_nothing(self):
        # ch2 exhausted before the pre-signature: nothing can complete the lock, so it is dropped, not held
        w = W([None])
        w.paid(0)
        routed0 = w.routed()
        oc = w.hub.out.chans[w.origins[0]]
        oc.signed = oc.routed = oc.p().max_amount
        r = w.lock(0)
        self.assertEqual(r["error"], "route_failed", r)
        self.assertEqual(w.stale1(), [])
        self.assertEqual((w.routed(), w.counters()[0]), (routed0, routed0))
        w.pay.close()                                              # nothing unresolved keeps ch1 open


class Config(unittest.TestCase):
    def test_max_lock_sat_defaults_small_and_is_at_most_half_of_ch2_capacity(self):
        c = HubConfig()
        self.assertLessEqual(c.max_lock_sat * 5, c.ch2_capacity)
        with self.assertRaises(ValueError):
            HubConfig(max_lock_sat=0)
        self.assertEqual(HubConfig(max_lock_sat=c.ch2_capacity // 2).max_lock_sat, c.ch2_capacity // 2)
        with self.assertRaises(ValueError):
            HubConfig(max_lock_sat=c.ch2_capacity // 2 + 1)
        with self.assertRaises(ValueError):
            HubConfig(max_lock_sat=1_000, ch2_capacity=1_999)


if __name__ == "__main__":
    unittest.main()
