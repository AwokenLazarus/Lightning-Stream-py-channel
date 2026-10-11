"""AGP-105 (fix wave 6, the hub): the rules this wave states, on the harness of test_agp093_hub.py (W)
and routehelp. The audit's own tests for the same items are in test_agp102_hub.py; these pin what
those do not: how a provider that was set aside comes back, what several dark providers cost a tick,
the mutex wait outside ch1's ledger lock, and the scan that starts where the spend was found.
xbt-rs has the same tests under the same names (crates/xbt402-interop/tests/agp105_hub.rs).
"""
import os
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402
import test_agp088_hub as H  # noqa: E402
import test_agp093_hub as A  # noqa: E402

from xbt402 import route  # noqa: E402
from xbt402.hub import CHECK_UNANSWERED  # noqa: E402


class Knobs:
    """The hub's transport. `dark`: a provider (by origin) that never answers a check: the transport
    gives up after that many seconds. `slow`: one that answers a check that much later. `checks`: every
    check sent, the watcher's included."""

    def __init__(self, net):
        self.net, self.dark, self.slow, self.checks = net, {}, {}, 0

    def http(self, method, url, body=b"", headers=None):
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        if R.is_lock_check(path, body):
            self.checks += 1
            if origin in self.dark:
                time.sleep(self.dark[origin])
                raise OSError("timed out")
            if origin in self.slow:
                time.sleep(self.slow[origin])
        return self.net.http(method, url, body, headers)


def world(n, **hkw):
    w = A.W([None] * n, hkw=hkw or None)
    k = Knobs(w.net)
    w.hub.http = k.http
    return w, k


def pay_due(tc, w, i):
    """A lock for what is already due, with no call first (a provider left unpaid for longer than
    window + lockWait serves nothing until it is paid)."""
    r = w.pay.lock(w.shards[i])
    tc.assertEqual((r or {}).get("status"), "paid", r)


class AProviderSetAside(unittest.TestCase):
    def test_a_provider_set_aside_is_refused_at_once_and_comes_back_when_it_answers(self):
        w, k = world(2)
        self.assertEqual(w.hub.reveal_timeout, 0.3, "control: the rig's reveal timeout")
        w.paid(0)
        w.paid(1)
        k.dark[w.origins[0]] = 0.4
        r = w.lock(0)
        self.assertEqual((r["status"], r.get("error")), ("refused", "route_failed"), r)
        oc = w.oc(0)
        self.assertEqual((oc.blocked, oc.state, oc.stale, oc.pending), (CHECK_UNANSWERED, "open", [], {}), "set aside, nothing written off")
        self.assertFalse(w.stale1(), "nothing is held on ch1")
        self.assertEqual(k.checks, 3, "control: two paid locks and the unanswered one")
        # refused at once, without a request to the provider
        t = time.time()
        r = w.pay.lock(w.shards[0])
        self.assertEqual((r["status"], r.get("error")), ("refused", "route_blocked"), r)
        self.assertIn(CHECK_UNANSWERED, r.get("detail", ""))
        self.assertTrue(time.time() - t < 0.3 and k.checks == 3, (time.time() - t, k.checks))
        w.paid(1)
        # still dark: the tick asks once and leaves it aside
        t = time.time()
        acts = w.hub.watch_tick()
        self.assertTrue(not H.has(acts, "ch2_answers_again") and w.oc(0).blocked == CHECK_UNANSWERED and k.checks == 5, (acts, k.checks))
        self.assertLess(time.time() - t, 1.5)
        # it answers again: the next tick lifts the block and the next lock is paid
        del k.dark[w.origins[0]]
        acts = w.hub.watch_tick()
        self.assertTrue(H.has(acts, "ch2_answers_again") and not w.oc(0).blocked, acts)
        self.assertFalse(H.has(w.hub.watch_tick(), "ch2_answers_again"), "once")
        pay_due(self, w, 0)
        w.paid(0)
        self.assertEqual(w.oc(0).stale, [])

    def test_providers_that_stay_dark_cost_a_tick_one_wait_and_are_asked_in_turn(self):
        w, k = world(3)
        for i in range(3):
            w.paid(i)
            k.dark[w.origins[i]] = 0.35
            self.assertEqual(w.lock(i).get("error"), "route_failed")
            self.assertEqual(w.oc(i).blocked, CHECK_UNANSWERED)
        before, t = k.checks, time.time()
        w.hub.watch_tick()
        self.assertEqual(k.checks - before, 1, "one provider asked per tick")
        self.assertLess(time.time() - t, 0.7, "three dark providers, one wait")
        k.dark.clear()
        back = sum(len([a for a in w.hub.watch_tick() if a.get("event") == "ch2_answers_again"]) for _ in range(3))
        self.assertEqual(back, 3, "three ticks, each provider asked once")
        for i in range(3):
            pay_due(self, w, i)

    def test_a_late_answer_is_an_answer(self):
        # an honest slow provider on a transport that does not keep the bound: its yes is taken
        w, k = world(1)
        w.paid(0)
        k.slow[w.origins[0]] = 0.45
        w.paid(0)
        self.assertEqual(w.oc(0).blocked, "")

    def test_the_shipped_transport_is_asked_with_the_reveal_timeout(self):
        # the bound itself: with the shipped `http` the check carries timeout=revealTimeoutSec; an
        # embedder's own callable is called as before
        from xbt402.x402_channel import XbtChannelClient
        w, _ = world(1)
        w.paid(0)
        seen, real, net = [], XbtChannelClient.http, w.net

        def http(method, url, body=b"", headers=None, timeout=30):
            seen.append(timeout)
            return net.http(method, url, body, headers)
        XbtChannelClient.http = staticmethod(http)
        try:
            w.hub.http = XbtChannelClient.http
            w.paid(0)
        finally:
            XbtChannelClient.http = staticmethod(real)
        self.assertEqual(seen[0], w.hub.reveal_timeout, f"the check, then the lock at the transport's own: {seen}")
        self.assertEqual(seen[1:], [30] * (len(seen) - 1))


class TheMutexWait(unittest.TestCase):
    def test_a_lock_that_waited_for_the_providers_mutex_is_paid_when_it_is_free(self):
        # HUB 8: a lock that found the provider's mutex taken waits for it outside ch1's ledger lock and
        # is then admitted, on ch1 as it is then; meanwhile another request gets the ledger lock
        w, k = world(1, reveal_timeout=2.0)
        w.paid(0)
        pay2 = R.payer(w.node, w.net)
        pay2.open()
        w.node.confirm_all()
        sh2 = pay2.shard(w.origins[0] + "/v1/chunk", "POST")
        R.stream(pay2, sh2, 10)
        R.stream(w.pay, w.shards[0], 10)
        k.slow[w.origins[0]] = 0.3
        out = {}
        first = threading.Thread(target=lambda: out.update(first=w.pay.lock(w.shards[0])))
        first.start()
        time.sleep(0.08)                              # client 1's lock holds p0's mutex while its check waits
        second = threading.Thread(target=lambda: out.update(second=pay2.lock(sh2)))
        t = time.time()
        second.start()
        time.sleep(0.05)                              # client 2's lock is waiting for the mutex
        t_ledger = time.time()
        with w.hub.inbound.ledger.lock:               # what every other request needs
            got_ledger = time.time() - t_ledger
        second.join()
        waited = time.time() - t
        first.join()
        self.assertEqual((out["first"] or {}).get("status"), "paid", out)
        self.assertEqual((out["second"] or {}).get("status"), "paid", f"after {waited:.2f} s: {out}")
        self.assertGreater(waited, 0.1, "control: it did wait for the mutex")
        self.assertLess(got_ledger, 0.1, f"the ledger lock was free while it waited ({got_ledger * 1000:.0f} ms)")


class TheRememberedHeight(unittest.TestCase):
    def test_the_remembered_height_is_only_where_the_scan_starts(self):
        w, _ = world(1, spend_final_depth=6)
        w.paid(0)
        funded_at = w.oc(0).scanned_to
        w.node.mine(50)
        w.hub.watch_tick()
        T.close_now(w.provs[0].inner, w.st2(0))
        w.hub.watch_tick()
        w.node.mine(1)
        found_at = w.node.height
        w.hub.watch_tick()
        self.assertEqual(w.oc(0).spend_at, found_at, "the close's height is on the record")
        # every scan the hub asks for, by the height it starts at; `lower`: the spender is reported that
        # many blocks lower (a reorg mined it again in an earlier block)
        passes, lower, real = [], [0], route.find_spend_at
        import xbt402.hub as hub_mod

        def scan(rpc, txid, vout, from_height):
            passes.append(from_height)
            found = real(rpc, txid, vout, 0)
            if not found or found[1] == 0:
                return found
            at = rpc.getblockcount() + 1 - found[1] - lower[0]
            return (found[0], rpc.getblockcount() + 1 - at) if at >= from_height else None
        hub_mod.find_spend_at = scan
        try:
            for _ in range(5):
                w.hub.watch_tick()
            self.assertEqual(passes, [found_at] * 5, "one scan per tick, from the close's block")
            lower[0] = 3
            del passes[:]
            w.hub.watch_tick()
            self.assertEqual(passes, [found_at, funded_at], "nothing from the remembered height: the whole scan again")
            self.assertEqual((w.oc(0).spend_at, w.oc(0).state), (found_at - 3, "closing"))
            w.node.mine(2)
            self.assertTrue(H.has(w.hub.watch_tick(), "ch2_closed"), "six deep counted from the lower block: final")
        finally:
            hub_mod.find_spend_at = real

    def test_a_scan_that_gives_no_depth_remembers_nothing(self):
        # (found by test_agp094_hub: the first cut compared the missing depth with a number)
        import xbt402.hub as hub_mod
        real = hub_mod.find_spend_at

        def no_depth(*a):
            found = real(*a)
            return found and (found[0], None)
        hub_mod.find_spend_at = no_depth
        try:
            w, _ = world(1, spend_final_depth=3)
            w.paid(0)
            T.close_now(w.provs[0].inner, w.st2(0))
            w.hub.watch_tick()
            for _ in range(3):
                w.node.mine(1)
                w.hub.watch_tick()
            self.assertEqual((w.oc(0).spend_at, w.oc(0).state), (0, "closed"))
            self.assertFalse([e for e in w.hub.events if e.get("event") == "ch2_watch_error"])
        finally:
            hub_mod.find_spend_at = real


if __name__ == "__main__":
    unittest.main()
