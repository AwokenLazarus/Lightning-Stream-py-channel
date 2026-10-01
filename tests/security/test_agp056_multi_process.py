"""AGP-056: routed locks at multi-process operators, rollovers a hub's own node has not seen yet, and
rollovers per lock. In process (routehelp: FakeNode + a fake HTTP transport). One class per finding:
    1 ch2 identity: one operator key, several provider processes (separate ledgers and origins). Each
      process gets its own ch2 and is paid on it, through rollovers (AGP-044's one ch2 per payTo sent the
      second process's locks to the first: unknown_session, route_failed); one key is bounded
      (ch2_max_per_pay_to); a refusal says what is wrong;
    2 rollover relay: the provider broadcasts the rollover on ITS node; a hub whose node has not received
      it yet must not call it vanished (cmp R14: every child was blocked until the next block);
    3 settle floor: with locks larger than settleMultiple x closeFee the ch2 rolled over on every lock;
      the hub now waits for settle_lock_multiple x the largest lock, and the provider's zero-conf cap
      follows;
    4 RoutePayer returns the refusal detail, as the Rust client does.
The Rust port has the same tests (xbt-rs crates/xbt402-interop/tests/hub_multi_process.rs)."""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.hub import ROLLOVER_GONE, HubConfig, RouteHub  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, ROUTE_LOCK_PATH  # noqa: E402

KEY = 0x5151
LOCK = 2_000                                   # 50 calls at 40 sat


class LagNode:
    """The hub's own node while `lag` is on: every tx broadcast since is still on its way over P2P, so
    this view shows neither it nor what it spends (the provider's node, the RouteNode behind, has it)."""

    def __init__(self, node):
        self._n, self._known = node, None

    def __getattr__(self, k):
        return getattr(self._n, k)

    def lag(self, on=True):
        self._known = set(self._n.txs) if on else None

    def _hidden(self, txid):
        return (self._known is not None and txid is not None and txid.lower() not in self._known
                and self._n.txs.get(txid.lower(), {}).get("confirmations", 0) < 1)

    def gettxout(self, txid, vout, include_mempool=True):
        if self._hidden(txid):
            return None
        if include_mempool and self._hidden(self._n.spenders.get((txid.lower(), vout))):
            tx = self._n.txs.get(txid.lower())
            if not tx or vout >= len(tx["vout"]):
                return None
            o = tx["vout"][vout]
            return {"confirmations": tx["confirmations"], "value": o["value"], "scriptPubKey": o["scriptPubKey"],
                    "coinbase": False}
        return self._n.gettxout(txid, vout, include_mempool)

    def getmempoolentry(self, txid):
        if self._hidden(txid):
            raise RuntimeError("Transaction not in mempool")
        return self._n.getmempoolentry(txid)

    def getrawtransaction(self, txid, verbose=True):
        if self._hidden(txid):
            raise RuntimeError("No such mempool or blockchain transaction")
        return self._n.getrawtransaction(txid, verbose)

    def gettxspendingprevout(self, outs):
        return [{k: v for k, v in r.items() if k != "spendingtxid" or not self._hidden(v)}
                for r in self._n.gettxspendingprevout(outs)]


class W:
    """One hub, one client, `n` provider processes on ONE operator key: each its own ledger and origin."""

    def __init__(self, n=2, hkw=None, connect=True, lagging=False, **pkw):
        self.node, self.net = R.RouteNode(), R.Net()
        self.view = LagNode(self.node) if lagging else self.node
        self.hub = R.hub(self.view, self.net, **(hkw or {}))
        pkw = {"settle_multiple": 2, "amsat_per_call": 40 * AMSAT_PER_SAT, **pkw}
        self.origins = [f"http://m{i}.test" for i in range(n)]
        self.provs = {o: R.provider(self.node, self.net, o, KEY, **pkw) for o in self.origins}
        if connect:
            for o in self.origins:
                self.hub.connect(o)
            self.node.confirm_all()
            self.hub.watch_tick()
        self.pay = R.payer(self.node, self.net, capacity=2_000_000)
        self.pay.open()
        self.sh = {o: self.pay.shard(o + "/v1/chunk") for o in self.origins}

    def lock(self, o, calls=50):
        R.stream(self.pay, self.sh[o], calls)
        return self.pay.lock(self.sh[o])

    def block(self):
        self.node.mine()
        for p in self.provs.values():
            p.close_due()
        return self.hub.watch_tick()

    def rollovers(self, o=None):
        return [e for e in self.hub.events if e["event"] == "ch2_rollover" and o in (None, e["provider"])]

    def locks_to(self, o):
        return sum(1 for c in self.net.calls if c[1] == o and c[2] == ROUTE_LOCK_PATH)


# --- 1 ch2 identity ---------------------------------------------------------------------------------------

class MultiProcessOperator(unittest.TestCase):
    def test_each_process_is_paid_on_its_own_ch2_through_rollovers(self):
        """The repro of cmp's merchants A0..A3: locks to every process, rollovers under load, no refusal."""
        w = W(3)
        chans = {o: w.hub.out.chans[o].p().channel_id for o in w.origins}
        self.assertEqual(len(set(chans.values())), 3)
        self.assertEqual(w.hub.routing_extra()["providers"], w.origins)
        paid = {o: 0 for o in w.origins}
        for _ in range(4):
            for o in w.origins:                                   # on the confirmed ch2: at the threshold
                r = w.lock(o)
                self.assertEqual(r["status"], "paid", r)
                paid[o] += r["amount"]
            w.hub.watch_tick()                                    # every ch2 rolls over; the children open unconfirmed
            for o in w.origins:                                   # on the unconfirmed child, no block yet
                r = w.lock(o)
                self.assertEqual(r["status"], "paid", r)
                paid[o] += r["amount"]
            w.block()                                             # the children confirm and roll over in turn
            w.block()
        self.assertEqual((w.pay.stats["refused"], w.hub.stats["refused"]), ({}, {}))
        for o in w.origins:
            self.assertEqual(len(w.rollovers(o)), 8, o)
            s = w.provs[o].routes.sessions[w.sh[o].session]
            self.assertEqual((s.paid_sat, w.sh[o].locked_sat), (paid[o], paid[o]))
            # every ch2 of this origin, the rolled ones included, is in this process's ledger and no other
            mine = {r["params"]["funding_txid"] for r in w.hub.out.archived if r["origin"] == o}
            mine.add(w.hub.out.chans[o].p().funding_txid)
            for q, prov in w.provs.items():
                held = {c.split(":")[0] for c in prov.ledger.channels}
                self.assertEqual(held & mine, mine if q == o else set(), (o, q))

    def test_a_lock_is_forwarded_to_the_origin_the_client_named(self):
        w = W(2)
        a, b = w.origins
        for o in (b, b, a):
            self.assertEqual(w.lock(o, 5)["status"], "paid")
        self.assertEqual((w.locks_to(a), w.locks_to(b)), (1, 2))
        self.assertEqual((w.hub.out.chans[a].routed, w.hub.out.chans[b].routed),
                         (w.sh[a].locked_sat, w.sh[b].locked_sat))

    def test_a_rollover_keeps_each_origin_on_its_own_next_ch2(self):
        w = W(2)
        a, b = w.origins
        before = {o: w.hub.out.chans[o].p().channel_id for o in w.origins}
        self.assertEqual(w.lock(b)["status"], "paid")
        w.hub.watch_tick()
        self.assertEqual([e["provider"] for e in w.rollovers()], [b])
        self.assertEqual(w.hub.out.chans[a].p().channel_id, before[a])
        child = w.hub.out.chans[b]
        self.assertEqual((child.origin, child.rolled_from, child.state), (b, before[b], "open"))
        self.assertIn(child.p().channel_id, w.provs[b].ledger.channels)
        self.assertNotIn(child.p().channel_id, w.provs[a].ledger.channels)
        for o in (a, b):
            self.assertEqual(w.lock(o)["status"], "paid")

    def test_an_origin_without_its_own_ch2_is_refused_with_the_reason(self):
        """An AGP-044 book: b was recorded under a's payTo and routed over a's ch2. Now its locks are
        refused at the hub, with the cause, before anything is signed on a's ch2; connect funds b's own."""
        w = W(2, connect=False)
        a, b = w.origins
        w.hub.connect(a)
        w.node.confirm_all()
        w.hub.watch_tick()
        with w.hub.out.lock:
            w.hub.out.origins[b] = w.hub.out.chans[a].pay_to.lower()
        self.assertEqual(w.hub.routing_extra()["providers"], [a])
        r = w.lock(b, 5)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_blocked"), r)
        self.assertIn(f"its payTo has a ch2 at {a}, another provider process", r["detail"])
        self.assertEqual((w.locks_to(a), w.hub.out.chans[a].pending, w.hub.out.chans[a].stale), (0, {}, []))
        nb = w.hub.connect(b)
        self.assertEqual((nb.origin, len(w.hub.out.live_keys(nb.pay_to))), (b, 2))
        w.node.confirm_all()
        w.hub.watch_tick()
        R.stream(w.pay, w.sh[b], 1)
        self.assertEqual(w.lock(b, 5)["status"], "paid")

    def test_one_key_is_bounded_and_the_refusal_is_clear(self):
        w = W(3, connect=False, hkw={"ch2_max_per_pay_to": 2})
        a, b, c = w.origins
        w.hub.connect(a)
        w.hub.connect(b)
        with self.assertRaises(ChannelError) as e:
            w.hub.connect(c)
        self.assertEqual(e.exception.code, "pay_to_limit")
        self.assertIn("ch2_max_per_pay_to 2", str(e.exception))
        self.assertEqual((w.hub.committed_sat(), sorted(w.hub.out.chans)), (200_000, [a, b]))
        self.assertNotIn(c, w.hub.out.chans)                       # nothing written ahead, nothing funded
        # a closed one frees its place
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.lock(a, 40)["status"], "paid")
        w.hub.close_ch2(w.hub.out.chans[a])
        self.assertEqual(w.hub.connect(c).origin, c)
        self.assertEqual((HubConfig().ch2_max_per_pay_to, HubConfig.from_dict({"ch2_max_per_pay_to": 0}).ch2_max_per_pay_to),
                         (8, 0))

    def test_the_liquidity_cap_counts_every_process(self):
        w = W(2, connect=False, hkw={"liquidity_cap_sat": 150_000})
        a, b = w.origins
        w.hub.connect(a)
        with self.assertRaises(ChannelError) as e:
            w.hub.connect(b)
        self.assertEqual(e.exception.code, "liquidity_cap")

    def test_the_book_survives_a_restart_per_origin(self):
        w = W(2)
        a, b = w.origins
        d = os.path.dirname(w.hub.out.path)
        h2 = RouteHub(w.node, 0x4B4B, R.NET, d, w.node.fund_address, http=w.net.http)
        self.assertEqual(h2.routing_extra()["providers"], [a, b])
        self.assertEqual((h2.connect(b).origin, h2.connect(a).origin), (b, a))
        self.assertEqual(h2.committed_sat(), 200_000)


# --- 2 rollover relay ---------------------------------------------------------------------------------------

class RolloverRelay(unittest.TestCase):
    def roll(self, **hkw):
        w = W(1, lagging=True, hkw=hkw or None)
        o = w.origins[0]
        self.assertEqual(w.lock(o)["status"], "paid")
        w.view.lag()                                              # from here the hub's node is behind
        acts = w.hub.watch_tick()
        self.assertIn("ch2_rollover", [a["event"] for a in acts])
        return w, o, w.hub.out.chans[o]

    def test_a_rollover_the_hubs_node_has_not_seen_yet_is_not_vanished(self):
        w, o, child = self.roll()
        txid = child.p().funding_txid
        self.assertIsNone(w.view.gettxout(txid, 1, True))          # the hub's node: not yet
        self.assertIsNotNone(w.node.gettxout(txid, 1, True))       # the provider's: in its mempool
        self.assertEqual((child.state, child.fund_seen, bool(child.zero_conf)), ("open", False, True))
        for _ in range(3):
            acts = w.hub.watch_tick()
            self.assertEqual([a for a in acts if a["event"].startswith("ch2_rollover")], [])
        self.assertEqual((child.state, child.blocked), ("open", ""))
        self.assertEqual(w.lock(o)["status"], "paid")              # routing never paused
        self.assertEqual(w.pay.stats["refused"], {})
        w.view.lag(False)                                          # relayed
        w.hub.watch_tick()
        self.assertTrue(child.fund_seen)
        # seen and then gone is a vanished rollover, grace or not (AGP-053)
        w.node.evict(txid)
        acts = w.hub.watch_tick()
        self.assertIn("ch2_rollover_vanished", [a["event"] for a in acts])
        self.assertEqual(child.blocked, ROLLOVER_GONE)

    def test_a_rollover_never_relayed_is_blocked_after_the_grace(self):
        w, o, child = self.roll(rollover_relay_grace=0.3)
        self.assertEqual([a for a in w.hub.watch_tick() if a["event"] == "ch2_rollover_vanished"], [])
        self.assertEqual(child.blocked, "")
        time.sleep(0.35)
        acts = w.hub.watch_tick()
        self.assertIn("ch2_rollover_vanished", [a["event"] for a in acts])
        self.assertEqual(child.blocked, ROLLOVER_GONE)
        r = w.lock(o)
        self.assertEqual((r["error"], r["detail"]), ("route_blocked", ROLLOVER_GONE))
        w.view.lag(False)                                          # it arrives after all
        acts = w.hub.watch_tick()
        self.assertIn("ch2_rollover_back", [a["event"] for a in acts])
        self.assertEqual((child.blocked, child.fund_seen), ("", True))

    def test_a_hub_on_the_providers_node_sees_it_at_once(self):
        w = W(1)
        o = w.origins[0]
        self.assertEqual(w.lock(o)["status"], "paid")
        w.hub.watch_tick()
        child = w.hub.out.chans[o]
        self.assertTrue(child.fund_seen and child.rolled_at > 0)
        w.node.evict(child.p().funding_txid)                       # no grace for a rollover it saw
        self.assertIn("ch2_rollover_vanished", [a["event"] for a in w.hub.watch_tick()])

    def test_a_record_without_rolled_at_gets_no_grace(self):
        w, o, child = self.roll()
        with w.hub.out.lock:
            child.rolled_at = 0.0                                  # a book written before AGP-056
        self.assertIn("ch2_rollover_vanished", [a["event"] for a in w.hub.watch_tick()])


# --- 3 settle floor -------------------------------------------------------------------------------------------

class SettleFloor(unittest.TestCase):
    def run_locks(self, k, n=12, **pkw):
        w = W(1, hkw={"settle_lock_multiple": k}, settle_lock_multiple=k, **pkw)
        o = w.origins[0]
        for _ in range(n):
            r = w.lock(o)
            self.assertEqual(r["status"], "paid", r)
            w.block()                                             # confirm, then roll over if due
        return w, o

    def test_rollovers_per_lock_fall_from_one_to_one_in_k(self):
        # the provider settles at 2 x 600 = 1,200 sat net; every lock is 2,000 sat
        w0, o = self.run_locks(0)
        self.assertEqual(len(w0.rollovers()), 12)                  # before: a rollover on every lock
        w4, o = self.run_locks(4)
        self.assertEqual(len(w4.rollovers()), 12 // 4)
        self.assertEqual([e["amount"] for e in w4.rollovers()], [4 * LOCK] * 3)
        self.assertEqual(w4.hub.out.chans[o].max_lock, LOCK)       # carried over the rollovers
        self.assertEqual((w0.pay.stats["refused"], w4.pay.stats["refused"]), ({}, {}))
        self.assertEqual((HubConfig().settle_lock_multiple, HubConfig().settle_idle), (4, 600.0))

    def test_never_below_the_providers_threshold(self):
        # locks of 200 sat: 4 x 200 is under the provider's 1,200 net, which stays the least it co-signs
        w = W(1, hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4)
        o = w.origins[0]
        for i in range(9):
            self.assertEqual(w.lock(o, 5)["status"], "paid")
            w.block()
            self.assertEqual(len(w.rollovers()), 1 if i >= 8 else 0, i)   # 9 x 200 = 1,800 - 600 = 1,200 net
        self.assertEqual(w.hub.stats["refused"], {})

    def test_an_idle_ch2_rolls_over_at_the_providers_threshold(self):
        w = W(1, hkw={"settle_lock_multiple": 4, "settle_idle": 0.3}, settle_lock_multiple=4)
        o = w.origins[0]
        self.assertEqual(w.lock(o)["status"], "paid")
        w.block()
        self.assertEqual(w.rollovers(), [])                        # due at the provider's threshold, held by the floor
        time.sleep(0.35)
        w.block()
        self.assertEqual([e["amount"] for e in w.rollovers()], [LOCK])

    def test_never_so_late_that_the_next_lock_does_not_fit(self):
        # capacity 110,000, locks of 30,000: 4 x 30,000 does not fit. After three locks a fourth would not
        # fit either, so the ch2 is due at 90,000. The 20,000 left is the provider's minimum capacity, but
        # could not take one more lock: the ch2 is closed and refilled, never left exhausted
        w = W(1, hkw={"settle_lock_multiple": 4, "max_lock_sat": 50_000, "ch2_capacity": 110_000},
              settle_lock_multiple=4, amsat_per_call=400 * AMSAT_PER_SAT)
        o = w.origins[0]
        for i in range(3):
            self.assertEqual(w.lock(o, 75)["status"], "paid")
            acts = w.block()
            self.assertEqual([a["event"] for a in acts if a["event"] in ("ch2_rollover", "ch2_close")],
                             ["ch2_close"] if i == 2 else [], i)
        new = w.hub.out.chans[o]
        self.assertEqual((new.state, new.p().capacity, new.rolled_from), ("funded", 110_000, ""))
        w.block()
        self.assertEqual(w.lock(o, 75)["status"], "paid")
        self.assertEqual((w.pay.stats["refused"], w.hub.stats["refused"]), ({}, {}))

    def test_a_child_too_small_for_the_next_lock_is_refilled_not_rolled(self):
        # capacity 100,000, locks of 20,000, k = 2: due at 40,000 (child 60,000), again at 40,000 (child
        # 20,000: one lock fits, a rollover), and then nothing fits: close and refill
        w = W(1, hkw={"settle_lock_multiple": 2}, settle_lock_multiple=2, amsat_per_call=400 * AMSAT_PER_SAT)
        o = w.origins[0]
        seen = []
        for _ in range(6):
            self.assertEqual(w.lock(o)["status"], "paid")
            seen += [a["event"] for a in w.block() if a["event"] in ("ch2_rollover", "ch2_close")]
            w.block()
        self.assertEqual(seen, ["ch2_rollover", "ch2_rollover", "ch2_close"])
        self.assertEqual((w.pay.stats["refused"], w.hub.stats["refused"]), ({}, {}))

    def test_the_providers_zero_conf_cap_follows_the_largest_lock(self):
        # cmp R14: cap 2 x 20 x 600 = 24,000 against locks of 7k-36k: the first lock on an unconfirmed
        # child was refused. Default cap: at least 2 x 4 x the largest lock; an explicit one is kept
        w = W(1, hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4)
        o = w.origins[0]
        for _ in range(4):
            self.assertEqual(w.lock(o)["status"], "paid")
        w.hub.watch_tick()
        child = w.hub.out.chans[o]
        self.assertEqual((child.state, child.zero_conf["maxCum"]), ("open", 2 * 4 * LOCK))
        for _ in range(4):                                         # 8,000 sat on the unconfirmed child
            self.assertEqual(w.lock(o)["status"], "paid")
        st = w.provs[o].ledger.channels[child.p().channel_id]
        self.assertEqual((st.extra["max_lock"], st.extra["zero_conf"]["maxCum"]), (LOCK, 16_000))
        w2 = W(1, hkw={"settle_lock_multiple": 4}, settle_lock_multiple=4, rollover_zero_conf_max=3_000)
        o = w2.origins[0]
        for _ in range(4):
            self.assertEqual(w2.lock(o)["status"], "paid")
        w2.hub.watch_tick()
        self.assertEqual(w2.hub.out.chans[o].zero_conf["maxCum"], 3_000)


# --- 4 refusal detail -------------------------------------------------------------------------------------------

class RefusalDetail(unittest.TestCase):
    def test_route_payer_returns_the_hubs_detail(self):
        w = W(1)
        o = w.origins[0]
        with w.hub.out.lock:
            w.hub.out.chans[o].blocked = "the provider did not reveal a lock in time"
        r = w.lock(o, 5)
        self.assertEqual(r, {"status": "refused", "error": "route_blocked",
                             "detail": "the provider did not reveal a lock in time"})

    def test_a_rollover_child_the_provider_did_not_take_unconfirmed_says_so(self):
        # what cmp's R14 saw between a rollover and the next block (its provider refused every unconfirmed
        # open): route_blocked, now with the reason
        w = W(1, rollover_zero_conf_max=0)
        o = w.origins[0]
        self.assertEqual(w.lock(o)["status"], "paid")
        w.hub.watch_tick()
        self.assertEqual(w.hub.out.chans[o].state, "funded")
        r = w.lock(o, 5)
        self.assertEqual(r, {"status": "refused", "error": "route_blocked", "detail":
                             "no open channel to that provider: its ch2 is a rollover the provider takes once it confirms"})
        w.block()
        self.assertEqual(w.lock(o, 5)["status"], "paid")

    def test_a_providers_refusal_reaches_the_client_with_its_code(self):
        w = W(1)
        o = w.origins[0]
        R.stream(w.pay, w.sh[o], 5)
        del w.provs[o].routes.sessions[w.sh[o].session]            # the provider lost the session
        r = w.pay.lock(w.sh[o])
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"))
        self.assertEqual(r["detail"], "provider refused the lock: unknown_session")
        self.assertEqual(w.hub.stats["refused"], {"unknown_session": 1})

    def test_a_providers_detail_is_sanitized(self):
        w = W(1)
        o = w.origins[0]
        prov = w.provs[o]

        class Evil:
            def serve(self, method, path, headers, body, url=""):
                if path == ROUTE_LOCK_PATH:
                    return 400, {}, b'{"error": "bad_invoice", "detail": "x\\u001b[31m\\n' + b"y" * 400 + b'"}'
                return prov.serve(method, path, headers, body, url)
        w.net.apps[o] = Evil()
        r = w.lock(o, 5)
        self.assertEqual(r["error"], "route_failed")
        self.assertTrue(r["detail"].startswith("provider refused the lock: bad_invoice (x[31my"), r["detail"])
        self.assertTrue(all(" " <= ch <= "~" for ch in r["detail"]) and len(r["detail"]) < 220)


if __name__ == "__main__":
    unittest.main()
