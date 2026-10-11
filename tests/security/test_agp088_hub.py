"""AGP-088 (fix wave 4, hub): tests of the fixes to the second closure audit's hub items, for the parts
the audit described from reading or that sit one step beside its own tests (test_agp087_hub_a.py,
test_agp087_hub_b.py). xbt-rs has the same tests (crates/xbt402-interop/tests/agp088_hub.rs).

The harness is test_agp087_hub_a.py's, with two more switches on the provider as the hub sees it
(`pay_to`: its /terms name another payTo and its preflight says yes; `fake_close`: it answers the hub's
close request with a close it never sends).
"""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402
import test_agp084_hub_leftovers as L  # noqa: E402
import test_agp087_hub_a as A  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402.hub import NONFINAL, OutBook, watched  # noqa: E402
from xbt402.hub_keys import WrapKey  # noqa: E402
from xbt402.route import HUB_ROUTE_PATH, HUB_VIEW_PATH, ROUTE_LOCK_PATH, TERMS_PATH, fee_due  # noqa: E402
from xbt402.x402_channel import MAX_KEPT_INTENTS, b64json  # noqa: E402

CLOSE_PATH = A.CLOSE_PATH
COUNTERS = (("routed_sat", "routed"), ("fee_units", "units"), ("fee_paid", "paid"))


class Sw(A.Deaf):
    pay_to = None          # its /terms name this payTo, and it answers an open preflight with yes
    fake_close = None      # (txid, cum, fee): it answers the hub's close request 200 with these and sends nothing

    def serve(self, method, path, headers, body, url):
        js = {"Content-Type": "application/json"}
        if path == CLOSE_PATH and self.fake_close and not self.deaf:
            txid, cum, fee = self.fake_close
            return 200, js, json.dumps({"txid": txid, "cum": str(cum), "payeeFee": fee, "payeeNet": cum - fee, "status": "closed"}).encode()
        if self.pay_to:
            if path == TERMS_PATH:
                _, _, out = self.inner.serve(method, path, headers, body, url)
                return 200, js, json.dumps({**json.loads(out), "payTo": self.pay_to}).encode()
            try:
                if json.loads(body or b"{}").get("preflight") is True:
                    return 200, js, b'{"preflight": true, "closeFeePayer": "payee"}'
            except (ValueError, AttributeError):
                pass
        return super().serve(method, path, headers, body, url)


class W(A.W):
    def __init__(self, blocks, hkw=None, pkw=None, price=T.PRICE, settle_multiple=20):
        self.node, self.net = R.RouteNode(), R.Net()
        self.hub = R.hub(self.node, self.net, **{"reveal_timeout": 0.3, **(hkw or {})})
        self.origins, self.provs = [], []
        for i, b in enumerate(blocks):
            o = f"http://p{i}.test"
            w = Sw(R.provider(self.node, self.net, o, amsat_per_call=price, settle_multiple=settle_multiple))
            self.net.apps[o] = w
            self.hub.connect(o, expiry_blocks=b)
            self.origins.append(o)
            self.provs.append(w)
        self.node.confirm_all()
        self.hub.watch_tick()
        self.pay = R.payer(self.node, self.net, **(pkw or {}))
        self.pay.open()
        self.shards = [self.pay.shard(o + "/v1/chunk") for o in self.origins]

    def oc(self, i):
        return self.hub.out.chans[self.origins[i]]

    def events(self, name):
        return [e for e in self.hub.events if e.get("event") == name]

    def held_lock(self, i):
        """p`i` takes a lock and keeps it without revealing: written off on its ch2 and held on ch1."""
        self.provs[i].inner.routes.no_reveal = True
        r = self.lock(i)
        assert (r["status"], r["error"]) == ("refused", "route_failed"), r
        held = self.stale1()[-1]
        assert isinstance(held.get("hold"), dict) and len(self.oc(i).stale) == 1, "control: written off on the ch2, held on ch1"
        return dict(held)

    def back_in_flight(self, i, held):
        """Put the written-off lock `held` (of p`i`'s ch2) back where a hub that stopped mid-route leaves
        it: route_lock on ch1, nothing held, and pending on the ch2, which routes again."""
        st1 = self.st1()
        with self.hub.inbound.ledger.lock:
            ex = dict(st1.extra)
            rl = {k: v for k, v in held.items() if k not in ("hold", "voided")}
            for k, a in COUNTERS:
                ex[k] = int(ex.get(k, 0)) - int(held["hold"][a])
            ex["route_lock"], ex["stale_locks"] = rl, []
            st1.extra = ex
            self.hub.inbound.ledger.save(st1)
        oc = self.oc(i)
        with self.hub.out.lock:
            oc.pending = {k: v for k, v in oc.stale.pop(0).items() if k not in ("voided", "why")}
            oc.blocked = ""
            self.hub.out.save()

    def provider_closes(self, i):
        return T.close_now(self.provs[i].inner, self.st2(i))

    def pending_anywhere(self):
        with self.hub.out.lock:
            live = list(self.hub.out.chans.values()) + list(self.hub.out.next_chans.values())
            return sum(1 for c in live if c.pending) + sum(1 for r in self.hub.out.archived if r.get("pending"))

    def route_calls(self, path):
        return sum(1 for c in self.net.calls if c[2] == path)


def has(acts, name, **kw):
    return any(a.get("event") == name and all(a.get(k) == v for k, v in kw.items()) for a in acts)


class OneLockPerLockId(unittest.TestCase):
    def test_a_lock_under_a_lock_id_ch1_holds_written_off_is_refused(self):
        # The audit's steps for two written-off locks under one lockId: p0's lock is written off and
        # held, then p1 names the same lockId in its invoice. The hub now refuses that lock before it
        # pre-signs anything on p1's ch2, and tells the client what it holds.
        w = W([None, None])
        w.paid(1)
        w.provs[0].refuse = True
        self.assertEqual(w.lock(0)["error"], "route_failed")
        lid = w.stale1()[0]["lockId"]
        base, sent = w.base1(), w.lock_calls()
        w.invoice_lock_id(1, lid)
        r = w.lock(1)
        self.assertEqual((r["status"], r["error"]), ("refused", "lock_held"), r)
        self.assertEqual(w.lock_calls(), sent, "nothing went to p1")
        oc1 = w.oc(1)
        self.assertTrue(not oc1.pending and not oc1.stale, "nothing was pre-signed on p1's ch2")
        self.assertEqual((len(w.stale1()), w.base1()), (1, base), "ch1 holds the one lock, as before")
        self.assertEqual(w.counters()[:3], base, "the client's counters are the hub's")
        # p1's next invoice has a lockId of its own: paid, above the held lock
        R.stream(w.pay, w.shards[1], 3)
        for s in w.provs[1].inner.routes.sessions.values():
            s.valid_until = 0.0
        R.stream(w.pay, w.shards[1], 3)
        r = w.pay.lock(w.shards[1])
        self.assertEqual(r["status"], "paid", r)
        self.assertGreater(w.st1().best_cum, w.stale1()[0]["cum"])


class InABlock(unittest.TestCase):
    def test_a_hold_on_an_unconfirmed_child_is_released_once_its_close_is_in_a_block(self):
        # the audit's unconfirmed child, to the end: nothing leaves ch1 while the close is in the
        # mempool, and the hold does leave once the rollover and the close are in a block
        w = W([None], price=40 * 10 ** 21, settle_multiple=2)

        def lock(calls):
            R.stream(w.pay, w.shards[0], calls)
            return w.pay.lock(w.shards[0])
        self.assertEqual(lock(50)["status"], "paid")
        self.assertTrue(has(w.hub.watch_tick(), "ch2_rollover"))
        child = w.oc(0)
        self.assertTrue(child.state == "open" and child.zero_conf and not child.zero_conf.get("confirmed"), "control: an unconfirmed child")
        self.assertEqual(lock(5)["status"], "paid")
        w.provs[0].inner.routes.no_reveal = True
        self.assertEqual(lock(5)["error"], "route_failed")
        routed = w.routed()
        close = T.close_now(w.provs[0].inner, w.provs[0].inner.ledger.channels[child.p().channel_id])
        for _ in range(2):
            acts = w.hub.watch_tick()
            self.assertFalse(has(acts, "lock_released") or has(acts, "ch2_closed"), acts)
        self.assertEqual((child.state, child.final, len(w.stale1()), w.routed()), ("closing", False, 1, routed), "nothing is in a block")
        w.node.confirm_all()
        self.assertTrue(w.node.confirmed(close))
        acts = w.hub.watch_tick() + w.hub.watch_tick()
        self.assertTrue(has(acts, "lock_released", held=True), acts)
        self.assertEqual((child.state, child.final, len(w.stale1())), ("closed", True, 0))
        self.assertLess(w.routed(), routed, "the hold left ch1's base")


class RolledAndRefill(unittest.TestCase):
    def test_a_rolled_ch2_is_watched_until_its_rollover_is_in_a_block(self):
        w = W([None], price=40 * 10 ** 21, settle_multiple=2)
        parent = w.oc(0)
        R.stream(w.pay, w.shards[0], 50)
        self.assertEqual(w.pay.lock(w.shards[0])["status"], "paid")
        self.assertTrue(has(w.hub.watch_tick(), "ch2_rollover"))

        def rec():
            return next(r for r in w.hub.out.archived if r["params"]["payer_pub"] == parent.params["payer_pub"])
        w.hub.watch_tick()
        r = rec()
        self.assertEqual((r["state"], r["final"], watched(r)), ("rolled", False, True), "in the mempool: still watched")
        w.node.confirm_all()
        w.hub.watch_tick()
        r = rec()
        self.assertEqual((r["state"], r["final"], watched(r)), ("rolled", True, False), "in a block: done")
        self.assertEqual(w.hub.committed_sat(), w.oc(0).p().capacity, "the coins are counted once, in the child")

    def test_a_ch2_rolled_before_agp088_is_left_final_and_one_rolled_since_is_watched(self):
        # `rolled` is now a state the watcher reconciles until the rollover is in a block. A record
        # rolled by a hub from before (it has no fund_confirmed) was never watched again, and is not
        # read against the chain from its first block on every tick now
        self.assertIn("rolled", NONFINAL)
        w = W([None])
        path, wrap = w.hub.out.path, w.hub.out.wrap
        old = {"origin": "http://p9.test", "state": "rolled", "final": False, "params": {}, "secret": ""}
        with open(path) as f:
            doc = json.load(f)
        doc["archived"] = [dict(old), {**old, "fund_confirmed": True}]
        with open(path, "w") as f:
            json.dump(doc, f)
        b = OutBook(path, wrap)
        self.assertIsInstance(wrap, WrapKey)
        self.assertEqual([watched(r) for r in b.archived], [False, True], b.archived)

    def test_the_refill_follows_a_close_once_this_node_shows_it(self):
        # the provider answers the hub's close with a close it has not sent. No refill is funded on
        # that answer; it is funded when the hub's own node shows the funding spent, within the cap
        w = W([None], hkw={"liquidity_cap_sat": 100_000})          # one ch2
        w.paid(0)
        oc = w.oc(0)
        w.provs[0].fake_close = ("ab" * 32, oc.signed, oc.p().payee_fee)
        ev = w.hub.close_ch2(oc, refill=True)
        self.assertTrue(str(ev.get("refillError", "")).startswith("deferred"), f"the refill was funded on the provider's word: {ev}")
        for _ in range(2):
            w.hub.watch_tick()
        self.assertTrue(w.oc(0) is oc and oc.state == "closing" and w.hub.committed_sat() == 100_000, "its coins still count")
        self.assertEqual(L.code_of(w.hub.connect, w.origins[0]), "liquidity_cap", "and nobody funds past the cap meanwhile")
        # the provider closes after all: this node shows it, and the refill follows
        w.provs[0].fake_close = None
        close = w.provider_closes(0)
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, "ch2_closing", txid=close), acts)
        self.assertTrue(any(a.get("event") == "ch2_refill" and "refillError" not in a for a in acts), acts)
        new = w.oc(0)
        self.assertTrue(new is not oc and new.state == "funded", new.state)
        self.assertEqual(w.hub.committed_sat(), 100_000, "the old ch2's coins are leaving, the new one's count")
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(len(w.events("ch2_refill")), 1, "once")


class WhatTheClientBelieves(unittest.TestCase):
    def test_a_completion_the_hub_claims_is_adopted_only_with_the_secret_that_opens_the_lock(self):
        # a lock the hub refused outright, then a view that says its best state is that lock: exactly
        # what a hub that completed it says, and what one that only wants the client's next lock quoted
        # a lock higher says too. Only the first can show t + r
        w = W([None])
        w.paid(0)
        with w.hub.out.lock:
            w.oc(0).blocked = "closed for the test"
        c0 = w.counters()
        r = w.lock(0)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_blocked"), r)
        g = w.pay.given_up[-1]
        claim = {"bestCum": g["cum"], "routedSat": g["after"][0], "feeUnits": g["after"][1], "feePaid": g["after"][2],
                 "held": [], "released": []}
        self.assertGreater(g["cum"], c0[3], "control: the lock was signed above the last paid state")
        self.assertFalse(w.pay._resync(dict(claim)), "a completion was adopted on the hub's word")
        self.assertFalse(w.pay._resync({**claim, "secret": f"{0x1234:064x}"}), "a completion was adopted with a secret that does not open the lock")
        self.assertEqual(w.counters(), c0, "nothing moved")

    def test_at_max_held_locks_nothing_more_is_signed_until_the_view_shows_a_hold_resolved(self):
        w = W([600, None], pkw={"max_held_locks": 1, "held_probe_secs": 0.0})
        w.paid(1)
        w.provs[0].refuse = w.provs[0].deaf = True
        self.assertEqual(w.lock(0)["error"], "route_failed")
        signed, held = w.counters(), dict(w.stale1()[0])
        self.assertEqual(signed[0], w.base1()[0], "control: the one hold is adopted")
        # p1 is owed, and nothing is pre-signed for it above the hold
        R.stream(w.pay, w.shards[1], 10)
        routes = w.route_calls(HUB_ROUTE_PATH)
        for _ in range(3):
            self.assertIsNone(w.pay.lock(w.shards[1]))
        self.assertEqual((w.route_calls(HUB_ROUTE_PATH), w.counters()), (routes, signed), "a lock was sent at the cap")
        self.assertGreaterEqual(w.route_calls(HUB_VIEW_PATH), 3, "it asked for the view")
        # p0's ch2 is refunded: the hold is released, the view says so, and p1 is paid
        w.node.height = w.oc(0).p().expiry + 10
        w.hub.watch_tick()
        w.node.confirm_all()
        self.assertTrue(has(w.hub.watch_tick(), "lock_released"))
        self.assertEqual(w.pay.lock(w.shards[1]), {"status": "resynced"})
        self.assertEqual(w.counters()[0], signed[0] - T.d_plus_f(held))
        R.stream(w.pay, w.shards[1], 3)
        self.assertEqual(w.pay.lock(w.shards[1])["status"], "paid")
        self.assertEqual(w.counters()[:3], w.base1())

    def test_the_view_is_answered_to_ch1s_own_auth_and_spends_its_seq(self):
        w = W([None])
        w.paid(0)
        url = R.HUB + HUB_VIEW_PATH

        def ask(seq):
            pl = {"chan": w.pay.chan, "seq": seq, "cum": "0"}
            w.pay.cc._auth(w.pay.ch, pl, "POST", url, b"")
            hdr = b64json({"x402Version": 2, "accepted": w.pay.ch.accepted, "payload": pl})
            st, _, out = w.hub.serve("POST", HUB_VIEW_PATH, {"PAYMENT-SIGNATURE": hdr}, b"", url)
            return st, json.loads(out)
        w.pay.ch.seq += 1
        seq = w.pay.ch.seq
        st, doc = ask(seq)
        st1 = w.st1()
        self.assertEqual((st, doc["bestCum"], doc["routedSat"]), (200, st1.best_cum, w.routed()), doc)
        self.assertEqual(len(doc.get("secret", "")), 64, f"the proof of the lock at its best state: {doc}")
        self.assertEqual(ask(seq)[0], 401, "the same seq again")
        self.assertEqual(w.st1().seq, seq, "and that seq is on disk")
        self.assertEqual(w.hub.serve("POST", HUB_VIEW_PATH, {}, b"", url)[0], 400)


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

    def test_a_stop_between_the_ch1_release_and_the_ch2_record_is_finished_by_the_next_tick(self):
        # The release wrote the ch2 record first and ch1 second: a stop between them left ch1 holding a
        # lock that no ch2 record named any more, for good. Now ch1 goes first and the record is final
        # last, so the same stop leaves a ch2 the next tick finishes, and nothing is given back twice.
        w = W([600])
        w.paid(0)
        base = w.base1()
        w.provs[0].refuse = w.provs[0].deaf = True
        self.assertEqual(w.lock(0)["error"], "route_failed")
        self.assertGreater(w.base1()[0], base[0])
        oc = w.oc(0)
        w.node.height = oc.p().expiry + 10
        self.assertTrue(has(w.hub.watch_tick(), "ch2_refund"))
        w.node.confirm_all()
        w.hub.stop_at = "release"
        w.hub.watch_tick()
        self.assertEqual((len(w.stale1()), w.base1(), len(oc.stale), oc.final), (0, base, 1, False), "stopped after ch1, before the ch2 record")
        w.hub.stop_at = ""
        w.hub.watch_tick()
        w.hub.watch_tick()
        self.assertEqual((oc.state, len(oc.stale), oc.final), ("refunded", 0, True))
        self.assertEqual((len(w.stale1()), w.base1(), len(w.events("lock_released"))), (0, base, 1), "released once")
        self.assertEqual(L.code_of(w.pay.close), "", "nothing unresolved keeps ch1 open")

    def test_a_lock_pending_on_a_ch2_that_is_closing_is_written_off_and_resolved(self):
        # The hub stops with a lock in flight; when it is back the provider's close of that ch2, at the
        # state before the lock, is in the mempool. The watcher asks again for a pending lock only on an
        # open ch2, so nobody wrote this one off: ch1 kept its lock in flight (no route, no close) until
        # its margin, and the ch2 ended final with the lock still pending.
        w = W([None])
        w.paid(0)
        base, held = w.base1(), w.held_lock(0)
        w.back_in_flight(0, held)
        oc = w.oc(0)
        self.assertEqual((w.base1(), bool(oc.pending)), (base, True), "control: in flight, nothing held")
        close = w.provider_closes(0)
        acts = w.hub.watch_tick() + w.hub.watch_tick()
        self.assertTrue(has(acts, "ch2_closing") and has(acts, "lock_written_off"), acts)
        stale = w.stale1()
        self.assertTrue(not oc.pending and len(oc.stale) == 1 and len(stale) == 1 and isinstance(stale[0].get("hold"), dict),
                        f"written off on the ch2, held on ch1: {stale}")
        self.assertEqual((w.base1()[0], w.st1().extra.get("route_lock")), (base[0] + T.d_plus_f(held), None))
        self.assertEqual(L.code_of(w.pay.close), "lock_pending", "its pre-signature may be out: ch1 does not close below it")
        # the close confirms without t: the lock was not paid
        w.node.confirm_all()
        self.assertTrue(w.node.confirmed(close))
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, "lock_released", held=True), acts)
        self.assertEqual((oc.state, oc.final, bool(oc.pending), len(w.stale1()), w.base1()), ("closed", True, False, 0, base))
        self.assertEqual(L.code_of(w.pay.close), "", "nothing unresolved keeps ch1 open")

    def test_a_ch2_with_a_lock_pending_is_not_replaced_when_its_pay_to_changes(self):
        # connect() (an embedder's refill, an operator) with the provider's /terms now naming another
        # payTo archived the origin's ch2 whatever it carried. With a lock pending on it the route that
        # sent the lock no longer found it, and the sweep took ch1's lock for an orphan and dropped it
        # while the ch2 pre-signature was out.
        w = W([None])
        w.paid(0)
        held = w.held_lock(0)
        w.back_in_flight(0, held)
        oc = w.oc(0)
        w.provs[0].pay_to = ecc.pubkey(0x7777).hex()
        self.assertEqual(L.code_of(w.hub.connect, w.origins[0]), "lock_pending")
        self.assertTrue(w.oc(0) is oc and oc.pending and not w.hub.out.archived, "the ch2 kept its place and its lock")
        w.hub.watch_tick()
        self.assertTrue(w.st1().extra.get("route_lock") or len(w.stale1()) == 1, "ch1's lock was dropped as an orphan")

    def test_a_next_ch2_does_not_take_over_from_under_a_pending_lock(self):
        # the same through the switch: the live ch2 is closing (the provider's close is in the mempool)
        # with a lock pending, and the origin's next ch2 is open. It takes over only once that lock is
        # written off, so no archived ch2 ever carries a pending lock
        w = W([None])
        w.paid(0)
        base = w.base1()
        w.hub.connect_next(w.origins[0])
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.hub.out.next_chans[w.origins[0]].state, "open")
        held = w.held_lock(0)
        w.back_in_flight(0, held)
        old = w.oc(0)
        close = w.provider_closes(0)
        w.hub.watch_tick()
        self.assertTrue(w.oc(0) is old and old.state == "closing" and w.pending_anywhere() == 1, "it kept its place")
        w.hub.watch_tick()
        self.assertTrue(w.oc(0) is not old and w.pending_anywhere() == 0, "written off, then replaced")
        self.assertEqual((len(w.stale1()), w.base1()[0]), (1, base[0] + T.d_plus_f(held)), "held on ch1")
        w.node.confirm_all()
        self.assertTrue(w.node.confirmed(close))
        self.assertTrue(has(w.hub.watch_tick(), "lock_released"))
        self.assertEqual((len(w.stale1()), w.base1()), (0, base))


if __name__ == "__main__":
    unittest.main()
