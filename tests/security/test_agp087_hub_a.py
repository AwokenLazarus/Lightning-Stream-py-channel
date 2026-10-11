"""AGP-087, area HUB-A (the hub's ch1 side): tests of the second closure audit of the external review.
xbt-rs has the same tests (crates/xbt402-interop/tests/agp087_hub_a.rs).

Tests named `test_hole_*` FAIL on master 21b21db: each one shows a hole. The others pass and are
evidence for a "fixed" verdict that had no test.
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
import test_agp064_hub_safety as T  # noqa: E402  (the AGP-064 harness: W, Wrapped)
import test_agp084_hub_leftovers as L  # noqa: E402  (errored_spend, down, code_of)

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.route import HUB_ROUTE_PATH, ROUTE_LOCK_PATH, FeeQuote, fee_due  # noqa: E402
from xbt402.x402_channel import MAX_KEPT_INTENTS, unb64json  # noqa: E402

CLOSE_PATH = "/x402/xbt-channel/close"


class Deaf(T.Wrapped):
    """T.Wrapped, and `deaf`: the provider answers the hub's close request with a 400 (it keeps its
    pre-signature and closes when it likes)."""
    deaf = False

    def serve(self, method, path, headers, body, url):
        if path == CLOSE_PATH and self.deaf:
            return 400, {"Content-Type": "application/json"}, b'{"error":"refused","detail":"later"}'
        return super().serve(method, path, headers, body, url)


class W(T.W):
    def __init__(self, blocks):
        super().__init__(blocks)
        for i, o in enumerate(self.origins):
            d = Deaf(self.provs[i].inner)
            self.provs[i] = self.net.apps[o] = d

    def invoice_lock_id(self, i, lock_id):
        """p`i` (a colluding provider) names `lock_id` in its next invoice. An invoice's lockId is the
        provider's to choose; the hub takes it as it comes."""
        for s in self.provs[i].inner.routes.sessions.values():
            s.lock_id, s.valid_until = lock_id, time.time() + 8.0

    def base1(self):
        ex = self.st1().extra or {}
        return tuple(int(ex.get(k, 0)) for k in ("routed_sat", "fee_units", "fee_paid"))

    def paid_out(self, provs):
        return sum(s.best_cum for i in provs for s in self.provs[i].inner.ledger.channels.values() if s.closed_txid)


def two_written_off_locks_under_one_lock_id(tc, blocks):
    """Two written-off locks on one ch1 that carry the same lockId, each over its own ch2, both held
    in ch1's base. p1 keeps its pre-signature and refuses the hub's close request.

    AGP-088: the hub no longer lets the second lock in under that lockId (lock_held:
    test_agp088_hub.py, test_a_lock_under_a_lock_id_ch1_holds_written_off_is_refused), so the audit's
    way of making the pair (p1 names p0's lockId in its invoice) now ends at that refusal. The pair is
    put in the ledgers as a hub from before left it: p1's lock is written off under its own lockId and
    then carries p0's, on ch1 and on p1's ch2. The controls and everything after are the audit's."""
    w = W(blocks)
    w.paid(1)                                     # ch1 has a state to close with
    w.provs[0].refuse = True
    r = w.lock(0)
    tc.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
    lid = w.stale1()[0]["lockId"]
    w.provs[1].refuse = w.provs[1].deaf = True
    r = w.lock(1)
    tc.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
    # the second lock under the first one's lockId (its own T, its own ch2)
    st1 = w.st1()
    with w.hub.inbound.ledger.lock:
        st1.extra["stale_locks"][1]["lockId"] = lid
        w.hub.inbound.ledger.save(st1)
    with w.hub.out.lock:
        w.hub.out.chans[w.origins[1]].stale[0]["lockId"] = lid
        w.hub.out.save()
    stale = w.stale1()
    tc.assertEqual(len(stale), 2, "control: both locks are written off and kept on ch1")
    tc.assertTrue(all(s["lockId"] == lid and isinstance(s.get("hold"), dict) for s in stale), "control: one lockId, both held")
    tc.assertNotEqual(stale[0]["T"], stale[1]["T"], "control: two different locks")
    tc.assertEqual(len(w.hub.out.chans[w.origins[1]].stale), 1, "control: p1's ch2 holds its written-off lock")
    tc.assertEqual(L.code_of(w.pay.close), "lock_pending", "control: ch1 cannot close below the two locks")
    return w


def client_closes_then_p1_uses_its_pre_signature(w):
    """(the close's refusal code or "", what ch1 collected, what the hub's ch2s paid out) after the
    client closes ch1 and p1 then closes its ch2 with the pre-signature it kept."""
    code = L.code_of(w.pay.close)
    T.close_now(w.provs[1].inner, w.st2(1))
    w.hub.watch_tick()
    w.node.confirm_all()
    w.hub.watch_tick()
    return code, w.st1().best_cum, w.paid_out((0, 1))


class TwoLocksOneLockId(unittest.TestCase):
    def test_hole_h2_a_written_off_lock_is_dropped_when_another_with_its_lock_id_completes(self):
        # The lockId comes from the provider's invoice, and the hub does not refuse one that a
        # written-off lock on the same ch1 already carries. _complete_ch1 removes EVERY written-off lock
        # with that lockId when one completes: the second is gone from ch1 while its pre-signature is
        # still out on p1's ch2. Nothing keeps ch1 from closing below it, and p1's later close is paid
        # by the hub for nothing.
        w = two_written_off_locks_under_one_lock_id(self, [None, None])
        T.close_now(w.provs[0].inner, w.st2(0))   # p0 uses its pre-signature
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        self.assertEqual(len(w.hub.out.chans[w.origins[1]].stale), 1, "p1's ch2 still holds its written-off lock")
        left = len(w.stale1())
        code, collected, paid_out = client_closes_then_p1_uses_its_pre_signature(w)
        self.assertTrue(code == "lock_pending" and collected >= paid_out,
                        f"p1's written-off lock left ch1 with p0's ({left} written-off locks on ch1, 1 on p1's ch2); ch1 then "
                        f"closed ({code or 'ok'}) at {collected} sat and the hub paid {paid_out} sat on its ch2s: "
                        f"{max(0, paid_out - collected)} sat uncollected")

    def test_hole_h2_a_written_off_lock_is_dropped_when_another_with_its_lock_id_is_released(self):
        # The same through the release: p1's ch2 (the SECOND lock's) is refunded, which proves p1's lock
        # unpaid. _release_unpaid takes the FIRST written-off lock with that lockId off ch1: p0's, whose
        # pre-signature is still out. What is left on ch1 is p1's dead lock, which p0's t cannot complete.
        w = two_written_off_locks_under_one_lock_id(self, [3_000, None])
        w.provs[0].deaf = True
        oc = w.hub.out.chans[w.origins[1]]
        w.node.height = oc.p().expiry + 10
        w.hub.watch_tick()
        w.node.confirm_all()
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "lock_released" and a["held"] for a in acts), acts)
        self.assertEqual(len(w.hub.out.chans[w.origins[0]].stale), 1, "p0's ch2 still holds its written-off lock")
        left = [s["provider"] for s in w.stale1()]
        # p0 uses its pre-signature: the hub pays it on ch2 and must collect on ch1
        best = w.st1().best_cum
        T.close_now(w.provs[0].inner, w.st2(0))
        errs = []
        try:
            acts = w.hub.watch_tick()
        except Exception as e:                    # noqa: BLE001  (what the watcher does with it is the finding)
            acts, errs = [], [repr(e)]
        collected, paid_out = w.st1().best_cum, w.paid_out((0,))
        self.assertTrue(collected - best >= paid_out and left == [w.origins[0]],
                        f"p1's refund released p0's lock: ch1 kept {left}; p0 then closed its ch2 with t and was paid "
                        f"{paid_out} sat, ch1 moved by {collected - best} sat (watcher: {errs or [a.get('event') for a in acts]})")


class ResyncCompletionAndRelease(unittest.TestCase):
    """AGP-085 stated limit 5: the client's resync of a view that carries a completion and a release
    at once was implemented and had no test."""

    def case(self, first):
        # p0's ch2 is the short one (refunded: its lock is released), p1's is closed with t (its lock
        # completes), p2 takes the lock after the resync. `first`: which of the two was given up first.
        w = W([None, 3_000, 3_000])
        w.paid(2)
        base, signed0 = w.base1(), w.counters()[3]
        w.provs[0].deaf = True
        adds = {}
        for i in (first, 1 - first):
            w.net.drop[w.origins[i]] = lambda m, p: p == ROUTE_LOCK_PATH
            r = w.lock(i)
            self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
            del w.net.drop[w.origins[i]]
            adds[i] = T.d_plus_f(w.stale1()[-1])
        stale = w.stale1()
        self.assertTrue(len(stale) == 2 and all(isinstance(s.get("hold"), dict) for s in stale))
        cum1 = next(s["cum"] for s in stale if s["provider"] == w.origins[1])
        self.assertEqual(w.counters()[0], base[0] + adds[0] + adds[1], "the client adopted both holds")
        self.assertEqual(w.counters()[3], signed0, "and counts neither as signed")
        oc = w.hub.out.chans[w.origins[0]]
        w.node.height = oc.p().expiry + 10
        acts = w.hub.watch_tick()
        w.node.confirm_all()
        acts += w.hub.watch_tick()
        acts += w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "lock_released" and a["held"] for a in acts), acts)
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        self.assertEqual(w.stale1(), [])
        st1 = w.st1()
        self.assertEqual(st1.best_cum, cum1, "ch1's best state is p1's completed lock")
        self.assertEqual(w.base1()[0], base[0] + adds[1], "p1's lock stays in the base, p0's hold left it")
        # the client's next lock is refused for its amount; the view has the completion and the release
        r = w.lock(2)
        self.assertEqual(r["status"], "resynced", f"first {first}: a completion and a release in one view: {r}")
        self.assertEqual(w.counters()[:3], w.base1(), "the client's counters are the hub's")
        self.assertEqual(w.counters()[3], st1.best_cum, "the client counts the completed lock as signed, nothing above it")
        r = w.pay.lock(w.shards[2])
        self.assertEqual(r["status"], "paid", r)
        self.assertEqual(w.counters()[:3], w.base1())
        st1 = w.st1()
        self.assertEqual(w.counters()[3], st1.best_cum)
        self.assertGreaterEqual(st1.best_cum, w.counters()[0], "ch1's state covers what was routed")
        paid_out = w.st2(1).best_cum + w.st2(2).best_cum
        self.assertGreaterEqual(st1.best_cum, paid_out, "the hub collected what it paid on p1's and p2's ch2s")
        self.assertEqual(L.code_of(w.pay.close), "", "nothing unresolved keeps ch1 open")

    def test_resync_adopts_a_completion_above_a_release_in_one_view(self):
        self.case(0)

    def test_resync_adopts_a_completion_below_a_release_in_one_view(self):
        self.case(1)


class LyingHub:
    """A hub that takes each lock, forwards nothing, and answers route_failed with a view that says it
    holds the lock in ch1's base (as an honest hub does for a lock whose ch2 pre-signature is out)."""

    def __init__(self, inner, base):
        self.inner, self.tally, self.held, self.last_cum = inner, list(base), [], 0

    def serve(self, method, path, headers, body, url):
        hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
        if not (method == "POST" and path == HUB_ROUTE_PATH and hdr):
            return self.inner.serve(method, path, headers, body, url)
        pl, rt = unb64json(hdr)["payload"], json.loads(body)["route"]
        d, f = int(rt["amount"]), int(rt["fee"])
        _, units = fee_due(FeeQuote.from_dict(rt["feeQuote"]), d, self.tally[1], self.tally[2])
        self.tally = [self.tally[0] + d + f, units, self.tally[2] + f]
        self.held.append(rt["lockId"])
        self.last_cum = int(pl["cum"])
        best = self.inner.inbound.ledger.channels[pl["chan"]].best_cum
        view = {"error": "route_failed", "detail": "provider refused the lock: refused", "bestCum": best,
                "routedSat": self.tally[0], "feeUnits": self.tally[1], "feePaid": self.tally[2], "held": self.held, "released": []}
        return 502, {"Content-Type": "application/json"}, json.dumps(view).encode()


class ClientAndALyingHub(unittest.TestCase):
    def test_hole_a_hub_that_lies_about_holds_raises_what_the_client_signs_without_bound(self):
        # The client adopts a hold on the hub's word: it cannot see whether a ch2 pre-signature is out.
        # Each adopted hold raises the base of its next lock by d + f. A hub that claims a hold for
        # every lock it is sent (and forwards none) walks the client's next pre-signed state up by one
        # lock per try; the provider is owed d once. Forwarding the last one honestly collects all of it.
        w = W([None])
        w.paid(0)
        base, signed0 = w.base1(), w.counters()[3]
        liar = LyingHub(w.hub, base)
        w.net.apps[R.HUB] = liar
        R.stream(w.pay, w.shards[0], 10)
        n0, tries = w.lock_calls(), 0
        for _ in range(6):
            r = w.pay.lock(w.shards[0])
            if not r:
                break
            self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
            tries += 1
        one = (liar.tally[0] - base[0]) // max(1, tries)
        self.assertEqual(w.lock_calls(), n0, "control: the hub forwarded nothing")
        self.assertEqual(w.counters()[0], liar.tally[0], "control: the client adopted every hold the hub claimed")
        self.assertEqual(w.counters()[3], signed0, "control: none of them is a state the client counts as signed")
        self.assertLessEqual(liar.last_cum, signed0 + 2 * one,
                             f"after {tries} locks the hub said it holds, the client pre-signed ch1 at {liar.last_cum} under the "
                             f"provider's real T: {liar.last_cum - signed0} sat above its last paid state {signed0} "
                             f"({(liar.last_cum - signed0) // max(1, one)} locks of {one} sat), for one lock owed")


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


class HeldLockNeighbours(unittest.TestCase):
    def test_a_held_lock_is_not_escaped_through_settle_or_an_errored_close(self):
        w = W([None, None])
        w.paid(0)
        w.provs[0].refuse = w.provs[0].deaf = True
        self.assertEqual(w.lock(0)["error"], "route_failed")
        best, lcum = w.st1().best_cum, w.stale1()[0]["cum"]
        self.assertGreater(lcum, best + 2)
        acc = w.pay.ch.accepted if hasattr(w.pay, "ch") else w.pay.accepted
        sig = w.pay.signer.sign_close(w.pay.chan)
        body = {"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": acc, "payload": {"chan": w.pay.chan, "sig": sig}},
                "paymentRequirements": acc}
        st, _h, out = w.hub.serve("POST", "/x402/settle", {}, json.dumps(body).encode(), R.HUB + "/x402/settle")
        doc = json.loads(out)
        self.assertFalse(w.st1().closed_txid, f"/x402/settle closed ch1 below a held lock: {doc}")
        self.assertTrue(str(doc.get("errorReason", "")).endswith("lock_pending"), doc)
        # with the node erroring: still refused, and no intent is written that would stop routing
        L.down(w.node, True)
        self.assertEqual(L.code_of(w.pay.close), "lock_pending")
        L.down(w.node, False)
        self.assertFalse((w.st1().extra or {}).get("close_intent"), "a refused close left an intent")
        self.assertEqual(w.hub.inbound.close_due(), [])
        self.assertEqual(len(w.stale1()), 1)
        r = w.lock(1)
        self.assertEqual(r["status"], "paid", r)
        self.assertGreater(w.st1().best_cum, lcum, "the next lock sits above the held one")
        closed = w.pay.close()
        self.assertGreater(int(closed["cum"]), lcum, closed)


class UnconfirmedChildClose(unittest.TestCase):
    def test_hole_h2_a_hold_is_released_on_an_unconfirmed_close_of_an_unconfirmed_rollover_child(self):
        # A ch2 that is a rollover's child takes locks before the rollover confirms (AGP-053). The
        # watcher decides "the close confirmed" by gettxout(funding, include_mempool=False) is None. For
        # an output of an UNCONFIRMED transaction that is always None, so a close of the child that is
        # only in the mempool counts as confirmed: the ch2 is `closed` and final (never read again) and
        # the written-off lock's hold leaves ch1. The provider still holds that lock's pre-signature and
        # can replace the mempool close with one that uses it: the hub pays, and ch1 no longer holds it.
        node, net, hub, provs, pay, shards = R.world(1, hkw={"reveal_timeout": 0.3}, settle_multiple=2, amsat_per_call=40 * 10 ** 21)
        origin = next(iter(provs))
        prov, sh = provs[origin], shards[origin]

        def lock(calls):
            R.stream(pay, sh, calls)
            return pay.lock(sh)
        self.assertEqual(lock(50)["status"], "paid")
        self.assertTrue(any(a.get("event") == "ch2_rollover" for a in hub.watch_tick()))
        child = hub.out.chans[origin]
        self.assertTrue(child.state == "open" and child.zero_conf and not child.zero_conf.get("confirmed"), "control: an unconfirmed child")
        self.assertEqual(lock(5)["status"], "paid")              # the child has a state to close with
        prov.routes.no_reveal = True                             # the provider takes the next lock and keeps it
        r = lock(5)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        st1 = hub.inbound.ledger.channels[pay.chan]
        self.assertEqual(len(st1.extra["stale_locks"]), 1, "control: held on ch1")
        self.assertEqual(len(hub.out.chans[origin].stale), 1)
        # the provider closes the child at the state before the lock: into the mempool, nothing confirms
        st2 = prov.ledger.channels[child.p().channel_id]
        close = T.close_now(prov, st2)
        self.assertEqual(node.txs[close]["confirmations"], 0, "control: the close is unconfirmed")
        self.assertEqual(node.txs[child.p().funding_txid]["confirmations"], 0, "control: so is the rollover that funds the child")
        acts = hub.watch_tick()
        oc = hub.out.chans[origin]
        self.assertEqual(oc.p().channel_id, child.p().channel_id)
        state, final = oc.state, oc.final
        self.assertTrue(len(st1.extra.get("stale_locks", [])) == 1 and not final,
                        f"on a close that is only in the mempool the child is {state!r} (final {final}) and ch1 holds "
                        f"{len(st1.extra.get('stale_locks', []))} written-off locks: {[a.get('event') for a in acts]}")


if __name__ == "__main__":
    unittest.main()
