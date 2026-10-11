"""AGP-094 (fix wave 5, the hub and the routed client): tests of the fixes to the third closure audit's
items for the hub and the routed client (test_agp093_hub.py holds the audit's own), and of the items
it had from reading. xbt-rs has the same tests under the same names (crates/xbt402-interop/tests/
agp093_hub.rs and agp093_overflow.rs, crates/xbt402/tests/agp093_client.rs: `agp094_*`), and the
audit's `one_client_request_does_not_stop_the_hub_routing_to_a_provider`, which B1 had no test for.

The rules:
- item 1: no request of a client's stops the hub routing to a provider, or costs it a transaction. The
  hub asks the provider first (`route.check`), before it pre-signs anything;
- item 2: what is done on a spend "for good" is done when the spend is spend_final_depth blocks deep;
- item 12: a ch1 lock is the lock of one ch2 (also one from a ledger before AGP-088); a client stops
  counting a lock as held when the hub proves its completion; coins count against the cap until this
  node shows them leaving; a lock leaves a ch2 record after ch1 took its completion; a close and the
  refill it owes are one write; a pending lock is written off wherever its ch2 record is;
- items 5, 18: ch1 is funded once, and every `open` goes on from the stage the last one reached;
- item 13: a watcher tick that raises ends that tick, never the watcher (B1 had this already).

The harness is test_agp093_hub.py's (W) and routehelp's (world).
"""
import copy
import json
import os
import sys
import threading
import time
import unittest
from dataclasses import asdict
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402
import test_agp084_hub_leftovers as L  # noqa: E402
import test_agp088_hub as H  # noqa: E402
import test_agp093_hub as A  # noqa: E402

import xbt402.hub as hubmod  # noqa: E402
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402
from xbt402.hub import LIVE, HubConfig  # noqa: E402
from xbt402.route import ROUTE_LOCK_PATH, RouteSession, fee_due, lock_auth, next_cum  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402
from xbt402.x402_channel import b64json  # noqa: E402

CLOSE_PATH = H.CLOSE_PATH
OPEN_PATH = "/x402/xbt-channel/open"
P0 = "http://p0.test"
CHECK = ROUTE_LOCK_PATH + "?check"           # how routehelp.Net records a hub's check of a lock


def route_built(pay, sh, tamper=None):
    """The client's POST /x402/route for `sh`'s open invoice from `pay`'s ch1, built and signed now (as
    routehelp.route_request does) and sent when the returned function is called: (status, doc)."""
    inv = dict(sh.invoice)
    d = max(1, sh.due_sat())
    f, _ = fee_due(pay.quote, d, pay.fee_units, pay.fee_paid)
    cum = next_cum(pay.routed, d + f, pay.ch.payer.params.min_amount)
    sa = pay.signer.sign_state_adaptor(pay.chan, cum, inv["point"])
    route = {"provider": sh.origin, "payTo": sh.pay_to, "network": R.NET, "amount": d, "point": inv["point"],
             "fee": f, "feeQuote": asdict(pay.quote), "invoice": inv, "session": sh.session, "lockId": inv["lockId"],
             "lockAuth": lock_auth(sh.key, sh.session, inv["lockId"], d, inv["point"], pay.hub_pay_to),
             "tweak": sa["tweak"]}
    pl = {"chan": pay.chan, "seq": 0, "cum": str(cum), "adaptor": sa["adaptor"], "point": sa["point"]}
    if tamper:
        tamper(pl, route)
    pay.ch.seq += 1
    pl["seq"] = pay.ch.seq
    body = json.dumps({"route": route}).encode()
    pay.cc._auth(pay.ch, pl, "POST", R.HUB + "/x402/route", body)
    hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": pay.ch.accepted, "payload": pl})}

    def send():
        st, _, raw = pay.http("POST", R.HUB + "/x402/route", body, hdrs)
        return st, json.loads(raw)
    return send


def bad_lock_auth(pl, route):
    route["lockAuth"] = "00" * 32


class World:
    """routehelp.world with one provider, and what these tests read off it."""

    def __init__(self, **hkw):
        self.node, self.net, self.hub, provs, self.pay, shards = R.world(1, hkw=hkw or None)
        self.prov, self.sh = provs[P0], shards[P0]

    def oc(self):
        return self.hub.out.chans[P0]

    def st2(self):
        return self.prov.ledger.channels[self.oc().p().channel_id]

    def fresh_client(self):
        """Another client of the same hub: its own ch1, its own session at the provider."""
        pay = R.payer(self.node, self.net)
        pay.open()
        return pay, pay.shard(P0 + "/v1/chunk")

    def paid(self, calls=10):
        R.stream(self.pay, self.sh, calls)
        r = self.pay.lock(self.sh)
        assert r and r["status"] == "paid", r

    def calls(self, path):
        return sum(1 for c in self.net.calls if c[1] == P0 and c[2] == path)

    def past_floor(self):
        """The ch2 as after it routed its floor: from there every lock needs a pre-signature."""
        oc, st = self.oc(), self.st2()
        with self.hub.out.lock:
            oc.routed = oc.signed
            self.hub.out.save()
        with self.prov.ledger.lock:
            st.extra = {**st.extra, "routed_sat": oc.signed}
            self.prov.ledger.save(st)

    def untouched(self, tc, pay=None):
        """Nothing is written off, pending or blocked on the ch2, and nothing is held on `pay`'s ch1."""
        oc = self.oc()
        tc.assertTrue(not oc.stale and not oc.pending and not oc.blocked, (oc.stale, oc.pending, oc.blocked))
        if pay is not None:
            ex = self.hub.inbound.ledger.channels[pay.chan].extra or {}
            tc.assertTrue(not ex.get("route_lock") and not ex.get("stale_locks"), "nothing held on ch1")


# --- item 1: the hub asks before it pre-signs ---------------------------------------------------------------------

class AskBeforePreSigning(unittest.TestCase):
    def test_one_client_request_does_not_stop_the_hub_routing_to_a_provider(self):
        # The audit's item 1 (xbt-rs agp093_overflow.rs): a lock carries what only the client and the
        # provider can check. One client sends a lock with a bad lockAuth; the hub pre-signed its ch2,
        # the provider refused, the lock was written off and the ch2 blocked (with nothing signed it
        # could not even be closed: no_state, until its refund). Now the provider is asked first.
        w = World()
        bad, bad_sh = w.fresh_client()
        R.stream(bad, bad_sh, 3)
        locks, checks = w.calls(ROUTE_LOCK_PATH), w.calls(CHECK)
        st, doc = route_built(bad, bad_sh, bad_lock_auth)()
        self.assertEqual((st, doc.get("error"), doc.get("providerError")), (502, "route_failed", "bad_auth"), doc)
        self.assertEqual((w.calls(CHECK) - checks, w.calls(ROUTE_LOCK_PATH) - locks), (1, 0), "refused at the check: no lock was sent")
        self.assertEqual(w.hub.stats["refused"], {"bad_auth": 1})
        w.untouched(self, bad)
        # an honest client's lock to that provider is paid at once
        R.stream(w.pay, w.sh, 10)
        r = w.pay.lock(w.sh)
        self.assertEqual(r and r["status"], "paid", f"after one client's refused lock the hub routes nothing to this provider: {r}; "
                                                   f"ch2 {w.oc().state}, {len(w.oc().stale)} written-off lock")
        self.assertFalse([e for e in w.hub.events if e.get("event") in ("ch2_close", "ch2_written_off_close_failed")])

    def test_agp094_a_refused_lock_the_floor_covers_is_dropped_and_blocks_nothing(self):
        # The rule of item 1 on the path the check does not cover: a lock the ch2's floor covers needs
        # no pre-signature, so nothing is asked first. A client's bad lockAuth on such a lock is refused
        # by the provider with nothing of the hub's out: the lock is dropped (not written off, not
        # held) and the ch2 takes the next lock.
        w = World()
        w.paid()
        bad, bad_sh = w.fresh_client()
        R.stream(bad, bad_sh, 1)
        oc = w.oc()
        d = max(1, bad_sh.due_sat())
        self.assertLessEqual(next_cum(oc.routed, d, oc.p().min_amount), oc.signed, "control: the ch2's floor covers this lock")
        checks = w.calls(CHECK)
        st, doc = route_built(bad, bad_sh, bad_lock_auth)()
        self.assertEqual((st, doc.get("providerError")), (502, "bad_auth"), doc)
        self.assertEqual(w.calls(CHECK), checks, "control: nothing to pre-sign, so nothing was asked first")
        w.untouched(self, bad)
        self.assertNotIn("held", doc)
        w.paid(1)

    def test_agp094_an_invoice_sent_again_from_another_ch1_does_not_put_the_ch2_out_of_step(self):
        # The same invoice sent again from another ch1 of the same client, after it was paid. The
        # provider answered a lock it had completed before with the same t, the hub counted it as a new
        # one, and every later lock on that ch2 was then one lock above what the provider expected
        # (bad_amount, after the pre-signature left: written off, ch2 blocked). Now the provider refuses
        # it at the check when a pre-signature is needed, and where the floor covers it the hub counts
        # what the provider counted.
        seen = []
        for past_floor in (False, True):
            w = World()
            if past_floor:
                w.paid()
                w.past_floor()
            R.stream(w.pay, w.sh, 10)
            bad, _ = w.fresh_client()
            # the second ch1's request for the invoice of the first one's session, built before it is paid
            send = route_built(bad, w.sh)
            d = max(1, w.sh.due_sat())
            r = w.pay.lock(w.sh)
            self.assertEqual(r["status"], "paid", r)
            oc = w.oc()
            floor = next_cum(oc.routed, d, oc.p().min_amount) <= oc.signed
            seen.append(floor)
            st, doc = send()
            # refused at the check when a pre-signature would be needed; answered again where the floor covers it
            self.assertEqual((st == 200, doc.get("providerError") == "bad_invoice"), (floor, not floor), f"floor {floor}: {doc}")
            self.assertEqual(w.oc().routed, int(w.st2().extra.get("routed_sat", 0)),
                             f"floor {floor}: the hub's routed total left the provider's")
            w.untouched(self, bad)
            w.paid(2)
        self.assertEqual(seen, [True, False], "control: once where the ch2's floor covers the second lock, once where it needs a pre-signature")

    def test_agp094_an_invoice_one_hub_checked_is_refused_to_another_channel_at_its_check(self):
        # An invoice a hub was told would be taken is paid over that hub's channel alone until its
        # window ends: sent through another channel it is refused, and at a hub's check, so before that
        # hub pre-signs.
        w = World()

        class Dies:
            """The check is answered and the lock itself never arrives: the hub's thread dies there."""
            boom = 1

            def serve(self, method, path, headers, body, url):
                if path == ROUTE_LOCK_PATH and not R.is_lock_check(path, body) and self.boom:
                    self.boom -= 1
                    raise RuntimeError("agp094: the hub stops while a lock is forwarded")
                return w.prov.serve(method, path, headers, body, url)
        w.net.apps[P0] = Dies()
        R.stream(w.pay, w.sh, 10)
        with self.assertRaises(RuntimeError):
            route_built(w.pay, w.sh)()
        chan2 = w.oc().p().channel_id
        self.assertIn(chan2, [s.bound for s in w.prov.routes.sessions.values()], "the check bound the session's invoice to the hub's ch2")
        self.assertTrue(H.has(w.hub.watch_tick(), "lock_settled_late"), "that hub's lock is still taken")
        self.assertEqual([s.bound for s in w.prov.routes.sessions.values()], [""], "the next window is bound to nobody")
        # as another hub's channel would find it: the next invoice bound to a channel that is not ours
        w.past_floor()
        pay, sh = w.fresh_client()
        R.stream(pay, sh, 3)
        for s in w.prov.routes.sessions.values():
            s.bound = "ab" * 32
        locks, checks = w.calls(ROUTE_LOCK_PATH), w.calls(CHECK)
        r = pay.lock(sh)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        self.assertEqual(w.hub.stats["refused"].get("lock_outstanding"), 1)
        self.assertEqual((w.calls(CHECK) - checks, w.calls(ROUTE_LOCK_PATH) - locks), (1, 0), "refused before anything was pre-signed")
        w.untouched(self, pay)

    def test_agp094_a_bound_invoice_lives_to_its_valid_until(self):
        # A call does not end the window of an invoice a hub was told would be taken (an unbound one is
        # replaced a second early, as before); the binding is in the session's saved JSON and ends with
        # the window.
        w = World()
        s = next(iter(w.prov.routes.sessions.values()))
        self.assertEqual(RouteSession(**json.loads(json.dumps(asdict(s)))).bound, "")
        lid = s.lock_id
        s.valid_until, s.bound = time.time() + 0.6, "cd" * 32
        self.assertEqual(RouteSession(**json.loads(json.dumps(asdict(s)))).bound, "cd" * 32)
        R.stream(w.pay, w.sh, 1)
        self.assertEqual((s.lock_id, s.bound), (lid, "cd" * 32), "a call ended a bound window before its valid_until")
        s.bound = ""
        R.stream(w.pay, w.sh, 1)
        self.assertNotEqual(s.lock_id, lid, "control: an unbound invoice is replaced a second early")
        lid = s.lock_id
        s.valid_until, s.bound = time.time() - 0.01, "cd" * 32
        R.stream(w.pay, w.sh, 1)
        self.assertTrue(s.lock_id != lid and s.bound == "", "past its valid_until a new window starts, bound to nobody")

    def test_agp094_a_provider_that_does_not_answer_the_check_costs_the_hub_nothing(self):
        w = World()
        answers = {"check": "lost"}

        class P:
            def serve(self, method, path, headers, body, url):
                if R.is_lock_check(path, body):
                    if answers["check"] == "lost":
                        raise OSError("agp094: no answer")
                    # a provider from before the check: the request is a lock without its pre-signature
                    return 400, {"Content-Type": "application/json"}, b'{"error":"bad_adaptor","detail":"no adaptor"}'
                return w.prov.serve(method, path, headers, body, url)
        w.net.apps[P0] = P()
        R.stream(w.pay, w.sh, 10)
        seq = w.oc().seq
        r = w.pay.lock(w.sh)
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        self.assertEqual(w.hub.stats["refused"], {"no_answer": 1})
        self.assertEqual(w.oc().seq, seq + 1, "the check spent a ch2 seq of its own")
        w.untouched(self, w.pay)
        # bad_adaptor is the yes of a provider that predates the check: the lock goes on and is paid
        answers["check"] = "old"
        for s in w.prov.routes.sessions.values():
            s.valid_until = 0.0                       # (the client gave that invoice up: a fresh one)
        w.paid(3)

    def test_agp094_an_invoice_must_outlive_the_hubs_wait(self):
        # The hub refuses an invoice with less than its reveal timeout left (it was half a second): the
        # provider is asked twice now, and the lock must still be good when the hub's wait ends.
        w = World()
        R.stream(w.pay, w.sh, 10)
        s = next(iter(w.prov.routes.sessions.values()))
        s.valid_until = time.time() + 0.8
        w.sh.invoice = w.prov.routes.invoice(s)
        self.assertEqual(w.hub.reveal_timeout, 1.0)
        st, doc = route_built(w.pay, w.sh)()
        self.assertEqual((st, doc.get("error")), (400, "bad_invoice"), doc)
        w.pay.signer.void_lock(w.pay.chan)
        w.hub.reveal_timeout = 0.3
        st, doc = route_built(w.pay, w.sh)()
        self.assertEqual(st, 200, f"control: with a wait of 0.3 s an invoice with 0.8 s left is taken: {doc}")


# --- item 2: spend_final_depth ------------------------------------------------------------------------------------

class SpentForGood(unittest.TestCase):
    def test_agp094_a_hold_is_released_when_the_close_is_spend_final_depth_deep(self):
        # The rule itself: a hold is released, and the ch2 record made final, when the close that did
        # not pay it is spend_final_depth blocks deep, with a scan that says how deep a spender is and
        # with one that does not (the depth is then counted from the block at which the watcher first
        # saw the funding spent).
        self.assertEqual(HubConfig().spend_final_depth, 6)
        for bad in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                HubConfig.from_dict({"spend_final_depth": bad})
        cfg = HubConfig()
        cfg.spend_final_depth = 0
        with self.assertRaises(ValueError):
            cfg.validate()
        real = hubmod.find_spend_at

        def no_depth(*a):
            found = real(*a)
            return found and (found[0], None)
        for depth in (True, False):
            with mock.patch.object(hubmod, "find_spend_at", real if depth else no_depth):
                w = A.W([None], hkw={"spend_final_depth": 3})
                w.paid(0)
                before = copy.deepcopy(w.st2(0))
                w.keeps_locks(0)
                w.refused(0)
                prov = w.provs[0].inner
                with prov.ledger.lock:
                    prov.ledger.channels[before.params.channel_id] = before
                    prov.ledger.save(before)
                T.close_now(prov, before)                 # at the state before the lock: no t on it
                w.hub.watch_tick()
                for deep in (1, 2, 3):
                    w.node.mine(1)
                    acts = w.hub.watch_tick() + w.hub.watch_tick()
                    oc = w.oc(0)
                    self.assertEqual((H.has(acts, "lock_released"), oc.final, len(w.stale1())), (deep == 3, deep == 3, 0 if deep == 3 else 1),
                                     f"scan depth {depth}, {deep} block(s) deep: ch2 {oc.state} {acts}")
                    if deep < 3:
                        self.assertEqual(L.code_of(w.pay.close), "lock_pending", "ch1 does not close below the held lock")
                self.assertEqual(w.oc(0).state, "closed")
                self.assertEqual(bool(w.oc(0).gone_at), not depth, "gone_at is the count of a scan that gives no depth")

    def test_agp094_the_hubs_own_refund_in_a_block_is_final_at_the_depth_and_not_bumped_before(self):
        # A spend in a block that is not yet that deep is treated as one in the mempool, except that the
        # hub's own refund is not bumped once it is in a block.
        w = A.W([600], hkw={"spend_final_depth": 3, "refund_bump_blocks": 1})
        oc = w.oc(0)
        w.node.height = oc.p().expiry
        self.assertTrue(H.has(w.hub.watch_tick(), "ch2_refund"), "control: an unsigned ch2 is refunded at its expiry")
        txid = oc.refund_txid
        for deep in (1, 2, 3):
            w.node.mine(1)
            acts = w.hub.watch_tick()
            self.assertFalse(H.has(acts, "ch2_refund_bump"), f"{deep} block(s) deep: a refund in a block was bumped: {acts}")
            self.assertEqual((oc.state, oc.final, oc.refund_txid, H.has(acts, "ch2_refund_confirmed")), ("refunded", deep == 3, txid, deep == 3),
                             f"{deep} block(s) deep: {acts}")


# --- item 12 ------------------------------------------------------------------------------------------------------

class LocksFromBeforeTheCh2Field(unittest.TestCase):
    def test_agp094_two_locks_of_one_invoice_from_a_ledger_before_agp088_are_each_given_their_ch2(self):
        # The case the audit's test stands for: the SAME invoice sent twice, as a hub before AGP-088
        # admitted it, so the two written-off locks share their lockId and their point, on two ch2s of
        # one provider. Each is given the ch2 it went over, the earlier lock the earlier ch2.
        w, a, _ = A.two_held_locks_on_two_ch2s_of_one_provider(self, True)
        st1 = w.st1()
        t = st1.extra["stale_locks"][0]["T"]
        with w.hub.inbound.ledger.lock:
            st1.extra["stale_locks"][1]["T"] = t
            w.hub.inbound.ledger.save(st1)
        with w.hub.out.lock:
            w.oc(0).stale[0]["T"] = t
            w.hub.out.save()
        acts = w.hub.name_legacy_locks()
        self.assertTrue(H.has(acts, "legacy_locks_named", locks=2), acts)
        self.assertEqual([s.get("ch2") for s in w.stale1()], [a.params["payer_pub"], w.oc(0).params["payer_pub"]])
        self.assertEqual(w.hub.name_legacy_locks(), [], "nothing left to name")

    def test_agp094_a_legacy_lock_no_ch2_record_holds_is_left_alone(self):
        w, a, _ = A.two_held_locks_on_two_ch2s_of_one_provider(self, True)
        with w.hub.out.lock:
            w.oc(0).stale = []
            w.hub.out.save()
        acts = w.hub.name_legacy_locks()
        self.assertTrue(H.has(acts, "legacy_locks_named", locks=1), acts)
        self.assertEqual([s.get("ch2") for s in w.stale1()], [a.params["payer_pub"], None])
        self.assertFalse(hubmod.is_lock(w.stale1()[1], w.stale1()[1]["lockId"], w.oc(0)), "and no ch2 of its origin moves it")


class TheCapCountsArchivedCh2s(unittest.TestCase):
    def test_agp094_a_ch2_replaced_for_a_changed_pay_to_is_retired_and_counted_until_it_is_spent(self):
        # The other side of the audit's test: with room under the cap the ch2 a changed payTo replaces
        # is funded, and the replaced one is `retired`, so the watcher has the provider close it.
        w = A.W([None], hkw={"liquidity_cap_sat": 200_000})
        w.paid(0)
        old = w.oc(0)
        w.provs[0].pay_to = ecc.pubkey(0x7777).hex()
        w.hub.connect(w.origins[0])
        self.assertEqual(w.hub.committed_sat(), 200_000, "both count while the first is unspent")
        rec = next(r for r in w.hub.out.archived if r["params"]["payer_pub"] == old.params["payer_pub"])
        self.assertIs(rec["retired"], True)
        asked = w.route_calls(CLOSE_PATH)
        w.hub.watch_tick()
        self.assertEqual(w.route_calls(CLOSE_PATH), asked + 1, "the watcher asked the provider to close the replaced ch2")


    def test_agp094_a_changed_pay_to_at_the_cap_funds_nothing(self):
        # the cap check itself (the audit's test also passes once the replaced ch2 is retired and
        # closed): at the cap nothing is funded for a changed payTo, and the live ch2 keeps its place
        w = A.W([None], hkw={"liquidity_cap_sat": 100_000})
        w.paid(0)
        old, funded = w.oc(0), len(w.node.wallet_txs)
        w.provs[0].pay_to = ecc.pubkey(0x7777).hex()
        self.assertEqual(L.code_of(w.hub.connect, w.origins[0]), "liquidity_cap")
        self.assertEqual((w.hub.committed_sat(), len(w.node.wallet_txs), w.oc(0) is old, old.retired), (100_000, funded, True, False))


class FromReading(unittest.TestCase):
    def test_agp094_a_completion_ch1_did_not_take_keeps_the_lock_on_the_ch2_record(self):
        # ch1's ledger does not take the write of a completion read off a ch2 close. The lock stays on
        # the ch2 record (and on ch1, in memory as on disk), and the next tick completes it.
        w = A.W([None])
        w.paid(0)
        w.keeps_locks(0)
        w.refused(0)
        cum, best = w.stale1()[0]["cum"], w.st1().best_cum
        w.provider_closes(0)
        w.hub.stop_at = "complete_ch1"
        acts = w.hub.watch_tick()
        self.assertTrue(H.has(acts, "secret_from_close", ch1_completed=False), acts)
        self.assertEqual((len(w.stale1()), len(w.oc(0).stale), w.st1().best_cum), (1, 1, best),
                         "the lock is still on ch1 and still on the ch2 record")
        w.hub.stop_at = ""
        acts = w.hub.watch_tick()
        self.assertTrue(H.has(acts, "secret_from_close", ch1_completed=True), acts)
        self.assertTrue(not w.stale1() and not w.oc(0).stale and w.st1().best_cum >= cum)

    def test_agp094_a_provider_answer_ch1_did_not_take_keeps_the_lock_pending(self):
        # the same for the provider's own answer: the lock stays pending on the ch2 and is settled again
        w = A.W([None])
        w.paid(0)
        routed = w.oc(0).routed
        w.hub.stop_at = "complete_ch1"
        R.stream(w.pay, w.shards[0], 10)
        r = w.pay.lock(w.shards[0])
        self.assertEqual(r.get("status"), "pending", r)
        self.assertTrue(w.oc(0).pending and w.oc(0).routed == routed and (w.st1().extra or {}).get("route_lock"),
                        "pending on the ch2, in flight on ch1")
        w.hub.stop_at = ""
        self.assertTrue(H.has(w.hub.watch_tick(), "lock_settled_late", ok=True))
        self.assertTrue(not w.oc(0).pending and w.oc(0).routed > routed and not (w.st1().extra or {}).get("route_lock"))

    def test_agp094_a_stop_after_the_close_is_written_does_not_lose_the_refill(self):
        # The hub stops right after it wrote the close. The refill that close owes is in that same
        # write, and the next tick funds it.
        w = A.W([None])
        w.paid(0)
        old = w.oc(0)
        w.hub.stop_at = "closing"
        self.assertEqual(L.code_of(w.hub.close_ch2, old, True), "test_stop")
        oc = w.oc(0)
        self.assertTrue(oc is old and oc.state == "closing" and oc.refill_owed, f"closing, the refill owed: {oc.state} {oc.refill_owed}")
        w.hub.stop_at = ""
        acts = w.hub.watch_tick()
        self.assertTrue(H.has(acts, "ch2_refill"), acts)
        new = w.oc(0)
        self.assertTrue(new.params["payer_pub"] != old.params["payer_pub"] and new.state in LIVE, f"a new ch2 is funded: {new.state}")
        n = w.hub.committed_sat()
        w.hub.watch_tick()
        self.assertEqual(w.hub.committed_sat(), n, "funded once")

    def test_agp094_a_lock_pending_on_a_ch2_archived_while_open_is_written_off(self):
        # A ch2 archived while open with its lock pending, as a ledger from before AGP-088 can hold
        # one. It is written off like any pending lock nobody will answer, held on ch1 (which is free
        # for the next lock), and the ch2 is closed like a retired one.
        w = A.W([None, None], pkw={"held_probe_secs": 0.0})
        w.paid(0)
        held = w.held_lock(0)
        w.back_in_flight(0, held)
        origin = w.origins[0]
        with w.hub.out.lock:
            w.hub.out.archived.append(asdict(w.hub.out.chans.pop(origin)))
            w.hub.out.save()
        time.sleep(w.hub.reveal_timeout + 0.05)
        acts = w.hub.watch_tick()
        self.assertTrue(H.has(acts, "lock_written_off"), acts)
        self.assertEqual(w.pending_anywhere(), 0)
        self.assertTrue(not (w.st1().extra or {}).get("route_lock") and len(w.stale1()) == 1 and isinstance(w.stale1()[0].get("hold"), dict),
                        "held on ch1, which takes a lock again")
        rec = next(r for r in w.hub.out.archived if r["origin"] == origin and r.get("stale"))
        self.assertIs(rec["retired"], True, f"and the watcher has the provider close it: {rec['state']}")
        r = w.pay_until_paid(1)
        self.assertEqual(r and r["status"], "paid", r)


# --- items 5, 18: the routed client's open ------------------------------------------------------------------------

class Hub:
    """The hub as a client sees it over the net. `refuse`: it answers every funded open with a 400;
    `lose`: it opens the next funded channel and its answer is lost."""

    def __init__(self, inner):
        self.inner, self.refuse, self.lose = inner, False, 0

    def serve(self, method, path, headers, body, url):
        funded = False
        if path == OPEN_PATH:
            try:
                funded = not json.loads(body).get("preflight")
            except (ValueError, AttributeError):
                pass
        if funded and self.refuse:
            return 400, {"Content-Type": "application/json"}, b'{"error":"bad_funding","detail":"no"}'
        r = self.inner.serve(method, path, headers, body, url)
        if funded and self.lose:
            self.lose -= 1
            raise OSError("agp094: answer lost")
        return r


class Fund:
    """The wallet: counts what it funds, and can refuse."""

    def __init__(self, node):
        self.node, self.sends, self.refuses = node, [], False

    def __call__(self, address, sats):
        if self.refuses:
            raise ChannelError("wallet_error", "insufficient funds")
        self.sends.append((address, sats))
        return self.node.fund_address(address, sats)


class RoutedOpen(unittest.TestCase):
    def rig(self, signer=None):
        """A hub with one open ch2, and a client whose ch1 is not opened yet."""
        node, net = R.RouteNode(), R.Net()
        hub = R.hub(node, net)
        R.provider(node, net, P0)
        hub.connect(P0)
        node.confirm_all()
        hub.watch_tick()
        seen = net.apps[R.HUB] = Hub(hub)
        fund = Fund(node)
        pay = R.payer(node, net, signer=signer(fund) if signer else ChannelSigner(fund=fund))
        return node, hub, seen, fund, pay

    def test_agp094_the_routed_client_funds_a_refusing_hub_once(self):
        # ch1 was kept only after the hub answered the funded open: a hub that said yes to the preflight
        # and no to the open was funded again by every `open`. And a ch1 the hub has not opened signs
        # no lock.
        node, hub, seen, fund, pay = self.rig()
        seen.refuse = True
        self.assertEqual([L.code_of(pay.open) for _ in range(3)], ["bad_funding"] * 3)
        self.assertEqual(len(fund.sends), 1, f"one hub, {len(fund.sends)} channels funded")
        sh = pay.shard(P0 + "/v1/chunk")
        R.stream(pay, sh, 3)
        self.assertIsNone(pay.lock(sh), "a ch1 the hub has not opened signs no lock")
        seen.refuse = False
        out = pay.open()
        self.assertEqual((out.get("resumed"), len(fund.sends), pay.ch.stage), (True, 1, "open"))
        self.assertEqual(pay.lock(sh)["status"], "paid")

    def test_agp094_the_routed_client_finishes_an_open_whose_answer_was_lost(self):
        # the hub opened ch1 and its answer never arrived: the next open is told duplicate_channel,
        # which is the yes that was lost
        node, hub, seen, fund, pay = self.rig()
        seen.lose = 1
        with self.assertRaises(OSError):
            pay.open()
        self.assertEqual(len(hub.inbound.ledger.channels), 1, "control: the hub has the channel")
        out = pay.open()
        self.assertEqual((out.get("resumed"), len(fund.sends)), (True, 1))
        self.assertIn(out["chan"], hub.inbound.ledger.channels)
        sh = pay.shard(P0 + "/v1/chunk")
        R.stream(pay, sh, 3)
        self.assertEqual(pay.lock(sh)["status"], "paid")
        self.assertNotIn("resumed", self.rig()[4].open(), "control: a first open is not a resumed one")

    def test_agp094_a_ch1_bound_in_the_signer_is_not_bound_again_by_the_next_open(self):
        # an open that failed between the signer's binding and the refund: the next one bound again,
        # and the signer, its issued key used up, refused it for good (bad_key)
        class Flaky(ChannelSigner):
            fails = 1

            def sign_refund(self, chan):
                hx = super().sign_refund(chan)        # (raises for a channel that is not bound)
                if self.fails:
                    self.fails -= 1
                    raise ChannelError("signer_error", "agp094: the signer did not answer")
                return hx
        node, hub, seen, fund, pay = self.rig(lambda fund: Flaky(fund=fund))
        self.assertEqual(L.code_of(pay.open), "signer_error")
        self.assertEqual((len(fund.sends), pay.cc.channels[R.HUB].stage), (1, "keyed"), "control: funded, bound, no refund yet")
        out = pay.open()
        self.assertEqual((out.get("resumed"), len(fund.sends), pay.ch.stage), (True, 1, "open"))

    def test_agp094_a_keyed_ch1_too_old_to_fund_is_refused_until_it_is_forgotten(self):
        node, hub, seen, fund, pay = self.rig()
        self.assertFalse(pay.forget_unfunded(), "nothing recorded yet")
        fund.refuses = True
        self.assertEqual(L.code_of(pay.open), "wallet_error")
        rec = pay.cc.channels[R.HUB]
        self.assertEqual((rec.stage, rec.payer.params.funding_txid, len(fund.sends)), ("keyed", "", 0), "recorded, unfunded")
        fund.refuses = False
        # the same key is funded by the next open for as long as the hub would still open it ...
        key = rec.payer.params.payer_pub
        # ... and past that it is refused until the owner says the wallet shows no send to it
        node.height = rec.payer.params.expiry
        self.assertEqual([L.code_of(pay.open) for _ in range(2)], ["open_unresolved"] * 2)
        self.assertEqual(len(fund.sends), 0)
        node.height = 1000
        self.assertTrue(pay.forget_unfunded())
        self.assertFalse(pay.forget_unfunded())
        out = pay.open()
        self.assertTrue("resumed" not in out and pay.ch.payer.params.payer_pub != key and len(fund.sends) == 1)

    def test_agp094_a_keyed_ch1_is_funded_once_by_the_next_open(self):
        node, hub, seen, fund, pay = self.rig()
        fund.refuses = True
        self.assertEqual(L.code_of(pay.open), "wallet_error")
        key = pay.cc.channels[R.HUB].payer.params.payer_pub
        fund.refuses = False
        out = pay.open()
        self.assertEqual((out.get("resumed"), len(fund.sends), pay.ch.payer.params.payer_pub), (True, 1, key))
        self.assertEqual((pay.open().get("resumed"), len(fund.sends)), (True, 1), "an open ch1 is not funded again")


# --- item 13: the watcher -----------------------------------------------------------------------------------------

class TheWatcherGoesOn(unittest.TestCase):
    def test_agp094_a_tick_that_raises_does_not_end_the_hub_watcher(self):
        # B1 had this before AGP-094 (RouteHub.watch catches per tick; watcher.Watcher._loop does for a
        # provider, test_h1_watcher.py): pinned here beside the rest of the wave.
        w = World()
        ticks, real = [], w.hub.watch_tick

        def tick():
            ticks.append(1)
            if len(ticks) == 1:
                raise ZeroDivisionError("agp094: injected")
            return real()
        w.hub.watch_tick = tick
        stop = w.hub.watch(0.01)
        try:
            self.assertTrue(R.wait(lambda: len(ticks) >= 4), f"the hub's watcher made {len(ticks)} tick(s) after one raised")
        finally:
            stop.set()
        self.assertTrue(any(t.name == "hub-watcher" for t in threading.enumerate()) or len(ticks) >= 4)


if __name__ == "__main__":
    unittest.main()
