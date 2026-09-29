"""AGP-021: xbt402 hub routing, security tests (in-process: FakeNode + a fake HTTP transport).

Hub, POST /x402/route, one test per check, in the order the hub runs them. Each refusal is checked to
leave nothing behind: no ch1 lock written, no ch2 state pre-signed, nothing sent to the provider.
    1 auth, 2 point (T1 = T + r*G), 3 amount, 4 pre-verify, 5 signed live fee quote,
    6 route_ok or the unguarded cap, 7 one lock per channel; and the order itself.
Provider, POST /x402/xbt-channel/lock: the hub cannot reprice or redirect a lock (client lock auth),
invoices are fresh and expire, only the bound hub's channel, write-ahead and idempotent answers.
cmp-lead's M2 constraints 1-7 that a unit test can show (the regtest demo shows the rest).
"""
import os
import secrets
import sys
import threading
import time
import unittest
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402 import adaptor, ecc  # noqa: E402
from xbt402.channel import DUST  # noqa: E402
from xbt402.route import (AMSAT_PER_SAT, FEE_UNITS_PER_SAT, ROUTE_LOCK_PATH, FeeQuote, ceil_div, fee_due,  # noqa: E402
                          lock_auth, next_cum, route_ok)
from xbt402.x402_channel import b64json, request_auth, request_digest  # noqa: E402
from xbt402.channel import channel_auth_key  # noqa: E402


class _World(unittest.TestCase):
    n_providers = 1
    pkw = {}

    def setUp(self):
        self.node, self.net, self.hub, self.provs, self.pay, self.shards = R.world(self.n_providers, **self.pkw)
        self.origin = next(iter(self.provs))
        self.prov, self.sh = self.provs[self.origin], self.shards[self.origin]
        R.stream(self.pay, self.sh, 10)

    def st1(self):
        return self.hub.inbound.ledger.channels[self.pay.chan]

    def st2(self, origin=None):
        p = self.provs[origin or self.origin]
        return next(s for s in p.ledger.channels.values() if not s.closed_txid)

    def assertRefusedClean(self, tamper, code):
        """The request is refused with `code`, and nothing was written or pre-signed for ch2."""
        oc = self.hub.out.chans[self.origin]
        seq2, best2, n_lock = oc.seq, self.st2().best_cum, self._lock_calls()
        st, doc = R.route_request(self.pay, self.sh, tamper=tamper)
        self.assertEqual(doc.get("error"), code, doc)
        self.assertGreaterEqual(st, 400)
        self.assertFalse((self.st1().extra or {}).get("route_lock"), "a refused lock was written on ch1")
        self.assertEqual(oc.pending, {}, "ch2 was pre-signed for a refused lock")
        self.assertEqual((oc.seq, self._lock_calls(), self.st2().best_cum), (seq2, n_lock, best2))
        return doc

    def _lock_calls(self):
        return sum(1 for c in self.net.calls if c[2] == ROUTE_LOCK_PATH)


class HubChecksInOrder(_World):
    def test_0_a_valid_lock_goes_through_and_a_retry_gets_the_same_answer(self):
        st, doc = R.route_request(self.pay, self.sh)
        self.assertEqual(st, 200, doc)
        # first ch2 lock: the channel's floor (dust + closeFee on a payee-pays ch2, AGP-023)
        self.assertEqual(self.st2().best_cum, self.st2().params.min_amount)
        self.assertEqual(self.st2().params.close_fee_payer, "payee")
        done = self.st1().extra["route_done"][doc["lockId"]]
        self.assertEqual(done["secret"], doc["secret"])

    def test_1_auth(self):
        self.assertRefusedClean(lambda pl, rt: "noauth", "bad_auth")

    def test_1_auth_stale_seq(self):
        def stale(pl, rt):
            self.pay.ch.seq = -1                                        # next seq 0: not above the last one
        self.assertRefusedClean(stale, "bad_auth")

    def test_2_point_must_be_T_plus_rG(self):
        def other_point(pl, rt):
            rt["point"] = adaptor.enc(adaptor.point_of(secrets.randbelow(adaptor.N - 1) + 1)).hex()
        self.assertRefusedClean(other_point, "bad_point")

        def other_tweak(pl, rt):
            rt["tweak"] = f"{secrets.randbelow(adaptor.N - 1) + 1:064x}"
        self.assertRefusedClean(other_tweak, "bad_point")

    def test_3_amount(self):
        self.assertRefusedClean(lambda pl, rt: pl.__setitem__("cum", str(int(pl["cum"]) + 1)), "bad_amount")
        self.assertRefusedClean(lambda pl, rt: rt.__setitem__("amount", 20_001), "bad_amount")   # > maxLockSat
        self.assertRefusedClean(lambda pl, rt: rt.__setitem__("amount", 0), "bad_amount")

    def test_4_preverify_against_the_exact_state(self):
        def presig_other_state(pl, rt):
            p = self.pay.ch.payer.params
            T1 = adaptor.dec(pl["point"])
            pl["adaptor"] = adaptor.presign(0xBAD, p.sighash(p.state_tx(int(pl["cum"]))), T1).to_json()   # not the payer
        self.assertRefusedClean(presig_other_state, "bad_adaptor")

        def presig_other_point(pl, rt):
            p = self.pay.ch.payer.params
            secret = self.pay.signer._secret(self.pay.chan)
            pl["adaptor"] = adaptor.presign(secret, p.sighash(p.state_tx(int(pl["cum"]))),
                                            adaptor.point_of(12345)).to_json()
        self.assertRefusedClean(presig_other_point, "bad_adaptor")

    def test_5_fee_quote_signed_live_and_paid(self):
        def underpay(pl, rt):                    # a consistent lock that pays less fee than due
            f = rt["fee"] - 1
            rt["fee"] = f
            cum = next_cum(self.pay.routed, rt["amount"] + f)
            self.pay.signer.void_lock(self.pay.chan)
            sa = self.pay.signer.sign_state_adaptor(self.pay.chan, cum, rt["point"])
            pl.update(cum=str(cum), adaptor=sa["adaptor"], point=sa["point"])
            rt["tweak"] = sa["tweak"]
        self.assertGreaterEqual(fee_due(self.pay.quote, max(1, self.sh.due_sat()), 0, 0)[0], 1)
        doc = self.assertRefusedClean(underpay, "route_fee")
        self.assertIn("feeDue", doc)

        now = int(time.time())
        forged = FeeQuote(**{**asdict(self.pay.quote), "feePpm": 0, "feeBaseMsat": 0}).sign(0xF00)   # not the hub
        self.assertRefusedClean(lambda pl, rt: rt.__setitem__("feeQuote", asdict(forged)), "route_fee")
        expired = FeeQuote(**{**asdict(self.pay.quote), "validUntil": now - 1}).sign(0x4B4B)       # the hub's, old
        self.assertRefusedClean(lambda pl, rt: rt.__setitem__("feeQuote", asdict(expired)), "route_fee")

    def test_7_one_lock_per_channel(self):
        self.hub.withhold = "all"                # the first lock stays pending at the hub
        st, doc = R.route_request(self.pay, self.sh)
        self.assertEqual(doc.get("error"), "route_pending")
        self.hub.withhold = ""
        self.assertTrue(self.st1().extra.get("route_lock"))
        st, doc = R.route_request(self.pay, self.sh)
        self.assertEqual(doc.get("error"), "lock_outstanding")

    def test_7_one_lock_per_ch2_across_clients(self):
        oc = self.hub.out.chans[self.origin]
        oc.pending = {"lockId": "other-client", "cum": 999, "d": 1, "T": "", "ch1": "x", "at": time.time()}
        st, doc = R.route_request(self.pay, self.sh)
        self.assertEqual(doc.get("error"), "lock_outstanding")
        self.assertFalse((self.st1().extra or {}).get("route_lock"))
        oc.pending = {}

    def test_order_the_first_failing_check_answers(self):
        both = [
            ("bad_auth", lambda pl, rt: (rt.__setitem__("point", "02" + "00" * 31 + "01"), "noauth")[1]),
            ("bad_point", lambda pl, rt: (rt.__setitem__("tweak", "11" * 32), pl.__setitem__("cum", "1"))),
            ("bad_amount", lambda pl, rt: (pl.__setitem__("cum", str(int(pl["cum"]) + 1)),
                                           rt.__setitem__("feeQuote", {}))),
            ("bad_adaptor", lambda pl, rt: (pl.__setitem__("adaptor", {**pl["adaptor"], "s1": "11" * 32}),
                                            rt.__setitem__("feeQuote", {}))),
        ]
        for code, tamper in both:
            with self.subTest(code):
                self.assertRefusedClean(tamper, code)


class HubExpiryRule(_World):
    pkw = {"amsat_per_call": 60 * AMSAT_PER_SAT}

    def setUp(self):
        super().setUp()
        # a client channel that ends before the hub's channel to the provider (+ delta): route_ok fails
        self.pay = R.payer(self.node, self.net, expiry_blocks=600)
        self.pay.open()
        self.sh = self.pay.shard(self.origin + "/v1/chunk")
        R.stream(self.pay, self.sh, 10)

    def test_6_route_ok_or_the_unguarded_cap(self):
        p1, p2 = self.pay.ch.payer.params, self.hub.out.chans[self.origin].p()
        self.assertFalse(route_ok(self.node.height, p1.expiry, p2.expiry, self.hub.close_margin, self.hub.delta))
        self.assertGreater(self.sh.due_sat(), self.hub.max_unguarded_lock_sat)       # 600 sat accrued
        self.assertRefusedClean(None, "route_expiry")
        # at or under maxUnguardedLockSat it is forwarded anyway (a bounded, unprofitable attack)
        def small(pl, rt):
            rt["amount"] = 400
            f, _ = fee_due(self.pay.quote, 400, 0, 0)
            rt["fee"] = f
            cum = next_cum(0, 400 + f)
            self.pay.signer.void_lock(self.pay.chan)
            sa = self.pay.signer.sign_state_adaptor(self.pay.chan, cum, rt["point"])
            pl.update(cum=str(cum), adaptor=sa["adaptor"], point=sa["point"])
            rt["tweak"] = sa["tweak"]
            rt["lockAuth"] = lock_auth(self.sh.key, self.sh.session, rt["lockId"], 400, rt["point"], self.pay.hub_pay_to)
        st, doc = R.route_request(self.pay, self.sh, tamper=small)
        self.assertEqual(st, 200, doc)


class ProviderLockChecks(_World):
    def _hub_lock(self, route_over=None, pl_over=None):
        """Send a ch2 lock to the provider as the hub would, with edits. Returns (status, doc)."""
        import json
        oc = self.hub.out.chans[self.origin]
        p2 = oc.p()
        inv = self.sh.invoice
        d = 3
        cum = next_cum(oc.routed, d, p2.min_amount)
        pre = adaptor.presign(int(oc.secret, 16), p2.sighash(p2.state_tx(cum)), adaptor.dec(inv["point"]))
        route = {"session": self.sh.session, "lockId": inv["lockId"], "amount": d, "hub": self.hub.pay_to,
                 "lockAuth": lock_auth(self.sh.key, self.sh.session, inv["lockId"], d, inv["point"], self.hub.pay_to)}
        route.update(route_over or {})
        oc.seq += 1
        pl = {"chan": p2.channel_id, "seq": oc.seq, "cum": str(cum), "point": inv["point"], "adaptor": pre.to_json()}
        pl.update(pl_over or {})
        body = json.dumps({"route": route}).encode()
        key = channel_auth_key(int(oc.secret, 16), bytes.fromhex(p2.payee_pub))
        pl["auth"] = request_auth(key, p2.channel_id, oc.seq, pl["cum"], None, request_digest("POST", ROUTE_LOCK_PATH, body))
        st, _, raw = self.net.http("POST", self.origin + ROUTE_LOCK_PATH, body,
                                   {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": {}, "payload": pl})})
        return st, json.loads(raw)

    def test_valid_lock_reveals_t_for_the_invoice_point(self):
        T = adaptor.dec(self.sh.invoice["point"])
        st, doc = self._hub_lock()
        self.assertEqual(st, 200, doc)
        self.assertEqual(adaptor.point_of(int(doc["secret"], 16)), T)

    def test_hub_cannot_reprice_a_lock(self):
        """The hub locks less on ch2 than the client authorised (to pocket the difference): refused,
        and t stays secret, so the hub cannot complete the client's ch1 lock either."""
        st, doc = self._hub_lock(route_over={"amount": 2}, pl_over={})
        self.assertEqual(doc["error"], "bad_auth")
        self.assertNotIn("secret", doc)

    def test_lock_for_another_hub_or_an_unbound_channel(self):
        st, doc = self._hub_lock(route_over={"hub": ecc.pubkey(0x999).hex()})
        self.assertEqual(doc["error"], "route_blocked")

    def test_invoice_fresh_and_expiring(self):
        st, doc = self._hub_lock(route_over={"lockId": "00" * 12})
        self.assertEqual(doc["error"], "bad_invoice")
        s = self.prov.routes.sessions[self.sh.session]
        s.valid_until = time.time() - 1
        st, doc = self._hub_lock()
        self.assertEqual(doc["error"], "bad_invoice")

    def test_amount_and_adaptor(self):
        oc = self.hub.out.chans[self.origin]
        p2 = oc.p()
        st, doc = self._hub_lock(pl_over={"cum": str(p2.min_amount + 1)})
        self.assertEqual(doc["error"], "bad_amount")
        bad = adaptor.presign(int(oc.secret, 16), p2.sighash(p2.state_tx(p2.min_amount)), adaptor.point_of(7)).to_json()
        st, doc = self._hub_lock(pl_over={"adaptor": bad})
        self.assertEqual(doc["error"], "bad_adaptor")

    def test_write_ahead_then_the_same_answer_again(self):
        """The provider saves the completed state and the lock (with t) before answering; a hub that
        lost the answer asks again and gets the same t, and the session is credited once."""
        st, first = self._hub_lock()
        st2 = self.st2()
        rec = st2.extra["route_locks"][first["lockId"]]
        self.assertEqual((st2.best_cum, rec["secret"]), (st2.params.min_amount, first["secret"]))
        from xbt402.ledger import Ledger
        reloaded = Ledger(self.prov.ledger.path).channels[st2.params.channel_id]     # on disk
        self.assertEqual(reloaded.extra["route_locks"][first["lockId"]]["secret"], first["secret"])
        paid = self.prov.routes.sessions[self.sh.session].paid_sat
        st, again = self._hub_lock(route_over={"lockId": first["lockId"]},
                                   pl_over={"point": adaptor.enc(adaptor.point_of(int(first["secret"], 16))).hex()})
        self.assertEqual((st, again["secret"]), (200, first["secret"]))
        self.assertEqual(self.prov.routes.sessions[self.sh.session].paid_sat, paid)

    def test_lost_answer_is_retried_and_settles_once(self):
        drops = {"n": 1}

        def drop(method, path):
            if path == ROUTE_LOCK_PATH and drops["n"]:
                drops["n"] -= 1
                return True
            return False
        self.net.drop[self.origin] = drop
        r = self.pay.lock(self.sh)
        self.assertEqual(r["status"], "paid", r)
        self.assertEqual(self.hub.out.chans[self.origin].routed, self.prov.routes.sessions[self.sh.session].paid_sat)


class Constraints(_World):
    n_providers = 4

    def test_c1_rate_and_locks_off_the_data_path(self):
        """>= 10 metered calls/s per provider on 4 providers while the per-window locks run beside them."""
        stop, counts = threading.Event(), {o: 0 for o in self.provs}

        def run(o):
            while not stop.is_set():
                st, _, _ = self.pay.call(self.shards[o], "POST", b"x")
                counts[o] += st == 200
                time.sleep(1 / 15)
        ths = [threading.Thread(target=run, args=(o,)) for o in self.provs]
        self.pay.start(interval=0.15)
        t0 = time.time()
        [t.start() for t in ths]
        time.sleep(2.0)
        stop.set()
        [t.join() for t in ths]
        self.pay.stop()
        dt = time.time() - t0
        for o, n in counts.items():
            self.assertGreaterEqual(n / dt, 10, (o, n / dt))
        self.assertGreaterEqual(self.pay.stats["locks"], 4)
        self.assertEqual(self.pay.stats["voided"], 0, self.pay.events)

    def test_c2_amsat_meter_and_carry_at_each_hop(self):
        """0.37 sat per call: provider and client meters agree to the amsat; each lock pays the ceil of
        the running total minus what is paid, so after the last lock paid == ceil(total) exactly. The
        hub's fee is carried the same way: fees == ceil(sum of exact fees)."""
        sh = self.sh
        exact_fee_units = 0
        for i in range(12):
            R.stream(self.pay, sh, 7)
            d = sh.due_sat()
            before = self.pay.fee_units
            r = self.pay.lock(sh)
            self.assertEqual(r["status"], "paid", r)
            exact_fee_units += self.pay.quote.units(d)
            self.assertEqual(self.pay.fee_units - before, self.pay.quote.units(d))
        s = self.prov.routes.sessions[sh.session]
        self.assertEqual(s.accrued_amsat, sh.accrued_amsat)
        self.assertEqual(s.accrued_amsat, sh.seen_amsat)
        self.assertEqual(s.accrued_amsat, (10 + 12 * 7) * 370 * 10 ** 18)
        self.assertEqual(s.paid_sat, ceil_div(s.accrued_amsat, AMSAT_PER_SAT))
        self.assertEqual(self.pay.fee_paid, ceil_div(exact_fee_units, FEE_UNITS_PER_SAT))
        st1 = self.st1()
        self.assertEqual(st1.extra["routed_sat"], self.pay.routed)
        self.assertEqual(st1.best_cum, max(self.pay.routed, DUST))

    def test_c3_fan_out_one_client_channel_serial_locks(self):
        """One ch1 pays 4 providers; locks are serial, so at most one lock (one provider's window) is
        ever at risk on ch1."""
        for o, sh in self.shards.items():
            R.stream(self.pay, sh, 20)
        seen = []
        orig = self.hub._forward

        def spy(st1, oc, lock1, rt, pl, t0):
            seen.append(sum(1 for c in self.hub.inbound.ledger.channels.values() if (c.extra or {}).get("route_lock")))
            return orig(st1, oc, lock1, rt, pl, t0)
        self.hub._forward = spy
        for sh in self.shards.values():
            self.assertEqual(self.pay.lock(sh)["status"], "paid")
        self.assertEqual(seen, [1, 1, 1, 1])
        self.assertEqual(len(self.hub.inbound.ledger.channels), 1)
        self.assertEqual(len({oc.p().channel_id for oc in self.hub.out.chans.values()}), 4)

    def test_c4_signed_quotes_end_to_end(self):
        """The client checks the provider's price quote and every per-call charge against it, and the
        hub's fee quote against the hub's payTo: a charge above the quote is refused."""
        sh = self.sh
        self.assertTrue(sh.quote.verify())
        self.assertTrue(self.pay.quote.verify())
        self.prov.routes.offers["/v1/chunk"].amsat_per_call *= 2          # the provider overcharges
        with self.assertRaises(Exception) as e:
            self.pay.call(sh, "POST", b"x")
        self.assertEqual(getattr(e.exception, "code", ""), "bad_receipt")

    def test_c7_one_payee_key_for_two_origins_one_ch2(self):
        # AGP-044: one live ch2 per payTo. One operator key behind two origins (CMP-023: one paid provider
        # per operator) gets ONE hub-funded ch2; both origins route over it.
        net, node, h = self.net, self.node, self.hub
        a = R.provider(node, net, "http://dev-a.test", 0xA0A0)
        net.apps["http://dev-b.test"] = a
        cap0 = h.committed_sat()
        oa = h.connect("http://dev-a.test")
        ob = h.connect("http://DEV-B.test:80/")                  # canonicalized
        self.assertEqual(oa.p().channel_id, ob.p().channel_id)
        self.assertEqual(h.committed_sat(), cap0 + oa.p().capacity)
        node.confirm_all()
        h.watch_tick()
        sa, sb = self.pay.shard("http://dev-a.test/v1/chunk"), self.pay.shard("http://dev-b.test/v1/chunk")
        self.assertEqual(sa.pay_to, sb.pay_to)
        for sh in (sa, sb):
            R.stream(self.pay, sh, 5)
            self.assertEqual(self.pay.lock(sh)["status"], "paid")
        self.assertNotIn("http://dev-b.test", h.out.chans)
        self.assertEqual(h.out.chans["http://dev-a.test"].routed, sa.locked_sat + sb.locked_sat)


class Withholding(_World):
    n_providers = 2

    def test_c6_hub_stops_forwarding_provider_stops_client_loses_one_lock(self):
        o2 = [o for o in self.provs if o != self.origin][0]
        self.hub.withhold = "all"
        R.stream(self.pay, self.shards[o2], 5)
        r = self.pay.lock(self.sh)
        self.assertEqual(r["status"], "pending")
        stuck = dict(self.pay.pending)
        # while one lock is out on ch1 nothing else is signed: the client's exposure is that one lock
        self.assertIsNone(self.pay.lock(self.shards[o2]))
        # the provider serves on credit for window + lockWait, then stops
        o = self.prov.routes.offers["/v1/chunk"]
        t0 = time.time()
        while time.time() - t0 < o.window + o.lock_wait + 1.0:
            st, _, _ = self.pay.call(self.sh, "POST", b"x")
            if st == 402:
                break
            time.sleep(0.05)
        self.assertEqual(st, 402)
        self.assertEqual(self.sh.stopped, "route_credit")
        self.assertLessEqual(time.time() - t0, o.window + o.lock_wait + 0.5)
        # the stuck lock is voided when its invoice expires unanswered; it is the only loss exposure
        self.pay.pending["until"] = time.time() - 1
        self.pay._check_pending()
        self.assertEqual(self.pay.pending, {})
        self.assertEqual(self.pay.stats["voided"], 1)
        self.assertLessEqual(stuck["d"] + stuck["f"], self.hub.max_lock_sat)

    def test_receipt_withheld_client_reads_t_from_the_provider(self):
        self.hub.withhold = "receipt"
        r = self.pay.lock(self.sh)
        self.assertEqual(r["status"], "pending")
        self.pay.call(self.sh, "POST", b"x")                    # the provider's ROUTE-STATE carries t
        self.assertEqual(self.pay.pending, {})
        self.assertEqual(self.pay.stats["via_provider"], 1)
        self.assertEqual(self.pay.routed, self.st1().extra["routed_sat"])

    def test_stale_answer_to_a_given_up_lock_then_resync(self):
        """The hub completes a lock but keeps the answer; the client gives it up (its invoice expired
        unanswered) and, before any data call brings a fresh invoice, tries the same invoice again. The
        hub replays its first answer (t + r of the first attempt): the client sees it does not open this
        attempt's T1 and drops it, and its next lock resyncs to the hub's view and is paid."""
        self.hub.withhold = "receipt"
        self.assertEqual(self.pay.lock(self.sh)["status"], "pending")
        self.hub.withhold = ""
        self.pay.pending["until"] = time.time() - 1
        self.pay._check_pending()                                  # given up; no ROUTE-STATE seen since
        self.assertEqual(self.pay.stats["voided"], 1)
        self.assertEqual(self.pay.lock(self.sh), {"status": "refused", "error": "stale_answer"})
        R.stream(self.pay, self.sh, 3)                             # a fresh invoice (and lastLock) arrives
        self.assertEqual(self.pay.lock(self.sh)["status"], "resynced")
        R.stream(self.pay, self.sh, 3)
        self.assertEqual(self.pay.lock(self.sh)["status"], "paid")
        self.assertEqual(self.pay.routed, self.st1().extra["routed_sat"])
        self.assertEqual(self.pay.signed, self.st1().best_cum)

    def test_provider_never_reveals_hub_writes_off_and_blocks(self):
        self.prov.routes.no_reveal = True
        R.stream(self.pay, self.sh, 30)
        self.hub.reveal_timeout = 0.3
        best1, best2 = self.st1().best_cum, self.st2().best_cum
        r = self.pay.lock(self.sh)
        self.assertEqual(r, {"status": "refused", "error": "route_failed"})
        self.assertEqual((self.st1().best_cum, self.st2().best_cum), (best1, best2))
        oc = self.hub.out.chans[self.origin]
        self.assertTrue(oc.blocked)
        self.assertEqual(len(oc.stale), 1)                        # kept for on-chain recovery
        st, doc = R.route_request(self.pay, self.sh)
        self.assertEqual(doc["error"], "route_blocked")


class WatcherAndRestart(_World):
    def test_t_from_a_ch2_close_completes_ch1_even_after_a_hub_restart(self):
        """The provider completes the lock but its answers never reach the hub; the hub writes the lock
        off (kept), restarts, and its watcher reads t off the provider's ch2 close and completes ch1.
        The client, which never heard back, reads t + r off the hub's ch1 close."""
        R.stream(self.pay, self.sh, 10)
        self.net.drop[self.origin] = lambda m, p: p == ROUTE_LOCK_PATH
        self.hub.reveal_timeout = 0.3
        pend_client = None
        orig = self.pay.signer.void_lock
        self.pay.signer.void_lock = lambda chan: {}               # the client keeps its lock to recover it
        r = self.pay.lock(self.sh)
        self.assertEqual(r["status"], "refused")
        pend_client = self.pay.signer.pending_lock(self.pay.chan)
        self.assertTrue(pend_client)
        st2 = self.st2()
        self.assertEqual(st2.best_cum, st2.params.min_amount)    # the provider did complete it
        from xbt402.hub import RouteHub
        hub2 = RouteHub(self.node, 0x4B4B, R.NET, os.path.dirname(self.hub.out.path), self.node.fund_address,
                        http=self.net.http, close_margin=36, delta=36)
        self.assertEqual(len(hub2.out.chans[self.origin].stale), 1)
        with self.prov.ledger.lock:
            close2 = self.prov._close_locked(st2)
        acts = hub2.watch_tick()
        self.assertTrue(any(a["event"] == "secret_from_close" and a["ch1_completed"] for a in acts), acts)
        st1 = hub2.inbound.ledger.channels[self.pay.chan]
        self.assertEqual(st1.best_cum, int(pend_client["cum"]))
        with hub2.inbound.ledger.lock:
            close1 = hub2.inbound._close_locked(st1)
        from xbt402.tx import Tx
        t = self.pay.signer.recover_lock(self.pay.chan, Tx.parse(bytes.fromhex(self.node.raw[close1])))
        self.assertEqual(adaptor.enc(adaptor.point_of(int(t, 16))).hex(), pend_client["T"])
        self.pay.signer.void_lock = orig
        self.assertTrue(close2)


class ResyncAfterChainRecovery(_World):
    n_providers = 2

    def test_client_adopts_only_a_lock_it_gave_up(self):
        """The hub writes a lock off (no answer from the provider), the client gives it up too; the
        provider had completed it and closes ch2; the hub reads t off the close and counts the lock.
        The client's next lock (to another provider) is refused bad_amount with the hub's view, which
        the client adopts because bestCum is a lock it pre-signed; routing goes on."""
        o2 = [o for o in self.provs if o != self.origin][0]
        self.net.drop[self.origin] = lambda m, p: p == ROUTE_LOCK_PATH
        self.hub.reveal_timeout = 0.3
        self.assertEqual(self.pay.lock(self.sh)["status"], "refused")
        gone = self.pay.given_up[-1]
        with self.prov.ledger.lock:
            self.prov._close_locked(self.st2())
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "secret_from_close" for a in acts), acts)
        self.assertEqual(self.st1().best_cum, gone["cum"])
        R.stream(self.pay, self.shards[o2], 5)
        self.assertEqual(self.pay.lock(self.shards[o2])["status"], "resynced")
        self.assertEqual(self.pay.signed, gone["cum"])
        self.assertEqual(self.pay.lock(self.shards[o2])["status"], "paid")
        self.assertEqual(self.pay.routed, self.st1().extra["routed_sat"])
        # a hub view that is not one of our given-up locks is never adopted
        self.assertFalse(self.pay._resync({"bestCum": 10 ** 6, "routedSat": 1, "feeUnits": 0, "feePaid": 0}))
        with self.assertRaises(Exception):
            self.pay.signer.adopt_lock(self.pay.chan, 10 ** 6)


class HubConfigTests(unittest.TestCase):
    def test_liquidity_cap_and_fee_strategies_are_config(self):
        from xbt402.hub import HubConfig
        node, net = R.RouteNode(), R.Net()
        R.provider(node, net, "http://a.test")
        R.provider(node, net, "http://b.test")
        h = R.hub(node, net, liquidity_cap_sat=150_000, ch2_capacity=100_000,
                  fee_strategy={"kind": "utilization", "ppm_min": 1_000, "ppm_max": 9_000, "base_msat": 0})
        q0 = h.fee_quote()
        self.assertEqual((q0.feeBaseMsat, q0.feePpm), (0, 1_000))
        h.connect("http://a.test")
        q1 = h.fee_quote()
        self.assertEqual(q1.feePpm, 1_000 + int(8_000 * 100_000 / 150_000))
        self.assertGreater(q1.seq, q0.seq)                         # a new signed quote, the old one still live
        with self.assertRaises(Exception) as e:
            h.connect("http://b.test")                              # 200,000 > 150,000
        self.assertEqual(e.exception.code, "liquidity_cap")
        with self.assertRaises(ValueError):
            HubConfig.from_dict({"fee_ppm": 1, "hub_pays_close": True})
        custom = R.hub(node, net, secret=0x77, fee_strategy=None)
        custom.fee_strategy = lambda hub: (5, 7)
        self.assertEqual((custom.fee_quote().feeBaseMsat, custom.fee_quote().feePpm), (5, 7))


class Rollover(_World):
    pkw = {"settle_multiple": 2, "amsat_per_call": 40 * AMSAT_PER_SAT}

    def test_c5_hub_funds_and_rolls_ch2_at_the_providers_threshold(self):
        oc = self.hub.out.chans[self.origin]
        first = oc.p().channel_id
        R.stream(self.pay, self.sh, 40)                           # 1,600 sat accrued
        self.assertEqual(self.pay.lock(self.sh)["status"], "paid")
        # the provider's threshold counts its own close fee (payee-pays ch2, AGP-023): net >= 2 x fee
        self.assertGreaterEqual(oc.signed - oc.p().close_fee, 2 * oc.p().close_fee)
        acts = self.hub.watch_tick()
        roll = next(a for a in acts if a.get("event") == "ch2_rollover")
        self.assertEqual(roll["amount"], oc.signed)
        from xbt402.tx import Tx
        tx = Tx.parse(bytes.fromhex(self.node.raw[roll["txid"]]))
        p = oc.p()
        # pays the provider its balance less its own close fee; the next ch2 takes all the hub's rest
        self.assertEqual(tx.outputs[0].value, oc.signed - p.close_fee)
        self.assertEqual(tx.outputs[1].value, p.capacity - oc.signed)
        self.assertEqual(tx.inputs[0].txid[::-1].hex() + f":{tx.inputs[0].vout}", first)
        new = self.hub.out.chans[self.origin]
        self.assertEqual((new.state, new.p().funding_txid), ("funded", roll["txid"]))
        self.node.confirm_all()
        self.hub.watch_tick()
        self.assertEqual(new.state, "open")
        R.stream(self.pay, self.sh, 5)
        self.assertEqual(self.pay.lock(self.sh)["status"], "paid")   # routing goes on over the new ch2
        st_new = next(s for s in self.prov.ledger.channels.values() if s.params.channel_id == new.p().channel_id)
        self.assertGreater(st_new.best_cum, 0)

    def test_no_rollover_while_a_lock_is_pending(self):
        oc = self.hub.out.chans[self.origin]
        oc.signed = 5_000
        oc.pending = {"lockId": "x", "cum": 5_100, "d": 100, "T": self.sh.invoice["point"], "ch1": self.pay.chan,
                      "at": time.time() + 60, "route": {}}
        self.hub.reveal_timeout = 120
        acts = self.hub.watch_tick()
        self.assertFalse([a for a in acts if a.get("event") == "ch2_rollover"])
        oc.pending = {}


class FeeCarryUnit(unittest.TestCase):
    def test_fee_carry_is_exact_and_never_rounds_per_lock(self):
        q = FeeQuote("02" + "11" * 32, R.NET, 100, 2_000, 1, 1, 1, 1, 1, 0, 1)
        units = paid = 0
        fees = []
        for d in [3] * 1000:                                  # 1000 locks of 3 sat: exact fee 0.106 sat each
            f, units = fee_due(q, d, units, paid)
            paid += f
            fees.append(f)
        self.assertEqual(paid, ceil_div(1000 * (100 * 10 ** 6 + 3 * 1000 * 2_000), FEE_UNITS_PER_SAT))
        self.assertEqual(paid, 106)
        self.assertTrue(all(f in (0, 1) for f in fees))


if __name__ == "__main__":
    unittest.main()
