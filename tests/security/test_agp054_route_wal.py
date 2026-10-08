"""AGP-054: routed billing throughput without weakening the meter's durability.

RouteWal (xbt402/route.py): a routed session's meter (seq, calls, accrued, unpaid_since) is durable
before its ROUTE-STATE leaves, and its fsync is written ahead while the handler runs.
  * every answered state survives a crash; a restart counts more only for calls in flight at the
    crash (authenticated, not answered), each at its projected charge;
  * a seq is durable before its handler runs: no ROUTE-AUTH is served twice across a crash;
  * a charge other than the projected one is corrected before its answer leaves;
  * a routes-file save during a call (a lock completing) covers that call's reservation;
  * rework 1: a state carries the session's CURRENT meter, so with concurrent calls on one session
    (or a seq a later begin_call took) it waits for a snapshot covering THAT, and so does a 402's
    routeState; a failed call is not taken back once a later state carries it; versions resume
    above the routes file's walV if the log was lost;
  * a write failure answers 500 route_wal_failed with no ROUTE-STATE and bills nothing;
  * the fsync overlaps the handler, and concurrent calls share one (group commit);
  * compaction keeps the latest snapshot per session.
ROUTE-STATE's invoice is signed once per window (byte-identical within a window).
RoutePayer: a data call never resolves a lock whose POST is still out; a hub refusal of a lock the
provider's signed state shows as paid resolves it through the provider instead of voiding it.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402 import route as route_mod  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, RouteWal, call_auth, state_verify  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider, b64json, request_digest_v2, unb64json  # noqa: E402
from sechelp import crashed

PRICE = 370 * 10 ** 18
PATH = "/v1/chunk"


class Box:
    """A provider on disk that can be 'crashed' (dropped without a save) and started again."""

    def __init__(self, d, *, handler=None, precharge=True, charge=None, wal=True, compact_bytes=None):
        self.d, self.wal, self.handler = d, wal, handler
        self.precharge, self.charge, self.compact_bytes = precharge, charge, compact_bytes
        self.node = R.RouteNode()
        self.start()

    def start(self):
        if getattr(self, "p", None) is not None:
            crashed(self.p)
        pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36)
        h = self.handler or (lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"ok":1}'))
        self.p = XbtChannelProvider(self.node, 0x5151, R.NET, os.path.join(self.d, "prov.json"), lambda m, p: 1000,
                                    lambda m, p, b: h(m, p, b), close_margin=36, policy=pol, height_ttl=0,
                                    route_wal=os.path.join(self.d, "prov.route-wal") if self.wal else None)
        if self.compact_bytes is not None and self.p.routes.wal is not None:
            self.p.routes.wal.compact_bytes = self.compact_bytes
        self.p.offer_route(PATH, window=5.0, lock_wait=5.0, amsat_per_call=PRICE, charge=self.charge,
                           precharge=(lambda m, p, b: PRICE) if self.precharge else None)
        return self.p


class Client:
    """ROUTE-CLIENT / ROUTE-AUTH by hand (b1 RoutePayer.shard / call without a hub)."""

    def __init__(self, box):
        from xbt402 import ecc
        from xbt402.route import session_key
        import secrets
        self.box = box
        c = secrets.randbelow(ecc.N - 1) + 1
        st, h, _ = box.p.serve("POST", PATH, {"ROUTE-CLIENT": ecc.pubkey(c).hex()}, b"")
        assert st == 402, st
        pr = unb64json(h["PAYMENT-REQUIRED"])
        self.session = pr["accepts"][0]["extra"]["route"]["session"]
        self.key = session_key(c, bytes.fromhex(box.p.pay_to))
        self.seq = 0
        self.states = []

    def request(self, body=b"x", seq=None):
        if seq is None:
            self.seq += 1
            seq = self.seq
        hdr = b64json({"session": self.session, "seq": seq,
                       "auth": call_auth(self.key, self.session, seq, request_digest_v2("POST", PATH, body))})
        return {"ROUTE-AUTH": hdr}, body

    def call(self, body=b"x", seq=None):
        h, b = self.request(body, seq)
        st, rh, out = self.box.p.serve("POST", PATH, h, b)
        if "ROUTE-STATE" in rh:
            s = unb64json(rh["ROUTE-STATE"])
            assert state_verify(self.box.p.pay_to, s)
            self.states.append(s)
        return st, rh, out


def meter(p, sid):
    s = p.routes.sessions[sid]
    return s.seq, s.calls, s.accrued_amsat


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="agp054-")


class TestReplay(_Tmp):
    def test_every_answered_state_survives_a_crash(self):
        box = Box(self.d)
        c = Client(box)
        for _ in range(25):
            self.assertEqual(c.call()[0], 200)
        last = c.states[-1]
        box.start()                                             # crash: nothing saved since the open
        self.assertEqual(meter(box.p, c.session), (25, 25, 25 * PRICE))
        self.assertEqual(int(last["accruedAmsat"]), 25 * PRICE)
        # an already-served ROUTE-AUTH is refused after the restart (seq was durable)
        h, b = c.request(seq=25)
        st, _, out = box.p.serve("POST", PATH, h, b)
        self.assertEqual(st, 402)
        self.assertIn("bad_auth", out.decode())
        self.assertEqual(c.call()[0], 200)
        self.assertEqual(int(c.states[-1]["accruedAmsat"]), 26 * PRICE)

    def test_without_the_wal_a_crash_rewinds_the_meter(self):
        """The baseline the WAL closes (why cmp journaled every call)."""
        box = Box(self.d, wal=False)
        c = Client(box)
        for _ in range(5):
            c.call()
        box.start()
        self.assertEqual(meter(box.p, c.session), (0, 0, 0))

    def test_a_call_in_flight_at_the_crash_counts_once_at_its_projection(self):
        entered, release = threading.Event(), threading.Event()

        def slow(m, p, b):
            if b == b"slow":
                entered.set()
                release.wait(5)
            return 200, {}, b"ok"
        box = Box(self.d, handler=slow)
        c = Client(box)
        for _ in range(3):
            c.call()
        h, b = c.request(b"slow")
        th = threading.Thread(target=box.p.serve, args=("POST", PATH, h, b), daemon=True)
        th.start()
        self.assertTrue(entered.wait(5))
        box.p.routes.wal.wait(box.p.routes.wal.v)             # the projection is on disk while it runs
        old = box.p
        box.start()                                             # crash mid-handler
        self.assertEqual(meter(box.p, c.session), (4, 4, 4 * PRICE))   # the in-doubt call, exactly once
        st, _, out = box.p.serve("POST", PATH, h, b)            # its seq is durable: never served twice
        self.assertEqual(st, 402)
        self.assertIn("bad_auth", out.decode())
        release.set()
        th.join(5)
        self.assertIsNot(old, box.p)

    def test_a_charge_other_than_projected_is_corrected_before_the_answer(self):
        def h(m, p, b):
            return (503, {}, b"busy") if b == b"fail" else (200, {}, b"ok")
        box = Box(self.d, handler=h)
        c = Client(box)
        c.call()
        st, rh, _ = c.call(b"fail")                               # 5xx: charge 0, projected PRICE
        self.assertEqual(st, 503)
        self.assertEqual(int(c.states[-1]["accruedAmsat"]), PRICE)
        box.start()
        self.assertEqual(meter(box.p, c.session), (2, 2, PRICE))

    def test_a_metered_charge_below_the_precharge_is_corrected(self):
        box = Box(self.d, charge=lambda m, p, st, out: PRICE // 3)
        c = Client(box)
        for _ in range(4):
            c.call()
        self.assertEqual(int(c.states[-1]["accruedAmsat"]), 4 * (PRICE // 3))
        box.start()
        self.assertEqual(meter(box.p, c.session), (4, 4, 4 * (PRICE // 3)))

    def test_a_routes_file_save_during_a_call_covers_it(self):
        """A lock completing (a routes-file save) while a call runs: the file holds the call's
        projection, so the reserved snapshot needs no second fsync and the answer still survives."""
        box = Box(self.d)
        c = Client(box)
        c.call()

        def h(m, p, b):
            with box.p.routes.lock:
                box.p.routes._save()                           # what complete_lock does mid-call
            return 200, {}, b"ok"
        box.handler = h
        box.start()
        fs = box.p.routes.wal.fsyncs
        c.call()
        self.assertEqual(box.p.routes.wal.fsyncs - fs, 1)       # the reservation only
        box.start()
        self.assertEqual(meter(box.p, c.session), (2, 2, 2 * PRICE))

    def test_a_handler_exception_is_an_in_doubt_call_then_corrected(self):
        def h(m, p, b):
            if b == b"boom":
                raise RuntimeError("boom")
            return 200, {}, b"ok"
        box = Box(self.d, handler=h)
        c = Client(box)
        c.call()
        h1, b1 = c.request(b"boom")
        with self.assertRaises(RuntimeError):
            box.p.serve("POST", PATH, h1, b1)
        box.p.routes.wal.wait(box.p.routes.wal.v)
        box.start()
        self.assertEqual(meter(box.p, c.session), (2, 1, PRICE))   # seq kept, the call not billed

    def test_a_wal_write_failure_is_a_500_with_nothing_billed(self):
        box = Box(self.d)
        c = Client(box)
        c.call()
        real = os.fdatasync
        fail = {"on": True}

        def bad(fd):
            if fail["on"]:
                raise OSError(5, "EIO (test)")
            return real(fd)
        route_mod.os.fdatasync = bad
        try:
            st, rh, out = c.call()
        finally:
            route_mod.os.fdatasync = real
        self.assertEqual(st, 500)
        self.assertNotIn("ROUTE-STATE", rh)
        self.assertEqual(json.loads(out)["error"], "route_wal_failed")
        self.assertEqual(meter(box.p, c.session), (2, 1, PRICE))    # taken back in memory
        self.assertEqual(c.call()[0], 200)                          # the disk healed
        self.assertEqual(int(c.states[-1]["accruedAmsat"]), 2 * PRICE)
        box.start()
        self.assertEqual(meter(box.p, c.session), (3, 2, 2 * PRICE))

    def test_a_wal_failure_is_not_taken_back_once_a_later_state_carries_it(self):
        """Rework 1: A fails its write while B (metered after A) answers from a durable snapshot that
        holds A's charge. Taking A back would make the next state go below B's."""
        box = Box(self.d)
        c = Client(box)
        rs, wal = box.p.routes, box.p.routes.wal
        s = rs.sessions[c.session]
        tA = rs.reserve(s, PRICE)
        wal.wait(tA[0])
        gate, orig = threading.Event(), wal._write

        def slow(batch):
            if any(v == tA[0] + 1 for v, _, _ in batch):
                gate.wait(10)
                raise OSError(5, "EIO (test)")
            return orig(batch)
        wal._write = slow
        tB = rs.reserve(s, PRICE)                                  # v2: its batch will fail
        out = {}

        def run(k, charge, t):
            try:
                out[k] = rs.end_call(s, charge, t)
            except route_mod.ChannelError as e:
                out[k] = e.code
        a = threading.Thread(target=run, args=("A", PRICE, tA)); a.start()
        time.sleep(0.2)                                            # A metered, waiting on v2
        b = threading.Thread(target=run, args=("B", PRICE // 2, tB)); b.start()
        time.sleep(0.2)                                            # B corrected: its own v3
        gate.set(); a.join(5); b.join(5)
        self.assertEqual(out["A"], "route_wal_failed")
        self.assertEqual(out["B"]["calls"], 2)
        self.assertEqual(int(out["B"]["accruedAmsat"]), PRICE + PRICE // 2)
        self.assertEqual((s.calls, s.accrued_amsat), (2, PRICE + PRICE // 2))   # A stays billed
        box.start()
        self.assertGreaterEqual(meter(box.p, c.session)[2], PRICE + PRICE // 2)


class TestCoveringSnapshot(_Tmp):
    """Rework 1 (agp-lead repro tests/security/lead_wal_race_repro.py): a ROUTE-STATE carries the
    session's CURRENT meter, so it may leave only once a snapshot covering THAT is durable, not
    merely the call's own reserved one. Each test holds the writer on the later snapshot and checks,
    at the moment a state is returned, that the durable log already covers it."""

    def _hold(self, wal, from_v):
        gate, orig = threading.Event(), wal._write

        def slow(batch):
            if any(v >= from_v for v, _, _ in batch):
                gate.wait(10)
            return orig(batch)
        wal._write = slow
        return gate

    def _covered(self, box, sid, state):
        d = box.p.routes.wal.read()[sid]
        return (d["seq"] >= int(state["seq"]) and d["calls"] >= int(state["calls"])
                and int(d["acc"]) >= int(state["accruedAmsat"]))

    def _answer_then_release(self, box, sid, fn):
        """Run fn (returns a state) in a thread; while the writer is held it must not return; at
        its return the durable log must cover what it returned."""
        res = {}

        def go():
            st = fn()
            res["covered"] = st is None or self._covered(box, sid, st)
            res["state"] = st
        th = threading.Thread(target=go)
        th.start()
        th.join(0.3)
        early = not th.is_alive()
        return th, res, early

    def test_concurrent_calls_on_one_session_wait_for_the_later_snapshot(self):
        box = Box(self.d)
        c = Client(box)
        rs, wal = box.p.routes, box.p.routes.wal
        s = rs.sessions[c.session]
        tA = rs.reserve(s, PRICE)
        wal.wait(tA[0])                                            # A's snapshot v1 durable
        gate = self._hold(wal, tA[0] + 1)
        tB = rs.reserve(s, PRICE)                                  # B's snapshot v2: writer held
        thB = threading.Thread(target=lambda: rs.end_call(s, PRICE, tB)); thB.start()
        time.sleep(0.2)                                            # B metered in memory, waiting on v2
        thA, res, early = self._answer_then_release(box, c.session, lambda: rs.end_call(s, PRICE, tA))
        gate.set(); thA.join(5); thB.join(5)
        self.assertFalse(early, "A's state (calls 2) left while only v1 (calls 1) was durable")
        self.assertTrue(res["covered"])
        self.assertEqual(res["state"]["calls"], 2)
        self.assertEqual(int(res["state"]["accruedAmsat"]), 2 * PRICE)

    def test_a_seq_taken_by_a_concurrent_begin_call_is_durable_before_a_state_carries_it(self):
        box = Box(self.d)
        c = Client(box)
        rs, wal = box.p.routes, box.p.routes.wal
        s = rs.sessions[c.session]
        h, b = c.request()                                         # A: seq 1
        sA, err = rs.begin_call(PATH, h["ROUTE-AUTH"], "POST", PATH, b)
        self.assertIsNone(err)
        tA = rs.reserve(sA, PRICE)
        wal.wait(tA[0])
        h, b = c.request()                                         # C: seq 2, authenticated, not reserved yet
        rs.begin_call(PATH, h["ROUTE-AUTH"], "POST", PATH, b)
        gate = self._hold(wal, tA[0] + 1)
        thA, res, early = self._answer_then_release(box, c.session, lambda: rs.end_call(s, PRICE, tA))
        gate.set(); thA.join(5)
        self.assertFalse(early, "A's state carried seq 2 while the durable seq was 1")
        self.assertTrue(res["covered"])
        self.assertEqual(res["state"]["seq"], 2)
        box.start()                                                # C's ROUTE-AUTH is not served again
        self.assertEqual(meter(box.p, c.session)[0], 2)

    def test_a_refusal_state_is_durable_before_the_402_carries_it(self):
        box = Box(self.d)
        c = Client(box)
        rs, wal = box.p.routes, box.p.routes.wal
        s = rs.sessions[c.session]
        self.assertEqual(c.call()[0], 200)
        h, b = c.request()                                         # a refused call still takes its seq
        rs.begin_call(PATH, h["ROUTE-AUTH"], "POST", PATH, b)
        gate = self._hold(wal, wal.v + 1)
        th, res, early = self._answer_then_release(box, c.session, lambda: rs.refusal_state(s))
        gate.set(); th.join(5)
        self.assertFalse(early)
        self.assertTrue(res["covered"])
        self.assertEqual(res["state"]["seq"], 2)

    def test_a_refusal_402_carries_a_covered_state(self):
        box = Box(self.d)
        c = Client(box)
        self.assertEqual(c.call()[0], 200)
        box.p.routes.sessions[c.session].unpaid_since = time.time() - 60   # past window + lock_wait
        st, rh, _ = c.call()
        self.assertEqual(st, 402)
        doc = unb64json(rh["PAYMENT-REQUIRED"])
        self.assertEqual(doc["routeState"]["seq"], 2)
        self.assertTrue(self._covered(box, c.session, doc["routeState"]))
        box.start()
        self.assertEqual(meter(box.p, c.session), (2, 1, PRICE))

    def test_sequential_calls_still_answer_from_their_reserved_snapshot(self):
        """The rule keeps the overlap: one snapshot per call when calls do not overlap."""
        box = Box(self.d)
        c = Client(box)
        v0 = box.p.routes.wal.v
        for _ in range(10):
            self.assertEqual(c.call()[0], 200)
        self.assertEqual(box.p.routes.wal.v - v0, 10)

    def test_a_lost_log_does_not_restart_below_walv(self):
        box = Box(self.d)
        c = Client(box)
        for _ in range(3):
            c.call()
        box.p.routes._save()
        saved = box.p.routes._saved_v
        self.assertGreater(saved, 0)
        os.remove(os.path.join(self.d, "prov.route-wal"))
        box.start()
        self.assertGreaterEqual(box.p.routes.wal.v, saved)
        self.assertEqual(c.call()[0], 200)
        box.start()                                                # the new line wins over the file
        self.assertEqual(meter(box.p, c.session), (4, 4, 4 * PRICE))

    def test_compaction_keeps_the_latest_snapshot_per_session(self):
        box = Box(self.d, compact_bytes=400)
        cs = [Client(box) for _ in range(3)]
        for i in range(40):
            cs[i % 3].call()
        wal = box.p.routes.wal
        wal.wait(wal.v)
        time.sleep(0.05)
        self.assertLess(os.path.getsize(wal.path), 2_000)
        box.start()
        for c in cs:
            n = len(c.states)
            self.assertEqual(meter(box.p, c.session), (n, n, n * PRICE))


class TestOverlap(_Tmp):
    def test_the_fsync_runs_while_the_handler_computes(self):
        real = os.fdatasync

        def slow_sync(fd):
            time.sleep(0.15)
            return real(fd)

        def compute(m, p, b):
            time.sleep(0.15)
            return 200, {}, b"ok"
        box = Box(self.d, handler=compute)
        c = Client(box)
        c.call()
        route_mod.os.fdatasync = slow_sync
        try:
            t = time.monotonic()
            self.assertEqual(c.call()[0], 200)
            overlapped = time.monotonic() - t
        finally:
            route_mod.os.fdatasync = real
        self.assertLess(overlapped, 0.27)                         # not 0.15 + 0.15

    def test_without_a_precharge_the_answer_waits_for_its_own_fsync(self):
        real = os.fdatasync

        def slow_sync(fd):
            time.sleep(0.15)
            return real(fd)
        box = Box(self.d, precharge=False, charge=lambda m, p, st, out: PRICE,
                  handler=lambda m, p, b: (time.sleep(0.15), (200, {}, b"ok"))[1])
        c = Client(box)
        c.call()
        route_mod.os.fdatasync = slow_sync
        try:
            t = time.monotonic()
            c.call()
            serial = time.monotonic() - t
        finally:
            route_mod.os.fdatasync = real
        self.assertGreaterEqual(serial, 0.29)
        box.start()
        self.assertEqual(meter(box.p, c.session), (2, 2, 2 * PRICE))

    def test_concurrent_calls_share_fsyncs(self):
        real = os.fdatasync

        def slow_sync(fd):
            time.sleep(0.02)
            return real(fd)
        box = Box(self.d, handler=lambda m, p, b: (time.sleep(0.005), (200, {}, b"ok"))[1])
        cs = [Client(box) for _ in range(8)]
        route_mod.os.fdatasync = slow_sync
        try:
            fs = box.p.routes.wal.fsyncs
            ths = [threading.Thread(target=lambda c=c: [c.call() for _ in range(10)]) for c in cs]
            for t in ths:
                t.start()
            for t in ths:
                t.join()
            used = box.p.routes.wal.fsyncs - fs
        finally:
            route_mod.os.fdatasync = real
        self.assertLess(used, 80 // 2)                           # grouped, not one per call
        box.start()
        for c in cs:
            self.assertEqual(meter(box.p, c.session), (10, 10, 10 * PRICE))


class TestInvoiceCache(_Tmp):
    def test_one_invoice_signature_per_window(self):
        box = Box(self.d, wal=False)
        c = Client(box)
        c.call()
        c.call()
        self.assertEqual(c.states[0]["invoice"], c.states[1]["invoice"])
        s = box.p.routes.sessions[c.session]
        box.p.routes._new_window(s)
        c.call()
        inv = c.states[-1]["invoice"]
        self.assertNotEqual(inv["lockId"], c.states[0]["invoice"]["lockId"])
        self.assertTrue(route_mod.Invoice.from_dict(inv).verify())


class TestPayerLockPath(unittest.TestCase):
    def setUp(self):
        self.node, self.net, self.hub, self.provs, self.pay, self.shards = R.world(1)
        self.origin = next(iter(self.provs))
        self.sh = self.shards[self.origin]
        R.stream(self.pay, self.sh, 10)

    def _hub_hook(self, after):
        inner = self.net.apps[R.HUB]

        class Hook:
            def serve(s, method, path, headers, body, url=""):
                out = inner.serve(method, path, headers, body, url)
                return after(path, out) if path == "/x402/route" else out
        self.net.apps[R.HUB] = Hook()

    def test_a_data_call_never_resolves_a_lock_whose_post_is_out(self):
        seen = {}

        def after(path, out):
            self.pay.call(self.sh, "POST", b"x")                  # the provider's state now shows t
            seen["pending"] = dict(self.pay.pending)
            seen["last"] = dict(self.sh.last_lock)
            return out
        self._hub_hook(after)
        r = self.pay.lock(self.sh)
        self.assertTrue(seen["pending"], "the data call resolved the in-flight lock")
        self.assertEqual(seen["last"].get("lockId"), seen["pending"]["lockId"])
        self.assertEqual(r["status"], "paid")
        self.assertEqual(self.pay.stats["via_provider"], 0)
        self.assertEqual(self.pay.pending, {})

    def test_a_refusal_of_a_lock_the_provider_was_paid_for_resolves_via_the_provider(self):
        def after(path, out):
            self.pay.call(self.sh, "POST", b"x")
            return 502, {"Content-Type": "application/json"}, json.dumps({"error": "route_failed"}).encode()
        self._hub_hook(after)
        r = self.pay.lock(self.sh)
        self.assertEqual((r["status"], r.get("via")), ("paid", "provider"))
        self.assertEqual((self.pay.stats["voided"], self.pay.stats["via_provider"]), (0, 1))
        self.assertEqual(self.pay.routed, self.hub.inbound.ledger.channels[self.pay.chan].extra["routed_sat"])
        prov = self.provs[self.origin]
        self.assertEqual(self.sh.locked_sat, prov.routes.sessions[self.sh.session].paid_sat)

    def test_receipt_withheld_still_resolves_from_the_next_data_call(self):
        self.hub.withhold = "receipt"
        r = self.pay.lock(self.sh)
        self.assertEqual(r["status"], "pending")
        self.pay.call(self.sh, "POST", b"x")
        self.assertEqual(self.pay.pending, {})
        self.assertEqual(self.pay.stats["via_provider"], 1)


if __name__ == "__main__":
    unittest.main()
