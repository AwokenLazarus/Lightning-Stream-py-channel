"""AGP-085: fix wave 3, the hub items (in-process: a fake node + a fake HTTP transport). xbt-rs has the
same tests, without `test_`.

Item 1, the next ch2 of a rollover. The hub writes the next ch2 (key, refund) ahead of the rollover
request. It then dropped it when the provider answered 400/401/403, and replaced it with a fresh key
at every later attempt. A provider that answers an error and broadcasts anyway (or whose node took the
transaction after erroring: AGP-084), or whose reply was lost while the hub's node had not seen the
transaction yet, left the next capacity in a script the hub had no key and no refund for. Now there
is one next key per ch2, kept until a confirmed spend of the funding shows the rollover did not happen.

Item 2, ch1's counters. A lock's `units` and `after` are totals fixed when it is admitted. A hold
released while that lock was in flight (the watcher, on another provider's ch2) came back when the
lock completed or was held, and the client, which had taken the release out, disagreed for good.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402  (W: providers whose /lock answer can be held or refused)

from xbt402 import ecc  # noqa: E402
from xbt402.channel import SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams  # noqa: E402
from xbt402.hub import OutBook, OutChannel, RouteHub  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, ROLLOVER_PATH, ROUTE_LOCK_PATH  # noqa: E402
from xbt402.tx import Tx  # noqa: E402

SHORT_CH2 = {"ch2_expiry_blocks": 100, "ch2_max_expiry_blocks": 2_000}    # the hub asks for the terms' floor
REFUSED = (400, {"error": "bad_amount", "detail": "no"})


class RolloverWorld:
    """routehelp's world with one provider whose ch2 carries a signed state, and an `answer` the
    provider's rollover endpoint can be made to give: `answer(body, serve) -> (status, doc)`, where
    `serve()` runs the real endpoint (which broadcasts). `lost`: the answer never arrives."""

    def __init__(self, test, hkw=None, **pkw):
        self.hkw = hkw
        self.node, self.net, self.hub, provs, self.pay, shards = R.world(hkw=hkw, **pkw)
        (self.origin, self.prov), = provs.items()
        self.sh = shards[self.origin]
        self.answer, self.requests, self.lost = None, [], False
        self.net.apps[self.origin] = self
        self.pay_lock(test)

    def serve(self, method, path, headers, body, url=""):
        if path != ROLLOVER_PATH or self.answer is None:
            return self.prov.serve(method, path, headers, body, url)
        self.requests.append(json.loads(body))
        if self.lost:
            raise OSError("answer lost")
        st, doc = self.answer(body, lambda: self.prov.serve(method, path, headers, body, url))
        return st, {"Content-Type": "application/json"}, json.dumps(doc).encode()

    def pay_lock(self, test):
        R.stream(self.pay, self.sh, 10)
        test.assertEqual(self.pay.lock(self.sh)["status"], "paid")

    def oc(self):
        return self.hub.out.chans[self.origin]

    def near_margin(self):
        self.node.height = self.oc().p().expiry - 40              # the provider co-signs near its close margin

    def on_disk(self):
        with open(self.hub.out.path) as f:
            return json.load(f)["chans"][self.origin]

    def next_pub(self, oc=None):
        nxt = (oc or self.oc()).next
        return ecc.pubkey(int(nxt["secret"], 16)).hex() if nxt.get("secret") else ""

    def refused(self, test, oc=None):
        """One rollover attempt the provider answers with an error."""
        with test.assertRaises(ChannelError):
            self.hub.rollover(oc or self.oc())

    def broadcast(self, req):
        """The provider co-signs and broadcasts a rollover request it kept, whatever it answered."""
        p = next(s for s in self.prov.ledger.channels.values() if s.params.channel_id == req["chan"]).params
        nxt = ChannelParams.derive(self.prov.pay_to, req["next"]["payerPub"], req["next"]["expiry"], p.close_fee,
                                   req["next"].get("payerSpk", ""), network=R.NET, close_fee_payer=p.close_fee_payer)
        tx = p.rollover_tx(req["amount"], nxt.spk, p.rollover_next_capacity(req["amount"]))
        digest = p.sighash(tx)
        tx.inputs[0].witness = [bytes.fromhex(req["sig"]),
                                ecc.sign(self.prov._chan_secret(p), digest) + bytes([SIGHASH_ALL_UNIFIED]), b"\x01", p.script]
        self.node.sendrawtransaction(tx.hex())
        return tx

    def restart(self):
        """A new hub process on the same datadir."""
        d = os.path.dirname(self.hub.out.path)
        opts = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
                    reveal_timeout=1.0, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
                    settle_lock_multiple=0, refill_ahead_locks=0, policy=self.hub.inbound.policy)
        opts.update(self.hkw or {})
        self.hub.inbound.ledger.close() if hasattr(self.hub.inbound.ledger, "close") else None
        self.hub = RouteHub(self.node, 0x4B4B, R.NET, d, self.node.fund_address, http=self.net.http, **opts)
        self.net.apps[R.HUB] = self.hub
        return self.hub


class RolloverNextChannel(unittest.TestCase):
    def check_owned(self, new, tx, pub):
        """`new` (a ch2 record) is output 1 of `tx`, under the key written ahead, with a refund for it."""
        p = new.p()
        self.assertEqual((p.funding_txid, p.funding_vout, p.capacity), (tx.txid(), 1, tx.outputs[1].value))
        self.assertEqual(ecc.pubkey(int(new.secret, 16)).hex(), pub)
        self.assertEqual(tx.outputs[1].script_pubkey, p.spk)
        refund = Tx.parse(bytes.fromhex(new.refund_hex))
        self.assertEqual((refund.inputs[0].txid[::-1].hex(), refund.inputs[0].vout, refund.locktime),
                         (tx.txid(), 1, p.expiry))

    def test_a_refused_rollover_keeps_the_next_channel(self):
        for status in (400, 401, 403, 500):
            with self.subTest(status=status):
                w = RolloverWorld(self)
                w.near_margin()
                old = w.oc()
                w.answer = lambda body, serve, st=status: (st, {"error": "bad_amount", "detail": "no"})
                w.refused(self)
                pub = w.requests[0]["next"]["payerPub"]
                self.assertEqual(w.next_pub(old), pub, f"the next ch2's key was dropped at HTTP {status}")
                self.assertTrue(old.next["refund_hex"])
                sealed = w.on_disk()["next"]["secret_sealed"]        # and on disk, for a restart
                self.assertEqual(ecc.pubkey(int(w.hub.out.wrap.open(sealed), 16)).hex(), pub)
                self.assertEqual(old.state, "open")

    def test_a_rollover_broadcast_after_a_refusal_is_adopted_with_its_refund(self):
        w = RolloverWorld(self)
        w.near_margin()
        old = w.oc()

        def answer(body, serve):
            st, _, out = serve()
            self.assertEqual(st, 200, out)                           # the provider broadcast the rollover...
            return REFUSED                                           # ...and answers an error
        w.answer = answer
        w.refused(self)
        tx = Tx.parse(bytes.fromhex(w.node.sent[-1]))
        self.assertEqual(tx.inputs[0].txid[::-1].hex(), old.p().funding_txid)
        acts = w.hub.watch_tick()                                    # the watcher sees the rollover spend the funding
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts),
                        f"{tx.outputs[1].value} sat have no key and no refund: {acts}")
        self.check_owned(w.oc(), tx, w.requests[0]["next"]["payerPub"])
        self.assertEqual(old.state, "rolled")
        self.assertEqual(sum(1 for r in w.hub.out.archived if r["params"]["funding_txid"] == old.p().funding_txid), 1)

    def test_a_retried_rollover_asks_under_the_same_key(self):
        w = RolloverWorld(self)
        w.near_margin()
        w.answer = lambda body, serve: REFUSED
        for _ in range(3):
            w.refused(self)
        self.assertEqual(w.requests[0], w.requests[1])
        self.assertEqual(w.requests[0], w.requests[2])
        self.assertEqual(w.hub.out.archived, [], "a refusal must not grow the hub's book")
        # the neighbour: a reply that was lost, and a rollover the hub's node has not seen yet
        w = RolloverWorld(self)
        w.near_margin()
        w.answer, w.lost = (lambda body, serve: REFUSED), True
        w.refused(self)
        w.refused(self)
        self.assertEqual(w.requests[0]["next"], w.requests[1]["next"], "the retry dropped the first attempt's key")
        tx = w.broadcast(w.requests[0])
        acts = w.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts), acts)
        self.check_owned(w.oc(), tx, w.requests[0]["next"]["payerPub"])

    def test_a_rollover_at_an_earlier_amount_is_adopted_by_its_script(self):
        w = RolloverWorld(self, amsat_per_call=200 * AMSAT_PER_SAT)   # a lock of 10 calls is above ch2's floor
        w.near_margin()
        old = w.oc()
        w.answer = lambda body, serve: REFUSED                       # refused: the provider keeps the request
        w.refused(self)
        w.pay_lock(self)                                             # ch2 moves on: the next attempt pays more
        w.refused(self)
        first, second = w.requests
        self.assertGreater(second["amount"], first["amount"])
        self.assertEqual(second["next"], first["next"])
        tx = w.broadcast(first)                                      # the provider sends the one it kept
        self.assertNotEqual(tx.txid(), old.next["params"]["funding_txid"])
        acts = w.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts), acts)
        self.check_owned(w.oc(), tx, first["next"]["payerPub"])
        self.assertEqual(w.oc().p().capacity, old.p().capacity - first["amount"])

    def test_a_next_channel_too_old_to_ask_again_is_kept_and_the_ch2_closed(self):
        w = RolloverWorld(self, hkw=SHORT_CH2)
        w.near_margin()
        old = w.oc()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        pub = w.requests[0]["next"]["payerPub"]
        w.node.height += 1                                           # the kept one's expiry is now under the floor
        ev = w.hub.rollover(old)
        self.assertEqual(ev["event"], "ch2_close", ev)
        self.assertEqual(len(w.requests), 1, "a second rollover was asked for, under another key or a stale expiry")
        self.assertEqual(w.next_pub(old), pub)
        self.assertEqual(old.state, "closing")
        self.assertIsNot(w.oc(), old)                                # refilled: the origin has a new ch2
        # the neighbour: the provider's close leaves the mempool and it sends the rollover it kept. The
        # replaced ch2 is in the archive: the rollover is adopted there, and its next ch2 refunded at expiry
        w.node.evict(old.close_txid)
        tx = w.broadcast(w.requests[0])
        w.hub.watch_tick()
        kept = [OutChannel(**r) for r in w.hub.out.archived if r["params"]["funding_txid"] == tx.txid()]
        self.assertEqual(len(kept), 1, f"the rollover's next ch2 is in no record: {w.hub.events[-4:]}")
        self.check_owned(kept[0], tx, pub)
        self.assertEqual(sum(1 for r in w.hub.out.archived if r["params"]["funding_txid"] == old.p().funding_txid), 1)
        w.node.mine()
        w.hub.watch_tick()
        w.node.height = w.requests[0]["next"]["expiry"]
        w.hub.watch_tick()
        spent = [Tx.parse(bytes.fromhex(hx)).inputs[0] for hx in w.node.sent]
        self.assertTrue(any((i.txid[::-1].hex(), i.vout) == (tx.txid(), 1) for i in spent),
                        f"no refund of the adopted next ch2: {w.hub.events[-4:]}")

    def test_a_kept_next_channel_is_dropped_once_another_spend_confirms(self):
        # the provider's own close
        w = RolloverWorld(self)
        w.near_margin()
        old = w.oc()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        st2 = next(iter(w.prov.ledger.channels.values()))
        T.close_now(w.prov, st2)
        w.hub.watch_tick()
        self.assertEqual(old.state, "closing")
        self.assertTrue(w.next_pub(old), "dropped on a close that is only in the mempool")
        w.node.mine()
        w.hub.watch_tick()
        self.assertEqual((old.state, old.final, old.next), ("closed", True, {}))
        # the hub's refund at expiry
        w = RolloverWorld(self)
        w.near_margin()
        old = w.oc()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        w.answer = None
        w.node.height = old.p().expiry + 10
        w.hub.watch_tick()
        self.assertEqual(old.state, "refunded")
        self.assertTrue(w.next_pub(old), "dropped on a refund that is only in the mempool")
        w.node.mine()
        w.hub.watch_tick()
        self.assertEqual((old.state, old.final, old.next), ("refunded", True, {}))

    def test_a_rollover_refused_before_a_restart_is_adopted_after_it(self):
        w = RolloverWorld(self)
        w.near_margin()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        hub = w.restart()
        self.assertEqual(w.next_pub(), w.requests[0]["next"]["payerPub"], "the restarted hub has no next ch2")
        tx = w.broadcast(w.requests[0])
        acts = hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts), acts)
        self.check_owned(w.oc(), tx, w.requests[0]["next"]["payerPub"])
        book = OutBook(hub.out.path, hub.out.wrap)
        self.assertEqual(book.chans[w.origin].secret, w.oc().secret)

    def test_a_rollover_adopted_over_a_written_off_lock_releases_it_once_confirmed(self):
        # a rollover shows no t: a lock written off on the ch2 it spends was not paid. The hub waits for
        # the rollover to confirm (a close that shows t could still replace it), then gives the hold back
        w = RolloverWorld(self, amsat_per_call=300 * AMSAT_PER_SAT)
        w.near_margin()
        old = w.oc()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        st1 = w.hub.inbound.ledger.channels[w.pay.chan]
        routed0 = int(st1.extra["routed_sat"])
        w.net.drop[w.origin] = lambda m, p: p == ROUTE_LOCK_PATH     # the provider takes the lock; its answer is lost
        R.stream(w.pay, w.sh, 10)
        self.assertEqual(w.pay.lock(w.sh)["error"], "route_failed")
        del w.net.drop[w.origin]
        self.assertEqual(len(old.stale), 1)
        self.assertGreater(int(st1.extra["routed_sat"]), routed0)
        tx = w.broadcast(w.requests[0])
        acts = w.hub.watch_tick()
        self.assertFalse(any(a["event"] in ("ch2_rollover", "lock_released") for a in acts), acts)
        self.assertEqual(len(st1.extra["stale_locks"]), 1)
        w.node.mine()
        acts = w.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts), acts)
        self.assertTrue(any(a["event"] == "lock_released" and a["held"] for a in acts), acts)
        self.assertEqual((st1.extra["stale_locks"], int(st1.extra["routed_sat"])), ([], routed0))
        self.check_owned(w.oc(), tx, w.requests[0]["next"]["payerPub"])

    def test_a_rollover_replaced_by_another_attempt_into_the_same_script_keeps_the_coins(self):
        # the hub adopted the second attempt (in the mempool); the provider's first one confirms in its place
        w = RolloverWorld(self, amsat_per_call=200 * AMSAT_PER_SAT)
        w.near_margin()
        w.answer = lambda body, serve: REFUSED
        w.refused(self)
        w.pay_lock(self)
        w.refused(self)
        first, second = w.requests
        tx2 = w.broadcast(second)
        w.hub.watch_tick()
        child = w.oc()
        self.assertEqual(child.p().funding_txid, tx2.txid())
        w.node.evict(tx2.txid())
        tx1 = w.broadcast(first)
        w.node.mine()
        acts = w.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover_replaced" and a.get("kept") for a in acts), acts)
        self.assertIs(w.oc(), child)
        self.assertFalse(child.final)
        self.check_owned(child, tx1, first["next"]["payerPub"])
        self.assertEqual((child.signed, child.routed), (0, 0))


class Ch1Counters(unittest.TestCase):
    def held_then_released_under(self, w, refuse: bool):
        """p0's lock is written off and held; p1's next lock is in flight while p0's ch2 is refunded and
        the hold released. Returns (routed before anything, the held lock's d + f, join)."""
        routed0 = w.routed()
        w.net.drop[w.origins[0]] = lambda m, p: p == ROUTE_LOCK_PATH
        self.assertEqual(w.lock(0)["error"], "route_failed")
        held = T.d_plus_f(w.stale1()[0])
        self.assertEqual(w.routed(), routed0 + held)
        w.provs[1].refuse = refuse
        join = w.lock_in_flight(1)                                   # admitted on a base that counts the hold
        oc = w.hub.out.chans[w.origins[0]]
        w.node.height = oc.p().expiry + 10
        w.hub.watch_tick()
        w.node.confirm_all()
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "lock_released" and a["held"] for a in acts), acts)
        self.assertEqual(w.routed(), routed0, "the unpaid hold left the base")
        w.provs[1].open()
        return routed0, held, join

    def hub_counters(self, w):
        ex = w.st1().extra or {}
        return int(ex.get("routed_sat", 0)), int(ex.get("fee_units", 0)), int(ex.get("fee_paid", 0))

    def test_a_lock_admitted_before_a_release_completes_by_delta(self):
        w = T.W([None, 3_000])                                       # p1's ch2 outlives p0's refund
        base = self.hub_counters(w)
        routed0, held, join = self.held_then_released_under(w, refuse=False)
        r = join()
        self.assertEqual(r["status"], "paid", r)
        lock = r["amount"] + r["fee"]
        got = self.hub_counters(w)
        self.assertEqual(got[0], routed0 + lock)
        self.assertEqual(got[2], base[2] + r["fee"])
        self.assertEqual(got[1] - base[1], w.pay.quote.units(r["amount"]),
                         "the released lock's fee units came back with a lock admitted before the release")
        # the client still counts the hold; its next lock is refused with the release in the view and it
        # adopts it, then pays: before, it was refused bad_amount from here on
        r = w.lock(1)
        self.assertEqual(r["status"], "resynced", r)
        self.assertEqual(w.counters()[:3], self.hub_counters(w))
        r = w.pay.lock(w.shards[1])
        self.assertEqual(r["status"], "paid", r)
        self.assertEqual(w.counters()[:3], self.hub_counters(w))

    def test_a_lock_admitted_before_a_release_and_written_off_holds_only_its_own(self):
        w = T.W([None, 3_000])
        base = self.hub_counters(w)
        routed0, held, join = self.held_then_released_under(w, refuse=True)   # p1 keeps the pre-signature, answers 400
        r = join()
        self.assertEqual((r["status"], r["error"]), ("refused", "route_failed"), r)
        own = w.stale1()[0]
        self.assertEqual(own["hold"], {"routed": own["d"] + own["f"], "units": own["unitsBy"], "paid": own["f"]},
                         "the lock holds the released lock's amounts too")
        self.assertEqual(self.hub_counters(w), (routed0 + own["d"] + own["f"], base[1] + own["unitsBy"], base[2] + own["f"]))
        # the view carries the release and the hold at once: the client adopts both
        self.assertEqual(w.counters()[:3], self.hub_counters(w), "the client did not adopt a release and a hold in one view")
        # p1 closes with t: the lock was paid, and the base counted it once
        w.provs[1].refuse = False
        T.close_now(w.provs[1].inner, w.st2(1))
        acts = w.hub.watch_tick()
        self.assertTrue(any(a.get("event") == "secret_from_close" for a in acts), acts)
        self.assertEqual(self.hub_counters(w)[0], routed0 + own["d"] + own["f"])
        self.assertEqual(w.stale1(), [])


if __name__ == "__main__":
    unittest.main()
