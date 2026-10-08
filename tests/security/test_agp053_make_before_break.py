"""AGP-053: make-before-break ch2 rollover. The hub opens the rollover's next ch2 at once, unconfirmed,
where the provider takes it (the child of its own confirmed hub-bound channel, below a cap and before the
parent's close margin), so routing to that provider never pauses for a block. In process (routehelp)."""
import time
import unittest

import routehelp as R

from xbt402.channel import ChannelError
from xbt402.hub import ROLLOVER_GONE, RouteHub
from xbt402.route import AMSAT_PER_SAT, ROLLOVER_PATH


class _Roll(unittest.TestCase):
    pkw = {"settle_multiple": 2, "amsat_per_call": 40 * AMSAT_PER_SAT}
    hkw = None

    def setUp(self):
        self.node, self.net, self.hub, self.provs, self.pay, self.shards = R.world(1, hkw=self.hkw, **self.pkw)
        self.origin = next(iter(self.provs))
        self.prov, self.sh = self.provs[self.origin], self.shards[self.origin]

    def lock(self, calls=5):
        R.stream(self.pay, self.sh, calls)
        return self.pay.lock(self.sh)

    def roll(self):
        """Stream to the provider's threshold and let the watcher roll ch2 over: (parent, child, event)."""
        parent = self.hub.out.chans[self.origin]
        self.assertEqual(self.lock(50)["status"], "paid")
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a.get("event") == "ch2_rollover")
        return parent, self.hub.out.chans[self.origin], ev

    def child_st(self, child):
        return self.prov.ledger.channels[child.p().channel_id]

    def refusals(self):
        return dict(self.pay.stats.get("refused", {})) if hasattr(self.pay, "stats") else {}


class MakeBeforeBreak(_Roll):
    def test_child_is_open_at_once_and_routing_never_pauses(self):
        parent, child, ev = self.roll()
        self.assertEqual(child.state, "open")
        self.assertEqual(child.rolled_from, parent.p().channel_id)
        self.assertEqual(child.zero_conf, {"parent": parent.p().channel_id, "maxCum": 2 * 2 * 600,
                                           "until": parent.p().expiry - 36, "confirmed": False})
        zc = self.child_st(child).extra["zero_conf"]
        self.assertEqual((zc["parent"], zc["maxCum"], zc["confirmed"]), (parent.p().channel_id, 2400, False))
        self.assertIn(child.p().channel_id, [e.get("chan") for e in self.hub.events if e.get("event") == "ch2_open"])
        # no block: the next locks go over the unconfirmed child
        for _ in range(3):
            self.assertEqual(self.lock()["status"], "paid")
        self.assertGreater(self.child_st(child).best_cum, 0)
        self.assertEqual(self.hub.stats["refused"], {})
        self.assertIn(self.origin, self.hub.routing_extra()["providers"])
        self.node.confirm_all()
        acts = self.hub.watch_tick()
        self.assertIn("ch2_zero_conf_confirmed", [a["event"] for a in acts])
        self.prov.close_due()
        self.assertTrue(self.child_st(child).extra["zero_conf"]["confirmed"])
        self.assertEqual(self.lock()["status"], "paid")

    def test_child_is_not_rolled_over_before_it_confirms(self):
        parent, child, _ = self.roll()
        self.assertEqual(self.lock(20)["status"], "paid")          # 800 sat on the child
        child.signed = 2_000                                          # past the provider's threshold
        acts = self.hub.watch_tick()
        self.assertFalse([a for a in acts if a.get("event") == "ch2_rollover"])
        with self.assertRaises(ChannelError) as e:                   # and the provider would refuse it
            self.hub.rollover(child)
        self.assertEqual(e.exception.code, "unconfirmed")
        self.assertEqual(child.next, {})
        child.signed = self.child_st(child).best_cum
        self.node.confirm_all()
        self.hub.watch_tick()
        self.assertTrue(child.zero_conf["confirmed"])

    def test_hub_caps_the_child_below_the_providers_zero_conf_max(self):
        parent, child, _ = self.roll()
        n_lock = sum(1 for c in self.net.calls if c[2] == "/x402/xbt-channel/lock")
        R.stream(self.pay, self.sh, 70)                              # 2,800 sat > the 2,400 cap
        r = self.pay.lock(self.sh)
        self.assertEqual(r.get("error"), "route_blocked", r)
        self.assertEqual(sum(1 for c in self.net.calls if c[2] == "/x402/xbt-channel/lock"), n_lock,
                         "the hub sent a lock past the provider's cap")
        self.assertEqual(child.pending, {})
        self.node.confirm_all()
        self.hub.watch_tick()
        R.stream(self.pay, self.sh, 1)
        self.assertEqual(self.pay.lock(self.sh)["status"], "paid")   # confirmed: no cap

    def test_provider_enforces_its_cap_and_margin_itself(self):
        parent, child, _ = self.roll()
        with self.hub.out.lock:
            child.zero_conf = {**child.zero_conf, "maxCum": 10 ** 9}   # a hub that ignores the cap
        R.stream(self.pay, self.sh, 70)
        r = self.pay.lock(self.sh)
        self.assertEqual(r.get("error"), "route_failed", r)
        self.assertEqual(self.hub.stats["refused"].get("zero_conf_cap"), 1)
        # the provider holds the refused lock's pre-signature: the child is not routed over again (AGP-064)
        R.stream(self.pay, self.sh, 1)
        self.assertEqual(self.pay.lock(self.sh).get("error"), "route_blocked")
        # at the parent's close margin the provider takes nothing more on the unconfirmed child (here
        # parent and child expire together, so the margin is moved rather than the tip)
        self.setUp()
        parent, child, _ = self.roll()
        st = self.child_st(child)
        with self.prov.ledger.lock:
            st.extra = {**st.extra, "zero_conf": {**st.extra["zero_conf"], "until": self.node.height}}
            self.prov.ledger.save(st)
        with self.hub.out.lock:
            child.zero_conf = {**child.zero_conf, "until": 10 ** 9}
        R.stream(self.pay, self.sh, 1)
        self.assertEqual(self.pay.lock(self.sh).get("error"), "route_failed")
        self.assertEqual(self.hub.stats["refused"].get("unconfirmed"), 1)

    def test_hub_stops_at_the_parents_close_margin(self):
        parent, child, _ = self.roll()
        with self.hub.out.lock:
            child.zero_conf = {**child.zero_conf, "until": self.node.height}
        r = self.lock()
        self.assertEqual(r.get("error"), "route_blocked", r)
        self.node.confirm_all()
        self.hub.watch_tick()
        self.assertEqual(self.lock()["status"], "paid")

    def test_reorg_across_the_switch(self):
        parent, child, _ = self.roll()
        self.assertEqual(self.lock()["status"], "paid")
        self.node.confirm_all()
        self.hub.watch_tick()
        self.prov.close_due()
        self.assertTrue(child.zero_conf["confirmed"])
        # the block with the rollover is reorged out: back in the mempool, the parent unspent in blocks
        txid, ptxid = child.p().funding_txid, parent.p().funding_txid
        self.node.txs[txid]["confirmations"] = 0
        self.node.mined.discard((ptxid, parent.p().funding_vout))
        acts = self.hub.watch_tick()
        self.assertIn("ch2_zero_conf_reorg", [a["event"] for a in acts])
        self.assertFalse(child.zero_conf["confirmed"])
        self.prov.close_due()
        st = self.child_st(child)
        self.assertEqual((st.extra["zero_conf"]["confirmed"], st.suspended), (False, False))
        self.assertEqual(self.lock()["status"], "paid")            # under the cap again, still routing
        # the parent itself reorged out: the child is no longer taken, by either side
        self.node.txs[ptxid]["confirmations"] = 0
        self.prov.close_due()
        self.assertTrue(self.child_st(child).suspended)
        r = self.lock()
        self.assertEqual(r.get("error"), "route_failed", r)
        self.assertEqual(self.hub.stats["refused"].get("unconfirmed"), 1)

    def test_vanished_rollover_blocks_until_it_is_back(self):
        parent, child, _ = self.roll()
        txid = child.p().funding_txid
        self.node.evict(txid)                                        # it left every mempool
        acts = self.hub.watch_tick()
        self.assertIn("ch2_rollover_vanished", [a["event"] for a in acts])
        self.assertEqual((child.state, child.blocked, child.final), ("open", ROLLOVER_GONE, False))
        self.assertEqual(self.lock().get("error"), "route_blocked")
        self.prov.close_due()                                        # the provider sends its rollover again
        self.assertIn(txid, self.node.txs)
        acts = self.hub.watch_tick()
        self.assertIn("ch2_rollover_back", [a["event"] for a in acts])
        self.assertEqual(child.blocked, "")
        self.prov.close_due()
        self.assertEqual(self.lock()["status"], "paid")

    def test_replaced_rollover_drops_the_child(self):
        parent, child, _ = self.roll()
        self.assertEqual(self.lock()["status"], "paid")
        self.node.evict(child.p().funding_txid)
        pst = self.prov.ledger.channels[parent.p().channel_id]
        close = self.prov._close_tx(pst)[0]                          # the provider closes the parent instead
        spender = self.node.sendrawtransaction(close.hex())
        self.node.confirm_all()
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_rollover_replaced")
        self.assertEqual((ev["spender"], ev["parent"]), (spender, parent.p().channel_id))
        self.assertEqual((child.state, child.final), ("dropped", True))
        self.assertEqual(self.lock().get("error"), "route_blocked")
        self.assertNotIn(self.origin, self.hub.routing_extra()["providers"])
        self.hub.connect(self.origin)                                # a new ch2 for that payTo
        self.assertEqual(self.hub.out.chans[self.origin].state, "funded")

    def test_lost_rollover_reply_child_opened_by_the_watcher(self):
        parent = self.hub.out.chans[self.origin]
        self.assertEqual(self.lock(50)["status"], "paid")
        self.net.drop[self.origin] = lambda m, p: p == ROLLOVER_PATH
        self.hub.watch_tick()                                        # broadcast by the provider, answer lost
        del self.net.drop[self.origin]
        self.hub.watch_tick()                                        # the watcher finishes the rollover
        child = self.hub.out.chans[self.origin]
        self.assertEqual((child.state, child.rolled_from), ("funded", parent.p().channel_id))
        acts = self.hub.watch_tick()                                 # and opens it unconfirmed
        self.assertIn({"event": "ch2_open", "provider": self.origin, "zeroConf": True}, acts)
        self.assertEqual(child.state, "open")
        self.assertEqual(self.lock()["status"], "paid")

    def test_watcher_waits_for_a_busy_provider_between_locks(self):
        # a provider streaming locks holds its mutex most of the time: the tick waits for it (bounded)
        parent = self.hub.out.chans[self.origin]
        self.assertEqual(self.lock(50)["status"], "paid")
        import threading
        mtx = self.hub.out.mutex_for(self.origin)
        mtx.acquire()
        threading.Timer(0.1, mtx.release).start()
        acts = self.hub.watch_tick()
        self.assertIn("ch2_rollover", [a.get("event") for a in acts])
        mtx.acquire()                                                # held past the budget: skipped
        try:
            t0 = time.time()
            self.assertEqual(self.hub.watch_tick(), [])
            self.assertLess(time.time() - t0, 2.0)
        finally:
            mtx.release()

    def test_route_rereads_the_ch2_under_its_mutex(self):
        # a lock checked against the parent while the watcher rolls it over goes over the child
        parent, child, _ = self.roll()
        self.assertIsNone(self.hub._ch2_refusal(child, self.hub.inbound.ledger.channels[self.pay.chan], 10))
        self.assertEqual(self.hub._ch2_refusal(parent, self.hub.inbound.ledger.channels[self.pay.chan], 10)[0],
                         "route_blocked")                        # the rolled parent is not open
        with self.hub.out.lock:
            child.pending = {"lockId": "x"}
        self.assertEqual(self.hub._ch2_refusal(child, self.hub.inbound.ledger.channels[self.pay.chan], 10)[0],
                         "lock_outstanding")
        with self.hub.out.lock:
            child.pending = {}


class ProviderRules(_Roll):
    def test_unrelated_unconfirmed_channel_is_refused(self):
        h2 = R.hub(self.node, self.net, secret=0x99)
        h2.fund = lambda address, sats: self.node.fund_address(address, sats, confirmations=0)
        oc = h2.connect(self.origin)
        self.assertFalse(h2._open(oc))
        self.assertEqual(oc.state, "funded")

    def test_child_bound_to_another_hub_is_refused(self):
        self.hub.zero_conf_rollover = False
        parent, child, _ = self.roll()
        self.assertEqual(child.state, "funded")                      # hub off: break-before-make
        other = RouteHub(self.node, 0x5151, R.NET, self.hub.out.path.rsplit("/", 1)[0] + "-o", self.node.fund_address,
                         http=self.net.http)
        from xbt402.hub import OutChannel
        from dataclasses import asdict
        self.assertFalse(other._open(OutChannel(**asdict(child))))
        self.hub.zero_conf_rollover = True
        self.assertTrue(self.hub._open_child(child, parent.p().channel_id))
        self.assertEqual(child.state, "open")


class ProviderOff(_Roll):
    pkw = {**_Roll.pkw, "rollover_zero_conf_max": 0}

    def test_break_before_make_when_the_provider_wants_confirmations(self):
        parent, child, _ = self.roll()
        self.assertEqual((child.state, child.zero_conf), ("funded", {}))
        self.assertEqual(self.lock().get("error"), "route_blocked")   # the pre-AGP-053 gap
        self.hub.watch_tick()                                          # tried once a block, not again
        self.node.confirm_all()
        self.hub.watch_tick()
        self.assertEqual((child.state, child.zero_conf), ("open", {}))
        self.assertEqual(self.lock()["status"], "paid")


class HubOff(_Roll):
    hkw = {"zero_conf_rollover": False}

    def test_hub_config_off_is_break_before_make(self):
        parent, child, _ = self.roll()
        self.assertEqual(child.state, "funded")
        self.assertFalse([c for c in self.net.calls if c[2] == "/x402/xbt-channel/open" and c[1] == self.origin][1:])


if __name__ == "__main__":
    unittest.main()
