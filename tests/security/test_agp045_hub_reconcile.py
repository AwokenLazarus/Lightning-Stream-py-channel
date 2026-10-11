"""AGP-045: RouteHub reconcile fixes from cmp-lead's CMP-012 review (b1 agp-037 42b843e).
In process (routehelp: FakeNode + a fake HTTP transport + a fake fund wallet). One class per item:
    1 the refill hook is looked up at call time: replacing `connect` (or `refill`) after construction
      takes effect;
    2 a `funding` record is reconciled against the wallet (gettransaction), the mempool (gettxout incl.
      the mempool, getmempoolentry) and scantxoutset, not scantxoutset alone: a slow funding past
      funding_timeout_blocks is recovered or refunded, never lost; a dropped record whose send is known
      is watched and refunded at expiry if it confirms late; a genuinely failed send is dropped and final;
    3 a mempool spender makes a ch2 `closing`; only a confirmed one makes it `closed` and takes the refund
      fee back; the fee is booked again if the mempool close vanishes.
The Rust port has the same tests (xbt-rs crates/xbt402-interop/tests/hub_reconcile.rs)."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
from test_agp037_hub_money_safety import _World, hub_at  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402


# --- 1 refill hook, late-bound ------------------------------------------------------------------------
class RefillLateBound(_World):
    def test_refill_is_looked_up_at_call_time(self):
        """cmp's case: the embedder replaces hub.connect after construction (no refill= passed)."""
        calls = []
        self.hub.connect = lambda origin, *a, **k: calls.append(origin)
        ev = self.hub.close_ch2(self.oc(), refill=True)
        self.assertEqual(calls, [self.origin])
        self.assertNotIn("refillError", ev)

    def test_refill_a_hook_set_to_none_falls_back_to_connect(self):
        hooked = []
        self.hub.refill = lambda origin: hooked.append(origin)
        self.hub.refill = None                                   # back to the default: connect, as it is now
        calls = []
        self.hub.connect = lambda origin, *a, **k: calls.append(origin)
        self.hub.close_ch2(self.oc(), refill=True)
        self.assertEqual((hooked, calls), ([], [self.origin]))

    def test_refill_a_hook_may_replace_the_hook_while_it_runs(self):
        seen = []

        def second(origin):
            seen.append(("second", origin))

        def first(origin):
            seen.append(("first", origin))
            self.hub.refill = second                             # re-entrant: no lock held around the call
        self.hub.refill = first
        self.hub.close_ch2(self.oc(), refill=True)
        self.assertEqual(seen, [("first", self.origin)])
        self.assertIs(self.hub.refill, second)


# --- 2 funding reconcile ---------------------------------------------------------------------------------
class FundingReconcile(unittest.TestCase):
    def setUp(self):
        self.node, self.net = R.RouteNode(), R.Net()
        self.origin = "http://p0.test"
        self.prov = R.provider(self.node, self.net, self.origin)
        self.sent = []

    def hub(self, fund):
        h = R.hub(self.node, self.net)
        h.fund = fund
        self.dir = os.path.dirname(h.out.path)
        return h

    def broadcast_then_fail(self, confirmations=0):
        def fund(address, sats):
            self.sent.append(self.node.fund_address(address, sats, confirmations=confirmations))
            raise RuntimeError("gettransaction: timeout")        # it broadcast, then the wallet call failed
        return fund

    def funding_failed(self, h):
        with self.assertRaises(ChannelError) as cm:
            h.connect(self.origin)
        self.assertEqual(cm.exception.code, "fund_failed")
        return h.out.chans[self.origin]

    def events(self, h, name):
        return [e for e in h.events if e["event"] == name]

    def confirm_late(self, txid):
        """The wallet rebroadcasts the evicted send and it confirms."""
        w = self.node.wallet_txs[txid]
        self.node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "vout": w["vout"], "confirmations": 1}

    def test_funding_slow_in_the_mempool_past_the_timeout_is_recovered_not_dropped(self):
        """The old reconcile read scantxoutset only (confirmed outputs): a funding still in the mempool at
        funding_timeout_blocks was dropped and never refunded."""
        h = self.hub(self.broadcast_then_fail(confirmations=0))
        self.funding_failed(h)
        self.node.height += h.config.funding_timeout_blocks + 3   # past the timeout, still unconfirmed
        self.assertEqual(self.node.scantxoutset("start", [])["unspents"], [])
        acts = h.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_funding_recovered" for a in acts), acts)
        self.assertEqual(self.events(h, "ch2_funding_dropped"), [])
        oc = h.out.chans[self.origin]
        self.assertEqual(((oc.p().funding_txid, oc.p().funding_vout), oc.state), (self.sent[0], "funded"))
        self.assertEqual(h.committed_sat(), 100_000)
        h.watch_tick()
        self.assertEqual(oc.state, "funded")                     # the open waits for minConf
        self.node.mine()
        h.watch_tick()
        self.assertEqual(oc.state, "open")

    def test_funding_slow_confirmation_after_eviction_is_watched_and_refunded_at_expiry(self):
        h = self.hub(self.broadcast_then_fail(confirmations=0))
        oc = self.funding_failed(h)
        secret, txid = oc.secret, self.sent[0][0]
        self.node.evict(txid)                                    # out of the mempool; the wallet still knows it
        self.node.height += h.config.funding_timeout_blocks
        acts = h.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_funding_dropped")
        self.assertEqual(ev["watching"], txid)
        self.assertNotIn(self.origin, h.out.chans)
        rec = h.out.archived[-1]
        self.assertEqual((rec["state"], rec["fund_txid"], rec["final"]), ("dropped", txid, False))
        h = hub_at(self.node, self.net, self.dir)                # a restart keeps watching it
        self.assertEqual(h.watch_tick(), [])
        self.confirm_late(txid)
        acts = h.watch_tick()
        late = next(a for a in acts if a["event"] == "ch2_funding_late")
        self.assertEqual((late["txid"], late["capacity"]), (txid, 100_000))
        rec = h.out.archived[-1]
        self.assertEqual((rec["state"], rec["secret"], rec["params"]["funding_txid"]), ("funded", secret, txid))
        self.node.height = rec["params"]["expiry"]               # never opened: refunded at expiry
        acts = h.watch_tick()
        ref = next(a for a in acts if a["event"] == "ch2_refund")
        self.assertEqual(h.out.archived[-1]["state"], "refunded")
        self.node.mine()
        acts = h.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund_confirmed" and a["txid"] == ref["txid"] for a in acts), acts)
        self.assertTrue(h.out.archived[-1]["final"])
        spk = R.Tx.parse(bytes.fromhex(self.node.raw[ref["txid"]])).outputs[0].script_pubkey
        self.assertEqual(spk.hex()[:4], "0014")                   # back to a key the hub holds

    def test_funding_a_failed_send_is_dropped_and_final(self):
        def fund(address, sats):
            raise RuntimeError("Insufficient funds")
        h = self.hub(fund)
        self.funding_failed(h)
        self.assertEqual(h.watch_tick(), [])
        self.node.height += h.config.funding_timeout_blocks
        acts = h.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_funding_dropped")
        self.assertNotIn("watching", ev)
        self.assertEqual((h.out.archived[-1]["state"], h.out.archived[-1]["final"]), ("dropped", True))
        n = len(h.events)
        h.watch_tick()
        self.assertEqual(len(h.events), n)                       # not watched

    def test_funding_a_conflicted_send_is_dropped_and_final(self):
        h = self.hub(self.broadcast_then_fail(confirmations=0))
        self.funding_failed(h)
        self.node.conflict(self.sent[0][0])                      # double-spent by a confirmed tx
        self.node.height += h.config.funding_timeout_blocks
        acts = h.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_funding_dropped")
        self.assertNotIn("watching", ev)
        self.assertTrue(h.out.archived[-1]["final"])

    def test_funding_an_abandoned_dropped_send_stops_being_watched(self):
        h = self.hub(self.broadcast_then_fail(confirmations=0))
        self.funding_failed(h)
        txid = self.sent[0][0]
        self.node.evict(txid)
        self.node.height += h.config.funding_timeout_blocks
        h.watch_tick()
        self.assertFalse(h.out.archived[-1]["final"])
        self.node.abandon(txid)                                  # the operator gives up on it
        acts = h.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_funding_failed")
        self.assertEqual((ev["txid"], ev["why"]), (txid, "abandoned"))
        self.assertTrue(h.out.archived[-1]["final"])
        n = len(h.events)
        h.watch_tick()
        self.assertEqual(len(h.events), n)

    def test_funding_found_by_the_wallet_when_scantxoutset_is_missing(self):
        h = self.hub(self.broadcast_then_fail(confirmations=6))

        def no_scan(*a):
            raise RuntimeError("Method not found")
        self.node.scantxoutset = no_scan
        self.funding_failed(h)
        acts = h.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_funding_recovered" and a["txid"] == self.sent[0][0] for a in acts), acts)

    def test_funding_mempool_entry_keeps_a_send_whose_output_is_not_visible(self):
        """getmempoolentry: a send the node holds in its mempool is the one kept watching, even when the
        wallet lists an older, evicted send to the same address first."""
        h = self.hub(self.broadcast_then_fail(confirmations=0))
        self.funding_failed(h)
        old = self.sent[0][0]
        self.node.evict(old)
        addr = self.node.wallet_txs[old]["address"]
        new, _ = self.node.fund_address(addr, 100_000, confirmations=0)
        real = self.node.gettxout
        self.node.gettxout = lambda t, v, m=True: None if t == new else real(t, v, m)   # output hidden
        self.node.height += h.config.funding_timeout_blocks
        acts = h.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_funding_dropped")
        self.assertEqual(ev["watching"], new)


# --- 3 close on confirmed spenders only --------------------------------------------------------------------
class CloseOnConfirmedOnly(_World):
    def refunded(self):
        oc = self.oc()
        self.node.height = oc.p().expiry + self.hub.config.refund_grace_blocks
        self.hub.watch_tick()
        self.assertEqual(oc.state, "refunded")
        self.assertGreater(oc.refund_fee, 0)
        return oc

    def test_close_a_mempool_spender_is_closing_and_keeps_the_refund_fee_booked(self):
        oc = self.refunded()
        fee = self.hub.refund_fees_sat()
        self.assertEqual(fee, oc.refund_fee)
        self.node.evict(oc.refund_txid)
        close = self.provider_closes()
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_closing")
        self.assertEqual((ev["txid"], ev["refundAtRisk"]), (close, oc.refund_txid))
        self.assertEqual((oc.state, oc.close_txid, oc.close_prev, oc.final), ("closing", close, "refunded", False))
        self.assertEqual(self.hub.refund_fees_sat(), fee)        # booked until the close confirms
        self.assertEqual(self.events("ch2_closed"), [])
        self.hub.watch_tick()
        self.assertEqual(len(self.events("ch2_closing")), 1)     # no repeat while it waits
        self.node.mine()
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_closed")
        self.assertEqual((ev["txid"], ev["refundFeeReverted"]), (close, fee))
        self.assertEqual((oc.state, oc.final, self.hub.refund_fees_sat()), ("closed", True, 0))

    def test_close_a_vanished_mempool_close_rebooks_the_refund_fee(self):
        oc = self.refunded()
        fee, refund = oc.refund_fee, oc.refund_txid
        self.node.evict(refund)
        close = self.provider_closes()
        self.hub.watch_tick()
        self.assertEqual(oc.state, "closing")
        self.node.evict(close)                                   # the close leaves the mempool
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_close_vanished")
        self.assertEqual((ev["txid"], ev["state"], ev["feeRebooked"]), (close, "refunded", fee))
        self.assertTrue(any(a["event"] == "ch2_refund_rebroadcast" and a["txid"] == refund for a in acts), acts)
        self.assertEqual((oc.state, oc.close_txid, self.hub.refund_fees_sat()), ("refunded", "", fee))
        self.node.mine()
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund_confirmed" and a["txid"] == refund for a in acts), acts)
        self.assertEqual((oc.state, oc.final, self.hub.refund_fees_sat()), ("refunded", True, fee))

    def test_close_an_unrefunded_ch2_whose_close_vanished_stays_closing_and_is_refunded_at_expiry(self):
        oc = self.oc()
        close = self.provider_closes()
        self.hub.watch_tick()
        self.assertEqual((oc.state, oc.close_prev), ("closing", "open"))
        self.node.evict(close)
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_close_vanished")
        self.assertEqual(ev["state"], "closing")
        self.assertEqual((oc.state, oc.close_txid), ("closing", ""))
        # AGP-088: its coins are in that ch2 again and count until this node sees them leave (the refund)
        self.assertEqual(self.hub.committed_sat(), oc.p().capacity)
        self.hub.watch_tick()
        self.assertEqual(len(self.events("ch2_close_vanished")), 1)
        self.node.height = oc.p().expiry + self.hub.config.refund_grace_blocks
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund" for a in acts), acts)
        self.assertEqual(oc.state, "refunded")

    def test_close_ch2_reply_is_closing_until_the_close_confirms(self):
        oc = self.oc()
        ev = self.hub.close_ch2(oc)
        self.assertEqual((oc.state, oc.close_txid, oc.close_prev), ("closing", ev["txid"], "open"))
        self.hub.watch_tick()
        self.assertEqual((oc.state, oc.final), ("closing", False))
        self.assertEqual(self.events("ch2_closed"), [])
        self.node.mine()
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_closed" and a["txid"] == ev["txid"] for a in acts), acts)
        self.assertEqual((oc.state, oc.final), ("closed", True))

    def test_close_a_closing_ch2_is_not_live_and_a_refill_funds_the_next(self):
        oc = self.oc()
        self.hub.close_ch2(oc, refill=True)
        new = self.hub.out.chans[self.origin]
        self.assertIsNot(new, oc)
        self.assertEqual(new.state, "funded")
        arch = self.hub.out.archived[-1]
        self.assertEqual((arch["state"], arch["params"]["funding_txid"]), ("closing", oc.p().funding_txid))
        self.node.mine()
        self.hub.watch_tick()                                    # the archived one is still reconciled
        arch = next(r for r in self.hub.out.archived if r["params"]["funding_txid"] == oc.p().funding_txid)
        self.assertEqual((arch["state"], arch["final"]), ("closed", True))

    def test_close_fields_round_trip(self):
        oc = self.oc()
        self.hub.close_ch2(oc)
        with open(self.hub.out.path) as f:
            rec = json.load(f)["chans"][self.origin]
        self.assertEqual((rec["state"], rec["close_prev"]), ("closing", "open"))
        self.assertIn("fund_txid", rec)
        self.assertIn("fund_vout", rec)


if __name__ == "__main__":
    unittest.main()
