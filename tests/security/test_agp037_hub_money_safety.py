"""AGP-037: RouteHub money safety (cmp-lead's CMP-012 review of the hub as xbt-compute's `--hub` mode).
In process (routehelp: FakeNode + a fake HTTP transport). One class per item of the task:
    1 write-ahead ch2: key and params on disk before fund(); a fund() that raises after it broadcast
      leaves a record the watcher reconciles (restart included); nothing on chain -> dropped, key kept;
      a rollover's next ch2 is written ahead too;
    2 every non-final ch2 is reconciled each tick: a provider's own close (signed, no lock), a close whose
      200 reply had no txid, a spent funding whose spender cannot be found;
    3 refunds at expiry (unsigned) or expiry + grace (signed), at a hub-chosen fee; watched until they
      confirm, rebroadcast when they leave the mempool; a provider close that wins takes the fee back
      and its lock secrets are recovered;
    4 close_ch2 checks the provider's reply against the ledger; the watcher survives a bad one;
    5 hostile /terms are refused before anything is funded;
    6 refills go through the refill hook (default: connect, with its terms and cap checks);
    7 one failing ch2 never stops the watcher.
The Rust port has the same tests (xbt-rs crates/xbt402-interop/tests/hub_money_safety.rs)."""
import json
import math
import os
import sys
import unittest
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402 import hub as hubmod  # noqa: E402
from xbt402.channel import DUST, ChannelError  # noqa: E402
from xbt402.hub import OutChannel, RouteHub  # noqa: E402
from xbt402.route import ROLLOVER_PATH, ROUTE_LOCK_PATH, TERMS_PATH  # noqa: E402
from sechelp import crashed


class Wrap:
    """A provider app whose answers `edit(method, path, status, doc) -> (status, body)` may rewrite."""

    def __init__(self, app, edit):
        self.app, self.edit = app, edit

    def serve(self, method, path, headers, body, url=""):
        st, h, out = self.app.serve(method, path, headers, body, url)
        try:
            doc = json.loads(out)
        except ValueError:
            doc = None
        r = self.edit(method, path, st, doc)
        if r is None:
            return st, h, out
        st2, body2 = r
        return st2, h, body2 if isinstance(body2, bytes) else json.dumps(body2).encode()


def hub_at(node, net, datadir, **kw):
    """A hub over an existing datadir (a restart)."""
    crashed(datadir)
    return RouteHub(node, 0x4B4B, R.NET, datadir, node.fund_address, http=net.http, close_margin=36, delta=36,
                    ch2_capacity=100_000, ch2_expiry_blocks=1_000,
                    **{"spend_final_depth": 1, **kw})          # (AGP-094: one confirmation, as written)


class _World(unittest.TestCase):
    n_providers = 1
    lock_first = True

    def setUp(self):
        self.node, self.net, self.hub, self.provs, self.pay, self.shards = R.world(self.n_providers)
        self.origin = next(iter(self.provs))
        self.prov, self.sh = self.provs[self.origin], self.shards[self.origin]
        R.stream(self.pay, self.sh, 10)
        if self.lock_first:
            self.assertEqual(self.pay.lock(self.sh)["status"], "paid")    # ch2 carries a signed state
            self.assertGreaterEqual(self.oc().signed, self.oc().p().min_amount)

    def oc(self, origin=None):
        return self.hub.out.chans[origin or self.origin]

    def st2(self, origin=None):
        p = self.provs[origin or self.origin]
        return next(s for s in p.ledger.channels.values() if not s.closed_txid)

    def events(self, name):
        return [e for e in self.hub.events if e["event"] == name]

    def provider_closes(self, origin=None):
        """The provider closes ch2 on its own (its best state), as at expiry - closeMargin."""
        p = self.provs[origin or self.origin]
        with p.ledger.lock:
            return p._close_locked(self.st2(origin))


# --- 1 write-ahead ch2 ------------------------------------------------------------------------------
class WriteAheadFunding(unittest.TestCase):
    def setUp(self):
        self.node, self.net = R.RouteNode(), R.Net()
        self.origin = "http://p0.test"
        self.prov = R.provider(self.node, self.net, self.origin)
        self.dir = None

    def hub(self, fund, **kw):
        h = R.hub(self.node, self.net, **kw)
        h.fund = fund
        self.dir = os.path.dirname(h.out.path)
        return h

    def on_disk(self):
        with open(os.path.join(self.dir, "ch2.json")) as f:
            return json.load(f)["chans"]

    def test_the_key_is_on_disk_before_fund_runs(self):
        seen = {}

        def fund(address, sats):
            seen.update(self.on_disk())               # what a crash inside fund() would leave
            return self.node.fund_address(address, sats)
        h = self.hub(fund)
        oc = h.connect(self.origin)
        rec = seen[self.origin]
        self.assertEqual(rec["state"], "funding")
        self.assertEqual(h.out.wrap.open(rec["secret_sealed"]), oc.secret)   # sealed at rest (AGP-073)
        self.assertEqual(rec["params"]["payer_pub"], oc.params["payer_pub"])
        self.assertEqual(oc.state, "funded")

    def test_fund_raising_after_broadcast_is_recovered_after_a_restart_and_refundable(self):
        sent = []

        def fund(address, sats):
            sent.append(self.node.fund_address(address, sats))   # broadcast...
            raise RuntimeError("gettransaction: timeout")          # ...then the wallet call fails
        h = self.hub(fund)
        with self.assertRaises(ChannelError) as cm:
            h.connect(self.origin)
        self.assertEqual(cm.exception.code, "fund_failed")
        self.assertEqual(len(sent), 1)
        self.assertEqual(self.on_disk()[self.origin]["state"], "funding")
        self.assertEqual(h.committed_sat(), 100_000)             # counted while in flight
        with self.assertRaises(ChannelError) as cm:
            h.connect(self.origin)                               # no second funding while it is unresolved
        self.assertEqual(cm.exception.code, "ch2_funding")
        h2 = hub_at(self.node, self.net, self.dir)               # restart
        acts = h2.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_funding_recovered" for a in acts), acts)
        oc = h2.out.chans[self.origin]
        self.assertEqual((oc.p().funding_txid, oc.p().funding_vout), sent[0])
        self.assertEqual(oc.state, "funded")
        h2.watch_tick()
        self.assertEqual(oc.state, "open")
        self.assertEqual(h2.committed_sat(), 100_000)
        self.node.height = oc.p().expiry                         # never used: refunded at expiry
        acts = h2.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund" for a in acts), acts)
        self.assertEqual((oc.state, h2.committed_sat()), ("refunded", 0))

    def test_fund_failing_before_broadcast_is_dropped_with_its_key_kept(self):
        def fund(address, sats):
            raise RuntimeError("Insufficient funds")
        h = self.hub(fund)
        with self.assertRaises(ChannelError):
            h.connect(self.origin)
        secret = h.out.chans[self.origin].secret
        self.assertEqual(h.watch_tick(), [])                     # not yet: it may still confirm
        self.node.height += h.config.funding_timeout_blocks
        acts = h.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_funding_dropped" for a in acts), acts)
        self.assertNotIn(self.origin, h.out.chans)
        self.assertEqual(h.committed_sat(), 0)
        self.assertEqual([r["secret"] for r in h.out.archived if r["state"] == "dropped"], [secret])
        h.fund = self.node.fund_address
        self.assertEqual(h.connect(self.origin).state, "funded")

    def test_the_cap_check_and_the_record_are_one_step(self):
        h = self.hub(self.node.fund_address, liquidity_cap_sat=150_000)
        other = "http://p1.test"
        R.provider(self.node, self.net, other)

        def fund(address, sats):                               # a second connect while this one funds
            with self.assertRaises(ChannelError) as cm:
                h.connect(other)
            self.assertEqual(cm.exception.code, "liquidity_cap")
            return self.node.fund_address(address, sats)
        h.fund = fund
        h.connect(self.origin)
        self.assertEqual(h.committed_sat(), 100_000)


class WriteAheadRollover(_World):
    def test_a_lost_rollover_answer_is_finished_by_the_watcher(self):
        oc = self.oc()
        self.assertGreaterEqual(oc.signed, oc.p().min_amount)
        self.node.height = oc.p().expiry - 40                    # near the close margin: the provider co-signs
        self.net.drop[self.origin] = lambda m, p: p == ROLLOVER_PATH
        with self.assertRaises(ChannelError):
            self.hub.rollover(oc)
        self.assertIn((oc.p().funding_txid, oc.p().funding_vout), self.node.spenders)   # it did broadcast
        self.net.drop.pop(self.origin)
        nxt = OutChannel(**oc.next)
        self.assertTrue(nxt.secret)                              # the next ch2's key survived the lost answer
        with open(self.hub.out.path) as f:
            self.assertEqual(self.hub.out.wrap.open(json.load(f)["chans"][self.origin]["next"]["secret_sealed"]),
                             nxt.secret)
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_rollover" for a in acts), acts)
        new = self.hub.out.chans[self.origin]
        self.assertEqual((new.secret, new.p().funding_txid), (nxt.secret, nxt.p().funding_txid))
        self.assertEqual(self.hub.out.archived[-1]["state"], "rolled")


# --- 2 reconcile every non-final ch2 --------------------------------------------------------------
class ReconcileEveryCh2(_World):
    def test_provider_self_close_of_a_signed_ch2_without_a_lock(self):
        oc = self.oc()
        self.assertGreaterEqual(oc.signed, oc.p().min_amount)
        self.assertFalse(oc.pending or oc.stale)
        txid = self.provider_closes()
        acts = self.hub.watch_tick()                             # in the mempool: closing (AGP-045)
        self.assertTrue(any(a["event"] == "ch2_closing" and a["txid"] == txid for a in acts), acts)
        self.assertEqual((oc.state, oc.close_txid, oc.final), ("closing", txid, False))
        self.assertEqual(self.hub.committed_sat(), 0)
        self.node.mine()
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_closed" and a["txid"] == txid for a in acts), acts)
        self.assertEqual((oc.state, oc.final), ("closed", True))
        n = len(self.hub.events)
        self.hub.watch_tick()                                    # final: nothing more, no retries
        self.assertEqual(len(self.hub.events), n)

    def test_close_reply_without_txid_after_the_provider_closed(self):
        self.net.apps[self.origin] = Wrap(self.prov, lambda m, p, st, doc: (
            (200, {k: v for k, v in doc.items() if k != "txid"}) if p.endswith("/close") and st == 200 else None))
        oc = self.oc()
        with self.assertRaises(ChannelError) as cm:
            self.hub.close_ch2(oc)
        self.assertEqual(cm.exception.code, "bad_close_reply")
        self.assertEqual(oc.state, "open")                       # a bad reply changes nothing...
        closed = [s for s in self.prov.ledger.channels.values() if s.closed_txid]
        self.assertEqual(len(closed), 1)
        acts = self.hub.watch_tick()                             # ...the chain does
        self.assertTrue(any(a["event"] == "ch2_closing" for a in acts), acts)
        self.assertEqual((oc.state, oc.close_txid), ("closing", closed[0].closed_txid))
        self.node.mine()
        self.hub.watch_tick()
        self.assertEqual((oc.state, oc.close_txid), ("closed", closed[0].closed_txid))
        self.assertEqual(self.hub.committed_sat(), 0)
        self.hub.watch_tick()
        self.assertEqual(self.events("ch2_watch_error"), [])

    def test_spent_with_the_spender_unknown(self):
        """No lock: closed (txid unknown), the cap slot is free. A written-off lock: left open, since the
        secret is on that close and the next tick may find it."""
        oc = self.oc()
        self.provider_closes()
        real = hubmod.find_spend_at             # (AGP-088: the reconcile's lookup, with the spender's depth)
        hubmod.find_spend_at = lambda *a: None
        try:
            oc.stale = [{"lockId": "x", "cum": oc.signed, "pre": None, "T": "", "d": 1, "ch1": ""}]
            # the early close of a written-off ch2 (AGP-073) gets no answer: the chain alone decides
            self.net.drop[self.origin] = lambda m, p: p.endswith("/close")
            self.hub.watch_tick()
            self.assertEqual(oc.state, "open")
            self.net.drop.pop(self.origin)
            oc.stale = []
            self.hub.watch_tick()
            self.assertEqual((oc.state, oc.close_txid), ("closing", ""))     # the spend is in the mempool
            self.assertEqual(self.hub.committed_sat(), 0)
            self.node.mine()
            self.hub.watch_tick()
            self.assertEqual((oc.state, oc.close_txid, oc.final), ("closed", "", False))   # confirmed, txid still unknown
        finally:
            hubmod.find_spend_at = real
        self.hub.watch_tick()                                    # found later: the real txid
        self.assertEqual(oc.close_txid, self.node.spenders[(oc.p().funding_txid, oc.p().funding_vout)])


# --- 3 refunds --------------------------------------------------------------------------------------
class Refunds(_World):
    n_providers = 2

    def setUp(self):
        super().setUp()
        self.idle = [o for o in self.provs if o != self.origin][0]   # never routed to: signed 0

    def test_unsigned_ch2_refunded_at_expiry_at_the_hub_fee(self):
        oc = self.oc(self.idle)
        self.assertEqual(oc.signed, 0)
        self.node.feerate = 0.00020                              # 20 sat/vB
        self.node.height = oc.p().expiry - 1
        self.hub.watch_tick()
        self.assertEqual(oc.state, "open")                       # not before expiry (non-final)
        self.node.height = oc.p().expiry
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_refund" and a["provider"] == self.idle)
        from xbt402.tx import Tx
        tx = Tx.parse(bytes.fromhex(oc.refund_hex))
        self.assertEqual(ev["fee"], math.ceil(20 * (tx.vsize() + 1)))
        self.assertNotEqual(ev["fee"], oc.p().close_fee)         # not the provider's closeFee
        self.assertEqual(tx.outputs[0].value, oc.p().capacity - ev["fee"])
        self.assertEqual((oc.state, oc.refund_txid), ("refunded", tx.txid()))
        self.assertEqual(self.hub.committed_sat(), self.oc().p().capacity)   # only the used ch2 is committed
        self.assertEqual(self.hub.refund_fees_sat(), ev["fee"])
        self.node.mine()
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund_confirmed" for a in acts), acts)
        self.assertTrue(oc.final)

    def test_refund_fee_floor_without_an_estimate(self):
        oc = self.oc(self.idle)
        self.node.height = oc.p().expiry
        self.hub.watch_tick()
        from xbt402.tx import Tx
        vsize = Tx.parse(bytes.fromhex(oc.refund_hex)).vsize()
        self.assertEqual(oc.refund_fee, math.ceil(self.hub.config.refund_min_feerate * (vsize + 1)))
        self.assertGreaterEqual(oc.p().capacity - oc.refund_fee, DUST)

    def test_refund_pays_the_refund_to_hook(self):
        from xbt402.tx import address_to_spk, segwit_address
        addr = segwit_address("bcrt", bytes.fromhex("0014" + "ab" * 20))
        self.hub.refund_to = lambda: addr
        oc = self.oc(self.idle)
        self.node.height = oc.p().expiry
        self.hub.watch_tick()
        from xbt402.tx import Tx
        self.assertEqual(Tx.parse(bytes.fromhex(oc.refund_hex)).outputs[0].script_pubkey, address_to_spk(addr, "bcrt"))

    def test_signed_ch2_with_the_provider_gone_is_refunded_after_the_grace(self):
        oc = self.oc()
        self.assertGreaterEqual(oc.signed, oc.p().min_amount)
        del self.net.apps[self.origin]                           # the provider vanished
        self.node.height = oc.p().expiry + self.hub.config.refund_grace_blocks - 1
        self.hub.watch_tick()
        self.assertEqual(oc.state, "open")
        self.node.height += 1
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund" and a["provider"] == self.origin for a in acts), acts)
        self.assertEqual(oc.state, "refunded")
        self.assertNotIn(self.origin, [o for o, c in self.hub.out.chans.items() if c.state in hubmod.LIVE])

    def test_refund_that_left_the_mempool_is_rebroadcast(self):
        oc = self.oc(self.idle)
        self.node.height = oc.p().expiry
        self.hub.watch_tick()
        txid = oc.refund_txid
        self.node.evict(txid)
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_refund_rebroadcast")
        self.assertEqual(ev["txid"], txid)                       # the same tx, not a new one
        self.assertIn(txid, self.node.raw)

class RefundLostToAProviderClose(_World):
    """The written-off lock is ch2's first (floor) state, so its adaptor signature is on the close."""
    n_providers = 2
    lock_first = False

    def setUp(self):
        super().setUp()
        self.idle = [o for o in self.provs if o != self.origin][0]

    def test_provider_close_beats_the_refund_secret_recovered_fee_reverted(self):
        """cmp-lead's rework-3 probe: the refund is accepted, then the provider's close (which carries a
        written-off lock's adaptor signature) confirms instead. The next tick marks ch2 closed with the
        provider's txid, recovers the stale lock's secret for ch1 and takes the refund fee back."""
        self.net.drop[self.origin] = lambda m, p: p == ROUTE_LOCK_PATH
        self.hub.reveal_timeout = 0.3
        self.assertEqual(self.pay.lock(self.sh)["status"], "refused")
        oc = self.oc()
        self.assertEqual(len(oc.stale), 1)
        stale_id = oc.stale[0]["lockId"]
        self.node.height = oc.p().expiry + self.hub.config.refund_grace_blocks
        self.hub.watch_tick()
        self.assertEqual(oc.state, "refunded")
        self.assertGreater(self.hub.refund_fees_sat(), 0)
        self.node.evict(oc.refund_txid)                          # the provider's close replaces it
        close = self.provider_closes()
        self.assertEqual(self.node.spenders[(oc.p().funding_txid, oc.p().funding_vout)], close)
        fees = self.hub.refund_fees_sat()
        acts = self.hub.watch_tick()                             # the close is in the mempool: the secret is read now
        self.assertTrue(any(a["event"] == "secret_from_close" and a["lockId"] == stale_id and a["ch1_completed"]
                            for a in acts), acts)
        self.assertEqual((oc.state, oc.close_txid, oc.stale), ("closing", close, []))
        self.assertEqual(self.hub.refund_fees_sat(), fees)       # ...but the refund fee stays booked (AGP-045)
        st1 = self.hub.inbound.ledger.channels[self.pay.chan]
        self.assertIn(stale_id, [r["lockId"] for r in st1.extra["recovered"]])
        self.node.mine()
        acts = self.hub.watch_tick()
        ev = next(a for a in acts if a["event"] == "ch2_closed")
        self.assertEqual((ev["txid"], ev["refundFeeReverted"] > 0), (close, True))
        self.assertEqual((oc.state, oc.close_txid, oc.final), ("closed", close, True))
        self.assertEqual(self.hub.refund_fees_sat(), self.oc(self.idle).refund_fee)   # only the idle ch2's



# --- 4 close_ch2 validates the provider's reply -------------------------------------------------------
class CloseReply(_World):
    def bad_reply(self, edit, why_part):
        self.net.apps[self.origin] = Wrap(self.prov, lambda m, p, st, doc: edit(doc) if p.endswith("/close") else None)
        oc = self.oc()
        with self.assertRaises(ChannelError) as cm:
            self.hub.close_ch2(oc)
        self.assertEqual(cm.exception.code, "bad_close_reply")
        self.assertIn(why_part, str(cm.exception))
        self.assertEqual((oc.state, oc.close_txid), ("open", ""))
        self.hub.watch_tick()                                    # the watcher survives and reconciles
        self.assertEqual(self.events("ch2_watch_error"), [])
        self.assertEqual(oc.state, "closing")                    # the provider's close, in the mempool
        self.node.mine()
        self.hub.watch_tick()
        self.assertEqual(oc.state, "closed")

    def test_no_txid(self):
        self.bad_reply(lambda d: (200, {k: v for k, v in d.items() if k != "txid"}), "txid")

    def test_txid_not_hex(self):
        self.bad_reply(lambda d: (200, {**d, "txid": "zz" * 32}), "txid")

    def test_cum_not_what_the_hub_signed(self):
        self.bad_reply(lambda d: (200, {**d, "cum": str(int(d["cum"]) + 1)}), "cum")

    def test_payee_fee_mismatch(self):
        self.bad_reply(lambda d: (200, {**d, "payeeFee": "1"}), "payeeFee")

    def test_not_json(self):
        self.net.apps[self.origin] = Wrap(self.prov, lambda m, p, st, doc: (200, b"ok") if p.endswith("/close") else None)
        with self.assertRaises(ChannelError) as cm:
            self.hub.close_ch2(self.oc())
        self.assertEqual(cm.exception.code, "bad_close_reply")

    def test_a_good_reply_reports_gross_cum_payee_fee_and_net(self):
        oc = self.oc()
        ev = self.hub.close_ch2(oc)
        p = oc.p()
        self.assertEqual(p.close_fee_payer, "payee")
        self.assertEqual((ev["amount"], ev["payeeFee"], ev["payeeNet"]), (oc.signed, p.close_fee, oc.signed - p.close_fee))
        self.assertEqual(ev["chan"], p.channel_id)
        self.assertEqual((oc.state, oc.close_txid), ("closing", ev["txid"]))   # closed once it confirms (AGP-045)
        self.node.mine()
        self.hub.watch_tick()
        self.assertEqual((oc.state, oc.final), ("closed", True))


# --- 5 bounded /terms ---------------------------------------------------------------------------------
class HostileTerms(unittest.TestCase):
    def attempt(self, _hub=None, **extra):
        node, net = R.RouteNode(), R.Net()
        origin = "http://evil.test"
        prov = R.provider(node, net, origin)
        net.apps[origin] = Wrap(prov, lambda m, p, st, doc: (
            (200, {**doc, "extra": {**doc["extra"], **extra}}) if p == TERMS_PATH else None))
        h = R.hub(node, net, **(_hub or {}))
        funded = []
        h.fund = lambda a, s: funded.append(a) or node.fund_address(a, s)
        with self.assertRaises(ChannelError) as cm:
            h.connect(origin)
        self.assertEqual(cm.exception.code, "bad_terms", str(cm.exception))
        self.assertEqual((funded, h.out.chans, h.committed_sat()), ([], {}, 0))
        return str(cm.exception)

    def test_close_fee_19990(self):
        self.attempt(closeFeeSat=19_990)

    def test_close_fee_25000_over_capacity(self):
        self.attempt(closeFeeSat=25_000)

    def test_min_expiry_5e6(self):
        self.attempt(minExpiryBlocks=5_000_000, maxExpiryBlocks=6_000_000)

    def test_min_conf_1e9(self):
        self.attempt(minConf=1_000_000_000)

    def test_min_capacity_huge(self):
        self.attempt(minCapacity=10 ** 9)

    def test_settle_multiple_huge(self):
        self.attempt(settleMultiple=10 ** 9)

    def test_malformed(self):
        self.attempt(closeFeeSat="lots")

    def test_the_close_fee_multiple_bounds_capacity(self):
        """Under ch2_max_close_fee_sat, but 20 x closeFeeSat > capacity: the floor would eat the ch2."""
        self.assertIn("x closeFeeSat", self.attempt(closeFeeSat=6_000, _hub=dict(ch2_max_close_fee_sat=10_000)))

    def test_a_close_fee_within_both_bounds_is_funded(self):
        node, net = R.RouteNode(), R.Net()
        origin = "http://ok.test"
        prov = R.provider(node, net, origin)
        net.apps[origin] = Wrap(prov, lambda m, p, st, doc: (
            (200, {**doc, "extra": {**doc["extra"], "closeFeeSat": 4_000}}) if p == TERMS_PATH else None))
        h = R.hub(node, net, ch2_max_close_fee_sat=10_000)
        self.assertEqual(h.connect(origin).p().close_fee, 4_000)     # 20 x 4000 <= 100000

    def test_fair_terms_are_clamped_not_refused(self):
        node, net = R.RouteNode(), R.Net()
        origin = "http://ok.test"
        R.provider(node, net, origin)
        h = R.hub(node, net, ch2_expiry_blocks=5_000, ch2_max_expiry_blocks=2_000)
        oc = h.connect(origin)
        self.assertEqual(oc.p().expiry, node.height + 2_000)     # the hub's max, not the provider's 8640


# --- 6 refill hook ------------------------------------------------------------------------------------
class RefillHook(_World):
    def test_refill_goes_through_the_hook(self):
        calls = []
        self.hub.refill = lambda origin: calls.append(origin)
        self.hub.close_ch2(self.oc(), refill=True)
        self.assertEqual(calls, [self.origin])

    def test_default_refill_is_connect_with_its_cap(self):
        self.hub.liquidity_cap_sat = 50_000                      # below one ch2: the refill is refused
        ev = self.hub.close_ch2(self.oc(), refill=True)
        self.assertIn("liquidity_cap", ev["refillError"])
        self.assertEqual(self.oc().state, "closing")             # the close stands
        self.assertTrue(self.events("ch2_refill_failed"))


# --- 7 watcher robustness -----------------------------------------------------------------------------
class WatcherRobustness(_World):
    n_providers = 2

    def test_one_failing_ch2_never_stops_the_others(self):
        other = [o for o in self.provs if o != self.origin][0]
        bad_txid = self.oc().p().funding_txid
        real = self.node.gettxout

        def gettxout(txid, vout, include_mempool=True):
            if txid == bad_txid:
                raise RuntimeError("node hiccup")
            return real(txid, vout, include_mempool)
        self.node.gettxout = gettxout
        oc2 = self.oc(other)
        self.node.height = oc2.p().expiry
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund" and a["provider"] == other for a in acts), acts)
        errs = self.events("ch2_watch_error")
        self.assertTrue(errs and all(e["provider"] == self.origin for e in errs), errs)

    def test_a_malformed_record_is_logged_per_channel(self):
        other = [o for o in self.provs if o != self.origin][0]
        self.oc().terms = {}                                     # broken: no extra
        oc2 = self.oc(other)
        self.node.height = oc2.p().expiry
        acts = self.hub.watch_tick()
        self.assertTrue(any(a["event"] == "ch2_refund" and a["provider"] == other for a in acts), acts)


if __name__ == "__main__":
    unittest.main()
