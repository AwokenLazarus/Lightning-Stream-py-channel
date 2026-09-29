"""AGP-044: the routing hub's leftovers from AGP-037. In process (routehelp: FakeNode + a fake HTTP
transport). One class per item:
    1 a stuck ch2 refund is re-signed at a higher fee (RBF: the hub holds the payer key, its refunds signal
      replaceability), capped by refund_max_fee_sat, and whichever version confirms is the refund;
    2 one live ch2 per payTo (two origins, one operator key), the cap accounting unchanged.
The Rust port has the same tests (xbt-rs crates/xbt402-interop/tests/hub_leftovers.rs)."""
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

from xbt402 import tx as txmod  # noqa: E402
from xbt402.channel import DUST, RBF_SEQUENCE, ChannelError  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.hub import LIVE, HubConfig, RouteHub  # noqa: E402
from xbt402.route import HUB_ROUTE_PATH, canon_origin  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import unb64json  # noqa: E402


class W:
    """A hub and a client; keys[i] is provider i's operator key. With `shared`, providers with the same
    key are one backend (one provider served at both origins)."""

    def __init__(self, keys, shared, delay=0.0, settle_multiple=20, datadir=None, **cfg):
        self.node, self.net = R.RouteNode(), R.Net()
        self.funds = 0
        self.lock = threading.Lock()

        def fund(address, sats):
            with self.lock:
                self.funds += 1
            time.sleep(delay)
            return self.node.fund_address(address, sats)
        self.fund = fund
        self.datadir = datadir or tempfile.mkdtemp(prefix="hub-")
        self.hub = self.new_hub(**cfg)
        self.origins, by_key = [], {}
        for i, k in enumerate(keys):
            o = f"http://p{i}.test"
            if shared and k in by_key:
                self.net.apps[o] = by_key[k]
            else:
                by_key[k] = R.provider(self.node, self.net, o, k, settle_multiple=settle_multiple)
            self.origins.append(o)
        self.pay = R.payer(self.node, self.net)
        self.pay.open()

    def new_hub(self, **cfg):
        opts = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
                    reveal_timeout=1.0, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
                    policy=FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36))
        opts.update(cfg)
        h = RouteHub(self.node, 0x4B4B, R.NET, self.datadir, self.fund, http=self.net.http, **opts)
        self.net.apps[R.HUB] = h
        return h

    def connect_all(self):
        for o in self.origins:
            self.hub.connect(o)
        self.node.confirm_all()
        self.hub.watch_tick()

    def oc(self, key):
        return self.hub.out.chans[key]

    def events(self, name):
        return [e for e in self.hub.events if e["event"] == name]

    def live(self):
        return sum(1 for c in self.hub.out.chans.values() if c.state in LIVE)

    def providers(self, hub=None):
        st, h, _ = (hub or self.hub).serve("GET", HUB_ROUTE_PATH, {}, b"")
        return unb64json(h["PAYMENT-REQUIRED"])["accepts"][0]["extra"]["routing"]["providers"]


def has(acts, f):
    return any(f(a) for a in acts)


# --- 1 stuck refund bump (RBF) --------------------------------------------------------------------------

class RefundBump(unittest.TestCase):
    def stuck(self, block_min, **cfg):
        """One unsigned ch2 at its expiry, a refund at 1 sat/vB, blocks that take only >= block_min sat/vB."""
        w = W([0xA1], False, **cfg)
        w.connect_all()
        w.node.feerate = 0.00001                                 # 1 sat/vB
        w.node.block_min_feerate = block_min
        w.node.height = w.oc(w.origins[0]).p().expiry
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, lambda a: a["event"] == "ch2_refund"), acts)
        return w

    @staticmethod
    def blocks(w, n):
        acts = []
        for _ in range(n):
            w.node.mine()
            acts += w.hub.watch_tick()
        return acts

    def test_bump_the_hub_refund_signals_rbf_and_keeps_its_locktime(self):
        w = self.stuck(0.0)
        oc = w.oc(w.origins[0])
        tx = Tx.parse(bytes.fromhex(oc.refund_hex))
        self.assertEqual(tx.inputs[0].sequence, RBF_SEQUENCE)
        self.assertEqual(tx.locktime, oc.p().expiry)
        self.assertEqual(oc.refund_at, oc.p().expiry)

    def test_bump_a_stuck_refund_is_replaced_at_a_higher_fee_until_it_confirms(self):
        w = self.stuck(5.0)
        o = w.origins[0]
        first = w.oc(o)
        f1, v = w.node.fee_of(first.refund_txid)
        self.assertEqual(f1, first.refund_fee)
        self.assertLess(f1, 5.0 * v)                             # below what blocks take
        acts = self.blocks(w, 2)                                 # not before refund_bump_blocks (3)
        self.assertFalse(has(acts, lambda a: a["event"] == "ch2_refund_bump"), acts)
        self.assertEqual(w.oc(o).refund_txid, first.refund_txid)
        fees, txids = [f1], [first.refund_txid]
        for _ in range(8):
            acts = self.blocks(w, 1)
            b = next((a for a in acts if a["event"] == "ch2_refund_bump"), None)
            if b:
                prev = fees[-1]
                self.assertEqual((b["replaces"], b["feeFrom"]), (txids[-1], prev))
                self.assertTrue(b["fee"] >= 2 * prev and b["fee"] >= prev + v, (b["fee"], prev))
                self.assertNotIn(txids[-1], w.node.raw)          # replaced in the mempool
                fees.append(b["fee"])
                txids.append(b["txid"])
            if w.oc(o).final:
                break
        oc = w.oc(o)
        self.assertTrue(oc.final, w.events("ch2_refund_bump"))
        self.assertEqual(oc.state, "refunded")
        self.assertGreaterEqual(len(fees), 3, fees)               # 1 -> 2 -> 4 -> 8 sat/vB: the third bump confirms
        self.assertEqual((oc.refund_txid, oc.refund_fee), (txids[-1], fees[-1]))
        self.assertEqual(len(oc.refund_prev), len(fees) - 1)
        self.assertTrue(w.node.confirmed(oc.refund_txid))
        out = Tx.parse(bytes.fromhex(w.node.raw[oc.refund_txid])).outputs[0].value
        self.assertEqual(out, oc.p().capacity - oc.refund_fee)
        self.assertEqual(w.hub.refund_fees_sat(), oc.refund_fee)
        conf = w.events("ch2_refund_confirmed")
        self.assertEqual((len(conf), conf[0]["txid"], conf[0]["versions"]), (1, oc.refund_txid, len(fees)))
        self.assertEqual(w.hub.committed_sat(), 0)

    def test_bump_the_fee_spent_is_capped_by_refund_max_fee_sat(self):
        w = self.stuck(1000.0, refund_max_fee_sat=700)
        o = w.origins[0]
        self.blocks(w, 30)
        oc = w.oc(o)
        self.assertFalse(oc.final)
        self.assertEqual(oc.refund_fee, 700)
        self.assertTrue(all(b["fee"] <= 700 for b in w.events("ch2_refund_bump")))
        capped = w.events("ch2_refund_bump_capped")
        self.assertTrue(capped and all(c["cap"] == 700 and c["fee"] == 700 for c in capped), capped)
        self.assertIn(oc.refund_txid, w.node.raw)                # at the cap it is still sent (and watched)
        self.assertGreaterEqual(oc.p().capacity - oc.refund_fee, DUST)

    def test_bump_an_earlier_version_that_confirms_is_the_refund(self):
        w = self.stuck(5.0)
        o = w.origins[0]
        old = w.oc(o)
        old_txid, old_fee, old_hex = old.refund_txid, old.refund_fee, old.refund_hex
        self.blocks(w, 3)
        new = w.oc(o)
        self.assertNotEqual(new.refund_txid, old_txid)
        self.assertEqual(new.refund_prev, [{"txid": old_txid, "fee": old_fee}])
        w.node.evict(new.refund_txid)                            # a miner that had only the first version mines it
        w.node.sendrawtransaction(old_hex)
        w.node.block_min_feerate = 0.0
        acts = self.blocks(w, 1)
        c = next(a for a in acts if a["event"] == "ch2_refund_confirmed")
        self.assertEqual((c["txid"], c["fee"]), (old_txid, old_fee))
        oc = w.oc(o)
        self.assertTrue(oc.final)
        self.assertEqual((oc.refund_txid, oc.refund_fee), (old_txid, old_fee))
        self.assertEqual(w.hub.refund_fees_sat(), old_fee)

    def test_bump_a_refund_that_left_the_mempool_goes_back_bumped_once_due(self):
        w = self.stuck(0.0)
        o = w.origins[0]
        first_txid, first_at = w.oc(o).refund_txid, w.oc(o).refund_at
        w.node.evict(first_txid)
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, lambda a: a["event"] == "ch2_refund_rebroadcast" and a["txid"] == first_txid), acts)
        w.node.evict(first_txid)
        w.node.height = first_at + 3
        acts = w.hub.watch_tick()
        b = next(a for a in acts if a["event"] == "ch2_refund_bump")
        self.assertNotEqual(b["txid"], first_txid)
        self.assertIn(b["txid"], w.node.raw)

    def test_bump_pays_the_same_destination_as_the_version_it_replaces(self):
        w = self.stuck(5.0)
        n = [0]

        def fresh():                                             # a wallet's getnewaddress: a new address per call
            n[0] += 1
            return txmod.segwit_address("bcrt", bytes([0, 20]) + bytes([n[0]]) * 20)
        w.hub.refund_to = fresh
        o = w.origins[0]
        spk0 = Tx.parse(bytes.fromhex(w.oc(o).refund_hex)).outputs[0].script_pubkey
        self.blocks(w, 3)
        oc = w.oc(o)
        self.assertEqual(len(oc.refund_prev), 1)
        self.assertEqual(Tx.parse(bytes.fromhex(oc.refund_hex)).outputs[0].script_pubkey, spk0)
        self.assertEqual(n[0], 0)

    def test_bump_off_with_refund_bump_blocks_zero(self):
        w = self.stuck(5.0, refund_bump_blocks=0)
        o = w.origins[0]
        first = w.oc(o).refund_txid
        self.blocks(w, 10)
        self.assertEqual(w.events("ch2_refund_bump"), [])
        self.assertEqual(w.oc(o).refund_txid, first)

    def test_bump_a_refused_replacement_keeps_both_versions_tracked(self):
        w = self.stuck(5.0)
        o = w.origins[0]
        old = w.oc(o)
        # an AGP-037 refund (no RBF signal) already in the mempool: the node refuses its replacement
        w.node.evict(old.refund_txid)
        legacy = old.p().refund_tx(int(old.secret, 16), None, old.refund_fee)
        w.node.sendrawtransaction(legacy.serialize().hex())
        with w.hub.out.lock:
            old.refund_hex, old.refund_txid = legacy.serialize().hex(), legacy.txid()
            w.hub.out.save()
        acts = self.blocks(w, 3)
        f = next(a for a in acts if a["event"] == "ch2_refund_bump_failed")
        self.assertIn("conflict", f["error"])
        self.assertEqual(w.oc(o).refund_prev[0]["txid"], legacy.txid())
        w.node.block_min_feerate = 0.0                           # the legacy version confirms after all: it is the refund
        self.blocks(w, 1)
        oc = w.oc(o)
        self.assertTrue(oc.final)
        self.assertEqual(oc.refund_txid, legacy.txid())

    def test_bump_config_keys_round_trip(self):
        c = HubConfig.from_dict({"refund_bump_blocks": 7, "refund_max_fee_sat": 1234})
        self.assertEqual((c.refund_bump_blocks, c.refund_max_fee_sat), (7, 1234))
        d = HubConfig()
        self.assertEqual((d.refund_bump_blocks, d.refund_max_fee_sat), (3, 5000))


# --- 2 one live ch2 per payTo ---------------------------------------------------------------------------

class OneCh2PerPayTo(unittest.TestCase):
    def test_payto_two_origins_one_operator_get_one_ch2_and_the_cap_is_unchanged(self):
        w = W([0xA1, 0xA1], True, liquidity_cap_sat=100_000)    # the cap holds exactly one ch2
        a, b = w.origins
        oa, ob = w.hub.connect(a), w.hub.connect(b)
        self.assertEqual(oa.p().channel_id, ob.p().channel_id)
        self.assertEqual((w.funds, w.hub.committed_sat(), w.live()), (1, 100_000, 1))
        reuse = w.events("ch2_reuse")
        self.assertEqual((len(reuse), reuse[0]["provider"], reuse[0]["ch2"]), (1, b, a))
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.providers(), [a, b])                  # the hub's 402 lists both origins as routable
        sa, sb = w.pay.shard(a + "/v1/chunk"), w.pay.shard(b + "/v1/chunk")
        for sh in (sa, sb, sa):
            R.stream(w.pay, sh, 6)
            self.assertEqual(w.pay.lock(sh)["status"], "paid")
        self.assertEqual(w.oc(a).routed, sa.locked_sat + sb.locked_sat)
        self.assertNotIn(b, w.hub.out.chans)
        self.assertEqual(w.hub.committed_sat(), 100_000)

    def test_payto_a_second_connect_to_the_same_origin_funds_nothing(self):
        w = W([0xA1], False)
        o = w.origins[0]
        c1 = w.hub.connect(o)
        w.node.confirm_all()
        w.hub.watch_tick()
        c2 = w.hub.connect(o.upper().replace("HTTP://", "http://") + "/")
        self.assertEqual(c1.p().channel_id, c2.p().channel_id)
        self.assertEqual((w.funds, len(w.hub.out.archived)), (1, 0))
        self.assertEqual(w.oc(o).state, "open")

    def test_payto_while_funding_a_second_origin_is_refused_not_funded(self):
        w = W([0xA1, 0xA1], True)
        a, b = w.origins
        w.hub.connect(a)
        w.oc(a).state = "funding"                                # the wallet call still out
        with self.assertRaises(ChannelError) as e:
            w.hub.connect(b)
        self.assertEqual(e.exception.code, "ch2_funding")
        self.assertEqual(w.funds, 1)

    def test_payto_racing_connects_fund_one_ch2(self):
        w = W([0xA1, 0xA1], True, delay=0.15)
        res = {}

        def go(o):
            try:
                res[o] = ("ok", w.hub.connect(o).p().channel_id)
            except ChannelError as e:
                res[o] = ("err", e.code)
        ths = [threading.Thread(target=go, args=(o,)) for o in w.origins]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        self.assertEqual(w.funds, 1, res)
        self.assertTrue(any(r[0] == "ok" for r in res.values()), res)
        self.assertTrue(all(r[0] == "ok" or r[1] == "ch2_funding" for r in res.values()), res)
        self.assertEqual(w.live(), 1)

    def test_payto_rollover_keeps_both_origins_on_the_next_ch2(self):
        w = W([0xA1, 0xA1], True)
        w.connect_all()
        a, b = w.origins
        sb = w.pay.shard(b + "/v1/chunk")
        R.stream(w.pay, sb, 6)
        self.assertEqual(w.pay.lock(sb)["status"], "paid")
        before = w.oc(a)
        before_chan = before.p().channel_id
        w.node.height = before.p().expiry - 40                   # near its close margin: the provider co-signs
        w.hub.rollover(before)
        after = w.oc(a)
        self.assertNotEqual(after.p().channel_id, before_chan)
        w.node.confirm_all()
        w.hub.watch_tick()
        self.assertEqual(w.oc(a).state, "open")
        R.stream(w.pay, sb, 6)
        self.assertEqual(w.pay.lock(sb)["status"], "paid")
        self.assertEqual(w.oc(a).p().channel_id, after.p().channel_id)
        self.assertGreater(w.oc(a).routed, 0)
        self.assertEqual(w.live(), 1)

    def test_payto_after_a_close_the_next_origin_funds_the_one_new_ch2(self):
        w = W([0xA1, 0xA1], True)
        w.connect_all()
        a, b = w.origins
        sa = w.pay.shard(a + "/v1/chunk")
        R.stream(w.pay, sa, 6)
        self.assertEqual(w.pay.lock(sa)["status"], "paid")
        w.hub.close_ch2(w.oc(a))
        self.assertEqual(w.live(), 0)
        nb = w.hub.connect(b)                                    # not live any more: a new ch2, under b
        self.assertEqual((nb.origin, w.funds, w.live()), (b, 2, 1))
        self.assertEqual(w.hub.connect(a).p().channel_id, nb.p().channel_id)   # a reuses it
        self.assertEqual(w.funds, 2)
        w.node.confirm_all()
        w.hub.watch_tick()
        R.stream(w.pay, sa, 6)
        self.assertEqual(w.pay.lock(sa)["status"], "paid")       # a's locks go over b's ch2
        self.assertGreater(w.oc(b).routed, 0)

    def test_payto_the_origin_map_survives_a_restart(self):
        w = W([0xA1, 0xA1], True)
        w.connect_all()
        a, b = w.origins
        h2 = w.new_hub()
        self.assertEqual(w.providers(h2), [a, b])
        self.assertEqual(h2.connect(b).origin, a)

    def test_payto_separate_backends_under_one_key_share_the_ch2_and_the_other_device_is_refused(self):
        # two provider processes with one operator key and separate ledgers: the second origin reuses the
        # first's ch2, so its locks reach a provider that has no session for them: refused, and only that
        # lock (nothing is blocked; the first origin keeps routing)
        w = W([0xA1, 0xA1], False)
        w.connect_all()
        a, b = w.origins
        self.assertEqual((w.funds, w.live()), (1, 1))
        sb = w.pay.shard(b + "/v1/chunk")
        R.stream(w.pay, sb, 6)
        r = w.pay.lock(sb)
        self.assertEqual((r["status"], r.get("error")), ("refused", "route_failed"), r)
        self.assertEqual(w.oc(a).blocked, "")
        sa = w.pay.shard(a + "/v1/chunk")
        R.stream(w.pay, sa, 6)
        self.assertEqual(w.pay.lock(sa)["status"], "paid")

    def test_payto_canonical_origins(self):
        for i, o in [("HTTP://Host.Test:80/", "http://host.test"), ("https://h.test:443", "https://h.test"),
                     ("http://h.test:8080//", "http://h.test:8080"), ("http://h.test/Path/", "http://h.test/Path"),
                     ("http://[::1]:80", "http://[::1]"), ("https://h.test:80", "https://h.test:80")]:
            self.assertEqual(canon_origin(i), o, i)


if __name__ == "__main__":
    unittest.main()
