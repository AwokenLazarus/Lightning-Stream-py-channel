"""AGP-087 (second closure audit, area HUB-B): the hub's ch2 side one step beside AGP-085's tests
(in-process: a fake node + a fake HTTP transport). As xbt-rs `xbt402-interop/tests/agp087_hub_b.rs`.
Each `test_hole_` FAILS on B1 21b21db.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
from test_agp085_hub import SHORT_CH2, RolloverWorld  # noqa: E402

from xbt402.channel import ChannelParams  # noqa: E402
from xbt402.hub import HubConfig, OutChannel  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider  # noqa: E402


def rollover_txid(w, req):
    p = next(s for s in w.prov.ledger.channels.values() if s.params.channel_id == req["chan"]).params
    nxt = ChannelParams.derive(w.prov.pay_to, req["next"]["payerPub"], req["next"]["expiry"], p.close_fee,
                               req["next"].get("payerSpk", ""), network=R.NET, close_fee_payer=p.close_fee_payer)
    return p.rollover_tx(req["amount"], nxt.spk, p.rollover_next_capacity(req["amount"])).txid()


def spent(node, txid, vout):
    return any((i.txid[::-1].hex(), i.vout) == (txid, vout)
               for hx in node.sent for i in Tx.parse(bytes.fromhex(hx)).inputs)


def locked(w):
    """Every unspent ch2 funding the hub's book knows: (chan, sats)."""
    recs = list(w.hub.out.chans.values()) + list(w.hub.out.next_chans.values()) + [OutChannel(**r) for r in w.hub.out.archived]
    out = []
    for c in recs:
        p = c.p()
        if p.funding_txid and w.node.gettxout(p.funding_txid, p.funding_vout, True) is not None:
            out.append((p.channel_id, p.capacity))
    return out


class HubB(unittest.TestCase):
    def test_hole_a_rollover_answered_200_and_never_broadcast_leaves_the_parent_refundable(self):
        """A 200 is the one rollover answer the hub takes on the provider's word: the parent becomes
        `rolled` (never reconciled or refunded again). A provider that says "rolled" and broadcasts
        nothing leaves the parent's funding unspent for good."""
        w = RolloverWorld(self, hkw={"rollover_relay_grace": 0})
        w.near_margin()
        old = w.oc()
        p = old.p()

        def answer(body, serve):
            req = json.loads(body)
            txid = rollover_txid(w, req)
            return 200, {"chan": req["chan"], "txid": txid, "amount": req["amount"], "nextChan": f"{txid}:1"}
        w.answer = answer
        ev = w.hub.rollover(old)
        self.assertEqual(ev["event"], "ch2_rollover", ev)
        self.assertFalse(spent(w.node, p.funding_txid, p.funding_vout), "nothing was broadcast")
        child = w.oc()
        w.hub.watch_tick()
        for h in (p.expiry + 20, child.p().expiry + 20):
            w.node.height = h
            w.hub.watch_tick()
            w.hub.watch_tick()
        self.assertTrue(spent(w.node, p.funding_txid, p.funding_vout),
                        f"{p.capacity} sat of the hub's coins are still in the parent ch2 {w.node.height - p.expiry} blocks after "
                        f"its expiry: state {old.state!r}, locked {locked(w)}")

    def test_hole_a_close_the_provider_names_and_never_sends_stays_within_the_liquidity_cap(self):
        """A refused rollover ends one block later in close-and-refill; the refill is funded on the
        provider's word that it closed, and a `closing` ch2 does not count against liquidity_cap_sat."""
        cap = 200_000
        w = RolloverWorld(self, hkw={**SHORT_CH2, "liquidity_cap_sat": cap})
        n = [0]
        inner = w.serve

        def serve(method, path, headers, body, url=""):
            if path.endswith("/close"):
                oc = w.oc()
                n[0] += 1
                fee = oc.p().payee_fee
                doc = {"txid": hashlib.sha256(f"no such close {n[0]}".encode()).hexdigest(), "cum": str(oc.signed),
                       "payeeFee": fee, "payeeNet": oc.signed - fee, "status": "closed"}
                return 200, {"Content-Type": "application/json"}, json.dumps(doc).encode()
            return inner(method, path, headers, body, url)
        w.serve = serve
        w.net.apps[w.origin] = type("App", (), {"serve": staticmethod(serve)})()
        w.answer = lambda body, serve: (400, {"error": "bad_request", "detail": "no"})
        cycles = 0
        for _ in range(4):
            old = w.oc()
            self.assertEqual(old.state, "open")
            w.refused(self, old)
            w.node.height += 1
            ev = w.hub.rollover(old)
            self.assertEqual(ev["event"], "ch2_close", ev)
            if ev.get("refillError"):
                break
            cycles += 1
            w.node.confirm_all()
            w.hub.watch_tick()
            self.assertEqual(w.oc().state, "open", "the refill opened")
            w.pay_lock(self)
        lk = locked(w)
        total = sum(s for _, s in lk)
        self.assertLessEqual(total, cap, f"after {cycles} refused rollovers the hub has {total} sat in {len(lk)} unspent ch2 "
                                         f"fundings; liquidity_cap_sat is {cap} and committed_sat() says {w.hub.committed_sat()}")

    def test_ok_decision_1_the_default_numbers_leave_no_headroom_above_the_floor(self):
        """Default hub against default provider terms: the hub asks for exactly the payer's floor."""
        node = R.RouteNode()
        prov = XbtChannelProvider(node, 0xB0B, R.NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: 1, lambda m, p, b: (200, {}, b""))
        ex = prov.terms()["extra"] if hasattr(prov, "terms") else None
        cfg = HubConfig()
        self.assertEqual(cfg.ch2_expiry_blocks, 1_100)
        floor = prov.policy.min_expiry_blocks + prov.policy.min_conf + prov.close_margin
        self.assertEqual((prov.policy.min_expiry_blocks, prov.policy.min_conf, prov.close_margin, floor), (1_008, 1, 144, 1_153))
        if ex is not None:
            self.assertEqual((ex["minExpiryBlocks"], ex.get("minConf", 1), ex["closeMarginBlocks"]), (1_008, 1, 144))
        self.assertEqual(max(cfg.ch2_expiry_blocks, floor), floor, "the hub's own figure is under the floor: asked == floor")


if __name__ == "__main__":
    unittest.main()
