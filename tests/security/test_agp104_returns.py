"""AGP-104: every coin the hub gets back reaches an address the operator controls. xbt-rs has the same
tests under the same names (crates/xbt402-interop/tests/agp104_returns.rs), and the ones for the status
page and its sums, which B1 does not have.

Rule R1: no coin of the hub's rests on a key only its state files know. A ch2 the hub funds names a
return address for its remainder; a closed ch1's payout and a ch2 remainder that an older ledger left on
a per-channel key are swept there.
Rule R2: one signed sweep per output. A sweep is written before it is sent, the same bytes are sent
again until the chain has them, and nothing is swept before the spend it depends on is
spend_final_depth deep.
"""
import os
import sys
import tempfile
import unittest
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelError, sign_p2wpkh  # noqa: E402
from xbt402.funding import FundingPolicy, open_expiry_floor  # noqa: E402
from xbt402.hub import HubConfig, OutChannel, RouteHub, own_key  # noqa: E402
from xbt402.tx import Tx, TxIn, TxOut, p2wpkh_spk, segwit_address  # noqa: E402

DEPOSIT = 1_000_000


class Node(R.RouteNode):
    """RouteNode with an output's real depth (it answered 1 for every confirmed output, however deep),
    a block that is replaced, and what a script holds."""

    def __init__(self, height=1000):
        super().__init__(height)
        self.conf_at, self.refuse = {}, False

    def confirm_all(self):
        fresh = [t for t, x in self.txs.items() if not self._held(t) and x.get("confirmations", 0) == 0]
        super().confirm_all()
        for t in fresh:
            self.conf_at[t] = self.height

    def gettxout(self, txid, vout, include_mempool=True):
        u = super().gettxout(txid, vout, include_mempool)
        at = self.conf_at.get(txid.lower())
        if u and at is not None and u["confirmations"] >= 1:
            u = {**u, "confirmations": max(u["confirmations"], self.height - at + 1)}
        return u

    def sendrawtransaction(self, hx):
        if self.refuse:
            raise RuntimeError("the node is away")
        return super().sendrawtransaction(hx)

    def unconfirm(self, txid):
        """The block with `txid` is replaced: the tx is back in the mempool."""
        self.txs[txid]["confirmations"] = 0
        self.conf_at.pop(txid, None)
        for k in [k for k, v in self.spenders.items() if v == txid]:
            self.mined.discard(k)
            self.mined_at.pop(k, None)

    def evict(self, txid):
        super().evict(txid)
        self.conf_at.pop(txid, None)

    def unspent_to(self, spk_hex: str) -> int:
        return sum(round(o["value"] * 1e8) for t, tx in self.txs.items() for o in tx["vout"]
                   if o["scriptPubKey"].get("hex") == spk_hex and (t, o["n"]) not in self.spent)

    def spender(self, txid, vout):
        return self.spenders.get((txid, vout))


class OpWallet:
    """The operator's wallet: the addresses it handed out, and what the chain holds on them."""

    def __init__(self, node):
        self.node, self.spks, self.down = node, [], False

    def address(self):
        if self.down:
            raise RuntimeError("getnewaddress: wallet is not loaded")
        spk = p2wpkh_spk(ecc.pubkey(0x9000 + len(self.spks)))
        self.spks.append(spk.hex())
        return segwit_address("bcrt", spk)

    def held(self):
        return sum(self.node.unspent_to(s) for s in self.spks)


class W:
    def __init__(self, n=1, returns=True, **hkw):
        self.node, self.net = Node(), R.Net()
        self.wallet = OpWallet(self.node)
        self.dir = tempfile.mkdtemp(prefix="hub104-")
        self.hkw = dict(spend_final_depth=6, **hkw)        # the shipped depth
        self.hub = self._hub(returns)
        self.provs = {}
        for i in range(n):
            o = f"http://p{i}.test"
            self.provs[o] = R.provider(self.node, self.net, o, amsat_per_call=500_000 * 10 ** 18)
            self.hub.connect(o)
        self.node.confirm_all()
        self.hub.watch_tick()
        self.pay = R.payer(self.node, self.net, expiry_blocks=3_000)
        self.pay.open()
        self.shards = [self.pay.shard(o + "/v1/chunk") for o in self.provs]
        self.origins = list(self.provs)

    def _hub(self, returns=True):
        opts = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
                    reveal_timeout=1.0, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
                    settle_lock_multiple=0, refill_ahead_locks=0,
                    policy=FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36))
        opts.update(self.hkw)
        # without a return address: as `python -m xbt402.hub` did before AGP-104 (refunds to the wallet)
        hook = {"return_to": self.wallet.address} if returns else {"refund_to": self.wallet.address}
        h = RouteHub(self.node, 0x4B4B, R.NET, self.dir, self.node.fund_address, http=self.net.http, **hook, **opts)
        self.net.apps[R.HUB] = h
        return h

    def restart(self):
        """The hub stops and starts again on the same data dir, with a return address."""
        self.hub.inbound.ledger.close() if hasattr(self.hub.inbound.ledger, "close") else None
        self.hub = self._hub(True)

    def pay_seller(self, i, calls):
        R.stream(self.pay, self.shards[i], calls)
        r = self.pay.lock(self.shards[i])
        assert r and r["status"] == "paid", r

    def seller_closes(self, i):
        p = self.provs[self.origins[i]]
        st = next(s for s in p.ledger.channels.values() if not s.closed_txid)
        with p.ledger.lock:
            return p._close_locked(st)

    def mine_tick(self):
        self.node.mine(1)
        return self.hub.watch_tick()

    def blocks(self, n):
        acts = self.hub.watch_tick()
        for _ in range(n):
            acts += self.mine_tick()
        return acts

    def records(self):
        return [asdict(c) for c in list(self.hub.out.chans.values()) + list(self.hub.out.next_chans.values())] + list(self.hub.out.archived)

    def on_channel_keys(self):
        """Sats on keys only the hub's state files know: each ch2's own payer key, each ch1's payee key."""
        ch2 = sum(self.node.unspent_to(p2wpkh_spk(bytes.fromhex(r["params"]["payer_pub"])).hex()) for r in self.records())
        ch1 = sum(self.node.unspent_to(st.params.payee_spk) for st in self.hub.inbound.ledger.channels.values())
        return ch2, ch1

    def oc(self, i):
        return self.hub.out.chans[self.origins[i]]

    def ch1_sweep(self):
        return (self.hub.inbound.ledger.channels[self.pay.chan].extra or {}).get("payee_sweep_intent")

    def events(self, name):
        return [e for e in self.hub.events if e.get("event") == name]


def has(acts, name):
    return any(a.get("event") == name for a in acts)


def closed_ch1():
    """A hub, one seller paid 5,000 sat through it, and the buyer's ch1 closed (in the mempool)."""
    w = W(1)
    w.pay_seller(0, 10)
    return w, w.pay.close()["txid"]


class Returns(unittest.TestCase):
    def test_full_cycle_leaves_no_coin_on_a_channel_key(self):
        # fund (two sellers), route, seller close, buyer close, refund
        w = W(2)
        w.pay_seller(0, 10)
        signed, best = w.oc(0).signed, w.hub.inbound.ledger.channels[w.pay.chan].best_cum
        w.seller_closes(0)
        w.blocks(7)
        w.pay.close()
        w.blocks(14)
        w.node.height = w.oc(1).p().expiry
        w.blocks(8)
        self.assertEqual(w.on_channel_keys(), (0, 0))
        # two channels of 100,000: one back less what the seller was paid, one back less its refund's fee;
        # and what the buyer paid, less its sweep's fee
        refund_fee = w.oc(1).refund_fee
        self.assertEqual(w.wallet.held(), (100_000 - signed) + (100_000 - refund_fee) + (best - 110))
        self.assertEqual(len(w.events("ch1_swept")), 1)

    def test_a_ch2_names_a_return_address_when_it_is_funded_funded_ahead_and_rolled_over(self):
        w = W(1)
        oc = w.oc(0)
        self.assertIn(oc.p().payer_spk, w.wallet.spks)
        self.assertFalse(own_key(oc.p()))
        p = w.provs[w.origins[0]]
        self.assertEqual(p.ledger.channels[oc.p().channel_id].params.payer_spk, oc.p().payer_spk, "the seller holds the same script")
        nxt = w.hub.connect_next(w.origins[0])
        self.assertIn(nxt.p().payer_spk, w.wallet.spks, "funded ahead")
        w.pay_seller(0, 30)
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, "ch2_rollover"), acts)
        child = w.oc(0)
        self.assertEqual((child.rolled_from, child.p().payer_spk), (oc.p().channel_id, oc.p().payer_spk),
                         "rollover: the next ch2 returns where its parent does")

    def test_a_return_address_that_fails_funds_nothing(self):
        w = W(1)
        before, sends = len(w.records()), len(w.node.wallet_txs)
        w.wallet.down = True
        R.provider(w.node, w.net, "http://late.test")
        with self.assertRaises(ChannelError) as e:
            w.hub.connect("http://late.test")
        self.assertEqual(e.exception.code, "return_address")
        with self.assertRaises(ChannelError) as e:
            w.hub.connect_next(w.origins[0])
        self.assertEqual(e.exception.code, "return_address")
        self.assertEqual((len(w.records()), len(w.node.wallet_txs)), (before, sends), "no record, nothing paid")
        w.pay_seller(0, 10)                              # the ch2s it has go on routing
        w.wallet.down = False
        self.assertEqual(w.hub.connect("http://late.test").state, "funded")

    def test_a_bad_return_address_is_refused_before_anything_is_funded(self):
        w = W(0)
        R.provider(w.node, w.net, "http://p0.test")
        for bad in ("", "not-an-address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"):      # (the last: another network's)
            w.hub.return_to = lambda bad=bad: bad
            with self.assertRaises(ChannelError) as e:
                w.hub.connect("http://p0.test")
            self.assertEqual(e.exception.code, "return_address", bad)
        self.assertEqual(w.records(), [])

    def test_nothing_is_swept_before_the_close_is_final(self):
        w, close = closed_ch1()
        for depth in range(1, 4):
            w.mine_tick()
            self.assertIsNone(w.ch1_sweep(), f"swept {depth} deep")
        w.node.unconfirm(close)                          # the block with the close is replaced
        for depth in range(1, 6):
            w.mine_tick()
            self.assertIsNone(w.ch1_sweep(), f"swept {depth} deep after the reorg")
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch1_sweep"), acts)
        self.assertEqual(w.node.spender(close, 0), w.ch1_sweep()["txid"])
        for _ in range(5):                               # the sweep itself is final only at the same depth
            self.assertFalse(has(w.mine_tick(), "ch1_swept"))
        self.assertTrue(has(w.mine_tick(), "ch1_swept"))
        self.assertEqual(w.on_channel_keys(), (0, 0))
        n = len(w.hub.events)
        w.blocks(3)
        self.assertEqual(len(w.hub.events), n, "nothing looks at it again")

    def test_a_failed_sweep_is_sent_again_with_the_same_bytes_and_never_signed_again(self):
        w, close = closed_ch1()
        w.blocks(5)
        w.node.refuse = True
        acts = w.mine_tick()
        self.assertFalse(has(acts, "ch1_sweep"))
        self.assertEqual(len(w.events("sweep_error")), 1)
        first = dict(w.ch1_sweep())                      # written ahead of the send that failed
        self.assertIsNone(w.node.spender(close, 0), "control: nothing reached the chain")
        # fees rise and the wallet hands out another address: neither makes a second sweep of the same output
        w.node.feerate = 9.0 * 1000 / 1e8
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch1_sweep_failed"), acts)
        w.node.refuse = False
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch1_sweep_resent"), acts)
        self.assertEqual(w.ch1_sweep(), first, "the sweep written ahead is unchanged")
        self.assertEqual(w.node.spender(close, 0), first["txid"])
        # the operator's tool on the same channel gets the same sweep, whatever it asks for
        other = w.hub.inbound.sweep_payee(w.pay.chan, p2wpkh_spk(ecc.pubkey(77)), 999)
        self.assertEqual(other["txid"], first["txid"])
        w.blocks(6)
        self.assertEqual((len(w.events("ch1_swept")), w.on_channel_keys()), (1, (0, 0)))

    def test_a_sweep_that_leaves_the_mempool_goes_out_again(self):
        w, close = closed_ch1()
        w.blocks(6)
        txid = w.ch1_sweep()["txid"]
        w.node.evict(txid)
        self.assertIsNone(w.node.spender(close, 0))
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch1_sweep_resent"), acts)
        self.assertEqual(w.node.spender(close, 0), txid)
        w.mine_tick()
        w.node.unconfirm(txid)                           # in a block, then that block is replaced
        for _ in range(5):
            self.assertFalse(has(w.mine_tick(), "ch1_swept"))
        self.assertTrue(has(w.mine_tick(), "ch1_swept"))

    def test_a_wallet_that_spends_the_swept_coin_at_once_does_not_leave_the_sweep_open(self):
        w, _ = closed_ch1()
        w.blocks(6)
        sw = w.ch1_sweep()
        w.mine_tick()
        key = next(0x9000 + i for i, s in enumerate(w.wallet.spks) if s == sw["dest_spk"])
        tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(sw["txid"])[::-1], 0, 0xFFFFFFFD)],
                outputs=[TxOut(sw["swept"] - 200, p2wpkh_spk(ecc.pubkey(88)))], locktime=0)
        sign_p2wpkh(key, tx, [TxOut(sw["swept"], bytes.fromhex(sw["dest_spk"]))])
        w.node.sendrawtransaction(tx.hex())
        acts = []
        for _ in range(7):
            acts += w.mine_tick()
        self.assertTrue(has(acts, "ch1_swept"), acts)
        self.assertFalse(has(acts, "ch1_sweep_resent") or has(acts, "ch1_sweep_failed"), acts)

    def test_a_payout_under_the_cost_of_a_sweep_is_left(self):
        w = W(1)
        w.pay_seller(0, 1)                               # one call of 500 sat: ch1 closes at its dust floor
        w.pay.close()
        acts = w.blocks(7)
        self.assertTrue(has(acts, "ch1_sweep_skipped") and not has(acts, "ch1_sweep"), acts)
        self.assertEqual(w.on_channel_keys(), (0, 546), "546 < 110 + 546: never worth a sweep")

    def test_a_payout_the_fee_is_too_high_for_now_waits_for_a_lower_fee(self):
        w = W(1)
        w.pay_seller(0, 2)
        w.pay.close()
        w.mine_tick()                                    # (the close confirms first: a close still unconfirmed at
        w.node.feerate = 9.0 * 1000 / 1e8                # this rate is bumped by a child that spends the payout)
        acts = w.blocks(7)
        self.assertFalse(has(acts, "ch1_sweep") or has(acts, "ch1_sweep_skipped"), acts)
        w.node.feerate = None
        self.assertTrue(has(w.mine_tick(), "ch1_sweep"))
        w.blocks(6)
        self.assertEqual(w.on_channel_keys(), (0, 0))

    def test_a_payout_that_is_there_but_shallow_long_after_the_expiry_is_waited_for(self):
        w, _ = closed_ch1()
        w.node.height = w.hub.inbound.ledger.channels[w.pay.chan].params.expiry + 150
        acts = w.blocks(5)
        self.assertFalse(has(acts, "ch1_sweep_skipped") or has(acts, "ch1_sweep"), acts)
        self.assertTrue(has(w.blocks(1), "ch1_sweep"))

    def test_without_a_return_address_nothing_is_swept(self):
        w = W(1, returns=False)                          # the library's default, and the hub before AGP-104
        w.pay_seller(0, 10)
        w.seller_closes(0)
        w.pay.close()
        w.blocks(20)
        ch2, ch1 = w.on_channel_keys()
        self.assertTrue(ch2 > 90_000 and ch1 > 5_000, (ch2, ch1))
        self.assertEqual(w.events("ch1_sweep") + w.events("ch2_sweep"), [])

    def test_a_ledger_from_before_is_swept_refunded_and_rolled_to_the_return_address(self):
        w = W(3, returns=False)
        self.assertTrue(all(own_key(OutChannel(**r).p()) for r in w.records()), "control: each ch2 names its own key")
        w.pay_seller(0, 10)
        w.seller_closes(0)
        w.pay.close()
        w.blocks(20)
        ch2, ch1 = w.on_channel_keys()
        self.assertTrue(ch2 > 90_000 and ch1 > 5_000)
        w.restart()                                      # upgrade
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch1_sweep") and has(acts, "ch2_sweep"), acts)
        acts = w.blocks(6)
        self.assertTrue(has(acts, "ch1_swept") and has(acts, "ch2_swept"), acts)
        self.assertEqual(w.on_channel_keys(), (0, 0))
        w.node.height = w.oc(1).p().expiry               # the ch2 never paid: refunded to a return address
        acts = w.blocks(8)
        self.assertTrue(has(acts, "ch2_refund_confirmed"), acts)
        self.assertEqual(w.on_channel_keys(), (0, 0))

    def test_a_ch2_on_its_own_key_rolls_over_into_one_that_names_a_return_address(self):
        w = W(1, returns=False)
        w.restart()
        w.pay_seller(0, 30)
        acts = w.hub.watch_tick()
        self.assertTrue(has(acts, "ch2_rollover"), acts)
        child = w.oc(0).p()
        self.assertTrue(not own_key(child) and child.payer_spk in w.wallet.spks)

    def test_a_stop_between_the_write_and_the_send_leaves_one_sweep_that_the_next_start_sends(self):
        w = W(1, returns=False)
        w.pay_seller(0, 10)
        w.seller_closes(0)
        w.blocks(7)
        key = p2wpkh_spk(bytes.fromhex(w.records()[0]["params"]["payer_pub"])).hex()
        held = w.node.unspent_to(key)
        self.assertGreater(held, 90_000)
        w.restart()
        w.hub.stop_at = "sweep"
        w.mine_tick()
        self.assertEqual(w.node.unspent_to(key), held, "control: stopped before the send")
        first = dict(w.records()[0]["sweep"])
        self.assertIn("hex", first)
        w.restart()
        acts = w.mine_tick()
        self.assertTrue(has(acts, "ch2_sweep_resent"), acts)
        self.assertEqual(w.records()[0]["sweep"]["txid"], first["txid"])
        acts = w.blocks(6)
        self.assertTrue(has(acts, "ch2_swept"), acts)
        self.assertEqual(w.node.unspent_to(key), 0)


class Capital(unittest.TestCase):
    def test_capital_admits_sellers_while_a_channel_and_one_spare_fit(self):
        w = W(2, capital_sat=300_000, refill_ahead_locks=4)
        R.provider(w.node, w.net, "http://p2.test")
        with self.assertRaises(ChannelError) as e:
            w.hub.connect("http://p2.test")
        self.assertEqual(e.exception.code, "liquidity_cap")
        self.assertIn("capital_sat 300000", str(e.exception))
        self.assertIn("kept for funding ahead", str(e.exception))
        self.assertEqual(w.hub.connect_next(w.origins[0]).state, "funded")
        with self.assertRaises(ChannelError) as e:
            w.hub.connect_next(w.origins[1])
        self.assertEqual(e.exception.code, "liquidity_cap")
        self.assertEqual(w.hub.committed_sat(), 300_000)

    def test_capital_is_one_setting(self):
        self.assertEqual(HubConfig(capital_sat=500_000).liquidity_cap(), 500_000)
        self.assertEqual(HubConfig(liquidity_cap_sat=400_000).liquidity_cap(), 400_000, "as before")
        self.assertEqual(HubConfig(capital_sat=500_000, liquidity_cap_sat=500_000).liquidity_cap(), 500_000)
        with self.assertRaises(ValueError):
            HubConfig(capital_sat=500_000, liquidity_cap_sat=400_000)
        with self.assertRaises(ValueError):
            HubConfig(capital_sat=199_999)               # one ch2 and its spare must fit
        HubConfig(capital_sat=200_000)
        c = HubConfig(capital_sat=100_000, refill_ahead_locks=0)
        self.assertEqual((c.liquidity_cap(), c.spare_sat()), (100_000, 0))

    def test_the_shipped_ch2_expiry_clears_a_default_sellers_floor(self):
        self.assertEqual((open_expiry_floor(1_008, 1, 144), HubConfig().ch2_expiry_blocks), (1_153, 1_153))


if __name__ == "__main__":
    unittest.main()
