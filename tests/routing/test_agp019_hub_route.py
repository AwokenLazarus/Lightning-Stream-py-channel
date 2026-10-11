"""AGP-019: a two-hop routed xbt402 payment, client -> hub -> provider, with adaptor-locked states.

Design: ~/notes/projects/xbt-agentpay/Research/AGP-019 xbt402 hub routing.md. Tests only; the
route model is tests/routing/route.py and the adaptor math tests/routing/adaptor.py.

Unit tests (no node): the lock is a plain state (so any increment, even sub-dust, works), the hub
pre-verifies before it signs anything, one lock per channel, a stuck lock is dominated by later
traffic, the expiry rule, and what one hop's crypto costs.

Regtest (Knots 29.4.2, RDTS + #419; ports XBT402_TEST_PORT_BASE + 50/51, datadir
run/agp019-<pid>, wiped after): two real P2WSH channels,
  1. one routed payment settled off-chain (nothing touches the chain until the channels close),
  2. the hub withholds: the provider closes ch2 with the completed state before its margin, the hub
     reads t from that close and closes ch1, the client reads its receipt from ch1's close,
  3. the provider never reveals: neither lock can be closed with, and the client pays nothing extra.
Run: XBT402_TEST_PORT_BASE=34700 python -m unittest discover -s tests/routing
"""
import os
import secrets
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.join(HERE, "..", "security"))

from sechelp import ROOT, RegtestNode, port_for  # noqa: E402

from xbt402 import ecc  # noqa: E402
from xbt402.channel import DUST, ChannelError, ChannelParams, channel_payee_secret  # noqa: E402
from xbt402.conditional import ConditionalParams  # noqa: E402
from xbt402.tx import SIGHASH_ALL_UNIFIED, Tx, segwit_address  # noqa: E402

import adaptor  # noqa: E402
from route import Hop, route_ok  # noqa: E402

NET = "bip122:" + "11" * 16
CLOSE_FEE = 600
N = adaptor.N


def keypair():
    s = secrets.randbelow(N - 1) + 1
    return s, ecc.pubkey(s)


def channel(net, payer_secret, pay_to_secret, expiry, capacity, txid=None, vout=0):
    """Params and the payee's per-channel secret for a channel payer -> payTo."""
    a_pub, pay_to = ecc.pubkey(payer_secret), ecc.pubkey(pay_to_secret)
    p = ChannelParams.derive(pay_to.hex(), a_pub.hex(), expiry, CLOSE_FEE, network=net)
    p.funding_txid, p.funding_vout, p.capacity = txid or os.urandom(32).hex(), vout, capacity
    return p, channel_payee_secret(net, pay_to_secret, a_pub, expiry, pay_to)


class Route:
    """client (a1) -> hub (payTo h) on ch1; hub (a2) -> provider (payTo q) on ch2."""

    def __init__(self, net=NET, expiry1=5000, expiry2=4000, cap1=100_000, cap2=200_000, fund=None):
        self.a1, self.h, self.a2, self.q = (keypair()[0] for _ in range(4))
        p1, s1 = channel(net, self.a1, self.h, expiry1, cap1)
        p2, s2 = channel(net, self.a2, self.q, expiry2, cap2)
        if fund:
            p1.funding_txid, p1.funding_vout = fund(p1)
            p2.funding_txid, p2.funding_vout = fund(p2)
        self.ch1, self.ch2 = Hop(p1, self.a1, s1), Hop(p2, self.a2, s2)

    def lock(self, d: int, fee: int):
        """One routed lock: provider invoice (t, T), client tweak r, ch1 then ch2."""
        self.t = secrets.randbelow(N - 1) + 1
        self.T = adaptor.point_of(self.t)
        self.r = secrets.randbelow(N - 1) + 1                      # client -> hub, with the lock
        self.T1 = adaptor.add(self.T, adaptor.point_of(self.r))
        cum1, pre1 = self.ch1.lock(d + fee, self.T1)             # client
        self.ch1.offer(cum1, pre1, self.T1, d + fee)             # hub pre-verifies ch1 first...
        cum2, pre2 = self.ch2.lock(d, self.T)                    # ...then pre-signs ch2
        self.ch2.offer(cum2, pre2, self.T, d)                    # provider
        return cum1, cum2

    def settle_off_chain(self):
        sig2 = self.ch2.complete(self.t)                         # provider: a plain state for cum2
        self.ch2.resolved(self.t)                                # hub gets t from the provider
        sig1 = self.ch1.complete((self.t + self.r) % N)          # hub: a plain state for cum1
        self.ch1.resolved((self.t + self.r) % N)                 # client gets t + r from the hub
        return sig1, sig2


class AdaptorLockUnit(unittest.TestCase):
    def test_completed_lock_is_a_plain_strict_der_state(self):
        rt = Route()
        rt.ch1.pay(2_000)
        rt.ch2.pay(1_500)
        cum1, cum2 = rt.lock(700, 7)
        self.assertEqual((cum1, cum2), (2_707, 2_200))
        sig1, sig2 = rt.settle_off_chain()
        for hop, cum, sig in ((rt.ch1, cum1, sig1), (rt.ch2, cum2, sig2)):
            self.assertEqual(sig[-1], SIGHASH_ALL_UNIFIED)
            self.assertTrue(ecc.is_strict_der(sig[:-1]))
            hop.payee.verify_state(cum, sig)                         # B1's own check, unchanged
            self.assertEqual((hop.payee.best_amount, hop.payer.signed), (cum, cum))
        # the client's receipt: t, recovered from t + r
        self.assertEqual(adaptor.point_of((rt.t + rt.r - rt.r) % N), rt.T)

    def test_sub_dust_increment_routes_where_a_hash_lock_cannot(self):
        rt = Route()
        rt.ch1.pay(DUST)
        rt.ch2.pay(DUST)
        cum1, cum2 = rt.lock(3, 1)                                  # a 3-sat chunk, 1-sat hub fee
        rt.settle_off_chain()
        self.assertEqual((rt.ch1.payee.best_amount, rt.ch2.payee.best_amount), (DUST + 4, DUST + 3))
        with self.assertRaises(ChannelError) as e:                   # the v1.1 hash lock needs an
            ConditionalParams(rt.ch2.params, os.urandom(32), 3)      # output of at least 546 sat
        self.assertEqual(e.exception.code, "bad_amount")

    def test_hub_signs_nothing_before_ch1_preverifies(self):
        rt = Route()
        rt.ch1.pay(2_000)
        t = secrets.randbelow(N - 1) + 1
        T = adaptor.point_of(t)
        wrong = adaptor.point_of(t + 1)
        cum1, pre1 = rt.ch1.lock(707, wrong)                      # client locks under another point
        with self.assertRaises(ChannelError) as e:
            rt.ch1.offer(cum1, pre1, T, 707)
        self.assertEqual(e.exception.code, "bad_adaptor")
        self.assertIsNone(rt.ch2.sent)                              # so the hub never pre-signs ch2
        with self.assertRaises(ChannelError) as e:                  # and an amount other than
            rt.ch1.offer(cum1, pre1, wrong, 700)                    # best + d + fee is refused
        self.assertEqual(e.exception.code, "bad_amount")

    def test_one_lock_per_channel_and_a_stuck_lock_is_dominated(self):
        rt = Route()
        rt.ch1.pay(2_000)
        rt.ch2.pay(1_500)
        rt.lock(700, 7)
        with self.assertRaises(ChannelError):                       # a second lock would sit on the
            rt.ch2.lock(100, adaptor.point_of(5))                  # first one's amount
        # the provider goes silent. The hub stops routing to it, and later traffic (other routes'
        # folds) is signed from the last plain state. Once a plain state reaches the stuck lock's
        # amount, the lock is worthless: a late completion is below the best state.
        stuck = rt.ch2.held
        rt.ch2.sent = None                                          # hub: written off after a timeout
        rt.ch2.held = None
        rt.ch2.pay(2_200)                                          # plain traffic reaches the lock
        rt.ch2.held = stuck
        with self.assertRaises(ChannelError) as e:
            rt.ch2.complete(rt.t)                                  # the provider reveals too late
        self.assertEqual(e.exception.code, "stale_amount")
        self.assertEqual(rt.ch2.payee.best_amount, 2_200)

    def test_on_chain_secret_extraction(self):
        rt = Route()
        rt.ch1.pay(2_000)
        rt.ch2.pay(1_500)
        rt.lock(700, 7)
        rt.ch2.complete(rt.t)                                       # the provider tells nobody
        close2 = rt.ch2.payee.close_tx()
        self.assertEqual(rt.ch2.secret_from_close(close2), rt.t)   # the hub reads it off the close
        rt.ch1.complete(rt.t + rt.r)
        close1 = rt.ch1.payee.close_tx()
        self.assertEqual((rt.ch1.secret_from_close(close1) - rt.r) % N, rt.t)
        # a plain close of another state reveals nothing
        rt2 = Route()
        rt2.ch2.pay(1_500)
        rt2.ch2.lock(10, rt.T)
        self.assertIsNone(rt2.ch2.secret_from_close(rt2.ch2.payee.close_tx()))

    def test_expiry_rule(self):
        # ch2 must end (margin included) before ch1's margin, with delta blocks for the hub
        self.assertTrue(route_ok(tip=1_000, in_expiry=3_000, out_expiry=2_500, close_margin=144, delta=144))
        self.assertFalse(route_ok(tip=1_000, in_expiry=2_700, out_expiry=2_500, close_margin=144, delta=144))
        self.assertFalse(route_ok(tip=2_400, in_expiry=9_000, out_expiry=2_500, close_margin=144, delta=144))
        # the usual hub topology (a long-lived hub->provider channel) fails the rule for a
        # shorter client channel: see the note, "Timeouts"
        self.assertFalse(route_ok(tip=1_000, in_expiry=1_000 + 1_014, out_expiry=1_000 + 8_000,
                                  close_margin=144, delta=144))

    def test_cost_of_one_routed_lock(self):
        rt = Route()
        rt.ch1.pay(2_000)
        rt.ch2.pay(1_500)
        n, t0 = 5, time.perf_counter()
        for _ in range(n):
            rt.lock(700, 7)
            rt.settle_off_chain()
        ms = (time.perf_counter() - t0) * 1000 / n
        sys.stderr.write(f"\n    one routed lock (2 presign + 2 preverify + 2 adapt + 2 verify), pure-Python "
                         f"adaptor, ecc backend {ecc.BACKEND}: {ms:.0f} ms ")
        self.assertLess(ms, 5_000)


BIN = os.environ.get("XBT_BIN", os.path.expanduser("~/lazarus-regtest/b1-xbt402/knots-29.4.2"))
DD = os.path.join(ROOT, "run", f"agp019-{os.getpid()}")
SAT = 100_000_000
MARGIN = 5


@unittest.skipUnless(os.path.exists(os.path.join(BIN, "bitcoind")), "Knots 29.4.2 binary not installed")
class HubRouteRegtest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regtest = RegtestNode(BIN, DD, port_for("agp019_rpc"), port_for("agp019_p2p"),
                                  XBT402_BLOCKS="300", XBT402_MATURITY_PAD="6800")
        cls.node = cls.regtest.start(cls)
        cls.w = cls.node.wallet("w")
        from xbt402.x402_channel import network_id
        cls.net = network_id(cls.node.getblockhash(101))

    def mine(self, n=1):
        return self.node.generatetoaddress(n, self.w.getnewaddress())

    def fund(self, p):
        txid = self.w.sendtoaddress(segwit_address("bcrt", p.spk), p.capacity / SAT)
        raw = self.node.getrawtransaction(txid, True)
        return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"]["hex"] == p.spk.hex())

    def route(self, in_blocks, out_blocks):
        tip = self.node.getblockcount()
        rt = Route(self.net, tip + in_blocks, tip + out_blocks, fund=self.fund)
        self.mine()
        self.assertTrue(route_ok(self.node.getblockcount(), rt.ch1.params.expiry, rt.ch2.params.expiry,
                                 MARGIN, delta=10))
        rt.ch1.pay(2_000)                                         # earlier traffic on both hops
        rt.ch2.pay(1_500)
        return rt

    def accepts(self, tx):
        return self.node.testmempoolaccept([tx.hex()])[0]

    def unspent(self, p):
        return self.node.gettxout(p.funding_txid, p.funding_vout, True) is not None

    def paid(self, txid, p):
        tx = self.node.getrawtransaction(txid, True)
        self.assertGreaterEqual(tx.get("confirmations", 0), 1)
        return [round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == p.payee_spk]

    def test_1_routed_payment_settles_off_chain(self):
        rt = self.route(80, 40)
        cum1, cum2 = rt.lock(700, 7)
        rt.settle_off_chain()
        # settled: both payees hold a closable state for the routed amount, nothing was broadcast
        self.assertTrue(self.unspent(rt.ch1.params) and self.unspent(rt.ch2.params))
        for hop in (rt.ch1, rt.ch2):
            r = self.accepts(hop.payee.close_tx())
            self.assertTrue(r["allowed"], r)
        # the channels go on: later plain payments on top, then the ordinary closes pay exactly
        rt.ch1.pay(cum1 + 505)
        rt.ch2.pay(cum2 + 500)
        c2 = self.node.sendrawtransaction(rt.ch2.payee.close_tx().hex())
        c1 = self.node.sendrawtransaction(rt.ch1.payee.close_tx().hex())
        self.mine()
        self.assertEqual(self.paid(c1, rt.ch1.params), [2_000 + 707 + 505])
        self.assertEqual(self.paid(c2, rt.ch2.params), [1_500 + 700 + 500])

    def test_2_hub_withholds_provider_closes_and_everyone_is_paid(self):
        rt = self.route(80, 40)
        cum1, cum2 = rt.lock(700, 7)
        rt.ch2.complete(rt.t)
        # the provider sends t; the hub takes it and goes silent: no receipt to the client, no more
        # ch2 states, and it plans to refund ch2 at expiry. The provider closes at its margin.
        self.mine(rt.ch2.params.expiry - MARGIN - self.node.getblockcount())
        close2 = rt.ch2.payee.close_tx()
        self.node.sendrawtransaction(close2.hex())
        self.mine()
        self.assertEqual(self.paid(close2.txid(), rt.ch2.params), [cum2])
        # the hub's refund of ch2 can never confirm now
        self.mine(rt.ch2.params.expiry - self.node.getblockcount())
        refund = rt.ch2.params.refund_tx(rt.a2)
        r = self.accepts(refund)
        self.assertFalse(r["allowed"])
        self.assertIn("missing", r.get("reject-reason", ""))
        # whoever holds the hub's pre-signature (the hub after a restart, here) reads t from the
        # chain, and the hub gets its routed amount back from ch1 with t + r
        onchain = Tx.parse(bytes.fromhex(self.node.getrawtransaction(close2.txid(), False)))
        t = rt.ch2.secret_from_close(onchain)
        self.assertEqual(t, rt.t)
        rt.ch1.complete((t + rt.r) % N)
        close1 = rt.ch1.payee.close_tx()
        self.node.sendrawtransaction(close1.hex())
        self.mine()
        self.assertEqual(self.paid(close1.txid(), rt.ch1.params), [cum1])
        # the client never heard from the hub; its receipt is on-chain
        got = Tx.parse(bytes.fromhex(self.node.getrawtransaction(close1.txid(), False)))
        self.assertEqual(adaptor.point_of((rt.ch1.secret_from_close(got) - rt.r) % N), rt.T)

    def test_3_provider_never_reveals_nobody_pays_the_lock(self):
        rt = self.route(80, 40)
        rt.lock(700, 7)
        # without t neither lock is a signature: a close with the raw pre-signature is refused
        for hop in (rt.ch1, rt.ch2):
            cum, pre, _ = hop.held
            tx = hop.params.state_tx(cum)
            mine = ecc.sign(hop.payee.secret, hop.params.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
            tx.inputs[0].witness = [pre.bogus_der() + bytes([SIGHASH_ALL_UNIFIED]), mine, b"\x01",
                                    hop.params.script]
            r = self.accepts(tx)
            self.assertFalse(r["allowed"])
            self.assertIn("script-verify", r.get("reject-reason", ""))
        # the hub closes ch1 with its last plain state: the client paid nothing for the lock
        close1 = rt.ch1.payee.close_tx()
        self.node.sendrawtransaction(close1.hex())
        self.mine()
        self.assertEqual(self.paid(close1.txid(), rt.ch1.params), [2_000])


if __name__ == "__main__":
    unittest.main()
