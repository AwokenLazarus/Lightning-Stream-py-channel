"""AGP-021 on a real chain (Knots 29.4.2 regtest, RDTS + #419; ports XBT402_TEST_PORT_BASE + 12/13,
datadir run/agp021-<pid>, wiped after). Hub, provider and client run in process over a fake HTTP
transport (tests/security/routehelp.py) against the real node:
  1. routed locks settle; the hub rolls ch2 over at the provider's net threshold (confirmed, pays the
     provider exactly its balance less its own close fee: ch2 is payee-pays, AGP-023), opens the next ch2, routes on; every close pays its ledger.
  2. the provider's answers never reach the hub: the hub writes the lock off; the provider closes ch2
     with the completed state; the hub's watcher finds that close in a block (no txindex, no mempool),
     reads t and completes ch1; the hub closes ch1; the client reads t + r off that close.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "security"))

from sechelp import ROOT, RegtestNode, port_for  # noqa: E402

import routehelp as R  # noqa: E402
from xbt402 import adaptor  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, ROUTE_LOCK_PATH  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

BIN = os.environ.get("XBT_BIN", "$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2")
DD = os.path.join(ROOT, "run", f"agp021-{os.getpid()}")
SAT = 100_000_000


class Node:
    """The real node with the wallet hooks the harness expects."""

    def __init__(self, rpc):
        self.rpc, self.w = rpc, rpc.wallet("w")
        self.addr = self.w.getnewaddress()

    def __getattr__(self, name):
        return getattr(self.rpc, name)

    @property
    def height(self):
        return self.rpc.getblockcount()

    def mine(self, n=1):
        self.rpc.generatetoaddress(n, self.addr)

    def fund_address(self, address, sats):
        txid = self.w.sendtoaddress(address, sats / SAT)
        raw = self.rpc.getrawtransaction(txid, True)
        vout = next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)
        self.mine()
        return txid, vout

    def confirm_all(self):
        self.mine()

    def paid(self, txid, spk):
        tx = self.rpc.getrawtransaction(txid, True)
        self.tc.assertGreaterEqual(tx.get("confirmations", 0), 1)
        return sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == spk)


@unittest.skipUnless(os.path.exists(os.path.join(BIN, "bitcoind")), "Knots 29.4.2 binary not installed")
class RoutedRegtest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regtest = RegtestNode(BIN, DD, port_for("agp021_rpc"), port_for("agp021_p2p"),
                                  XBT402_BLOCKS="300", XBT402_MATURITY_PAD="6800")
        cls.node = Node(cls.regtest.start(cls))
        R.NET = network_id(cls.node.getblockhash(101))

    def world(self, **pkw):
        node, net = self.node, R.Net()
        node.tc = self
        h = R.hub(node, net, secret=int.from_bytes(os.urandom(16), "big"))
        prov = R.provider(node, net, "http://p.test", **pkw)
        h.connect("http://p.test", capacity=30_000)
        h.watch_tick()
        self.assertEqual(h.out.chans["http://p.test"].state, "open")
        pay = R.payer(node, net)
        pay.open()
        return net, h, prov, pay, pay.shard("http://p.test/v1/chunk")

    def test_1_locks_rollover_and_closes_on_chain(self):
        net, h, prov, pay, sh = self.world(settle_multiple=2, amsat_per_call=40 * AMSAT_PER_SAT)
        R.stream(pay, sh, 30)
        self.assertEqual(pay.lock(sh)["status"], "paid")
        oc = h.out.chans["http://p.test"]
        # ch2 is payee-pays (AGP-023): 1,200 sat routed nets the provider 600, under its 2 x 600 threshold
        self.assertFalse(any(a.get("event") == "ch2_rollover" for a in h.watch_tick()))
        R.stream(pay, sh, 20)                                       # 2,000 routed: net 1,400 >= 1,200
        self.assertEqual(pay.lock(sh)["status"], "paid")
        roll = next(a for a in h.watch_tick() if a.get("event") == "ch2_rollover")
        self.node.mine()
        # the provider pays its own close fee; the next ch2 carries every sat the hub did not route
        self.assertEqual(self.node.paid(roll["txid"], oc.params["payee_spk"]), roll["amount"] - oc.p().close_fee)
        self.assertEqual(roll["nextCapacity"], oc.p().capacity - roll["amount"])
        h.watch_tick()
        new = h.out.chans["http://p.test"]
        self.assertEqual(new.state, "open")
        R.stream(pay, sh, 5)
        self.assertEqual(pay.lock(sh)["status"], "paid")
        c1 = pay.close()
        c2 = h.close_ch2(new)
        self.node.mine()
        st1 = h.inbound.ledger.channels[pay.chan]
        st2 = next(s for s in prov.ledger.channels.values() if s.closed_txid == c2["txid"])
        self.assertEqual(self.node.paid(c1["txid"], st1.params.payee_spk), st1.best_cum)
        self.assertEqual(self.node.paid(c2["txid"], st2.params.payee_spk), st2.best_cum - st2.params.close_fee)
        self.assertEqual(st1.best_cum, max(546, pay.routed))

    def test_2_secret_read_off_a_mined_ch2_close_after_a_write_off(self):
        net, h, prov, pay, sh = self.world()
        R.stream(pay, sh, 10)
        net.drop["http://p.test"] = lambda m, p: p == ROUTE_LOCK_PATH
        h.reveal_timeout = 0.3
        pay.signer.void_lock = lambda chan: {}                     # keep it: recovered from ch1's close below
        self.assertEqual(pay.lock(sh)["status"], "refused")
        lk = pay.signer.pending_lock(pay.chan)
        st2 = next(iter(prov.ledger.channels.values()))
        with prov.ledger.lock:
            prov._close_locked(st2)
        self.node.mine()                                           # in a block: the watcher scans blocks
        acts = h.watch_tick()
        self.assertTrue(any(a["event"] == "secret_from_close" and a["ch1_completed"] for a in acts), acts)
        st1 = h.inbound.ledger.channels[pay.chan]
        self.assertEqual(st1.best_cum, lk["cum"])
        with h.inbound.ledger.lock:
            close1 = h.inbound._close_locked(st1)
        self.node.mine()
        tx = Tx.parse(bytes.fromhex(self.node.getrawtransaction(close1, False)))
        t = pay.signer.recover_lock(pay.chan, tx)
        self.assertEqual(adaptor.enc(adaptor.point_of(int(t, 16))).hex(), lk["T"])
        self.assertEqual(self.node.paid(close1, st1.params.payee_spk), lk["cum"])


    def test_3_hub_runs_as_a_service_from_a_config_file(self):
        import json
        import tempfile
        import threading
        from xbt402.hub import main
        from xbt402.x402_channel import XbtChannelClient, unb64json
        d = tempfile.mkdtemp(prefix="hubsvc-")
        key = os.path.join(d, "payto.key")
        with open(key, "w") as f:
            f.write(os.urandom(31).hex())
        port = port_for("agp021_hub")
        conf = {"node": {"rpcport": port_for("agp021_rpc"), "cookie": os.path.join(DD, "regtest", ".cookie"),
                         "wallet": "w"},
                "network": R.NET, "port": port, "datadir": os.path.join(d, "hub"), "pay_to_key_file": key,
                "hub": {"fee_ppm": 1_500, "liquidity_cap_sat": 300_000,
                        "fee_strategy": {"kind": "utilization", "ppm_min": 1_000, "ppm_max": 4_000}},
                "watch_interval": 1}
        with open(os.path.join(d, "hub.json"), "w") as f:
            json.dump(conf, f)
        hub, srv, stop = main(["--config", os.path.join(d, "hub.json")], serve=False)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            st, h, _ = XbtChannelClient.http("GET", f"http://127.0.0.1:{port}/x402/route")
            self.assertEqual(st, 402)
            routing = unb64json(h["PAYMENT-REQUIRED"])["accepts"][0]["extra"]["routing"]
            self.assertEqual((routing["feePpm"], routing["quote"]["hub"]), (1_000, hub.pay_to))
            self.assertEqual(hub.liquidity_cap_sat, 300_000)
        finally:
            srv.shutdown()
            stop.set()


if __name__ == "__main__":
    unittest.main()
