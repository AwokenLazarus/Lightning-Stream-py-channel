"""M8 (Medium) a close the node accepted but the provider never recorded: the hash-lock claim is lost.

`_close_locked` recorded the close (its txid, its hex, whether it is the conditional one) only after
`sendrawtransaction` returned, and saved it afterwards. If the RPC answer is lost (a timeout after
the node accepted), or the provider dies between the broadcast and the save, the ledger says "not
closed". Once that close confirms, every retry is refused ("outputs already in utxo set"), so the
channel is stuck in close_failed forever and, for a conditional close, the claim is never sent: after
csvDelta blocks the payer's branch of the hash lock opens and takes condAmount. The ledger's own
promise is that a crash never loses what was paid.

Fix: write-ahead. The close is built, its txid computed locally and the intent (hex, txid,
conditional) saved before the broadcast. A failed broadcast whose transaction the node already knows
counts as sent, and the watcher adopts a recorded intent it finds on-chain or in the mempool, then
claims as usual.
"""
import unittest

from condhelp import ORIGIN, Rig, spends
from sechelp import V11, FakeNode, Repro, load, v11
from xbt402.tx import Tx
from sechelp import crashed


class LossyNode(FakeNode):
    """Accepts a transaction and then loses the answer (`timeouts`), and refuses a re-send of a
    transaction that already confirmed, as bitcoind does."""

    def __init__(self):
        super().__init__()
        self.timeouts = 0

    def sendrawtransaction(self, hx):
        txid = Tx.parse(bytes.fromhex(hx)).txid()
        if self.txs.get(txid, {}).get("confirmations", 0) > 0:
            raise RuntimeError("Transaction outputs already in utxo set")
        txid = super().sendrawtransaction(hx)
        if self.timeouts:
            self.timeouts -= 1
            raise TimeoutError("timed out")
        return txid

    def confirm_all(self):
        for t in self.txs.values():
            t["confirmations"] = max(1, t["confirmations"])


def conditional_open(xm):
    r = Rig(xm, node=LossyNode())
    r.client.request("GET", ORIGIN + "/v1/x")
    r.fold = False
    r.client.request_conditional("GET", ORIGIN + "/v1/cond")
    return r


def claimed(r):
    closes = [Tx.parse(bytes.fromhex(hx)).txid() for hx in r.node.sent
              if spends(hx, r.chan.params.funding_txid)]
    return bool(closes) and any(spends(hx, closes[0]) for hx in r.node.sent)


def restart(xm, r):
    crashed(r.prov)
    return xm.XbtChannelProvider(r.node, 0xB0B, r.prov.network, r.prov.ledger.path, lambda m, p: 150,
                                 lambda m, p, b: (200, {}, b"ok"))


class CloseWriteAhead(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_lost_rpc_answer_loses_the_claim(self):
        r = conditional_open(v11("x402_channel"))
        r.node.timeouts = 1
        r.close_at_margin()                               # the node took the close, the answer was lost
        r.node.confirm_all()
        for _ in range(3):
            r.prov.close_due()
        self.reproduces(not r.chan.closed_txid and not claimed(r) and "already in utxo" in r.chan.close_error,
                        f"close confirmed but never recorded; claim never sent; watcher stuck: {r.chan.close_error}")

    def test_repro_crash_after_broadcast_loses_the_claim(self):
        xm = v11("x402_channel")
        r = conditional_open(xm)
        real = r.node.sendrawtransaction

        def crash_after(hx):                              # the process dies right after the broadcast
            real(hx)
            r.prov.ledger.save = lambda *a: (_ for _ in ()).throw(SystemExit("killed"))
            raise SystemExit("killed")
        r.node.sendrawtransaction = crash_after
        try:
            r.close_at_margin()
        except SystemExit:
            pass
        r.node.sendrawtransaction = real
        r.node.confirm_all()
        prov2 = restart(xm, r)
        for _ in range(3):
            prov2.close_due()
        st = next(iter(prov2.ledger.channels.values()))
        self.reproduces(not st.closed_txid and not claimed(r),
                        f"after the restart the ledger has no close; claim never sent: {st.close_error}")

    def test_fixed_lost_rpc_answer(self):
        r = conditional_open(load("x402_channel"))
        r.node.timeouts = 1
        r.close_at_margin()
        r.node.confirm_all()
        r.prov.close_due()
        self.assertTrue(r.chan.closed_txid)
        self.assertTrue(r.chan.extra["cond_close"])
        self.assertTrue(claimed(r))
        self.assertEqual(r.chan.close_error, "")

    def test_fixed_crash_after_broadcast(self):
        xm = load("x402_channel")
        r = conditional_open(xm)
        real = r.node.sendrawtransaction

        def crash_after(hx):
            real(hx)
            r.prov.ledger.save = lambda *a: (_ for _ in ()).throw(SystemExit("killed"))
            raise SystemExit("killed")
        r.node.sendrawtransaction = crash_after
        try:
            r.close_at_margin()
        except SystemExit:
            pass
        r.node.sendrawtransaction = real
        r.node.confirm_all()
        prov2 = restart(xm, r)
        prov2.close_due()
        st = next(iter(prov2.ledger.channels.values()))
        self.assertTrue(st.closed_txid)
        self.assertTrue(claimed(r))

    def test_control_refused_close_stays_open_for_a_better_state(self):
        """A close the node refuses is not adopted: the next tick builds it again (maybe higher)."""
        r = conditional_open(load("x402_channel"))
        r.node.fail = {"": "min relay fee not met"}          # every broadcast refused
        r.close_at_margin()
        self.assertEqual(r.chan.closed_txid, "")
        self.assertIn("close_failed", r.chan.close_error)
        r.node.fail = {}
        r.prov.close_due()
        self.assertTrue(r.chan.closed_txid)
        self.assertTrue(claimed(r))


if __name__ == "__main__":
    unittest.main()
