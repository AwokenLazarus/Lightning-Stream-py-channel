"""AGP-059: the public surface for embedders (cmp CMP-051), and the reservation crash window.

1. Crash window. A direct call's max-price reservation was saved before the handler and its refund only
   after the charge. A provider that died between the two restarted with `spent_msat` above what it had
   billed, and a payer that signs its own meter (cmp) got 402 `insufficient_payment` on every later
   call of the channel; cmp repaired b1's private ledger at start (`reconcile_direct`).
   Fix: a metered call's reservation is recorded in its row (`extra.resv`), its settlement is always
   saved before the answer leaves, and a provider start refunds what is still recorded
   (`recovered_reservations`). A handler that raises refunds its reservation too. An unmetered call's
   reservation is its exact charge, as before (one save per call).
2. Client: the embedder's own request headers and a caller-chosen cumulative amount, bounded.
3. Provider: `close_channel(chan)`, the margin close's path for one named channel, with its refusals.
"""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode, Repro, base  # noqa: E402

import xbt402.x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402
from xbt402.tx import Tx, address_to_spk  # noqa: E402

ORIGIN = "http://prov.test"
NET = "bip122:" + "11" * 16
AGP056 = "3b2d009"      # b1 before this task


def snapshot(path: str, snap: str):
    """The ledger files as a crash at this moment leaves them."""
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(path + ext):
            shutil.copy(path + ext, snap + ext)


class Rig:
    """A provider and the reference client over serve() and a fake node. `/crash` snapshots the ledger
    while its handler runs; `/boom` raises in the handler. `sent` holds every request's headers."""

    def __init__(self, xm=xc, price=1_000, charge=400, ledger=None, node=None, **client_kw):
        self.xm, self.node = xm, node or FakeNode()
        self.dir = tempfile.mkdtemp(prefix="agp059-")
        self.path = ledger or os.path.join(self.dir, "ledger.sqlite")
        self.snap = os.path.join(self.dir, "crashed.sqlite")
        self.sent, self.in_handler = [], None

        def handler(method, path, body):
            if path.startswith("/crash"):
                snapshot(self.path, self.snap)
            if path.startswith("/boom"):
                raise RuntimeError("handler failed")
            if self.in_handler:
                self.in_handler()
            return 200, {}, b"ok"
        self.prov = xm.XbtChannelProvider(self.node, 0xB0B, NET, self.path, lambda m, p: price, handler,
                                          charge=(lambda m, p, st, out: charge) if charge is not None else None)

        def fund(addr, sats):
            txid = os.urandom(32).hex()
            self.node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                                   "vout": [{"n": 0, "value": sats / 1e8,
                                             "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
            return txid, 0
        self.cl = xm.XbtChannelClient(NET, fund, self.node.getblockcount, **client_kw)
        self.cl.http = self.http

    def http(self, method, url, body=b"", headers=None):
        self.sent.append(dict(headers or {}))
        st, h, out = self.prov.serve(method, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)
        return st, {k.upper(): v for k, v in h.items()}, out

    def call(self, path="/v1/x", origin=ORIGIN, **kw):
        return self.cl.request("GET", origin + path, **kw)[0]

    def restart(self, ledger=None, **kw):
        """A new provider process on `ledger` (this one's by default), the same payer."""
        r = Rig(self.xm, ledger=ledger or self.path, node=self.node, **kw)
        r.cl.channels = self.cl.channels
        return r

    @property
    def ch(self):
        return self.cl.channels[ORIGIN]

    @property
    def st(self):
        return self.prov.ledger.channels[self.ch.payer.params.channel_id]


def crashed_in_call_two(xm):
    """Call 1 is billed 400 of its 1,000 sat price; the provider dies while call 2's handler runs.
    Returns the rig restarted from the disk the crash left, with the payer as it was left: call 2
    sent (its seq spent, its state signed), never answered."""
    r = Rig(xm)
    assert r.call() == 200 and r.st.spent_msat == 400_000
    assert r.call("/crash") == 200
    r.ch.seq, r.ch.spent_msat, r.ch.receipts = 2, 400_000, r.ch.receipts[:1]
    return r.restart(ledger=r.snap)


class ReservationCrashWindow(Repro, unittest.TestCase):
    REPRO_BASE = AGP056

    def test_repro_a_crash_mid_call_leaves_the_reservation_charged(self):
        r = crashed_in_call_two(base("x402_channel", AGP056, "xbt402agp056"))
        self.reproduces(r.st.spent_msat == 1_400_000,
                        f"400 sat billed, spent_msat {r.st.spent_msat} after the restart")
        # a payer that signs what it was billed (cmp's meter) is refused from here on
        paid = r.st.best_cum * 1000
        self.reproduces(paid < r.st.spent_msat, f"paid {paid} msat < spent {r.st.spent_msat}: insufficient_payment")

    def test_fixed_after_a_restart_spent_is_what_was_charged(self):
        r = crashed_in_call_two(xc)
        chan = r.ch.payer.params.channel_id
        self.assertEqual(r.prov.recovered_reservations, [(chan, 1_000_000)])
        self.assertEqual((r.st.seq, r.st.spent_msat, r.st.extra.get("resv")), (2, 400_000, None))
        # the refund is on disk: another restart has nothing to recover
        r2 = r.restart()
        self.assertEqual((r2.prov.recovered_reservations, r2.st.spent_msat), ([], 400_000))
        # the payer's next call is served by one request, no 402, and spent = charged
        self.assertEqual((r2.call(), len(r2.sent)), (200, 1))
        self.assertEqual((r2.st.spent_msat, r2.ch.receipts[-1]["spentMsat"]), (800_000, "800000"))

    def test_fixed_the_disk_at_the_crash_records_the_reservation(self):
        r = Rig()
        r.call()
        r.call("/crash")
        self.assertEqual((r.st.spent_msat, r.st.extra.get("resv")), (800_000, None))    # settled in the live process
        led = xc.Ledger(r.snap)
        st = led.channels[r.ch.payer.params.channel_id]
        self.assertEqual((st.spent_msat, st.extra["resv"]), (1_400_000, {"2": 1_000_000}))

    def test_fixed_an_unmetered_call_in_flight_is_charged_once_at_its_price(self):
        r = Rig(price=150, charge=None)
        r.call()
        r.call("/crash")
        r2 = r.restart(ledger=r.snap, price=150, charge=None)
        self.assertEqual((r2.prov.recovered_reservations, r2.st.spent_msat), ([], 300_000))

    def test_fixed_a_handler_that_raises_refunds_its_reservation(self):
        for charge in (400, None):
            r = Rig(charge=charge)
            r.call()
            spent = r.st.spent_msat
            with self.assertRaises(RuntimeError):
                r.call("/boom")
            self.assertEqual((r.st.spent_msat, r.st.extra.get("resv"), r.prov._in_call), (spent, None, {}))
            r2 = r.restart(charge=charge)          # and on disk
            self.assertEqual((r2.prov.recovered_reservations, r2.st.spent_msat), ([], spent))

    def test_control_a_metered_call_at_full_price_and_a_failed_one(self):
        r = Rig(charge=1_000)
        r.call()
        self.assertEqual((r.st.spent_msat, r.st.extra.get("resv")), (1_000_000, None))
        r2 = r.restart(charge=1_000)               # charged == price is saved too: nothing to refund
        self.assertEqual((r2.prov.recovered_reservations, r2.st.spent_msat), ([], 1_000_000))


class ClientHeadersAndCum(unittest.TestCase):
    def test_extra_headers_go_with_every_request_of_a_call(self):
        r = Rig(price=150, charge=None)
        mine = {"X-CMP-Payer": "me"}
        self.assertEqual(r.call(headers=mine), 200)
        self.assertEqual(r.call(headers=mine), 200)
        calls = [h for h in r.sent if "X-CMP-Payer" in h]
        # the unpaid try, its paid retry and the next paid call (the open is the client's own request)
        self.assertEqual([("PAYMENT-SIGNATURE" in h, h["X-CMP-Payer"]) for h in calls],
                         [(False, "me"), (True, "me"), (True, "me")])
        # a lost answer: the provider's 402 carries its view of the channel, and the paid retry the headers
        for _ in range(3):
            r.call(headers=mine)
        r.ch.spent_msat, r.ch.receipts = 600_000, r.ch.receipts[:4]      # the fifth call's answer never came
        del r.sent[:]
        self.assertEqual(r.call(headers=mine), 200)
        self.assertEqual([("PAYMENT-SIGNATURE" in h, h["X-CMP-Payer"]) for h in r.sent], [(True, "me"), (True, "me")])
        self.assertEqual(r.ch.slack_msat, 150_000)
        n = len(r.sent)
        for bad in ({"payment-signature": "x"}, {"X-A": "a\r\nX-B: b"}, {"": "x"}, {"X\nY": "x"}, {"X-N": 1}):
            with self.assertRaises(ChannelError) as e:
                r.call(headers=bad)
            self.assertEqual(e.exception.code, "bad_header")
        self.assertEqual(len(r.sent), n, "nothing was sent")

    def refused(self, r, cum, code):
        state = (r.ch.payer.signed, r.ch.seq)
        for act in (lambda: r.call(cum=cum), lambda: r.cl.close(ORIGIN, cum=cum)):
            with self.assertRaises(ChannelError) as e:
                act()
            self.assertEqual(e.exception.code, code, f"cum {cum}")
        self.assertEqual((r.ch.payer.signed, r.ch.seq), state, "nothing signed, no seq spent")

    def test_a_caller_chosen_cum_is_bounded(self):
        r = Rig(price=600, charge=None)
        # under the channel's minimum state nothing is signed: never rounded up to it
        self.assertEqual(r.call(cum=100), 200)
        self.assertEqual((r.ch.payer.signed, r.st.best_cum), (0, 0))
        # the caller's amount is the state signed, not the client's own ceil(spent) = 600
        self.assertEqual(r.call(cum=700), 200)
        self.assertEqual((r.ch.payer.signed, r.st.best_cum, r.ch.spent_msat), (700, 700, 1_200_000))
        self.refused(r, 699, "bad_amount")                                  # below the last signed state
        self.refused(r, r.ch.payer.params.max_amount + 1, "exhausted")      # above the channel's capacity
        self.refused(r, 1_801, "too_expensive")                             # above receipts (1200) + one call (600)
        for bad in (-1, True, "700", 7.0):
            self.refused(r, bad, "bad_amount")
        # the bound itself is allowed, and the daily budget still counts what a chosen cum signs
        r.cl.daily_budget, r.cl.day_spent = 1_000, 0
        self.assertEqual(r.call(cum=1_700), 200)
        self.assertEqual((r.ch.payer.signed, r.cl.day_spent), (1_700, 1_000))
        with self.assertRaises(ChannelError) as e:
            r.call(cum=1_701)
        self.assertEqual(e.exception.code, "budget")
        r.cl.daily_budget = 0
        # a close at the caller's amount settles exactly it
        out = r.cl.close(ORIGIN, cum=1_900)
        self.assertEqual((out["cum"], out["unpaidMsat"]), ("1900", "0"))
        close = Tx.parse(bytes.fromhex(r.node.sent[-1]))
        self.assertEqual(sum(o.value for o in close.outputs if o.script_pubkey.hex() == r.ch.payer.params.payee_spk), 1_900)


class CloseOneChannel(unittest.TestCase):
    def code(self, r, chan):
        with self.assertRaises(ChannelError) as e:
            r.prov.close_channel(chan)
        return e.exception.code

    def test_close_channel_and_its_refusals(self):
        r = Rig(price=150, charge=None)
        for _ in range(5):
            r.call()
        chan, st = r.ch.payer.params.channel_id, r.st
        self.assertEqual(st.best_cum, 600)
        # a second channel that stays open, with nothing signed yet
        other = "http://other.test"
        r.call(origin=other)
        chan2 = r.cl.channels[other].payer.params.channel_id
        self.assertEqual(self.code(r, chan2), "no_state")
        self.assertEqual(self.code(r, "00" * 32 + ":0"), "unknown_channel")
        # a routed lock open on it; a hub-funded ch2
        st.extra = {**st.extra, "route_lock": {"lockId": "l1"}}
        self.assertEqual(self.code(r, chan), "lock_pending")
        st.extra = {**st.extra, "route_lock": None, "stale_locks": [{"lockId": "l0"}]}
        self.assertEqual(self.code(r, chan), "lock_pending")
        st.extra = {"hub": "02ab"}
        self.assertEqual(self.code(r, chan), "hub_channel")
        st.extra = {}
        # a call being served on it
        seen = []
        r.in_handler = lambda: seen.append(self.code(r, chan))
        r.call()
        r.in_handler = None
        self.assertEqual(seen, ["call_in_flight"])
        self.assertEqual((st.closed_txid, r.node.sent), ("", []), "a refusal changes nothing")
        # the close pays the provider the best signed state, by the margin close's path
        out = r.prov.close_channel(chan)
        self.assertEqual(list(out), ["chan", "txid", "cum", "unpaidMsat"])
        self.assertEqual((out["cum"], out["unpaidMsat"]), ("750", "150000"))
        close = Tx.parse(bytes.fromhex(r.node.sent[-1]))
        paid = sum(o.value for o in close.outputs if o.script_pubkey.hex() == st.params.payee_spk)
        self.assertEqual((close.txid(), paid, st.extra["close_hex"]), (out["txid"], 750, r.node.sent[-1]))
        self.assertEqual(self.code(r, chan), "channel_closed")
        self.assertEqual(len(r.node.sent), 1)
        self.assertEqual(r.prov.ledger.channels[chan2].closed_txid, "", "only the named channel")
        self.assertEqual(r.prov.close_due(), [])       # the watcher has nothing left to do for it

    def test_close_channel_adopts_a_close_it_sent_and_never_recorded(self):
        r = Rig(price=150, charge=None)
        for _ in range(5):
            r.call()
        real = r.node.sendrawtransaction

        def lost_answer(hx):
            real(hx)
            raise TimeoutError("timed out")
        r.node.sendrawtransaction, r.prov._tx_known = lost_answer, lambda txid, tx: False
        self.assertEqual(self.code(r, r.ch.payer.params.channel_id), "close_failed")
        del r.prov._tx_known
        r.node.sendrawtransaction = real
        out = r.prov.close_channel(r.ch.payer.params.channel_id)
        self.assertEqual((out["txid"], len(r.node.sent)), (r.st.closed_txid, 1))


if __name__ == "__main__":
    unittest.main()
