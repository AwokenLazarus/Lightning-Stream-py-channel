"""AGP-102 fourth closure audit, area HUB (the hub and the routed client): tests written by the
auditor on the harness of test_agp093_hub.py (W) and routehelp (world). Nothing here is a fix.

Tests named after a rule fail today (each is a hole of the audit's list 1); `control_` tests pass.
xbt-rs has the same tests under the same names (crates/xbt402-interop/tests/agp102_hub.rs and
crates/xbt402/tests/agp102_route_client.rs).
"""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp064_hub_safety as T  # noqa: E402
import test_agp084_hub_leftovers as L  # noqa: E402
import test_agp088_hub as H  # noqa: E402
import test_agp093_hub as A  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.hub import HubConfig  # noqa: E402
from xbt402.route import RouteOffer  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402

P0 = "http://p0.test"


def count_getblock(node):
    """Count the node's `getblock` calls (each is one full block read by route.find_spend_at)."""
    seen, real = [], node.getblock

    def getblock(blockhash, verbosity=1):
        seen.append(int(blockhash, 16))
        return real(blockhash, verbosity)
    node.getblock = getblock
    return seen


class WaitingForDepth(unittest.TestCase):
    """Part B, spend_final_depth: what waiting for depth costs on every tick.

    A ch2 record keeps `scanned_to` at the tip of the day it was funded (hub.py: nothing moves it).
    `_reconcile` asks find_spend_at(funding, scanned_to) on every tick while the record is not final,
    and a spender in a block is answered by reading every block from `scanned_to` to the spender's
    with getblock(hash, 2) (route.py:945-951). Before AGP-094 a spend was final in its first block, so
    this was one pass. Now the record waits spend_final_depth (6) blocks, and at a 5 s tick that is
    about 600 ticks, each a full pass."""

    def test_the_watcher_reads_the_chain_once_for_a_spend_that_waits_for_depth(self):
        # HOLE (Low, new in wave 5; B1 and xbt-rs).
        self.assertEqual(HubConfig().spend_final_depth, 6)
        w = A.W([None], hkw={"spend_final_depth": 6})
        w.paid(0)
        funded_at = w.oc(0).scanned_to
        w.node.mine(200)                      # the ch2 is 200 blocks old when its provider closes it
        w.hub.watch_tick()
        T.close_now(w.provs[0].inner, w.st2(0))
        w.hub.watch_tick()
        w.node.mine(1)
        close_height = w.node.height
        seen = count_getblock(w.node)
        ticks = 20
        for _ in range(ticks):
            acts = w.hub.watch_tick()
            self.assertFalse(H.has(acts, "ch2_closed"), f"control: one block deep at depth 6, nothing is final: {acts}")
        one_pass = close_height - funded_at + 1
        self.assertLessEqual(len(seen), 2 * one_pass,
                             f"{ticks} ticks while one close waited for depth read {len(seen)} blocks (getblock(hash, 2) each): "
                             f"{len(seen) // ticks} per tick, from the ch2's funding height {funded_at} to the close at "
                             f"{close_height}, every tick")

    def test_the_watcher_reads_the_chain_once_for_a_rollover_that_waits_for_depth(self):
        # The same for the usual case, a rollover: its parent is watched until the rollover is deep.
        w = A.W([None], hkw={"spend_final_depth": 6}, price=40 * 10 ** 21, settle_multiple=2)
        w.node.mine(200)
        w.hub.watch_tick()
        R.stream(w.pay, w.shards[0], 50)
        self.assertEqual(w.pay.lock(w.shards[0])["status"], "paid")
        self.assertTrue(H.has(w.hub.watch_tick(), "ch2_rollover"), "control: the ch2 is rolled over")
        w.node.mine(1)
        seen = count_getblock(w.node)
        ticks = 20
        for _ in range(ticks):
            w.hub.watch_tick()
        self.assertLessEqual(len(seen), 2 * 202,
                             f"{ticks} ticks while one rollover waited for depth read {len(seen)} blocks: {len(seen) // ticks} per tick "
                             f"for the rolled parent alone")


class StalledNet:
    """The hub's transport: a provider (by origin) that takes the hub's CHECK of a lock and does not
    answer it. The transport gives up after `secs` (30 s in xbt402's XbtChannelClient.http)."""

    def __init__(self, net):
        self.net, self.stall, self.waits = net, {}, 0

    def http(self, method, url, body=b"", headers=None):
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        if origin in self.stall and R.is_lock_check(path, body):
            self.net.http(method, url, body, headers)
            time.sleep(self.stall[origin])
            self.waits += 1
            raise OSError("timed out")
        return self.net.http(method, url, body, headers)


class AProviderThatDoesNotAnswer(unittest.TestCase):
    def test_a_provider_that_does_not_answer_the_check_is_not_waited_for_on_every_lock(self):
        # HOLE (Medium, availability; new in wave 5; B1 and xbt-rs). A provider that takes the hub's check
        # and does not answer is waited for until the hub's transport gives up (30 s), and the answer is
        # "no_answer: nothing written off, the ch2 not blocked" (hub.py `_forward`). So it is waited for
        # again on the next lock, and the next. A client's locks are serial on its ch1, so each wait is
        # time in which that client pays no other provider. Before AGP-094 the first unanswered lock
        # blocked the ch2 and every later one was refused at once.
        w = A.W([None, None])
        w.paid(0)
        w.paid(1)
        net = StalledNet(w.net)
        w.hub.http = net.http
        net.stall[w.origins[0]] = 0.7
        R.stream(w.pay, w.shards[0], 10)
        rounds, t0, paid_other = 4, time.time(), 0
        for _ in range(rounds):
            r = w.pay.lock(w.shards[0])
            self.assertTrue(r is None or r["status"] == "refused", f"control: nothing is paid to the hung provider: {r}")
            r = w.lock(1)
            paid_other += bool(r and r["status"] == "paid")
        oc = w.oc(0)
        self.assertLessEqual(net.waits, 1,
                             f"{rounds} rounds of one client's tick took {time.time() - t0:.1f} s: the hub waited {net.waits} times "
                             f"0.7 s for a provider that never answers a check (30 s each with the shipped transport), its ch2 is "
                             f"{oc.state} and blocked {oc.blocked!r} with {len(oc.stale)} written off, so the next lock waits again; "
                             f"the client paid its other provider {paid_other} times in that time")

    def test_control_a_check_whose_answer_is_lost_writes_nothing_off(self):
        w = A.W([None])
        net = StalledNet(w.net)
        w.hub.http = net.http
        net.stall[w.origins[0]] = 0.0
        r = w.lock(0)
        self.assertEqual((r["status"], r.get("error")), ("refused", "route_failed"), r)
        oc = w.oc(0)
        self.assertTrue(not oc.stale and not oc.blocked and not oc.pending and not w.stale1())
        net.stall.clear()
        w.paid(0)


class FundAfterSend:
    """ch1's fund hook: it sends, and its first `fail` calls then raise (the node took the send and the
    answer timed out)."""

    def __init__(self, node, fail):
        self.node, self.sends, self.fail = node, [], fail

    def __call__(self, address, sats):
        self.sends.append((address, sats))
        r = self.node.fund_address(address, sats)
        if self.fail > 0:
            self.fail -= 1
            raise ChannelError("wallet_error", "timed out after the send")
        return r


class RoutedOpen(unittest.TestCase):
    def rig(self, fail):
        node, net = R.RouteNode(), R.Net()
        hub = R.hub(node, net)
        R.provider(node, net, P0)
        hub.connect(P0)
        node.confirm_all()
        hub.watch_tick()
        fund = FundAfterSend(node, fail)
        pay = R.payer(node, net, signer=ChannelSigner(fund=fund))
        return node, hub, fund, pay

    def test_a_ch1_funding_that_failed_after_it_was_sent_is_not_sent_again(self):
        # HOLE (Medium by the audit's scale: coins left in a script until its expiry with no refund held
        # and no outpoint on the books, by the owner's own wallet failing, not by a counterparty; left
        # from before: the half of list 1 item 5's "from reading" bullet that AGP-094 did not close, its
        # found-not-fixed 5, and AGP-101's found-not-fixed 1, which measured two sends).
        # `fund` is a bare callable in B1, so the client cannot ask whether the first call sent
        # (x402_channel.py `_fund_keyed`): every `open` after a `fund` that raised sends ch1's capacity
        # again, to the same script, with no bound.
        node, hub, fund, pay = self.rig(fail=3)
        errors = [L.code_of(pay.open) for _ in range(3)]
        scripts = {a for a, _ in fund.sends}
        self.assertLessEqual(len(fund.sends), 1,
                             f"three calls to open ({errors}) sent ch1's funding {len(fund.sends)} times, "
                             f"{sum(s for _, s in fund.sends)} sat in all, to {len(scripts)} script(s); the books hold no outpoint "
                             f"({pay.cc.channels[R.HUB].payer.params.funding_txid!r}) and no refund for any of them")

    def test_control_a_fund_that_fails_before_it_sends_is_asked_again_and_sends_once(self):
        node, hub, fund, pay = self.rig(fail=0)
        real = fund.__class__.__call__
        calls = []

        def refuse_then_fund(address, sats):
            calls.append(1)
            if len(calls) < 3:
                raise ChannelError("wallet_error", "insufficient funds")
            return real(fund, address, sats)
        pay.signer.fund = refuse_then_fund
        pay.cc.fund = refuse_then_fund
        self.assertEqual([L.code_of(pay.open) for _ in range(2)], ["wallet_error"] * 2)
        pay.open()
        self.assertEqual((len(fund.sends), pay.ch.stage), (1, "open"))


class ShippedDefaults(unittest.TestCase):
    def test_control_the_reference_defaults_leave_five_seconds_of_each_invoice(self):
        # B1's own defaults: a window's invoice lives 15 s (RouteOffer.invoice_ttl), the hub admits it
        # with reveal_timeout (10 s) left: the first 5 s of each 15. (xbt-rs's `xbt402-route-provider`
        # issues 8 s invoices by default, which a default hub never admits: that hole is xbt-rs's.)
        self.assertEqual((RouteOffer("/x", 1).invoice_ttl, HubConfig().reveal_timeout), (15.0, 10.0))
        w = A.W([None], hkw={"reveal_timeout": HubConfig().reveal_timeout})
        # the rig's providers issue 8 s invoices (routehelp.provider): not admitted, not sent
        R.stream(w.pay, w.shards[0], 10)
        self.assertIsNone(w.pay.lock(w.shards[0]), "an 8 s invoice against a 10 s reveal timeout is never locked")
        st, doc = R.route_request(w.pay, w.shards[0])
        self.assertEqual((st, doc.get("error")), (400, "bad_invoice"), doc)


if __name__ == "__main__":
    unittest.main()
