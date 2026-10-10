"""AGP-084: what fix wave 2 (AGP-078) found and left (in-process: a fake node + a fake HTTP transport).
xbt-rs has the same tests, in `lifecycle.rs`, `hub_routing_safety.rs` and `routing_checks.rs`.

A spend whose broadcast errored (AGP-078's stated limit 3): `close` and `rollover` write `close_intent`,
then send. If the node answers with an error the answer is `close_failed`, the channel stays open and
the fully signed transaction stays in the ledger: it can still reach the chain. A call served, or a
lock routed, on a later state was then above what that spend pays. Now such a channel takes no new
state (`channel_closing`) until its spend is resolved: the watcher sends a close again every tick,
and records a spend the node shows after all; a rollover is never sent again (its client was told it
failed and may no longer hold the next channel's key), so the client rolls over again or closes.
Capacity (stated limit 4): `max_lock_sat` was bounded against the configured `ch2_capacity` only, and
`connect(origin, capacity=...)` takes another one.
"""
import json
import os
import secrets
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import routehelp as R  # noqa: E402
import test_agp059_embedder_api as E  # noqa: E402  (Rig: a provider and the reference client)
import test_agp064_hub_safety as T  # noqa: E402  (the AGP-064 harness: W)
import test_agp078_hub_closure as C  # noqa: E402  (rollover_ch1)

from xbt402 import ecc  # noqa: E402
from xbt402.channel import SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams  # noqa: E402
from xbt402.tx import Tx  # noqa: E402

O = E.ORIGIN


def down(node, on: bool):
    """While down, the node answers a broadcast with an error and does not have the transaction."""
    def timed_out(hx):
        raise TimeoutError("timed out")
    if on:
        node.sendrawtransaction = timed_out
    else:
        node.__dict__.pop("sendrawtransaction", None)


def code_of(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except ChannelError as e:
        return e.code
    return ""


def rollover_req(r, amount):
    """The payer's rollover of the rig's channel at `amount`, into a fresh next channel."""
    ch = r.ch
    p = ch.payer.params
    expiry = r.node.getblockcount() + 2000
    nxt = ChannelParams.derive(r.prov.pay_to, ecc.pubkey(secrets.randbelow(ecc.N - 1) + 1).hex(), expiry, p.close_fee,
                               network=E.NET, close_fee_payer=p.close_fee_payer)
    tx = p.rollover_tx(amount, nxt.spk, p.rollover_next_capacity(amount))
    sig = ecc.sign(ch.payer.secret, p.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
    return {"chan": p.channel_id, "amount": amount, "sig": sig.hex(), "next": {"payerPub": nxt.payer_pub, "expiry": expiry}}


def errored_spend(rollover: bool):
    """Five paid calls, then the close (or the rollover) while the node answers every broadcast with an
    error: the rig and the intent left behind."""
    r = E.Rig(price=150, charge=None, node=R.RouteNode())
    for _ in range(5):
        r.call()
    down(r.node, True)
    code = code_of(r.prov.rollover, rollover_req(r, 750)) if rollover else code_of(r.cl.close, O)
    assert code == "close_failed", code
    down(r.node, False)
    assert not r.st.closed_txid and not r.node.sent, "the node took nothing"
    return r, dict(r.st.extra["close_intent"])


class ErroredSpend(unittest.TestCase):
    def test_a_channel_whose_spend_the_node_errored_on_serves_nothing_above_it(self):
        # the provider holds the fully signed close (or rollover). The node said no, but the tx can still
        # reach the chain: a call served on a later state would be above what that spend pays
        for rollover in (False, True):
            with self.subTest(rollover=rollover):
                r, intent = errored_spend(rollover)
                paid, spent = Tx.parse(bytes.fromhex(intent["hex"])).outputs[0].value, r.st.spent_msat
                status, _h, out = r.cl.request("GET", O + "/v1/x")
                # the spend reaches the chain after all, and the watcher records it
                r.node.sendrawtransaction(intent["hex"])
                self.assertEqual(r.prov.close_due(), [intent["txid"]])
                self.assertEqual(r.st.closed_txid, intent["txid"])
                self.assertEqual(r.st.spent_msat, spent, f"a call was served above a spend that confirmed at {paid}")
                self.assertEqual((status, json.loads(out).get("error")), (402, "channel_closing"))
                self.assertEqual("rollover_to" in r.st.extra, rollover, "a rollover that lands later is recorded as one")

    def test_the_watcher_sends_a_close_the_node_errored_on_again(self):
        # nothing else would resolve it: the channel takes no new state until its close is on the node
        r, intent = errored_spend(False)
        down(r.node, True)
        self.assertEqual(r.prov.close_due(), [])
        self.assertTrue(not r.st.closed_txid and r.st.close_error, f"still open, and the failure shows: {r.st.close_error!r}")
        down(r.node, False)
        self.assertEqual(r.prov.close_due(), [intent["txid"]])
        self.assertEqual(Tx.parse(bytes.fromhex(r.node.sent[-1])).txid(), intent["txid"])
        self.assertEqual(r.st.closed_txid, intent["txid"])
        # the client asks again and gets the answer it lost
        self.assertEqual(r.cl.close(O)["txid"], intent["txid"])

    def test_the_watcher_does_not_send_a_rollover_the_client_was_told_failed(self):
        # the client was answered close_failed and may have dropped the next channel's key: sent now, the
        # rollover would fund a channel nobody can spend from. The client rolls over again or closes
        r, intent = errored_spend(True)
        self.assertEqual((r.prov.close_due(), r.node.sent), ([], []))
        self.assertFalse(r.st.closed_txid)
        out = r.prov.rollover(rollover_req(r, 750))
        self.assertNotEqual(out["txid"], intent["txid"], "a new rollover, to a key the client holds")
        self.assertEqual(r.st.closed_txid, out["txid"])
        self.assertEqual(r.st.extra["rollover_to"], out["nextChan"])
        # or the client closes
        r, intent = errored_spend(True)
        out = r.cl.close(O)
        self.assertNotEqual(out["txid"], intent["txid"])
        self.assertEqual(r.st.closed_txid, out["txid"])
        # or the operator closes it, at the best state
        r, intent = errored_spend(True)
        out = r.prov.close_channel(r.st.params.channel_id)
        self.assertNotEqual(out["txid"], intent["txid"])
        self.assertEqual(r.st.closed_txid, out["txid"])

    def test_a_spend_that_reached_the_chain_is_recorded_before_another_replaces_it(self):
        # the rollover the node errored on confirms; the client, told it failed, rolls over again or
        # closes. Either would overwrite the intent, and the spend on the chain would never be recorded
        for close in (False, True):
            with self.subTest(close=close):
                r, intent = errored_spend(True)
                txid = intent["txid"]
                r.node.sendrawtransaction(intent["hex"])
                if close:
                    try:
                        got = r.cl.close(O)["txid"]
                    except ChannelError as e:
                        got = e.code
                else:
                    got = code_of(r.prov.rollover, rollover_req(r, 750))
                self.assertEqual(r.st.closed_txid, txid, got)
                self.assertEqual(r.st.extra["rollover_to"], f"{txid}:1")
                self.assertEqual(got, txid if close else "channel_closing")
                self.assertEqual(len(r.node.sent), 1)


class HubErroredSpend(unittest.TestCase):
    def test_h1_no_lock_is_routed_above_a_ch1_spend_the_node_errored_on(self):
        # the hub signs ch1's close (or co-signs its rollover), writes the intent and sends; the node
        # answers with an error. The tx is complete and can still confirm. A lock routed meanwhile would
        # sit above it: the hub would pay the provider on ch2 for sats ch1's spend does not hold
        for rollover in (False, True):
            with self.subTest(rollover=rollover):
                w = T.W([None])
                w.paid(0)
                best = w.st1().best_cum
                R.stream(w.pay, w.shards[0], 10)
                down(w.node, True)
                code = C.rollover_ch1(w, best)[1].get("error") if rollover else code_of(w.pay.close)
                self.assertEqual(code, "close_failed")
                down(w.node, False)
                self.assertFalse(w.st1().closed_txid, "the node took nothing")
                intent = dict(w.st1().extra["close_intent"])
                n, best2 = w.lock_calls(), w.st2(0).best_cum
                r = w.pay.lock(w.shards[0])
                # the spend reaches the chain after all, and the hub's watcher records it
                w.node.sendrawtransaction(intent["hex"])
                self.assertEqual(w.hub.inbound.close_due(), [intent["txid"]])
                st1 = w.st1()
                self.assertEqual(st1.closed_txid, intent["txid"])
                self.assertEqual((w.lock_calls(), w.st2(0).best_cum), (n, best2),
                                 f"the hub paid the provider {w.st2(0).best_cum - best2} on ch2 for a lock above "
                                 f"ch1's spend at {best} ({r})")
                self.assertEqual((r.get("status"), r.get("error")), ("refused", "channel_closing"), r)
                self.assertEqual(st1.best_cum, best, "ch1 has no state above the spend")

    def test_h1_a_ch1_close_the_node_errored_on_goes_through_at_the_next_tick(self):
        w = T.W([None])
        w.paid(0)
        down(w.node, True)
        self.assertEqual(code_of(w.pay.close), "close_failed")
        self.assertEqual(w.hub.inbound.close_due(), [])
        down(w.node, False)
        txid = w.st1().extra["close_intent"]["txid"]
        self.assertEqual(w.hub.inbound.close_due(), [txid])
        self.assertEqual(w.st1().closed_txid, txid)
        self.assertEqual(w.pay.close()["txid"], txid, "the client asks again and gets the answer it lost")

    def test_h1_a_provider_takes_no_lock_on_a_ch2_whose_spend_its_node_errored_on(self):
        # the same on the provider's side of a ch2: the hub's rollover of it, co-signed and written
        # ahead, that the provider's node answered with an error
        w = T.W([None])
        w.paid(0)
        st2 = w.st2(0)
        best2 = st2.best_cum
        st2.extra = {**(st2.extra or {}), "close_intent": {"hex": "00", "txid": "ab" * 32, "cond": False,
                                                          "next": "ab" * 32 + ":1"}}
        r = w.lock(0)
        self.assertEqual(r["status"], "refused", r)
        self.assertEqual(w.st2(0).best_cum, best2, "the provider took a lock above a spend that can still confirm")


class Config(unittest.TestCase):
    def test_hub_bounds_max_lock_sat_against_the_capacity_a_ch2_is_opened_with(self):
        # the bound was made against the configured ch2_capacity only, and connect() takes another
        # capacity (max_lock_sat is 20,000 here: a ch2 of less than 40,000 breaks AGP-064's rule)
        node, net, hub, provs, _pay, _shards = R.world(1)
        small, live = "http://dev-small.test", next(iter(provs))
        R.provider(node, net, small)
        committed, sent = hub.committed_sat(), len(node.wallet_txs)
        self.assertEqual(code_of(hub.connect, small, capacity=39_999), "bad_config")
        # the next ch2 of a provider it already pays, funded ahead
        self.assertEqual(code_of(hub.connect_next, live, capacity=39_999), "bad_config")
        self.assertEqual((hub.committed_sat(), len(node.wallet_txs)), (committed, sent), "refused before anything is funded")
        self.assertEqual(hub.connect(small, capacity=40_000).p().capacity, 40_000)
        self.assertEqual(hub.connect_next(live, capacity=40_000).p().capacity, 40_000)


if __name__ == "__main__":
    unittest.main()
