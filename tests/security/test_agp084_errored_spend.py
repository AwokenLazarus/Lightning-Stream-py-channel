"""AGP-084: what fix wave 2 (AGP-078) found and left (in-process: a fake node + a fake HTTP transport).
xbt-rs has the same tests, in `lifecycle.rs`.

A spend whose broadcast errored (AGP-078's stated limit 3): `close` and `rollover` write `close_intent`,
then send. If the node answers with an error the answer is `close_failed`, the channel stays open and
the fully signed transaction stays in the ledger: it can still reach the chain. A call served on a
later state was then above what that spend pays. Now such a channel takes no new
state (`channel_closing`) until its spend is resolved: the watcher sends a close again every tick,
and records a spend the node shows after all; a rollover is never sent again (its client was told it
failed and may no longer hold the next channel's key), so the client rolls over again or closes.
"""
import json
import os
import secrets
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

import nodehelp as R  # noqa: E402
import test_agp059_embedder_api as E  # noqa: E402  (Rig: a provider and the reference client)

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
    r = E.Rig(price=150, charge=None, node=R.MempoolNode())
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


if __name__ == "__main__":
    unittest.main()
