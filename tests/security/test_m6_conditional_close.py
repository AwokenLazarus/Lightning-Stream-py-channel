"""M6 (Medium) the hash-locked conditional state was not closable.

Wave 2's provider stored the payer's conditional signature (`cond_sig`) but no close path used it:
close_tx() always closed the best plain state and ConditionalParams.claim_tx was never called. So a
payer who took the deliverable (and k) and then never signed the upgrade paid nothing on-chain for
it: the increment was postpay credit, not the hash lock the design promises.

Fix (option a of the review): the provider closes with the conditional state whenever it pays more
than the best plain state (uncond + condAmount - claim fee > best cum), broadcasts the claim with k
right after the close, and the watcher rebroadcasts the claim every tick until it is spent, well
inside csvDelta. A new conditional call is refused while an earlier one is not yet folded into a
plain 0x21 state, since only one conditional state can be closed with. k and the state's terms are
kept in the ledger, so a restart can still close and claim.

The regtest class runs the whole thing on a throwaway Knots 29.4.2 node (RDTS + #419) on ports
33001/33002 (AGP-001's range), datadir ~/xbt-rnd/b1/run/m6 (wiped after). It is skipped only when
the node binary is missing.
"""
import json
import os
import shutil
import subprocess
import unittest

from sechelp import ROOT, FakeNode, Repro, base, load, make_provider

PLAIN = b"the deliverable"
COND_PRICE = 1000


def rig(xm, node, fold=True, **kw):
    """A provider with a conditional offer on /v1/cond and a client whose HTTP goes straight into
    provider.serve. The client funds through `fund` and holds its own payer key (no signer).
    fold=False: a payer that takes the deliverable and never hands over the upgrade (its POST to
    /x402/verify never reaches the provider)."""
    prov = make_provider(xm, node, **{k: v for k, v in kw.items() if k in ("billing",)})
    for k in ("policy", "close_margin"):
        if k in kw:
            setattr(prov, k, kw[k])
    prov.offer_conditional("/v1/cond", COND_PRICE, PLAIN)
    client = xm.XbtChannelClient(prov.network, fund=kw.get("fund", lambda a, s: (os.urandom(32).hex(), 0)),
                                 height=node.getblockcount, capacity=kw.get("capacity", 200_000),
                                 expiry_blocks=kw.get("expiry_blocks", 1_008),
                                 on_open=kw.get("on_open", lambda ch: node.add_funding(ch.payer.params)))

    client.log = []

    def http(method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        if not fold and path == "/x402/verify":
            return 503, {}, b'{"error": "withheld"}'
        st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
        client.log.append((st, out))
        return st, {k.upper(): v for k, v in h.items()}, out
    client.http = http
    return prov, client


def outputs(hx):
    from xbt402.tx import Tx
    return Tx.parse(bytes.fromhex(hx)).outputs


class ConditionalClose(Repro, unittest.TestCase):
    def test_repro_conditional_state_never_closed(self):
        xm = base("x402_channel")
        node = FakeNode()
        prov, client = rig(xm, node)
        client.request("GET", "http://api.test/v1/x")
        st, _, _, plain = client.request_conditional("GET", "http://api.test/v1/cond")
        chan = next(iter(prov.ledger.channels.values()))
        close = prov._payee(chan).close_tx() if chan.best_sig else None
        paid = sum(o.value for o in close.outputs if o.script_pubkey.hex() == chan.params.payee_spk) if close else 0
        cond_out = close and any(o.value == COND_PRICE for o in close.outputs)
        self.reproduces(st == 200 and plain == PLAIN and chan.cond_sig and not cond_out and paid < COND_PRICE,
                        f"payer got the deliverable; the provider's only close pays it {paid} sat, "
                        f"no {COND_PRICE}-sat hash lock (cond_sig stored, never used)")

    def fixed(self, fold=False, **kw):
        xm = load("x402_channel")
        node = FakeNode()
        prov, client = rig(xm, node, fold, **kw)
        return xm, node, prov, client

    def test_fixed_close_uses_conditional_state_and_claims(self):
        xm, node, prov, client = self.fixed()
        client.request("GET", "http://api.test/v1/x")
        client.request("GET", "http://api.test/v1/x")                    # best plain state: 546 (dust floor)
        st, _, _, plain = client.request_conditional("GET", "http://api.test/v1/cond")
        self.assertEqual((st, plain), (200, PLAIN))
        chan = next(iter(prov.ledger.channels.values()))
        self.assertEqual(chan.best_cum, 546)
        node.height = chan.params.expiry - prov.close_margin               # the payer never signs again
        self.assertEqual(len(prov.close_due()), 1)
        close_hex, claim_hex = node.sent
        cp = prov._cond_state(chan)[0]
        outs = outputs(close_hex)
        self.assertEqual([o.value for o in outs if o.script_pubkey == cp.spk], [COND_PRICE])
        self.assertEqual([o.value for o in outs if o.script_pubkey.hex() == chan.params.payee_spk], [546])
        from xbt402.tx import Tx
        claim = Tx.parse(bytes.fromhex(claim_hex))
        self.assertEqual(claim.inputs[0].txid[::-1].hex(), chan.closed_txid)
        self.assertEqual([(o.value, o.script_pubkey.hex()) for o in claim.outputs],
                         [(COND_PRICE - prov.claim_fee, chan.params.payee_spk)])
        self.assertEqual(claim.inputs[0].witness[1], prov._cond_state(chan)[2])     # reveals k (already public)
        self.assertEqual(chan.extra["claim_txid"], claim.txid())
        # the watcher does not send the claim again while it is in the mempool / chain
        prov.close_due()
        self.assertEqual(len(node.sent), 2)

    def test_fixed_claim_retried_and_survives_restart(self):
        xm, node, prov, client = self.fixed()
        client.request("GET", "http://api.test/v1/x")
        client.request_conditional("GET", "http://api.test/v1/cond")
        chan = next(iter(prov.ledger.channels.values()))
        # the claim fails the first time (say the close was not relayed yet); the close still stands
        real = node.sendrawtransaction
        calls = []

        def flaky(hx):
            calls.append(hx)
            if len(calls) >= 2:            # every claim this tick fails (the close was not relayed yet, say)
                raise RuntimeError("bad-txns-inputs-missingorspent")
            return real(hx)
        node.sendrawtransaction = flaky
        node.height = chan.params.expiry - prov.close_margin
        prov.close_due()
        self.assertIn("claim_failed", chan.close_error)
        self.assertEqual(len(node.sent), 1)                                   # the close only
        node.sendrawtransaction = real
        # restart: a new provider on the same ledger (k and terms come from the ledger, not memory)
        prov2 = xm.XbtChannelProvider(node, 0xB0B, prov.network, prov.ledger.path, lambda m, p: 150,
                                      lambda m, p, b: (200, {}, b"ok"))
        prov2.close_due()
        self.assertEqual(len(node.sent), 2)
        self.assertEqual(outputs(node.sent[1])[0].value, COND_PRICE - prov2.claim_fee)

    def test_fixed_honest_payer_folds_at_once(self):
        xm, node, prov, client = self.fixed(fold=True)
        client.request("GET", "http://api.test/v1/x")
        client.request("GET", "http://api.test/v1/x")
        client.request_conditional("GET", "http://api.test/v1/cond")      # posts the upgrade to /x402/verify
        chan = next(iter(prov.ledger.channels.values()))
        self.assertEqual(chan.best_cum, 546 + COND_PRICE)
        self.assertFalse(prov._cond_outstanding(chan))
        self.assertEqual(client.request("GET", "http://api.test/v1/x")[0], 200)
        node.height = chan.params.expiry - prov.close_margin
        prov.close_due()
        self.assertEqual(len(node.sent), 1)                                   # a plain close, no claim
        self.assertEqual(outputs(node.sent[0])[0].value, chan.best_cum)

    def test_fixed_plain_close_after_late_upgrade(self):
        xm, node, prov, client = self.fixed()
        client.request("GET", "http://api.test/v1/x")
        client.request_conditional("GET", "http://api.test/v1/cond")      # upgrade withheld...
        chan = next(iter(prov.ledger.channels.values()))
        self.assertTrue(prov._cond_outstanding(chan))
        self.assertEqual(client.request("GET", "http://api.test/v1/x")[0], 200)   # ...the next call carries it
        self.assertEqual(chan.best_cum, 150 + COND_PRICE)                    # the first call + the increment
        self.assertFalse(prov._cond_outstanding(chan))
        self.assertFalse(prov._cond_outstanding(chan))
        node.height = chan.params.expiry - prov.close_margin
        prov.close_due()
        self.assertEqual(len(node.sent), 1)                                   # a plain close, no claim
        self.assertEqual(outputs(node.sent[0])[0].value, chan.best_cum)

    def test_fixed_first_call_conditional_is_closable(self):
        xm, node, prov, client = self.fixed()
        client.request_conditional("GET", "http://api.test/v1/cond")        # no plain state at all
        chan = next(iter(prov.ledger.channels.values()))
        self.assertEqual((chan.best_sig, chan.best_cum), ("", 0))
        node.height = chan.params.expiry - prov.close_margin
        self.assertEqual(len(prov.close_due()), 1)
        cp = prov._cond_state(chan)[0]
        self.assertEqual([o.value for o in outputs(node.sent[0]) if o.script_pubkey == cp.spk], [COND_PRICE])
        self.assertEqual(len(node.sent), 2)

    def test_fixed_second_conditional_refused_until_folded(self):
        xm, node, prov, client = self.fixed()
        client.request("GET", "http://api.test/v1/x")
        client.request_conditional("GET", "http://api.test/v1/cond")
        chan = next(iter(prov.ledger.channels.values()))
        first = chan.cond_sig
        # a second conditional call signed over the same uncond would replace the first state and
        # drop its increment: refused, and the stored conditional state is unchanged
        from xbt402.channel import ChannelError
        client.channels["http://api.test"].payer.signed = chan.best_cum    # "forget" the local upgrade
        with self.assertRaises((ChannelError, KeyError, ValueError)):
            client.request_conditional("GET", "http://api.test/v1/cond")
        self.assertEqual(json.loads(client.log[-1][1])["error"], "conditional_outstanding")
        self.assertEqual(chan.cond_sig, first)
        self.assertTrue(prov._cond_outstanding(chan))


BIN = "$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2"
DD = os.path.expanduser("~/xbt-rnd/b1/run/m6")
ENV = {"XBT_BIN": BIN, "XBT402_DATADIR": DD, "XBT402_RPCPORT": "33001", "XBT402_P2PPORT": "33002",
       "XBT402_BLOCKS": "300", "XBT402_MATURITY_PAD": "6800"}


@unittest.skipUnless(os.path.exists(os.path.join(BIN, "bitcoind")), "Knots 29.4.2 binary not installed")
class ConditionalCloseRegtest(unittest.TestCase):
    """The payer takes the deliverable and stops signing; the provider still gets condAmount on-chain."""

    @classmethod
    def setUpClass(cls):
        cls.env = {**os.environ, **ENV}
        node_sh = os.path.join(ROOT, "scripts", "node.sh")
        subprocess.run([node_sh, "wipe"], env=cls.env, capture_output=True)
        cls.addClassCleanup(lambda: (subprocess.run([node_sh, "wipe"], env=cls.env, capture_output=True),
                                     shutil.rmtree(DD, ignore_errors=True)))
        subprocess.run(["nice", "-n", "10", node_sh, "up"], env=cls.env, check=True, capture_output=True)
        from xbt402.rpc import RPC
        cls.node = RPC(33001, os.path.join(DD, "regtest", ".cookie"))
        cls.w = cls.node.wallet("w")

    def mine(self, n=1):
        return self.node.generatetoaddress(n, self.w.getnewaddress())

    def test_payer_stops_signing_provider_claims_cond_amount(self):
        from xbt402 import ecc
        from xbt402.funding import FundingPolicy
        from xbt402.tx import (SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxIn, TxOut, p2wpkh_spk,
                               unified_sighash)
        xm = load("x402_channel")
        node, w = self.node, self.w
        SAT = 100_000_000

        def fund(addr, sats):
            txid = w.sendtoaddress(addr, sats / SAT)
            raw = node.getrawtransaction(txid, True)
            return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == addr)
        net = xm.network_id(node.getblockhash(101))
        prov = xm.XbtChannelProvider(node, 0xB0B5, net, os.path.join(DD, "provider.sqlite"), lambda m, p: 150,
                                     lambda m, p, b: (200, {}, b"ok"), close_margin=5,
                                     policy=FundingPolicy(min_expiry_blocks=20, close_margin=5), height_ttl=0)
        prov.offer_conditional("/v1/cond", COND_PRICE, PLAIN)
        client = xm.XbtChannelClient(net, fund=fund, height=node.getblockcount, capacity=100_000, expiry_blocks=30,
                                     on_open=lambda ch: self.mine())

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3]
            if path == "/x402/verify":                                      # the payer withholds the upgrade
                return 503, {}, b'{"error": "withheld"}'
            st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
            return st, {k.upper(): v for k, v in h.items()}, out
        client.http = http
        self.assertEqual(client.request("GET", "http://api.test/v1/x")[0], 200)
        self.assertEqual(client.request("GET", "http://api.test/v1/x")[0], 200)
        st, _, _, plain = client.request_conditional("GET", "http://api.test/v1/cond")
        self.assertEqual((st, plain), (200, PLAIN))                          # payer holds the deliverable
        chan = next(iter(prov.ledger.channels.values()))
        payer = client.channels["http://api.test"].payer
        self.assertGreater(payer.signed, chan.best_cum)                       # signed the upgrade locally...
        # ...and never sends it. The provider's watcher reaches expiry - closeMarginBlocks:
        self.mine(chan.params.expiry - prov.close_margin - node.getblockcount())
        closed = prov.close_due()
        self.assertEqual(closed, [chan.closed_txid])
        self.assertTrue(chan.extra["cond_close"])
        claim_txid = chan.extra["claim_txid"]
        self.mine()
        close = node.getrawtransaction(chan.closed_txid, True)
        claim = node.getrawtransaction(claim_txid, True)
        self.assertGreaterEqual(close["confirmations"], 1)
        self.assertGreaterEqual(claim["confirmations"], 1)
        cp = prov._cond_state(chan)[0]
        hl = [o for o in close["vout"] if o["scriptPubKey"]["hex"] == cp.spk.hex()]
        self.assertEqual([round(o["value"] * SAT) for o in hl], [COND_PRICE])     # condAmount on-chain
        to_payee = [round(o["value"] * SAT) for o in close["vout"] + claim["vout"]
                    if o["scriptPubKey"]["hex"] == chan.params.payee_spk]
        self.assertEqual(sorted(to_payee), sorted([chan.best_cum, COND_PRICE - prov.claim_fee]))
        self.assertEqual(claim["vin"][0]["txid"], chan.closed_txid)
        # the payer's CSV refund of the hash lock can never confirm now, even after csvDelta
        self.mine(cp.csv_delta)
        vout = hl[0]["n"]
        tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(chan.closed_txid)[::-1], vout, cp.csv_delta)],
                outputs=[TxOut(COND_PRICE - 300, p2wpkh_spk(bytes.fromhex(chan.params.payer_pub)))], locktime=0)
        h = unified_sighash(tx, [TxOut(COND_PRICE, cp.spk)], 0, ST_WITNESS_V0, cp.script, SIGHASH_ALL_UNIFIED)
        tx.inputs[0].witness = [ecc.sign(payer.secret, h) + bytes([SIGHASH_ALL_UNIFIED]), b"", cp.script]
        r = node.testmempoolaccept([tx.hex()])[0]
        self.assertFalse(r["allowed"])
        self.assertIn("missing", r.get("reject-reason", "") + json.dumps(r))
        self.assertIsNone(node.gettxout(chan.closed_txid, vout, True))


if __name__ == "__main__":
    unittest.main()
