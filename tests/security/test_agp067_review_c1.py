"""AGP-067: review C1 (xbt-rs `crates/xbt402/tests/review_c1.rs`, same names). A close pays the fixed
closeFee agreed at open (600 sat, about 3 sat/vB); if fees spike through the close margin and nothing
bumps it, the payer's refund at expiry takes the whole channel back. The watcher now bumps the close
with a CPFP child from the provider's own close output.

Pool is a node with a mempool: a floor (minrelaytxfee/mempoolminfee), full RBF with the 1 sat/vB
increment, submitpackage (a parent below the floor goes in on its child's fee), an estimate the test
sets, and blocks that take only packages at or above the market's feerate.
"""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from xbt402.channel import DUST  # noqa: E402
from xbt402.tx import Tx, address_to_spk  # noqa: E402
from xbt402.x402_channel import CPFP_CHILD_VSIZE, XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"


def txid_of(i):
    return i.txid[::-1].hex()


class Pool:
    def __init__(self):
        self.tip, self.floor, self.estimate, self.funded = 1_000, 1.0, None, 0
        self.utxos = {}          # (txid, vout) -> (value, spk bytes, height): confirmed and unspent
        self.confirmed, self.mempool = set(), []

    # --- the mempool model --------------------------------------------------------------------
    def value_of(self, txid, vout):
        if (txid, vout) in self.utxos:
            return self.utxos[(txid, vout)][0]
        t = next((t for t in self.mempool if t.txid() == txid), None)
        return t.outputs[vout].value if t is not None and vout < len(t.outputs) else None

    def fee(self, tx):
        ins = [self.value_of(txid_of(i), i.vout) for i in tx.inputs]
        if any(v is None for v in ins):
            return None
        f = sum(ins) - sum(o.value for o in tx.outputs)
        return f if f >= 0 else None

    def children(self, txid):
        return [t for t in self.mempool if any(txid_of(i) == txid for i in t.inputs)]

    def package_rate(self, tx):
        """The best feerate this tx confirms at: alone, or with all its children in the pool (CPFP)."""
        own = (self.fee(tx) or 0) / tx.vsize()
        kids = self.children(tx.txid())
        fee = (self.fee(tx) or 0) + sum(self.fee(k) or 0 for k in kids)
        return max(own, fee / (tx.vsize() + sum(k.vsize() for k in kids)))

    def remove_with_descendants(self, txid):
        kids = [k.txid() for k in self.children(txid)]
        self.mempool = [t for t in self.mempool if t.txid() != txid]
        for k in kids:
            self.remove_with_descendants(k)

    def accept(self, tx, rate=None):
        """Mempool acceptance; `rate` is the package's feerate when it comes in a package."""
        if any(t.txid() == tx.txid() for t in self.mempool) or tx.txid() in self.confirmed:
            return
        fee = self.fee(tx)
        if fee is None:
            raise RuntimeError("bad-txns-inputs-missingorspent")
        own = fee / tx.vsize()
        if (own if rate is None else rate) < self.floor:
            raise RuntimeError(f"min relay fee not met ({own:.2f} sat/vB < {self.floor})")
        outs = {(txid_of(i), i.vout) for i in tx.inputs}
        conflicts = [t for t in self.mempool if any((txid_of(i), i.vout) in outs for i in t.inputs)]
        if conflicts:
            replaced = sum((self.fee(c) or 0) + sum(self.fee(k) or 0 for k in self.children(c.txid()))
                           for c in conflicts)
            if fee < replaced + tx.vsize():
                raise RuntimeError("insufficient fee (BIP125 rule 4)")
            for c in conflicts:
                self.remove_with_descendants(c.txid())
        self.mempool.append(tx)

    def set_floor(self, f):
        """A fee spike: the floor rises and what pays less leaves the mempool (a full node trimming,
        or a restart with a higher minrelaytxfee)."""
        self.floor = f
        for g in [t.txid() for t in self.mempool if self.package_rate(t) < f]:
            self.remove_with_descendants(g)

    def mine(self, market):
        """One block of the packages paying `market` sat/vB or more (CPFP counted)."""
        self.tip += 1
        while True:
            tx = next((t for t in self.mempool if all((txid_of(i), i.vout) in self.utxos for i in t.inputs)
                       and self.package_rate(t) >= market), None)
            if tx is None:
                break
            self.mempool = [t for t in self.mempool if t.txid() != tx.txid()]
            for i in tx.inputs:
                del self.utxos[(txid_of(i), i.vout)]
            for n, o in enumerate(tx.outputs):
                self.utxos[(tx.txid(), n)] = (o.value, o.script_pubkey, self.tip)
            self.confirmed.add(tx.txid())

    def in_block(self, txid):
        return txid in self.confirmed

    def in_pool(self, txid):
        return any(t.txid() == txid for t in self.mempool)

    # --- the node's RPCs ----------------------------------------------------------------------
    def getblockcount(self):
        return self.tip

    def gettxout(self, txid, vout, include_mempool=True):
        def out(conf, value, spk):
            return {"confirmations": conf, "value": value / 1e8, "scriptPubKey": {"hex": spk.hex()}, "coinbase": False}
        if include_mempool and any(txid_of(i) == txid and i.vout == vout for t in self.mempool for i in t.inputs):
            return None
        if (txid, vout) in self.utxos:
            v, spk, h = self.utxos[(txid, vout)]
            return out(self.tip - h + 1, v, spk)
        if not include_mempool:
            return None
        t = next((t for t in self.mempool if t.txid() == txid), None)
        return out(0, t.outputs[vout].value, t.outputs[vout].script_pubkey) if t and vout < len(t.outputs) else None

    def getrawtransaction(self, txid, verbose=True):
        if txid in self.confirmed or self.in_pool(txid):
            return {"txid": txid}
        raise RuntimeError("No such mempool or blockchain transaction")

    def sendrawtransaction(self, hx):
        tx = Tx.parse(bytes.fromhex(hx))
        self.accept(tx)
        return tx.txid()

    def estimatesmartfee(self, target):
        return {"feerate": self.estimate * 1000 / 1e8} if self.estimate else {"errors": ["no estimate"]}

    def getmempoolinfo(self):
        return {"mempoolminfee": self.floor * 1000 / 1e8, "minrelaytxfee": 1000 / 1e8}

    def submitpackage(self, hexes):
        parent, child = (Tx.parse(bytes.fromhex(h)) for h in hexes)
        try:
            if self.in_pool(parent.txid()):
                self.accept(child)
            else:
                # the child's input is the parent's output, not in the pool yet: the package's fee
                pf = self.fee(parent)
                if pf is None:
                    raise RuntimeError("package: parent inputs missing")
                cf = parent.outputs[child.inputs[0].vout].value - sum(o.value for o in child.outputs)
                self.accept(parent, (pf + cf) / (parent.vsize() + child.vsize()))
                try:
                    self.accept(child)
                except Exception:
                    self.remove_with_descendants(parent.txid())
                    raise
        except RuntimeError as e:
            return {"package_msg": "transaction failed", "tx-results": {child.wtxid() if hasattr(child, "wtxid")
                                                                         else child.txid(): {"error": str(e)}}}
        return {"package_msg": "success", "tx-results": {}}

    def fund(self, address, sats):
        self.funded += 1
        txid = hashlib.sha256(f"funding {self.funded}".encode()).hexdigest()
        self.utxos[(txid, 0)] = (sats, address_to_spk(address, "bcrt"), self.tip)
        self.confirmed.add(txid)
        return txid, 0


def provider(pool, max_fee, price):
    secret = int.from_bytes(hashlib.sha256(b"provider payTo").digest(), "big")
    import tempfile
    return XbtChannelProvider(pool, secret, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: price,
                              lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"answer": 1}'),
                              close_bump_max_fee=max_fee)


def channel(pool, prov, calls):
    """A channel with `calls` paid calls; returns (client, channel id, expiry)."""
    c = XbtChannelClient(NET, pool.fund, pool.getblockcount)

    def http(method, url, body=b"", headers=None):
        st, h, out = prov.serve(method, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)
        return st, {k.upper(): v for k, v in h.items()}, out
    c.http = http
    for _ in range(calls):
        assert c.request("GET", f"{O}/v1/q")[0] == 200
    p = c.channels[O].payer.params
    return c, p.channel_id, p.expiry


def bump(prov, chan):
    return (prov.ledger.channels[chan].extra or {}).get("close_bump") or {}


def funding_spent_in_a_block(pool, chan):
    txid, vout = chan.split(":")
    return pool.gettxout(txid, int(vout), False) is None


def run_to_expiry(pool, prov, chan, expiry, market):
    """The watcher every block from the close margin to expiry, blocks at `market`; the height the
    funding was spent in a block, if before expiry."""
    pool.tip = expiry - prov.close_margin
    while pool.tip < expiry:
        prov.close_due()
        pool.mine(market)
        if funding_spent_in_a_block(pool, chan):
            return pool.tip
    return None


def close_of(prov, chan):
    st = prov.ledger.channels[chan]
    return st, Tx.parse(bytes.fromhex(st.extra["close_hex"]))


class ReviewC1(unittest.TestCase):
    def test_c1_a_close_below_the_mempool_floor_goes_in_with_a_child(self):
        pool = Pool()
        prov = provider(pool, 10_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 20)
        pool.set_floor(10.0)
        at = run_to_expiry(pool, prov, chan, expiry, 10.0)
        self.assertEqual(at, expiry - prov.close_margin + 1, "in the first block after the margin close")
        st, close = close_of(prov, chan)
        self.assertTrue(pool.in_block(st.closed_txid))
        b = bump(prov, chan)
        self.assertTrue(pool.in_block(b["txid"]), b)
        rate = (600 + b["fee"]) / (close.vsize() + CPFP_CHILD_VSIZE)
        self.assertTrue(10.0 <= rate < 10.1, f"the package pays the floor, no more: {rate} {b}")

    def test_c1_without_the_bump_the_close_never_confirms(self):
        # main's behaviour (close_bump_max_fee 0): the close only rebroadcasts, the node refuses it
        # through the whole margin, and at expiry the payer's refund is valid on an unspent funding
        pool = Pool()
        prov = provider(pool, 0, 1_000)
        c, chan, expiry = channel(pool, prov, 20)
        pool.set_floor(10.0)
        self.assertIsNone(run_to_expiry(pool, prov, chan, expiry, 10.0))
        self.assertFalse(funding_spent_in_a_block(pool, chan))
        self.assertIn("min relay fee", prov.ledger.channels[chan].close_error)
        refund = Tx.parse(bytes.fromhex(c.channels[O].refund_hex))
        self.assertEqual(refund.locktime, expiry)

    def test_c1_the_bump_follows_the_estimate_and_escalates_near_expiry(self):
        pool = Pool()
        prov = provider(pool, 50_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 40)
        # the close goes in alone at the margin; the market moves to 50 sat/vB, the estimate says 5
        pool.estimate = 5.0
        at = run_to_expiry(pool, prov, chan, expiry, 50.0)
        self.assertIsNotNone(at, "the close confirmed before expiry")
        b = bump(prov, chan)
        half = expiry - prov.close_margin // 2
        self.assertTrue(half + 1 <= at < half + 20,
                        f"doubled from the estimate every close_bump_blocks in the margin's second half: at {at}, {b}")
        self.assertTrue(b["rate"] >= 50.0 and b["replaced"], b)
        self.assertTrue(pool.in_block(b["txid"]))

    def test_c1_the_child_never_pays_more_than_the_cap_or_the_output(self):
        # the cap: the estimate wants 40 sat/vB, the operator allows 2,000 sat
        pool = Pool()
        prov = provider(pool, 2_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 20)
        pool.set_floor(5.0)
        pool.estimate = 40.0
        pool.tip = expiry - prov.close_margin
        self.assertEqual(len(prov.close_due()), 1)
        b = bump(prov, chan)
        self.assertEqual((b["fee"], b["capped"]), (2_000, True), b)
        self.assertTrue(pool.in_pool(b["txid"]))
        # the output: a small channel's close output is all the child can spend
        pool = Pool()
        prov = provider(pool, 1_000_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 2)
        pool.estimate = 400.0
        pool.tip = expiry - prov.close_margin
        # the close goes in alone (the floor is 1 sat/vB); the next look bumps it
        self.assertEqual(len(prov.close_due()), 1)
        prov.close_due()
        st, close = close_of(prov, chan)
        value = next(o.value for o in close.outputs if o.script_pubkey.hex() == st.params.payee_spk)
        b = bump(prov, chan)
        self.assertEqual((b["fee"], b["capped"]), (value - DUST, True), b)

    def test_c1_the_payee_sweep_spends_the_child_after_a_bump(self):
        pool = Pool()
        prov = provider(pool, 10_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 20)
        pool.set_floor(10.0)
        self.assertIsNotNone(run_to_expiry(pool, prov, chan, expiry, 10.0))
        b = bump(prov, chan)
        r = prov.sweep_payee(chan, bytes([0, 20]) + bytes([7]) * 20, 2_000)
        self.assertEqual(r["outpoint"], f"{b['txid']}:0", r)
        st, close = close_of(prov, chan)
        paid = next(o.value for o in close.outputs if o.script_pubkey.hex() == st.params.payee_spk)
        self.assertEqual(r["value"], paid - b["fee"])
        self.assertTrue(pool.in_pool(r["txid"]))

    def test_c1_a_close_that_pays_enough_is_left_alone(self):
        pool = Pool()
        prov = provider(pool, 10_000, 1_000)
        _c, chan, expiry = channel(pool, prov, 20)
        self.assertIsNotNone(run_to_expiry(pool, prov, chan, expiry, 1.0))
        self.assertNotIn("txid", bump(prov, chan), "no child for a close the market takes")


if __name__ == "__main__":
    unittest.main()
