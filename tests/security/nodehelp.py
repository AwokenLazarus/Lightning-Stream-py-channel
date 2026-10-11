"""A fake node with a mempool, for the in-process tests that need more than sechelp's FakeNode."""
import time

from sechelp import FakeNode

from xbt402.tx import Tx

NET = "bip122:" + "11" * 16


class MempoolNode(FakeNode):
    """FakeNode plus a mempool that behaves like a node's: one spend per outpoint, and a conflicting
    spend is refused unless it replaces a mempool spend by BIP125 (the old one signals, the new one
    pays its fee + 1 sat/vB more). Blocks take only txs paying block_min_feerate sat/vB. It answers
    raw tx hex and estimatesmartfee."""

    def __init__(self, height=1000):
        super().__init__(height)
        self.spenders, self.raw, self.mined = {}, {}, set()
        self.feerate = None               # estimatesmartfee's BTC/kvB (None: no estimate)
        self.fees = {}                    # txid -> (fee, vsize) of every broadcast tx
        self.block_min_feerate = 0.0

    def fee_of(self, txid):
        return self.fees.get(txid)

    def confirmed(self, txid):
        return self.txs.get(txid, {}).get("confirmations", 0) >= 1

    def _held(self, txid):
        f = self.fees.get(txid)
        return f is not None and f[0] < self.block_min_feerate * f[1]

    def sendrawtransaction(self, hx):
        tx = Tx.parse(bytes.fromhex(hx))
        if tx.locktime > self.height and tx.locktime < 500_000_000:
            raise RuntimeError("non-final")
        ins = 0
        for i in tx.inputs:
            prev = self.txs.get(i.txid[::-1].hex(), {}).get("vout", [])
            ins += sum(round(o["value"] * 1e8) for o in prev if o["n"] == i.vout)
        fee, vsize = ins - sum(o.value for o in tx.outputs), tx.vsize()
        replaced = []
        for i in tx.inputs:                   # like a node: one spend per outpoint, or a BIP125 replacement
            k = (i.txid[::-1].hex(), i.vout)
            old = self.spenders.get(k)
            if old is None or old == tx.txid():
                continue
            signals = old in self.raw and any(x.sequence < 0xFFFFFFFE for x in Tx.parse(bytes.fromhex(self.raw[old])).inputs)
            if k in self.mined or not signals or fee < self.fees.get(old, (1 << 62, 0))[0] + vsize:
                raise RuntimeError("txn-mempool-conflict")
            replaced.append(old)
        for old in replaced:
            self.evict(old)
        self.fees[tx.txid()] = (fee, vsize)
        txid = super().sendrawtransaction(hx)
        for i in tx.inputs:
            self.spenders[(i.txid[::-1].hex(), i.vout)] = txid
        self.raw[txid] = hx
        return txid

    def getrawtransaction(self, txid, verbose=True):
        if not verbose and txid in self.raw:
            return self.raw[txid]
        return super().getrawtransaction(txid, verbose)

    def confirm_all(self):
        for txid, t in self.txs.items():
            if not self._held(txid):
                t["confirmations"] = max(t.get("confirmations", 0), 1)
        for k in [k for k, v in self.spenders.items() if not self._held(v) and k not in self.mined]:
            self.mined.add(k)

    def mine(self, n=1):
        """n blocks: every mempool tx and spend confirms."""
        self.height += n
        self.confirm_all()

    def evict(self, txid):
        """A mempool tx leaves the mempool (expired, or replaced by what the caller broadcasts next)."""
        for k in [k for k, v in self.spenders.items() if v == txid]:
            del self.spenders[k]
            self.spent.discard(k)
        self.txs.pop(txid, None)
        self.raw.pop(txid, None)

    def gettxout(self, txid, vout, include_mempool=True):
        if not include_mempool and (txid.lower(), vout) in self.mined:
            return None
        return super().gettxout(txid, vout, include_mempool)

    def estimatesmartfee(self, target):
        if self.feerate is None:
            return {"errors": ["Insufficient data or no feerate found"], "blocks": target}
        return {"feerate": self.feerate, "blocks": target}


def wait(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()
