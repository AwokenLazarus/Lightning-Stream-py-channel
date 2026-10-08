"""In-process harness for the AGP-021 routing tests: a hub, providers and a RoutePayer wired through a
fake HTTP transport (each origin's `serve`) over sechelp's FakeNode. No sockets, no node."""
import json
import os
import secrets
import tempfile
import time

from sechelp import FakeNode

from xbt402 import ecc
from xbt402.funding import FundingPolicy
from xbt402.hub import RouteHub
from xbt402.route_client import RoutePayer
from xbt402.tx import Tx, address_to_spk
from xbt402.x402_channel import XbtChannelProvider

NET = "bip122:" + "11" * 16
HUB = "http://hub.test"


class RouteNode(FakeNode):
    """FakeNode plus what the hub's watcher reads: gettxspendingprevout and raw tx hex. A conflicting
    spend is refused unless it replaces a mempool spend by BIP125 (the old one signals, the new one pays
    its fee + 1 sat/vB more: AGP-044); blocks take only txs paying block_min_feerate sat/vB. It is also the
    hub's fund wallet (AGP-045): fund_address is a wallet send (listtransactions, gettransaction, which
    remembers a send after it left the mempool; `abandon` / `conflict` mark one that can never confirm)."""

    def __init__(self, height=1000):
        super().__init__(height)
        self.spenders, self.raw, self.mined = {}, {}, set()
        self.feerate = None               # estimatesmartfee's BTC/kvB (None: no estimate)
        self.fees = {}                    # txid -> (fee, vsize) of every broadcast tx
        self.block_min_feerate = 0.0
        self.wallet_txs = {}              # txid -> {address, vout: [...], abandoned, conflicted}

    def fee_of(self, txid):
        return self.fees.get(txid)

    def confirmed(self, txid):
        return self.txs.get(txid, {}).get("confirmations", 0) >= 1

    def _held(self, txid):
        f = self.fees.get(txid)
        return f is not None and f[0] < self.block_min_feerate * f[1]

    def fund_address(self, address, sats, confirmations=6):
        spk = address_to_spk(address, "bcrt")
        txid = os.urandom(32).hex()
        vout = [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": spk.hex()}}]
        self.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "vout": vout, "confirmations": confirmations}
        self.wallet_txs[txid] = {"address": address, "vout": vout, "abandoned": False, "conflicted": False}
        return txid, 0

    def listtransactions(self, label="*", count=10, skip=0, watchonly=False):
        return [{"category": "send", "address": w["address"], "txid": t, "amount": -w["vout"][0]["value"]}
                for t, w in self.wallet_txs.items()][skip:skip + count]

    def gettransaction(self, txid, watchonly=False, verbose=False):
        w = self.wallet_txs.get(txid)
        if w is None:
            raise RuntimeError("Invalid or non-wallet transaction id")
        conf = -1 if w["conflicted"] else self.txs.get(txid, {}).get("confirmations", 0)
        return {"txid": txid, "confirmations": conf,
                "details": [{"category": "send", "address": w["address"], "abandoned": w["abandoned"]}],
                **({"decoded": {"txid": txid, "vout": w["vout"]}} if verbose else {})}

    def getmempoolentry(self, txid):
        if self.txs.get(txid, {}).get("confirmations", 1) >= 1:
            raise RuntimeError("Transaction not in mempool")
        return {"vsize": 150}

    def abandon(self, txid):
        """The wallet gives up on a send that left the mempool (abandontransaction)."""
        self.evict(txid)
        self.wallet_txs[txid]["abandoned"] = True

    def conflict(self, txid):
        """A send double-spent by a confirmed tx: gettransaction confirmations -1."""
        self.evict(txid)
        self.wallet_txs[txid]["conflicted"] = True

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

    def gettxspendingprevout(self, outs):
        return [{"txid": o["txid"], "vout": o["vout"],
                 **({"spendingtxid": self.spenders[(o["txid"], o["vout"])]}
                    if (o["txid"], o["vout"]) in self.spenders else {})} for o in outs]

    def confirm_all(self):
        for txid, t in self.txs.items():
            if not self._held(txid):
                t["confirmations"] = max(t.get("confirmations", 0), 1)
        self.mined |= {k for k, v in self.spenders.items() if not self._held(v)}

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

    def scantxoutset(self, action, descs):
        want = {d[4:-1].lower() for d in descs if d.startswith("raw(")}
        return {"success": True, "unspents": [
            {"txid": t, "vout": o["n"], "amount": o["value"], "height": self.height}
            for t, tx in self.txs.items() if tx.get("confirmations", 0) >= 1
            for o in tx["vout"] if o["scriptPubKey"].get("hex", "").lower() in want and (t, o["n"]) not in self.spent]}

    def estimatesmartfee(self, target):
        if self.feerate is None:
            return {"errors": ["Insufficient data or no feerate found"], "blocks": target}
        return {"feerate": self.feerate, "blocks": target}


class Net:
    """origin -> app with serve(method, path, headers, body, url); `http` has XbtChannelClient.http's shape.
    `drop` maps an origin to a callable(method, path) -> True when the answer is lost after serving."""

    def __init__(self):
        self.apps, self.drop, self.calls = {}, {}, []

    def http(self, method, url, body=b"", headers=None):
        origin = "/".join(url.split("/")[:3])
        path = "/" + "/".join(url.split("/")[3:])
        app = self.apps.get(origin)
        if app is None:
            raise OSError(f"connection refused: {origin}")
        self.calls.append((method, origin, path))
        st, h, out = app.serve(method, path, dict(headers or {}), body or b"", url)
        dr = self.drop.get(origin)
        if dr and dr(method, path):
            raise OSError("answer lost")
        return st, {k.upper(): v for k, v in h.items()}, out


def provider(node, net, origin, secret=None, *, window=0.3, lock_wait=0.6, invoice_ttl=8.0,
             amsat_per_call=370 * 10 ** 18, settle_multiple=20, hubs="any", rollover_zero_conf_max=None,
             settle_lock_multiple=0, ledger=None):
    """`settle_lock_multiple` 0 (and the hub's, below): the settle floor (AGP-056) is off unless a test
    asks for it, so the older tests still roll over at exactly the provider's threshold."""
    secret = secret or secrets.randbelow(ecc.N - 1) + 1
    pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36)
    p = XbtChannelProvider(node, secret, NET, ledger or tempfile.mktemp(suffix=".sqlite"), lambda m, pth: 1000,
                           lambda m, pth, b: (200, {"Content-Type": "application/json"}, b'{"ok":1}'),
                           close_margin=36, policy=pol, settle_multiple=settle_multiple, height_ttl=0,
                           rollover_zero_conf_max=rollover_zero_conf_max, settle_lock_multiple=settle_lock_multiple)
    p.offer_route("/v1/chunk", window=window, lock_wait=lock_wait, invoice_ttl=invoice_ttl,
                  amsat_per_call=amsat_per_call, hubs=hubs)
    net.apps[origin] = p
    return p


def hub(node, net, secret=0x4B4B, **kw):
    d = tempfile.mkdtemp(prefix="hub-")
    opts = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
                reveal_timeout=1.0, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
                settle_lock_multiple=0, refill_ahead_locks=0,   # AGP-057 too: off unless a test asks for it
                policy=FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640,
                                     close_margin=36))
    opts.update({k: v for k, v in kw.items() if v is not None})
    h = RouteHub(node, secret, NET, d, node.fund_address, http=net.http, **opts)
    net.apps[HUB] = h
    return h


def payer(node, net, signer=None, **kw):
    from xbt402.signer import ChannelSigner
    signer = signer or ChannelSigner(fund=node.fund_address)
    return RoutePayer(HUB, NET, node.getblockcount, fund=node.fund_address, signer=signer, http=net.http,
                      **{"capacity": 200_000, "expiry_blocks": 8_000, **kw})


def world(n_providers=1, hkw=None, **pkw):
    """node, net, hub, providers {origin: provider}, payer (ch1 open), shards {origin: Shard}."""
    node, net = RouteNode(), Net()
    h = hub(node, net, **(hkw or {}))
    provs = {}
    for i in range(n_providers):
        origin = f"http://p{i}.test"
        provs[origin] = provider(node, net, origin, **pkw)
        h.connect(origin)
    node.confirm_all()
    h.watch_tick()
    pay = payer(node, net)
    pay.open()
    shards = {o: pay.shard(o + "/v1/chunk") for o in provs}
    return node, net, h, provs, pay, shards


def stream(pay, sh, n):
    for _ in range(n):
        st, _, _ = pay.call(sh, "POST", b'{"tokens":1}')
        assert st == 200, st


def route_request(pay, sh, *, tamper=None):
    """Build the client's POST /x402/route exactly as RoutePayer.lock does, let `tamper(pl, route)` edit
    it, re-authenticate unless tamper returns "noauth", and send it. Returns (status, doc)."""
    from dataclasses import asdict
    from xbt402.route import fee_due, lock_auth, next_cum
    from xbt402.x402_channel import b64json
    inv = dict(sh.invoice)
    d = max(1, sh.due_sat())
    f, _ = fee_due(pay.quote, d, pay.fee_units, pay.fee_paid)
    cum = next_cum(pay.routed, d + f, pay.ch.payer.params.min_amount)
    sa = pay.signer.sign_state_adaptor(pay.chan, cum, inv["point"])
    route = {"provider": sh.origin, "payTo": sh.pay_to, "network": NET, "amount": d, "point": inv["point"],
             "fee": f, "feeQuote": asdict(pay.quote), "invoice": inv, "session": sh.session, "lockId": inv["lockId"],
             "lockAuth": lock_auth(sh.key, sh.session, inv["lockId"], d, inv["point"], pay.hub_pay_to),
             "tweak": sa["tweak"]}
    pl = {"chan": pay.chan, "seq": 0, "cum": str(cum), "adaptor": sa["adaptor"], "point": sa["point"]}
    mode = tamper(pl, route) if tamper else None
    pay.ch.seq += 1
    pl["seq"] = pay.ch.seq
    body = json.dumps({"route": route}).encode()
    pay.cc._auth(pay.ch, pl, "POST", HUB + "/x402/route", body)
    if mode == "noauth":
        pl["auth"] = "00" * 32
    st, _, raw = pay.http("POST", HUB + "/x402/route", body,
                          {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": pay.ch.accepted, "payload": pl})})
    pay.signer.void_lock(pay.chan)
    return st, json.loads(raw)


def wait(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()
