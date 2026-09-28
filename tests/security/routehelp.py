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
    """FakeNode plus what the hub's watcher reads: gettxspendingprevout and raw tx hex."""

    def __init__(self, height=1000):
        super().__init__(height)
        self.spenders, self.raw = {}, {}

    def fund_address(self, address, sats, confirmations=6):
        spk = address_to_spk(address, "bcrt")
        txid = os.urandom(32).hex()
        self.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}],
                          "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": spk.hex()}}],
                          "confirmations": confirmations}
        return txid, 0

    def sendrawtransaction(self, hx):
        txid = super().sendrawtransaction(hx)
        tx = Tx.parse(bytes.fromhex(hx))
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
        for t in self.txs.values():
            t["confirmations"] = max(t.get("confirmations", 0), 1)


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
             amsat_per_call=370 * 10 ** 18, settle_multiple=20, hubs="any"):
    secret = secret or secrets.randbelow(ecc.N - 1) + 1
    pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36)
    p = XbtChannelProvider(node, secret, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, pth: 1000,
                           lambda m, pth, b: (200, {"Content-Type": "application/json"}, b'{"ok":1}'),
                           close_margin=36, policy=pol, settle_multiple=settle_multiple, height_ttl=0)
    p.offer_route("/v1/chunk", window=window, lock_wait=lock_wait, invoice_ttl=invoice_ttl,
                  amsat_per_call=amsat_per_call, hubs=hubs)
    net.apps[origin] = p
    return p


def hub(node, net, secret=0x4B4B, **kw):
    d = tempfile.mkdtemp(prefix="hub-")
    opts = dict(fee_base_msat=100, fee_ppm=2_000, max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36,
                reveal_timeout=1.0, ch2_capacity=100_000, ch2_expiry_blocks=1_000, close_margin=36,
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


def world(n_providers=1, **pkw):
    """node, net, hub, providers {origin: provider}, payer (ch1 open), shards {origin: Shard}."""
    node, net = RouteNode(), Net()
    h = hub(node, net)
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
    cum = next_cum(pay.routed, d + f)
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
    pay.cc._auth(pay.ch, pl, "POST", "/x402/route", body)
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
