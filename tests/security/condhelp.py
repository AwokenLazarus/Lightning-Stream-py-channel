"""Shared rig for the AGP-005 review of v1.1's hash-locked conditional calls (M6 close + claim).

`Rig` is a provider with a conditional offer on /v1/cond and a client whose HTTP goes straight into
provider.serve. Switches model a payer that withholds its fold (`fold = False`) and a network (or a
provider) that drops the paid conditional response (`drop_cond_response = True`).
"""
import json
import os

from sechelp import FakeNode, make_provider

PLAIN = b"the deliverable"
COND_PRICE = 1000
ORIGIN = "http://api.test"


class Rig:
    def __init__(self, xm, node=None, cond_price=COND_PRICE, max_price=1_000, capacity=200_000, **kw):
        self.xm, self.node = xm, node or FakeNode()
        self.prov = make_provider(xm, self.node)
        self.prov.offer_conditional("/v1/cond", cond_price, PLAIN)
        self.fold, self.drop_cond_response, self.log = True, False, []
        self.client = xm.XbtChannelClient(self.prov.network, fund=lambda a, s: (os.urandom(32).hex(), 0),
                                          height=self.node.getblockcount, capacity=capacity,
                                          max_price=max_price,
                                          on_open=lambda ch: self.node.add_funding(ch.payer.params), **kw)
        self.client.http = self.http

    def http(self, method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        if not self.fold and path == "/x402/verify":
            return 503, {}, b'{"error": "withheld"}'
        st, h, out = self.prov.serve(method, path, headers or {}, body or b"", url)
        self.log.append((path, st, out))
        if self.drop_cond_response and path == "/v1/cond" and "PAYMENT-SIGNATURE" in (headers or {}):
            return 504, {}, b""                  # served and signed for, but the answer never arrives
        return st, {k.upper(): v for k, v in h.items()}, out

    @property
    def chan(self):
        return next(iter(self.prov.ledger.channels.values()))

    @property
    def cch(self):
        return self.client.channels[ORIGIN]

    def offer(self, path="/v1/cond"):
        st, h, out = self.prov.serve("GET", path, {}, b"")
        return json.loads(out)["accepts"][0]

    def close_at_margin(self):
        self.node.height = self.chan.params.expiry - self.prov.close_margin
        return self.prov.close_due()


def outputs(hx):
    from xbt402.tx import Tx
    return Tx.parse(bytes.fromhex(hx)).outputs


def spends(hx, txid):
    from xbt402.tx import Tx
    return any(i.txid[::-1].hex() == txid for i in Tx.parse(bytes.fromhex(hx)).inputs)
