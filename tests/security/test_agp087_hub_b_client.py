"""AGP-087 (second closure audit, area HUB-B): the B1 client around a FUNDED open the seller answers
with an error. review C2 was closed with a preflight, which is the seller's word. As xbt-rs
`crates/xbt402/tests/agp087_hub_b_client.rs` (same names). Each `test_hole_` FAILS on B1 21b21db.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.tx import address_to_spk  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"
OPEN_PATH = "/x402/xbt-channel/open"


def provider(node):
    key = int.from_bytes(hashlib.sha256(b"provider payTo").digest(), "big")
    return XbtChannelProvider(node, key, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: 150,
                              lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"answer": 1}'))


def serve(prov, method, url, body, headers):
    st, h, out = prov.serve(method, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)
    return st, {k.upper(): v for k, v in h.items()}, out


def client(node, http, **kw):
    def fund(addr, sats):
        txid = hashlib.sha256(f"funding {len(c.outs) + 1}".encode()).hexdigest()
        node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                          "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
        c.outs.append((txid, sats))
        return txid, 0
    c = XbtChannelClient(NET, fund, node.getblockcount, **kw)
    c.outs, c.http = [], http
    return c


def yes_then_no(prov):
    """The seller answers the preflight yes and the funded open 400."""
    def http(method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        req = json.loads(body) if body and path == OPEN_PATH else None
        if path == OPEN_PATH and not (req or {}).get("preflight"):
            return 400, {}, json.dumps({"error": "bad_funding", "detail": "no"}).encode()
        return serve(prov, method, url, body, headers)
    return http


class FundedOpenRefused(unittest.TestCase):
    def test_hole_c2_a_funded_open_answered_with_an_error_keeps_the_channel_key(self):
        node = FakeNode()
        c = client(node, yes_then_no(provider(node)))
        with self.assertRaises(ChannelError) as e:
            c.request("GET", O + "/v1/q")
        self.assertEqual(e.exception.code, "bad_funding")
        self.assertEqual(len(c.outs), 1, "the funded open is what was refused")
        txid, sats = c.outs[0]
        held = [ch for ch in c.channels.values() if ch.payer.params.funding_txid == txid]
        self.assertTrue(held, f"the client funded {sats} sat at {txid}:0 and holds no key and no refund for it")

    def test_hole_c2_a_seller_refusing_every_funded_open_is_funded_once(self):
        node = FakeNode()
        c = client(node, yes_then_no(provider(node)))
        for _ in range(8):
            try:
                c.request("GET", O + "/v1/q")
            except ChannelError:
                pass
        total = sum(s for _, s in c.outs)
        self.assertEqual(len(c.outs), 1, f"the seller's yes-then-no made the client fund {len(c.outs)} channels, "
                                         f"{total} sat, none of them on its books")

    def test_ok_c2_with_a_hook_the_refused_open_is_refundable_at_expiry(self):
        node = FakeNode()
        got = []
        c = client(node, yes_then_no(provider(node)), on_refund=lambda hx, exp: got.append((hx, exp)))
        with self.assertRaises(ChannelError):
            c.request("GET", O + "/v1/q")
        self.assertEqual(len(got), 1)
        self.assertIn(bytes.fromhex(c.outs[0][0])[::-1].hex(), got[0][0])

    def test_hole_c2_the_client_bounds_the_expiry_a_sellers_offer_asks_for(self):
        """Every number in the expiry a client funds is the seller's; the client has no ceiling of its own."""
        from xbt402.funding import FundingPolicy
        node = FakeNode()
        key = int.from_bytes(hashlib.sha256(b"slow seller").digest(), "big")
        prov = XbtChannelProvider(node, key, NET, tempfile.mktemp(suffix=".sqlite"), lambda m, p: 150,
                                  lambda m, p, b: (200, {"Content-Type": "application/json"}, b"{}"),
                                  policy=FundingPolicy(min_expiry_blocks=2_000_000, max_expiry_blocks=3_000_000, close_margin=144))
        c = client(node, lambda method, url, body=b"", headers=None: serve(prov, method, url, body, headers))
        try:
            c.request("GET", O + "/v1/q")
        except ChannelError:
            pass
        blocks = c.channels[O].payer.params.expiry - node.getblockcount() if O in c.channels else 0
        self.assertTrue(not c.outs or blocks <= 10 * c.expiry_blocks,
                        f"the client wanted {c.expiry_blocks} blocks and funded {c.outs and c.outs[0][1]} sat locked for "
                        f"{blocks} blocks (about {blocks // 52_560} years) on the seller's word")


if __name__ == "__main__":
    unittest.main()
