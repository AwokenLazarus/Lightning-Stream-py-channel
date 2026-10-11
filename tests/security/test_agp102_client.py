"""AGP-102 fourth closure audit, CLIENT area, B1: tests written by the auditor against fix wave 5
(AGP-096, AGP-101). As xbt-rs `crates/xbt402/tests/agp102_client.rs` (same names where B1 has the
code). No fix is in this file.

`test_hole_*` fail today and state the rule that should hold. `test_control_*` are the honest path
in the same rig and `test_limit_*` pin a number a reader must be told; both pass.

  cd tests/security && ~/xbt-rnd/b1/.venv/bin/python -B -m unittest test_agp102_client
"""
import json
import os
import socket
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from test_agp093_client import O, OPEN_PATH, PRICE, Rig, paid  # noqa: E402
from xbt402 import x402_channel as xc  # noqa: E402
from xbt402.channel import ChannelError  # noqa: E402


def forger(s):
    """The seller of test_limit_two_forged_refusals_end_the_channel: the provider serves and charges,
    and the payer is shown a bare 402, s["forge"] times."""
    def edit(path, req, headers, forward):
        st, h, out = forward()
        if st == 402:
            s["last"] = xc.unb64json(h["PAYMENT-REQUIRED"])
        if paid(path, headers) and st == 200 and s["forge"]:
            s["forge"] -= 1
            pr = json.loads(json.dumps(s["last"]))
            pr.pop("channel", None)
            return 402, {"PAYMENT-REQUIRED": xc.b64json(pr)}, b""
        return st, h, out
    return edit


class ForgedRefusal(unittest.TestCase):
    def twice(self):
        s = {"forge": 0, "last": None}
        r = Rig(forger(s))
        self.assertEqual([r.get() for _ in range(4)], [200] * 4)
        s["forge"] = 1
        self.assertEqual((r.get(), r.get()), (402, 200))
        self.assertEqual([r.get() for _ in range(2)], [200] * 2)
        s["forge"] = 1
        self.assertEqual((r.get(), r.get()), (402, "bad_offer"))
        return r

    def test_hole_after_the_close_that_follows_two_forged_refusals_the_next_call_opens_a_new_channel(self):
        """HOLE (Low; a public sentence that is not true of the library). AGP-101's sentence says that
        at the second forged refusal the payer "closes the channel at what it signed and opens
        another". The client does neither by itself: every call is bad_offer until the embedder calls
        close(), and close() leaves the closed channel on the book as "open", so every call after it
        is refused too, until the embedder also deletes the record."""
        r = self.twice()
        chan = r.c.channels[O].payer.params.channel_id
        self.assertFalse(r.prov.ledger.channels[chan].closed_txid, "control: the client closed nothing by itself")
        r.c.close(O)
        after = [r.get() for _ in range(3)]
        self.assertIn(200, after, f"after the close every call is still refused: {after}; the book still holds "
                                  f"{r.c.channels[O].payer.params.channel_id} at stage {r.c.channels[O].stage!r}, "
                                  f"{len(r.sends)} channel(s) funded")

    def test_control_after_the_close_and_the_embedder_removing_the_record_the_next_call_opens_a_new_channel(self):
        r = self.twice()
        r.c.close(O)
        del r.c.channels[O]
        self.assertEqual((r.get(), len(r.sends)), (200, 2))


class BareWallet(unittest.TestCase):
    def test_limit_a_fund_that_raises_after_it_sent_pays_one_script_on_every_retry_past_the_budget(self):
        """LIMIT (AGP-101 found-not-fixed 1 and AGP-096 stated limit 4, with their numbers; the same
        in xbt-rs for a wallet that cannot list its sends). `fund` is a bare callable: when it raises
        after it sent, every retry inside the 72-block window pays the SAME script again, and the
        budget counts none of it (opened_sats grows only when `fund` returns). Six such calls send
        1,200,000 sat under a budget of 1,000,000 and the book says 0. With and without a
        ChannelSigner. The seller cannot cause it; the owner's own wallet does."""
        for signer in (False, True):
            r = Rig(signer=signer) if signer else Rig()
            real = r.fund
            state = {"fail": True}

            def fund(addr, sats):
                out = real(addr, sats)
                if state["fail"]:
                    raise ChannelError("wallet_error", "timed out after the broadcast")
                return out
            r.c.fund = fund
            if signer:
                r.c.signer.fund = fund
            self.assertEqual(r.c.budget_sats, 1_000_000)
            for _ in range(6):
                self.assertEqual(r.get(), "wallet_error")
                r.node.height += 10
            self.assertEqual((len(r.sends), len({s[1] for s in r.sends}), sum(s[2] for s in r.sends), r.c.opened_sats),
                             (6, 1, 1_200_000, 0), f"signer {signer}: six sends to one script, none in the budget's count")
            self.assertEqual((r.c.channels[O].stage, r.c.channels[O].refund_hex), ("keyed", ""))
            state["fail"] = False
            self.assertEqual((r.get(), len(r.sends), r.c.opened_sats), (200, 7, 200_000), f"signer {signer}")


class Origin(unittest.TestCase):
    def test_limit_what_the_canonical_origin_unifies(self):
        one = lambda u: xc.split_url(u)[0]   # noqa: E731
        for u in ["https://api.example/x", "HTTPS://API.Example/x", "https://api.example:443/x", "https://api.example:0443/x",
                  "https://api.example:/x", "https://u:p@api.example/x", "https://api.example?x"]:
            self.assertEqual(one(u), "https://api.example", u)
        for u, key in [("https://api.example./x", "https://api.example."), ("https://%61pi.example/x", "https://%61pi.example"),
                       ("http://127.1/x", "http://127.1"), ("http://2130706433/x", "http://2130706433"),
                       ("http://0x7f.0.0.1/x", "http://0x7f.0.0.1"), ("http://[0:0:0:0:0:0:0:1]/x", "http://[0:0:0:0:0:0:0:1]")]:
            self.assertEqual(one(u), key, u)
        # B1's own transport (urllib) reads a backslash before an "@" as part of the userinfo, as the
        # book does: the Rust transport does not (xbt-rs agp102_client.rs, the Medium hole there)
        import urllib.parse
        url = "http://127.0.0.1:27760\\@127.0.0.1:27761/v1/q"
        p = urllib.parse.urlsplit(url)
        self.assertEqual((one(url), f"http://{p.hostname}:{p.port}"), ("http://127.0.0.1:27761", "http://127.0.0.1:27761"))

    def test_hole_a_refusing_seller_is_funded_once_however_its_host_is_spelled(self):
        """HOLE (Low, left from before; AGP-096 fixed the five spellings the audit named). The number
        forms of an IPv4 address reach one server (the resolver reads them as the transport's connect
        does) and are four keys in the book: a seller that refuses every funded open is funded once
        per spelling, up to budget_sats. A trailing dot on a name is the same case."""
        def edit(path, req, headers, forward):
            if path == OPEN_PATH and not (req or {}).get("preflight"):
                return 400, {}, json.dumps({"error": "bad_funding", "detail": "no"}).encode()
            return forward()
        r = Rig(edit)
        hosts = ["127.0.0.1", "127.1", "2130706433", "0x7f.0.0.1"]
        self.assertEqual({socket.gethostbyname(h) for h in hosts}, {"127.0.0.1"}, "control: one host, as the transport connects")
        for h in hosts:
            with self.assertRaises(ChannelError) as e:
                r.c.request("GET", f"http://{h}:8402/v1/q")
            self.assertEqual(e.exception.code, "bad_funding", h)
        self.assertEqual(len(r.sends), 1, f"one seller, {len(r.sends)} channels funded ({r.c.opened_sats} sat): "
                                          f"{sorted(r.c.channels)}")


if __name__ == "__main__":
    unittest.main()
