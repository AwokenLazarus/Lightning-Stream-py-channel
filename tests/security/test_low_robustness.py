"""Low findings: malformed input escapes as uncaught exceptions; a refused call's new state is not
persisted; a re-sent state in upper-case hex is refused."""
import json
import unittest

from sechelp import FakeNode, Repro, base, make_channel, make_provider, pay
ch, ecc, xc = base("channel"), base("ecc"), base("x402_channel")   # unpatched wave 2: the repro tests


class Low(Repro, unittest.TestCase):
    def test_repro_l1_malformed_json_types_escape(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p, _ = make_channel(ch, prov, node)
        escaped = []
        hdr = xc.b64json({"x402Version": 2, "accepted": prov.requirements(150), "payload": [p.channel_id]})
        for call in (lambda: prov.serve("GET", "/v1/x", {"PAYMENT-SIGNATURE": hdr}, b""),
                     lambda: prov.serve("POST", "/x402/xbt-channel/open", {}, json.dumps({
                         "network": prov.network, "channel": {"payerPub": ecc.pubkey(5).hex(), "expiry": -1,
                                                              "redeemScript": "", "txid": "", "vout": 0,
                                                              "capacity": 1}}).encode())):
            try:
                call()
            except Exception as e:  # noqa: BLE001
                escaped.append(type(e).__name__)
        self.reproduces(escaped == ["AttributeError", "OverflowError"],
                        f"{escaped} escaped serve(): the HTTP thread drops the connection, no 400/402")

    def test_repro_l2_state_on_refused_call_not_persisted(self):
        node = FakeNode()
        prov = make_provider(xc, node, billing="prepay")
        p, payer = make_channel(ch, prov, node)
        pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "600", "sig": payer.sign_state(600).hex()})
        for s in range(2, 5):
            pay(xc, prov, {"chan": p.channel_id, "seq": s, "cum": "600"})
        # 600 sat covered 4 calls; a higher state that still does not cover the 5th is accepted, then refused
        err = pay(xc, prov, {"chan": p.channel_id, "seq": 5, "cum": "700", "sig": payer.sign_state(700).hex()})[1]
        on_disk = xc.Ledger(prov.ledger.path).channels[p.channel_id].best_cum
        self.reproduces(err == "insufficient_payment" and prov.ledger.channels[p.channel_id].best_cum == 700
                        and on_disk == 600, "the 700-sat state lives only in memory: a restart loses it")

    def test_repro_l5_uppercase_resend_refused(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p, payer = make_channel(ch, prov, node)
        sig = payer.sign_state(20_000).hex()
        pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": sig})
        self.reproduces(pay(xc, prov, {"chan": p.channel_id, "seq": 2, "cum": "20000", "sig": sig.upper()})[1] == "bad_sig",
                        "the same state in upper-case hex is refused as bad_sig")


if __name__ == "__main__":
    unittest.main()
