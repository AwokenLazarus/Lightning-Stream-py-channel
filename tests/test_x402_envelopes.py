"""xbt402 v1.1 wire envelopes (AGP-004): PAYMENT-RESPONSE is an x402 v2 SettlementResponse carrying the
signed channel receipt in `extra`, and the facilitator endpoints take {x402Version, paymentPayload,
paymentRequirements} and answer VerifyResponse / SettlementResponse."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "security"))

from sechelp import PRICE, FakeNode, authed, make_channel, make_provider  # noqa: E402
from xbt402 import channel as cp  # noqa: E402
from xbt402 import ecc  # noqa: E402
from xbt402 import x402_channel as xp  # noqa: E402
from xbt402.tx import Tx  # noqa: E402

A = 0xA11CE


class Envelopes(unittest.TestCase):
    def setUp(self):
        self.node = FakeNode()
        self.prov = make_provider(xp, self.node, billing="prepay")
        self.p, self.payer = make_channel(cp, self.prov, self.node, a=A)
        self.acc = self.prov.requirements(PRICE)

    def paid(self, seq=1, cum=1000, path="/v1/x"):
        pl = {"chan": self.p.channel_id, "seq": seq, "cum": str(cum)}
        if cum > self.payer.signed:
            pl["sig"] = self.payer.sign_state(cum).hex()
        pl = authed(xp, cp, self.payer, self.p.payee_pub, pl, path=path)
        hdr = xp.b64json({"x402Version": 2, "accepted": self.acc, "payload": pl})
        return self.prov.serve("GET", path, {"PAYMENT-SIGNATURE": hdr}, b"")

    def facilitator(self, path, body):
        st, _, out = self.prov.serve("POST", path, {}, json.dumps(body).encode())
        return st, json.loads(out)

    def test_payment_response_is_a_settlement_response(self):
        st, h, _ = self.paid()
        self.assertEqual(st, 200)
        resp = xp.unb64json(h["PAYMENT-RESPONSE"])
        self.assertEqual(set(resp), {"success", "transaction", "network", "payer", "amount", "extra"})
        self.assertEqual((resp["success"], resp["transaction"], resp["amount"]), (True, "", ""))
        self.assertEqual((resp["network"], resp["payer"]), (self.prov.network, self.p.payer_pub))
        r = xp.receipt_of(resp)
        self.assertEqual(resp["extra"]["chargedAmount"], r["charged"])
        self.assertEqual(set(r), {"scheme", "chan", "seq", "cum", "charged", "spentMsat", "owedMsat",
                                  "creditMsat", "expiry", "req", "sig"})
        self.assertEqual((r["scheme"], r["chan"], r["charged"]), ("batch-settlement", self.p.channel_id, str(PRICE)))
        self.assertTrue(ecc.verify(bytes.fromhex(self.p.payee_pub), xp.receipt_message(r), bytes.fromhex(r["sig"])))

    def test_client_checks_the_envelope(self):
        _, h, _ = self.paid()
        good = xp.unb64json(h["PAYMENT-RESPONSE"])
        client = xp.XbtChannelClient(self.prov.network, None, lambda: 1000)
        ch = xp.ClientChannel(self.payer, "http://api.test", self.acc, price=PRICE)
        client._receipt(ch, good, "GET", "/v1/x", b"")
        self.assertEqual(ch.receipts[-1], good["extra"]["receipt"])
        for tamper in (lambda d: d["extra"].__setitem__("chargedAmount", "1"),
                       lambda d: d.__setitem__("network", "bip122:" + "00" * 16),
                       lambda d: d.__setitem__("payer", ecc.pubkey(7).hex()),
                       lambda d: d["extra"].pop("receipt"),
                       lambda d: d["extra"]["receipt"].__setitem__("charged", "1"),     # breaks the signature
                       lambda d: d.update(good["extra"]["receipt"]) or d.pop("extra")):  # the v1.0 shape
            bad = json.loads(json.dumps(good))
            tamper(bad)
            with self.assertRaises(cp.ChannelError) as err:
                client._receipt(ch, bad, "GET", "/v1/x", b"")
            self.assertEqual(err.exception.code, "bad_receipt")

    def test_verify_takes_and_answers_x402_shapes(self):
        sig = self.payer.sign_state(2000).hex()
        pl = {"chan": self.p.channel_id, "cum": "2000", "sig": sig}
        st, out = self.facilitator(xp.FACILITATOR_VERIFY, xp.facilitator_request(self.acc, pl))
        self.assertEqual((st, out), (200, {"isValid": True, "payer": self.p.payer_pub,
                                           "extra": {"chan": self.p.channel_id, "cum": "2000"}}))
        self.assertEqual(self.prov.ledger.channels[self.p.channel_id].best_cum, 2000)
        cases = [({"payload": pl}, "invalid_batch_settlement_xbt_payload"),                       # the v1.0 body
                 ({**xp.facilitator_request(self.acc, pl), "x402Version": 1}, "invalid_batch_settlement_xbt_payload"),
                 (xp.facilitator_request({**self.acc, "scheme": "exact"}, pl), "invalid_batch_settlement_xbt_scheme_or_network"),
                 (xp.facilitator_request({**self.acc, "network": "bip122:" + "00" * 16}, pl),
                  "invalid_batch_settlement_xbt_scheme_or_network"),
                 (xp.facilitator_request({**self.acc, "payTo": ecc.pubkey(7).hex()}, pl),
                  "invalid_batch_settlement_xbt_scheme_or_network"),
                 (xp.facilitator_request(self.acc, {**pl, "chan": "ab" * 32 + ":9"}), "invalid_batch_settlement_xbt_unknown_channel"),
                 (xp.facilitator_request(self.acc, {**pl, "cum": "2001"}), "invalid_batch_settlement_xbt_signature")]
        for body, reason in cases:
            self.assertEqual(self.facilitator(xp.FACILITATOR_VERIFY, body), (200, {"isValid": False, "invalidReason": reason}))
        # paymentRequirements is right but the payload's own `accepted` names another payTo
        body = xp.facilitator_request(self.acc, pl)
        body["paymentPayload"]["accepted"] = {**self.acc, "payTo": ecc.pubkey(7).hex()}
        self.assertEqual(self.facilitator(xp.FACILITATOR_VERIFY, body)[1]["invalidReason"],
                         "invalid_batch_settlement_xbt_scheme_or_network")

    def test_settle_answers_a_settlement_response(self):
        self.assertEqual(self.paid(cum=1000)[0], 200)
        close = {"chan": self.p.channel_id, "sig": ecc.sign(A, xp.close_message(self.p.channel_id)).hex()}
        st, out = self.facilitator(xp.FACILITATOR_SETTLE, xp.facilitator_request(
            self.acc, {**close, "sig": ecc.sign(0xBAD, xp.close_message(self.p.channel_id)).hex()}))
        self.assertEqual((st, out), (200, {"success": False, "errorReason": "invalid_batch_settlement_xbt_signature",
                                           "transaction": "", "network": self.prov.network}))
        st, out = self.facilitator(xp.FACILITATOR_SETTLE, xp.facilitator_request(self.acc, close))
        txid = self.prov.ledger.channels[self.p.channel_id].closed_txid
        self.assertEqual((st, out), (200, {"success": True, "transaction": txid, "network": self.prov.network,
                                           "payer": self.p.payer_pub, "amount": "1000",
                                           "extra": {"chan": self.p.channel_id, "unpaidMsat": "0"}}))
        self.assertEqual(Tx.parse(bytes.fromhex(self.node.sent[-1])).txid(), txid)

    def test_supported_lists_the_kind_with_its_version(self):
        st, _, out = self.prov.serve("GET", xp.FACILITATOR_SUPPORTED, {}, b"")
        self.assertEqual((st, json.loads(out)), (200, {
            "kinds": [{"x402Version": 2, "scheme": "batch-settlement", "network": self.prov.network}],
            "extensions": [], "signers": {}}))

    def test_upstream_codes(self):
        self.assertEqual(xp.upstream_code("bad_sig"), "invalid_batch_settlement_xbt_signature")
        self.assertEqual(xp.upstream_code("insufficient_payment"), "invalid_batch_settlement_xbt_insufficient_payment")
        self.assertEqual(xp.upstream_code("wrong_network"), "invalid_network")
        self.assertEqual(xp.upstream_code("close_failed"), "unexpected_settle_error")

    def test_xbt_channel_alias_accepted_on_input(self):
        """One-release alias: a PAYMENT-SIGNATURE that still names scheme xbt-channel is accepted."""
        acc = dict(self.acc)
        acc["scheme"] = "xbt-channel"
        pl = {"chan": self.p.channel_id, "seq": 1, "cum": "1000", "sig": self.payer.sign_state(1000).hex()}
        pl = authed(xp, cp, self.payer, self.p.payee_pub, pl, path="/v1/alias")
        hdr = xp.b64json({"x402Version": 2, "accepted": acc, "payload": pl})
        st, h, _ = self.prov.serve("GET", "/v1/alias", {"PAYMENT-SIGNATURE": hdr}, b"")
        self.assertEqual(st, 200)
        resp = xp.unb64json(h["PAYMENT-RESPONSE"])
        self.assertEqual(xp.receipt_of(resp)["scheme"], "batch-settlement")
        self.assertEqual(self.acc["extra"]["assetTransferMethod"], "channel")
        self.assertTrue(xp.scheme_accepted("xbt-channel") and xp.scheme_accepted("batch-settlement"))
        self.assertFalse(xp.scheme_accepted("exact"))


if __name__ == "__main__":
    unittest.main()
