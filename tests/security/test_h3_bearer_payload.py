"""H3 (High) state replay within a channel: the payment payload is a bearer token.

v1 needs no signature when `cum` repeats the stored value, binds nothing to the request, and a 402
tells anyone who names a channel its `cum`. A third party who learns a channel id (logs, a proxy,
a captured header) spends the payer's prepaid credit or replays a captured header, and the payer's
own client later pays for any unreceipted call without complaint (it allows one call of slack).

Wave 2 adds two more bearer paths: the facilitator POST /verify answers anyone who names a channel
(its stale_amount error reads "have <cum>"), and a hash-locked payload is never checked against the
request, so a captured one is served the deliverable again and billed to the payer each time.
"""
import json
import unittest

from sechelp import FakeNode, PRICE, Repro, authed, base, load, make_channel, make_provider, pay
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests


class BearerPayload(Repro, unittest.TestCase):
    def test_repro_stranger_spends_prepaid_credit(self):
        node = FakeNode()
        prov = make_provider(xc, node, billing="prepay")
        p, payer = make_channel(ch, prov, node)
        # the payer prepays 20 calls and makes one
        assert pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "3000", "sig": payer.sign_state(3000).hex()})[0] == 200
        # a stranger knows only the channel id: probe for the cum, then spend
        _, err, body = pay(xc, prov, {"chan": p.channel_id, "cum": "0"})
        cum = body["channel"]["cum"]
        stolen = sum(pay(xc, prov, {"chan": p.channel_id, "cum": cum})[0] == 200 for _ in range(50))
        self.reproduces(err == "stale_amount" and stolen == 19,
                        f"402 leaked cum={cum}; a stranger with no key took {stolen} of the payer's 20 prepaid calls")

    def test_repro_captured_header_replays(self):
        node = FakeNode()
        prov = make_provider(xc, node, billing="prepay")
        p, payer = make_channel(ch, prov, node)
        captured = {"chan": p.channel_id, "seq": 1, "cum": "3000", "sig": payer.sign_state(3000).hex()}
        replays = sum(pay(xc, prov, captured)[0] == 200 for _ in range(20))
        self.reproduces(replays == 20, "one captured PAYMENT-SIGNATURE header was served 20 times")

    def test_fixed_needs_request_auth_and_fresh_seq(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node, billing="prepay")
        p, payer = make_channel(cp, prov, node)
        good = authed(xp, cp, payer, p.payee_pub,
                      {"chan": p.channel_id, "seq": 1, "cum": "3000", "sig": payer.sign_state(3000).hex()})
        self.assertEqual(pay(xp, prov, good)[0], 200)
        st, err, body = pay(xp, prov, {"chan": p.channel_id, "seq": 99, "cum": "0"})
        self.assertEqual(err, "bad_auth")
        self.assertNotIn("channel", body)                              # nothing leaked
        self.assertEqual(pay(xp, prov, good)[1], "bad_auth")           # captured header: seq is used
        other = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": 2, "cum": "3000"}, path="/v1/a")
        self.assertEqual(pay(xp, prov, other, path="/v1/b")[1], "bad_auth")   # bound to the request
        wrong_key = dict(other, auth=xp.request_auth(b"\x00" * 32, p.channel_id, 2, "3000", None,
                                                     xp.request_digest_v2("GET", "/v1/a", b"")))
        self.assertEqual(pay(xp, prov, wrong_key, path="/v1/a")[1], "bad_auth")
        self.assertEqual(pay(xp, prov, other, path="/v1/a")[0], 200)
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 2 * PRICE * 1000)


    def test_repro_facilitator_verify_leaks_cum(self):
        node = FakeNode()
        prov = make_provider(xc, node, billing="prepay")
        p, payer = make_channel(ch, prov, node)
        pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "3000", "sig": payer.sign_state(3000).hex()})
        st, _, out = prov.serve("POST", "/verify", {}, json.dumps({"chan": p.channel_id, "cum": "0"}).encode())
        self.reproduces(st == 400 and "have 3000" in json.loads(out)["detail"],
                        "POST /verify told a stranger the channel's cum (then spend it as above)")

    def test_repro_hashlock_payload_replays(self):
        node = FakeNode()
        prov = make_provider(xc, node)
        p, payer = make_channel(ch, prov, node, a=0xA11CE)
        h, _, _ = prov.offer_conditional("/v1/secret", 600, b"deliverable")
        cond = cond_mod(ch).ConditionalParams(p, h, 600)
        sig = (ch.ecc.sign(0xA11CE, cond.sighash(cond.state_tx(0))) + b"\x21").hex()
        captured = {"chan": p.channel_id, "seq": 1, "cum": "0", "hashlock": h.hex(), "sig": sig}
        served = sum(pay(xc, prov, captured, path="/v1/secret")[0] == 200 for _ in range(5))
        spent = prov.ledger.channels[p.channel_id].spent_msat
        self.reproduces(served == 5 and spent == 5 * 600_000,
                        f"one captured hash-locked header served the deliverable {served} times, "
                        f"billing the payer {spent // 1000} sat for one 600-sat increment")

    def test_fixed_facilitator_verify_needs_a_signed_state(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node, billing="prepay")
        p, payer = make_channel(cp, prov, node)
        sig3 = payer.sign_state(3000).hex()
        self.assertEqual(pay(xp, prov, authed(xp, cp, payer, p.payee_pub,
                                              {"chan": p.channel_id, "seq": 1, "cum": "3000", "sig": sig3}))[0], 200)
        acc = prov.requirements(150)
        for req in ({"chan": p.channel_id, "cum": "0"}, {"chan": p.channel_id, "cum": "3000", "seq": 10**9}):
            st, _, out = prov.serve("POST", xp.FACILITATOR_VERIFY, {}, json.dumps(xp.facilitator_request(acc, req)).encode())
            self.assertEqual((st, json.loads(out)), (200, {"isValid": False, "invalidReason": "invalid_batch_settlement_xbt_signature"}))
        st, _, out = prov.serve("POST", xp.FACILITATOR_VERIFY, {}, json.dumps(xp.facilitator_request(
            acc, {"chan": p.channel_id, "cum": "3000", "sig": sig3, "seq": 10**9})).encode())
        self.assertEqual((st, json.loads(out)["isValid"]), (200, True))
        self.assertEqual(prov.ledger.channels[p.channel_id].seq, 1)          # /verify never moves seq
        self.assertEqual(pay(xp, prov, authed(xp, cp, payer, p.payee_pub,
                                              {"chan": p.channel_id, "seq": 2, "cum": "3000"}))[0], 200)

    def test_fixed_hashlock_payload_needs_auth(self):
        xp, cp = load("x402_channel"), load("channel")
        node = FakeNode()
        prov = make_provider(xp, node)
        p, payer = make_channel(cp, prov, node, a=0xA11CE)
        h, _, _ = prov.offer_conditional("/v1/secret", 600, b"deliverable")
        cond = cond_mod(cp).ConditionalParams(p, h, 600)
        sig = (cp.ecc.sign(0xA11CE, cond.sighash(cond.state_tx(0))) + b"\x21").hex()
        pl = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": 1, "cum": "0", "hashlock": h.hex(),
                                                 "sig": sig}, path="/v1/secret")
        self.assertEqual(pay(xp, prov, pl, path="/v1/secret")[0], 200)
        self.assertEqual([pay(xp, prov, pl, path="/v1/secret")[1] for _ in range(4)], ["bad_auth"] * 4)
        self.assertEqual(prov.ledger.channels[p.channel_id].spent_msat, 600_000)


def cond_mod(channel_mod):
    import importlib
    return importlib.import_module(channel_mod.__name__.rsplit(".", 1)[0] + ".conditional")


if __name__ == "__main__":
    unittest.main()
