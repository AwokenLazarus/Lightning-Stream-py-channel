"""M7 (Medium) the hash lock is not a fair exchange: the ciphertext arrives only after the payer signs.

A conditional call's 402 carried only `H` and the amount. The payer signed the hash-locked state
first and got the ciphertext and k together, in the paid response. Before AGP-001 that signature was
harmless to the payer (nothing closed with it). Since M6's fix the provider closes with it and claims
the hash lock with k whether or not the payer ever received the answer: a provider that drops the
response (or a response lost on the way) is paid condAmount, and the payer learns k from the claim's
witness with nothing to decrypt. The spec (6.5) promises payment "atomically with a secret".

Fix: the 402 carries the ciphertext (`extra.conditional.cipher`), and the client refuses a
conditional offer without one, before signing. Whatever happens to the paid response, k then
reaches the payer either off-chain or in the claim's witness, and `recover_conditional` decrypts the
ciphertext it already holds (`conditional.preimage_from_tx`). A response whose ciphertext differs from
the one offered is ignored in favour of the offered one. Since the ciphertext is now public and a claim
publishes k, the provider offers each path under a fresh k after every sale.
"""
import json
import unittest

from condhelp import ORIGIN, PLAIN, COND_PRICE, Rig, spends
from sechelp import V11, Repro, load, v11
from xbt402.tx import Tx


def withheld(xm):
    r = Rig(xm)
    r.client.request("GET", ORIGIN + "/v1/x")
    r.drop_cond_response = True
    try:
        r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        got = True
    except Exception:  # noqa: BLE001 - the answer never came
        got = False
    r.close_at_margin()
    return r, got


class CipherFirst(Repro, unittest.TestCase):
    REPRO_BASE = V11

    def test_repro_provider_paid_payer_has_no_ciphertext(self):
        r, got = withheld(v11("x402_channel"))
        cond = r.offer()["extra"]["conditional"]
        close_txid = r.chan.closed_txid
        claims = [hx for hx in r.node.sent if spends(hx, close_txid)]
        k_public = claims and r.prov._cond_state(r.chan)[2] in Tx.parse(bytes.fromhex(claims[0])).inputs[0].witness
        self.reproduces(not got and "cipher" not in cond and r.chan.extra.get("cond_close") and k_public,
                        f"the payer never got an answer, the provider closed with the hash lock and claimed "
                        f"{COND_PRICE} sat (k now public), and the payer holds no ciphertext to use k on")

    def test_fixed_offer_carries_the_ciphertext(self):
        r = Rig(load("x402_channel"))
        cond = r.offer()["extra"]["conditional"]
        from xbt402.conditional import decrypt, sha256
        k = r.prov._cond["/v1/cond"]["k"]
        self.assertEqual(sha256(k).hex(), cond["hash"])
        self.assertEqual(decrypt(bytes.fromhex(cond["cipher"]), k), PLAIN)

    def test_fixed_payer_recovers_the_deliverable_from_the_claim(self):
        from xbt402.channel import ChannelError
        r = Rig(load("x402_channel"))
        r.client.request("GET", ORIGIN + "/v1/x")
        r.drop_cond_response = True
        with self.assertRaises(ChannelError):
            r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertTrue(r.cch.pending_cond)                          # ciphertext kept before signing
        r.close_at_margin()
        claim = next(hx for hx in r.node.sent if spends(hx, r.chan.closed_txid))
        self.assertEqual(r.client.recover_conditional(ORIGIN, claim), PLAIN)
        with self.assertRaises(ChannelError):                       # a tx without k recovers nothing
            r.client.recover_conditional(ORIGIN, r.node.sent[0])

    def test_fixed_one_k_per_sale(self):
        """The ciphertext is public in the 402 and a claim publishes k: after a sale the path must be
        offered under a new k, or one on-chain claim would decrypt every later buyer's deliverable."""
        from xbt402.conditional import decrypt
        r = Rig(load("x402_channel"))
        before = r.offer()["extra"]["conditional"]
        k1 = r.prov._cond["/v1/cond"]["k"]
        r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        after = r.offer()["extra"]["conditional"]
        self.assertNotEqual(before["hash"], after["hash"])
        self.assertNotEqual(decrypt(bytes.fromhex(after["cipher"]), k1), PLAIN)
        st, _, _, plain = r.client.request_conditional("GET", ORIGIN + "/v1/cond")   # a second sale works
        self.assertEqual((st, plain), (200, PLAIN))

    def test_fixed_offer_without_ciphertext_refused_before_signing(self):
        from xbt402.channel import ChannelError
        r = Rig(load("x402_channel"))
        serve = r.prov.serve

        def no_cipher(method, path, headers, body, url=""):
            st, h, out = serve(method, path, headers, body, url)
            if st == 402 and path == "/v1/cond":
                pr = json.loads(out)
                pr["accepts"][0]["extra"].get("conditional", {}).pop("cipher", None)
                h = dict(h, **{"PAYMENT-REQUIRED": r.xm.b64json(pr)})
                out = json.dumps(pr).encode()
            return st, h, out
        r.prov.serve = no_cipher
        r.client.request("GET", ORIGIN + "/v1/x")
        with self.assertRaises(ChannelError) as e:
            r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual(e.exception.code, "bad_offer")
        self.assertEqual(r.chan.cond_sig, "")

    def test_fixed_response_ciphertext_must_match_the_offer(self):
        r = Rig(load("x402_channel"))
        serve = r.prov.serve

        def swap(method, path, headers, body, url=""):
            st, h, out = serve(method, path, headers, body, url)
            if st == 200 and path == "/v1/cond":
                d = json.loads(out)
                d["cipher"] = "00" * len(PLAIN)                       # some other "deliverable"
                out = json.dumps(d).encode()
            return st, h, out
        r.prov.serve = swap
        st, _, _, plain = r.client.request_conditional("GET", ORIGIN + "/v1/cond")
        self.assertEqual((st, plain), (200, PLAIN))                  # decrypted from the offered ciphertext


if __name__ == "__main__":
    unittest.main()
