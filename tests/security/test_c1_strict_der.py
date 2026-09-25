"""C1 (Critical) signature malleability: a non-strict-DER state signature.

Wave 2 verifies through coincurve, whose DER parser is strict. Without coincurve (the system
python3 this suite runs on, or any install without the extra) ecc.verify falls back to the v1
oracle, whose DER parser checks only the outer lengths: a valid (r, s) re-encoded with a
superfluous 0x00 before r verifies in the provider. BIP66 strict DER is consensus for segwit v0,
so the close built from that state is invalid (regtest_confirm.py F1: `mandatory-script-verify-
flag-failed (Non-canonical DER signature)` in a block). The payer gets the service and its full
refund. Fixed: ecc.verify checks strict DER before either backend.
"""
import unittest

from sechelp import (FakeNode, Repro, authed, backends, base, is_strict_der, lax_der, load, make_channel,
                     make_provider, pay, use_backend)
ch, xc = base("channel"), base("x402_channel")   # unpatched wave 2: the repro tests


class StrictDer(Repro, unittest.TestCase):
    def test_repro_provider_serves_on_unclosable_state(self):
        with use_backend(base("ecc"), "oracle"):
            node = FakeNode()
            prov = make_provider(xc, node)
            p, payer = make_channel(ch, prov, node)
            good = payer.sign_state(20_000)
            bad = lax_der(good[:-1]) + good[-1:]
            self.assertTrue(is_strict_der(good) and not is_strict_der(bad))
            st, err, _ = pay(xc, prov, {"chan": p.channel_id, "seq": 1, "cum": "20000", "sig": bad.hex()})
            close_sig = prov._payee(prov.ledger.channels[p.channel_id]).close_tx().inputs[0].witness[0]
        self.reproduces(st == 200 and not is_strict_der(close_sig),
                        "provider (no coincurve) served on a non-strict-DER state; its only close is consensus-invalid")

    def test_fixed_non_strict_der_is_bad_sig(self):
        xp, cp, e = load("x402_channel"), load("channel"), load("ecc")
        for backend in backends(e):
            with use_backend(e, backend):
                node = FakeNode()
                prov = make_provider(xp, node)
                p, payer = make_channel(cp, prov, node)
                good = payer.sign_state(20_000)
                for seq, bad in ((1, lax_der(good[:-1]) + good[-1:]),                       # padded r
                                 (2, good[:-1] + b"\x00" + good[-1:])):                      # trailing garbage
                    pl = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": seq, "cum": "20000",
                                                             "sig": bad.hex()})
                    self.assertEqual(pay(xp, prov, pl)[1], "bad_sig", backend)
                pl = authed(xp, cp, payer, p.payee_pub, {"chan": p.channel_id, "seq": 3, "cum": "20000", "sig": good.hex()})
                self.assertEqual(pay(xp, prov, pl)[0], 200, backend)

    def test_fixed_signer_output_is_strict(self):
        e = load("ecc")
        for backend in backends(e):
            with use_backend(e, backend):
                for k in range(1, 200):
                    sig = e.sign(k * 7919, k.to_bytes(32, "big"))
                    self.assertTrue(e.is_strict_der(sig) and is_strict_der(sig + b"\x21"))


if __name__ == "__main__":
    unittest.main()
