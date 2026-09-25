"""H4 (High) non-constant-time crypto on a remotely triggered path.

The provider signs a receipt with the channel key on every paid call, a signing oracle any payer can
drive for 150 sat a call. Wave 2 signs with coincurve (libsecp256k1, constant time) when it is
installed, but falls back to the v1 oracle otherwise, and the system python3 has no coincurve. The
oracle's k*G is double-and-add over a table: one point addition per set bit of the nonce, no work
above its top bit. Signing time therefore tracks the nonce's Hamming weight and length, the leak that
Minerva / TPM-Fail turned into key recovery from a few thousand signatures by lattice reduction. The
payTo tweak t is public, so one channel key gives payTo_secret = p - t: every channel's key,
receipts, and the provider's close outputs.

The test counts group operations (deterministic, unlike wall-clock timing).
"""
import unittest

from sechelp import Repro, base, load, use_backend
ecc = base("ecc")   # unpatched wave 2: the repro tests


def ops(oracle, fn):
    """Point additions + doublings done by `fn` (all curve arithmetic goes through `oracle`)."""
    n = [0]
    ja, jd = oracle._jadd, oracle._jdouble

    def cadd(a, b):
        n[0] += 1
        return ja(a, b)

    def cdbl(a):
        n[0] += 1
        return jd(a)
    oracle._jadd, oracle._jdouble = cadd, cdbl
    try:
        fn()
    finally:
        oracle._jadd, oracle._jdouble = ja, jd
    return n[0]


SECRET = 0x5EC12E7
MSGS = [bytes([i]) * 32 for i in range(40)]


class NonConstantTime(Repro, unittest.TestCase):
    def test_repro_sign_cost_tracks_the_nonce(self):
        orc = base("ecc_oracle")
        rows = []
        with use_backend(ecc, "oracle"):
            for m in MSGS:
                k = orc._rfc6979(SECRET, m)
                rows.append((ops(orc, lambda: ecc.sign(SECRET, m)), bin(k).count("1")))
        costs = {c for c, _ in rows}
        # cost - popcount(k) is the fixed part of signing: the rest is exactly one addition per set nonce bit
        self.reproduces(len(costs) > 10 and len({c - w for c, w in rows}) == 1,
                        f"fallback signing: {len(costs)} distinct costs over {len(MSGS)} receipts; "
                        f"cost = const + popcount(nonce)")

    def test_fixed_sign_pubkey_ecdh_cost_is_constant(self):
        e, orc = load("ecc"), load("ecc_oracle")
        with use_backend(e, "oracle"):
            self.assertEqual(len({ops(orc, lambda: e.sign(SECRET, m)) for m in MSGS}), 1)
            self.assertEqual(len({ops(orc, lambda: e.pubkey(k)) for k in (1, 2, 3, 2**255 + 5, e.N - 1, 0xFFFF)}), 1)
            pub = e.pubkey(7)
            self.assertEqual(len({ops(orc, lambda: e.ecdh(k, pub)) for k in (1, 2**100, e.N - 2)}), 1)

    def test_fixed_same_signatures_and_keys(self):
        e, orc = load("ecc"), load("ecc_oracle")
        with use_backend(e, "oracle"):
            for k in (1, 2, 3, 0xDEADBEEF, e.N - 1):
                self.assertEqual(e.pubkey(k), orc.pubkey(k))
                self.assertEqual(e.sign(k, MSGS[k % 40]), orc.sign(k, MSGS[k % 40]))   # RFC 6979: identical
                self.assertEqual(e.ecdh(k, orc.pubkey(5)), e.ecdh(5, orc.pubkey(k)))

    def test_fixed_coincurve_matches_the_hardened_fallback(self):
        e = load("ecc")
        if e.BACKEND != "coincurve":
            self.skipTest("coincurve not installed for this python (the demo's venv has it)")
        for k in (1, 0xDEADBEEF, e.N - 1):
            with use_backend(e, "oracle"):
                want = (e.pubkey(k), e.sign(k, MSGS[k % 40]), e.ecdh(k, e.pubkey(9)))
            self.assertEqual((e.pubkey(k), e.sign(k, MSGS[k % 40]), e.ecdh(k, e.pubkey(9))), want)


if __name__ == "__main__":
    unittest.main()
