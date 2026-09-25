"""coincurve backend matches the pure-Python oracle on pubkey / sign / verify."""
import unittest

from xbt402 import ecc
from xbt402 import ecc_oracle


class EccOracleTest(unittest.TestCase):
    def test_backend_is_coincurve(self):
        self.assertEqual(ecc.BACKEND, "coincurve")

    def test_pubkey_matches_oracle(self):
        for sk in (1, 0x1111, 0x2222, 2**255 - 19):
            self.assertEqual(ecc.pubkey(sk), ecc_oracle.pubkey(sk))

    def test_verify_cross(self):
        msg = bytes(range(32))
        for sk in (0x1111, 0xABCDEF):
            pub = ecc.pubkey(sk)
            self.assertTrue(ecc.verify(pub, msg, ecc.sign(sk, msg)))
            self.assertTrue(ecc_oracle.verify(pub, msg, ecc.sign(sk, msg)))
            self.assertTrue(ecc.verify(pub, msg, ecc_oracle.sign(sk, msg)))
            self.assertFalse(ecc.verify(ecc.pubkey(sk + 1), msg, ecc.sign(sk, msg)))


if __name__ == "__main__":
    unittest.main()
