"""UnifiedSighash matches the 166 Knots hf-sighash-opt-in reference vectors (via bitkey-xbt)."""
import json
import os
import unittest

from xbt402.tx import ST_TAPSCRIPT, Tx, TxOut, tagged_hash, unified_sighash, varbytes

HERE = os.path.dirname(__file__)


class VectorTest(unittest.TestCase):
    def test_reference_vectors(self):
        with open(os.path.join(HERE, "data", "unified_sighash.json")) as f:
            rows = json.load(f)[1:]
        for n, (script, raw, idx, ht, st, spent, want) in enumerate(rows):
            script = bytes.fromhex(script)
            tx = Tx.parse(bytes.fromhex(raw))
            prevouts = [TxOut(v, bytes.fromhex(s)) for v, s in spent]
            leaf = tagged_hash("TapLeaf", b"\xc0" + varbytes(script)) if st == ST_TAPSCRIPT else None
            got = unified_sighash(tx, prevouts, idx, st, script, ht & 0xFF, leaf)
            self.assertEqual(got.hex(), want, f"vector {n}")
        self.assertEqual(len(rows), 166)


if __name__ == "__main__":
    unittest.main()
