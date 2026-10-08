"""AGP-069 review S1: UnifiedSighash with an annex and a codeseparator position, against vectors from
Knots' independent Python implementation (xbt-rs scripts/gen_unified_sighash_ext.py; the Rust tests
of the same names are in xbt-rs crates/xbt-primitives/tests/sighash_ext.rs)."""
import json
import os
import unittest

from xbt402.tx import NO_CODESEP, ST_BARE, ST_TAPROOT, ST_TAPSCRIPT, ST_WITNESS_V0, Tx, TxOut, unified_sighash

HERE = os.path.dirname(__file__)


def cases():
    with open(os.path.join(HERE, "data", "unified_sighash_ext.json")) as f:
        rows = json.load(f)
    assert rows[0][8] == "sighash"
    out = []
    for raw, idx, ht, st, spent, leaf, annex, pos, want in rows[1:]:
        out.append({"tx": Tx.parse(bytes.fromhex(raw)), "index": idx, "hash_type": ht, "script_type": st,
                    "prevouts": [TxOut(v, bytes.fromhex(s)) for v, s in spent],
                    "leaf": bytes.fromhex(leaf) if leaf else None, "annex": bytes.fromhex(annex) if annex is not None else None,
                    "codesep_pos": pos, "sighash": want})
    return out


class SighashExt(unittest.TestCase):
    def test_s1_annex_and_codesep_vectors_match_knots(self):
        cs = cases()
        self.assertEqual(len(cs), 60)
        self.assertGreaterEqual(sum(c["annex"] is not None for c in cs), 40)
        self.assertGreaterEqual(sum(c["codesep_pos"] != NO_CODESEP for c in cs), 20)
        for n, c in enumerate(cs):
            got = unified_sighash(c["tx"], c["prevouts"], c["index"], c["script_type"], b"", c["hash_type"], c["leaf"],
                                  annex=c["annex"], codesep_pos=c["codesep_pos"])
            self.assertEqual(got.hex(), c["sighash"], f"case {n}")
            if c["annex"] is None and c["codesep_pos"] == NO_CODESEP:
                plain = unified_sighash(c["tx"], c["prevouts"], c["index"], c["script_type"], b"", c["hash_type"], c["leaf"])
                self.assertEqual(plain.hex(), c["sighash"], f"case {n}: the default is no annex, no codeseparator")

    def test_s1_refuses_values_the_script_type_does_not_commit_to(self):
        c = cases()[0]
        leaf, annex = bytes([7]) * 32, bytes([0x50, 1, 2])

        def call(st, leaf=None, **kw):
            return unified_sighash(c["tx"], c["prevouts"], c["index"], st, b"\x51", 0x21, leaf, **kw)

        for st in (ST_BARE, ST_WITNESS_V0):
            with self.assertRaises(ValueError, msg=f"{st} has no annex"):
                call(st, annex=annex)
            with self.assertRaises(ValueError, msg=f"{st}: its script code carries the codeseparator"):
                call(st, codesep_pos=0)
            call(st)
        with self.assertRaises(ValueError, msg="key path: no codeseparator"):
            call(ST_TAPROOT, codesep_pos=3)
        with self.assertRaises(ValueError, msg="no 0x50 tag"):
            call(ST_TAPROOT, annex=bytes([0x51, 1]))
        with self.assertRaises(ValueError):
            call(ST_TAPROOT, annex=b"")
        self.assertNotEqual(call(ST_TAPSCRIPT, leaf, annex=annex, codesep_pos=2), call(ST_TAPSCRIPT, leaf),
                            "both are committed to")


if __name__ == "__main__":
    unittest.main()
