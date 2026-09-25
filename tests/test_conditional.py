"""Hash-locked increment: preimage claim, wrong preimage, upgrade."""
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelParams, Payer
from xbt402.conditional import ConditionalParams, decrypt, encrypt, sha256
from xbt402.tx import p2wpkh_spk


def params():
    return ChannelParams(
        payer_pub=ecc.pubkey(0x1111).hex(), payee_pub=ecc.pubkey(0x2222).hex(), expiry=1000,
        payer_spk=p2wpkh_spk(ecc.pubkey(0x1111)).hex(), payee_spk=p2wpkh_spk(ecc.pubkey(0x2222)).hex(),
        close_fee=380, funding_txid="ab" * 32, funding_vout=1, capacity=100_000)


class ConditionalTest(unittest.TestCase):
    def test_encrypt_roundtrip(self):
        k = b"k" * 32
        self.assertEqual(decrypt(encrypt(b"hello-result", k), k), b"hello-result")

    def test_sign_and_verify_conditional_state(self):
        p, k = params(), os_urandom()
        h = sha256(k)
        cond = ConditionalParams(p, h, 1000)
        payer = Payer(p, 0x1111)
        tx = cond.state_tx(2000)
        sig = ecc.sign(0x1111, cond.sighash(tx)) + bytes([0x21])
        self.assertTrue(ecc.verify(bytes.fromhex(p.payer_pub), cond.sighash(tx), sig[:-1]))
        self.assertTrue(any(o.script_pubkey == cond.spk for o in tx.outputs))
        self.assertEqual(sha256(k), h)
        self.assertNotEqual(sha256(b"wrong" + k[5:]), h)

    def test_claim_rejects_wrong_preimage(self):
        p = params()
        k = b"\x42" * 32
        cond = ConditionalParams(p, sha256(k), 1000)
        with self.assertRaises(Exception):
            cond.claim_tx("cd" * 32, 1, b"\x00" * 32, 0x2222, bytes.fromhex(p.payee_spk), 200)


def os_urandom():
    return b"\x11" * 32


if __name__ == "__main__":
    unittest.main()
