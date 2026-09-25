"""MCP surface never returns keys; xbt402_pay talks only to the signer."""
import unittest

from xbt402 import ecc
from xbt402.channel import ChannelError, ChannelParams
from xbt402.mcp_server import MCP_TOOL_NAMES, assert_no_key_material, handle, sanitize, xbt_channels
from xbt402.signer import ChannelSigner
from xbt402.tx import p2wpkh_spk


class McpTest(unittest.TestCase):
    def test_tool_names(self):
        self.assertIn("xbt402_pay", MCP_TOOL_NAMES)
        self.assertNotIn("approve", MCP_TOOL_NAMES)

    def test_sanitize_strips_secret_keys(self):
        clean = sanitize({"chan": "ab:0", "secret": "nope", "charged": "150"})
        self.assertNotIn("secret", clean)
        with self.assertRaises(RuntimeError):
            assert_no_key_material({"private_key": "00" * 32})

    def test_signer_never_exports_secret(self):
        s = ChannelSigner()
        pub = s.new_key("http://x")
        self.assertEqual(len(bytes.fromhex(pub)), 33)
        p = ChannelParams(
            payer_pub=pub, payee_pub=ecc.pubkey(2).hex(), expiry=1000,
            payer_spk=p2wpkh_spk(bytes.fromhex(pub)).hex(),
            payee_spk=p2wpkh_spk(ecc.pubkey(2)).hex(),
            close_fee=600, funding_txid="ab" * 32, funding_vout=0, capacity=20_000)
        s.attach("http://x", p)
        listing = xbt_channels(s)
        blob = str(listing)
        self.assertNotIn("secret", blob.lower())
        self.assertTrue(s.has(p.channel_id))

    def test_policy_denies(self):
        def deny(origin, sats):
            raise ChannelError("policy", "no")
        s = ChannelSigner(policy=deny)
        pub = s.new_key("http://x")
        p = ChannelParams(
            payer_pub=pub, payee_pub=ecc.pubkey(2).hex(), expiry=1000,
            payer_spk=p2wpkh_spk(bytes.fromhex(pub)).hex(),
            payee_spk=p2wpkh_spk(ecc.pubkey(2)).hex(),
            close_fee=600, funding_txid="ab" * 32, funding_vout=0, capacity=20_000)
        s.attach("http://x", p)
        with self.assertRaises(ChannelError):
            s.sign_state(p.channel_id, 1000)


if __name__ == "__main__":
    unittest.main()
