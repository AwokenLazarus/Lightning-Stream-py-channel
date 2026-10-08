"""P7: the mainnet test provider's launcher (scripts/mainnet_provider.py, scripts/sealed_key.py).

Every demo provider drew a random payTo secret per start and read the regtest cookie. On mainnet a
restart after a close would strand the payee output. The launcher seals the payTo secret once and
reloads it, listens on loopback only, checks the node's chain and the spec's network id (block
961640 on mainnet) before serving, and refuses to serve mainnet at all while Mike's hold stands.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "scripts")))

import mainnet_provider as mp  # noqa: E402
import sealed_key  # noqa: E402
from xbt402 import ecc  # noqa: E402
from xbt402.tx import segwit_address  # noqa: E402
from xbt402.x402_channel import XBT_MAINNET  # noqa: E402

MAIN_961640 = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"


class Node:
    def __init__(self, chain="main", blocks=974_446, ibd=False, h961640=MAIN_961640):
        self.chain, self.blocks, self.ibd, self.h = chain, blocks, ibd, h961640

    def getblockchaininfo(self):
        return {"chain": self.chain, "blocks": self.blocks, "initialblockdownload": self.ibd}

    def getblockhash(self, height):
        if height == 961640:
            return self.h
        return f"{height:064x}"

    def getblockcount(self):
        return self.blocks


class Launcher(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.environ.pop(sealed_key.ENV_PASSPHRASE, None)
        self.cfg_path = self.config()

    def config(self, **over):
        cfg = {"chain": "main", "payto_key": f"{self.dir}/keys/payto.key", "payto_wrap": f"{self.dir}/keys/payto.wrap",
               "admin_token": f"{self.dir}/keys/admin.token", "ledger": f"{self.dir}/provider/ledger.sqlite",
               "cookie": f"{self.dir}/.cookie", **over}
        path = f"{self.dir}/provider-{len(os.listdir(self.dir))}.json"
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path

    def build(self, node=None, **over):
        cfg = mp.load_config(self.config(**over) if over else self.cfg_path)
        return mp.build(cfg, rpc=node or Node())

    def test_mainnet_network_is_block_961640_and_matches_the_spec(self):
        prov, created = self.build()
        self.assertTrue(created)
        self.assertEqual(prov.network, XBT_MAINNET)
        self.assertEqual(prov.hrp, "bc")
        with self.assertRaises(mp.LaunchError):
            self.build(Node(h961640="00" * 32))                     # another chain's 961640
        with self.assertRaises(mp.LaunchError):
            self.build(Node(chain="regtest"))                        # the node is not what the config says
        with self.assertRaises(mp.LaunchError):
            self.build(Node(ibd=True))
        with self.assertRaises(mp.LaunchError):
            self.build(Node(blocks=961_000))

    def test_regtest_uses_block_101(self):
        prov, _ = self.build(Node(chain="regtest", blocks=200), chain="regtest")
        self.assertEqual(prov.network, "bip122:" + f"{101:064x}"[:32])
        self.assertEqual(prov.hrp, "bcrt")

    def test_payto_secret_is_sealed_created_once_and_reloaded(self):
        p1, created1 = self.build()
        p2, created2 = self.build()
        self.assertEqual((created1, created2), (True, False))
        self.assertEqual(p1.pay_to, p2.pay_to, "a restart keeps the payTo key")
        path = f"{self.dir}/keys/payto.key"
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(f"{self.dir}/keys/payto.wrap").st_mode & 0o777, 0o600)
        raw = open(path).read()
        self.assertNotIn(f"{p1.secret:064x}", raw)
        self.assertEqual(json.loads(raw)["pub"], p1.pay_to)

    def test_wrong_wrap_key_or_tampering_is_refused_and_nothing_is_overwritten(self):
        p1, _ = self.build()
        key = f"{self.dir}/keys/payto.key"
        before = open(key).read()
        with open(f"{self.dir}/keys/payto.wrap", "wb") as f:
            f.write(os.urandom(32))
        with self.assertRaises(sealed_key.SealedKeyError):
            self.build()
        self.assertEqual(open(key).read(), before)
        doc = json.loads(before)
        doc["pub"] = ecc.pubkey(7).hex()
        other = self.config(payto_key=f"{self.dir}/keys/other.key")
        with open(f"{self.dir}/keys/other.key", "w") as f:
            json.dump(doc, f)
        os.chmod(f"{self.dir}/keys/other.key", 0o600)
        with self.assertRaises(sealed_key.SealedKeyError):
            mp.build(mp.load_config(other), rpc=Node())

    def test_passphrase_wrap(self):
        os.environ[sealed_key.ENV_PASSPHRASE] = "correct horse"
        p1, _ = self.build(payto_wrap="", payto_key=f"{self.dir}/keys/pp.key")
        self.assertNotIn(sealed_key.ENV_PASSPHRASE, os.environ, "the passphrase leaves the environment")
        os.environ[sealed_key.ENV_PASSPHRASE] = "correct horse"
        p2, _ = self.build(payto_wrap="", payto_key=f"{self.dir}/keys/pp.key")
        self.assertEqual(p1.pay_to, p2.pay_to)

    def test_loopback_only(self):
        for host in ("0.0.0.0", "192.0.2.1", "::"):
            with self.assertRaises(mp.LaunchError):
                mp.load_config(self.config(host=host))

    def test_offer_matches_the_runbook(self):
        prov, _ = self.build()
        extra = prov.requirements(500)["extra"]
        self.assertEqual((extra["minCapacity"], extra["maxCapacity"], extra["closeFeeSat"], extra["minConf"]),
                         ("10000", "10000", "600", 1))
        self.assertEqual((extra["minExpiryBlocks"], extra["closeMarginBlocks"], extra["derivation"]), (1008, 144, "v3"))
        self.assertEqual(prov.requirements(500)["amount"], "500")

    def test_mainnet_serving_is_on_hold_but_check_works(self):
        orig = mp.RPC
        mp.RPC = lambda port, cookie, wallet="": Node()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(mp.main(["--config", self.cfg_path, "--check"]), 0)
            info = json.loads(out.getvalue())
            self.assertEqual((info["network"], info["offer"]["amount"]), (XBT_MAINNET, "500"))
            self.assertNotIn("secret", out.getvalue().lower().replace("payto_key_created", ""))
            with self.assertRaises(mp.LaunchError) as cm:
                mp.main(["--config", self.cfg_path])
            self.assertIn("on hold", str(cm.exception))
            self.assertFalse(os.path.exists(f"{self.dir}/keys/admin.token"), "nothing started")
        finally:
            mp.RPC = orig

    def test_sweep_address_must_be_this_networks(self):
        prov, _ = self.build()
        cfg = mp.load_config(self.cfg_path)
        spk = bytes.fromhex("0014" + "66" * 20)
        with self.assertRaises(ValueError):
            mp.admin_sweep(prov, cfg, "00" * 32 + ":0", segwit_address("bcrt", spk), 300)

    def test_example_config_is_the_runbooks(self):
        cfg = mp.load_config(os.path.join(HERE, "..", "..", "scripts", "mainnet_provider.example.json"))
        self.assertEqual((cfg["chain"], cfg["port"], cfg["rpc_port"], cfg["host"]), ("main", 39480, 39332, "127.0.0.1"))
        self.assertEqual(cfg["route"], {"method": "GET", "path": "/agp015/echo", "price": 500})
        self.assertIs(cfg["mainnet_start_approved"], False)
        self.assertEqual((cfg["close_fee"], cfg["close_margin"], cfg["watcher_interval"]), (600, 144, 30))


if __name__ == "__main__":
    unittest.main()
