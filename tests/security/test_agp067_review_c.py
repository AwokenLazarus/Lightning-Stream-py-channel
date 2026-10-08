"""AGP-067: review C2, C3, C5 (xbt-rs `crates/xbt402/tests/review_c.rs`, same names; C4 is xbt-rs only:
b1's launcher already seals the payTo key, P7).
  * C2: a seller that would refuse /open is asked first ("preflight": true, no outpoint), so the
    buyer funds nothing on-chain for a channel that never opens;
  * C3: the rollover's txid is the one the payer computed from the tx it signed. b1's client has no
    wire rollover; its hub already refuses a reply naming another tx (bad_rollover_reply);
  * C5: one opener per ledger file, the lock gone with the ledger (and with a dead process).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from sechelp import FakeNode  # noqa: E402

from xbt402.channel import ChannelError  # noqa: E402
from xbt402.ledger import Ledger  # noqa: E402
from xbt402.tx import address_to_spk  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, XbtChannelProvider  # noqa: E402

NET = "bip122:" + "11" * 16
O = "https://api.example"
OPEN_PATH = "/x402/xbt-channel/open"


def secret(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big")


def provider(node, key, ledger=None):
    return XbtChannelProvider(node, key, NET, ledger or tempfile.mktemp(suffix=".sqlite"), lambda m, p: 150,
                              lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"answer": 1}'))


def serve(prov, method, url, body, headers):
    st, h, out = prov.serve(method, "/" + url.split("/", 3)[3], dict(headers or {}), body, url)
    return st, {k.upper(): v for k, v in h.items()}, out


def client(node, http):
    """A client whose `fund` counts what it funds: a refused open must leave it at zero."""
    def fund(addr, sats):
        c.funded += 1
        txid = hashlib.sha256(f"funding {c.funded}".encode()).hexdigest()
        node.txs[txid] = {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                          "vout": [{"n": 0, "value": sats / 1e8, "scriptPubKey": {"hex": address_to_spk(addr, "bcrt").hex()}}]}
        return txid, 0
    c = XbtChannelClient(NET, fund, node.getblockcount)
    c.funded, c.http = 0, http
    return c


def edit(prov, f):
    """The provider, with `f(path, req, (status, headers, body))` free to change each answer on the way back."""
    def http(method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        try:
            req = json.loads(body) if body else None
        except ValueError:
            req = None
        return f(path, req, serve(prov, method, url, body, headers))
    return http


class ReviewC2(unittest.TestCase):
    def test_c2_a_refused_open_funds_nothing(self):
        node = FakeNode()
        before = provider(node, secret("payTo before the restart"))
        after = provider(node, secret("payTo after the restart"))

        def split(method, url, body=b"", headers=None):
            # the 402 from `before`, /open to `after`: a seller restarted with another payTo between them
            return serve(after if url.endswith(OPEN_PATH) else before, method, url, body, headers)
        c = client(node, split)
        with self.assertRaises(ChannelError) as cm:
            c.request("GET", f"{O}/v1/q")
        self.assertEqual(cm.exception.code, "bad_funding", cm.exception)
        self.assertEqual(c.funded, 0, "the buyer funded a channel the seller refused")
        self.assertEqual(after.ledger.channels, {})

    def test_c2_the_preflight_records_nothing(self):
        node = FakeNode()
        prov = provider(node, secret("provider payTo"))
        seen = []

        def f(path, req, r):
            if path == OPEN_PATH and isinstance(req, dict) and req.get("preflight") is True:
                seen.append({"req": req, "status": r[0], "body": json.loads(r[2])})
            return r
        c = client(node, edit(prov, f))
        self.assertEqual(c.request("GET", f"{O}/v1/q")[0], 200)
        self.assertEqual(len(seen), 1, "one preflight before the funding")
        req, ans = seen[0]["req"], seen[0]["body"]
        self.assertEqual(seen[0]["status"], 200, ans)
        self.assertIs(ans["preflight"], True)
        self.assertTrue("txid" not in req["channel"] and "vout" not in req["channel"], f"no outpoint in a preflight: {req}")
        p = c.channels[O].payer.params
        self.assertEqual((ans["expiry"], ans["maxCum"]), (p.expiry, str(p.max_amount)))
        self.assertEqual(c.funded, 1)
        self.assertEqual(len(prov.ledger.channels), 1, "the funded open only")
        # a preflight on its own changes nothing, and refuses what the funded open would
        st, _, out = prov.serve("POST", OPEN_PATH, {}, json.dumps(req).encode(), f"{O}{OPEN_PATH}")
        self.assertEqual((st, json.loads(out).get("preflight")), (200, True))
        self.assertEqual(len(prov.ledger.channels), 1)
        req["channel"]["capacity"] = prov.policy.max_capacity + 1
        st, _, out = prov.serve("POST", OPEN_PATH, {}, json.dumps(req).encode(), f"{O}{OPEN_PATH}")
        self.assertEqual((st, json.loads(out).get("error")), (400, "bad_capacity"), out)

    def test_c2_a_provider_without_preflight_still_opens(self):
        node = FakeNode()
        prov = provider(node, secret("provider payTo"))

        def f(path, req, r):
            # a provider from before AGP-067 checks the terms, then fails on the missing vout
            if path == OPEN_PATH and isinstance(req, dict) and req.get("preflight") is True:
                return 400, {}, json.dumps({"error": "bad_request", "detail": "vout"}).encode()
            return r
        c = client(node, edit(prov, f))
        self.assertEqual(c.request("GET", f"{O}/v1/q")[0], 200)
        self.assertEqual((c.funded, len(prov.ledger.channels)), (1, 1))


class ReviewC3(unittest.TestCase):
    def test_c3_a_rollover_reply_naming_another_txid_is_refused(self):
        self.skipTest("b1's client has no wire rollover; hub.py's rollover already refuses a reply naming "
                      "another tx (bad_rollover_reply), as xbt-rs hub.rs does")


class ReviewC5(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="agp067-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_c5_a_second_provider_on_one_ledger_is_refused(self):
        path = os.path.join(self.dir, "ledger.sqlite")
        first = Ledger(path)
        with self.assertRaises(ChannelError) as cm:
            Ledger(path)
        self.assertEqual(cm.exception.code, "ledger_locked")
        self.assertIn(str(os.getpid()), str(cm.exception), "the error names the holder")
        # the lock goes with the ledger (a crash too: the OS drops it with the process)
        first.close()
        Ledger(path).close()
        node = FakeNode()
        prov = provider(node, secret("provider payTo"), path)
        with self.assertRaises(ChannelError) as cm:
            provider(node, secret("provider payTo"), path)
        self.assertEqual(cm.exception.code, "ledger_locked")
        prov.ledger.close()

    def test_c5_a_second_client_on_one_client_ledger_is_refused(self):
        self.skipTest("b1's client keeps its channels in memory (RefundCustody is an append-only refund log)")

    @unittest.skipUnless(shutil.which("flock"), "flock(1) not installed: the in-process cases cover the lock")
    def test_c5_another_process_holding_the_lock_is_refused(self):
        """Another process holding flock(2) on the sidecar (util-linux flock; xbt-rs's File::try_lock is
        the same call) keeps a provider off the file."""
        path = os.path.join(self.dir, "ledger.sqlite")
        lock = path + ".lock"
        open(lock, "w").close()
        # -o: flock(1) itself holds the lock, not the shell, which ends when its stdin closes
        child = subprocess.Popen(["flock", "-o", "-n", lock, "-c", "echo held; read x || true"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(child.stdout.readline().strip(), "held")
        with self.assertRaises(ChannelError) as cm:
            Ledger(path)
        self.assertEqual(cm.exception.code, "ledger_locked")
        child.stdin.close()
        self.assertEqual(child.wait(), 0)
        child.stdout.close()
        Ledger(path).close()


if __name__ == "__main__":
    unittest.main()
