"""Shared helpers for the XBT-061 security tests: attack encodings, a fake node, the unpatched base.

Layout: every `test_repro_*` runs against unpatched wave 2 (BASE, imported as `xbt402w2`) and must
reproduce its finding; every `test_fixed_*` / `test_control_*` runs against the tree under test
(`xbt402`, i.e. wave2-hardened) and must pass. So on wave2-hardened the whole suite is green.
The v1 patch series and its tests' history are in review/v1/."""
import atexit
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
REVIEW = os.path.join(ROOT, "review")
BASE = "8a6bf26"     # unpatched wave 2 (XBT-060), which wave2-hardened patches
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _der_int(b: bytes) -> bytes:
    return b"\x02" + bytes([len(b)]) + b


def lax_der(sig: bytes) -> bytes:
    """Re-encode a DER ECDSA signature with a superfluous 0x00 in front of r: the same (r, s),
    but not strict DER (BIP66), which consensus requires for every segwit v0 signature."""
    rl = sig[3]
    r, s = sig[4:4 + rl], sig[6 + rl:]
    body = _der_int(b"\x00" + r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def is_strict_der(sig: bytes) -> bool:
    """Port of Bitcoin Core's IsValidSignatureEncoding (BIP66), for a sig WITH its hash-type byte."""
    if len(sig) < 9 or len(sig) > 73 or sig[0] != 0x30 or sig[1] != len(sig) - 3:
        return False
    lr = sig[3]
    if 5 + lr >= len(sig):
        return False
    ls = sig[5 + lr]
    if lr + ls + 7 != len(sig) or sig[2] != 0x02 or lr == 0 or sig[4] & 0x80:
        return False
    if lr > 1 and sig[4] == 0 and not sig[5] & 0x80:
        return False
    if sig[lr + 4] != 0x02 or ls == 0 or sig[lr + 6] & 0x80:
        return False
    if ls > 1 and sig[lr + 6] == 0 and not sig[lr + 7] & 0x80:
        return False
    return True


class FakeNode:
    """Just enough of bitcoind for the provider: funding lookups, the UTXO view, tip height and
    broadcast. Like bitcoind it parses txids case-insensitively. `fail` maps a substring of a raw
    tx (or a txid) to the error its broadcast raises."""

    def __init__(self, height=1000):
        self.height, self.txs, self.sent, self.fail, self.spent = height, {}, [], {}, set()

    def add_funding(self, p, confirmations=6, coinbase=False):
        self.txs[p.funding_txid.lower()] = {
            "vin": [{"coinbase": "00"}] if coinbase else [{"txid": "cd" * 32, "vout": 0}],
            "vout": [{"n": i, "value": 0, "scriptPubKey": {"hex": ""}} for i in range(p.funding_vout)]
            + [{"n": p.funding_vout, "value": p.capacity / 1e8, "scriptPubKey": {"hex": p.spk.hex()}}],
            "confirmations": confirmations}

    def reorg_out(self, txid):
        """The funding leaves the chain (and its inputs are double-spent)."""
        self.txs.pop(txid.lower(), None)

    def getrawtransaction(self, txid, verbose=True):
        if txid.lower() not in self.txs:
            raise RuntimeError("No such mempool or blockchain transaction")
        return self.txs[txid.lower()]

    def gettxout(self, txid, vout, include_mempool=True):
        tx = self.txs.get(txid.lower())
        if not tx or (include_mempool and (txid.lower(), vout) in self.spent):
            return None
        if tx["confirmations"] < 1 and not include_mempool:
            return None
        if vout >= len(tx["vout"]):
            return None
        o = tx["vout"][vout]
        return {"confirmations": tx["confirmations"], "value": o["value"], "scriptPubKey": o["scriptPubKey"],
                "coinbase": any("coinbase" in i for i in tx.get("vin", []))}

    def getblockcount(self):
        return self.height

    def sendrawtransaction(self, hx):
        from xbt402.tx import Tx
        tx = Tx.parse(bytes.fromhex(hx))
        for k, why in self.fail.items():
            if k in hx or k == tx.txid():
                raise RuntimeError(why)
        for i in tx.inputs:
            self.spent.add((i.txid[::-1].hex(), i.vout))
        self.sent.append(hx)
        self.txs.setdefault(tx.txid(), {   # in the mempool: its outputs are spendable (a claim of a close)
            "vin": [{"txid": i.txid[::-1].hex(), "vout": i.vout} for i in tx.inputs],
            "vout": [{"n": n, "value": o.value / 1e8, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
                     for n, o in enumerate(tx.outputs)], "confirmations": 0})
        return tx.txid()


PRICE = 150


def crashed(*targets):
    """A crash, in one test process (AGP-067): a ledger takes one opener and the OS drops a dead
    process's lock, but here the old instance is still alive. Each target (a provider, a hub, a
    Ledger, or a ledger path or data directory) lets go of its ledger locks; the objects stay usable,
    as a call still running in the old instance may finish. A no-op on the unpatched base."""
    import gc

    def release(led):
        f = getattr(led, "_file_lock", None)
        if f is not None:
            f.close()
            led._file_lock = None

    for t in targets:
        if isinstance(t, str):
            root = os.path.abspath(t[:-5] + ".sqlite" if t.endswith(".json") else t)
            for o in gc.get_objects():
                if type(o).__name__ == "Ledger" and isinstance(getattr(o, "path", None), str):
                    lp = os.path.abspath(o.path)
                    if lp == root or lp.startswith(root.rstrip(os.sep) + os.sep):
                        release(o)
            continue
        for led in (t, getattr(t, "ledger", None), getattr(getattr(t, "inbound", None), "ledger", None)):
            if led is not None:
                release(led)


def make_provider(xc, node, billing="postpay", secret=0xB0B):
    """A provider from module `xc` (xbt402w2.x402_channel = unpatched, xbt402.x402_channel = tree)."""
    import tempfile
    return xc.XbtChannelProvider(node, secret, "bip122:" + "11" * 16, tempfile.mktemp(suffix=".json"),
                                 lambda m, p: PRICE, lambda m, p, b: (200, {}, b"ok"), billing=billing)


def make_channel(ch, prov, node, a=0xA11CE, capacity=200_000, vout=0, confs=6, payer_spk="", txid=None,
                 open_as=None, expiry_in=2000):
    """Fund and open a channel (module `ch` = channel module of the same tree). Returns (params, payer)."""
    p = derive(ch, prov.network, prov.pay_to, _pub(ch, a), node.height + expiry_in, prov.close_fee, payer_spk)
    p.funding_txid, p.funding_vout, p.capacity = txid or os.urandom(32).hex(), vout, capacity
    node.add_funding(p, confirmations=confs)
    for t in open_as or [p.funding_txid]:
        c = {"txid": t, "vout": vout, "capacity": capacity, "expiry": p.expiry, "payerPub": p.payer_pub,
             "redeemScript": p.script.hex()}
        if payer_spk:
            c["payerSpk"] = payer_spk
        prov.open({"x402Version": 2, "network": prov.network, "channel": c})
    return p, ch.Payer(p, a)


def derive(ch, network, pay_to, payer_pub, expiry, close_fee, payer_spk=""):
    """ChannelParams.derive of either tree: v1.1 commits to the network (AGP-004, M2), wave 2 did not."""
    import inspect
    kw = {"network": network} if "network" in inspect.signature(ch.ChannelParams.derive).parameters else {}
    return ch.ChannelParams.derive(pay_to, payer_pub, expiry, close_fee, payer_spk, **kw)


def _pub(ch, a):
    return ch.ecc.pubkey(a).hex()


def pay(xc, prov, payload, method="GET", path="/v1/x", body=b""):
    """One paid request straight into provider.serve. Returns (status, error code or '', 402 body)."""
    import json
    hdr = xc.b64json({"x402Version": 2, "accepted": prov.requirements(PRICE), "payload": payload})
    st, h, out = prov.serve(method, path, {"PAYMENT-SIGNATURE": hdr}, body)
    if st == 402:
        pr = json.loads(out)
        return st, pr["error"], pr
    return st, "", None


def authed(xc, ch, payer, prov_payee_pub, payload, method="GET", path="/v1/x", body=b""):
    """Add the hardened protocol's request auth to `payload` (payer side)."""
    key = ch.channel_auth_key(payer.secret, bytes.fromhex(prov_payee_pub))
    payload = dict(payload)
    payload["auth"] = xc.request_auth(key, payload["chan"], payload["seq"], payload["cum"], payload.get("sig"),
                                      xc.request_digest_v2(method, path, body))
    return payload


class Repro:
    """Mixin: a finding reproduces on its unpatched base (a failure means the base changed, not the fix)."""
    REPRO_BASE = BASE

    def reproduces(self, cond, what):
        self.assertTrue(cond, f"did not reproduce on {self.REPRO_BASE}: {what}")
        sys.stderr.write(f"\n    REPRODUCED on {self.REPRO_BASE}: {what} ")


_base = {}
V11 = "c770880"      # xbt402 v1.1 as AGP-004 shipped it, which AGP-005 reviews and patches


def base_tree(rev=BASE, pkg="xbt402w2"):
    """An unpatched tree (`rev`) as an importable package `pkg`, so the repro tests show each finding
    on the code that shipped while the fixed tests run the tree they sit in."""
    if rev in _base:
        return _base[rev]
    out = None
    tmp = tempfile.mkdtemp(prefix=f"xbt402-{rev}-")
    try:
        arc = subprocess.run(["git", "-C", ROOT, "archive", rev, "xbt402"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=arc, check=True)
        shutil.move(os.path.join(tmp, "xbt402"), os.path.join(tmp, pkg))
        atexit.register(shutil.rmtree, tmp, True)
        out = tmp
    except (subprocess.CalledProcessError, OSError) as e:
        sys.stderr.write(f"base_tree: {e}\n")
    _base[rev] = out
    return out


def base(name, rev=BASE, pkg="xbt402w2"):
    """Import <pkg>.<name> from unpatched `rev` (wave 2 by default; raises SkipTest if git or the
    revision is unavailable)."""
    import importlib
    import unittest
    d = base_tree(rev, pkg)
    if not d:
        raise unittest.SkipTest(f"unpatched base {rev} unavailable")
    if d not in sys.path:
        sys.path.insert(0, d)
    return importlib.import_module(f"{pkg}.{name}")


def v11(name):
    """Import xbt402v11.<name>: v1.1 as AGP-004 shipped it (c770880), before the AGP-005 fixes."""
    return base(name, V11, "xbt402v11")


V11R1 = "075a8a7"    # v1.1 after its first review's fixes, before the L13 fix


def v11r1(name):
    """Import xbt402v11r1.<name>: v1.1 with the first review's fixes (075a8a7), before L13's."""
    return base(name, V11R1, "xbt402v11r1")


def load(name):
    """Import xbt402.<name> from the tree under test (wave2-hardened)."""
    import importlib
    return importlib.import_module(f"xbt402.{name}")


# Every port a test binds is XBT402_TEST_PORT_BASE + one of these offsets (a block of 100), so
# parallel runs on one machine use disjoint ranges. Without the variable, a free block is picked
# at runtime (logged to stderr).
# Every offset fits one 50-port block (AGP-023: workers get 50-port ranges). m4 binds 4 ports,
# agp020 2; the regtest demo (scripts/demo_route.sh) uses base + 1/2 and 10..14, so run it alone.
PORT_OFFSETS = {"m6_rpc": 0, "m6_p2p": 1, "agp020": 2, "agp019_rpc": 4, "agp019_p2p": 5, "l6": 10,
                "agp021_rpc": 12, "agp021_p2p": 13, "agp021_hub": 14, "agp023_rpc": 15, "agp023_p2p": 16,
                "m4": 20, "m3": 30, "l13": 40}
PORT_BLOCK = 50
_port_base = []


def _block_free(base):
    import socket
    for p in range(base, base + PORT_BLOCK):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                return False
    return True


def port_base():
    if not _port_base:
        env = os.environ.get("XBT402_TEST_PORT_BASE")
        if env:
            base = int(env)
            if not 1024 <= base <= 65535 - PORT_BLOCK:
                raise ValueError(f"XBT402_TEST_PORT_BASE={env}: not in 1024..{65535 - PORT_BLOCK}")
        else:
            import random
            rng = random.Random()
            for _ in range(50):
                base = rng.randrange(20000, 60000, PORT_BLOCK)
                if _block_free(base):
                    break
            else:
                raise RuntimeError("no free block of test ports; set XBT402_TEST_PORT_BASE")
            sys.stderr.write(f"\n[test ports: XBT402_TEST_PORT_BASE unset, using {base}-{base + PORT_BLOCK - 1}]\n")
        _port_base.append(base)
    return _port_base[0]


def port_for(name, i=0):
    """The port for `name` (see PORT_OFFSETS), plus `i` for tests that bind several."""
    return port_base() + PORT_OFFSETS[name] + i


class RegtestNode:
    """A throwaway regtest node started with scripts/node.sh, which a test class owns: `start()`
    registers the teardown before it launches bitcoind, so a node that fails to start, or a class
    whose setUpClass or tests fail, is still stopped (SIGKILL after a grace period) and wiped."""

    def __init__(self, bin_dir, datadir, rpcport, p2pport, **env):
        self.datadir, self.rpcport = datadir, rpcport
        self.env = {**os.environ, "XBT_BIN": bin_dir, "XBT402_DATADIR": datadir,
                    "XBT402_RPCPORT": str(rpcport), "XBT402_P2PPORT": str(p2pport), **env}
        self.node_sh = os.path.join(ROOT, "scripts", "node.sh")
        self._stopped = False

    def start(self, test_class):
        test_class.addClassCleanup(self.stop)
        atexit.register(self.stop)
        self.stop(final=False)                      # a leftover datadir from a killed run
        self._stopped = False
        r = subprocess.run(["nice", "-n", "10", self.node_sh, "up"], env=self.env, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"regtest node on {self.rpcport} did not start: {r.stderr.strip()[-600:]}")
        from xbt402.rpc import RPC
        return RPC(self.rpcport, os.path.join(self.datadir, "regtest", ".cookie"))

    def _pid(self):
        try:
            with open(os.path.join(self.datadir, "regtest", "bitcoind.pid")) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _ours(self, pid):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read()
        except OSError:
            return False
        return b"bitcoind" in cmd and self.datadir.encode() in cmd

    def stop(self, final=True):
        import signal
        import time
        if self._stopped:
            return
        self._stopped = final
        subprocess.run([self.node_sh, "down"], env=self.env, capture_output=True, timeout=90)
        pid = self._pid()
        if pid and self._ours(pid):                 # `stop` did not answer: the node never came up
            for sig, wait in ((signal.SIGTERM, 30), (signal.SIGKILL, 5)):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    break
                end = time.time() + wait
                while time.time() < end:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.2)
                else:
                    continue
                break
        shutil.rmtree(self.datadir, ignore_errors=True)


def backends(ecc_mod):
    """The ECDSA backends this python can run: always the pure-Python fallback, plus coincurve."""
    return ["oracle"] + (["coincurve"] if ecc_mod.BACKEND == "coincurve" else [])


class use_backend:
    """Context manager: run `ecc_mod` on one backend (the fallback path is what python3 without
    coincurve runs, including this suite's verify)."""

    def __init__(self, ecc_mod, backend):
        self.ecc, self.backend = ecc_mod, backend

    def __enter__(self):
        self.saved, self.ecc.BACKEND = self.ecc.BACKEND, self.backend
        return self.ecc

    def __exit__(self, *a):
        self.ecc.BACKEND = self.saved
