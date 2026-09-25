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
        return {"confirmations": tx["confirmations"], "value": tx["vout"][vout]["value"]}

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
        return tx.txid()


PRICE = 150


def make_provider(xc, node, billing="postpay", secret=0xB0B):
    """A provider from module `xc` (xbt402w2.x402_channel = unpatched, xbt402.x402_channel = tree)."""
    import tempfile
    return xc.XbtChannelProvider(node, secret, "bip122:" + "11" * 16, tempfile.mktemp(suffix=".json"),
                                 lambda m, p: PRICE, lambda m, p, b: (200, {}, b"ok"), billing=billing)


def make_channel(ch, prov, node, a=0xA11CE, capacity=200_000, vout=0, confs=6, payer_spk="", txid=None,
                 open_as=None, expiry_in=2000):
    """Fund and open a channel (module `ch` = channel module of the same tree). Returns (params, payer)."""
    p = ch.ChannelParams.derive(prov.pay_to, _pub(ch, a), node.height + expiry_in, prov.close_fee, payer_spk)
    p.funding_txid, p.funding_vout, p.capacity = txid or os.urandom(32).hex(), vout, capacity
    node.add_funding(p, confirmations=confs)
    for t in open_as or [p.funding_txid]:
        c = {"txid": t, "vout": vout, "capacity": capacity, "expiry": p.expiry, "payerPub": p.payer_pub,
             "redeemScript": p.script.hex()}
        if payer_spk:
            c["payerSpk"] = payer_spk
        prov.open({"x402Version": 2, "network": prov.network, "channel": c})
    return p, ch.Payer(p, a)


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
                                      xc.request_digest(method, path, body))
    return payload


class Repro:
    """Mixin: a finding reproduces on unpatched wave 2 (a failure means BASE changed, not the fix)."""

    def reproduces(self, cond, what):
        self.assertTrue(cond, f"did not reproduce on {BASE}: {what}")
        sys.stderr.write(f"\n    REPRODUCED on {BASE}: {what} ")


_base = {}


def base_tree():
    """The unpatched wave-2 tree (BASE) as an importable package `xbt402w2`, so the repro tests show
    each finding on the code XBT-060 shipped while the fixed tests run the tree they sit in."""
    if "dir" in _base:
        return _base["dir"]
    out = None
    tmp = tempfile.mkdtemp(prefix="xbt061-base-")
    try:
        arc = subprocess.run(["git", "-C", ROOT, "archive", BASE, "xbt402"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", tmp], input=arc, check=True)
        shutil.move(os.path.join(tmp, "xbt402"), os.path.join(tmp, "xbt402w2"))
        atexit.register(shutil.rmtree, tmp, True)
        out = tmp
    except (subprocess.CalledProcessError, OSError) as e:
        sys.stderr.write(f"base_tree: {e}\n")
    _base["dir"] = out
    return out


def base(name):
    """Import xbt402w2.<name>: unpatched wave 2 (raises SkipTest if git or BASE is unavailable)."""
    import importlib
    import unittest
    d = base_tree()
    if not d:
        raise unittest.SkipTest(f"unpatched base {BASE} unavailable")
    if d not in sys.path:
        sys.path.insert(0, d)
    return importlib.import_module(f"xbt402w2.{name}")


def load(name):
    """Import xbt402.<name> from the tree under test (wave2-hardened)."""
    import importlib
    return importlib.import_module(f"xbt402.{name}")


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
