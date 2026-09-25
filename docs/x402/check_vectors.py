#!/usr/bin/env python3
"""Test vectors for the x402 `xbt-channel` scheme (xbt402), checked against the reference library.

    python docs/x402/check_vectors.py            recompute every vector and compare with vectors.json
    python docs/x402/check_vectors.py --write    regenerate vectors.json from the library

Every value in vectors.json is recomputed here with the reference library (`xbt402/`, the package
at the root of this repository). The check also verifies what can be verified independently of the
generator: each signature verifies under the key the spec says signed it, p·G = P, both ECDH sides
agree on K, a non-strict-DER or 0x01 re-encoding of a state signature is refused, and a replayed
PAYMENT-SIGNATURE is refused with `bad_auth`. Exits 0 when everything matches, 1 on any mismatch.

Signatures are deterministic (RFC 6979, low S), so the vectors are byte-exact. The keys below are
test keys: never fund them.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from xbt402 import ecc  # noqa: E402
from xbt402.channel import (ChannelError, ChannelParams, Payee, Payer, _payee_tweak,  # noqa: E402
                            channel_auth_key, channel_payee_pub, channel_payee_secret)
from xbt402.tx import SIGHASH_ALL, SIGHASH_ALL_UNIFIED, Tx, segwit_address, sha256, tagged_hash  # noqa: E402
from xbt402.x402_channel import (XBT_MAINNET, XbtChannelProvider, b64json, close_message,  # noqa: E402
                                 receipt_message, request_auth, request_digest, unb64json)

VECTORS = os.path.join(HERE, "vectors.json")

# Test keys. Small, memorable scalars so anyone can re-derive them; worthless by construction.
PAYTO_SECRET = int.from_bytes(sha256(b"xbt402 test vector: payTo secret"), "big") % ecc.N
PAYER_SECRETS = [int.from_bytes(sha256(b"xbt402 test vector: payer secret %d" % i), "big") % ecc.N
                 for i in range(3)]
FUNDING_TXID = sha256(b"xbt402 test vector: funding tx").hex()   # stands in for a real funding txid
NETWORK = XBT_MAINNET
TIP = 1_000                    # stub chain tip for the round trip
EXPIRY = TIP + 1_014           # the reference client's default: minExpiryBlocks + 6
CAPACITY = 200_000
CLOSE_FEE = 600
PRICE = 150


def _pub(secret: int) -> str:
    return ecc.pubkey(secret).hex()


def _params(payer_secret: int, expiry: int = EXPIRY, capacity: int = CAPACITY, vout: int = 0) -> ChannelParams:
    p = ChannelParams.derive(_pub(PAYTO_SECRET), _pub(payer_secret), expiry, CLOSE_FEE)
    p.funding_txid, p.funding_vout, p.capacity = FUNDING_TXID, vout, capacity
    return p


def _lax_der(der: bytes) -> bytes:
    """The same (r, s) with a superfluous 0x00 before r: valid BER, not BIP66 strict DER."""
    rl = der[3]
    r, s = der[4:4 + rl], der[6 + rl:]
    body = b"\x02" + bytes([len(r) + 1]) + b"\x00" + r + s
    return b"\x30" + bytes([len(body)]) + body


# --- 1. payee key derivation P = payTo + t·G ------------------------------------------------------
def gen_derivation():
    out = []
    cases = [(PAYER_SECRETS[0], EXPIRY), (PAYER_SECRETS[0], EXPIRY + 1), (PAYER_SECRETS[1], 961_640 + 8_000)]
    for a, expiry in cases:
        pay_to, payer = bytes.fromhex(_pub(PAYTO_SECRET)), bytes.fromhex(_pub(a))
        t = _payee_tweak(pay_to, payer, expiry)
        p = ChannelParams.derive(pay_to.hex(), payer.hex(), expiry, CLOSE_FEE)
        out.append({
            "payTo": pay_to.hex(), "payerPub": payer.hex(), "expiry": expiry,
            "expiryLE32": expiry.to_bytes(4, "little").hex(),
            "tweakPreimage": (pay_to + payer + expiry.to_bytes(4, "little")).hex(),
            "t": "%064x" % t,
            "payeePub": channel_payee_pub(pay_to, payer, expiry).hex(),
            "redeemScript": p.script.hex(),
            "fundingSpk": p.spk.hex(),
            "fundingAddressMainnet": segwit_address("bc", p.spk),
            "payeeSpk": p.payee_spk, "payerSpk": p.payer_spk,
        })
    return out


# --- 2. request-authentication key and payload.auth ----------------------------------------------
def gen_auth():
    a = PAYER_SECRETS[0]
    p = _params(a)
    payee_secret = channel_payee_secret(PAYTO_SECRET, bytes.fromhex(p.payer_pub), p.expiry)
    k_payer = channel_auth_key(a, bytes.fromhex(p.payee_pub))
    k_payee = channel_auth_key(payee_secret, bytes.fromhex(p.payer_pub))
    shared = ecc.ecdh(a, bytes.fromhex(p.payee_pub))
    cases = []
    for method, path, body, seq, cum, sig in (
            ("GET", "/v1/quote?pair=XBT-USD", b"", 1, "0", None),
            ("POST", "/v1/infer", b'{"prompt":"hello"}', 2, "546", Payer(p, a).sign_state(546).hex()),
            ("POST", "/v1/a%20b?x=1", b"\x00\x01binary", 7, "1200", None)):
        req = request_digest(method, path, body)
        cases.append({"method": method, "path": path, "bodyHex": body.hex(), "req": req,
                      "chan": p.channel_id, "seq": seq, "cum": cum, "sig": sig or "",
                      "message": "|".join(("xbt402/auth", p.channel_id, str(seq), cum, sig or "", req)),
                      "auth": request_auth(k_payer, p.channel_id, seq, cum, sig, req)})
    return {"payerSecret": "%064x" % a, "payTo": _pub(PAYTO_SECRET), "payerPub": p.payer_pub,
            "expiry": p.expiry, "payeePub": p.payee_pub, "ecdhX": shared.hex(), "K": k_payer.hex(),
            "_K_payee_side": k_payee.hex(), "cases": cases}


# --- 3. states, close, refund --------------------------------------------------------------------
def gen_states():
    a = PAYER_SECRETS[0]
    p = _params(a)
    payee_secret = channel_payee_secret(PAYTO_SECRET, bytes.fromhex(p.payer_pub), p.expiry)
    out = {"payerSecret": "%064x" % a, "payToSecret": "%064x" % PAYTO_SECRET, "payeeSecret": "%064x" % payee_secret,
           "params": p.to_dict(), "chan": p.channel_id, "maxCum": p.max_amount, "states": []}
    for cum in (546, 150_000, p.max_amount - 545, p.max_amount):
        tx = p.state_tx(cum)
        sig = Payer(p, a).sign_state(cum)
        out["states"].append({"cum": cum, "unsignedTx": tx.hex(), "outputs": len(tx.outputs),
                              "sighash": p.sighash(tx).hex(), "payerSig": sig.hex()})
    payee = Payee(p, payee_secret)
    payee.accept(150_000, bytes.fromhex(out["states"][1]["payerSig"]))
    close = payee.close_tx()
    out["closeTx"] = {"cum": 150_000, "hex": close.hex(), "txid": close.txid(), "vsize": close.vsize()}
    refund = p.refund_tx(a)
    out["refundTx"] = {"hex": refund.hex(), "txid": refund.txid(), "nLockTime": refund.locktime}
    s = bytes.fromhex(out["states"][1]["payerSig"])
    out["invalid"] = [
        {"why": "non-strict DER (0x00 before r): consensus-invalid in segwit v0", "cum": 150_000,
         "payerSig": (_lax_der(s[:-1]) + s[-1:]).hex(), "error": "bad_sig"},
        {"why": "SIGHASH_ALL (0x01) instead of ALL|UNIFIED (0x21)", "cum": 150_000,
         "payerSig": (s[:-1] + bytes([SIGHASH_ALL])).hex(), "error": "bad_sighash"},
        {"why": "valid signature relabelled with a higher cum", "cum": 150_001,
         "payerSig": s.hex(), "error": "bad_sig"},
    ]
    return out


# --- 4. PAYMENT-REQUIRED / open / PAYMENT-SIGNATURE / PAYMENT-RESPONSE / close ----------------------
class StubNode:
    """The four RPCs the reference provider uses on a paid path, returning fixed answers."""

    def __init__(self, p: ChannelParams):
        self.p, self.sent = p, []

    def getblockcount(self):
        return TIP

    def getrawtransaction(self, txid, verbose=True):
        return {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 1,
                "vout": [{"n": 0, "value": self.p.capacity / 1e8, "scriptPubKey": {"hex": self.p.spk.hex()}}]}

    def gettxout(self, txid, vout, include_mempool=True):
        return {"confirmations": 1, "value": self.p.capacity / 1e8}

    def sendrawtransaction(self, hx):
        self.sent.append(hx)
        return Tx.parse(bytes.fromhex(hx)).txid()


def gen_roundtrip():
    a = PAYER_SECRETS[0]
    p = _params(a)
    node = StubNode(p)
    handler_body = b'{"result":"ok"}'
    with tempfile.TemporaryDirectory() as d:
        prov = XbtChannelProvider(node, PAYTO_SECRET, NETWORK, os.path.join(d, "ledger.sqlite"),
                                  lambda m, path: PRICE,
                                  lambda m, path, b: (200, {"Content-Type": "application/json"}, handler_body),
                                  billing="postpay", close_fee=CLOSE_FEE)
        url = "https://api.example.com/v1/infer?model=small"
        method, path, body = "POST", "/v1/infer?model=small", b'{"prompt":"hello"}'
        steps = []

        status, hdrs, out = prov.serve(method, path, {}, body, url)
        steps.append({"step": "unpaid request", "request": {"method": method, "path": path, "bodyHex": body.hex()},
                      "status": status, "PAYMENT-REQUIRED": hdrs["PAYMENT-REQUIRED"],
                      "decoded": unb64json(hdrs["PAYMENT-REQUIRED"])})
        accepted = unb64json(hdrs["PAYMENT-REQUIRED"])["accepts"][0]

        open_req = {"x402Version": 2, "network": NETWORK, "channel": {
            "txid": p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "payerSpk": p.payer_spk, "redeemScript": p.script.hex()}}
        status, _, out = prov.serve("POST", accepted["extra"]["openUrl"], {}, json.dumps(open_req).encode())
        steps.append({"step": "open", "path": accepted["extra"]["openUrl"], "request": open_req,
                      "status": status, "response": json.loads(out)})

        payer = Payer(p, a)
        k = channel_auth_key(a, bytes.fromhex(p.payee_pub))
        spent_msat, seq, headers = 0, 0, []
        for n in range(5):                      # postpay: each call pays for the calls before it
            need = -(-spent_msat // 1000)
            cum = max(need, payer.signed, 546 if need else 0)
            seq += 1
            pl = {"chan": p.channel_id, "seq": seq, "cum": str(cum)}
            if cum > payer.signed:
                pl["sig"] = payer.sign_state(cum).hex()
            pl["auth"] = request_auth(k, pl["chan"], seq, pl["cum"], pl.get("sig"), request_digest(method, path, body))
            hdr = b64json({"x402Version": 2, "accepted": accepted, "payload": pl})
            headers.append(hdr)
            status, h, out = prov.serve(method, path, {"PAYMENT-SIGNATURE": hdr}, body, url)
            receipt = unb64json(h["PAYMENT-RESPONSE"])
            spent_msat = int(receipt["spentMsat"])
            steps.append({"step": "paid call %d" % (n + 1), "PAYMENT-SIGNATURE": hdr, "payload": pl,
                          "status": status, "bodyHex": out.hex(), "PAYMENT-RESPONSE": h["PAYMENT-RESPONSE"],
                          "receipt": receipt})

        status, h, out = prov.serve(method, path, {"PAYMENT-SIGNATURE": headers[-1]}, body, url)
        steps.append({"step": "replay of paid call 5", "PAYMENT-SIGNATURE": headers[-1], "status": status,
                      "error": json.loads(out)["error"], "hasChannelDetails": "channel" in json.loads(out)})

        final = max(-(-spent_msat // 1000), payer.signed)   # the final state pays what is owed
        seq += 1
        pl = {"chan": p.channel_id, "seq": seq, "cum": str(final)}
        if final > payer.signed:
            pl["sig"] = payer.sign_state(final).hex()
        pl["auth"] = request_auth(k, pl["chan"], seq, pl["cum"], pl.get("sig"), request_digest("", "", b""))   # as the reference client does
        close_req = {"chan": p.channel_id, "sig": ecc.sign(a, close_message(p.channel_id)).hex(), "payload": pl}
        status, _, out = prov.serve("POST", accepted["extra"]["closeUrl"], {}, json.dumps(close_req).encode())
        steps.append({"step": "cooperative close", "path": accepted["extra"]["closeUrl"], "request": close_req,
                      "status": status, "response": json.loads(out), "closeTx": node.sent[-1]})
    return {"network": NETWORK, "tip": TIP, "payToSecret": "%064x" % PAYTO_SECRET, "payerSecret": "%064x" % a,
            "url": url, "price": PRICE, "billing": "postpay", "handlerBodyHex": handler_body.hex(), "steps": steps}


def generate():
    return {
        "title": "x402 xbt-channel test vectors",
        "version": "1.1-draft (wire-compatible with v1.0)",
        "generator": "docs/x402/check_vectors.py --write, reference library xbt402 (commit 702b262)",
        "notes": ["All keys are test keys derived from sha256 of fixed strings. Never fund them.",
                  "Hex is lowercase. Integers are JSON numbers unless the wire format uses decimal strings.",
                  "Signatures are RFC 6979 deterministic with low S, so every value is byte-exact.",
                  "Fields starting with '_' are cross-checks, not wire values."],
        "constants": {"network": NETWORK, "dust": 546, "closeFeeSat": CLOSE_FEE, "capacity": CAPACITY,
                      "sighashAllUnified": SIGHASH_ALL_UNIFIED,
                      "tags": ["xbt-channel/payee", "xbt402/auth-key", "xbt402/receipt", "xbt402/close",
                               "UnifiedSighash"]},
        "derivation": gen_derivation(),
        "auth": gen_auth(),
        "state": gen_states(),
        "roundtrip": gen_roundtrip(),
    }


# --- independent checks ----------------------------------------------------------------------------
def independent_checks(v) -> list:
    errs = []

    def need(ok, what):
        if not ok:
            errs.append(what)

    for i, d in enumerate(v["derivation"]):
        need(int.from_bytes(tagged_hash("xbt-channel/payee", bytes.fromhex(d["tweakPreimage"])), "big") % ecc.N
             == int(d["t"], 16), f"derivation[{i}]: t != tagged_hash(preimage) mod n")
        p = (PAYTO_SECRET + int(d["t"], 16)) % ecc.N
        need(ecc.pubkey(p).hex() == d["payeePub"], f"derivation[{i}]: (payTo_secret + t)·G != P")
    au = v["auth"]
    need(au["K"] == au["_K_payee_side"], "auth: payer and payee disagree on K")
    need(tagged_hash("xbt402/auth-key", bytes.fromhex(au["ecdhX"])).hex() == au["K"], "auth: K != tagged_hash(x)")
    st = v["state"]
    p = ChannelParams(**st["params"])
    for s in st["states"]:
        sig = bytes.fromhex(s["payerSig"])
        need(sig[-1] == SIGHASH_ALL_UNIFIED and ecc.is_strict_der(sig[:-1]), f"state {s['cum']}: not strict DER ‖ 0x21")
        need(ecc.verify(bytes.fromhex(p.payer_pub), bytes.fromhex(s["sighash"]), sig[:-1]),
             f"state {s['cum']}: payer signature does not verify")
    payee = Payee(p, int(st["payeeSecret"], 16))
    for bad in st["invalid"]:
        try:
            payee.verify_state(bad["cum"], bytes.fromhex(bad["payerSig"]))
            errs.append(f"invalid state accepted: {bad['why']}")
        except ChannelError as e:
            need(e.code == bad["error"], f"invalid state {bad['why']}: got {e.code}, want {bad['error']}")
    rt = v["roundtrip"]
    payee_pub = v["derivation"][0]["payeePub"]
    for s in rt["steps"]:
        if "receipt" in s:
            r = s["receipt"]
            need(ecc.verify(bytes.fromhex(payee_pub), receipt_message(r), bytes.fromhex(r["sig"])),
                 f"{s['step']}: receipt not signed by P")
            need(unb64json(s["PAYMENT-RESPONSE"]) == r, f"{s['step']}: header does not decode to the receipt")
        if s["step"].startswith("replay"):
            need(s["status"] == 402 and s["error"] == "bad_auth" and not s["hasChannelDetails"],
                 "replay: expected 402 bad_auth with no channel details")
        if s["step"] == "cooperative close":
            need(ecc.verify(bytes.fromhex(v["derivation"][0]["payerPub"]),
                            close_message(s["request"]["chan"]), bytes.fromhex(s["request"]["sig"])),
                 "close: request signature does not verify")
    return errs


def diff(want, got, path="$") -> list:
    if type(want) is not type(got):
        return [f"{path}: type {type(want).__name__} != {type(got).__name__}"]
    if isinstance(want, dict):
        out = [f"{path}.{k}: missing" for k in want if k not in got]
        out += [f"{path}.{k}: unexpected" for k in got if k not in want]
        for k in want:
            if k in got:
                out += diff(want[k], got[k], f"{path}.{k}")
        return out
    if isinstance(want, list):
        if len(want) != len(got):
            return [f"{path}: length {len(want)} != {len(got)}"]
        return [e for i, (a, b) in enumerate(zip(want, got)) for e in diff(a, b, f"{path}[{i}]")]
    return [] if want == got else [f"{path}: {str(want)[:60]} != {str(got)[:60]}"]


def main() -> int:
    got = generate()
    if "--write" in sys.argv:
        with open(VECTORS, "w") as f:
            json.dump(got, f, indent=1)
            f.write("\n")
        print(f"wrote {VECTORS}")
    with open(VECTORS) as f:
        want = json.load(f)
    errs = diff(want, got) + independent_checks(want)
    n = (len(want["derivation"]) + len(want["auth"]["cases"]) + len(want["state"]["states"])
         + len(want["state"]["invalid"]) + 2 + len(want["roundtrip"]["steps"]))
    for e in errs:
        print("MISMATCH", e)
    print(f"{'FAIL' if errs else 'OK'}: {n} vectors, backend {ecc.BACKEND}, {len(errs)} mismatches")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
