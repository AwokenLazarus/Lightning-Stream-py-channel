#!/usr/bin/env python3
"""Test vectors for the x402 `xbt-channel` scheme (xbt402), checked against the reference library.

    python docs/x402/check_vectors.py            recompute every vector and compare with vectors.json
    python docs/x402/check_vectors.py --write    regenerate vectors.json from the library

Every value in vectors.json is recomputed here with the reference library (`xbt402/`, the package
at the root of this repository). The check also verifies what can be verified independently of the
generator: each tweak is the tagged hash of a preimage laid out as the spec says (len8(network) ‖
network ‖ payTo ‖ A ‖ LE32(expiry)), p·G = P, one payTo derives different keys on different networks
and differs from the v1.0 derivation, each signature verifies under the key the spec says signed it,
both ECDH sides agree on K, a non-strict-DER or 0x01 re-encoding of a state signature is refused, every
PAYMENT-RESPONSE is a SettlementResponse whose receipt verifies under P, a replayed PAYMENT-SIGNATURE is
refused with `bad_auth`, and for the hash-locked conditional call: H = sha256(k), the ciphertext is
the plaintext XOR the sha256(k || BE32(i)) keystream and is in the 402 before the payer signs, the
hash-lock script and P2WSH output are laid out as the spec says, the conditional state's payer
signature verifies, the provider's close carries that state, and its claim reveals k in the witness;
and for v1.2 payee-pays channels (closeFeePayer "payee"): every state pays the payee cum - closeFee and
the payer capacity - cum, the v1.1 signature for the same cum does not verify (the payer's signature
commits to who pays), the least state is dust + closeFee, the 0xA3 output 0 and the rollover's next
channel are the payer's whole remainder, the conditional state's fee comes out of the payee's
unconditional output, and a provider's /terms and hub-bound open carry closeFeePayer. Exits 0 when
everything matches, 1 on any mismatch.
Run it under both crypto backends: the project venv (libsecp256k1 via coincurve) and a Python without
coincurve (the pure-Python fallback); the output names the backend.

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
from xbt402.channel import (DERIVATION, DUST, PAYEE_TAG, SIGHASH_SINGLE_ACP_UNIFIED, ChannelError,  # noqa: E402
                            ChannelParams, Payee, Payer, _payee_tweak, channel_auth_key, channel_payee_pub,
                            channel_payee_secret, payee_tweak_preimage)
from xbt402.conditional import ConditionalParams, decrypt, preimage_from_tx  # noqa: E402
from xbt402.tx import SIGHASH_ALL, SIGHASH_ALL_UNIFIED, Tx, segwit_address, sha256, tagged_hash  # noqa: E402
from xbt402.x402_channel import (FACILITATOR_SETTLE, FACILITATOR_SUPPORTED, FACILITATOR_VERIFY,  # noqa: E402
                                 XBT_MAINNET, XbtChannelProvider, b64json, close_message, facilitator_request,
                                 receipt_message, receipt_of, request_auth, request_digest, unb64json)

VECTORS = os.path.join(HERE, "vectors.json")

# Test keys. Small, memorable scalars so anyone can re-derive them; worthless by construction.
PAYTO_SECRET = int.from_bytes(sha256(b"xbt402 test vector: payTo secret"), "big") % ecc.N
PAYER_SECRETS = [int.from_bytes(sha256(b"xbt402 test vector: payer secret %d" % i), "big") % ecc.N
                 for i in range(3)]
FUNDING_TXID = sha256(b"xbt402 test vector: funding tx").hex()   # stands in for a real funding txid
NETWORK = XBT_MAINNET
OTHER_NETWORKS = ["bip122:" + "11" * 16,      # example regtest id (the real one is per chain: block 101)
                  "bip122:000000000933ea01ad0ee984209779ba"]   # Bitcoin testnet3's id: any other network
TIP = 1_000                    # stub chain tip for the round trip
EXPIRY = TIP + 1_014           # the reference client's default: minExpiryBlocks + 6
CAPACITY = 200_000
CLOSE_FEE = 600
PRICE = 150


def _pub(secret: int) -> str:
    return ecc.pubkey(secret).hex()


def _params(payer_secret: int, expiry: int = EXPIRY, capacity: int = CAPACITY, vout: int = 0,
            close_fee_payer: str = "payer") -> ChannelParams:
    p = ChannelParams.derive(_pub(PAYTO_SECRET), _pub(payer_secret), expiry, CLOSE_FEE, network=NETWORK,
                             close_fee_payer=close_fee_payer)
    p.funding_txid, p.funding_vout, p.capacity = FUNDING_TXID, vout, capacity
    return p


def _lax_der(der: bytes) -> bytes:
    """The same (r, s) with a superfluous 0x00 before r: valid BER, not BIP66 strict DER."""
    rl = der[3]
    r, s = der[4:4 + rl], der[6 + rl:]
    body = b"\x02" + bytes([len(r) + 1]) + b"\x00" + r + s
    return b"\x30" + bytes([len(body)]) + body


# --- 1. payee key derivation P = payTo + t·G --------------------------------------------------------
def _v10_payee_pub(pay_to: bytes, payer: bytes, expiry: int) -> str:
    """v1.0's P (tag "xbt-channel/payee", no network), which a v1.1 provider refuses: a cross-check."""
    t = int.from_bytes(tagged_hash("xbt-channel/payee", pay_to + payer + expiry.to_bytes(4, "little")), "big") % ecc.N
    return ecc.pubkey((PAYTO_SECRET + t) % ecc.N).hex()


def gen_derivation():
    out = []
    cases = [(NETWORK, PAYER_SECRETS[0], EXPIRY), (NETWORK, PAYER_SECRETS[0], EXPIRY + 1),
             (NETWORK, PAYER_SECRETS[1], 961_640 + 8_000)] + [(n, PAYER_SECRETS[0], EXPIRY) for n in OTHER_NETWORKS]
    for network, a, expiry in cases:
        pay_to, payer = bytes.fromhex(_pub(PAYTO_SECRET)), bytes.fromhex(_pub(a))
        t = _payee_tweak(network, pay_to, payer, expiry)
        p = ChannelParams.derive(pay_to.hex(), payer.hex(), expiry, CLOSE_FEE, network=network)
        out.append({
            "network": network, "payTo": pay_to.hex(), "payerPub": payer.hex(), "expiry": expiry,
            "expiryLE32": expiry.to_bytes(4, "little").hex(),
            "tweakPreimage": payee_tweak_preimage(network, pay_to, payer, expiry).hex(),
            "t": "%064x" % t,
            "payeePub": channel_payee_pub(network, pay_to, payer, expiry).hex(),
            "redeemScript": p.script.hex(),
            "fundingSpk": p.spk.hex(),
            "fundingAddressMainnet": segwit_address("bc", p.spk),
            "payeeSpk": p.payee_spk, "payerSpk": p.payer_spk,
            "_payeePubV10": _v10_payee_pub(pay_to, payer, expiry),
        })
    return out


# --- 2. request-authentication key and payload.auth ----------------------------------------------
def gen_auth():
    a = PAYER_SECRETS[0]
    p = _params(a)
    payee_secret = channel_payee_secret(NETWORK, PAYTO_SECRET, bytes.fromhex(p.payer_pub), p.expiry)
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
    payee_secret = channel_payee_secret(NETWORK, PAYTO_SECRET, bytes.fromhex(p.payer_pub), p.expiry)
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
        self.p, self.sent, self.tip = p, [], TIP

    def getblockcount(self):
        return self.tip

    def getrawtransaction(self, txid, verbose=True):
        return {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 1,
                "vout": [{"n": 0, "value": self.p.capacity / 1e8, "scriptPubKey": {"hex": self.p.spk.hex()}}]}

    def gettxout(self, txid, vout, include_mempool=True):
        return {"confirmations": 1, "value": self.p.capacity / 1e8, "scriptPubKey": {"hex": self.p.spk.hex()},
                "coinbase": False}

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
            resp = unb64json(h["PAYMENT-RESPONSE"])
            receipt = receipt_of(resp)
            spent_msat = int(receipt["spentMsat"])
            steps.append({"step": "paid call %d" % (n + 1), "PAYMENT-SIGNATURE": hdr, "payload": pl,
                          "status": status, "bodyHex": out.hex(), "PAYMENT-RESPONSE": h["PAYMENT-RESPONSE"],
                          "settlementResponse": resp, "receipt": receipt})

        status, h, out = prov.serve(method, path, {"PAYMENT-SIGNATURE": headers[-1]}, body, url)
        steps.append({"step": "replay of paid call 5", "PAYMENT-SIGNATURE": headers[-1], "status": status,
                      "error": json.loads(out)["error"], "hasChannelDetails": "channel" in json.loads(out)})

        status, _, out = prov.serve("GET", FACILITATOR_SUPPORTED, {}, b"")
        steps.append({"step": "facilitator supported", "path": FACILITATOR_SUPPORTED, "status": status,
                      "response": json.loads(out)})
        last_sig = next(s["payload"]["sig"] for s in reversed(steps) if "sig" in s.get("payload", {}))
        signed = {"chan": p.channel_id, "cum": str(payer.signed), "sig": last_sig}   # the best state so far
        for what, pl in (("facilitator verify", signed),
                         ("facilitator verify, cum relabelled", {**signed, "cum": str(payer.signed + 1)})):
            req = facilitator_request(accepted, pl)
            status, _, out = prov.serve("POST", FACILITATOR_VERIFY, {}, json.dumps(req).encode())
            steps.append({"step": what, "path": FACILITATOR_VERIFY, "request": req, "status": status,
                          "response": json.loads(out)})

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
        req = facilitator_request(accepted, close_req)    # the same close through the facilitator: idempotent
        status, _, out = prov.serve("POST", FACILITATOR_SETTLE, {}, json.dumps(req).encode())
        steps.append({"step": "facilitator settle (same close)", "path": FACILITATOR_SETTLE, "request": req,
                      "status": status, "response": json.loads(out)})
    return {"network": NETWORK, "tip": TIP, "payToSecret": "%064x" % PAYTO_SECRET, "payerSecret": "%064x" % a,
            "url": url, "price": PRICE, "billing": "postpay", "handlerBodyHex": handler_body.hex(), "steps": steps}


# --- 5. hash-locked conditional call: offer, state, paid call, close, claim, recovery ----------------
COND_K = sha256(b"xbt402 test vector: conditional k")      # a revealed test key: never reuse a k
COND_PLAIN = b"the deliverable: a report sold under a hash lock\n"
COND_PRICE = 1_000
COND_PATH = "/v1/report"


def gen_conditional():
    """A payer buys a hash-locked deliverable, takes it, and never folds the increment into a plain
    state; at expiry - closeMarginBlocks the provider closes with the conditional state and claims
    the hash lock with k, which anyone can read from the claim's witness (preimage_from_tx)."""
    a = PAYER_SECRETS[1]
    p = _params(a)
    node = StubNode(p)
    with tempfile.TemporaryDirectory() as d:
        prov = XbtChannelProvider(node, PAYTO_SECRET, NETWORK, os.path.join(d, "ledger.sqlite"),
                                  lambda m, path: PRICE, lambda m, path, b: (200, {}, b'{"result":"ok"}'),
                                  billing="postpay", close_fee=CLOSE_FEE)
        h, cipher, _ = prov.offer_conditional(COND_PATH, COND_PRICE, COND_PLAIN, k=COND_K)
        url = "https://api.example.com" + COND_PATH
        steps = []
        status, hdrs, _ = prov.serve("GET", COND_PATH, {}, b"", url)
        offer = unb64json(hdrs["PAYMENT-REQUIRED"])
        steps.append({"step": "conditional offer", "status": status, "PAYMENT-REQUIRED": hdrs["PAYMENT-REQUIRED"],
                      "decoded": offer})
        accepted = offer["accepts"][0]
        cond_extra = accepted["extra"]["conditional"]
        open_req = {"x402Version": 2, "network": NETWORK, "channel": {
            "txid": p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "payerSpk": p.payer_spk, "redeemScript": p.script.hex()}}
        prov.serve("POST", accepted["extra"]["openUrl"], {}, json.dumps(open_req).encode())
        payer, kauth = Payer(p, a), channel_auth_key(a, bytes.fromhex(p.payee_pub))

        def paid(path, pl, seq):
            pl = {"chan": p.channel_id, "seq": seq, **pl}
            pl["auth"] = request_auth(kauth, pl["chan"], seq, pl["cum"], pl.get("sig"),
                                      request_digest("GET", path, b""))
            hdr = b64json({"x402Version": 2, "accepted": accepted, "payload": pl})
            st_, h_, out_ = prov.serve("GET", path, {"PAYMENT-SIGNATURE": hdr}, b"", "https://api.example.com" + path)
            return pl, hdr, st_, h_, out_
        uncond = 546                           # one plain call paid first: the payee's unconditional part
        pl, hdr, status, h1, _ = paid("/v1/x", {"cum": str(uncond), "sig": payer.sign_state(uncond).hex()}, 1)
        steps.append({"step": "plain paid call", "payload": pl, "status": status})
        cp = ConditionalParams(p, h, COND_PRICE, int(cond_extra["csvDelta"]))
        tx = cp.state_tx(uncond)
        csig = ecc.sign(a, cp.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        pl, hdr, status, h2, out = paid(COND_PATH, {"cum": str(uncond), "hashlock": h.hex(), "sig": csig.hex()}, 2)
        resp = unb64json(h2["PAYMENT-RESPONSE"])
        steps.append({"step": "conditional paid call", "PAYMENT-SIGNATURE": hdr, "payload": pl, "status": status,
                      "body": json.loads(out), "PAYMENT-RESPONSE": h2["PAYMENT-RESPONSE"],
                      "settlementResponse": resp, "receipt": receipt_of(resp)})
        node.tip = p.expiry - prov.close_margin         # the payer never folded: the watcher closes
        prov.close_due()
        close, claim = node.sent[:2]            # (the stub never reports the claim spent: it is re-sent)
        ctx, cltx = Tx.parse(bytes.fromhex(close)), Tx.parse(bytes.fromhex(claim))
        claim_vout = cltx.inputs[0].vout
        steps.append({"step": "conditional close", "closeTx": close, "txid": ctx.txid(), "vsize": ctx.vsize(),
                      "hashlockVout": next(i for i, o in enumerate(ctx.outputs) if o.script_pubkey == cp.spk)})
        steps.append({"step": "claim", "claimTx": claim, "txid": cltx.txid(), "vsize": cltx.vsize(),
                      "spends": f"{ctx.txid()}:{claim_vout}", "fee": COND_PRICE - cltx.outputs[0].value,
                      "preimageFromTx": preimage_from_tx(claim, h).hex(),
                      "recoveredPlaintextHex": decrypt(cipher, preimage_from_tx(claim, h)).hex()})
    return {"network": NETWORK, "payerSecret": "%064x" % a, "payToSecret": "%064x" % PAYTO_SECRET,
            "params": p.to_dict(), "chan": p.channel_id, "k": COND_K.hex(), "H": h.hex(),
            "plaintextHex": COND_PLAIN.hex(), "cipher": cipher.hex(), "condAmount": COND_PRICE,
            "csvDelta": cp.csv_delta, "hashlockScript": cp.script.hex(), "hashlockSpk": cp.spk.hex(),
            "state": {"uncond": uncond, "unsignedTx": tx.hex(), "outputs": len(tx.outputs),
                      "sighash": cp.sighash(tx).hex(), "payerSig": csig.hex()},
            "steps": steps}


# --- 6. v1.2 payee-pays (closeFeePayer "payee") -----------------------------------------------------
HUB_SECRET = int.from_bytes(sha256(b"xbt402 test vector: hub payTo secret"), "big") % ecc.N


def gen_payee_pays():
    """A payee-pays channel (v1.2, the default for hub-funded routed channels): states, close, the
    0xA3 fee-input state, a rollover, a conditional state, what does not verify, and the provider's
    /terms plus a hub-bound open that carries closeFeePayer."""
    from xbt402.route import hub_channel_message
    a = PAYER_SECRETS[2]
    p = _params(a, close_fee_payer="payee")
    payee_secret = channel_payee_secret(NETWORK, PAYTO_SECRET, bytes.fromhex(p.payer_pub), p.expiry)
    out = {"payerSecret": "%064x" % a, "payeeSecret": "%064x" % payee_secret, "params": p.to_dict(),
           "chan": p.channel_id, "minCum": p.min_amount, "maxCum": p.max_amount, "states": []}
    for cum in (p.min_amount, 150_000, p.capacity - DUST, p.capacity - DUST + 1, p.capacity):
        tx = p.state_tx(cum)
        sig = Payer(p, a).sign_state(cum)
        out["states"].append({"cum": cum, "unsignedTx": tx.hex(),
                              "outputs": [[o.value, o.script_pubkey.hex()] for o in tx.outputs],
                              "sighash": p.sighash(tx).hex(), "payerSig": sig.hex()})
    payee = Payee(p, payee_secret)
    payee.accept(150_000, bytes.fromhex(out["states"][1]["payerSig"]))
    close = payee.close_tx()
    out["closeTx"] = {"cum": 150_000, "hex": close.hex(), "txid": close.txid()}
    a3 = p.state_tx_a3(150_000)
    out["a3State"] = {"cum": 150_000, "unsignedTx": a3.hex(), "sighash": p.sighash_a3(a3).hex(),
                      "payerSig": Payer(p, a).sign_state_a3(150_000).hex()}
    nxt = ChannelParams.derive(_pub(PAYTO_SECRET), _pub(a), EXPIRY + 1_000, CLOSE_FEE, network=NETWORK,
                               close_fee_payer="payee")
    cap2 = p.rollover_next_capacity(150_000)
    roll = p.rollover_tx(150_000, nxt.spk, cap2)
    out["rollover"] = {"amount": 150_000, "nextExpiry": nxt.expiry, "nextSpk": nxt.spk.hex(), "nextCapacity": cap2,
                       "unsignedTx": roll.hex(), "sighash": p.sighash(roll).hex(),
                       "payerSig": (ecc.sign(a, p.sighash(roll)) + bytes([SIGHASH_ALL_UNIFIED])).hex()}
    cp = ConditionalParams(p, sha256(COND_K), COND_PRICE, 10)
    ctx = cp.state_tx(p.min_amount)
    out["conditional"] = {"H": cp.h.hex(), "condAmount": COND_PRICE, "csvDelta": 10, "uncond": p.min_amount,
                          "hashlockSpk": cp.spk.hex(), "unsignedTx": ctx.hex(), "sighash": cp.sighash(ctx).hex(),
                          "payerSig": (ecc.sign(a, cp.sighash(ctx)) + bytes([SIGHASH_ALL_UNIFIED])).hex()}
    v11 = Payer(_params(a), a).sign_state(150_000)                 # the same cum, signed as payer-pays
    out["invalid"] = [
        {"why": "a payer-pays (v1.1) signature for the same cum: the signature commits to who pays the fee",
         "cum": 150_000, "payerSig": v11.hex(), "error": "bad_sig"},
        {"why": "below the least state: the payee output would be dust after its close fee",
         "cum": p.min_amount - 1, "payerSig": out["states"][0]["payerSig"], "error": "bad_amount"},
    ]
    node = StubNode(p)
    with tempfile.TemporaryDirectory() as d:
        prov = XbtChannelProvider(node, PAYTO_SECRET, NETWORK, os.path.join(d, "ledger.sqlite"),
                                  lambda m, path: PRICE, lambda m, path, b: (200, {}, b"{}"), close_fee=CLOSE_FEE)
        terms = prov.terms()
        req = {"x402Version": 2, "network": NETWORK, "channel": {
            "txid": p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "payerSpk": p.payer_spk, "redeemScript": p.script.hex(), "closeFeePayer": "payee"},
            "hub": {"payTo": _pub(HUB_SECRET), "sig": ecc.sign(HUB_SECRET, hub_channel_message(p.channel_id)).hex()}}
        status, _, resp = prov.serve("POST", terms["extra"]["openUrl"], {}, json.dumps(req).encode())
    out["terms"] = terms
    out["open"] = {"request": req, "status": status, "response": json.loads(resp)}
    return out


def generate():
    return {
        "title": "x402 xbt-channel test vectors",
        "version": "1.2-draft (payee derivation %s, x402 v2 SettlementResponse and facilitator shapes, "
                   "closeFeePayer)" % DERIVATION,
        "generator": "docs/x402/check_vectors.py --write, reference library xbt402 v1.2",
        "notes": ["All keys are test keys derived from sha256 of fixed strings. Never fund them.",
                  "Hex is lowercase. Integers are JSON numbers unless the wire format uses decimal strings.",
                  "Signatures are RFC 6979 deterministic with low S, so every value is byte-exact.",
                  "Fields starting with '_' are cross-checks, not wire values.",
                  "Sections derivation..conditional are v1.1 and unchanged in v1.2 (payer-pays, closeFeePayer "
                  "absent); section payeePays is the v1.2 closeFeePayer \"payee\" state format."],
        "constants": {"network": NETWORK, "dust": 546, "closeFeeSat": CLOSE_FEE, "capacity": CAPACITY,
                      "sighashAllUnified": SIGHASH_ALL_UNIFIED,
                      "derivation": DERIVATION,
                      "tags": [PAYEE_TAG, "xbt402/auth-key", "xbt402/receipt", "xbt402/close",
                               "UnifiedSighash"]},
        "derivation": gen_derivation(),
        "auth": gen_auth(),
        "state": gen_states(),
        "roundtrip": gen_roundtrip(),
        "conditional": gen_conditional(),
        "payeePays": gen_payee_pays(),
    }


# --- independent checks ----------------------------------------------------------------------------
def independent_checks(v) -> list:
    errs = []

    def need(ok, what):
        if not ok:
            errs.append(what)

    for i, d in enumerate(v["derivation"]):
        net = d["network"].encode()
        need(bytes.fromhex(d["tweakPreimage"]) == bytes([len(net)]) + net + bytes.fromhex(d["payTo"])
             + bytes.fromhex(d["payerPub"]) + bytes.fromhex(d["expiryLE32"]),
             f"derivation[{i}]: preimage != len8(network) ‖ network ‖ payTo ‖ A ‖ LE32(expiry)")
        need(int.from_bytes(tagged_hash("xbt-channel/payee/v2", bytes.fromhex(d["tweakPreimage"])), "big") % ecc.N
             == int(d["t"], 16), f"derivation[{i}]: t != tagged_hash(preimage) mod n")
        p = (PAYTO_SECRET + int(d["t"], 16)) % ecc.N
        need(ecc.pubkey(p).hex() == d["payeePub"], f"derivation[{i}]: (payTo_secret + t)·G != P")
        need(d["payeePub"] != d["_payeePubV10"], f"derivation[{i}]: v1.1 key equals the v1.0 key")
    same = {d["payeePub"] for d in v["derivation"]
            if (d["payerPub"], d["expiry"]) == (v["derivation"][0]["payerPub"], v["derivation"][0]["expiry"])}
    need(len(same) == 1 + len(OTHER_NETWORKS), "derivation: one payTo, A, expiry must give one key per network")
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
            r, resp = s["receipt"], s["settlementResponse"]
            need(ecc.verify(bytes.fromhex(payee_pub), receipt_message(r), bytes.fromhex(r["sig"])),
                 f"{s['step']}: receipt not signed by P")
            need(unb64json(s["PAYMENT-RESPONSE"]) == resp, f"{s['step']}: header does not decode to the response")
            need(set(resp) == {"success", "transaction", "network", "payer", "amount", "extra"}
                 and resp["transaction"] == "" and resp["network"] == rt["network"]
                 and resp["payer"] == v["derivation"][0]["payerPub"] and resp["extra"]["receipt"] == r
                 and resp["extra"]["chargedAmount"] == r["charged"],
                 f"{s['step']}: PAYMENT-RESPONSE is not the SettlementResponse around the receipt")
        if s["step"] == "facilitator verify":
            need(s["response"].get("isValid") is True, "verify: a signed state must be valid")
        if s["step"].startswith("facilitator verify,"):
            need(s["response"] == {"isValid": False, "invalidReason": "invalid_xbt_channel_signature"},
                 "verify: a relabelled cum must be invalid_xbt_channel_signature")
        if s["step"].startswith("facilitator settle"):
            close = next(c for c in rt["steps"] if c["step"] == "cooperative close")
            need(s["response"].get("success") is True and s["response"].get("transaction") == close["response"]["txid"]
                 == Tx.parse(bytes.fromhex(close["closeTx"])).txid(),
                 "settle: SettlementResponse.transaction must be the close txid")
        if s["step"].startswith("replay"):
            need(s["status"] == 402 and s["error"] == "bad_auth" and not s["hasChannelDetails"],
                 "replay: expected 402 bad_auth with no channel details")
        if s["step"] == "cooperative close":
            need(ecc.verify(bytes.fromhex(v["derivation"][0]["payerPub"]),
                            close_message(s["request"]["chan"]), bytes.fromhex(s["request"]["sig"])),
                 "close: request signature does not verify")
    errs += conditional_checks(v)
    errs += payee_pays_checks(v)
    return errs


def payee_pays_checks(v) -> list:
    """The v1.2 section, recomputed from its own fields: output values against the formula, the
    payer's signatures, the v1.1 signature refused, the least state, 0xA3, rollover, conditional."""
    errs = []

    def need(ok, what):
        if not ok:
            errs.append("payeePays: " + what)
    pp = v.get("payeePays")
    if not pp:
        return ["payeePays: section missing"]
    p = ChannelParams(**pp["params"])
    cap, fee = p.capacity, p.close_fee
    need(p.close_fee_payer == "payee" and pp["params"].get("close_fee_payer") == "payee", "params are not payee-pays")
    need(pp["minCum"] == DUST + fee and pp["maxCum"] == cap, "least state != dust + closeFee or most != capacity")
    A = bytes.fromhex(p.payer_pub)
    for s in pp["states"]:
        want = [[s["cum"] - fee, p.payee_spk]] + ([[cap - s["cum"], p.payer_spk]] if cap - s["cum"] >= DUST else [])
        need(s["outputs"] == want, f"state {s['cum']}: outputs are not [cum - closeFee to P, capacity - cum to A]")
        tx = Tx.parse(bytes.fromhex(s["unsignedTx"]))
        need([[o.value, o.script_pubkey.hex()] for o in tx.outputs] == want, f"state {s['cum']}: tx outputs")
        sig = bytes.fromhex(s["payerSig"])
        need(sig[-1] == SIGHASH_ALL_UNIFIED and ecc.verify(A, bytes.fromhex(s["sighash"]), sig[:-1]),
             f"state {s['cum']}: payer signature does not verify")
    payee = Payee(p, int(pp["payeeSecret"], 16))
    for bad in pp["invalid"]:
        try:
            payee.verify_state(bad["cum"], bytes.fromhex(bad["payerSig"]))
            errs.append(f"payeePays: invalid state accepted: {bad['why']}")
        except ChannelError as e:
            need(e.code == bad["error"], f"invalid {bad['why']}: got {e.code}, want {bad['error']}")
    v11 = next(b for b in pp["invalid"] if b["error"] == "bad_sig")
    s150 = next(s for s in pp["states"] if s["cum"] == 150_000)
    need(not ecc.verify(A, bytes.fromhex(s150["sighash"]), bytes.fromhex(v11["payerSig"])[:-1]),
         "a v1.1 signature verifies over the payee-pays state")
    close = Tx.parse(bytes.fromhex(pp["closeTx"]["hex"]))
    need([o.value for o in close.outputs] == [150_000 - fee, cap - 150_000]
         and close.inputs[0].witness[0].hex() == s150["payerSig"], "close: not the signed 150,000 state")
    a3 = Tx.parse(bytes.fromhex(pp["a3State"]["unsignedTx"]))
    sig = bytes.fromhex(pp["a3State"]["payerSig"])
    need((a3.outputs[0].value, a3.outputs[0].script_pubkey.hex()) == (cap - 150_000, p.payer_spk)
         and a3.outputs[1].value == 150_000 - fee and sig[-1] == SIGHASH_SINGLE_ACP_UNIFIED
         and ecc.verify(A, bytes.fromhex(pp["a3State"]["sighash"]), sig[:-1]),
         "a3: output 0 is not the payer's capacity - cum under a 0xA3 signature")
    r = pp["rollover"]
    rt = Tx.parse(bytes.fromhex(r["unsignedTx"]))
    need([(o.value, o.script_pubkey.hex()) for o in rt.outputs]
         == [(r["amount"] - fee, p.payee_spk), (cap - r["amount"], r["nextSpk"])] and r["nextCapacity"] == cap - r["amount"],
         "rollover: not [amount - closeFee to P, capacity - amount to the next channel]")
    need(ecc.verify(A, bytes.fromhex(r["sighash"]), bytes.fromhex(r["payerSig"])[:-1]), "rollover: payer signature")
    c = pp["conditional"]
    ct = Tx.parse(bytes.fromhex(c["unsignedTx"]))
    need([(o.value, o.script_pubkey.hex()) for o in ct.outputs]
         == [(c["uncond"] - fee, p.payee_spk), (c["condAmount"], c["hashlockSpk"]),
             (cap - c["uncond"] - c["condAmount"], p.payer_spk)] and c["uncond"] >= DUST + fee,
         "conditional: the fee is not out of the payee's unconditional output")
    need(ecc.verify(A, bytes.fromhex(c["sighash"]), bytes.fromhex(c["payerSig"])[:-1]), "conditional: payer signature")
    t = pp["terms"]["extra"]
    need(t.get("closeFeePayer") == "payee" and "settleMultiple" in t, "terms: no closeFeePayer payee / settleMultiple")
    o = pp["open"]
    need(o["status"] == 200 and o["response"].get("closeFeePayer") == "payee"
         and o["response"].get("minCum") == str(DUST + fee) and o["response"]["chan"] == p.channel_id
         and o["request"]["channel"]["closeFeePayer"] == "payee",
         "open: a hub-bound payee-pays open must echo closeFeePayer and minCum")
    return errs


def conditional_checks(v) -> list:
    """The conditional section, recomputed from its own fields without the library's conditional
    module: H, the keystream, the hash-lock script, the payer's signature, the close and the claim."""
    errs = []

    def need(ok, what):
        if not ok:
            errs.append("conditional: " + what)
    c = v.get("conditional")
    if not c:
        return ["conditional: section missing"]
    k, h, plain, cipher = (bytes.fromhex(c[x]) for x in ("k", "H", "plaintextHex", "cipher"))
    need(sha256(k) == h, "H != sha256(k)")
    stream = b"".join(sha256(k + i.to_bytes(4, "big")) for i in range(-(-len(plain) // 32)))
    need(cipher == bytes(x ^ y for x, y in zip(plain, stream)),
         "cipher != plaintext XOR sha256(k || BE32(i)) keystream")
    p = ChannelParams(**c["params"])
    csv = c["csvDelta"]
    want = (bytes([0x63, 0xa8, 0x20]) + h + bytes([0x88, 0x21]) + bytes.fromhex(p.payee_pub) + bytes([0xac, 0x67])
            + (bytes([0x50 + csv]) if 1 <= csv <= 16 else bytes([1, csv])) + bytes([0xb2, 0x75, 0x21])
            + bytes.fromhex(p.payer_pub) + bytes([0xac, 0x68]))
    need(bytes.fromhex(c["hashlockScript"]) == want,
         "script != IF SHA256 <H> EQUALVERIFY <P> CHECKSIG ELSE <csvDelta> CSV DROP <A> CHECKSIG ENDIF")
    need(c["hashlockSpk"] == "0020" + sha256(want).hex(), "hashlockSpk != P2WSH(script)")
    s = c["state"]
    sig = bytes.fromhex(s["payerSig"])
    need(sig[-1] == SIGHASH_ALL_UNIFIED and ecc.is_strict_der(sig[:-1])
         and ecc.verify(bytes.fromhex(p.payer_pub), bytes.fromhex(s["sighash"]), sig[:-1]),
         "state: payer signature is not strict DER || 0x21 under A")
    outs = [(o.value, o.script_pubkey.hex()) for o in Tx.parse(bytes.fromhex(s["unsignedTx"])).outputs]
    need(outs[:2] == [(s["uncond"], p.payee_spk), (c["condAmount"], c["hashlockSpk"])]
         and outs[2] == (p.capacity - s["uncond"] - c["condAmount"] - p.close_fee, p.payer_spk),
         "state: outputs are not uncond to P, condAmount to the hash lock, change to the payer")
    steps = {st["step"]: st for st in c["steps"]}
    ce = steps["conditional offer"]["decoded"]["accepts"][0]["extra"]["conditional"]
    need(steps["conditional offer"]["status"] == 402 and ce == {"hash": c["H"], "amount": str(c["condAmount"]),
                                                                 "csvDelta": csv, "cipher": c["cipher"]},
         "offer: the 402 must carry {hash, amount, csvDelta, cipher} before the payer signs")
    paid = steps["conditional paid call"]
    need(paid["payload"]["hashlock"] == c["H"] and paid["payload"]["sig"] == s["payerSig"]
         and paid["payload"]["cum"] == str(s["uncond"]), "paid call: payload is not {cum: uncond, hashlock, sig}")
    need(paid["status"] == 200 and paid["body"] == {"cipher": c["cipher"], "preimage": c["k"], "hash": c["H"]},
         "paid call: the response must reveal k for the offered ciphertext")
    need(ecc.verify(bytes.fromhex(p.payee_pub), receipt_message(paid["receipt"]), bytes.fromhex(paid["receipt"]["sig"]))
         and paid["receipt"]["charged"] == str(c["condAmount"]), "paid call: receipt not signed by P for condAmount")
    close = Tx.parse(bytes.fromhex(steps["conditional close"]["closeTx"]))
    wit = close.inputs[0].witness
    need([(o.value, o.script_pubkey.hex()) for o in close.outputs] == outs and close.txid() == steps["conditional close"]["txid"]
         and wit[0] == sig and wit[2] == b"\x01" and wit[3] == p.script,
         "close: not the signed conditional state (payer sig, payee sig, IF branch, funding script)")
    claim = Tx.parse(bytes.fromhex(steps["claim"]["claimTx"]))
    cw = claim.inputs[0].witness
    hv = steps["conditional close"]["hashlockVout"]
    need(claim.inputs[0].txid[::-1].hex() == close.txid() and claim.inputs[0].vout == hv
         and close.outputs[hv].script_pubkey.hex() == c["hashlockSpk"], "claim: does not spend the hash-lock output")
    need(len(cw) == 4 and cw[1] == k and cw[2] == b"\x01" and cw[3] == want and cw[0][-1] == SIGHASH_ALL_UNIFIED,
         "claim: witness is not [payee sig || 0x21, k, 0x01, script]")
    need([(o.value, o.script_pubkey.hex()) for o in claim.outputs] == [(c["condAmount"] - steps["claim"]["fee"], p.payee_spk)],
         "claim: pays condAmount - fee to the payee key")
    got_k = next((w for w in cw if sha256(w) == h), b"")
    need(got_k == k and steps["claim"]["preimageFromTx"] == k.hex()
         and bytes.fromhex(steps["claim"]["recoveredPlaintextHex"]) == plain,
         "recovery: k from the claim's witness must decrypt the offered ciphertext")
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
         + len(want["state"]["invalid"]) + 2 + len(want["roundtrip"]["steps"])
         + 1 + len(want.get("conditional", {}).get("steps", []))
         + len(want.get("payeePays", {}).get("states", [])) + len(want.get("payeePays", {}).get("invalid", [])) + 6)
    for e in errs:
        print("MISMATCH", e)
    print(f"{'FAIL' if errs else 'OK'}: {n} vectors, backend {ecc.BACKEND}, {len(errs)} mismatches")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
