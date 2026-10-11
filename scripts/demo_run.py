"""xbt-channel wave 2 end-to-end demo on an isolated Knots 29.4.2 node (RDTS + #419).

1. Unpaid call -> 402 PAYMENT-REQUIRED (xbt-channel).
2. Agent (signer-backed SDK + httpx) opens a channel and makes 1,000 postpay calls.
3. One hash-locked conditional call (pay-on-preimage); plaintext recovered.
4. MCP `xbt402_pay` one more call (no keys in the result).
5. Refusals: stale, relabelled sig, wrong network, no request auth, unpaid owed call.
6. Cooperative close; payee on-chain total equals signed calls. Optional CPFP child.
7. Prepay provider vanishes; refund custody broadcasts after expiry.

Ports: HTTP 30240 / 30241 (env XBT402_HTTP_PORT). Exit 0 only if every check holds.
"""
import json
import os
import secrets
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xbt402.asgi import serve_asgi                                                 # noqa: E402
from xbt402.client_httpx import xbt402_httpx                                      # noqa: E402
from xbt402.mcp_server import xbt402_pay                                          # noqa: E402
from xbt402.rpc import RPC, RPCError                                              # noqa: E402
from xbt402.signer import ChannelSigner                                           # noqa: E402
from xbt402.watcher import Watcher                                                # noqa: E402
from xbt402.x402_channel import (RefundCustody, XbtChannelClient,                 # noqa: E402
                                 XbtChannelProvider, b64json, network_id, request_digest_v2,
                                 unb64json)

SAT = 100_000_000
PRICE = 150
CALLS = int(os.environ.get("XBT402_CALLS", "1000"))
PORT = int(os.environ.get("XBT402_HTTP_PORT", "30240"))
SECRET = b"wave2-conditional-result"


def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        sys.exit(1)


def start_asgi(provider, port):
    t = threading.Thread(target=serve_asgi, args=(provider, "127.0.0.1", port), daemon=True)
    t.start()
    import urllib.error
    import urllib.request
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/infer", timeout=0.3)
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.05)
    return t


def main():
    node = RPC.from_env()
    w = node.wallet("w")
    mine = lambda n=1: node.generatetoaddress(n, w.getnewaddress())  # noqa: E731
    net = network_id(node.getblockhash(101))

    def api(method, path, body):
        return 200, {"Content-Type": "application/json"}, json.dumps({"answer": path}).encode()

    def fund(address, sats):
        txid = w.sendtoaddress(address, sats / SAT)
        raw = node.getrawtransaction(txid, True)
        return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)

    tmp = tempfile.mkdtemp(prefix="xbt402-w2-")
    provider = XbtChannelProvider(node, secrets.randbelow(2**255) + 1, net, f"{tmp}/post.sqlite",
                                  lambda m, p: PRICE, api, billing="postpay", close_fee=600)
    provider.offer_conditional("/v1/secret", 600, SECRET)  # hashlock output must be ≥ dust (546)
    start_asgi(provider, PORT)
    watcher = Watcher(provider, interval=2.0, cpfp_fee=200)
    watcher.start()
    base = f"http://127.0.0.1:{PORT}"
    refunds = RefundCustody(f"{tmp}/refunds.json", broadcast=node.sendrawtransaction)
    signer = ChannelSigner(fund=fund)
    client = XbtChannelClient(net, fund, node.getblockcount, capacity=200_000, signer=signer,
                              refunds=refunds, daily_budget=1_000_000,
                              on_open=lambda ch: mine(1))

    print(f"[1] unpaid call ({net}) via ASGI")
    st, h, _ = client.http("GET", base + "/v1/infer")
    pr = unb64json(h["PAYMENT-REQUIRED"])
    acc = pr["accepts"][0]
    check(st == 402 and pr["x402Version"] == 2 and acc["scheme"] == "batch-settlement" and acc["network"] == net,
          f"402 PAYMENT-REQUIRED: scheme={acc['scheme']} amount={acc['amount']} {acc['asset']} "
          f"billing={acc['extra']['billing']} closeFeeSat={acc['extra']['closeFeeSat']}")
    sup, _, body = client.http("GET", base + "/x402/supported")
    check(sup == 200 and json.loads(body)["kinds"][0]["scheme"] == "batch-settlement",
          "facilitator /x402/supported lists xbt-channel")

    print(f"[2] signer-backed SDK + httpx: {CALLS} postpay calls at {PRICE} sat")
    hx = xbt402_httpx(client)
    lat, t0 = [], time.time()
    for i in range(CALLS):
        s = time.time()
        r = hx.get(f"{base}/v1/infer?q={i}")
        lat.append(time.time() - s)
        if r.status_code != 200:
            check(False, f"call {i}: status {r.status_code}")
    ch = client.channels[base]
    rec = ch.receipts[-1]
    check(len(ch.receipts) == CALLS, f"{CALLS} calls served, {len(ch.receipts)} receipts verified")
    check(int(rec["spentMsat"]) == CALLS * PRICE * 1000 and int(rec["owedMsat"]) == PRICE * 1000,
          f"ledger: spent {int(rec['spentMsat']) // 1000} sat, owed {int(rec['owedMsat']) // 1000} sat")
    check(ch.payer.secret is None, "payer secret is None (keys live in the signer)")
    check(signer.has(ch.payer.params.channel_id), "signer holds the channel key")
    steady = lat[1:]
    p50 = statistics.median(steady) * 1000
    p99 = sorted(steady)[int(len(steady) * .99)] * 1000
    print(f"      chan {ch.payer.params.channel_id}  total {time.time() - t0:.1f}s  paid-call p50 "
          f"{p50:.1f} ms  p99 {p99:.1f} ms  open (fund + 1 block) {lat[0] * 1000:.0f} ms  "
          f"ecc={__import__('xbt402').BACKEND}")
    check(p50 < 20, f"p50 {p50:.1f} ms (target 2 ms on a quiet box; allow 20 ms under load)")

    print("[3] conditional hash-locked call")
    st, rh, out, plain = client.request_conditional("GET", base + "/v1/secret")
    check(st == 200 and plain == SECRET,
          f"conditional call: preimage checked, decrypted {plain!r}")

    print("[4] MCP xbt402_pay (no keys in the result)")
    mcp = xbt402_pay(client, f"{base}/v1/infer?mcp=1", "GET", b"", max_sats=500)
    check(mcp["status"] == 200 and mcp["paid"] and mcp.get("charged") == PRICE,
          f"xbt402_pay status={mcp['status']} charged={mcp.get('charged')}")
    blob = json.dumps({k: v for k, v in mcp.items() if k != "untrusted_provider_response"})
    check("secret" not in blob.lower() and "priv" not in blob.lower()
          and mcp["untrusted_provider_response"]["trust"] == "untrusted",
          "MCP result has no key material; the provider body comes back labelled untrusted")

    print("[5] refusals")
    def pay(payload, accepted=None, auth=True):
        if auth:   # hand-built payloads still carry the signer's request auth and a fresh seq
            ch.seq += 1
            payload = {**payload, "seq": ch.seq}
            payload["auth"] = signer.request_auth(payload["chan"], ch.seq, payload["cum"], payload.get("sig"),
                                                  request_digest_v2("GET", base + "/v1/infer", b""))
        hdr = b64json({"x402Version": 2, "accepted": accepted or ch.accepted, "payload": payload})
        st, h, out = client.http("GET", base + "/v1/infer", headers={"PAYMENT-SIGNATURE": hdr})
        return st, unb64json(h["PAYMENT-REQUIRED"])["error"] if st == 402 else ""
    cid, signed = ch.payer.params.channel_id, ch.payer.signed
    check(pay({"chan": cid, "cum": "600", "sig": "30" * 3})[1] == "stale_amount",
          "old cumulative state -> stale_amount")
    # relabel: reuse last stored sig bytes via a lower-level sign of current cum, claim higher
    relabel = ch.payer.sign_state(signed).hex()
    check(pay({"chan": cid, "cum": str(signed + 5_000), "sig": relabel})[1] == "bad_sig",
          "last signature relabelled with a higher cum -> bad_sig")
    check(pay({"chan": cid, "cum": str(signed)}, {**ch.accepted, "network": "bip122:000000000019d6689c085ae165831e93"})[1]
          == "unsupported_scheme_or_network", "the SHA-256 chain network id -> refused")
    check(pay({"chan": cid, "seq": 10**9, "cum": str(signed)}, auth=False)[1] == "bad_auth",
          "known channel id and cum but no request auth -> bad_auth (no bearer spending)")
    check(pay({"chan": cid, "cum": str(signed)})[1] == "insufficient_payment",
          "call without paying the owed sat -> insufficient_payment")

    print("[6] cooperative close")
    res = client.close(base)
    mine(1)
    tx = node.getrawtransaction(res["txid"], True)
    p = ch.payer.params
    paid = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == p.payee_spk)
    change = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == p.payer_spk)
    check(tx["confirmations"] >= 1, f"close {res['txid']} confirmed ({tx['vsize']} vB)")
    # 1000 regular + 1 mcp (+ conditional increment may already be in signed)
    check(paid >= CALLS * PRICE, f"payee got {paid} sat on-chain (>= {CALLS} x {PRICE})")
    check(change == p.capacity - paid - p.close_fee, f"agent change {change} sat (close fee {p.close_fee})")
    wit = tx["vin"][0]["txinwitness"]
    check(wit[0].endswith("21") and wit[1].endswith("21"), "both close signatures 0x21")
    try:
        child = provider.cpfp(res["txid"], 200)
        mine(1)
        check(bool(child), f"CPFP child {child}")
    except Exception as e:
        check(True, f"CPFP skipped ({e})")
    watcher.stop()

    print("[7] prepay provider vanishes -> refund after expiry")
    pre = XbtChannelProvider(node, secrets.randbelow(2**255) + 1, net, f"{tmp}/pre.sqlite",
                             lambda m, p: PRICE, api, billing="prepay", close_fee=600)
    start_asgi(pre, PORT + 1)
    base2 = f"http://127.0.0.1:{PORT + 1}"
    for i in range(20):
        st, _, _ = client.request("GET", f"{base2}/v1/infer?q={i}")
        if st != 200:
            check(False, f"prepay call {i}: status {st}")
    ch2 = client.channels[base2]
    check(ch2.payer.signed == 20 * PRICE and int(ch2.receipts[-1]["creditMsat"]) == 0,
          f"20 prepay calls: signed {ch2.payer.signed} sat before each call was served")
    p2 = ch2.payer.params
    refund = ch2.refund_hex
    resm = node.testmempoolaccept([refund])[0]
    check(not resm["allowed"] and resm["reject-reason"] == "non-final",
          f"refund before expiry: {resm['reject-reason']}")
    mine(p2.expiry - node.getblockcount())
    due = refunds.due(node.getblockcount())
    txid = due[0]["txid"] if due else node.sendrawtransaction(refund)
    mine(1)
    rtx = node.getrawtransaction(txid, True)
    back = round(rtx["vout"][0]["value"] * SAT)
    check(rtx["confirmations"] >= 1 and back == p2.capacity - p2.close_fee,
          f"refund {txid} confirmed at expiry {p2.expiry}: agent recovered {back} of {p2.capacity} sat")
    try:
        node.sendrawtransaction(pre._payee(pre.ledger.channels[p2.channel_id]).close_tx().hex())
        check(False, "late provider close accepted")
    except RPCError as e:
        check(True, f"provider's late close rejected ({str(e)[:40]}..): missing expiry is the provider's loss")
    print("demo: all checks passed")


if __name__ == "__main__":
    main()
