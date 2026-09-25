"""xbt-channel (x402 v2) end-to-end demo on an isolated Knots 29.4.2 regtest node with RDTS on.

1. Unpaid call -> 402 with PAYMENT-REQUIRED (scheme xbt-channel, network bip122:<first BLAKE2b block>).
2. An agent (client SDK) opens a channel on the first call and makes 1,000 postpay calls at 150 sat.
3. Refusals: stale state, relabelled signature, wrong network, unpaid owed call.
4. Cooperative close with a final state paying what is owed; the chain shows exactly 1,000 x 150 sat.
5. A prepay provider takes 20 calls, then vanishes without closing; the agent's refund is non-final
   until expiry, then confirms and returns everything but the fee.
Exit 0 only if every check holds.
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
from xbt402.rpc import RPC, RPCError                                            # noqa: E402
from xbt402.x402_channel import (XbtChannelClient, XbtChannelProvider, b64json,  # noqa: E402
                                 network_id, unb64json)

SAT = 100_000_000
PRICE = 150            # sat per call (~$0.0004 at $272/XBT)
CALLS = int(os.environ.get("XBT402_CALLS", "1000"))
PORT = int(os.environ.get("XBT402_HTTP_PORT", "19402"))


def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        sys.exit(1)


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

    def start(provider, port):
        httpd = provider.http_server(port)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    tmp = tempfile.mkdtemp(prefix="xbt402-")
    provider = XbtChannelProvider(node, secrets.randbelow(2**255) + 1, net, f"{tmp}/post.json",
                                  lambda m, p: PRICE, api, billing="postpay", close_fee=600)
    httpd = start(provider, PORT)
    base = f"http://127.0.0.1:{PORT}"
    refunds = {}
    client = XbtChannelClient(net, fund, node.getblockcount, capacity=200_000,
                              on_open=lambda ch: mine(1), on_refund=lambda hx, exp: refunds.update({exp: hx}))

    print(f"[1] unpaid call ({net})")
    st, h, _ = client.http("GET", base + "/v1/infer")
    pr = unb64json(h["PAYMENT-REQUIRED"])
    acc = pr["accepts"][0]
    check(st == 402 and pr["x402Version"] == 2 and acc["scheme"] == "xbt-channel" and acc["network"] == net,
          f"402 PAYMENT-REQUIRED: scheme={acc['scheme']} amount={acc['amount']} {acc['asset']} "
          f"billing={acc['extra']['billing']} closeFeeSat={acc['extra']['closeFeeSat']}")

    print(f"[2] agent makes {CALLS} postpay calls at {PRICE} sat (channel opens on the first)")
    lat, t0 = [], time.time()
    for i in range(CALLS):
        s = time.time()
        st, h, _ = client.request("GET", f"{base}/v1/infer?q={i}")
        lat.append(time.time() - s)
        if st != 200:
            check(False, f"call {i}: status {st}")
    ch = client.channels[base]
    r = ch.receipts[-1]
    check(len(ch.receipts) == CALLS, f"{CALLS} calls served, {len(ch.receipts)} receipts verified (payee-signed)")
    check(int(r["spentMsat"]) == CALLS * PRICE * 1000 and int(r["owedMsat"]) == PRICE * 1000,
          f"provider ledger: spent {int(r['spentMsat']) // 1000} sat, owed {int(r['owedMsat']) // 1000} sat "
          f"(postpay: the last call is unpaid until the next state)")
    steady = lat[1:]
    print(f"      chan {ch.payer.params.channel_id}  total {time.time() - t0:.1f}s  paid-call p50 "
          f"{statistics.median(steady) * 1000:.1f} ms  p99 {sorted(steady)[int(len(steady) * .99)] * 1000:.1f} ms  "
          f"open (fund + 1 block) {lat[0] * 1000:.0f} ms")

    print("[3] refusals")
    def pay(payload, accepted=None):
        hdr = b64json({"x402Version": 2, "accepted": accepted or ch.accepted, "payload": payload})
        st, h, out = client.http("GET", base + "/v1/infer", headers={"PAYMENT-SIGNATURE": hdr})
        return st, unb64json(h["PAYMENT-REQUIRED"])["error"] if st == 402 else ""
    cid, signed = ch.payer.params.channel_id, ch.payer.signed
    check(pay({"chan": cid, "cum": "600", "sig": "30" * 3})[1] == "stale_amount", "old cumulative state -> stale_amount")
    relabel = ch.payer.sign_state(signed).hex()
    check(pay({"chan": cid, "cum": str(signed + 5_000), "sig": relabel})[1] == "bad_sig",
          "last signature relabelled with a higher cum -> bad_sig")
    check(pay({"chan": cid, "cum": str(signed)}, {**ch.accepted, "network": "bip122:000000000019d6689c085ae165831e93"})[1]
          == "unsupported_scheme_or_network", "SHA-256 Bitcoin network id -> refused")
    check(pay({"chan": cid, "cum": str(signed)})[1] == "insufficient_payment",
          f"call without paying the {int(r['owedMsat']) // 1000} sat owed -> insufficient_payment")

    print("[4] cooperative close (final state pays what is owed)")
    res = client.close(base)
    mine(1)
    tx = node.getrawtransaction(res["txid"], True)
    p = ch.payer.params
    paid = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == p.payee_spk)
    change = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == p.payer_spk)
    check(tx["confirmations"] >= 1, f"close {res['txid']} confirmed ({tx['vsize']} vB)")
    check(paid == CALLS * PRICE, f"payee got {paid} sat on-chain = {CALLS} x {PRICE}; unpaid {res['unpaidMsat']} msat")
    check(change == p.capacity - paid - p.close_fee, f"agent change {change} sat (close fee {p.close_fee})")
    wit = tx["vin"][0]["txinwitness"]
    check(wit[0].endswith("21") and wit[1].endswith("21"), "both close signatures SIGHASH_ALL|UNIFIED (0x21)")
    httpd.shutdown()

    print("[5] prepay provider vanishes -> agent refunds after expiry")
    pre = XbtChannelProvider(node, secrets.randbelow(2**255) + 1, net, f"{tmp}/pre.json",
                             lambda m, p: PRICE, api, billing="prepay", close_fee=600)
    httpd2 = start(pre, PORT + 1)
    base2 = f"http://127.0.0.1:{PORT + 1}"
    for i in range(20):
        st, _, _ = client.request("GET", f"{base2}/v1/infer?q={i}")
        if st != 200:
            check(False, f"prepay call {i}: status {st}")
    ch2 = client.channels[base2]
    check(ch2.payer.signed == 20 * PRICE and int(ch2.receipts[-1]["creditMsat"]) == 0,
          f"20 prepay calls: signed {ch2.payer.signed} sat before each call was served")
    httpd2.shutdown()                      # provider disappears, never closes
    p2 = ch2.payer.params
    refund = refunds[p2.expiry]
    res = node.testmempoolaccept([refund])[0]
    check(not res["allowed"] and res["reject-reason"] == "non-final", f"refund before expiry: {res['reject-reason']}")
    mine(p2.expiry - node.getblockcount())
    txid = node.sendrawtransaction(refund)
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
