"""xbt402 end-to-end demo on the private regtest node.

An agent (client SDK) calls a paid API 25 times at 250 sat per call. The first call gets
402, the SDK opens a channel (funding from wallet `w`, i.e. the stand-in for the B2 agent
wallet), then every call carries a new 0x21-signed state. Then: a replayed stale state and an
unpaid call are refused, the agent asks for a cooperative close, the payee broadcasts the best
state, a block is mined, and the chain shows the payee got exactly what was served.
Exit status is 0 only if every check holds.
"""
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xbt402.funding import FundingPolicy                      # noqa: E402
from xbt402.http402 import SCHEME, Xbt402Client, Xbt402Server, format_params  # noqa: E402
from xbt402.rpc import RPC, RPCError                          # noqa: E402
from xbt402.tx import address_to_spk                          # noqa: E402

SAT = 100_000_000
PRICE_MSAT = 250_000   # 250 sat per call (~$0.0007 at $272/XBT)
CALLS = 25
PORT = int(os.environ.get("XBT402_HTTP_PORT", "19402"))


def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        sys.exit(1)


def main():
    node = RPC.from_env()
    payer_w = node.wallet("w")
    try:
        node.createwallet("payee")
    except RPCError:
        try:
            node.loadwallet("payee")
        except RPCError:
            pass
    payee_w = node.wallet("payee")
    mine = lambda n=1: node.generatetoaddress(n, payer_w.getnewaddress())  # noqa: E731

    def api(method, path, body):
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"answer": f"result for {path}", "height": node.getblockcount()}).encode()

    ledger = os.path.join(tempfile.mkdtemp(prefix="xbt402-"), "ledger.json")
    server = Xbt402Server(node, payee_w, ledger, lambda m, p: PRICE_MSAT, api,
                          policy=FundingPolicy(min_conf=1, min_expiry_blocks=144))
    httpd = server.http_server(PORT)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{PORT}"

    def fund(address, sats):
        txid = payer_w.sendtoaddress(address, sats / SAT)
        raw = node.getrawtransaction(txid, True)
        vout = next(o["n"] for o in raw["vout"] if o.get("scriptPubKey", {}).get("address") == address)
        return txid, vout

    client = Xbt402Client(fund, address_to_spk(payer_w.getnewaddress("", "bech32")).hex(),
                          node.getblockcount, capacity=100_000, expiry_blocks=1_008)

    print(f"[1] unpaid call to {base}/v1/answer")
    st, hdrs, _ = Xbt402Client._http("GET", base + "/v1/answer")
    check(st == 402 and hdrs.get("WWW-Authenticate", "").startswith(SCHEME), f"402 + {hdrs.get('WWW-Authenticate')}")

    print(f"[2] agent pays {CALLS} calls at {PRICE_MSAT // 1000} sat (channel opens on the first)")
    t0 = time.time()
    lat = []
    for i in range(CALLS):
        s = time.time()
        st, hdrs, out = client.request("GET", f"{base}/v1/answer?q={i}", on_open=lambda oc: mine(1))
        lat.append(time.time() - s)
        check(st == 200, f"call {i:2d}: 200, receipt credit={client.channels[base].receipts[-1]['credit_msat']} msat") \
            if i in (0, 1, CALLS - 1) else (st == 200 or check(False, f"call {i} status {st}"))
    oc = client.channels[base]
    cid = oc.payer.params.channel_id
    check(oc.payer.signed == CALLS * PRICE_MSAT // 1000, f"payer signed cumulative {oc.payer.signed} sat over {CALLS} calls")
    steady = sorted(lat[1:])[len(lat[1:]) // 2]
    print(f"      channel {cid}, total {time.time() - t0:.2f}s, median paid-call latency {steady * 1000:.1f} ms"
          f" (open incl. funding + 1 block: {lat[0] * 1000:.0f} ms)")

    print("[3] refusals")
    stale = format_params({"channel": cid, "amount": 546 + 250, "sig": "30" + "00" * 70 + "21"})
    st, _, out = Xbt402Client._http("GET", base + "/v1/answer", headers={"Authorization": f"{SCHEME} {stale}"})
    check(st == 402 and json.loads(out)["error"] == "stale_amount", f"stale/forged state -> 402 {json.loads(out)['error']}")
    nosig = format_params({"channel": cid, "amount": oc.payer.signed})
    st, _, out = Xbt402Client._http("GET", base + "/v1/answer", headers={"Authorization": f"{SCHEME} {nosig}"})
    check(st == 402 and json.loads(out)["error"] == "insufficient_credit", "no new payment, no credit -> 402 insufficient_credit")
    evil = format_params({"channel": cid, "amount": oc.payer.signed + 50_000, "sig": oc.payer.sign_state(oc.payer.signed)[:-1].hex() + "21"})
    st, _, out = Xbt402Client._http("GET", base + "/v1/answer", headers={"Authorization": f"{SCHEME} {evil}"})
    check(st == 402 and json.loads(out)["error"] == "bad_sig", "old sig relabelled with a higher amount -> 402 bad_sig")

    print("[4] refund tx the agent holds (valid only at expiry)")
    res = node.testmempoolaccept([oc.refund_hex])[0]
    check(not res["allowed"] and res["reject-reason"] == "non-final", f"refund now: {res['reject-reason']}")

    print("[5] cooperative close")
    txid = client.close(base)["txid"]
    mine(1)
    tx = node.getrawtransaction(txid, True)
    payee_spk = oc.payer.params.payee_spk
    paid = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == payee_spk)
    change = sum(round(o["value"] * SAT) for o in tx["vout"] if o["scriptPubKey"]["hex"] == oc.payer.params.payer_spk)
    check(tx["confirmations"] >= 1, f"close {txid} confirmed ({tx['vsize']} vB)")
    check(paid == CALLS * PRICE_MSAT // 1000, f"payee received {paid} sat on-chain = {CALLS} x {PRICE_MSAT // 1000}")
    check(change == 100_000 - paid - oc.payer.params.close_fee, f"payer change {change} sat (fee {oc.payer.params.close_fee})")
    wit = tx["vin"][0]["txinwitness"]
    check(wit[0].endswith("21") and wit[1].endswith("21"), "both close signatures are SIGHASH_ALL|UNIFIED (0x21)")
    httpd.shutdown()
    print("demo: all checks passed")


if __name__ == "__main__":
    main()
