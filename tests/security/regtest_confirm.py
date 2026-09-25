"""Chain-level confirmation of the XBT-061 findings on a Knots 29.4.2 regtest node with RDTS on.

Not part of the offline suite (the name doesn't match test*.py). Run with review/confirm.sh, which
starts a throwaway node on ports 30201/30202 under ~/xbt-rnd/xbt-061/run/ and wipes it on exit.
Every attack runs against the unpatched wave-2 provider (BASE 8a6bf26, on its pure-Python ECDSA
fallback as python3 without coincurve runs it) and a real node, and then against the tree's
hardened provider, which must refuse it (lines marked "fixed"):

  F1  non-strict DER state signature: the provider accepts it, the node refuses the close
  F2  one funding output opened twice by changing the case of its txid: both ledger rows credit
      the same signed state
  F3  a 35-byte payerSpk: the provider accepts and serves, the close is consensus-invalid under RDTS
  F4  the funding is reorged out and double-spent after open: the provider keeps serving
Prints one line per check; exits non-zero if an expectation fails.
"""
import json
import os
import secrets
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xbt402 import channel as hch, x402_channel as hxc                  # noqa: E402  (hardened)
from xbt402.rpc import RPC, RPCError                                    # noqa: E402
from xbt402.tx import segwit_address                                    # noqa: E402
from sechelp import authed, base, lax_der                               # noqa: E402

bch, bxc, ecc = base("channel"), base("x402_channel"), base("ecc")      # unpatched wave 2
ecc.BACKEND = "oracle"
network_id = bxc.network_id

SAT = 100_000_000
PRICE = 150
node = RPC.from_env()
w = node.wallet("w")
failures = []


def report(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        failures.append(what)


def mine(n=1):
    return node.generatetoaddress(n, w.getnewaddress())


def api(method, path, body):
    return 200, {}, b"ok"


def provider(xc=bxc):
    return xc.XbtChannelProvider(node, secrets.randbelow(2**255) + 1, network_id(node.getblockhash(101)),
                              tempfile.mktemp(suffix=".json"), lambda m, p: PRICE, api)


def open_channel(prov, payer_spk="", confirm=True, ch=bch):
    a = secrets.randbelow(ecc.N - 1) + 1
    p = ch.ChannelParams.derive(prov.pay_to, ecc.pubkey(a).hex(), node.getblockcount() + 1100, prov.close_fee, payer_spk)
    addr = segwit_address("bcrt", p.spk)
    txid = w.sendtoaddress(addr, 200_000 / SAT)
    raw = node.getrawtransaction(txid, True)
    vout = next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == addr)
    if confirm:
        mine()
    p.funding_txid, p.funding_vout, p.capacity = txid, vout, 200_000
    return p, ch.Payer(p, a)


def req(prov, p, chan, cum, sig=None, payer=None, seq=1):
    """A paid GET. With `payer` it carries the hardened protocol's request auth."""
    pl = {"chan": chan, "seq": seq, "cum": str(cum)}
    if sig is not None:
        pl["sig"] = sig
    if payer is not None:
        pl = authed(hxc, hch, payer, p.payee_pub, pl)
        pl["chan"] = chan
    hdr = bxc.b64json({"x402Version": 2, "accepted": prov.requirements(PRICE), "payload": pl})
    st, _, out = prov.serve("GET", "/v1/x", {"PAYMENT-SIGNATURE": hdr}, b"")
    return st if st != 402 else json.loads(out)["error"]


def open_req(p, txid=None, payer_spk=None):
    c = {"txid": txid or p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity, "expiry": p.expiry,
         "payerPub": p.payer_pub, "redeemScript": p.script.hex()}
    if payer_spk:
        c["payerSpk"] = payer_spk
    return c


def refused(prov, c, code):
    try:
        prov.open({"network": prov.network, "channel": c})
        return False
    except hch.ChannelError as e:
        return e.code == code


def mempool_reason(tx_hex):
    r = node.testmempoolaccept([tx_hex])[0]
    return r["allowed"], r.get("reject-reason", "")


def f1_lax_der():
    prov = provider()
    p, payer = open_channel(prov)
    prov.open({"network": prov.network, "channel": {"txid": p.funding_txid, "vout": p.funding_vout,
               "capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
    good = payer.sign_state(20_000)
    bad = lax_der(good[:-1]) + good[-1:]
    report(req(prov, p, p.channel_id, 20_000, bad.hex()) == 200, "F1 provider accepts a non-strict-DER state and serves")
    close = prov._payee(prov.ledger.channels[p.channel_id]).close_tx()
    ok, why = mempool_reason(close.hex())
    report(not ok and "DER" in why.upper(), f"F1 mempool refuses that close: {why}")
    try:
        node.generateblock(w.getnewaddress(), [close.hex()])
        report(False, "F1 a block containing that close is invalid (BIP66 is consensus)")
    except RPCError as e:
        report(True, f"F1 a block containing that close is invalid (BIP66 is consensus): {e}")
    hard = provider(hxc)
    p, payer = open_channel(hard, ch=hch)
    hard.open({"network": hard.network, "channel": open_req(p)})
    good = payer.sign_state(20_000)
    report(req(hard, p, p.channel_id, 20_000, (lax_der(good[:-1]) + good[-1:]).hex(), payer) == "bad_sig",
           "F1 fixed: the hardened provider refuses that state (bad_sig)")


def f2_case_replay():
    prov = provider()
    p, payer = open_channel(prov)
    for txid in (p.funding_txid, p.funding_txid.upper()):
        prov.open({"network": prov.network, "channel": {"txid": txid, "vout": p.funding_vout, "capacity": p.capacity,
                   "expiry": p.expiry, "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
    report(len(prov.ledger.channels) == 2, "F2 node resolves the upper-case txid; the provider opens 2 rows for 1 outpoint")
    sig = payer.sign_state(20_000).hex()
    served = sum(req(prov, p, f"{t}:{p.funding_vout}", 20_000, sig) == 200
                 for t in (p.funding_txid, p.funding_txid.upper()))
    rows = list(prov.ledger.channels.values())
    report(served == 2 and all(r.best_cum == 20_000 for r in rows),
           "F2 the same signed 20,000-sat state is credited on both rows (paid once, credited twice)")
    hard = provider(hxc)
    p, payer = open_channel(hard, ch=hch)
    hard.open({"network": hard.network, "channel": open_req(p)})
    report(refused(hard, open_req(p, p.funding_txid.upper()), "duplicate_channel"),
           "F2 fixed: the upper-case re-open is a duplicate_channel")


def f3_payer_spk():
    prov = provider()
    spk35 = "21" + ecc.pubkey(7).hex() + "ac"          # P2PK: 35 bytes, over the RDTS 34-byte output cap
    p, payer = open_channel(prov, payer_spk=spk35)
    prov.open({"network": prov.network, "channel": {"txid": p.funding_txid, "vout": p.funding_vout,
               "capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub, "payerSpk": spk35,
               "redeemScript": p.script.hex()}})
    report(req(prov, p, p.channel_id, 20_000, payer.sign_state(20_000).hex()) == 200,
           "F3 provider opens a channel with a 35-byte payerSpk and serves on it")
    close = prov._payee(prov.ledger.channels[p.channel_id]).close_tx()
    ok, why = mempool_reason(close.hex())
    report(not ok, f"F3 mempool refuses the close: {why}")
    try:
        node.generateblock(w.getnewaddress(), [close.hex()])
        report(False, "F3 a block containing the close is invalid")
    except RPCError as e:
        report(True, f"F3 a block containing the close is invalid: {e}")
    hard = provider(hxc)
    p, payer = open_channel(hard, payer_spk=spk35, ch=hch)
    report(refused(hard, open_req(p, payer_spk=spk35), "bad_payer_spk"), "F3 fixed: the open is refused (bad_payer_spk)")


def f4_reorg():
    prov, hard = provider(), provider(hxc)
    # a second channel, on the hardened provider, funded into the same block as the unpatched one's
    ha = secrets.randbelow(ecc.N - 1) + 1
    hp = hch.ChannelParams.derive(hard.pay_to, ecc.pubkey(ha).hex(), node.getblockcount() + 1100, hard.close_fee)
    haddr = segwit_address("bcrt", hp.spk)
    htxid = w.sendtoaddress(haddr, 200_000 / SAT)
    hp.funding_txid, hp.capacity = htxid, 200_000
    hp.funding_vout = next(o["n"] for o in node.getrawtransaction(htxid, True)["vout"]
                           if o["scriptPubKey"].get("address") == haddr)
    hpayer = hch.Payer(hp, ha)
    p, payer = open_channel(prov)                          # mines the block holding both fundings
    prov.open({"network": prov.network, "channel": open_req(p)})
    hard.open({"network": hard.network, "channel": open_req(hp)})
    report(req(hard, hp, hp.channel_id, 20_000, hpayer.sign_state(20_000).hex(), hpayer) == 200,
           "F4 fixed (setup): the hardened provider serves while its funding is confirmed")
    raw = node.getrawtransaction(p.funding_txid, True)
    node.invalidateblock(raw["blockhash"])
    # double-spend both fundings' inputs back to the wallet, paying more fee (full RBF replaces them)
    ins = [{"txid": i["txid"], "vout": i["vout"]} for t in (p.funding_txid, htxid)
           for i in node.getrawtransaction(t, True)["vin"] if i["txid"] not in (p.funding_txid, htxid)]
    total = sum(round(node.getrawtransaction(i["txid"], True)["vout"][i["vout"]]["value"] * SAT) for i in ins)
    conflict = w.signrawtransactionwithwallet(
        node.createrawtransaction(ins, {w.getnewaddress(): (total - 20_000) / SAT}))["hex"]
    node.sendrawtransaction(conflict)
    mine(3)
    gone = node.gettxout(p.funding_txid, p.funding_vout) is None and node.gettxout(htxid, hp.funding_vout) is None
    report(gone, "F4 both fundings reorged out and double-spent (gettxout is null)")
    prov._height_at = 0
    report(req(prov, p, p.channel_id, 20_000, payer.sign_state(20_000).hex()) == 200,
           "F4 provider still serves on the vanished channel")
    try:
        node.sendrawtransaction(prov._payee(prov.ledger.channels[p.channel_id]).close_tx().hex())
        report(False, "F4 close of the vanished channel is refused")
    except RPCError as e:
        report(True, f"F4 close of the vanished channel is refused: {e}")
    hard.close_due()                                       # one watcher tick
    hard._height_at = 0
    report(req(hard, hp, hp.channel_id, 30_000, hpayer.sign_state(30_000).hex(), hpayer, seq=2) == "unconfirmed",
           "F4 fixed: after one watcher tick the hardened provider suspends the vanished channel (unconfirmed)")


if __name__ == "__main__":
    for f in (f1_lax_der, f2_case_replay, f3_payer_spk, f4_reorg):
        f()
    print(f"regtest_confirm: {'all ok' if not failures else str(len(failures)) + ' FAILED'}")
    sys.exit(1 if failures else 0)
