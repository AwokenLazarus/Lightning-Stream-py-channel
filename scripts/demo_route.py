"""AGP-021 demo: xbt402 hub routing on regtest (scripts/demo_route.sh runs this on its own node).
AGP-023: every ch2 is payee-pays (xbt402 v1.2 closeFeePayer), so each provider pays its own settlement
close fee, D's threshold counts that fee (net payout >= 2x the fee), and every ch2 close and rollover is
checked to pay the provider its state less its own fee, and the hub its whole remainder.

1 client (B2 wallet signer when ~/xbt-rnd/b2-agp-023 is there, else B1's ChannelSigner), 1 hub,
4 providers. Operator 1 runs providers A and B under ONE payTo key (one provider serving two mounts on
two ports); C and D are separate operators. The client has ONE channel (to the hub); the hub funds one
channel per payTo itself (AGP-044: A and B share one).

  phase 1 (~10 s): the client streams chunks to all 4 providers at >= 12 calls/s each; per-window
                   adaptor locks pay each provider's accrued amount through the hub. A and B are
                   priced below a sat per call (amsat metering, carry at each hop). D settles once its
                   net payout is 2x its own close fee, so the hub rolls D's channel over (one tx pays D
                   less D's fee and funds the next channel with all the rest).
                   At 5 s provider C stops revealing: the hub writes the lock off after its reveal
                   timeout, stops routing to C, and neither channel pays the lock.
  phase 2 (~2 s):  the hub withholds receipts (keeps t + r): the client takes its receipts from the
                   providers' signed ROUTE-STATE instead, and keeps going.
  phase 3 (~9 s):  the hub withholds everything: providers stop serving within window + lockWait,
                   the client's stuck lock is voided when its invoice expires.
  settle:          the client closes ch1 (the hub closes it), the hub closes each ch2 (the provider
                   closes it); every close and rollover is checked on-chain against the ledgers.

Prints PASS/FAIL per check and latency numbers; writes a JSON report next to the node's datadir.
"""
import json
import os
import statistics
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xbt402 import adaptor, ecc  # noqa: E402
from xbt402.channel import DUST, SIGHASH_ALL_UNIFIED  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.hub import RouteHub  # noqa: E402
from xbt402.route import AMSAT_PER_SAT, ceil_div  # noqa: E402
from xbt402.route_client import RoutePayer  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider, network_id, unb64json  # noqa: E402

SAT = 100_000_000
PB = int(os.environ.get("XBT402_TEST_PORT_BASE", "34800"))
RPCPORT = int(os.environ.get("XBT402_RPCPORT", PB + 1))
DD = os.environ["XBT402_DATADIR"]
RUN = os.environ.get("DEMO_RUN", os.path.dirname(DD))
HUB_PORT, PROV_PORTS = PB + 10, [PB + 11, PB + 12, PB + 13, PB + 14]
WINDOW, LOCK_WAIT, INVOICE_TTL, REVEAL_TIMEOUT = 1.0, 3.0, 8.0, 2.0
RATE = 12.0                                   # calls per second per provider
PRICES = {  # amsat per call: A and B under a sat per call (sub-sat metering), C and D whole sats
    "A": 370 * 10 ** 18,                      # 0.37 sat
    "B": 813 * 10 ** 18 + 123_456_789,        # 0.813... sat, with an amsat tail
    "C": 20 * AMSAT_PER_SAT,
    "D": 40 * AMSAT_PER_SAT,
}
CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def pct(xs, q):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


class Chain:
    def __init__(self):
        self.rpc = RPC(RPCPORT, os.path.join(DD, "regtest", ".cookie"))
        self.w = self.rpc.wallet("w")
        self.addr = self.w.getnewaddress()
        self.lock = threading.Lock()

    def mine(self, n=1):
        with self.lock:
            return self.rpc.generatetoaddress(n, self.addr)

    def fund(self, address, sats):
        """The wallet hook (regtest: a block is mined after the spend, as B2 does)."""
        with self.lock:
            txid = self.w.sendtoaddress(address, sats / SAT)
            raw = self.rpc.getrawtransaction(txid, True)
            vout = next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)
            self.rpc.generatetoaddress(1, self.addr)
        return txid, vout

    def payee_out(self, txid, spk_hex):
        tx = self.rpc.getrawtransaction(txid, True)
        return tx.get("confirmations", 0), sum(round(o["value"] * SAT) for o in tx["vout"]
                                                if o["scriptPubKey"]["hex"] == spk_hex)


def make_signer(chain):
    """The client's signer: B2's policy-checked RouteSigner if b2-agp-023 is next to us."""
    b2 = os.environ.get("B2_ROOT", os.path.expanduser("~/xbt-rnd/b2-agp-023"))
    if os.path.exists(os.path.join(b2, "agentwallet", "routing.py")) and os.environ.get("DEMO_SIGNER", "b2") == "b2":
        os.environ["B1_ROOT"] = ROOT
        sys.path.insert(1, b2)
        from agentwallet.channels import ChannelBook
        from agentwallet.routing import RoutePolicy, RouteSigner
        d = tempfile.mkdtemp(prefix="b2-", dir=RUN)
        book = ChannelBook(os.path.join(d, "channels.json"), os.path.join(d, "channel_keys.json"))
        pol = RoutePolicy.from_dict({"hubs": {f"http://127.0.0.1:{HUB_PORT}": {"max_fee_ppm": 5_000,
                                                                               "max_fee_base_msat": 2_000}},
                                     "max_lock_sats": 20_000, "daily_budget_sats": 5_000_000})
        return RouteSigner(book, pol, fund=chain.fund, state_path=os.path.join(d, "routing.json")), "B2 (agentwallet.routing.RouteSigner)"
    from xbt402.signer import ChannelSigner
    return ChannelSigner(fund=chain.fund), "B1 ChannelSigner"


def mount(n):
    """Each provider's metered mount (A and B are two mounts of operator 1's one provider)."""
    return "/v1/chunk-b" if n == "B" else "/v1/chunk"


def provider(chain, name, secret, port, settle_multiple=20):
    served = {"n": 0}

    def handler(method, path, body):
        served["n"] += 1
        return 200, {"Content-Type": "application/json"}, json.dumps({"shard": name, "chunk": served["n"]}).encode()
    pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=1_008, max_expiry_blocks=8_640, close_margin=144)
    p = XbtChannelProvider(chain.rpc, secret, NET, os.path.join(RUN, f"prov-{name}.sqlite"), lambda m, pth: 1000,
                           handler, close_margin=144, policy=pol, settle_multiple=settle_multiple, height_ttl=0.5)
    p.offer_route(mount(name), window=WINDOW, lock_wait=LOCK_WAIT, invoice_ttl=INVOICE_TTL, amsat_per_call=PRICES[name])
    srv = p.http_server(port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return p, srv, served


def main():
    global NET
    t_start = time.time()
    chain = Chain()
    NET = network_id(chain.rpc.getblockhash(101))
    print(f"== node: height {chain.rpc.getblockcount()}, rpc {RPCPORT}, network {NET}")
    op1, op3, op4, hub_key = 0xA0A0, 0xC0C0, 0xD0D0, 0x4B4B
    provs = {}
    for name, sec, port, mult in (("A", op1, PROV_PORTS[0], 20), ("C", op3, PROV_PORTS[2], 20), ("D", op4, PROV_PORTS[3], 2)):
        provs[name] = provider(chain, name, sec, port, mult)
    # operator 1's second mount, on its own port: the same provider (one payTo, one ledger)
    pa = provs["A"][0]
    pa.offer_route(mount("B"), window=WINDOW, lock_wait=LOCK_WAIT, invoice_ttl=INVOICE_TTL, amsat_per_call=PRICES["B"])
    srv_b = pa.http_server(PROV_PORTS[1])
    threading.Thread(target=srv_b.serve_forever, daemon=True).start()
    provs["B"] = (pa, srv_b, provs["A"][2])
    urls = {n: f"http://127.0.0.1:{PROV_PORTS[i]}" for i, n in enumerate("ABCD")}
    check("operator 1 runs A and B under one payTo key", provs["A"][0].pay_to == provs["B"][0].pay_to
          and provs["A"][0].pay_to != provs["C"][0].pay_to, provs["A"][0].pay_to[:18] + "...")

    hub = RouteHub(chain.rpc, hub_key, NET, os.path.join(RUN, "hub"), chain.fund, fee_base_msat=100, fee_ppm=2_000,
                   max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=144, reveal_timeout=REVEAL_TIMEOUT,
                   ch2_capacity=150_000, ch2_expiry_blocks=1_100, close_margin=144)
    hsrv = hub.http_server(HUB_PORT)
    threading.Thread(target=hsrv.serve_forever, daemon=True).start()
    hub_url = f"http://127.0.0.1:{HUB_PORT}"
    print("== hub funds one channel per payTo from its own wallet (providers open nothing)")
    committed0 = hub.committed_sat()
    for n in "ABCD":
        cap = 30_000 if n == "D" else 150_000
        oc = hub.connect(urls[n], capacity=cap)
        print(f"   ch2 hub->{n}: {oc.p().channel_id[:20]}... capacity {oc.p().capacity}"
              + (" (A's: one ch2 per payTo)" if oc.origin != urls[n] else ""))
    hub.watch_tick()

    def ch2(n):
        return hub.ch2_for(urls[n])
    opened = [n for n in "ABCD" if ch2(n).state == "open"]
    check("hub-funded ch2 open to all 4 providers", len(opened) == 4, ",".join(opened))
    check("one live ch2 per payTo: A and B share one ch2, 3 funded for 4 origins, the cap counts it once",
          ch2("A").p().channel_id == ch2("B").p().channel_id and len(hub.out.chans) == 3
          and hub.committed_sat() - committed0 == 150_000 * 2 + 30_000,
          f"{len(hub.out.chans)} ch2s, {hub.committed_sat() - committed0} sat committed")
    _, h402, _ = hub.serve("GET", "/x402/route", {}, b"", f"http://127.0.0.1:{HUB_PORT}/x402/route")
    routing = unb64json(h402["PAYMENT-REQUIRED"])["accepts"][0]["extra"]["routing"]
    payers = {n: ch2(n).p().close_fee_payer for n in "ABCD"}
    check("v1.2: the hub advertises payee-pays ch2 (ch1 payer-pays) and every ch2 is payee-pays",
          (routing.get("ch1CloseFeePayer"), routing.get("ch2CloseFeePayer")) == ("payer", "payee")
          and set(payers.values()) == {"payee"},
          f"extra.routing ch1 {routing.get('ch1CloseFeePayer')}, ch2 {routing.get('ch2CloseFeePayer')}; "
          f"ch2 minCum {ch2('A').p().min_amount}")

    signer, signer_name = make_signer(chain)
    payer = RoutePayer(hub_url, NET, chain.rpc.getblockcount, fund=chain.fund, signer=signer,
                       capacity=200_000, expiry_blocks=8_000)
    ch1 = payer.open()
    print(f"== client ({signer_name}) opened ONE channel to the hub: {ch1['chan'][:20]}... capacity {ch1['capacity']}")
    shards = {n: payer.shard(urls[n] + mount(n)) for n in "ABCD"}

    # background: blocks every 1.5 s (rollover confirmations), hub watcher every 0.3 s
    stop = threading.Event()

    def miner():
        while not stop.wait(1.5):
            try:
                chain.mine()
            except Exception as e:  # noqa: BLE001
                print("miner:", e)
    threading.Thread(target=miner, daemon=True).start()
    hub_stop = hub.watch(0.3)

    run = {"on": True}
    tl = {n: [] for n in "ABCD"}                 # (time, status) per call

    def streamer(n):
        sh = shards[n]
        nxt = time.time()
        while run["on"]:
            nxt += 1.0 / RATE
            try:
                st, _, _ = payer.call(sh, "POST", b'{"tokens":1}')
            except Exception as e:  # noqa: BLE001
                st = f"err:{type(e).__name__}"
            tl[n].append((time.time(), st))
            time.sleep(max(0.0, nxt - time.time()))

    threads = [threading.Thread(target=streamer, args=(n,), daemon=True) for n in "ABCD"]
    t0 = time.time()
    for th in threads:
        th.start()
    payer.start(interval=WINDOW / 2)
    print(f"== phase 1: streaming to 4 providers at {RATE:.0f} calls/s each, {WINDOW:.0f} s windows")
    time.sleep(5.0)
    provs["C"][0].routes.no_reveal = True
    t_c = time.time()
    print(f"   t={t_c - t0:.1f}s provider C stops revealing")
    time.sleep(5.0)
    t_p1 = time.time()
    snap1 = {n: dict(calls=sum(1 for t, s in tl[n] if s == 200 and t <= t_p1)) for n in "ABCD"}

    print("== phase 2: the hub withholds receipts (t + r); the client reads t from the providers")
    via0 = payer.stats["via_provider"]
    hub.withhold = "receipt"
    time.sleep(2.5)
    via_provider = payer.stats["via_provider"] - via0

    print("== phase 3: the hub withholds everything")
    hub.withhold = "all"
    t_w = time.time()
    time.sleep(WINDOW + LOCK_WAIT + INVOICE_TTL - 2.0)
    run["on"] = False
    for th in threads:
        th.join(timeout=5)
    payer.stop()
    t_end = time.time()
    hub.withhold = ""
    stop.set()
    hub_stop.set()
    time.sleep(0.5)

    kinds = {}
    for e in payer.events:
        k = e["event"] + (":" + e.get("error", e.get("why", "")) if e["event"] != "lock" else ":" + e.get("via", ""))
        kinds[k] = kinds.get(k, 0) + 1
    print("   client lock events:", json.dumps(kinds, sort_keys=True))
    if getattr(signer, "denials", None):
        print("   signer denials:", signer.denials[:3])
    # --- phase 1 results -------------------------------------------------------------------------
    print("== phase 1 results")
    dur1 = t_p1 - t0
    for n in "ABD":
        rate = snap1[n]["calls"] / dur1
        check(f"provider {n}: >= 10 paid-route updates/s over phase 1", rate >= 10, f"{rate:.1f}/s")
    c_ok = [t for t, s in tl["C"] if s == 200]
    rate_c = sum(1 for t in c_ok if t <= t_c) / (t_c - t0)
    check("provider C: >= 10 updates/s until it stopped revealing", rate_c >= 10, f"{rate_c:.1f}/s")

    ev = hub.events
    rolls = [e for e in ev if e["event"] == "ch2_rollover"]
    fee_d = ch2("D").p().close_fee
    check("hub rolled D's channel over at D's threshold (net payout >= 2x its own close fee)",
          len(rolls) >= 1 and all(r["amount"] - fee_d >= 2 * fee_d for r in rolls),
          f"{len(rolls)} rollover(s), amounts {[r['amount'] for r in rolls]}, nets {[r['amount'] - fee_d for r in rolls]}")
    for r in rolls:
        old = next(a for a in hub.out.archived if a.get("rolled_to") == f"{r['txid']}:1")
        confs, paid = chain.payee_out(r["txid"], old["params"]["payee_spk"])
        check(f"rollover {r['txid'][:12]}... confirmed, pays D {r['amount']} less D's fee, the hub keeps the rest",
              confs >= 1 and paid == r["amount"] - fee_d and r["nextCapacity"] == old["params"]["capacity"] - r["amount"],
              f"{confs} conf, payee output {paid}, next ch2 {r['nextCapacity']} = {old['params']['capacity']} - {r['amount']}")

    voids = [e for e in ev if e["event"] == "void" and e["provider"] == urls["C"]]
    oc_c = ch2("C")
    held = [h for h in provs["C"][0].routes.held if h.get("pre")]
    st2c = next(iter(provs["C"][0].ledger.channels.values()))
    check("C never revealed: the hub wrote the lock off, stopped routing to C", bool(voids) and bool(oc_c.blocked),
          f"{len(voids)} lock(s) written off, blocked: {oc_c.blocked[:40]}")
    stuck_cum = held[0]["cum"] if held else None
    check("C never revealed: its ch2 does not pay the lock", held and st2c.best_cum < stuck_cum,
          f"ch2 best {st2c.best_cum} < held lock {stuck_cum}")
    if held:
        pre = adaptor.PreSig.from_json(held[0]["pre"])
        p2 = st2c.params
        tx = p2.state_tx(stuck_cum)
        mine = ecc.sign(provs["C"][0]._chan_secret(p2), p2.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [pre.bogus_der() + bytes([SIGHASH_ALL_UNIFIED]), mine, b"\x01", p2.script]
        r = chain.rpc.testmempoolaccept([tx.hex()])[0]
        check("C cannot close with the held pre-signature (no t, no signature)", not r["allowed"],
              r.get("reject-reason", ""))
    c_stop = next((t for t, s in tl["C"] if s == 402 and t > t_c), None)
    check("C: the client stopped being served once C's locks stopped", c_stop is not None,
          f"{(c_stop - t_c) if c_stop else 0:.1f} s after C stopped revealing")

    print("== phase 2/3 results")
    check("withheld receipts: the client took t from the providers' signed ROUTE-STATE", via_provider >= 1,
          f"{via_provider} lock(s) settled via the provider")
    stops = {}
    for n in "ABD":
        s = provs[n][0].routes.sessions[shards[n].session]
        first402 = next((t for t, st in tl[n] if st == 402 and t > t_w), None)
        stops[n] = first402
        o = provs[n][0].routes.offers[mount(n)]
        per_window = RATE * WINDOW * PRICES[n]
        bound = (o.window + o.lock_wait + 1.0) * RATE * PRICES[n]    # + 1 s: the last window's lock in flight
        owed = s.owed_amsat()
        check(f"withholding hub: {n} stopped serving, unpaid <= window + lockWait of traffic",
              first402 is not None and owed <= bound,
              f"stopped {first402 - t_w if first402 else -1:.1f} s after, unpaid {owed / AMSAT_PER_SAT:.2f} sat "
              f"(one window = {per_window / AMSAT_PER_SAT:.2f} sat, bound {bound / AMSAT_PER_SAT:.2f})")
    cvoid = [e for e in payer.events if e["event"] == "void" and "expired" in e.get("why", "")]
    worst = max([e["amount"] for e in cvoid] or [0])
    check("withholding hub: the client's stuck lock voided on invoice expiry, loss <= one lock",
          len(cvoid) >= 1 and worst <= 20_000, f"{len(cvoid)} voided, largest {worst} sat")

    # --- metering invariants -------------------------------------------------------------------
    print("== metering (amsat, carry at each hop)")
    for n in "ABCD":
        sh, s = shards[n], provs[n][0].routes.sessions[shards[n].session]
        check(f"{n}: provider meter == client meter (exact amsat)",
              s.accrued_amsat == sh.accrued_amsat == sh.seen_amsat,
              f"{s.accrued_amsat} amsat = {s.accrued_amsat / AMSAT_PER_SAT:.6f} sat over {s.calls} calls")
        check(f"{n}: paid == sum of completed locks, never above the ceil",
              s.paid_sat == sh.locked_sat <= ceil_div(s.accrued_amsat, AMSAT_PER_SAT),
              f"paid {s.paid_sat}, ceil {ceil_div(s.accrued_amsat, AMSAT_PER_SAT)}")

    ab = ch2("A")
    la, lb = shards["A"].locked_sat, shards["B"].locked_sat
    check("one ch2 per payTo: A's and B's locks all went over operator 1's one ch2",
          ch2("B").p().channel_id == ab.p().channel_id and ab.routed == la + lb and la > 0 and lb > 0,
          f"ch2 routed {ab.routed} = A {la} + B {lb}")

    # --- settlement --------------------------------------------------------------------------------
    print("== settle: client closes ch1, hub closes every ch2; check on-chain")
    ib = hub.inbound
    st1 = ib.ledger.channels[payer.chan]
    best1 = st1.best_cum
    c1 = payer.close()
    closes = {}
    for n in "ABCD":
        oc = ch2(n)
        if oc is not None and oc.state == "open":        # B's ch2 is A's: closed once
            closes["A+B" if n == "A" else n] = hub.close_ch2(oc)
    chain.mine()
    confs, paid1 = chain.payee_out(c1["txid"], st1.params.payee_spk)
    check("ch1 close confirmed, pays the hub its best state", confs >= 1 and paid1 == best1 == int(c1["cum"]),
          f"{paid1} sat = routed {payer.routed} (+ dust floor if any)")
    check("client and hub agree on ch1", payer.routed == int((st1.extra or {}).get("routed_sat", 0))
          and payer.fee_paid == int((st1.extra or {}).get("fee_paid", 0)),
          f"routed {payer.routed}, fees {payer.fee_paid}")
    total_d = onchain = fees_paid = 0
    for n, c in list(closes.items()):
        if c.get("event") == "ch2_idle":
            print(f"   ch2 {n}: {c['chan'][:16]}... has no state yet (opened by a rollover): nothing to close")
            del closes[n]
            continue
        st2 = next(s for s in provs[n[0]][0].ledger.channels.values() if s.closed_txid == c["txid"])
        confs, paid = chain.payee_out(c["txid"], st2.params.payee_spk)
        routed = int(st2.extra.get("routed_sat", 0))
        fee2 = st2.params.close_fee
        total_d += routed
        onchain += paid
        fees_paid += fee2
        _, change = chain.payee_out(c["txid"], st2.params.payer_spk)
        check(f"ch2 {n} close confirmed, pays the provider its best state less its own close fee",
              confs >= 1 and paid == st2.best_cum - fee2 and change == st2.params.capacity - st2.best_cum,
              f"{paid} = {st2.best_cum} - {fee2} sat, hub change {change}, routed on this channel {routed}"
              + (f", {st2.best_cum - routed} of the state the hub's floor prepay" if st2.best_cum > routed else ""))
    for r in rolls:
        onchain += r["amount"] - fee_d
        fees_paid += fee_d
        total_d += r["amount"]
    lock_ms = [x for s in shards.values() for x in s.lock_ms]
    call_ms = [x for s in shards.values() for x in s.call_ms]
    report = {
        "signer": signer_name, "network": NET, "duration_s": round(t_end - t0, 1),
        "calls": {n: sum(1 for t, s in tl[n] if s == 200) for n in "ABCD"},
        "phase1_rate_per_s": {n: round(snap1[n]["calls"] / dur1, 1) for n in "ABCD"},
        "call_ms": {"p50": round(statistics.median(call_ms), 2), "p95": round(pct(call_ms, 0.95), 2),
                    "max": round(max(call_ms), 1)},
        "lock_ms": {"n": len(lock_ms), "p50": round(statistics.median(lock_ms), 1), "p95": round(pct(lock_ms, 0.95), 1),
                    "max": round(max(lock_ms), 1)},
        "hub_lock_ms_p50": round(statistics.median(hub.stats["lock_ms"]), 1) if hub.stats["lock_ms"] else None,
        "locks": payer.stats, "client_routed_sat": payer.routed, "client_fee_sat": payer.fee_paid,
        "hub_events": hub.events, "rollovers": rolls, "ch1_close": c1, "ch2_closes": closes,
        "stops_after_withhold_s": {n: (round(t - t_w, 2) if t else None) for n, t in stops.items()},
        "checks": CHECKS, "elapsed_s": round(time.time() - t_start, 1),
    }
    print("== latency")
    print(f"   data call (client -> provider, metered, signed ROUTE-STATE): p50 {report['call_ms']['p50']} ms, "
          f"p95 {report['call_ms']['p95']} ms")
    print(f"   routed lock (client -> hub -> provider -> hub -> client, both hops' adaptor crypto): "
          f"p50 {report['lock_ms']['p50']} ms, p95 {report['lock_ms']['p95']} ms over {len(lock_ms)} locks")
    print(f"   locks: {payer.stats['locks']} settled ({payer.stats['floor_locks']} under the dust floor, "
          f"{payer.stats['via_provider']} receipts via the provider), {payer.stats['voided']} voided")
    print(f"   client paid {payer.routed} sat through the hub ({payer.fee_paid} sat routing fees); providers were "
          f"routed {total_d} sat and received {onchain} sat on-chain after paying their own {fees_paid} sat of close "
          f"fees (closes + rollovers; states above the routed total are the hub's one-off floor prepay, "
          f"dust + closeFee = 1,146 sat, on channels that routed less than that)")
    report["onchain_to_providers_sat"], report["routed_to_providers_sat"] = onchain, total_d
    report["provider_close_fees_sat"] = fees_paid
    ok = all(c["ok"] for c in CHECKS)
    with open(os.path.join(RUN, "demo_route_report.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    print(f"== demo_route: {'PASS' if ok else 'FAIL'} ({sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks) "
          f"report {os.path.join(RUN, 'demo_route_report.json')}")
    for srv in [hsrv] + [p[1] for p in provs.values()]:
        srv.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
