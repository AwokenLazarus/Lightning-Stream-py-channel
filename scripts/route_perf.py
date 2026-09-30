"""AGP-054: routed vs unpaid throughput of a 3-stage pipeline, in process (no sockets, no node).

    python scripts/route_perf.py --dir ~/xbt-rnd/b1-agp-054/run/perf --tokens 200 \
        --stages 18.5,3.5,36 --b2 ~/xbt-rnd/cmp-rails/b2-04c3f56 --journal cmp --out result.json

A client decodes `--tokens` tokens; each token calls stage 1, 2, 3 in turn (like cmp's decode
route). Each stage's handler sleeps its compute time in ms. Unpaid: the same handlers, no payment.
Paid: b1 RoutePayer.call over a hub (RouteHub, fake node), a lock driver thread locking every shard
as soon as a sat is due (cmp's LockDriver pacing, off the data path). The payer's signer is B2's
RouteSigner (ChannelBook on disk) when `--b2` is given, else B1's in-memory ChannelSigner.

Every ledger, book and journal lives under `--dir`, so fsyncs cost what they cost on that disk.

--journal
  none   b1 only (no per-call durability of the route session)
  cmp    emulates cmp's RouteJournal: one line appended and fdatasync'ed after b1's serve, before the
         answer leaves (billing_routed._journal_route), per routed call
  wal    b1's RouteWal (AGP-054): the session's post-call state is written ahead while the handler
         runs, and the answer waits for it (usually already durable)

Output: ms per token (p50 of each stage call and the mean over the run), tok/s, the routed/unpaid
ratio, locks made, and where the data path waited (RoutePayer lock waits).
"""
import argparse
import json
import os
import statistics
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _i, _a in enumerate(sys.argv):          # --b1 <root>: measure another B1 tree (e.g. the pre-AGP-054 line)
    if _a == "--b1" and _i + 1 < len(sys.argv):
        ROOT = os.path.abspath(os.path.expanduser(sys.argv[_i + 1]))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "security"))

NET = "bip122:" + "11" * 16
HUB = "http://hub.test"


def pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(len(xs) * q))], 3) if xs else None


class Unpaid:
    """A stage without payment: the handler alone."""

    def __init__(self, handler):
        self.handler = handler

    def serve(self, method, path, headers, body, url=""):
        return self.handler(method, path, body)


def stage_handler(ms):
    def h(method, path, body):
        time.sleep(ms / 1000.0)
        return 200, {"Content-Type": "application/octet-stream"}, body
    return h


class CmpJournal:
    """cmp's RouteJournal on the provider (CMP-018 R3), reduced to its cost: after b1's serve of a
    routed call, one line {s, seq, calls, acc, us} is appended and fdatasync'ed before the answer
    leaves (a single writer here, so a group commit has nothing to group)."""

    def __init__(self, prov, path):
        self.prov, self.fh, self.lock = prov, open(path, "ab"), threading.Lock()
        self.inner = prov.serve

    def serve(self, method, path, headers, body, url="", max_body=None):
        st, h, out = self.inner(method, path, headers, body, url)
        if "ROUTE-AUTH" in {k.upper() for k in headers} and "ROUTE-STATE" in h:
            from xbt402.x402_channel import unb64json
            rs = unb64json(h["ROUTE-STATE"])
            line = json.dumps({"s": rs["session"], "seq": rs["seq"], "calls": rs["calls"],
                               "acc": rs["accruedAmsat"]}, separators=(",", ":")) + "\n"
            with self.lock:
                self.fh.write(line.encode())
                self.fh.flush()
                os.fdatasync(self.fh.fileno())
        return st, h, out


def build(a, d):
    from sechelp import FakeNode  # noqa: F401  (routehelp needs it on the path)
    from routehelp import Net, RouteNode
    from xbt402 import ecc
    from xbt402.funding import FundingPolicy
    from xbt402.hub import RouteHub
    from xbt402.route_client import RoutePayer
    from xbt402.x402_channel import XbtChannelProvider

    node, net = RouteNode(), Net()
    pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=500, max_expiry_blocks=8_640, close_margin=36)
    hd = os.path.join(d, "hub")
    os.makedirs(hd, exist_ok=True)
    hub = RouteHub(node, 0x4B4B, NET, hd, node.fund_address, http=net.http, fee_base_msat=100, fee_ppm=2_000,
                   max_lock_sat=20_000, max_unguarded_lock_sat=500, delta=36, reveal_timeout=1.0,
                   ch2_capacity=1_000_000, ch2_expiry_blocks=1_000, close_margin=36, policy=pol)
    net.apps[HUB] = hub
    stages = [float(x) for x in a.stages.split(",")]
    provs, unpaid = [], []
    for i, ms in enumerate(stages):
        origin = f"http://p{i}.test"
        kw = {}
        if a.journal == "wal":
            kw["route_wal"] = os.path.join(d, f"p{i}.route-wal")
        p = XbtChannelProvider(node, 0x1000 + i, NET, os.path.join(d, f"p{i}.json"), lambda m, pth: 1000,
                               stage_handler(ms), close_margin=36, policy=pol, settle_multiple=20, height_ttl=0, **kw)
        p.offer_route("/forward", window=1.0, lock_wait=2.5, invoice_ttl=12.0, amsat_per_call=a.amsat_per_call,
                      **({"precharge": (lambda m, pth, b, _c=a.amsat_per_call: _c)} if a.journal == "wal" else {}))
        app = CmpJournal(p, os.path.join(d, f"p{i}.cmp-journal")) if a.journal == "cmp" else p
        net.apps[origin] = app
        net.apps[f"http://u{i}.test"] = Unpaid(stage_handler(ms))
        hub.connect(origin)
        provs.append((origin, p))
    node.confirm_all()
    hub.watch_tick()
    if a.b2:
        sys.path.insert(0, a.b2)
        os.environ["B1_ROOT"] = ROOT
        from pathlib import Path
        from agentwallet.channels import ChannelBook
        from agentwallet.routing import RoutePolicy, RouteSigner
        cd = Path(d) / "client"
        cd.mkdir(exist_ok=True)
        book = ChannelBook(cd / "channels.json", cd / "channel_keys.json")
        policy = RoutePolicy.from_dict({"hubs": {HUB: {"max_fee_ppm": 10_000, "max_fee_base_msat": 10_000}},
                                        "max_lock_sats": 30_000, "daily_budget_sats": 50_000_000})
        signer = RouteSigner(book, policy, fund=node.fund_address, state_path=str(cd / "routing.json"))
    else:
        from xbt402.signer import ChannelSigner
        signer = ChannelSigner(fund=node.fund_address)
    pay = RoutePayer(HUB, NET, node.getblockcount, fund=node.fund_address, signer=signer, http=net.http,
                     capacity=2_000_000, expiry_blocks=8_000)
    pay.open()
    node.confirm_all()
    shards = [pay.shard(o + "/forward") for o, _ in provs]
    return node, net, hub, provs, pay, shards, ecc


class CmpHold:
    """cmp's lock driver holds the shard's call lock from before b1's lock() until b1 is about to POST
    it (routing.py: the http hook releases it), so no unverified chunk slips into a lock. The data path
    of that shard waits for b1's pre-POST section: the hub fee quote, B2's adaptor signing (its book
    write-ahead) and the ch1 auth. `hold(sh)` / `release()` / `call_lock(sh)` model exactly that."""

    def __init__(self, pay):
        self.locks, self.tl = {}, threading.local()
        inner = pay.http

        def http(method, url, body=b"", headers=None):
            if url.endswith("/x402/route"):
                self.release()
            return inner(method, url, body, headers)
        pay.http = http
        self.waits = []

    def call_lock(self, sh):
        return self.locks.setdefault(sh.session, threading.Lock())

    def hold(self, sh):
        lk = self.call_lock(sh)
        lk.acquire()
        self.tl.held = lk

    def release(self):
        lk = getattr(self.tl, "held", None)
        if lk is not None:
            self.tl.held = None
            lk.release()


class LockDriver(threading.Thread):
    """cmp's LockDriver, reduced: every `interval` s, lock each shard with a sat due (serial on ch1)."""

    def __init__(self, pay, shards, interval, hold=None):
        super().__init__(daemon=True)
        self.pay, self.shards, self.interval, self.hold = pay, shards, interval, hold
        self.stop_ev = threading.Event()
        self.results = {}
        self.lock_ms = []

    def run(self):
        while not self.stop_ev.is_set():
            for sh in self.shards:
                t = time.perf_counter()
                if self.hold:
                    self.hold.hold(sh)
                try:
                    r = self.pay.lock(sh)
                except Exception as e:  # noqa: BLE001
                    r = {"status": "error", "error": getattr(e, "code", repr(e))}
                finally:
                    if self.hold:
                        self.hold.release()
                if r:
                    k = r.get("status") + ("/" + r["error"] if r.get("error") else "")
                    self.results[k] = self.results.get(k, 0) + 1
                    if r.get("status") == "paid":
                        self.lock_ms.append((time.perf_counter() - t) * 1000)
            self.stop_ev.wait(self.interval)


def decode(call, n):
    per_stage = [[] for _ in range(3)]
    t0 = time.perf_counter()
    for _ in range(n):
        for i in range(len(per_stage)):
            t = time.perf_counter()
            st = call(i)
            per_stage[i].append((time.perf_counter() - t) * 1000)
            assert st == 200, st
    return (time.perf_counter() - t0), per_stage


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--tokens", type=int, default=200)
    ap.add_argument("--stages", default="18.5,3.5,36", help="compute ms per stage (CMP-024 unpaid p50 less the hop)")
    ap.add_argument("--amsat-per-call", type=int, default=4 * 10 ** 20, help="0.4 sat: a lock every ~3 tokens")
    ap.add_argument("--journal", choices=("none", "cmp", "wal"), default="cmp")
    ap.add_argument("--b2", default="", help="B2 root: the payer signs with agentwallet RouteSigner")
    ap.add_argument("--lock-interval", type=float, default=0.02)
    ap.add_argument("--cmp-hold", action="store_true", help="the data path waits for the lock driver's pre-POST section")
    ap.add_argument("--label", default="")
    ap.add_argument("--b1", default="", help="B1 root to measure (default: this tree)")
    ap.add_argument("--out", default="")
    a = ap.parse_args(argv)
    d = os.path.abspath(os.path.expanduser(a.dir))
    os.makedirs(d, exist_ok=True)
    node, net, hub, provs, pay, shards, ecc = build(a, d)
    body = b"\0" * 6144                     # one token of 1536 fp32

    def unpaid(i):
        return net.http("POST", f"http://u{i}.test/forward", body)[0]

    hold = CmpHold(pay) if a.cmp_hold else None

    def paid(i):
        if hold is None:
            return pay.call(shards[i], "POST", body)[0]
        t = time.perf_counter()
        with hold.call_lock(shards[i]):
            hold.waits.append((time.perf_counter() - t) * 1000)
            return pay.call(shards[i], "POST", body)[0]

    decode(unpaid, 10)
    u_s, u_stage = decode(unpaid, a.tokens)
    drv = LockDriver(pay, shards, a.lock_interval, hold)
    drv.start()
    decode(paid, 10)
    p_s, p_stage = decode(paid, a.tokens)
    drv.stop_ev.set()
    drv.join(5)
    # everything verified was paid for: flush the tail and check the money
    for _ in range(200):
        for sh in shards:
            pay.lock(sh)
        if all(sh.due_sat() < 1 for sh in shards) and not pay.pending:
            break
        time.sleep(0.02)
    out = {
        "label": a.label, "b1": ROOT, "journal": a.journal, "signer": "b2" if a.b2 else "b1", "tokens": a.tokens,
        "stages_ms": a.stages, "dir": d,
        "unpaid": {"ms_per_token": round(u_s * 1000 / a.tokens, 3), "tok_s": round(a.tokens / u_s, 3),
                   "stage_p50": [pct(x, .5) for x in u_stage]},
        "paid": {"ms_per_token": round(p_s * 1000 / a.tokens, 3), "tok_s": round(a.tokens / p_s, 3),
                 "stage_p50": [pct(x, .5) for x in p_stage], "stage_p95": [pct(x, .95) for x in p_stage],
                 "stage_mean": [round(statistics.mean(x), 3) for x in p_stage]},
        "ratio": round(u_s / p_s, 4),
        "cmp_hold": bool(hold), "hold_wait_ms": ({"mean": round(statistics.mean(hold.waits), 3), "p95": pct(hold.waits, .95),
                                                   "max": pct(hold.waits, 1.0)} if hold else None),
        "locks": drv.results, "lock_ms_p50": pct(drv.lock_ms, .5),
        "money": {"accrued_sat": [round(sh.accrued_amsat / 10 ** 21, 3) for sh in shards],
                  "locked_sat": [sh.locked_sat for sh in shards],
                  "provider_paid_sat": [p.routes.sessions[sh.session].paid_sat for (_, p), sh in zip(provs, shards)],
                  "due_left": [sh.due_sat() for sh in shards]},
    }
    print(json.dumps(out, indent=1))
    if a.out:
        with open(a.out, "a") as f:
            f.write(json.dumps(out) + "\n")


if __name__ == "__main__":
    main()
