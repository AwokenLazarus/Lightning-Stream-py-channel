"""AGP-054: where a routed call's time goes in cmp's operator app (cmp.billing_routed), per span.

    ~/xbt-rnd/cmp/.venv/bin/python scripts/cmp_route_spans.py --cmp ~/xbt-rnd/cmp \
        --dir ~/xbt-rnd/cmp/run --n 400 --mode journal|wal [--compute-ms 0]

Drives cmp's real operator app (its test fixtures: one routed mount, a recording shard, a route
client without a hub) in process, with b1 from THIS tree, and times each call's spans: b1's serve,
begin_call, end_call (ROUTE-STATE), cmp's journal commit, its ChargeV2 signing, the worker-thread
total and the ASGI round trip.

--mode journal  cmp as it is: RouteJournal fdatasyncs each call's meter after b1's serve
--mode wal      b1's RouteWal instead (route_wal= on the provider, a precharge from cmp's own
                per-call context: tokens in the frame x the quote), cmp's journal off
--compute-ms    the shard's compute per call (sleep), so the overlap shows

It uses cmp's rails override (CMP_B1_ROOT, CMP_RAILS_ALLOW_MISMATCH=1: dev only): a measurement,
never a deployment. Prints one JSON document.
"""
import argparse
import collections
import functools
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

B1 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmp", default=os.path.expanduser("~/xbt-rnd/cmp"))
    ap.add_argument("--dir", required=True, help="where the ledgers and journals go (the disk you measure)")
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--mode", choices=("journal", "wal"), default="journal")
    ap.add_argument("--compute-ms", type=float, default=0.0)
    a = ap.parse_args()
    os.environ["CMP_B1_ROOT"] = B1
    os.environ["CMP_RAILS_ALLOW_MISMATCH"] = "1"
    sys.path.insert(0, a.cmp)
    os.chdir(a.cmp)
    tmp = Path(tempfile.mkdtemp(dir=os.path.expanduser(a.dir), prefix="agp054-spans-"))
    from cmp import billing, billing_routed as br, pricing
    billing.ensure_b1()
    import xbt402.x402_channel as xc
    if a.mode == "wal":
        init = xc.XbtChannelProvider.__init__

        def with_wal(self, *args, **kw):
            kw.setdefault("route_wal", str(tmp / "prov.route-wal"))
            init(self, *args, **kw)
        xc.XbtChannelProvider.__init__ = with_wal
    from tests import test_billing_routed as T

    app, provider, key, shards = T._operator(tmp, route_opts=br.RouteOpts(credit_policy=br.CreditPolicy(tokens=10 ** 9)))
    prefix = "/d/a"
    if a.mode == "wal":
        app.route_journal = None                         # cmp's journal off: b1's RouteWal holds the meter

        def precharge(method, path, body):
            c = br._CALL.get()
            if not c or c.get("mode") != "routed" or not c.get("tokens_frame") or c.get("quote") is None:
                return None
            q = c["quote"]
            return pricing.charge_amsat(int(c["tokens_frame"]), q.params, q.price_nmsat_per_gpt)
        for o in provider.routes.offers.values():
            o.precharge = precharge
    rc, q = T.RouteClient(app, provider, prefix), T._quote(app, prefix)
    provider.routes.sessions[rc.session].paid_sat = 10 ** 6      # a paying session (not the free-call limiter)
    spans = collections.defaultdict(list)

    def wrap(obj, name, label):
        f = getattr(obj, name)

        @functools.wraps(f)
        def g(*args, **kw):
            t = time.perf_counter()
            try:
                return f(*args, **kw)
            finally:
                spans[label].append((time.perf_counter() - t) * 1e3)
        setattr(obj, name, g)
    shard = shards[prefix]
    if a.compute_ms:
        h = shard.handle

        def slow(*args, **kw):
            time.sleep(a.compute_ms / 1000)
            return h(*args, **kw)
        shard.handle = slow
    wrap(provider, "serve", "b1.serve (incl. the shard)")
    wrap(provider.routes, "begin_call", "b1.begin_call")
    wrap(provider.routes, "end_call", "b1.end_call (ROUTE-STATE, RouteWal wait)")
    wrap(app, "_journal_route", "cmp._journal_route")
    wrap(app, "_charge_record", "cmp._charge_record (ChargeV2 sign)")
    wrap(app, "_paid_call", "cmp._paid_call (worker thread)")
    wrap(shard, "handle", "shard.handle")
    wrap(billing, "_run_asgi", "ASGI round trip (client view)")
    pos = 0
    for _ in range(a.n):
        st, hdrs, out, body = rc.forward(1, q, pos=pos)
        assert st == 200, out
        pos += 1
    s = provider.routes.sessions[rc.session]
    assert s.accrued_amsat == rc.meter.amsat, (s.accrued_amsat, rc.meter.amsat)
    res = {"mode": a.mode, "n": a.n, "compute_ms": a.compute_ms, "dir": str(tmp), "b1": B1,
           "meter_exact": s.accrued_amsat == rc.meter.amsat, "spans_ms": {}}
    if a.mode == "wal":
        res["wal_fsyncs"] = provider.routes.wal.fsyncs
    for k, v in spans.items():
        v = sorted(v[a.n // 10:])
        res["spans_ms"][k] = {"p50": round(v[len(v) // 2], 3), "p95": round(v[int(len(v) * .95)], 3),
                              "mean": round(statistics.mean(v), 3)}
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
