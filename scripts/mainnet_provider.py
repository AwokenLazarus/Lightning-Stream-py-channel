#!/usr/bin/env python3
"""The xbt402 provider for the one approved mainnet test channel (AGP-015 runbook §1.4, G1.6, G6).

One route (`GET /agp015/echo` at 500 sat in the runbook), loopback only, a payTo secret sealed on
disk and created once (scripts/sealed_key.py), the network id checked against the node at start,
a ledger that survives restarts, a watcher, and a loopback admin API behind a token file.

    mainnet_provider.py --config FILE                     serve (refused on mainnet until approved)
    mainnet_provider.py --config FILE --check             check config, keys and node; print the offer
    mainnet_provider.py --config FILE --sweep-payee CHAN --to ADDR --fee 300
    mainnet_provider.py --config FILE --close CHAN        admin close with the best state held

`--sweep-payee` and `--close` go through the running provider's admin API; with the provider
stopped they act on the ledger directly. The config (JSON, `~` expanded) is documented in
scripts/mainnet_provider.example.json. The same script runs the regtest rehearsal: only `chain`,
the RPC port, the paths and the port change.

Safety rails:
  * `host` must be a loopback address; anything else is refused.
  * the node's `getblockchaininfo.chain` must equal the config's `chain`.
  * on mainnet the network id is `network_id(getblockhash(961640))` and must equal XBT_MAINNET; the
    node must be out of initial block download.
  * on mainnet the server does not start unless the config says `"mainnet_start_approved": true`
    (Mike, 2026-09-28: the launcher stays a config file until the hold on the runbook is lifted).
"""
import argparse
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from xbt402 import ecc  # noqa: E402
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.tx import HRP, address_to_spk  # noqa: E402
from xbt402.x402_channel import XBT_MAINNET, XbtChannelProvider, network_id  # noqa: E402

from sealed_key import Wrap, load_or_create_payto  # noqa: E402

MAINNET_ANCHOR = 961640          # the first BLAKE2b block: the spec's network id
REGTEST_ANCHOR = 101             # where the regtest rigs switch to BLAKE2b (spec §4)
LOOPBACK = {"127.0.0.1", "::1", "localhost"}

DEFAULTS = {
    "chain": "main", "rpc_port": 39332, "cookie": "~/xbt-mainnet/knots/.cookie",
    "payto_key": "~/.config/xbt-mainnet-test/payto.key", "payto_wrap": "~/.config/xbt-mainnet-test/payto.wrap",
    "admin_token": "~/.config/xbt-mainnet-test/provider-admin.token",
    "ledger": "~/xbt-mainnet/provider/ledger.sqlite", "host": "127.0.0.1", "port": 39480,
    "route": {"method": "GET", "path": "/agp015/echo", "price": 500},
    "policy": {"min_capacity": 10_000, "max_capacity": 10_000, "min_expiry_blocks": 1_008,
               "max_expiry_blocks": 8_640, "min_conf": 1, "zero_conf_max": 0},
    "close_fee": 600, "close_margin": 144, "claim_fee": 300, "billing": "postpay",
    "watcher_interval": 30, "cpfp_fee": 0, "mainnet_start_approved": False,
}


class LaunchError(RuntimeError):
    pass


def load_config(path: str) -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    with open(os.path.expanduser(path)) as f:
        user = json.load(f)
    for k, v in user.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    for k in ("cookie", "payto_key", "payto_wrap", "admin_token", "ledger"):
        if cfg.get(k):
            cfg[k] = os.path.expanduser(cfg[k])
    if cfg["chain"] not in HRP:
        raise LaunchError(f"unknown chain {cfg['chain']!r}")
    if str(cfg["host"]) not in LOOPBACK:
        raise LaunchError(f"host {cfg['host']!r} is not loopback: this provider never listens off 127.0.0.1")
    return cfg


def expected_network(rpc, cfg: dict) -> str:
    """The network id from the node, checked against the spec (P4) and the config's chain."""
    info = rpc.getblockchaininfo()
    if info.get("chain") != cfg["chain"]:
        raise LaunchError(f"the node is on {info.get('chain')!r}, the config says {cfg['chain']!r}")
    if cfg["chain"] == "main":
        if info.get("initialblockdownload"):
            raise LaunchError("the node is still in initial block download")
        if int(info.get("blocks", 0)) < MAINNET_ANCHOR:
            raise LaunchError(f"the node has no block {MAINNET_ANCHOR} yet")
        net = network_id(rpc.getblockhash(MAINNET_ANCHOR))
        if net != XBT_MAINNET:
            raise LaunchError(f"block {MAINNET_ANCHOR} gives {net}, not {XBT_MAINNET}: wrong chain")
        return net
    anchor = int(cfg.get("anchor_height") or REGTEST_ANCHOR)
    if int(info.get("blocks", 0)) < anchor:
        raise LaunchError(f"the node has no block {anchor} yet")
    net = network_id(rpc.getblockhash(anchor))
    if cfg.get("network") and cfg["network"] != net:
        raise LaunchError(f"the config pins {cfg['network']}, the node gives {net}")
    return net


def build(cfg: dict, rpc=None):
    """(provider, created): the provider with its sealed payTo secret, checked against the node."""
    rpc = rpc or RPC(int(cfg["rpc_port"]), cfg["cookie"])
    net = expected_network(rpc, cfg)
    secret, created = load_or_create_payto(cfg["payto_key"], Wrap.from_config(cfg.get("payto_wrap", "")), ecc.pubkey)
    pol = cfg["policy"]
    policy = FundingPolicy(min_capacity=int(pol["min_capacity"]), max_capacity=int(pol["max_capacity"]),
                           min_expiry_blocks=int(pol["min_expiry_blocks"]),
                           max_expiry_blocks=int(pol["max_expiry_blocks"]),
                           close_margin=int(cfg["close_margin"]), min_conf=int(pol["min_conf"]),
                           zero_conf_max=int(pol.get("zero_conf_max", 0)))
    route = cfg["route"]
    os.makedirs(os.path.dirname(cfg["ledger"]), mode=0o700, exist_ok=True)

    def price(method, path):
        return int(route["price"])

    def handler(method, path, body):
        if method == route["method"] and path.split("?", 1)[0] == route["path"]:
            return 200, {"Content-Type": "application/json"}, json.dumps({"ok": True, "echo": path}).encode()
        return 404, {}, b"not found"

    prov = XbtChannelProvider(rpc, secret, net, cfg["ledger"], price, handler, billing=cfg["billing"],
                              close_fee=int(cfg["close_fee"]), close_margin=int(cfg["close_margin"]),
                              policy=policy, hrp=HRP[cfg["chain"]], claim_fee=int(cfg["claim_fee"]))
    return prov, created


def status(prov) -> dict:
    with prov.ledger.lock:
        chans = [{"chan": c, "capacity": st.params.capacity, "expiry": st.params.expiry, "best_cum": st.best_cum,
                  "spent_msat": st.spent_msat, "closed_txid": st.closed_txid or None,
                  "payee_sweep": (st.extra or {}).get("payee_sweep"), "close_error": st.close_error or None}
                 for c, st in prov.ledger.channels.items()]
    return {"payTo": prov.pay_to, "network": prov.network, "channels": chans}


def admin_close(prov, chan: str) -> dict:
    from xbt402.channel import canonical_chan
    with prov.ledger.lock:
        st = prov.ledger.channels.get(canonical_chan(chan))
        if not st:
            raise LaunchError("unknown channel")
        txid = prov._close_locked(st)
        report = prov._close_report(st)
        report.pop("unpaidMsat")
        return {"chan": st.params.channel_id, "txid": txid, **report}


def admin_sweep(prov, cfg, chan: str, to: str, fee: int) -> dict:
    return prov.sweep_payee(chan, address_to_spk(to, HRP[cfg["chain"]]), int(fee))


def asgi(prov, cfg, token: str):
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from xbt402.asgi import Xbt402Middleware
    from xbt402.channel import ChannelError

    def allowed(request) -> bool:
        return (request.client is not None and request.client.host in LOOPBACK
                and hmac.compare_digest(request.headers.get("x-admin-token", ""), token))

    def guarded(fn):
        async def ep(request: Request):
            if not allowed(request):
                return JSONResponse({"error": "forbidden"}, 403)
            try:
                body = await request.json() if request.method == "POST" else {}
                return JSONResponse(fn(body))
            except (ChannelError, LaunchError, ValueError, KeyError, TypeError) as e:
                return JSONResponse({"error": getattr(e, "code", "bad_request"), "detail": str(e)}, 400)
        return ep

    admin = Starlette(routes=[
        Route("/admin/status", guarded(lambda b: status(prov)), methods=["GET"]),
        Route("/admin/close", guarded(lambda b: admin_close(prov, b["chan"])), methods=["POST"]),
        Route("/admin/sweep-payee", guarded(lambda b: admin_sweep(prov, cfg, b["chan"], b["to"], b.get("fee", 300))),
              methods=["POST"]),
    ])
    paid = Xbt402Middleware(None, prov)
    route = cfg["route"]["path"]

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        path = scope["path"]
        if path.startswith("/admin/"):
            await admin(scope, receive, send)
        elif path == route or path.startswith("/x402/"):
            await paid(scope, receive, send)
        else:
            await JSONResponse({"error": "not found"}, 404)(scope, receive, send)
    return app


def _token(cfg, create: bool) -> str:
    path = cfg["admin_token"]
    if create:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        tok = secrets.token_hex(16)
        with os.fdopen(fd, "w") as f:
            f.write(tok)
        return tok
    with open(path) as f:
        return f.read().strip()


def _admin_call(cfg, method: str, path: str, body=None):
    """The running provider's admin API, or None when nothing listens on its port."""
    try:
        tok = _token(cfg, create=False)
    except OSError:
        return None
    req = urllib.request.Request(f"http://127.0.0.1:{int(cfg['port'])}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"x-admin-token": tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)
    except (urllib.error.URLError, ConnectionError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=os.environ.get("XBT402_PROVIDER_CONFIG", ""), required=False)
    ap.add_argument("--port", type=int, help="override the config's port")
    ap.add_argument("--check", action="store_true", help="check config, keys and node; print the offer; exit")
    ap.add_argument("--sweep-payee", metavar="CHAN")
    ap.add_argument("--to", metavar="ADDR", help="sweep destination (bech32 witness v0 of this chain)")
    ap.add_argument("--fee", type=int, default=300)
    ap.add_argument("--close", metavar="CHAN")
    a = ap.parse_args(argv)
    if not a.config:
        ap.error("--config (or XBT402_PROVIDER_CONFIG) is required")
    cfg = load_config(a.config)
    if a.port:
        cfg["port"] = a.port

    if a.sweep_payee or a.close:
        if a.sweep_payee and not a.to:
            ap.error("--sweep-payee needs --to")
        if a.sweep_payee:
            address_to_spk(a.to, HRP[cfg["chain"]])          # refuse a wrong-network address up front
            res = _admin_call(cfg, "POST", "/admin/sweep-payee", {"chan": a.sweep_payee, "to": a.to, "fee": a.fee})
        else:
            res = _admin_call(cfg, "POST", "/admin/close", {"chan": a.close})
        if res is None:                       # the provider is stopped: act on the ledger directly
            prov, _ = build(cfg)
            res = admin_sweep(prov, cfg, a.sweep_payee, a.to, a.fee) if a.sweep_payee else admin_close(prov, a.close)
            res["via"] = "ledger"
        print(json.dumps(res, indent=1))
        return 1 if "error" in res else 0

    prov, created = build(cfg)
    offer = prov.requirements(int(cfg["route"]["price"]))
    info = {"chain": cfg["chain"], "network": prov.network, "payTo": prov.pay_to, "payto_key_created": created,
            "listen": f"{cfg['host']}:{cfg['port']}", "route": cfg["route"], "offer": offer}
    if created:
        info["notice"] = "new payTo key: back up the payto key and wrap files now (a password manager), before any channel"
    if a.check:
        prov.ledger.close()
        print(json.dumps(info, indent=1))
        return 0
    if cfg["chain"] == "main" and cfg.get("mainnet_start_approved") is not True:
        raise LaunchError("mainnet serving is on hold (mainnet_start_approved is not true); --check works")
    token = _token(cfg, create=True)
    from xbt402.watcher import Watcher
    Watcher(prov, interval=float(cfg["watcher_interval"]), cpfp_fee=int(cfg["cpfp_fee"])).start()
    print(json.dumps(info), flush=True)
    import uvicorn
    uvicorn.run(asgi(prov, cfg, token), host=cfg["host"], port=int(cfg["port"]), log_level="warning")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LaunchError as e:
        sys.stderr.write(f"mainnet_provider: {e}\n")
        sys.exit(2)
