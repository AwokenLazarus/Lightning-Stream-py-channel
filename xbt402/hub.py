"""xbt402 routing hub (AGP-021): one client -> hub channel pays many providers through hub-funded
hub -> provider channels, with adaptor-locked states on both hops (design: AGP-019).

    client --ch1 (client pays, hub is payee)--> hub --ch2 (hub pays, provider is payee)--> provider

The hub is two things at once:
  * a payee on every ch1: an embedded XbtChannelProvider serves ch1's open/close/facilitator
    endpoints, keeps ch1's states in its SQLite ledger and closes ch1 at its margin;
  * a payer on every ch2: `OutBook` holds each ch2's key, its highest plain state, the routed total
    and the one pending lock. The hub funds ch2 from its own wallet (`fund`), so a small provider
    never opens a channel, and rolls ch2 over at the provider's settle threshold.

POST /x402/route (a PAYMENT-SIGNATURE on ch1; the JSON body carries the route) runs its checks in
this order, and pre-signs nothing on ch2 until all of them pass:
    1 auth       ch1's request HMAC and a fresh seq          -> bad_auth
    2 point      T1 = T + r*G                                  -> bad_point
    3 amount     cum = next_cum(routed1, d + f), d <= maxLockSat -> bad_amount
    4 pre-verify the ch1 pre-signature under T1 against the exact state tx -> bad_adaptor
    5 fee        a live fee quote this hub signed, f >= the carried fee    -> route_fee
    6 expiry     route_ok(tip, expiry1, expiry2) or d <= maxUnguardedLockSat -> route_expiry
    7 one lock   no pending lock on ch1 and none on ch2       -> lock_outstanding
Then it writes the ch1 lock to disk, pre-signs ch2 under T, writes that, sends it to the provider,
checks t*G = T, completes ch1 with t + r and answers the client with t + r.

The watcher (`watch_tick`): posts the opens of hub-funded ch2s once confirmed; retries a pending
ch2 lock until `revealTimeoutSec`, then writes it off and stops routing to that provider; reads t
off any ch2 close that spends a funding with a pending or written-off lock and completes the ch1
lock with t + r; rolls ch2 over (one tx pays the provider and funds the next ch2) once the provider's
balance reaches its settleMultiple x closeFee or ch2 nears expiry, never while a lock is pending;
and closes ch1s at their margin.
"""
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Optional

from . import adaptor, ecc
from .channel import (DUST, SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams, canonical_chan)
from .funding import FundingPolicy
from .route import (HUB_ROUTE_PATH, ROLLOVER_PATH, ROUTE_LOCK_PATH, TERMS_PATH, FeeQuote, Invoice, fee_due,
                    find_spend, hub_channel_message, next_cum, route_ok)
from .tx import segwit_address
from .x402_channel import (XbtChannelClient, XbtChannelProvider, b64json, request_auth, request_digest,
                           unb64json)
from .channel import channel_auth_key


@dataclass
class OutChannel:
    """One hub -> provider channel (ch2); the hub is the payer."""
    origin: str
    pay_to: str                  # the provider operator's payTo (one key may serve many devices)
    params: dict
    secret: str                  # payer key (regtest: stored here; production: the B2 signer)
    state: str = "funded"        # funded -> open -> closed | rolled
    signed: int = 0              # highest cumulative state the provider can close with
    routed: int = 0              # sum of completed routed amounts (the provider keeps the same total)
    seq: int = 0
    pending: dict = field(default_factory=dict)     # the one lock: {lockId, cum, pre, T, d, ch1, at}
    stale: list = field(default_factory=list)       # written-off locks, kept for on-chain recovery
    settle_multiple: int = 20
    terms: dict = field(default_factory=dict)
    refund_hex: str = ""
    blocked: str = ""            # why the hub stopped routing to this provider
    close_txid: str = ""
    rolled_to: str = ""
    opened_at: int = 0
    scanned_to: int = 0

    def p(self) -> ChannelParams:
        return ChannelParams(**self.params)


class OutBook:
    """The hub's ch2s, fsynced JSON (keys included: regtest only; the production hub signs with B2)."""

    def __init__(self, path: str):
        self.path, self.lock = path, threading.RLock()
        self.chans: Dict[str, OutChannel] = {}
        self.archived: list = []
        if os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            self.chans = {k: OutChannel(**v) for k, v in raw.get("chans", {}).items()}
            self.archived = raw.get("archived", [])
        self.mutex: Dict[str, threading.Lock] = {}

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"chans": {k: asdict(v) for k, v in self.chans.items()}, "archived": self.archived}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)

    def mutex_for(self, origin: str) -> threading.Lock:
        with self.lock:
            return self.mutex.setdefault(origin, threading.Lock())


@dataclass
class HubConfig:
    """Everything a hub operator decides (JSON/dict: `HubConfig.from_dict`); nothing here is protocol.

    fee_strategy: {"kind": "flat"} charges fee_base_msat + fee_ppm; {"kind": "utilization",
    "ppm_min", "ppm_max"} scales feePpm with the share of liquidity_cap_sat already committed to ch2s
    (a library user may pass any callable(hub) -> (base_msat, ppm) instead). liquidity_cap_sat bounds
    the hub's own coins in hub-funded ch2s (0: no cap); rollovers reuse a channel's coins and add none.
    Who pays a ch2 settlement's close fee is the channel's closeFeeSat terms, taken from the provider's
    /terms; nothing here assumes the hub pays it (AGP-023 moves it to the payee on routed channels)."""
    fee_base_msat: int = 1_000
    fee_ppm: int = 2_000
    fee_strategy: dict = field(default_factory=lambda: {"kind": "flat"})
    quote_ttl: int = 600
    max_lock_sat: int = 50_000
    max_unguarded_lock_sat: int = 500
    delta: int = 144
    reveal_timeout: float = 10.0
    ch2_capacity: int = 100_000
    ch2_expiry_blocks: int = 1_100
    liquidity_cap_sat: int = 0
    close_fee: int = 600                 # ch1 terms (the hub is ch1's payee)
    close_margin: int = 144
    rollover_margin: int = 36
    hrp: str = "bcrt"
    policy: dict = field(default_factory=lambda: {"min_expiry_blocks": 1_008, "max_expiry_blocks": 8_640})

    @classmethod
    def from_dict(cls, d: dict) -> "HubConfig":
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown hub config keys: {sorted(unknown)}")
        return cls(**d)

    def funding_policy(self) -> FundingPolicy:
        return FundingPolicy(**{"close_margin": self.close_margin, **self.policy})


class RouteHub:
    def __init__(self, rpc, pay_to_secret: int, network: str, datadir: str, fund: Callable[[str, int], tuple],
                 config: HubConfig = None, *, http: Callable = None, policy: FundingPolicy = None,
                 fee_strategy: Callable = None, **overrides):
        """`config` (a HubConfig) holds the operator's choices; keyword `overrides` set single fields
        (fee_ppm=..., liquidity_cap_sat=...). `fee_strategy`, if given, is a callable(hub) ->
        (fee_base_msat, fee_ppm) that replaces the configured one."""
        cfg = config or HubConfig()
        if isinstance(fee_strategy, dict):              # a configured strategy, not a callable
            overrides["fee_strategy"], fee_strategy = fee_strategy, None
        if overrides:
            cfg = HubConfig(**{**asdict(cfg), **overrides})
        self.config = cfg
        os.makedirs(datadir, exist_ok=True)
        self.rpc, self.secret, self.network, self.fund, self.hrp = rpc, pay_to_secret, network, fund, cfg.hrp
        self.pay_to = ecc.pubkey(pay_to_secret).hex()
        self.inbound = XbtChannelProvider(
            rpc, pay_to_secret, network, os.path.join(datadir, "ch1.sqlite"), price=lambda m, p: 0,
            handler=lambda m, p, b: (404, {}, b"not found"), close_fee=cfg.close_fee, close_margin=cfg.close_margin,
            policy=policy or cfg.funding_policy())
        self.out = OutBook(os.path.join(datadir, "ch2.json"))
        self.fee_base_msat, self.fee_ppm, self.quote_ttl = cfg.fee_base_msat, cfg.fee_ppm, cfg.quote_ttl
        self.max_lock_sat, self.max_unguarded_lock_sat, self.delta = cfg.max_lock_sat, cfg.max_unguarded_lock_sat, cfg.delta
        self.reveal_timeout, self.close_margin, self.close_fee = cfg.reveal_timeout, cfg.close_margin, cfg.close_fee
        self.ch2_capacity, self.ch2_expiry_blocks = cfg.ch2_capacity, cfg.ch2_expiry_blocks
        self.rollover_margin, self.liquidity_cap_sat = cfg.rollover_margin, cfg.liquidity_cap_sat
        self.fee_strategy = fee_strategy or self._configured_fees
        self.http = http or XbtChannelClient.http
        self._quote: Optional[FeeQuote] = None
        self._quote_seq = int(time.time())
        self.withhold = ""           # tests/demo: "" | "receipt" (keep t + r from the client) | "all"
        self.events: list = []
        self.stats = {"routed": 0, "floor": 0, "refused": {}, "lock_ms": []}

    # ---------------------------------------------------------------------------------------------
    def committed_sat(self) -> int:
        """The hub's own coins in live ch2s (funded or open)."""
        with self.out.lock:
            return sum(c.p().capacity for c in self.out.chans.values() if c.state in ("funded", "open"))

    def _configured_fees(self, hub) -> tuple:
        st = self.config.fee_strategy or {"kind": "flat"}
        if st.get("kind", "flat") == "flat":
            return self.fee_base_msat, self.fee_ppm
        if st["kind"] == "utilization":
            cap = self.liquidity_cap_sat
            u = min(1.0, self.committed_sat() / cap) if cap else 0.0
            lo, hi = int(st.get("ppm_min", self.fee_ppm)), int(st.get("ppm_max", self.fee_ppm))
            return int(st.get("base_msat", self.fee_base_msat)), int(lo + (hi - lo) * u)
        raise ValueError(f"unknown fee strategy {st.get('kind')!r}")

    def fee_quote(self) -> FeeQuote:
        now = int(time.time())
        q = self._quote
        base, ppm = self.fee_strategy(self)
        if q is None or q.validUntil - now < self.quote_ttl // 4 or (q.feeBaseMsat, q.feePpm) != (base, ppm):
            self._quote_seq += 1
            q = FeeQuote(self.pay_to, self.network, int(base), int(ppm), self.max_lock_sat,
                         self.max_unguarded_lock_sat, self.delta, int(self.reveal_timeout), self._quote_seq, now,
                         now + self.quote_ttl).sign(self.secret)
            self._quote = q
        return q

    def routing_extra(self) -> dict:
        q = self.fee_quote()
        return {"feeBaseMsat": q.feeBaseMsat, "feePpm": q.feePpm, "maxLockSat": q.maxLockSat,
                "maxUnguardedLockSat": q.maxUnguardedLockSat, "minInExpiryDelta": q.minInExpiryDelta,
                "revealTimeoutSec": q.revealTimeoutSec, "routeUrl": HUB_ROUTE_PATH, "quote": asdict(q),
                "providers": sorted(o for o, c in self.out.chans.items() if c.state == "open" and not c.blocked)}

    def body_limit(self, path: str, max_body: int = None) -> int:
        return self.inbound.body_limit(path, max_body)

    def serve(self, method: str, path: str, headers: dict, body: bytes, url: str = "", max_body: int = None):
        if len(body or b"") > self.body_limit(path, max_body):
            return 400, {}, b"bad request framing or body over MAX_BODY"
        if path.split("?", 1)[0] == HUB_ROUTE_PATH:
            hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
            if method == "POST" and hdr:
                return self.route(method, HUB_ROUTE_PATH, hdr, body)
            st, h, b = self.inbound._payment_required(url or path, 0, "payment_required")
            doc = json.loads(b)
            doc["accepts"][0]["extra"]["routing"] = self.routing_extra()
            h["PAYMENT-REQUIRED"] = b64json(doc)
            return 402, h, json.dumps(doc).encode()
        return self.inbound.serve(method, path, headers, body, url, max_body)

    def http_server(self, port: int):
        return XbtChannelProvider.http_server(self, port)

    # --- POST /x402/route --------------------------------------------------------------------------
    @staticmethod
    def _err(code: str, detail: str = "", status: int = 400, **extra):
        return status, {"Content-Type": "application/json"}, json.dumps(
            {"error": code, "detail": detail, **extra}).encode()

    def route(self, method: str, path: str, hdr: str, body: bytes):
        t0 = time.perf_counter()
        try:
            pl = unb64json(hdr)["payload"]
            rt = json.loads(body)["route"]
            if not isinstance(pl, dict) or not isinstance(rt, dict):
                raise TypeError
            d, f, lock_id = int(rt["amount"]), int(rt["fee"]), str(rt["lockId"])
            provider = str(rt["provider"]).rstrip("/")
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._err("bad_payload")
        ib = self.inbound
        with ib.ledger.lock:
            # 1 auth ---------------------------------------------------------------------------
            try:
                st1 = ib.ledger.channels.get(canonical_chan(pl.get("chan")))
            except ChannelError:
                st1 = None
            if st1 is None:
                return self._err("unknown_channel")
            if not ib._authentic(st1, pl, method, path, body):
                return self._err("bad_auth", status=401)
            st1.seq = int(pl["seq"])
            done = ((st1.extra or {}).get("route_done") or {}).get(lock_id)
            if done:                                   # the client lost our answer: the same one again
                return 200, {"Content-Type": "application/json"}, json.dumps(done).encode()
            if st1.closed_txid or ib.height() >= st1.params.expiry - ib.close_margin:
                return self._err("channel_closing")
            if st1.suspended:
                return self._err("unconfirmed")
            # 2 point --------------------------------------------------------------------------
            try:
                T = adaptor.dec(rt["point"])
                r = int(rt["tweak"], 16) % adaptor.N
                T1 = adaptor.dec(pl["point"]) if pl.get("point") else None
            except (KeyError, TypeError, ValueError):
                return self._err("bad_point", "points must be compressed secp256k1 points")
            if T1 is not None and (not r or adaptor.add(T, adaptor._mul_pub(r)) != T1):
                return self._err("bad_point", "T1 != T + r*G")
            # 3 amount -------------------------------------------------------------------------
            ex1 = st1.extra or {}
            routed1 = int(ex1.get("routed_sat", 0))
            cum = int(pl.get("cum", -1))
            need1 = next_cum(routed1, d + f)
            if d < 1 or f < 0 or d > self.max_lock_sat:
                return self._err("bad_amount", f"lock amount must be in [1, {self.max_lock_sat}]")
            floor1 = need1 <= st1.best_cum
            # our view of ch1, so a client that gave up a lock we later completed (t read off a ch2
            # close) can resync: it adopts it only if bestCum is a state it pre-signed itself
            view = {"bestCum": st1.best_cum, "routedSat": routed1, "feeUnits": int(ex1.get("fee_units", 0)),
                    "feePaid": int(ex1.get("fee_paid", 0))}
            if floor1:
                if cum != st1.best_cum or pl.get("adaptor"):
                    return self._err("bad_amount", f"the dust floor covers this lock: cum {st1.best_cum}, no adaptor",
                                     expectCum=st1.best_cum, **view)
            elif cum != need1 or cum > st1.params.max_amount or T1 is None:
                return self._err("bad_amount", f"lock pays {cum}, expected {need1}", expectCum=need1, **view)
            # 4 pre-verify ---------------------------------------------------------------------
            pre1 = None
            if not floor1:
                try:
                    pre1 = adaptor.PreSig.from_json(pl["adaptor"])
                except (KeyError, TypeError, ValueError):
                    return self._err("bad_adaptor", "malformed adaptor")
                z1 = st1.params.sighash(st1.params.state_tx(cum))
                if not adaptor.preverify(bytes.fromhex(st1.params.payer_pub), z1, T1, pre1):
                    return self._err("bad_adaptor", "pre-signature does not verify under T1")
            # 5 fee quote ----------------------------------------------------------------------
            try:
                q = FeeQuote.from_dict(rt["feeQuote"])
            except (ChannelError, KeyError):
                return self._err("route_fee", "no fee quote")
            # any live quote this hub signed is honoured, including one the fee strategy has since moved
            if q.hub != self.pay_to or q.network != self.network or not q.verify() or not q.live(time.time()):
                return self._err("route_fee", "not a live fee quote of this hub")
            f_due, units = fee_due(q, d, int(ex1.get("fee_units", 0)), int(ex1.get("fee_paid", 0)))
            if f < f_due:
                return self._err("route_fee", f"fee {f} < {f_due} due under quote {q.seq}", feeDue=f_due)
            # 6 expiry rule --------------------------------------------------------------------
            oc = self.out.chans.get(provider)
            if oc is None or oc.state != "open":
                return self._err("route_blocked", "no open channel to that provider")
            if oc.blocked:
                return self._err("route_blocked", oc.blocked)
            try:
                inv = Invoice.from_dict(rt["invoice"])
            except (ChannelError, KeyError):
                return self._err("bad_invoice")
            if (inv.payTo != oc.pay_to or not inv.verify() or inv.point.lower() != str(rt["point"]).lower()
                    or inv.lockId != lock_id or inv.validUntil < time.time() + 0.5
                    or (inv.hubs != "any" and self.pay_to not in inv.hubs)):
                return self._err("bad_invoice", "invoice not signed by the provider for this point, or expiring")
            p2 = oc.p()
            if not route_ok(ib.height(), st1.params.expiry, p2.expiry, self.close_margin, self.delta) \
                    and d > self.max_unguarded_lock_sat:
                return self._err("route_expiry", f"ch2 outlives ch1 and {d} > maxUnguardedLockSat")
            # 7 one lock per channel -----------------------------------------------------------
            if ex1.get("route_lock"):
                return self._err("lock_outstanding", "a lock on this ch1 is pending")
            mtx = self.out.mutex_for(provider)
            if not mtx.acquire(timeout=0.5):
                return self._err("lock_outstanding", "a lock on this provider's ch2 is pending")
            if oc.pending:
                mtx.release()
                return self._err("lock_outstanding", "a lock on this provider's ch2 is pending")
            # write-ahead: pre1 (enough to complete ch1 from t on-chain after a crash)
            lock1 = {"lockId": lock_id, "cum": cum, "floor": floor1, "pre": pre1.to_json() if pre1 else None,
                     "T": rt["point"], "T1": pl.get("point"), "r": f"{r:064x}", "d": d, "f": f, "units": units,
                     "provider": provider, "at": round(time.time(), 3), "session": rt.get("session"),
                     "after": {"routed": routed1 + d + f, "units": units, "paid": int(ex1.get("fee_paid", 0)) + f}}
            st1.extra = {**ex1, "route_lock": lock1}
            ib.ledger.save(st1)
        try:
            return self._forward(st1, oc, lock1, rt, pl, t0)
        finally:
            mtx.release()

    def _forward(self, st1, oc: OutChannel, lock1: dict, rt: dict, pl: dict, t0: float):
        """Pre-sign ch2 under T (only now), send it to the provider, settle ch1 with t + r."""
        d, provider = lock1["d"], lock1["provider"]
        if self.withhold == "all":                    # test hook: a hub that takes locks and forwards none
            return self._err("route_pending", "hub withholding (test)", status=504)
        p2 = oc.p()
        need2 = next_cum(oc.routed, d)
        T = adaptor.dec(lock1["T"])
        pre2 = None
        if need2 > oc.signed:
            if need2 > p2.max_amount:
                self._void(st1, oc, lock1, "ch2 exhausted", block="")
                return self._err("route_failed", "the hub's channel to that provider is exhausted")
            pre2 = adaptor.presign(int(oc.secret, 16), p2.sighash(p2.state_tx(need2)), T)
        with self.out.lock:
            oc.pending = {"lockId": lock1["lockId"], "cum": max(need2, oc.signed), "pre": pre2.to_json() if pre2 else None,
                          "T": lock1["T"], "d": d, "ch1": st1.params.channel_id, "at": round(time.time(), 3),
                          "route": {"session": rt.get("session"), "lockId": lock1["lockId"], "amount": d,
                                    "lockAuth": rt.get("lockAuth", ""), "hub": self.pay_to}}
            self.out.save()                                   # write-ahead: pre2 before it leaves
        # wait for t up to revealTimeoutSec (a provider may hold a lock without answering): then write
        # the lock off, stop routing to that provider, and tell the client, so its ch1 is free again
        while True:
            ans = self._send_lock(oc)
            if ans is not None or time.time() - oc.pending.get("at", 0) >= self.reveal_timeout:
                break
            time.sleep(0.1)
        if ans is None:
            self._void(st1, oc, lock1, "no reveal within revealTimeoutSec",
                       block="the provider did not reveal a lock in time")
            return self._err("route_failed", "provider did not reveal within revealTimeoutSec", status=502)
        if "error" in ans:
            self._void(st1, oc, lock1, f"provider refused: {ans['error']}", block="")
            self.stats["refused"][ans["error"]] = self.stats["refused"].get(ans["error"], 0) + 1
            return self._err("route_failed", "provider refused the lock", providerError=ans["error"], status=502)
        out = self._settled(st1.params.channel_id, oc, ans)
        self.stats["lock_ms"].append((time.perf_counter() - t0) * 1000)
        if out is None:
            return self._err("route_pending", "provider answer did not open the lock", status=504)
        if self.withhold == "receipt":
            return self._err("route_pending", "hub withholding the receipt (test)", status=504)
        return 200, {"Content-Type": "application/json"}, json.dumps(out).encode()

    def _send_lock(self, oc: OutChannel) -> Optional[dict]:
        """POST the pending ch2 lock (fresh seq and auth each time: idempotent at the provider)."""
        pend = oc.pending
        p2 = oc.p()
        if self.withhold == "all" or not pend:
            return None
        with self.out.lock:
            oc.seq += 1
            seq = oc.seq
            self.out.save()
        body = json.dumps({"route": pend["route"]}).encode()
        pl = {"chan": p2.channel_id, "seq": seq, "cum": str(pend["cum"]), "point": pend["T"]}
        if pend.get("pre"):
            pl["adaptor"] = pend["pre"]
        key = channel_auth_key(int(oc.secret, 16), bytes.fromhex(p2.payee_pub))
        pl["auth"] = request_auth(key, p2.channel_id, seq, pl["cum"], None, request_digest("POST", ROUTE_LOCK_PATH, body))
        hdrs = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": oc.terms, "payload": pl}),
                "Content-Type": "application/json"}
        try:
            st, _, raw = self.http("POST", oc.origin + ROUTE_LOCK_PATH, body, hdrs)
            doc = json.loads(raw)
        except (OSError, ValueError):
            return None
        if st == 200 and isinstance(doc, dict) and doc.get("secret"):
            return doc
        if st in (400, 401, 403) and isinstance(doc, dict) and isinstance(doc.get("error"), str):
            return {"error": doc["error"][:40]}
        return None

    def _settled(self, ch1: str, oc: OutChannel, ans: dict) -> Optional[dict]:
        """The provider revealed t: check it, fold ch2, complete ch1 with t + r."""
        pend = oc.pending
        if not pend or ans.get("lockId") != pend.get("lockId"):
            return None                                      # settled already (idempotent)
        try:
            t = int(ans["secret"], 16) % adaptor.N
        except (KeyError, TypeError, ValueError):
            return None
        if not t or adaptor.point_of(t) != adaptor.dec(pend["T"]):
            return None                                      # bad_secret: keep the lock pending
        with self.out.lock:
            oc.signed = max(oc.signed, pend["cum"])
            oc.routed += pend["d"]
            oc.pending = {}
            self.out.save()
        return self._complete_ch1(ch1, pend["lockId"], t, via="provider")

    def _complete_ch1(self, ch1: str, lock_id: str, t: int, via: str) -> Optional[dict]:
        ib = self.inbound
        with ib.ledger.lock:
            st1 = ib.ledger.channels.get(ch1)
            ex = st1.extra or {}
            lock1 = ex.get("route_lock") if (ex.get("route_lock") or {}).get("lockId") == lock_id else None
            stale = False
            if lock1 is None:
                lock1 = next((s for s in ex.get("stale_locks", []) if s["lockId"] == lock_id), None)
                stale = True
            if lock1 is None:
                return None
            s1 = (t + int(lock1["r"], 16)) % adaptor.N
            if not lock1["floor"]:
                pre1 = adaptor.PreSig.from_json(lock1["pre"])
                sig1 = adaptor.adapt(pre1, s1) + bytes([SIGHASH_ALL_UNIFIED])
                if lock1["cum"] > st1.best_cum and not st1.closed_txid:
                    ib._payee(st1).accept(lock1["cum"], sig1)
                    st1.best_cum, st1.best_sig = lock1["cum"], sig1.hex()
            ans = {"lockId": lock_id, "secret": f"{s1:064x}", "cum": str(max(lock1["cum"], st1.best_cum)),
                   "fee": lock1["f"], "amount": lock1["d"], "via": via}
            if stale:
                ex["stale_locks"] = [s for s in ex.get("stale_locks", []) if s["lockId"] != lock_id]
                ex.setdefault("recovered", []).append({**ans, "at": round(time.time(), 3)})
                aft = lock1.get("after")
                if aft and st1.best_cum == lock1["cum"]:        # it is our best state now: count it
                    ex["routed_sat"] = max(int(ex.get("routed_sat", 0)), aft["routed"])
                    ex["fee_units"] = max(int(ex.get("fee_units", 0)), aft["units"])
                    ex["fee_paid"] = max(int(ex.get("fee_paid", 0)), aft["paid"])
            else:
                ex["route_lock"] = None
                ex["routed_sat"] = int(ex.get("routed_sat", 0)) + lock1["d"] + lock1["f"]
                ex["fee_units"] = lock1["units"]
                ex["fee_paid"] = int(ex.get("fee_paid", 0)) + lock1["f"]
                done = dict(ex.get("route_done") or {})
                done[lock_id] = ans
                if len(done) > 64:                           # the recent answers, for client retries
                    done = dict(list(done.items())[-64:])
                ex["route_done"] = done
            st1.extra = ex
            ib.ledger.save(st1)
        self.stats["routed"] += 1
        if lock1["floor"]:
            self.stats["floor"] += 1
        return ans

    def _void(self, st1, oc: OutChannel, lock1: dict, why: str, block: str):
        """Write both locks off (kept for on-chain recovery). A later plain or locked state above them
        dominates them; until then a late completion costs the hub at most this one lock."""
        ib = self.inbound
        with self.out.lock:
            if oc.pending:
                oc.stale.append({**oc.pending, "voided": round(time.time(), 3), "why": why})
                oc.pending = {}
            if block:
                oc.blocked = block
            self.out.save()
        with ib.ledger.lock:
            st1 = ib.ledger.channels[st1.params.channel_id]
            ex = st1.extra or {}
            if ex.get("route_lock"):
                ex.setdefault("stale_locks", []).append({**ex["route_lock"], "voided": round(time.time(), 3)})
                ex["route_lock"] = None
            st1.extra = ex
            ib.ledger.save(st1)
        self.events.append({"event": "void", "provider": oc.origin, "lockId": lock1.get("lockId"), "why": why,
                            "blocked": bool(block)})

    # --- hub-funded ch2 -----------------------------------------------------------------------------
    def connect(self, origin: str, capacity: int = None, expiry_blocks: int = None) -> OutChannel:
        """Fund a ch2 to `origin` from the hub's own wallet. It opens (watch_tick / open_pending) once
        the funding has the provider's minConf."""
        origin = origin.rstrip("/")
        st, _, raw = self.http("GET", origin + TERMS_PATH)
        if st != 200:
            raise ChannelError("provider_error", f"terms: HTTP {st}")
        terms = json.loads(raw)
        ex = terms["extra"]
        cap = max(capacity or self.ch2_capacity, int(ex["minCapacity"]))
        blocks = min(max(expiry_blocks or self.ch2_expiry_blocks, int(ex["minExpiryBlocks"]) + 6),
                     int(ex["maxExpiryBlocks"]) - 1)
        return self._fund_ch2(origin, terms, cap, self.rpc.getblockcount() + blocks)

    def _fund_ch2(self, origin: str, terms: dict, cap: int, expiry: int, funding=None) -> OutChannel:
        if funding is None and self.liquidity_cap_sat:
            old = self.out.chans.get(origin)
            freed = old.p().capacity if old is not None and old.state in ("funded", "open") else 0
            if self.committed_sat() - freed + cap > self.liquidity_cap_sat:
                raise ChannelError("liquidity_cap", f"{self.committed_sat()} + {cap} sat > liquidity_cap_sat "
                                                    f"{self.liquidity_cap_sat}")
        secret = secrets.randbelow(adaptor.N - 1) + 1
        pub = ecc.pubkey(secret).hex()
        p = ChannelParams.derive(terms["payTo"], pub, expiry, int(terms["extra"]["closeFeeSat"]), network=self.network)
        if funding is None:
            txid, vout = self.fund(segwit_address(self.hrp, p.spk), cap)
        else:
            txid, vout = funding
        p.funding_txid, p.funding_vout, p.capacity = txid, vout, cap
        oc = OutChannel(origin, terms["payTo"], p.to_dict(), f"{secret:064x}", "funded",
                        settle_multiple=int(terms["extra"].get("settleMultiple", 20)), terms=terms,
                        refund_hex=p.refund_tx(secret).hex(), opened_at=self.rpc.getblockcount(),
                        scanned_to=self.rpc.getblockcount())
        with self.out.lock:
            old = self.out.chans.get(origin)
            if old is not None:
                self.out.archived.append(asdict(old))
            self.out.chans[origin] = oc
            self.out.save()
        return oc

    def _open(self, oc: OutChannel) -> bool:
        p = oc.p()
        body = {"x402Version": 2, "network": self.network,
                "channel": {"txid": p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity,
                            "expiry": p.expiry, "payerPub": p.payer_pub, "payerSpk": p.payer_spk,
                            "redeemScript": p.script.hex()},
                "hub": {"payTo": self.pay_to, "sig": ecc.sign(self.secret, hub_channel_message(p.channel_id)).hex()}}
        st, _, raw = self.http("POST", oc.origin + oc.terms["extra"]["openUrl"], json.dumps(body).encode(),
                               {"Content-Type": "application/json"})
        if st != 200:
            return False
        with self.out.lock:
            oc.state = "open"
            self.out.save()
        self.events.append({"event": "ch2_open", "provider": oc.origin, "chan": p.channel_id, "capacity": p.capacity})
        return True

    def rollover(self, oc: OutChannel) -> dict:
        """One tx pays the provider its balance and funds the next ch2 (rollover instead of close)."""
        p = oc.p()
        amount = oc.signed
        next_cap = p.capacity - p.close_fee - amount
        min_cap = int(oc.terms["extra"]["minCapacity"])
        tip = self.rpc.getblockcount()
        ex = oc.terms["extra"]
        expiry = tip + min(max(self.ch2_expiry_blocks, int(ex["minExpiryBlocks"]) + 6), int(ex["maxExpiryBlocks"]) - 1)
        if next_cap < max(min_cap, DUST):
            return self.close_ch2(oc, refill=True)
        secret = secrets.randbelow(adaptor.N - 1) + 1
        pub = ecc.pubkey(secret).hex()
        nxt = ChannelParams.derive(oc.pay_to, pub, expiry, p.close_fee, network=self.network)
        tx = p.rollover_tx(amount, nxt.spk, next_cap)
        sig = ecc.sign(int(oc.secret, 16), p.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        req = {"chan": p.channel_id, "amount": amount, "sig": sig.hex(),
               "next": {"payerPub": pub, "payerSpk": nxt.payer_spk, "expiry": expiry}}
        st, _, raw = self.http("POST", oc.origin + ROLLOVER_PATH, json.dumps(req).encode(),
                               {"Content-Type": "application/json"})
        doc = json.loads(raw)
        if st != 200:
            raise ChannelError(doc.get("error", "provider_error") if isinstance(doc, dict) else "provider_error",
                               str(doc))
        txid = doc["txid"]
        with self.out.lock:
            oc.state, oc.rolled_to, oc.close_txid = "rolled", f"{txid}:1", txid
            self.out.save()
        nxt.funding_txid, nxt.funding_vout, nxt.capacity = txid, 1, next_cap
        new = OutChannel(oc.origin, oc.pay_to, nxt.to_dict(), f"{secret:064x}", "funded",
                         settle_multiple=oc.settle_multiple, terms=oc.terms, refund_hex=nxt.refund_tx(secret).hex(),
                         opened_at=tip, scanned_to=tip)
        with self.out.lock:
            self.out.archived.append(asdict(oc))
            self.out.chans[oc.origin] = new
            self.out.save()
        ev = {"event": "ch2_rollover", "provider": oc.origin, "txid": txid, "amount": amount,
              "next": new.p().channel_id, "nextCapacity": next_cap}
        self.events.append(ev)
        return ev

    def close_ch2(self, oc: OutChannel, refill: bool = False) -> dict:
        """Ask the provider to close ch2 (payer-signed close request); with `refill`, fund a new one."""
        from .x402_channel import close_message
        p = oc.p()
        if not oc.signed:
            # nothing signed on this ch2 (e.g. a fresh rollover): nothing to close; the hub's refund
            # (refund_hex, valid at expiry) returns the coins, or the next routed lock uses it
            ev = {"event": "ch2_idle", "provider": oc.origin, "chan": p.channel_id, "capacity": p.capacity}
            self.events.append(ev)
            return ev
        req = {"chan": p.channel_id, "sig": ecc.sign(int(oc.secret, 16), close_message(p.channel_id)).hex()}
        st, _, raw = self.http("POST", oc.origin + oc.terms["extra"]["closeUrl"], json.dumps(req).encode(),
                               {"Content-Type": "application/json"})
        doc = json.loads(raw)
        if st != 200:
            raise ChannelError("provider_error", str(doc))
        with self.out.lock:
            oc.state, oc.close_txid = "closed", doc["txid"]
            self.out.save()
        ev = {"event": "ch2_close", "provider": oc.origin, "txid": doc["txid"], "amount": int(doc["cum"])}
        self.events.append(ev)
        if refill:
            self.connect(oc.origin)
        return ev

    # --- watcher -----------------------------------------------------------------------------------
    def watch_tick(self) -> list:
        actions = []
        tip = self.rpc.getblockcount()
        for origin, oc in list(self.out.chans.items()):
            try:
                actions += self._watch_out(oc, tip)
            except Exception as e:  # noqa: BLE001 - one channel never stops the rest
                sys.stderr.write(f"hub watcher {origin}: {type(e).__name__}: {e}\n")
        for rec in list(self.out.archived):
            if rec.get("stale") and rec.get("state") in ("rolled", "closed"):
                pass                                          # their closes were read when they happened
        try:
            actions += [{"event": "ch1_close", "txid": t} for t in self.inbound.close_due()]
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"hub watcher ch1: {e}\n")
        return actions

    def _watch_out(self, oc: OutChannel, tip: int) -> list:
        # a route request in flight owns this ch2 (its mutex): never race it for the same lock
        mtx = self.out.mutex_for(oc.origin)
        if not mtx.acquire(blocking=False):
            return []
        try:
            return self._watch_out_locked(oc, tip)
        finally:
            mtx.release()

    def _watch_out_locked(self, oc: OutChannel, tip: int) -> list:
        out = []
        p = oc.p()
        if oc.state == "funded":
            utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
            if utxo and utxo.get("confirmations", 0) >= int(oc.terms["extra"].get("minConf", 1)):
                if self._open(oc):
                    out.append({"event": "ch2_open", "provider": oc.origin})
            return out
        if oc.state != "open":
            return out
        # a spent funding with a pending or written-off lock: read t off the close
        if (oc.pending or oc.stale) and self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is None:
            tx = find_spend(self.rpc, p.funding_txid, p.funding_vout, oc.scanned_to)
            if tx is not None:
                out += self._from_close(oc, tx)
                with self.out.lock:
                    oc.state, oc.close_txid = "closed", tx.txid()
                    self.out.save()
                return out
        if oc.pending:
            if time.time() - oc.pending["at"] < self.reveal_timeout:
                ans = self._send_lock(oc)
                if ans and "secret" in ans:
                    res = self._settled(oc.pending["ch1"], oc, ans)
                    out.append({"event": "lock_settled_late", "provider": oc.origin, "ok": res is not None})
            else:
                ans = self._send_lock(oc)                    # last try, then write it off
                if ans and "secret" in ans and self._settled(oc.pending["ch1"], oc, ans):
                    out.append({"event": "lock_settled_late", "provider": oc.origin})
                else:
                    st1 = self.inbound.ledger.channels[oc.pending["ch1"]]
                    lock1 = (st1.extra or {}).get("route_lock") or {"lockId": oc.pending["lockId"]}
                    self._void(st1, oc, lock1, "no reveal within revealTimeoutSec",
                               block="the provider did not reveal a lock in time")
                    out.append({"event": "lock_written_off", "provider": oc.origin})
            return out
        # settlement: >= settleMultiple x closeFee, or near ch2 expiry: roll over
        due = oc.signed >= oc.settle_multiple * p.close_fee
        near = tip >= p.expiry - self.close_margin - self.rollover_margin
        if (due or near) and oc.signed >= DUST and not oc.pending:
            out.append(self.rollover(oc))
        return out

    def _from_close(self, oc: OutChannel, tx) -> list:
        out = []
        pend = ([oc.pending] if oc.pending else []) + list(oc.stale)
        wit = tx.inputs[0].witness if tx.inputs else []
        for lk in pend:
            if not lk.get("pre"):
                continue
            t = adaptor.secret_from_witness(adaptor.PreSig.from_json(lk["pre"]), wit, adaptor.dec(lk["T"]))
            if t is None:
                continue
            with self.out.lock:
                oc.signed = max(oc.signed, lk["cum"])
                if oc.pending and oc.pending.get("lockId") == lk["lockId"]:
                    oc.routed += lk["d"]
                    oc.pending = {}
                oc.stale = [s for s in oc.stale if s["lockId"] != lk["lockId"]]
                self.out.save()
            res = self._complete_ch1(lk["ch1"], lk["lockId"], t, via=f"ch2 close {tx.txid()}")
            out.append({"event": "secret_from_close", "provider": oc.origin, "lockId": lk["lockId"],
                        "close": tx.txid(), "ch1_completed": res is not None})
        return out

    def watch(self, interval: float = 1.0):
        stop = threading.Event()

        def loop():
            while not stop.wait(interval):
                try:
                    self.watch_tick()
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"hub watcher: {e}\n")
        th = threading.Thread(target=loop, daemon=True, name="hub-watcher")
        th.start()
        return stop


# --- running a hub as a service ------------------------------------------------------------------
def main(argv=None, serve: bool = True):
    """python -m xbt402.hub --config hub.json

    {"node": {"rpcport": 8332, "cookie": "~/.xbt/.cookie", "wallet": "hub"},   the merchant's (pruned) node
     "network": "bip122:...", "port": 9480, "datadir": "~/xbt-hub",
     "pay_to_key_file": "~/.config/xbt-hub/payto.key",                          hex secret, 0600, never logged
     "connect": ["http://provider:port", ...],                                  providers to fund ch2s to
     "hub": {HubConfig fields: fees, fee_strategy, liquidity_cap_sat, ...},
     "watch_interval": 5}
    The fund hook is the node wallet named in "node" (sendtoaddress; no mining off regtest)."""
    import argparse
    from .rpc import RPC
    ap = argparse.ArgumentParser(prog="xbt402.hub")
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv)
    with open(os.path.expanduser(a.config)) as f:
        conf = json.load(f)
    node = conf["node"]
    rpc = RPC(int(node["rpcport"]), os.path.expanduser(node["cookie"]))
    wallet = rpc.wallet(node.get("wallet", "hub"))
    with open(os.path.expanduser(conf["pay_to_key_file"])) as f:
        secret = int(f.read().strip(), 16)
    cfg = HubConfig.from_dict(conf.get("hub") or {})

    def fund(address, sats):
        txid = wallet.sendtoaddress(address, sats / 1e8)
        raw = wallet.gettransaction(txid, False, True)["decoded"]
        return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)
    hub = RouteHub(rpc, secret, conf["network"], os.path.expanduser(conf["datadir"]), fund, cfg)
    for origin in conf.get("connect", []):
        if origin.rstrip("/") not in hub.out.chans:
            try:
                hub.connect(origin)
            except (ChannelError, OSError) as e:
                sys.stderr.write(f"hub: connect {origin}: {e}\n")
    stop = hub.watch(float(conf.get("watch_interval", 5)))
    srv = hub.http_server(int(conf["port"]))
    sys.stderr.write(f"xbt402 hub {hub.pay_to} on 127.0.0.1:{conf['port']} ({conf['network']})\n")
    if not serve:                                  # embedding (xbt-compute merchant --hub): caller serves
        return hub, srv, stop
    srv.serve_forever()


if __name__ == "__main__":
    main()
