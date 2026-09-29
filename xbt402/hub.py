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

The watcher (`watch_tick`): reconciles every non-final ch2 against the chain first (AGP-037, below);
posts the opens of hub-funded ch2s once confirmed; retries a pending
ch2 lock until `revealTimeoutSec`, then writes it off and stops routing to that provider; reads t
off any ch2 close that spends a funding with a pending or written-off lock and completes the ch1
lock with t + r; rolls ch2 over (one tx pays the provider and funds the next ch2) once the provider's
net payout reaches its settleMultiple x closeFee or ch2 nears expiry, never while a lock is pending;
and closes ch1s at their margin.

Money safety (AGP-037):
  * write-ahead funding: a ch2's payer key and params are on disk (state `funding`) before the `fund`
    hook runs, and a rollover's next ch2 (`next`) before the rollover request leaves. A fund hook that
    fails after it broadcast leaves a record the watcher reconciles against the chain (scantxoutset:
    found -> funded, the open goes on; not found within funding_timeout_blocks -> archived as
    `dropped`, key kept);
  * every non-final ch2 (funded, open, refunded, closed but unconfirmed) is checked each tick: a spent
    funding is read (find_spend) and the ch2 marked closed with the real spender, its locks' secrets
    recovered (_from_close); the hub's own refund is final once it confirms, rebroadcast while it is
    not; a provider close that beats the refund reverts the refund fee;
  * refunds: an unsigned ch2 at expiry, a signed one at expiry + refund_grace_blocks (the provider had
    its close margin to settle), at a hub-chosen fee (estimatesmartfee x vsize, floor
    refund_min_feerate), never the provider's closeFee;
  * close_ch2 checks the provider's reply against the ledger (txid, cum, payeeFee/payeeNet) and a bad
    reply is an error, never a state change; the watcher's reconcile finds what really happened;
  * a provider's /terms are bounded before the hub funds anything (HubConfig ch2_max_*); refills go
    through the `refill` hook (default: connect, the same terms, lock and cap path).

Leftovers (AGP-044, as the Rust hub):
  * a stuck refund is bumped by RBF: the hub holds the ch2 payer key and its refunds signal
    replaceability (RBF_SEQUENCE), so a refund still unconfirmed refund_bump_blocks after it was signed
    is re-signed at a higher fee (the estimate, at least 2x and + 1 sat/vB) to the same destination, up
    to refund_max_fee_sat; every version is kept (refund_prev) until one confirms, and whichever does
    is the refund;
  * one live ch2 per payTo: a provider is the payTo its /terms name, not the URL it was reached at
    (origins are canonical: canon_origin). A second origin with the payTo of a live ch2 reuses it
    (event ch2_reuse; its locks go over that ch2, to the origin that opened it), so one operator never
    splits the hub's capital over several ch2s; the cap accounting is unchanged.

Close fees (xbt402 v1.2 closeFeePayer, AGP-023): ch2 is payee-pays by default (Mike, 2026-09-28): the
provider pays its own settlement's close fee out of its output, so the hub's fees price only liquidity
and routing, and the settle threshold counts the provider's net payout. ch1 stays payer-pays (the
client pays, as on any plain channel) unless the operator configures otherwise. extra.routing
advertises both.
"""
import json
import math
import os
import secrets
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Optional

from . import adaptor, ecc
from .channel import (DUST, FEE_PAYERS, RBF_SEQUENCE, SIGHASH_ALL_UNIFIED, ChannelError, ChannelParams,
                      canonical_chan, settle_due)
from .funding import FundingPolicy
from .route import (HUB_ROUTE_PATH, ROLLOVER_PATH, ROUTE_LOCK_PATH, TERMS_PATH, FeeQuote, Invoice, canon_origin,
                    fee_due, find_spend, hub_channel_message, next_cum, route_ok)
from .tx import Tx, address_to_spk, segwit_address
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
    state: str = "funded"        # funding -> funded -> open -> closed | rolled | refunded; funding -> dropped
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
    refund_txid: str = ""        # the hub's broadcast refund (AGP-037)
    refund_fee: int = 0          # its fee; 0 again if a provider close won instead
    final: bool = False          # the funding's spend is confirmed: nothing left to watch
    next: dict = field(default_factory=dict)       # write-ahead: the rollover's next ch2 (asdict)
    fund_error: str = ""         # the fund hook raised: reconciled against the chain
    refund_at: int = 0           # the tip when the current refund version was signed (AGP-044)
    refund_prev: list = field(default_factory=list)  # earlier refund versions it replaced, {txid, fee}

    def p(self) -> ChannelParams:
        return ChannelParams(**self.params)


LIVE = ("funding", "funded", "open")                        # the hub's coins are committed
NONFINAL = ("funded", "open", "refunded", "closed")         # the watcher reconciles these until final


class OutBook:
    """The hub's ch2s, fsynced JSON (keys included: regtest only; the production hub signs with B2).

    One live ch2 per payTo (AGP-044): `origins` maps every origin the hub connected (canonical) to the
    payTo its /terms named; a second origin with the payTo of a live ch2 routes over that ch2."""

    def __init__(self, path: str):
        self.path, self.lock = path, threading.RLock()
        self.chans: Dict[str, OutChannel] = {}
        self.archived: list = []
        self.origins: Dict[str, str] = {}
        if os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            self.chans = {k: OutChannel(**v) for k, v in raw.get("chans", {}).items()}
            self.archived = raw.get("archived", [])
            self.origins = {k: str(v) for k, v in raw.get("origins", {}).items()}
        self.mutex: Dict[str, threading.Lock] = {}

    def live_for_pay_to(self, pay_to: str) -> Optional[str]:
        """The key of the live ch2 (funding, funded or open) to `pay_to`."""
        with self.lock:
            return next((k for k, c in self.chans.items() if c.pay_to.lower() == pay_to.lower() and c.state in LIVE), None)

    def key_for(self, origin: str) -> Optional[str]:
        """The key of the ch2 that serves `origin` (canonical): its own record while live, else the live
        ch2 of the payTo it was connected under, else its own record (closed, refunded, ...)."""
        with self.lock:
            own = self.chans.get(origin)
            if own is not None and own.state in LIVE:
                return origin
            pt = self.origins.get(origin) or (own.pay_to if own is not None else None)
            k = self.live_for_pay_to(pt) if pt else None
            return k or (origin if own is not None else None)

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"chans": {k: asdict(v) for k, v in self.chans.items()}, "archived": self.archived,
                           "origins": self.origins}, f)
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
    ch2_close_fee_payer: "payee" (default, v1.2): the hub opens ch2s only to providers whose /terms offer
    payee-pays, and each provider pays its own ch2 settlement fee; "payer": the hub pays ch2 closes
    (v1.1 providers) and should price them into its fees. ch1_close_fee_payer: ch1's terms (default
    "payer": the client pays its own channel's close, as on any plain channel).

    A provider's /terms are bounded before the hub funds a ch2 (AGP-037), or it is refused bad_terms:
    minExpiryBlocks + 6 <= ch2_max_expiry_blocks (0: 2 x ch2_expiry_blocks; the expiry is clamped to it
    too), closeFeeSat <= ch2_max_close_fee_sat and ch2_close_fee_multiple x closeFeeSat <= capacity,
    minConf <= ch2_max_min_conf, minCapacity <= ch2_max_min_capacity (0: ch2_capacity), settleMultiple
    <= ch2_max_settle_multiple. Refunds: refund_grace_blocks past expiry for a signed ch2, fee
    estimatesmartfee(refund_conf_target) x vsize, at least refund_min_feerate sat/vB, at most
    refund_max_fee_sat (bumps included); a refund still unconfirmed refund_bump_blocks after it was
    signed is re-signed at a higher fee (RBF, AGP-044; 0: never). A `funding` record the chain never
    shows is dropped after funding_timeout_blocks."""
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
    ch1_close_fee_payer: str = "payer"
    ch2_close_fee_payer: str = "payee"
    close_margin: int = 144
    rollover_margin: int = 36
    hrp: str = "bcrt"
    policy: dict = field(default_factory=lambda: {"min_expiry_blocks": 1_008, "max_expiry_blocks": 8_640})
    ch2_max_expiry_blocks: int = 0
    ch2_max_close_fee_sat: int = 5_000
    ch2_close_fee_multiple: int = 20
    ch2_max_min_conf: int = 6
    ch2_max_min_capacity: int = 0
    ch2_max_settle_multiple: int = 100
    refund_grace_blocks: int = 6
    refund_conf_target: int = 6
    refund_min_feerate: float = 1.0
    funding_timeout_blocks: int = 6
    refund_bump_blocks: int = 3
    refund_max_fee_sat: int = 5_000

    @classmethod
    def from_dict(cls, d: dict) -> "HubConfig":
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown hub config keys: {sorted(unknown)}")
        return cls(**d)

    def __post_init__(self):
        if self.ch1_close_fee_payer not in FEE_PAYERS or self.ch2_close_fee_payer not in FEE_PAYERS:
            raise ValueError("ch1_close_fee_payer / ch2_close_fee_payer are payer or payee")

    def funding_policy(self) -> FundingPolicy:
        return FundingPolicy(**{"close_margin": self.close_margin, **self.policy})


class RouteHub:
    def __init__(self, rpc, pay_to_secret: int, network: str, datadir: str, fund: Callable[[str, int], tuple],
                 config: HubConfig = None, *, http: Callable = None, policy: FundingPolicy = None,
                 fee_strategy: Callable = None, refill: Callable[[str], "OutChannel"] = None,
                 refund_to: Callable[[], str] = None, **overrides):
        """`config` (a HubConfig) holds the operator's choices; keyword `overrides` set single fields
        (fee_ppm=..., liquidity_cap_sat=...). `fee_strategy`, if given, is a callable(hub) ->
        (fee_base_msat, fee_ppm) that replaces the configured one. `refill(origin)` funds the ch2 that
        replaces a closed one (default `connect`: an embedder passes its own path, with its lock and
        cap). `refund_to()` gives the address a ch2 refund pays (default: the ch2's payer key)."""
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
            policy=policy or cfg.funding_policy(), close_fee_payer=cfg.ch1_close_fee_payer)
        self.out = OutBook(os.path.join(datadir, "ch2.json"))
        self.fee_base_msat, self.fee_ppm, self.quote_ttl = cfg.fee_base_msat, cfg.fee_ppm, cfg.quote_ttl
        self.max_lock_sat, self.max_unguarded_lock_sat, self.delta = cfg.max_lock_sat, cfg.max_unguarded_lock_sat, cfg.delta
        self.reveal_timeout, self.close_margin, self.close_fee = cfg.reveal_timeout, cfg.close_margin, cfg.close_fee
        self.ch2_capacity, self.ch2_expiry_blocks = cfg.ch2_capacity, cfg.ch2_expiry_blocks
        self.rollover_margin, self.liquidity_cap_sat = cfg.rollover_margin, cfg.liquidity_cap_sat
        self.fee_strategy = fee_strategy or self._configured_fees
        self.http = http or XbtChannelClient.http
        self.refill = refill or self.connect
        self.refund_to = refund_to
        self._quote: Optional[FeeQuote] = None
        self._quote_seq = int(time.time())
        self.withhold = ""           # tests/demo: "" | "receipt" (keep t + r from the client) | "all"
        self.events: list = []
        self.stats = {"routed": 0, "floor": 0, "refused": {}, "lock_ms": []}

    # ---------------------------------------------------------------------------------------------
    def committed_sat(self) -> int:
        """The hub's own coins in live ch2s (funding, funded or open)."""
        with self.out.lock:
            return sum(c.p().capacity for c in self.out.chans.values() if c.state in LIVE)

    def refund_fees_sat(self) -> int:
        """Fees of the hub's own ch2 refunds that spent (or still may spend) their fundings."""
        with self.out.lock:
            recs = [asdict(c) for c in self.out.chans.values()] + list(self.out.archived)
        return sum(int(r.get("refund_fee") or 0) for r in recs if r.get("state") == "refunded")

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
                # v1.2: who pays each hop's settlement close fee. ch2 payee-pays means the providers pay
                # their own closes, so feePpm prices only liquidity and routing
                "ch1CloseFeePayer": self.config.ch1_close_fee_payer,
                "ch2CloseFeePayer": self.config.ch2_close_fee_payer,
                "providers": self._routable()}

    def _routable(self) -> list:
        """Every origin whose ch2 (its own, or its payTo's) is open and not blocked."""
        with self.out.lock:
            def ok(o):
                k = self.out.key_for(o)
                c = self.out.chans.get(k) if k else None
                return c is not None and c.state == "open" and not c.blocked
            return sorted({o for o in list(self.out.chans) + list(self.out.origins) if ok(o)})

    def ch2_for(self, origin: str) -> Optional[OutChannel]:
        """The ch2 that serves `origin` (AGP-044: the live ch2 of its payTo, which may have been opened
        at another origin of the same operator)."""
        with self.out.lock:
            k = self.out.key_for(canon_origin(origin))
            return self.out.chans.get(k) if k else None

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
            provider = canon_origin(str(rt["provider"]))
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
            need1 = next_cum(routed1, d + f, st1.params.min_amount)
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
            # the provider is its payTo: an origin sharing a live ch2's payTo routes over that ch2
            key = self.out.key_for(provider) or provider
            oc = self.out.chans.get(key)
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
            mtx = self.out.mutex_for(key)
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
        need2 = next_cum(oc.routed, d, p2.min_amount)
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
    def ch2_terms(self, terms: dict, capacity: int = None, expiry_blocks: int = None) -> tuple:
        """Bound a provider's /terms before the hub funds anything (AGP-037): (capacity, blocks) or
        ChannelError bad_terms. A provider must not be able to set a ch2 the hub can never use or get
        back: an expiry decades away, a close fee that eats the capacity, a minConf never reached."""
        c = self.config
        try:
            ex = terms["extra"]
            if not isinstance(terms["payTo"], str) or len(bytes.fromhex(terms["payTo"])) != 33:
                raise ValueError("payTo")
            close_fee, min_cap = int(ex["closeFeeSat"]), int(ex["minCapacity"])
            lo, hi = int(ex["minExpiryBlocks"]) + 6, int(ex["maxExpiryBlocks"]) - 1
            min_conf, mult = int(ex.get("minConf", 1)), int(ex.get("settleMultiple", 20))
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ChannelError("bad_terms", f"malformed /terms: {type(e).__name__} {e}") from None
        max_blocks = c.ch2_max_expiry_blocks or 2 * c.ch2_expiry_blocks
        cap = max(capacity or self.ch2_capacity, min_cap)
        why = ""
        if not 0 <= close_fee <= c.ch2_max_close_fee_sat:
            why = f"closeFeeSat {close_fee} > ch2_max_close_fee_sat {c.ch2_max_close_fee_sat}"
        elif close_fee * c.ch2_close_fee_multiple > cap:
            why = f"{c.ch2_close_fee_multiple} x closeFeeSat {close_fee} > capacity {cap}"
        elif not 0 <= min_cap <= (c.ch2_max_min_capacity or self.ch2_capacity):
            why = f"minCapacity {min_cap} > ch2_max_min_capacity {c.ch2_max_min_capacity or self.ch2_capacity}"
        elif lo > max_blocks or lo > hi:
            why = f"minExpiryBlocks + 6 = {lo} > max expiry {min(max_blocks, hi)}"
        elif not 0 <= min_conf <= c.ch2_max_min_conf:
            why = f"minConf {min_conf} > ch2_max_min_conf {c.ch2_max_min_conf}"
        elif not 1 <= mult <= c.ch2_max_settle_multiple:
            why = f"settleMultiple {mult} outside [1, {c.ch2_max_settle_multiple}]"
        if why:
            raise ChannelError("bad_terms", why)
        return cap, min(max(expiry_blocks or self.ch2_expiry_blocks, lo), hi, max_blocks)

    def connect(self, origin: str, capacity: int = None, expiry_blocks: int = None) -> OutChannel:
        """Fund a ch2 to `origin` from the hub's own wallet. It opens (watch_tick / open_pending) once
        the funding has the provider's minConf.

        One live ch2 per payTo (AGP-044): if the provider's payTo already has a live ch2 (under this
        origin or another), nothing is funded: `origin` is recorded under that payTo and the live ch2 is
        returned (event ch2_reuse); its rollovers and refills go on as usual."""
        origin = canon_origin(origin)
        cur = self.out.chans.get(origin)
        if cur is not None and cur.state == "funding":
            raise ChannelError("ch2_funding", f"a ch2 to {origin} is being funded (the watcher reconciles it)")
        st, _, raw = self.http("GET", origin + TERMS_PATH)
        if st != 200:
            raise ChannelError("provider_error", f"terms: HTTP {st}")
        try:
            terms = json.loads(raw)
            offered = terms["extra"].get("closeFeePayer", "payer")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ChannelError("bad_terms", "terms are not a JSON object with extra") from None
        if self.config.ch2_close_fee_payer == "payee" and offered != "payee":
            raise ChannelError("bad_fee_payer", f"{origin} does not offer payee-pays routed channels "
                                                f"(closeFeePayer {offered!r}); set ch2_close_fee_payer payer to fund it")
        cap, blocks = self.ch2_terms(terms, capacity, expiry_blocks)
        pay_to = str(terms["payTo"]).lower()
        with self.out.lock:
            self.out.origins[origin] = pay_to
            k = self.out.live_for_pay_to(pay_to)
            reused = self.out.chans[k] if k else None
            self.out.save()
        if reused is not None:
            if reused.state == "funding":
                raise ChannelError("ch2_funding", f"a ch2 to payTo {pay_to[:16]}... is being funded (the watcher reconciles it)")
            if reused.origin != origin:
                self.events.append({"event": "ch2_reuse", "provider": origin, "ch2": reused.origin, "payTo": pay_to,
                                    "chan": reused.p().channel_id})
            return reused
        return self._fund_ch2(origin, terms, cap, self.rpc.getblockcount() + blocks)

    def _fund_ch2(self, origin: str, terms: dict, cap: int, expiry: int) -> OutChannel:
        """Write-ahead (AGP-037): the ch2's key and params are on disk, state `funding`, before the fund
        hook runs, and the cap check and that record are one step under the book's lock."""
        secret = secrets.randbelow(adaptor.N - 1) + 1
        pub = ecc.pubkey(secret).hex()
        p = ChannelParams.derive(terms["payTo"], pub, expiry, int(terms["extra"]["closeFeeSat"]), network=self.network,
                                 close_fee_payer=self.config.ch2_close_fee_payer)
        p.capacity = cap
        tip = self.rpc.getblockcount()
        oc = OutChannel(origin, terms["payTo"], p.to_dict(), f"{secret:064x}", "funding",
                        settle_multiple=int(terms["extra"].get("settleMultiple", 20)), terms=terms,
                        opened_at=tip, scanned_to=tip)
        with self.out.lock:
            old = self.out.chans.get(origin)
            if old is not None and old.state == "funding":
                raise ChannelError("ch2_funding", f"a ch2 to {origin} is being funded")
            live = self.out.live_for_pay_to(terms["payTo"])
            if live is not None:                    # one live ch2 per payTo, checked with the insert (racing connects)
                raise ChannelError("ch2_funding", f"a live ch2 to that payTo exists ({live})")
            if self.liquidity_cap_sat:
                freed = old.p().capacity if old is not None and old.state in LIVE else 0
                if self.committed_sat() - freed + cap > self.liquidity_cap_sat:
                    raise ChannelError("liquidity_cap", f"{self.committed_sat()} + {cap} sat > liquidity_cap_sat "
                                                        f"{self.liquidity_cap_sat}")
            if old is not None:
                self.out.archived.append(asdict(old))
            self.out.chans[origin] = oc
            self.out.save()
        try:
            txid, vout = self.fund(segwit_address(self.hrp, p.spk), cap)
        except Exception as e:  # noqa: BLE001 - it may have broadcast: the record stays for the watcher
            with self.out.lock:
                oc.fund_error = f"{type(e).__name__}: {e}"[:200]
                self.out.save()
            self.events.append({"event": "ch2_fund_failed", "provider": origin, "error": oc.fund_error})
            raise ChannelError("fund_failed", f"fund hook: {oc.fund_error} (the watcher reconciles the record)") from e
        self._funded(oc, txid, vout, cap)
        return oc

    def _funded(self, oc: OutChannel, txid: str, vout: int, cap: int):
        p = oc.p()
        p.funding_txid, p.funding_vout, p.capacity = txid, int(vout), int(cap)
        with self.out.lock:
            oc.params, oc.state = p.to_dict(), "funded"
            oc.refund_hex = p.refund_tx(int(oc.secret, 16)).hex()   # fallback; the watcher refunds at its own fee
            self.out.save()

    def _reconcile_funding(self, oc: OutChannel, tip: int) -> list:
        """A `funding` record (the fund hook raised, or the hub stopped mid-fund): the funding on chain
        -> funded, and the open goes on; none within funding_timeout_blocks -> dropped (archived with
        its key, so a late confirmation can still be refunded by hand)."""
        p = oc.p()
        try:
            r = self.rpc.scantxoutset("start", [f"raw({p.spk.hex()})"]) or {}
        except Exception as e:  # noqa: BLE001 - a node without scantxoutset: wait, then drop
            sys.stderr.write(f"hub: scantxoutset for {oc.origin}: {e}\n")
            r = {}
        hits = [u for u in r.get("unspents", []) if round(float(u.get("amount", 0)) * 1e8) >= DUST]
        if hits:
            u = hits[0]
            self._funded(oc, u["txid"], int(u["vout"]), round(float(u["amount"]) * 1e8))
            ev = {"event": "ch2_funding_recovered", "provider": oc.origin, "chan": oc.p().channel_id}
            self.events.append(ev)
            return [ev]
        if tip - oc.opened_at < self.config.funding_timeout_blocks:
            return []
        with self.out.lock:
            oc.state = "dropped"
            self.out.archived.append(asdict(oc))
            if self.out.chans.get(oc.origin) is oc:
                del self.out.chans[oc.origin]
            self.out.save()
        ev = {"event": "ch2_funding_dropped", "provider": oc.origin, "error": oc.fund_error}
        self.events.append(ev)
        return [ev]

    def _open(self, oc: OutChannel) -> bool:
        p = oc.p()
        body = {"x402Version": 2, "network": self.network,
                "channel": {"txid": p.funding_txid, "vout": p.funding_vout, "capacity": p.capacity,
                            "expiry": p.expiry, "payerPub": p.payer_pub, "payerSpk": p.payer_spk,
                            "redeemScript": p.script.hex(),
                            **({"closeFeePayer": p.close_fee_payer} if p.close_fee_payer != "payer" else {})},
                "hub": {"payTo": self.pay_to, "sig": ecc.sign(self.secret, hub_channel_message(p.channel_id)).hex()}}
        st, _, raw = self.http("POST", oc.origin + oc.terms["extra"]["openUrl"], json.dumps(body).encode(),
                               {"Content-Type": "application/json"})
        if st != 200:
            return False
        try:
            echoed = json.loads(raw).get("closeFeePayer", "payer")
        except (ValueError, AttributeError):
            echoed = None
        if echoed != p.close_fee_payer:
            # every state we would sign would fail at the provider: never route over this channel
            with self.out.lock:
                oc.blocked = f"the provider opened ch2 with closeFeePayer {echoed!r}"
                self.out.save()
            return False
        with self.out.lock:
            oc.state = "open"
            self.out.save()
        self.events.append({"event": "ch2_open", "provider": oc.origin, "chan": p.channel_id, "capacity": p.capacity})
        return True

    def rollover(self, oc: OutChannel) -> dict:
        """One tx pays the provider its balance and funds the next ch2 (rollover instead of close). The
        next ch2's key is written ahead (`oc.next`), and its funding txid is known before the request
        leaves, so a lost answer is finished by the watcher when that tx spends the funding."""
        p = oc.p()
        amount = oc.signed
        next_cap = p.rollover_next_capacity(amount)      # payee-pays: capacity - amount, the fee is the provider's
        min_cap = int(oc.terms["extra"]["minCapacity"])
        tip = self.rpc.getblockcount()
        _, blocks = self.ch2_terms(oc.terms)
        expiry = tip + blocks
        if next_cap < max(min_cap, p.min_amount):
            return self.close_ch2(oc, refill=True)
        secret = secrets.randbelow(adaptor.N - 1) + 1
        pub = ecc.pubkey(secret).hex()
        nxt = ChannelParams.derive(oc.pay_to, pub, expiry, p.close_fee, network=self.network,
                                   close_fee_payer=p.close_fee_payer)
        tx = p.rollover_tx(amount, nxt.spk, next_cap)
        txid = tx.txid()
        nxt.funding_txid, nxt.funding_vout, nxt.capacity = txid, 1, next_cap
        new = OutChannel(oc.origin, oc.pay_to, nxt.to_dict(), f"{secret:064x}", "funded",
                         settle_multiple=oc.settle_multiple, terms=oc.terms, refund_hex=nxt.refund_tx(secret).hex(),
                         opened_at=tip, scanned_to=tip)
        with self.out.lock:
            oc.next = asdict(new)                     # write-ahead: the next ch2's key before the request
            self.out.save()
        sig = ecc.sign(int(oc.secret, 16), p.sighash(tx)) + bytes([SIGHASH_ALL_UNIFIED])
        req = {"chan": p.channel_id, "amount": amount, "sig": sig.hex(),
               "next": {"payerPub": pub, "payerSpk": nxt.payer_spk, "expiry": expiry}}
        try:
            st, _, raw = self.http("POST", oc.origin + ROLLOVER_PATH, json.dumps(req).encode(),
                                   {"Content-Type": "application/json"})
            doc = json.loads(raw)
        except (OSError, ValueError) as e:
            raise ChannelError("provider_error", f"rollover: {type(e).__name__}: {e}") from None
        if st != 200:
            if st in (400, 401, 403):                  # refused: nothing was broadcast
                with self.out.lock:
                    oc.next = {}
                    self.out.save()
            raise ChannelError(doc.get("error", "provider_error") if isinstance(doc, dict) else "provider_error",
                               str(doc)[:200])
        if not isinstance(doc, dict) or str(doc.get("txid", "")).lower() != txid:
            raise ChannelError("bad_rollover_reply", f"rollover reply {str(doc)[:120]} is not tx {txid}")
        return self._finish_rollover(oc, amount)

    def _finish_rollover(self, oc: OutChannel, amount: int) -> dict:
        new = OutChannel(**oc.next)
        txid = new.p().funding_txid
        with self.out.lock:
            oc.state, oc.rolled_to, oc.close_txid, oc.next = "rolled", f"{txid}:1", txid, {}
            self.out.archived.append(asdict(oc))
            if self.out.chans.get(oc.origin) is oc:
                self.out.chans[oc.origin] = new
            else:
                self.out.archived.append(asdict(new))
            self.out.save()
        ev = {"event": "ch2_rollover", "provider": oc.origin, "txid": txid, "amount": amount,
              "next": new.p().channel_id, "nextCapacity": new.p().capacity}
        self.events.append(ev)
        return ev

    def close_ch2(self, oc: OutChannel, refill: bool = False) -> dict:
        """Ask the provider to close ch2 (payer-signed close request); with `refill`, fund a new one
        through the `refill` hook. The provider's reply must match the ledger (AGP-037): a 64-hex txid,
        cum = a state the hub signed (its best, or a pending or written-off lock's), and on a payee-pays
        ch2 payeeFee = the channel's close fee, payeeNet = cum - payeeFee. Anything else raises
        bad_close_reply and changes nothing: the watcher reads the real close off the chain."""
        from .x402_channel import close_message
        p = oc.p()
        if not oc.signed:
            # nothing signed on this ch2 (e.g. a fresh rollover): nothing to close; the hub's refund
            # (at expiry, by the watcher) returns the coins, or the next routed lock uses it
            ev = {"event": "ch2_idle", "provider": oc.origin, "chan": p.channel_id, "capacity": p.capacity}
            self.events.append(ev)
            return ev
        req = {"chan": p.channel_id, "sig": ecc.sign(int(oc.secret, 16), close_message(p.channel_id)).hex()}
        try:
            st, _, raw = self.http("POST", oc.origin + oc.terms["extra"]["closeUrl"], json.dumps(req).encode(),
                                   {"Content-Type": "application/json"})
        except OSError as e:
            raise ChannelError("provider_error", f"close: {type(e).__name__}: {e}") from None
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if st != 200:
            raise ChannelError("provider_error", str(doc)[:200])
        txid, cum = self._check_close_reply(oc, doc)
        with self.out.lock:
            oc.state, oc.close_txid = "closed", txid
            self.out.save()
        ev = {"event": "ch2_close", "provider": oc.origin, "chan": p.channel_id, "txid": txid, "amount": cum,
              "payeeFee": p.payee_fee, "payeeNet": max(0, cum - p.payee_fee)}
        self.events.append(ev)
        if refill:
            try:
                self.refill(oc.origin)
            except Exception as e:  # noqa: BLE001 - the close stands; the refill is reported
                ev["refillError"] = f"{type(e).__name__}: {e}"[:200]
                self.events.append({"event": "ch2_refill_failed", "provider": oc.origin, "error": ev["refillError"]})
        return ev

    def _check_close_reply(self, oc: OutChannel, doc) -> tuple:
        p = oc.p()

        def bad(why):
            self.events.append({"event": "ch2_close_bad_reply", "provider": oc.origin, "chan": p.channel_id,
                                "why": why})
            return ChannelError("bad_close_reply", why)
        if not isinstance(doc, dict):
            raise bad("not a JSON object")
        txid = doc.get("txid")
        if not isinstance(txid, str) or len(txid) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in txid):
            raise bad(f"txid {str(txid)[:70]!r}")
        try:
            cum = int(str(doc["cum"]), 10)
        except (KeyError, ValueError):
            raise bad(f"cum {str(doc.get('cum'))[:40]!r}") from None
        allowed = {oc.signed} | {int(lk["cum"]) for lk in ([oc.pending] if oc.pending else []) + list(oc.stale)}
        if cum not in allowed:
            raise bad(f"cum {cum} is no state the hub signed (best {oc.signed})")
        if "chan" in doc and doc["chan"] != p.channel_id:
            raise bad(f"chan {str(doc['chan'])[:80]!r}")
        for k, want in (("payeeFee", p.payee_fee), ("payeeNet", max(0, cum - p.payee_fee))):
            if p.payee_fee and k in doc and str(doc[k]) != str(want):
                raise bad(f"{k} {str(doc[k])[:30]!r} != {want}")
        return txid.lower(), cum

    # --- refunds -----------------------------------------------------------------------------------
    def refund_fee(self, p: ChannelParams, dest: bytes = None) -> int:
        """The hub's fee for a ch2 refund: estimatesmartfee(refund_conf_target) x vsize, at least
        refund_min_feerate sat/vB; never the provider's closeFee, never above refund_max_fee_sat, and
        never below dust left over."""
        vsize = p.refund_tx(1, dest, 0).vsize() + 1        # +1: a 73-byte signature at worst
        rate = float(self.config.refund_min_feerate)
        try:
            est = self.rpc.estimatesmartfee(int(self.config.refund_conf_target)) or {}
            if est.get("feerate"):
                rate = max(rate, float(est["feerate"]) * 1e8 / 1000)
        except Exception:  # noqa: BLE001 - no estimate (regtest, a fresh node): the floor
            pass
        return max(0, min(math.ceil(rate * vsize), self._refund_fee_cap(p)))

    def _refund_fee_cap(self, p: ChannelParams) -> int:
        return max(0, min(int(self.config.refund_max_fee_sat), p.capacity - DUST))

    def _bumped_fee(self, oc: OutChannel, dest: bytes) -> int:
        """The fee of the version that replaces a stuck refund (AGP-044): the current estimate, at least
        double the stuck fee, capped. A replacement must pay the stuck fee + 1 sat/vB (BIP125's
        incremental relay fee): when the cap leaves less, there is none (the stuck fee is returned)."""
        p = oc.p()
        est = self.refund_fee(p, dest)
        vsize = Tx.parse(bytes.fromhex(oc.refund_hex)).vsize() + 1 if oc.refund_hex else 0
        step = oc.refund_fee + vsize
        f = min(max(est, 2 * oc.refund_fee, step), self._refund_fee_cap(p))
        return oc.refund_fee if f < step else f

    def _refund_due(self, oc: OutChannel, tip: int) -> bool:
        if oc.state not in ("funded", "open", "closed") or oc.pending or not oc.p().funding_txid:
            return False
        p = oc.p()
        grace = self.config.refund_grace_blocks if oc.signed >= p.min_amount else 0
        return tip >= p.expiry + grace

    def _bump_due(self, oc: OutChannel, tip: int) -> bool:
        """The current refund has waited refund_bump_blocks since it was signed."""
        n = int(self.config.refund_bump_blocks)
        return bool(oc.refund_txid) and n > 0 and tip >= oc.refund_at + n

    def _refund(self, oc: OutChannel, tip: int) -> list:
        """Refund a ch2 at the hub's fee, or send the refund already signed again; once it has waited
        refund_bump_blocks, re-sign it at _bumped_fee (RBF: the hub holds the payer key and its refunds
        signal replaceability), paying the same destination. Every version is written ahead and kept
        (refund_prev) until one confirms."""
        p = oc.p()
        prior, bump = bool(oc.refund_txid), self._bump_due(oc, tip)
        out = []
        kind = "ch2_refund_rebroadcast" if prior else "ch2_refund"
        old_txid, old_fee = oc.refund_txid, oc.refund_fee
        if not prior or bump:
            if bump:        # the same destination as the version it replaces (refund_to may hand out a new address)
                dest = Tx.parse(bytes.fromhex(oc.refund_hex)).outputs[0].script_pubkey
                f = self._bumped_fee(oc, dest)
            else:
                dest = address_to_spk(self.refund_to(), self.hrp) if self.refund_to else None
                f = self.refund_fee(p, dest)
            if bump and f <= oc.refund_fee:
                # at the cap: nothing higher to sign; send what we have and look again in refund_bump_blocks
                with self.out.lock:
                    oc.refund_at = tip
                    self.out.save()
                ev = {"event": "ch2_refund_bump_capped", "provider": oc.origin, "chan": p.channel_id,
                      "txid": oc.refund_txid, "fee": oc.refund_fee, "cap": self._refund_fee_cap(p)}
                self.events.append(ev)
                out.append(ev)
            else:
                tx = p.refund_tx(int(oc.secret, 16), dest, f, sequence=RBF_SEQUENCE)
                with self.out.lock:                         # write-ahead: every version we may see confirm
                    if prior:
                        oc.refund_prev = oc.refund_prev + [{"txid": oc.refund_txid, "fee": oc.refund_fee}]
                    oc.refund_hex, oc.refund_txid, oc.refund_fee, oc.refund_at = tx.serialize().hex(), tx.txid(), f, tip
                    self.out.save()
                if bump:
                    kind = "ch2_refund_bump"
        try:
            self.rpc.sendrawtransaction(oc.refund_hex)
        except Exception as e:  # noqa: BLE001 - e.g. the provider's close got there first (the reconcile
            # sees it), or a replacement the node refused (the version it replaces is still tracked)
            ev = {"event": "ch2_refund_bump_failed" if kind == "ch2_refund_bump" else "ch2_refund_failed",
                  "provider": oc.origin, "chan": p.channel_id, "txid": oc.refund_txid, "fee": oc.refund_fee,
                  "error": f"{type(e).__name__}: {e}"[:200]}
            self.events.append(ev)
            out.append(ev)
            return out
        with self.out.lock:
            oc.state = "refunded"
            self.out.save()
        ev = {"event": kind, "provider": oc.origin, "chan": p.channel_id, "txid": oc.refund_txid, "fee": oc.refund_fee,
              "signed": oc.signed}
        if kind == "ch2_refund_bump":
            ev.update(replaces=old_txid, feeFrom=old_fee)
        self.events.append(ev)
        out.append(ev)
        return out

    # --- watcher -----------------------------------------------------------------------------------
    def watch_tick(self) -> list:
        actions = []
        tip = self.rpc.getblockcount()
        for origin, oc in list(self.out.chans.items()):
            try:
                actions += self._watch_out(oc, tip)
            except Exception as e:  # noqa: BLE001 - one channel never stops the rest
                self._watch_error(origin, "watch", e)
        with self.out.lock:
            archived = [(i, r) for i, r in enumerate(self.out.archived)
                        if r.get("state") in NONFINAL and not r.get("final")]
        for i, rec in archived:                             # replaced ch2s are still the hub's coins
            try:
                oc = OutChannel(**rec)
                acts = self._reconcile(oc, tip)
                with self.out.lock:
                    self.out.archived[i] = asdict(oc)
                    self.out.save()
                actions += acts
            except Exception as e:  # noqa: BLE001
                self._watch_error(rec.get("origin", "?"), "archived", e)
        try:
            actions += [{"event": "ch1_close", "txid": t} for t in self.inbound.close_due()]
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"hub watcher ch1: {e}\n")
        return actions

    def _watch_error(self, origin: str, step: str, e: Exception):
        msg = f"{type(e).__name__}: {e}"[:200]
        sys.stderr.write(f"hub watcher {origin} ({step}): {msg}\n")
        self.events.append({"event": "ch2_watch_error", "provider": origin, "step": step, "error": msg})

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
        if oc.state == "funding":
            return self._reconcile_funding(oc, tip)
        try:                                                # its own step: a failure here never skips the rest
            out += self._reconcile(oc, tip)
        except Exception as e:  # noqa: BLE001
            self._watch_error(oc.origin, "reconcile", e)
        if self.out.chans.get(oc.origin) is not oc:
            return out                                      # finished a rollover: the next ch2 is watched next tick
        p = oc.p()
        if oc.state == "funded":
            utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
            if utxo and utxo.get("confirmations", 0) >= int(oc.terms["extra"].get("minConf", 1)):
                if self._open(oc):
                    out.append({"event": "ch2_open", "provider": oc.origin})
            return out
        if oc.state != "open":
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
        # settlement: the provider's net payout >= its settleMultiple x closeFee (on a payee-pays ch2 the
        # close fee is the provider's, so it counts against the payout), or near ch2's close margin as
        # the provider counts it (it co-signs only then): roll over. Past expiry the refund took over.
        ex = oc.terms.get("extra", {})
        due = settle_due(p, oc.signed, oc.settle_multiple)
        margin = int(ex.get("closeMarginBlocks", self.close_margin))
        grace = min(self.rollover_margin, int(ex.get("rolloverGraceBlocks", self.rollover_margin)))
        near = tip >= p.expiry - margin - grace
        if (due or near) and oc.signed >= p.min_amount and not oc.pending and tip < p.expiry:
            out.append(self.rollover(oc))
        return out

    def _reconcile(self, oc: OutChannel, tip: int) -> list:
        """Check one non-final ch2's funding against the chain (AGP-037).
        unspent: refund it when due; rebroadcast our refund if it left the mempool.
        spent by the rollover we wrote ahead: finish it. spent by our refund: final once confirmed.
        spent by anything else (the provider's close): read the locks' secrets off it, mark it closed
        with the real txid, and take back the refund fee if our refund lost. Spent, spender not found:
        with locks outstanding leave it (their secrets are on that tx); without, closed, txid unknown."""
        if oc.final or oc.state not in NONFINAL:
            return []
        p = oc.p()
        if not p.funding_txid:
            return []
        out = []
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is not None:
            if oc.state == "refunded" or self._refund_due(oc, tip):
                # due, or our refund left the mempool: send it (again, or bumped once it waited)
                return self._refund(oc, tip)
            return out
        confirmed = self.rpc.gettxout(p.funding_txid, p.funding_vout, False) is None
        if oc.state == "closed" and oc.close_txid and not (oc.pending or oc.stale) and not oc.refund_txid:
            if confirmed:                                   # the provider's close as it told us: done
                with self.out.lock:
                    oc.final = True
                    self.out.save()
            return out
        tx = find_spend(self.rpc, p.funding_txid, p.funding_vout, oc.scanned_to)
        if tx is None:
            if oc.state == "open" and not (oc.pending or oc.stale):     # a funded one may not be visible yet
                with self.out.lock:
                    oc.state, oc.close_txid = "closed", ""
                    self.out.save()
                ev = {"event": "ch2_closed", "provider": oc.origin, "chan": p.channel_id, "txid": "", "by": "unknown"}
                self.events.append(ev)
                out.append(ev)
            return out
        spender = tx.txid()
        if oc.next and spender == OutChannel(**oc.next).p().funding_txid:
            return [self._finish_rollover(oc, oc.signed)]
        prev_fee = next((int(r.get("fee") or 0) for r in oc.refund_prev if r.get("txid") == spender), None)
        if spender == oc.refund_txid or prev_fee is not None:          # one of our refund versions
            fee = oc.refund_fee if prev_fee is None else prev_fee
            with self.out.lock:
                oc.state, oc.final = "refunded", confirmed
                if confirmed and prev_fee is not None:     # an earlier version won: it is the refund that counts
                    oc.refund_txid, oc.refund_fee, oc.refund_hex = spender, fee, ""
                self.out.save()
            if confirmed:
                ev = {"event": "ch2_refund_confirmed", "provider": oc.origin, "chan": p.channel_id,
                      "txid": spender, "fee": fee, "versions": len(oc.refund_prev) + 1}
                self.events.append(ev)
                out.append(ev)
            elif self._bump_due(oc, tip):                   # stuck in the mempool: replace it at a higher fee
                out += self._refund(oc, tip)
            return out
        if oc.pending or oc.stale:
            out += self._from_close(oc, tx)
        lost = oc.refund_fee if oc.refund_txid else 0
        changed = oc.state != "closed" or oc.close_txid != spender
        with self.out.lock:
            oc.state, oc.close_txid, oc.final, oc.next = "closed", spender, confirmed, {}
            if lost:
                oc.refund_fee = 0
            self.out.save()
        if changed:
            ev = {"event": "ch2_closed", "provider": oc.origin, "chan": p.channel_id, "txid": spender, "by": "provider",
                  **({"refundLost": oc.refund_txid, "refundFeeReverted": lost} if oc.refund_txid else {})}
            self.events.append(ev)
            out.append(ev)
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
    hub = RouteHub(rpc, secret, conf["network"], os.path.expanduser(conf["datadir"]), fund, cfg,
                   refund_to=lambda: wallet.getnewaddress("", "bech32"))   # bech32 whatever the wallet default (AGP-044)
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
