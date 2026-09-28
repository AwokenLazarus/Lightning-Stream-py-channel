"""RoutePayer: pay many xbt402 providers through one hub channel (AGP-021 client SDK).

    payer = RoutePayer("http://hub:port", network, height=node.getblockcount, fund=wallet_fund)
    payer.open()                                   # one ch1 to the hub, whatever the number of shards
    a = payer.shard("http://shard-a:port/forward") # a session: signed price quote + first invoice
    payer.start()                                  # per-window locks, serial on ch1, off the data path
    status, headers, body = a.call("POST", chunk)  # data calls go straight to the provider
    ...
    payer.stop(); payer.close()                    # cooperative close of ch1 (the hub closes it)

Data calls carry ROUTE-AUTH (an HMAC under a client <-> provider ECDH key the hub never sees) and come
back with a provider-signed ROUTE-STATE: the running meter in amsat, what the provider has been
paid, the open invoice (a fresh lock point T per window) and the last lock's t. So the client:
  * never waits on routing per chunk: chunks run on the provider's credit window;
  * pays each window's accrued amount as the ceil of the running total minus what is already
    paid (the carry, constraint 2) with one adaptor lock per provider, one after another on ch1;
  * gets its receipt from the hub (t + r) or, if the hub withholds it, from the provider (t);
  * gives a lock up when the hub refuses it, or when its invoice expires unanswered: the lock can
    then cost at most its own amount (one window of one provider), and a later state dominates it.

`signer` is anything with the ChannelSigner API plus the adaptor methods (`sign_state_adaptor`,
`resolve_lock`, `void_lock`): B1's ChannelSigner (keys in process, tests), or the B2 wallet
(agentwallet.routing.RouteSigner, policy-checked, keys never leave B2).
"""
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Optional

from . import adaptor, ecc
from .channel import ChannelError
from .route import (AMSAT_PER_SAT, HUB_ROUTE_PATH, FeeQuote, Invoice, PriceQuote, call_auth, ceil_div, fee_due,
                    lock_auth, next_cum, session_key, state_verify)
from .signer import ChannelSigner
from .x402_channel import XbtChannelClient, b64json, request_digest, unb64json


@dataclass
class Shard:
    url: str
    origin: str
    path: str
    pay_to: str
    session: str
    key: bytes
    quote: PriceQuote
    invoice: dict
    window: float
    lock_wait: float
    seq: int = 0
    accrued_amsat: int = 0        # the provider's signed running total
    seen_amsat: int = 0           # the sum of the per-call charges we were shown
    paid_sat: int = 0             # what the provider says it has been paid (signed)
    locked_sat: int = 0           # what our completed locks paid it
    calls: int = 0
    last_lock: dict = field(default_factory=dict)
    stopped: str = ""
    call_ms: list = field(default_factory=list)
    lock_ms: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def due_sat(self) -> int:
        return ceil_div(self.accrued_amsat, AMSAT_PER_SAT) - max(self.paid_sat, self.locked_sat)


class RoutePayer:
    def __init__(self, hub_url: str, network: str, height: Callable[[], int], fund: Callable = None, signer=None, *,
                 capacity: int = 200_000, expiry_blocks: int = 8_000, max_fee_ppm: int = 10_000,
                 max_fee_base_msat: int = 10_000, max_lock_sat: int = 50_000, void_grace: float = 1.0,
                 http: Callable = None):
        self.hub_url = hub_url.rstrip("/")
        self.network = network
        self.signer = signer or ChannelSigner(fund=fund)
        self.cc = XbtChannelClient(network, fund, height, capacity=capacity, expiry_blocks=expiry_blocks,
                                   max_price=10 ** 12, signer=self.signer, budget_sats=10 ** 12)
        if http:
            self.cc.http = http
        self.http = self.cc.http
        self.max_fee_ppm, self.max_fee_base_msat, self.max_lock_sat = max_fee_ppm, max_fee_base_msat, max_lock_sat
        self.void_grace = void_grace
        self.ch = None
        self.quote: Optional[FeeQuote] = None
        self.hub_pay_to = ""
        self.shards: Dict[str, Shard] = {}
        self.routed = self.fee_units = self.fee_paid = self.signed = 0
        self.pending: dict = {}
        self.given_up: list = []          # recent voided locks: {cum, after: (routed, units, paid)}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self.events: list = []
        self.stats = {"locks": 0, "floor_locks": 0, "voided": 0, "via_provider": 0, "refused": {}}

    # --- setup -------------------------------------------------------------------------------------
    def _refresh_quote(self, routing: dict):
        q = FeeQuote.from_dict(routing.get("quote"))
        if q.hub != self.hub_pay_to or q.network != self.network or not q.verify() or not q.live(time.time()):
            raise ChannelError("route_fee", "hub fee quote not signed by the hub's payTo, or not live")
        if q.feePpm > self.max_fee_ppm or q.feeBaseMsat > self.max_fee_base_msat:
            raise ChannelError("route_fee", f"hub fee {q.feeBaseMsat} msat + {q.feePpm} ppm above our caps")
        self.quote = q

    def open(self) -> dict:
        """Open ch1 to the hub from its 402 (x402 v2, xbt-channel, extra.routing)."""
        st, rh, _ = self.http("GET", self.hub_url + HUB_ROUTE_PATH)
        if st != 402:
            raise ChannelError("bad_offer", f"hub answered {st}, expected 402")
        acc = self.cc._pick(unb64json(rh["PAYMENT-REQUIRED"]))
        self.hub_pay_to = acc["payTo"]
        self._refresh_quote(acc["extra"].get("routing") or {})
        self.ch = self.cc._open(self.hub_url, acc)
        self.cc.channels[self.hub_url] = self.ch
        return {"chan": self.ch.payer.params.channel_id, "capacity": self.ch.payer.params.capacity,
                "expiry": self.ch.payer.params.expiry}

    def refresh_hub(self):
        st, rh, _ = self.http("GET", self.hub_url + HUB_ROUTE_PATH)
        acc = self.cc._pick(unb64json(rh["PAYMENT-REQUIRED"]))
        if acc["payTo"] != self.hub_pay_to:
            raise ChannelError("bad_offer", "the hub's payTo changed")
        self._refresh_quote(acc["extra"].get("routing") or {})

    def shard(self, url: str, method: str = "POST") -> Shard:
        """Start a metered session on a routed path: verify the provider's signed price quote and
        first invoice (the hub never touches either)."""
        c = secrets.randbelow(ecc.N - 1) + 1
        st, rh, out = self.http(method, url, b"", {"ROUTE-CLIENT": ecc.pubkey(c).hex()})
        if st != 402:
            raise ChannelError("bad_offer", f"expected a 402 with extra.route, got {st}")
        acc = self.cc._pick(unb64json(rh["PAYMENT-REQUIRED"]))
        rt = acc["extra"].get("route") or {}
        pay_to = acc["payTo"]
        q = PriceQuote(**rt["quote"])
        inv = Invoice.from_dict(rt["invoice"])
        if q.payTo != pay_to or q.network != self.network or not q.verify():
            raise ChannelError("bad_offer", "price quote not signed by the provider's payTo")
        if inv.payTo != pay_to or inv.session != rt["session"] or not inv.verify():
            raise ChannelError("bad_invoice", "invoice not signed by the provider's payTo")
        if inv.hubs != "any" and self.hub_pay_to not in inv.hubs:
            raise ChannelError("route_blocked", "the provider does not take locks from our hub")
        origin = "/".join(url.split("/")[:3])
        sh = Shard(url, origin, "/" + "/".join(url.split("/")[3:]), pay_to, rt["session"],
                   session_key(c, bytes.fromhex(pay_to)), q, asdict(inv), float(rt["window"]), float(rt["lockWait"]))
        self.shards[url] = sh
        return sh

    # --- data path ---------------------------------------------------------------------------------
    def call(self, sh: Shard, method: str = "POST", body: bytes = b""):
        """One metered call straight to the provider. Returns (status, headers, body); a 402 with
        error route_credit means the provider stopped serving us (its credit window ran out)."""
        with sh.lock:
            sh.seq += 1
            seq = sh.seq
        hdr = b64json({"session": sh.session, "seq": seq,
                       "auth": call_auth(sh.key, sh.session, seq, request_digest(method, sh.path, body))})
        t0 = time.perf_counter()
        st, rh, out = self.http(method, sh.url, body, {"ROUTE-AUTH": hdr})
        sh.call_ms.append((time.perf_counter() - t0) * 1000)
        state = None
        if "ROUTE-STATE" in rh:
            state = unb64json(rh["ROUTE-STATE"])
        elif st == 402:
            try:
                doc = json.loads(out)
                state = doc.get("routeState")
                sh.stopped = doc.get("error") or "refused"
            except ValueError:
                sh.stopped = "refused"
        if state is not None:
            self._apply_state(sh, state)
        if st < 400:
            sh.calls += 1
        return st, rh, out

    def _apply_state(self, sh: Shard, state: dict):
        if not state_verify(sh.pay_to, state) or state.get("session") != sh.session:
            raise ChannelError("bad_receipt", "ROUTE-STATE not signed by the provider for this session")
        charge = int(state.get("chargeAmsat", 0))
        if sh.quote.amsatPerCall and charge > sh.quote.amsatPerCall:
            raise ChannelError("bad_receipt", "charged above the signed price quote")
        with sh.lock:
            sh.seen_amsat += charge
            sh.accrued_amsat = max(sh.accrued_amsat, int(state["accruedAmsat"]))
            sh.paid_sat = max(sh.paid_sat, int(state["paidSat"]))
            inv = state.get("invoice") or {}
            if inv.get("lockId") and inv["lockId"] != sh.invoice.get("lockId"):
                i = Invoice.from_dict(inv)
                if i.verify() and i.payTo == sh.pay_to and i.session == sh.session:
                    sh.invoice = inv
            if state.get("lastLock"):
                sh.last_lock = state["lastLock"]
        self._check_pending(from_shard=sh)

    # --- locks (serial on ch1) ---------------------------------------------------------------------
    def _commit(self, p: dict, t_hex: str, via: str):
        sh = p["shard"]
        self.routed += p["d"] + p["f"]
        self.fee_units, self.fee_paid = p["units"], self.fee_paid + p["f"]
        self.signed = max(self.signed, p["cum"])
        with sh.lock:
            sh.locked_sat += p["d"]
            sh.lock_ms.append((time.perf_counter() - p["t0"]) * 1000)
        self.stats["locks"] += 1
        if p["floor"]:
            self.stats["floor_locks"] += 1
        if via == "provider":
            self.stats["via_provider"] += 1
        self.events.append({"event": "lock", "provider": sh.origin, "lockId": p["lockId"], "amount": p["d"],
                            "fee": p["f"], "cum1": p["cum"], "via": via, "t": t_hex[:16]})

    def _check_pending(self, from_shard: Shard = None):
        with self._lock:
            p = self.pending
            if not p:
                return
            sh = p["shard"]
            if from_shard is not None and from_shard is not sh:
                return
            ll = sh.last_lock or {}
            if ll.get("lockId") == p["lockId"]:
                # the provider was paid for this lock: its t is our receipt even if the hub keeps t + r
                t = int(ll["secret"], 16)
                if adaptor.point_of(t) != adaptor.dec(p["T"]):
                    return
                if not p["floor"]:
                    self.signer.resolve_lock(self.chan, f"{t:064x}")
                self.pending = {}
                self._commit(p, f"{t:064x}", "provider")
            elif time.time() > p["until"] and not p.get("inflight"):
                # never while our request is out: the hub may still complete it
                self._void(p, "invoice expired unanswered")

    def _void(self, p: dict, why: str):
        if not p["floor"]:
            self.signer.void_lock(self.chan)
            self.given_up = (self.given_up + [{"cum": p["cum"], "lockId": p["lockId"], "d": p["d"], "f": p["f"],
                                               "after": (self.routed + p["d"] + p["f"], p["units"],
                                                         self.fee_paid + p["f"])}])[-16:]
        self.pending = {}
        self.stats["voided"] += 1
        self.events.append({"event": "void", "provider": p["shard"].origin, "lockId": p["lockId"], "amount": p["d"],
                            "why": why})

    def _resync(self, doc: dict) -> bool:
        """The hub completed a lock we had given up (it read t off the provider's ch2 close). Adopt
        its view only if its best state is one of those locks, with the counters it implied."""
        try:
            best = int(doc["bestCum"])
            view = (int(doc["routedSat"]), int(doc["feeUnits"]), int(doc["feePaid"]))
        except (KeyError, TypeError, ValueError):
            return False
        g = next((g for g in self.given_up if g["cum"] == best and tuple(g["after"]) == view), None)
        if g is None or best <= self.signed:
            return False
        self.signer.adopt_lock(self.chan, best)
        self.routed, self.fee_units, self.fee_paid = view
        self.signed = best
        self.given_up = [x for x in self.given_up if x is not g]
        self.events.append({"event": "resync", "lockId": g["lockId"], "cum1": best})
        return True

    @property
    def chan(self) -> str:
        return self.ch.payer.params.channel_id

    def lock(self, sh: Shard) -> Optional[dict]:
        """Pay `sh`'s accrued amount through the hub with one adaptor lock. None if nothing is due
        or a lock is still pending on ch1."""
        with self._lock:
            self._check_pending()
            if self.pending:
                return None
            d = sh.due_sat()
            inv = dict(sh.invoice)
            # the hub may wait revealTimeoutSec for the provider: lock only with that much invoice left
            if d < 1 or float(inv["validUntil"]) < time.time() + 1.0 + self.quote.revealTimeoutSec:
                return None
            d = min(d, self.max_lock_sat, self.quote.maxLockSat)
            if not self.quote.live(time.time() + 30):
                self.refresh_hub()
            q = self.quote
            f, units = fee_due(q, d, self.fee_units, self.fee_paid)
            cum = next_cum(self.routed, d + f, self.ch.payer.params.min_amount)
            floor = cum <= self.signed
            p = {"shard": sh, "lockId": inv["lockId"], "d": d, "f": f, "units": units, "cum": max(cum, self.signed),
                 "floor": floor, "T": inv["point"], "until": float(inv["validUntil"]) + self.void_grace,
                 "t0": time.perf_counter()}
            route = {"provider": sh.origin, "payTo": sh.pay_to, "network": self.network, "amount": d,
                     "point": inv["point"], "fee": f, "feeQuote": asdict(q), "invoice": inv,
                     "session": sh.session, "lockId": inv["lockId"],
                     "lockAuth": lock_auth(sh.key, sh.session, inv["lockId"], d, inv["point"], self.hub_pay_to)}
            if floor:
                route["tweak"] = "00" * 32
                pl = {"chan": self.chan, "seq": 0, "cum": str(self.signed)}
            else:
                sa = self.signer.sign_state_adaptor(self.chan, cum, inv["point"], route={
                    "hub": self.hub_url, "provider": sh.origin, "lockId": inv["lockId"], "amount": d, "fee": f})
                route["tweak"] = sa["tweak"]
                p["T1"] = sa["point"]
                pl = {"chan": self.chan, "seq": 0, "cum": str(cum), "adaptor": sa["adaptor"], "point": sa["point"]}
            p["inflight"] = True
            self.pending = p
            body = json.dumps({"route": route}).encode()
            self.ch.seq += 1
            pl["seq"] = self.ch.seq
            self.cc._auth(self.ch, pl, "POST", HUB_ROUTE_PATH, body)
        try:
            st, _, raw = self.http("POST", self.hub_url + HUB_ROUTE_PATH, body,
                                   {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": self.ch.accepted,
                                                                  "payload": pl}),
                                    "Content-Type": "application/json"})
            doc = json.loads(raw)
        except (OSError, ValueError):
            st, doc = 0, {}
        with self._lock:
            p["inflight"] = False
            if self.pending is not p:
                return {"status": "resolved_elsewhere"}
            if st == 200 and isinstance(doc, dict) and doc.get("secret"):
                y = int(doc["secret"], 16) % adaptor.N
                if floor:
                    if adaptor.point_of(y) != adaptor.dec(p["T"]):
                        return {"status": "pending", "why": "bad secret"}
                    t = f"{y:064x}"
                else:
                    # the answer must open OUR T1: a hub replaying its answer to an earlier attempt at
                    # this invoice (whose lock we gave up) is refused here, and resynced on the next lock
                    if doc.get("lockId") != p["lockId"] or adaptor.point_of(y) != adaptor.dec(p["T1"]):
                        self._void(p, "hub answer does not open this lock")
                        self.events.append({"event": "stale_answer", "lockId": p["lockId"], "cum1": doc.get("cum")})
                        return {"status": "refused", "error": "stale_answer"}
                    t = self.signer.resolve_lock(self.chan, doc["secret"])
                self.pending = {}
                self._commit(p, t, "hub")
                return {"status": "paid", "amount": d, "fee": f, "lockId": p["lockId"]}
            code = doc.get("error") if isinstance(doc, dict) else None
            if code == "bad_amount" and self._resync(doc):
                self._void(p, "hub: resynced")
                return {"status": "resynced"}
            if st in (400, 401, 402, 502) and isinstance(code, str):
                # the hub refused (or the provider did, through it): nothing was completed with t
                self.stats["refused"][code] = self.stats["refused"].get(code, 0) + 1
                self._void(p, f"hub: {code}")
                return {"status": "refused", "error": code}
            return {"status": "pending", "http": st}

    # --- background locking ------------------------------------------------------------------------
    def tick(self):
        for sh in list(self.shards.values()):
            if self._stop.is_set():
                return
            try:
                self.lock(sh)
            except ChannelError as e:
                self.events.append({"event": "lock_error", "provider": sh.origin, "error": e.code})

    def start(self, interval: float = None):
        interval = interval or min([s.window for s in self.shards.values()] or [1.0])

        def loop():
            nxt = time.time()
            while not self._stop.is_set():
                nxt += interval
                self.tick()
                self._stop.wait(max(0.0, nxt - time.time()))
        self._stop.clear()
        self._thread = threading.Thread(target=loop, daemon=True, name="route-payer")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def close(self) -> dict:
        """Cooperative close of ch1: the hub closes with the best state it holds (every completed
        lock is already a plain state there, so no final state is needed)."""
        return self.cc._post(self.hub_url + self.ch.accepted["extra"]["closeUrl"],
                             {"chan": self.chan, "sig": self.signer.sign_close(self.chan)})

    def summary(self) -> dict:
        return {"chan": self.chan if self.ch else None, "routed_sat": self.routed, "fee_paid_sat": self.fee_paid,
                "signed": self.signed, **self.stats,
                "shards": {u: {"accrued_amsat": s.accrued_amsat, "seen_amsat": s.seen_amsat, "paid_sat": s.paid_sat,
                               "locked_sat": s.locked_sat, "calls": s.calls, "stopped": s.stopped}
                           for u, s in self.shards.items()}}
