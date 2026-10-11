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

from . import adaptor, ecc, x402_channel
from .channel import ChannelError
from .route import (AMSAT_PER_SAT, HUB_ROUTE_PATH, HUB_VIEW_PATH, FeeQuote, Invoice, PriceQuote, call_auth, ceil_div, fee_due,
                    lock_auth, next_cum, session_key, state_verify)
from .signer import ChannelSigner
from .x402_channel import XbtChannelClient, b64json, request_digest_v2, same_origin_url, unb64json


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
    last_locked: str = ""       # lockId of the last lock we completed: an invoice is paid once
    stopped: str = ""
    call_ms: list = field(default_factory=list)
    lock_ms: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def due_sat(self) -> int:
        return ceil_div(self.accrued_amsat, AMSAT_PER_SAT) - max(self.paid_sat, self.locked_sat)


class _BindOnce:
    """The signer as ch1's open sees it (AGP-094): `attach` binds a channel to its key only if it is
    not bound yet (a signer that has the channel signs its refund). An open that failed between the
    two (the binding done, the refund not signed) is then finished by the next one; before, the next
    one attached again and the signer, its issued key used up, refused it for good. Everything else
    is the signer's own."""

    def __init__(self, signer):
        self._signer = signer

    def __getattr__(self, name):
        if name == "_signer":                       # (not set yet: a copy being built)
            raise AttributeError(name)
        return getattr(self._signer, name)

    def attach(self, origin: str, params) -> str:
        try:
            self._signer.sign_refund(params.channel_id)
            return params.channel_id
        except Exception:  # noqa: BLE001 - not bound yet
            return self._signer.attach(origin, params)


class RoutePayer:
    def __init__(self, hub_url: str, network: str, height: Callable[[], int], fund: Callable = None, signer=None, *,
                 capacity: int = 200_000, expiry_blocks: int = 8_000, max_fee_ppm: int = 10_000,
                 max_fee_base_msat: int = 10_000, max_lock_sat: int = 50_000, void_grace: float = 1.0,
                 http: Callable = None, max_held_locks: int = 2, held_probe_secs: float = 5.0):
        """What the client believes of its hub (AGP-088). A hub that says one of our given-up locks was
        COMPLETED proves it: the view carries the t + r that opens that lock's own point, which only its
        completion yields. A hub that says a given-up lock is HELD (its ch2 pre-signature is out, so it
        stays in ch1's base) cannot prove it, and each hold we adopt raises what our next lock signs by
        that lock. So at most `max_held_locks` are adopted at a time, and at that many nothing more is
        pre-signed until one resolves: the client only asks the hub for its view (at most every
        `held_probe_secs`). The trust that remains: a hub that lies about holds gets us to sign
        max_held_locks - 1 locks (each at most max_lock_sat plus its fee) above what we owe; with
        max_held_locks 1, none, and one refusing provider then pauses our payments to the others until
        its ch2 resolves. 0: no hold is ever adopted."""
        self.hub_url = x402_channel.no_fragment(hub_url.rstrip("/"))    # every lock is bound to hub_url + /x402/route (AGP-081)
        self.network = network
        self.signer = signer or ChannelSigner(fund=fund)
        self.cc = XbtChannelClient(network, fund, height, capacity=capacity, expiry_blocks=expiry_blocks,
                                   max_price=10 ** 12, signer=_BindOnce(self.signer), budget_sats=10 ** 12)
        if http:
            self.cc.http = http
        self.http = self.cc.http
        self.max_fee_ppm, self.max_fee_base_msat, self.max_lock_sat = max_fee_ppm, max_fee_base_msat, max_lock_sat
        self.void_grace = void_grace
        self.max_held_locks, self.held_probe_secs = int(max_held_locks), float(held_probe_secs)
        self._probe_at = 0.0        # when the hub may next be asked for its view (at max_held_locks)
        self.ch = None
        self.quote: Optional[FeeQuote] = None
        self.hub_pay_to = ""
        self.shards: Dict[str, Shard] = {}
        self.routed = self.fee_units = self.fee_paid = self.signed = 0
        self.pending: dict = {}
        # recent voided locks: {cum, lockId, before/after: (routed, units, paid), floor, held}; `held`: the
        # hub keeps it in ch1's base until its ch2 resolves (AGP-064), our counters are its `after`
        self.given_up: list = []
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
        """Open ch1 to the hub from its 402 (x402 v2, xbt-channel, extra.routing). Returns {chan,
        capacity, expiry} (and `resumed` when ch1 was on the books already).

        AGP-094 rule (the library client's, AGP-090): ch1 is funded once. Its key is on the books
        before the wallet is asked, its outpoint before the hub hears of it, and every open goes on
        from the stage the last one reached (XbtChannelClient._ensure_open: keyed, funded, open): no
        second key is asked for and no second funding sent while the first is unresolved, whatever the
        hub or the wallet answered. A hub that has the channel already says duplicate_channel, which is
        the yes that was lost. The books are this RoutePayer's (it has no ledger). A ch1 recorded and
        never funded that is too near its expiry is set aside and derived again for the same key by
        the same call, as the library client's (AGP-096; the sentence here said "refused
        open_unresolved until `forget_unfunded`", which the shared function no longer does)."""
        st, rh, _ = self.http("GET", self.hub_url + HUB_ROUTE_PATH)
        if st != 402:
            raise ChannelError("bad_offer", f"hub answered {st}, expected 402")
        acc = self.cc._pick(unb64json(rh["PAYMENT-REQUIRED"]))
        rec = self.cc.channels.get(self.hub_url)
        if rec is not None and rec.accepted.get("payTo") != acc["payTo"]:
            # the ch1 on the books pays the hub it was keyed for: never opened under another key's quote
            raise ChannelError("bad_offer", "the hub's payTo changed since ch1 was recorded")
        self.hub_pay_to = acc["payTo"]
        self._refresh_quote(acc["extra"].get("routing") or {})
        self.ch = self.cc._open(self.hub_url, acc)
        self.cc.channels[self.hub_url] = self.ch
        return {"chan": self.ch.payer.params.channel_id, "capacity": self.ch.payer.params.capacity,
                "expiry": self.ch.payer.params.expiry, **({"resumed": True} if rec is not None else {})}

    def forget_unfunded(self) -> bool:
        """Drop a ch1 that was recorded and never funded, and the earlier scripts kept for it (their
        keys go with them). Call it only when the wallet shows no send to their scripts. Nothing needs
        it to go on paying (AGP-096): it only tidies the book. True if one was dropped."""
        return self.cc.forget_unfunded(self.hub_url) > 0

    def refresh_hub(self):
        st, rh, _ = self.http("GET", self.hub_url + HUB_ROUTE_PATH)
        acc = self.cc._pick(unb64json(rh["PAYMENT-REQUIRED"]))
        if acc["payTo"] != self.hub_pay_to:
            raise ChannelError("bad_offer", "the hub's payTo changed")
        self._refresh_quote(acc["extra"].get("routing") or {})

    def shard(self, url: str, method: str = "POST") -> Shard:
        """Start a metered session on a routed path: verify the provider's signed price quote and
        first invoice (the hub never touches either)."""
        x402_channel.no_fragment(url)
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
        x402_channel.no_fragment(sh.url)              # before the call is numbered: ROUTE-AUTH binds sh.url
        with sh.lock:
            sh.seq += 1
            seq = sh.seq
        hdr = b64json({"session": sh.session, "seq": seq,
                       "auth": call_auth(sh.key, sh.session, seq, request_digest_v2(method, sh.url, body))})
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
            sh.last_locked = p["lockId"]
            sh.lock_ms.append((time.perf_counter() - p["t0"]) * 1000)
        self.stats["locks"] += 1
        if p["floor"]:
            self.stats["floor_locks"] += 1
        if via == "provider":
            self.stats["via_provider"] += 1
        self.events.append({"event": "lock", "provider": sh.origin, "lockId": p["lockId"], "amount": p["d"],
                            "fee": p["f"], "cum1": p["cum"], "via": via, "t": t_hex[:16]})

    def _via_provider(self, p: dict) -> bool:
        """Under self._lock: the provider's signed ROUTE-STATE says this lock was paid: its t is our
        receipt even if the hub keeps t + r. Resolves the lock and returns True."""
        ll = p["shard"].last_lock or {}
        if ll.get("lockId") != p["lockId"]:
            return False
        t = int(ll["secret"], 16)
        if adaptor.point_of(t) != adaptor.dec(p["T"]):
            return False
        if not p["floor"]:
            self.signer.resolve_lock(self.chan, f"{t:064x}")
        self.pending = {}
        self._commit(p, f"{t:064x}", "provider")
        return True

    def _check_pending(self, from_shard: Shard = None):
        with self._lock:
            p = self.pending
            if not p:
                return
            sh = p["shard"]
            if from_shard is not None and (from_shard is not sh or p.get("inflight")):
                # a data call never resolves a lock whose POST is still out (AGP-054): the hub's answer
                # is on its way and settles it off the data path (a signer's write-ahead is fsyncs); a
                # lost or refused answer leaves it to the next check, which reads the provider's t
                return
            if self._via_provider(p):
                return
            if time.time() > p["until"] and not p.get("inflight"):
                # never while our request is out: the hub may still complete it
                self._void(p, "invoice expired unanswered")

    def _void(self, p: dict, why: str):
        if not p["floor"]:
            self.signer.void_lock(self.chan)
        # T1 (AGP-088): the lock's own point, which a hub's claim that it completed the lock must open
        self.given_up.append({"cum": p["cum"], "lockId": p["lockId"], "d": p["d"], "f": p["f"], "floor": p["floor"],
                              "held": False, "T1": p.get("T1", ""), "before": (self.routed, self.fee_units, self.fee_paid),
                              "after": (self.routed + p["d"] + p["f"], p["units"], self.fee_paid + p["f"])})
        if len(self.given_up) > 16:
            # a held lock is kept until its release or completion: without it a release could not be adopted
            i = next((i for i, g in enumerate(self.given_up) if not g.get("held")), 0)
            del self.given_up[i]
        self.pending = {}
        self.stats["voided"] += 1
        self.events.append({"event": "void", "provider": p["shard"].origin, "lockId": p["lockId"], "amount": p["d"],
                            "why": why})

    def _resync(self, doc: dict) -> bool:
        """Adopt a hub view of ch1: the completions it proves of held locks below its best state
        (`_drop_completed`), then the view itself (`_resync_view`). True if anything was adopted."""
        done = self._drop_completed(doc)
        return self._resync_view(doc) or done

    def _drop_completed(self, doc: dict) -> bool:
        """AGP-094: a held lock the hub completed BELOW its best state is in none of the view's other
        lists. The view names it under `completed` with the t + r that completed it: with that proof (it
        opens the lock's own T1, as for a completion at the best state) the lock stops counting as held.
        Nothing else moves: its amount was in both bases since the hold. Without the proof it stays
        held, so a hub cannot empty the client's max_held_locks by its word."""
        try:
            best = int(doc["bestCum"])
        except (KeyError, TypeError, ValueError):
            return False
        done = [x for x in (doc.get("completed") if isinstance(doc.get("completed"), list) else []) if isinstance(x, dict)]
        held_now = doc.get("held") if isinstance(doc.get("held"), list) else []

        def proved(g) -> bool:
            for x in done:
                if x.get("lockId") != g["lockId"]:
                    continue
                try:
                    y = int(x["secret"], 16) % adaptor.N
                    if y and adaptor.point_of(y) == adaptor.dec(g["T1"]):
                        return True
                except (KeyError, TypeError, ValueError):
                    pass
            return False
        # (one completed AT the best state above ours is adopted by _resync_view, with the state itself)
        gone = [g for g in self.given_up if g.get("held") and not g.get("floor") and g.get("T1")
                and not (g["cum"] == best and best > self.signed) and g["lockId"] not in held_now and proved(g)]
        if not gone:
            return False
        self.given_up = [x for x in self.given_up if not any(x is g for g in gone)]
        self._probe_at = 0.0
        self.events.append({"event": "resync_completed", "lockIds": [g["lockId"] for g in gone]})
        return True

    def _resync_view(self, doc: dict) -> bool:
        """Adopt a hub view of ch1 ({bestCum, routedSat, feeUnits, feePaid, held, released}) only when it
        is one of our given-up locks, at the counters it implied:
          completed: the hub read t off the provider's ch2 close; its best state is that lock;
          held (AGP-064): its ch2 pre-signature may be out, so the hub keeps it in the base until that
            ch2 resolves; our counters become its `after`, our signed state stays;
          released: its ch2 resolved unpaid; the hold leaves our counters, so our next locks are quoted
            below our signed state (the dust floor) until what we paid ahead for it is used.
        AGP-085: a release may come in the same view as a completion or a hold; see `gone` below.
        AGP-088: a completion is adopted only with its proof (the view's `secret` opens that lock's T1),
        and a hold only while fewer than max_held_locks are held (see __init__)."""
        try:
            best = int(doc["bestCum"])
            hub = (int(doc["routedSat"]), int(doc["feeUnits"]), int(doc["feePaid"]))
        except (KeyError, TypeError, ValueError):
            return False
        ours = (self.routed, self.fee_units, self.fee_paid)

        def listed(k: str, lid: str) -> bool:
            v = doc.get(k)
            return isinstance(v, list) and lid in v

        # AGP-085: held locks the hub lists as released, and what they take out of the counters. A view
        # may show a release together with a completion or a new hold (the hub released while that lock
        # was in flight), so each case below is also tried with the released holds taken out
        gone = [g for g in self.given_up if g.get("held") and listed("released", g["lockId"])]

        def less(v, skip=None) -> tuple:
            v = list(v)
            for x in gone:
                if x is not skip:
                    for i in range(3):
                        v[i] = max(0, v[i] - max(0, x["after"][i] - x["before"][i]))
            return tuple(v)

        def drop(*gs):
            self.given_up = [x for x in self.given_up if not any(x is g for g in gs)]

        def opens(g) -> bool:
            # only the lock's completion gives the hub t + r (a lock from before has no point kept)
            if not g.get("T1"):
                return True
            try:
                y = int(doc["secret"], 16) % adaptor.N
                return bool(y) and adaptor.point_of(y) == adaptor.dec(g["T1"])
            except (KeyError, TypeError, ValueError):
                return False

        if best > self.signed:
            for g in (g for g in self.given_up if not g.get("floor") and g["cum"] == best):
                if not opens(g):
                    continue
                rel = [x for x in gone if x is not g]
                if tuple(g["after"]) == hub or (g.get("held") and hub == ours):
                    rel = []
                elif not rel or not (less(g["after"], g) == hub or (g.get("held") and less(ours, g) == hub)):
                    continue
                self.signer.adopt_lock(self.chan, best)
                self.routed, self.fee_units, self.fee_paid = hub
                self.signed = best
                drop(g, *rel)
                self.events.append({"event": "resync", "lockId": g["lockId"], "cum1": best})
                if rel:
                    self.events.append({"event": "resync_release", "lockIds": [x["lockId"] for x in rel], "routedSat": hub[0]})
                return True
            return False
        if best != self.signed or hub == ours:
            return False
        if gone and less(ours) == hub:
            self.routed, self.fee_units, self.fee_paid = hub
            drop(*gone)
            self.events.append({"event": "resync_release", "lockIds": [g["lockId"] for g in gone], "routedSat": hub[0]})
            return True

        def adds(g) -> tuple:
            return tuple(g["after"][i] - g["before"][i] for i in range(3))
        g = next((g for g in self.given_up if not g.get("held") and tuple(g.get("before") or ()) == ours
                  and tuple(g["after"]) == hub and listed("held", g["lockId"])), None)
        rel = []
        if g is None and gone:
            # a hold on top of a release: the hub holds this lock by what it adds, on a base the
            # released holds have left
            base = less(ours)
            g = next((g for g in self.given_up if not g.get("held") and tuple(g.get("before") or ()) == ours
                      and tuple(base[i] + adds(g)[i] for i in range(3)) == hub and listed("held", g["lockId"])), None)
            rel = gone
        if g is None:
            return False
        # the hub's word is all there is for a hold: no more than max_held_locks at a time
        if sum(1 for x in self.given_up if x.get("held") and not any(x is r for r in rel)) >= self.max_held_locks:
            self.events.append({"event": "hold_not_adopted", "lockId": g["lockId"], "max": self.max_held_locks})
            return False
        self._probe_at = 0.0
        if rel:
            # as if the release had been adopted first: the lock was given up on the base without them
            g["before"], g["after"] = less(ours), hub
            drop(*rel)
            self.events.append({"event": "resync_release", "lockIds": [x["lockId"] for x in rel], "routedSat": less(ours)[0]})
        g["held"] = True
        self.routed, self.fee_units, self.fee_paid = hub
        self.events.append({"event": "resync_hold", "lockId": g["lockId"], "routedSat": hub[0]})
        return True

    @property
    def chan(self) -> str:
        return self.ch.payer.params.channel_id

    def lock(self, sh: Shard) -> Optional[dict]:
        """Pay `sh`'s accrued amount through the hub with one adaptor lock. None if nothing is due
        or a lock is still pending on ch1."""
        with self._lock:
            self._check_pending()
            if self.pending or self.ch is None or self.ch.stage != "open":
                # (AGP-094: a ch1 the hub has not opened yet signs nothing)
                return None
            if 0 < self.max_held_locks <= sum(1 for g in self.given_up if g.get("held")):
                # AGP-088: nothing more is pre-signed above that many holds; a release or a completion
                # of one of them is learnt from the hub's view
                return {"status": "resynced"} if self._probe_view() else None
            d = sh.due_sat()
            inv = dict(sh.invoice)
            # the hub may wait revealTimeoutSec for the provider: lock only with that much invoice left;
            # and never an invoice already paid (wait for the fresh one in the next ROUTE-STATE). A
            # ROUTE-STATE produced before that lock completed can still carry its invoice; locking it
            # again would be answered with the hub's saved answer, which a floor lock (no T1 to check)
            # would count twice (AGP-026 / AGP-033).
            paid_already = inv.get("lockId") and inv["lockId"] == sh.last_locked
            if (d < 1 or float(inv["validUntil"]) < time.time() + 1.0 + self.quote.revealTimeoutSec
                    or paid_already):
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
            self.cc._auth(self.ch, pl, "POST", self.hub_url + HUB_ROUTE_PATH, body)
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
                        return {"status": "refused", "error": "stale_answer",
                                "detail": "hub answer does not open this lock"}
                    t = self.signer.resolve_lock(self.chan, doc["secret"])
                self.pending = {}
                self._commit(p, t, "hub")
                return {"status": "paid", "amount": d, "fee": f, "lockId": p["lockId"]}
            code = doc.get("error") if isinstance(doc, dict) else None
            if code == "bad_amount" and self._resync(doc):
                self._void(p, "hub: resynced")
                return {"status": "resynced"}
            if st in (400, 401, 402, 502) and isinstance(code, str):
                # the hub refused (or the provider did, through it): nothing was completed with t,
                # unless the provider's signed ROUTE-STATE already says it was paid
                if self._via_provider(p):
                    return {"status": "paid", "amount": d, "fee": f, "lockId": p["lockId"], "via": "provider"}
                self.stats["refused"][code] = self.stats["refused"].get(code, 0) + 1
                self._void(p, f"hub: {code}")
                if "held" in doc:
                    self._resync(doc)       # AGP-064: the hub keeps this lock in ch1's base until its ch2 resolves
                # the hub's reason, as the Rust RoutePayer returns it (AGP-056): free text, for logs
                detail = doc.get("detail")
                return {"status": "refused", "error": code, "detail": detail if isinstance(detail, str) else ""}
            return {"status": "pending", "http": st}

    def _probe_view(self) -> bool:
        """Under self._lock (AGP-088): ask the hub for its view of ch1 (POST /x402/route/view) and adopt
        it, without signing a state. True if the view was adopted (a release, or a completion with its
        proof). At most once every held_probe_secs, the first right after a hold was adopted."""
        if time.time() < self._probe_at or self.ch is None:
            return False
        self._probe_at = time.time() + self.held_probe_secs
        self.ch.seq += 1
        pl = {"chan": self.chan, "seq": self.ch.seq, "cum": str(self.signed)}
        self.cc._auth(self.ch, pl, "POST", self.hub_url + HUB_VIEW_PATH, b"")
        try:
            st, _, raw = self.http("POST", self.hub_url + HUB_VIEW_PATH, b"",
                                   {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": self.ch.accepted, "payload": pl})})
            doc = json.loads(raw)
        except (OSError, ValueError):
            return False
        if st != 200 or not isinstance(doc, dict) or not self._resync(doc):
            return False
        self.events.append({"event": "view_adopted", "routedSat": self.routed, "signed": self.signed})
        return True

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
        return self.cc._post(same_origin_url(self.hub_url, self.ch.accepted["extra"]["closeUrl"]),
                             {"chan": self.chan, "sig": self.signer.sign_close(self.chan)})

    def summary(self) -> dict:
        return {"chan": self.chan if self.ch else None, "routed_sat": self.routed, "fee_paid_sat": self.fee_paid,
                "signed": self.signed, **self.stats,
                "shards": {u: {"accrued_amsat": s.accrued_amsat, "seen_amsat": s.seen_amsat, "paid_sat": s.paid_sat,
                               "locked_sat": s.locked_sat, "calls": s.calls, "stopped": s.stopped}
                           for u, s in self.shards.items()}}
