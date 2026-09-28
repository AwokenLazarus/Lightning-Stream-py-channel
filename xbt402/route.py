"""xbt402 hub routing, shared parts (AGP-021, from the AGP-019 design).

Design note: ~/notes/projects/xbt-agentpay/Research/AGP-019 xbt402 hub routing.md. A routed payment
goes client -> hub -> provider over two ordinary xbt402 channels, ch1 (client pays hub) and ch2 (hub
pays provider), as an adaptor-locked state on each hop (xbt402/adaptor.py):

    provider: t per window, T = t*G in its signed invoice      client: tweak r, T1 = T + r*G
    ch1: client pre-signs cum1 + d + f under T1  ->  hub pre-verifies, then pre-signs ch2 cum2 + d under T
    provider completes ch2 with t (a plain 0x21 state), saves it, returns t
    hub completes ch1 with t + r, returns t + r; the client's receipt is t = (t + r) - r

This module holds what the three roles share:
  * `route_ok`, the expiry rule;
  * `FeeQuote`, the hub's signed, expiring fee quote (no fixed routing fee) and the fee carry;
  * `PriceQuote` and `Invoice`, the provider's signed price and per-window lock point;
  * the session and lock authenticators (a client -> provider key from ECDH, so the hub can relay a
    lock but can neither change its amount nor its target);
  * `RouteSeller`, the provider side: sessions metered in amsat, the optimistic credit window,
    completion of adaptor-locked ch2 states (write-ahead), and a fresh point per window;
  * `find_spend`, used by the hub's watcher to read t off a ch2 close.

Units: amsat = 1e-18 msat (cmp/pricing.py), so 1 sat = 10**21 amsat. Running totals are exact;
whole sats appear only in lock amounts, as the ceil of the running total minus what is already paid.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Optional

from . import adaptor, ecc
from .channel import DUST, SIGHASH_ALL_UNIFIED, ChannelError
from .tx import tagged_hash

AMSAT_PER_SAT = 10 ** 21
AMSAT_PER_MSAT = 10 ** 18
FEE_UNITS_PER_SAT = 10 ** 9            # fee carry unit: 1e-6 msat (feePpm x msat, exact)
ROUTE_LOCK_PATH = "/x402/xbt-channel/lock"
ROLLOVER_PATH = "/x402/xbt-channel/rollover"
TERMS_PATH = "/x402/xbt-channel/terms"
HUB_ROUTE_PATH = "/x402/route"
ROUTE_ERRORS = ("bad_auth", "bad_point", "bad_amount", "bad_adaptor", "route_fee", "route_expiry",
                "lock_outstanding", "bad_secret", "route_failed", "route_blocked", "bad_invoice")


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def route_ok(tip: int, in_expiry: int, out_expiry: int, close_margin: int, delta: int) -> bool:
    """May the hub forward a lock from the channel expiring at `in_expiry` into the one expiring at
    `out_expiry`? An adaptor-locked state has no timeout of its own: the provider can complete and
    close ch2 until ch2's close margin, and its close can confirm as late as `out_expiry`. The hub
    then needs `delta` blocks to learn t and get ch1's close confirmed before ch1's margin."""
    return tip < out_expiry - close_margin and out_expiry + delta <= in_expiry - close_margin


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _sign(secret: int, tag: str, body: dict) -> str:
    return ecc.sign(secret, tagged_hash(tag, _canon(body))).hex()


def _verify(pub_hex: str, tag: str, body: dict, sig_hex: str) -> bool:
    try:
        return bool(ecc.verify(bytes.fromhex(pub_hex), tagged_hash(tag, _canon(body)), bytes.fromhex(sig_hex)))
    except (ValueError, TypeError):
        return False


# --- hub fee quotes ---------------------------------------------------------------------------
@dataclass
class FeeQuote:
    """A hub's signed, expiring routing-fee offer (like cmp's Quote: seq, validUntil, sig). Fee for a
    lock of d sat: feeBaseMsat + d * 1000 * feePpm / 1e6 msat, accrued exactly (1e-6 msat units)
    per ch1 and charged as the ceil of the running total: never rounded per lock."""
    hub: str                      # the hub's payTo (33-byte compressed hex): who signs
    network: str
    feeBaseMsat: int
    feePpm: int
    maxLockSat: int
    maxUnguardedLockSat: int
    minInExpiryDelta: int         # the delta in route_ok
    revealTimeoutSec: int
    seq: int
    issuedAt: int
    validUntil: int
    sig: str = ""

    TAG = "xbt402/route/fee-quote"

    def body(self) -> dict:
        d = asdict(self)
        d.pop("sig")
        return d

    def sign(self, secret: int) -> "FeeQuote":
        self.sig = _sign(secret, self.TAG, self.body())
        return self

    def verify(self) -> bool:
        return _verify(self.hub, self.TAG, self.body(), self.sig)

    def live(self, now: float) -> bool:
        return self.issuedAt <= now + 5 and now <= self.validUntil

    def units(self, d_sat: int) -> int:
        """This lock's fee in 1e-6 msat (exact)."""
        return self.feeBaseMsat * 10 ** 6 + d_sat * 1000 * self.feePpm

    @classmethod
    def from_dict(cls, d: dict) -> "FeeQuote":
        if not isinstance(d, dict):
            raise ChannelError("route_fee", "fee quote must be an object")
        try:
            return cls(**{k: d[k] for k in cls.__dataclass_fields__})
        except (KeyError, TypeError) as e:
            raise ChannelError("route_fee", f"fee quote: {e}")


def fee_due(quote: FeeQuote, d_sat: int, units_total: int, paid_sat: int) -> (int, int):
    """(fee in sat for this lock, new running total in units): the carry at the hub hop."""
    total = units_total + quote.units(d_sat)
    return max(0, ceil_div(total, FEE_UNITS_PER_SAT) - paid_sat), total


# --- provider price quotes and invoices -------------------------------------------------------
@dataclass
class PriceQuote:
    """The provider's signed price for a routed path, verifiable end to end: the client checks it
    against payTo, and every charge in a ROUTE-STATE names the quote it was billed under, so a hub
    in the middle cannot reprice the provider's work."""
    payTo: str
    network: str
    path: str
    amsatPerCall: int             # a flat price per call; a metered path reports `chargeAmsat` per call
    unit: str
    seq: int
    issuedAt: int
    validUntil: int
    sig: str = ""

    TAG = "xbt402/route/price-quote"

    def body(self) -> dict:
        d = asdict(self)
        d.pop("sig")
        return d

    def quote_id(self) -> str:
        return hashlib.sha256(_canon(self.body())).hexdigest()

    def sign(self, secret: int) -> "PriceQuote":
        self.sig = _sign(secret, self.TAG, self.body())
        return self

    def verify(self) -> bool:
        return _verify(self.payTo, self.TAG, self.body(), self.sig)


@dataclass
class Invoice:
    """One window's lock point T = t*G, fresh per window, signed by the provider's payTo."""
    payTo: str
    network: str
    session: str
    lockId: str
    point: str                    # T, compressed hex
    validUntil: float             # the provider completes no lock for this invoice after this
    hubs: object                  # ["<hub payTo>", ...] or "any"
    sig: str = ""

    TAG = "xbt402/route/invoice"

    def body(self) -> dict:
        d = asdict(self)
        d.pop("sig")
        return d

    def sign(self, secret: int) -> "Invoice":
        self.sig = _sign(secret, self.TAG, self.body())
        return self

    def verify(self) -> bool:
        return _verify(self.payTo, self.TAG, self.body(), self.sig)

    @classmethod
    def from_dict(cls, d: dict) -> "Invoice":
        if not isinstance(d, dict):
            raise ChannelError("bad_invoice", "invoice must be an object")
        try:
            return cls(**{k: d[k] for k in cls.__dataclass_fields__})
        except (KeyError, TypeError) as e:
            raise ChannelError("bad_invoice", str(e))


STATE_TAG = "xbt402/route/state"


def state_sign(secret: int, st: dict) -> dict:
    return {**st, "sig": _sign(secret, STATE_TAG, st)}


def state_verify(pay_to: str, st: dict) -> bool:
    body = {k: v for k, v in st.items() if k != "sig"}
    return _verify(pay_to, STATE_TAG, body, st.get("sig", ""))


# --- client <-> provider authenticators ---------------------------------------------------------
def session_key(secret: int, other_pub: bytes) -> bytes:
    """ECDH(client route key, provider payTo): both ends compute it, the hub cannot."""
    return tagged_hash("xbt402/route/session-key", ecc.ecdh(secret, other_pub))


def call_auth(key: bytes, session: str, seq: int, req: str) -> str:
    return hmac.new(key, "|".join(("xbt402/route/call", session, str(seq), req)).encode(), hashlib.sha256).hexdigest()


def lock_auth(key: bytes, session: str, lock_id: str, amount: int, point: str, hub: str) -> str:
    """The client authorises exactly this amount for this invoice via this hub. The provider refuses
    a ch2 lock whose amount or point differs, so the hub can relay but not reprice or redirect."""
    msg = "|".join(("xbt402/route/lock", session, lock_id, str(int(amount)), point.lower(), hub.lower()))
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


# --- provider side ------------------------------------------------------------------------------
@dataclass
class RouteSession:
    session: str
    client_pub: str
    path: str
    created: float
    seq: int = 0
    accrued_amsat: int = 0
    paid_sat: int = 0
    calls: int = 0
    unpaid_since: float = 0.0     # time of the oldest charge not covered by paid_sat (0: none)
    lock_id: str = ""
    t: str = ""                   # current window's secret (hex); never leaves until the lock completes
    point: str = ""
    valid_until: float = 0.0
    last_lock: dict = field(default_factory=dict)   # {lockId, amount, secret}: the client's receipt
    locks: int = 0

    def owed_amsat(self) -> int:
        return self.accrued_amsat - self.paid_sat * AMSAT_PER_SAT


@dataclass
class RouteOffer:
    path: str
    window: float = 1.0           # seconds per lock window
    lock_wait: float = 2.0        # grace after a window for its lock to arrive (configurable)
    invoice_ttl: float = 15.0     # a window's invoice is completed only until then
    hubs: object = "any"
    amsat_per_call: int = 0
    unit: str = "call"
    credit_msat: int = 0          # optional hard cap on unpaid credit (0: time-based only)


class RouteSeller:
    """Provider side of routing, owned by an XbtChannelProvider (`provider.routes`).

    Serving rule (constraint 6): a session is served while its unpaid charges are younger than
    `window + lock_wait` (and under `credit_msat` if set). When the hub stops forwarding, the lock
    never arrives and the provider stops within one window: its loss is at most one window of that
    session's traffic, the client's at most one lock per provider."""

    def __init__(self, provider, path: str = None):
        self.p = provider
        self.offers: Dict[str, RouteOffer] = {}
        self.sessions: Dict[str, RouteSession] = {}
        self.lock = threading.Lock()
        self.path = path
        self._quote_seq = int(time.time())
        self._quotes: Dict[str, PriceQuote] = {}
        if path and os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            self.sessions = {k: RouteSession(**v) for k, v in raw.get("sessions", {}).items()}
        self._keys: Dict[str, bytes] = {}
        self.no_reveal = False        # tests/demo: take locks, never reveal t (a withholding provider)
        self.held: list = []

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"sessions": {k: asdict(v) for k, v in self.sessions.items()}}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    # offers -------------------------------------------------------------------------------------
    def offer(self, path: str, **kw) -> RouteOffer:
        o = RouteOffer(path=path, **kw)
        self.offers[path] = o
        self._quotes.pop(path, None)
        return o

    def price_quote(self, path: str) -> PriceQuote:
        q = self._quotes.get(path)
        now = int(time.time())
        if q is None or q.validUntil - now < 60:
            o = self.offers[path]
            self._quote_seq += 1
            q = PriceQuote(self.p.pay_to, self.p.network, path, int(o.amsat_per_call), o.unit, self._quote_seq,
                           now, now + 3600).sign(self.p.secret)
            self._quotes[path] = q
        return q

    def _key(self, s: RouteSession) -> bytes:
        k = self._keys.get(s.session)
        if k is None:
            k = self._keys[s.session] = session_key(self.p.secret, bytes.fromhex(s.client_pub))
        return k

    def _new_window(self, s: RouteSession):
        """A fresh (t, T) per window."""
        o = self.offers[s.path]
        t = secrets.randbelow(adaptor.N - 1) + 1
        s.t, s.point = f"{t:064x}", adaptor.enc(adaptor.point_of(t)).hex()
        s.lock_id = secrets.token_hex(12)
        s.valid_until = time.time() + o.invoice_ttl

    def invoice(self, s: RouteSession) -> dict:
        o = self.offers[s.path]
        return asdict(Invoice(self.p.pay_to, self.p.network, s.session, s.lock_id, s.point,
                              round(s.valid_until, 3), o.hubs).sign(self.p.secret))

    def open_session(self, path: str, client_pub_hex: str) -> RouteSession:
        pub = bytes.fromhex(client_pub_hex)
        ecc._decode_pub(pub)
        with self.lock:
            s = RouteSession(secrets.token_hex(16), pub.hex(), path, time.time())
            self._new_window(s)
            self.sessions[s.session] = s
            self._save()
        return s

    def route_extra(self, path: str, client_pub_hex: str = "") -> dict:
        """PaymentRequirements.extra.route for a routed path: the offer, the signed price quote and,
        when the request named a client route key (ROUTE-CLIENT), a new session with its first
        invoice."""
        o = self.offers[path]
        out = {"window": o.window, "lockWait": o.lock_wait, "invoiceTtl": o.invoice_ttl, "hubs": o.hubs,
               "creditMsat": str(o.credit_msat), "quote": asdict(self.price_quote(path)),
               "lockUrl": ROUTE_LOCK_PATH, "settleMultiple": self.p.settle_multiple}
        if client_pub_hex:
            s = self.open_session(path, client_pub_hex)
            out["session"] = s.session
            out["invoice"] = self.invoice(s)
        return out

    # metered calls ------------------------------------------------------------------------------
    def _serving(self, s: RouteSession, now: float) -> Optional[str]:
        o = self.offers[s.path]
        if s.owed_amsat() <= 0:
            return None
        if s.unpaid_since and now - s.unpaid_since > o.window + o.lock_wait:
            return "route_credit"
        if o.credit_msat and s.owed_amsat() > o.credit_msat * AMSAT_PER_MSAT:
            return "route_credit"
        return None

    def state(self, s: RouteSession, charge: int = 0) -> dict:
        """ROUTE-STATE: the signed running meter and the open invoice (and the last completed lock's
        t, so the client has its receipt even from a hub that withholds it)."""
        if time.time() > s.valid_until - 1:
            self._new_window(s)       # an expired invoice: nobody can complete it now, issue a fresh T
        body = {"session": s.session, "seq": s.seq, "calls": s.calls, "chargeAmsat": str(charge),
                "accruedAmsat": str(s.accrued_amsat), "paidSat": s.paid_sat,
                "quote": self.price_quote(s.path).quote_id(), "lastLock": s.last_lock,
                "invoice": self.invoice(s)}
        return state_sign(self.p.secret, body)

    def begin_call(self, path: str, hdr: str, method: str, req_path: str, body: bytes):
        """Authenticate a routed call. Returns (session, None) to serve or (session|None, error)."""
        from .x402_channel import request_digest, unb64json
        try:
            h = unb64json(hdr)
            sid, seq, auth = str(h["session"]), int(h["seq"]), str(h["auth"])
        except (ValueError, KeyError, TypeError):
            return None, "bad_payload"
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s.path != path:
                return None, "unknown_session"
            want = call_auth(self._key(s), s.session, seq, request_digest(method, req_path, body))
            if seq <= s.seq or not hmac.compare_digest(want, auth):
                return None, "bad_auth"
            s.seq = seq
            err = self._serving(s, time.time())
            return s, err

    def end_call(self, s: RouteSession, charge_amsat: int) -> dict:
        with self.lock:
            now = time.time()
            if charge_amsat > 0:
                if s.owed_amsat() <= 0:
                    s.unpaid_since = now
                s.accrued_amsat += charge_amsat
            s.calls += 1
            return self.state(s, charge_amsat)

    # adaptor-locked ch2 states (from the hub) ----------------------------------------------------
    def complete_lock(self, st, pl: dict, route: dict) -> dict:
        """Called by the provider with its ledger lock held, after the hub's channel auth passed.
        Checks the lock, completes it with the window's t, saves the plain state write-ahead, and
        only then credits the session and returns t.

        ch2's cumulative amount is `next_cum(routed, d, min_amount)`: the routed total with the
        channel's floor (546-sat dust, plus closeFee when the provider pays its own close, v1.2),
        which the hub pre-pays once per channel and later locks use up. A lock the floor
        already covers needs no new state (and carries no adaptor). A lockId completed before is
        answered again with the same t, so the hub can retry after a lost answer or a crash."""
        try:
            sid, lock_id, amount = str(route["session"]), str(route["lockId"]), int(route["amount"])
            point, auth, hub = str(pl["point"]).lower(), str(route["lockAuth"]), str(route["hub"])
            cum = int(pl["cum"])
        except (KeyError, TypeError, ValueError) as e:
            raise ChannelError("bad_payload", str(e))
        locks = dict((st.extra or {}).get("route_locks") or {})
        with self.lock:
            done = locks.get(lock_id)
            if done:                                         # idempotent: the same answer again
                if done["session"] != sid or done["amount"] != amount:
                    raise ChannelError("bad_invoice", "lockId already completed with other terms")
                return self._lock_answer(st, lock_id, done)
            s = self.sessions.get(sid)
            if s is None:
                raise ChannelError("unknown_session")
            o = self.offers[s.path]
            if lock_id != s.lock_id or point != s.point:
                raise ChannelError("bad_invoice", "not this session's open invoice")
            if time.time() > s.valid_until:
                raise ChannelError("bad_invoice", "invoice expired: a fresh point is in the next ROUTE-STATE")
            if hub != (st.extra or {}).get("hub", ""):
                raise ChannelError("route_blocked", "this channel is not that hub's")
            if o.hubs != "any" and hub not in o.hubs:
                raise ChannelError("route_blocked", "hub not accepted by this provider")
            if not hmac.compare_digest(lock_auth(self._key(s), sid, lock_id, amount, point, hub), auth):
                raise ChannelError("bad_auth", "the client did not authorise this amount for this invoice")
            if amount < 1:
                raise ChannelError("bad_amount", "lock amount must be >= 1 sat")
            if self.no_reveal:
                self.held.append({"lockId": lock_id, "cum": cum, "pre": pl.get("adaptor"), "chan": st.params.channel_id})
                return {"held": lock_id}
            routed = int((st.extra or {}).get("routed_sat", 0))
            need = next_cum(routed, amount, st.params.min_amount)
            if need <= st.best_cum:
                if cum != st.best_cum or pl.get("adaptor"):
                    raise ChannelError("bad_amount", f"the dust floor covers this lock: cum {st.best_cum}, no adaptor")
                sig = b""
            else:
                if cum != need:
                    raise ChannelError("bad_amount", f"lock pays {cum}, expected {need}")
                if cum > st.params.max_amount:
                    raise ChannelError("channel_exhausted")
                try:
                    pre = adaptor.PreSig.from_json(pl["adaptor"])
                except (KeyError, TypeError, ValueError) as e:
                    raise ChannelError("bad_adaptor", str(e))
                z = st.params.sighash(st.params.state_tx(cum))
                if not adaptor.preverify(bytes.fromhex(st.params.payer_pub), z, adaptor.dec(point), pre):
                    raise ChannelError("bad_adaptor", "pre-signature does not verify under the invoice point")
                sig = adaptor.adapt(pre, int(s.t, 16)) + bytes([SIGHASH_ALL_UNIFIED])
                self.p._payee(st).accept(cum, sig)            # an ordinary 0x21 state from here on
            # write-ahead (M8): the plain state and the lock record are on disk before t leaves
            rec = {"session": sid, "amount": amount, "cum": max(cum, st.best_cum), "secret": s.t,
                   "at": round(time.time(), 3)}
            locks[lock_id] = rec
            if sig:
                st.best_cum, st.best_sig = cum, sig.hex()
            st.extra = {**(st.extra or {}), "route_locks": locks, "routed_sat": routed + amount}
            self.p.ledger.save(st)
            s.paid_sat += amount
            s.locks += 1
            s.last_lock = {"lockId": lock_id, "amount": amount, "secret": s.t}
            s.unpaid_since = time.time() if s.owed_amsat() > 0 else 0.0
            self._new_window(s)
            self._save()
            return self._lock_answer(st, lock_id, rec)

    def _lock_answer(self, st, lock_id: str, rec: dict) -> dict:
        s = self.sessions.get(rec["session"])
        return {"lockId": lock_id, "secret": rec["secret"], "cum": str(rec["cum"]), "chan": st.params.channel_id,
                "routedSat": int(st.extra.get("routed_sat", 0)),
                "session": state_sign(self.p.secret, {"session": rec["session"], "lockId": lock_id,
                                                      "amount": rec["amount"],
                                                      "paidSat": s.paid_sat if s else None})}


def next_cum(routed: int, amount: int, floor: int = DUST) -> int:
    """A routed channel's next cumulative state: the routed total plus this lock, floored at the
    channel's least state (`ChannelParams.min_amount`: dust, plus the close fee on a payee-pays
    channel, v1.2)."""
    return max(int(routed) + int(amount), int(floor))


def find_spend(rpc, txid: str, vout: int, from_height: int):
    """The transaction spending txid:vout, from the mempool or blocks at or above `from_height`, as a
    Tx; None if nothing spends it. Needs no txindex (the hub's node may be pruned)."""
    from .tx import Tx
    try:
        r = rpc.gettxspendingprevout([{"txid": txid, "vout": vout}])
        spender = (r[0] if r else {}).get("spendingtxid")
        if spender:
            return Tx.parse(bytes.fromhex(rpc.getrawtransaction(spender, False)))
    except Exception:  # noqa: BLE001 - older node or no mempool entry
        pass
    tip = rpc.getblockcount()
    for h in range(max(0, from_height), tip + 1):
        blk = rpc.getblock(rpc.getblockhash(h), 2)
        for tx in blk.get("tx", []):
            for i in tx.get("vin", []):
                if i.get("txid") == txid and i.get("vout") == vout:
                    return Tx.parse(bytes.fromhex(tx["hex"]))
    return None


def hub_channel_message(chan: str) -> bytes:
    """What a hub's payTo signs to bind a hub-funded ch2 to itself at open."""
    return tagged_hash("xbt402/route/hub-channel", chan.encode())
