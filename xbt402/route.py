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
  * `find_spend`, used by the hub's watcher to read t off a ch2 close;
  * `RouteWal` (AGP-054), the provider's optional write-ahead log of each session's meter.

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
import weakref
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
# POST with a PAYMENT-SIGNATURE on ch1 ({chan, seq, cum, auth}, an empty body): the hub's view of that
# ch1, the one its refusals carry (AGP-088). A client at its cap on held locks asks here instead of
# pre-signing another lock.
HUB_VIEW_PATH = "/x402/route/view"
ROUTE_ERRORS = ("bad_auth", "bad_point", "bad_amount", "bad_adaptor", "route_fee", "route_expiry",
                "lock_outstanding", "bad_secret", "route_failed", "route_blocked", "bad_invoice")


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def canon_origin(origin: str) -> str:
    """A provider origin as the hub keys it (AGP-044, Rust `route::canon_origin`): scheme and host
    lowercased, the default port (:80 for http, :443 for https) and trailing '/'s dropped."""
    o = origin.strip().rstrip("/")
    if "://" not in o:
        return o
    scheme, rest = o.split("://", 1)
    scheme = scheme.lower()
    host, path = (rest.split("/", 1)[0], "/" + rest.split("/", 1)[1]) if "/" in rest else (rest, "")
    host = host.lower()
    if (scheme == "http" and host.endswith(":80")) or (scheme == "https" and host.endswith(":443")):
        host = host[:host.rfind(":")]
    return f"{scheme}://{host}{path}"


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


# --- provider write-ahead log of the route meter (AGP-054) ------------------------------------------
class RouteWal:
    """A routed session's meter (seq, calls, accruedAmsat, unpaid_since) made durable before the
    ROUTE-STATE that carries it leaves, without an fsync on the call's critical path.

    Without it, RouteSeller keeps the meter in memory between saves of its routes file (open, lock),
    so a crash loses what was served since the last lock (the client's signed states run ahead of
    the provider) and rewinds seq (an already-served ROUTE-AUTH is taken again). A caller that needs
    that (cmp's RouteJournal) paid one fdatasync per call after the handler.

    Here every record is a snapshot of one session's meter PROJECTED over its calls in flight
    (`RouteSeller.reserve`: the charge a call is expected to bill, known before it runs), versioned
    by `v`. One writer thread appends whatever is queued and fdatasyncs it (group commit: a record
    waits at most for the fsync in progress plus its own). So the fsync runs while the handler
    computes, and the answer waits only for what is left of it. A call whose charge differs from
    its projection (an error, a 5xx, fewer tokens) writes a corrected snapshot and waits for that.

    Invariants (tests/security/test_agp054_route_wal.py):
      * every ROUTE-STATE that left is covered by a durable snapshot: after a restart, seq, calls
        and accrued are >= what any answer carried. A state carries the session's current meter,
        so it waits for the session's latest snapshot, not only its own call's (RouteSeller._covering);
      * a restart can count more only for calls that were authenticated and not answered (in
        flight at the crash), each at its projected charge: the in-doubt chunk a client already
        accounts for (cmp: MAX_IN_DOUBT per route session); the projection is exact, so it is
        never more than such a call would have billed;
      * a seq is durable before its handler runs, so no ROUTE-AUTH is served twice across a crash.

    Replay (at start): the snapshot with the highest `v` per session wins over the routes file when
    its `v` is above the routes file's `walV` (the version at that file's last save). The file is
    rewritten as one snapshot per session once it passes `compact_bytes`."""

    def __init__(self, path: str, compact_bytes: int = 1 << 20):
        self.path, self.compact_bytes = path, int(compact_bytes)
        self._cv = threading.Condition()
        self._queue: list = []            # (v, line)
        self._durable = 0                 # every v <= this is on disk
        self._failed: list = []           # (lo, hi) v ranges whose write failed
        self._latest: Dict[str, bytes] = {}
        self._fh = None
        self._thread = None
        self.v = 0
        self.fsyncs = 0
        self.error = ""
        for sid, rec in self.read().items():
            self.v = max(self.v, int(rec["v"]))
            self._latest[sid] = self._line(rec)

    @staticmethod
    def _line(rec: dict) -> bytes:
        return (json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n").encode()

    def read(self) -> Dict[str, dict]:
        """The highest-v snapshot per session, from every whole line (a torn last line was never
        acknowledged: its call was never answered)."""
        out: Dict[str, dict] = {}
        if not os.path.exists(self.path):
            return out
        with open(self.path, "rb") as f:
            for raw in f:
                try:
                    r = json.loads(raw)
                    sid, v = str(r["s"]), int(r["v"])
                    rec = {"s": sid, "v": v, "seq": int(r["seq"]), "calls": int(r["calls"]),
                           "acc": str(int(r["acc"])), "us": float(r.get("us") or 0.0)}
                except (ValueError, KeyError, TypeError):
                    continue
                if sid not in out or v > out[sid]["v"]:
                    out[sid] = rec
        return out

    def submit(self, sid: str, seq: int, calls: int, acc: int, us: float) -> int:
        """Queue one snapshot; returns its version (the ticket to `wait` for). Never blocks on I/O."""
        with self._cv:
            self.v += 1
            v = self.v
            self._queue.append((v, sid, self._line({"s": sid, "v": v, "seq": int(seq), "calls": int(calls),
                                                    "acc": str(int(acc)), "us": round(float(us), 3)})))
            if self._thread is None:
                self._thread = threading.Thread(target=RouteWal._writer, args=(weakref.ref(self),), daemon=True,
                                                name="route-wal")
                self._thread.start()
            self._cv.notify_all()
            return v

    def wait(self, v: int, timeout: float = 30.0) -> None:
        """Return once snapshot `v` is durable; OSError if its write failed (or timed out)."""
        end = time.monotonic() + timeout
        with self._cv:
            while True:
                if any(lo <= v <= hi for lo, hi in self._failed):
                    raise OSError(f"route wal {self.path}: {self.error or 'write failed'}")
                if self._durable >= v:
                    return
                left = end - time.monotonic()
                if left <= 0:
                    raise OSError(f"route wal {self.path}: not durable after {timeout} s")
                self._cv.wait(left)

    def forget(self, sid: str) -> None:
        """A pruned session: left out of the next compaction."""
        with self._cv:
            self._latest.pop(sid, None)

    @staticmethod
    def _writer(ref):
        """The writer thread holds its RouteWal only weakly between batches: it ends once the
        provider that owns it is gone."""
        while True:
            w = ref()
            if w is None or not w._step():
                return
            del w

    def _step(self) -> bool:
        with self._cv:
            if not self._queue:
                self._cv.wait(1.0)
            if not self._queue:
                return True
        self._run_batch()
        return True

    def _run_batch(self):
        with self._cv:
            batch, self._queue = self._queue, []
        lo, hi = batch[0][0], batch[-1][0]
        try:
            self._write(batch)
        except OSError as e:
            with self._cv:
                self.error = str(e)
                self._failed = (self._failed + [(lo, hi)])[-64:]
                self._durable = max(self._durable, hi)   # waiters of this batch see _failed first
                self._cv.notify_all()
            return
        with self._cv:
            self._durable = hi
            for _, sid, line in batch:
                self._latest[sid] = line
            self._cv.notify_all()
        if self._fh is not None and self._fh.tell() > self.compact_bytes:
            try:
                self._compact()
            except OSError:
                pass                      # the log still holds every line: retried after the next batch

    def __del__(self):
        fh = getattr(self, "_fh", None)
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass

    def _write(self, batch):
        created = False
        if self._fh is None:
            created = not os.path.exists(self.path)
            self._fh = open(self.path, "ab")
        start = self._fh.tell()
        try:
            self._fh.write(b"".join(line for _, _, line in batch))
            self._fh.flush()
            os.fdatasync(self._fh.fileno()) if hasattr(os, "fdatasync") else os.fsync(self._fh.fileno())
            self.fsyncs += 1
            if created:
                _fsync_dir(self.path)
        except OSError:
            try:
                self._fh.truncate(start)
                self._fh.seek(start)
            except (OSError, ValueError):
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
            raise

    def _compact(self):
        """In the writer thread: one snapshot per live session, fsynced, renamed over the log."""
        with self._cv:
            lines = list(self._latest.values())
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(b"".join(lines))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        _fsync_dir(self.path)
        self._fh.close()
        self._fh = open(self.path, "ab")


def _fsync_dir(path: str):
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


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
    charge: Optional[Callable] = None     # (method, path, status, body) -> amsat, after serving
    precharge: Optional[Callable] = None  # (method, path, body) -> amsat the call will bill, before it runs
                                          # (AGP-054: its meter is written ahead while the handler runs)


class RouteSeller:
    """Provider side of routing, owned by an XbtChannelProvider (`provider.routes`).

    Serving rule (constraint 6): a session is served while its unpaid charges are younger than
    `window + lock_wait` (and under `credit_msat` if set). When the hub stops forwarding, the lock
    never arrives and the provider stops within one window: its loss is at most one window of that
    session's traffic, the client's at most one lock per provider."""

    def __init__(self, provider, path: str = None, wal_path: str = None):
        self.p = provider
        self.offers: Dict[str, RouteOffer] = {}
        self.sessions: Dict[str, RouteSession] = {}
        self.lock = threading.Lock()
        self.path = path
        self._quote_seq = int(time.time())
        self._quotes: Dict[str, PriceQuote] = {}
        self._saved_v = 0             # RouteWal version at the routes file's last save (its "walV")
        if path and os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            self.sessions = {k: RouteSession(**v) for k, v in raw.get("sessions", {}).items()}
            self._saved_v = int(raw.get("walV", 0))
        self._keys: Dict[str, bytes] = {}
        self._invoices: Dict[str, tuple] = {}   # session -> ((lockId, validUntil), signed invoice): one sign per window
        self._inflight: Dict[str, list] = {}    # session -> [calls, amsat] reserved and not yet ended (AGP-054)
        # session -> (v, seq, calls, accrued): the meter its latest snapshot holds, v 0 for a completed
        # routes-file save (durable already). An answer waits for a snapshot that covers it (AGP-054 rework)
        self._snap: Dict[str, tuple] = {}
        self._states: Dict[str, int] = {}       # session -> ROUTE-STATEs built so far (a failed call's take-back guard)
        self.wal = RouteWal(wal_path) if wal_path else None
        if self.wal is not None:
            # a log that lost its lines (deleted, replaced) must not restart below walV: replay would
            # take the routes file over every snapshot written since
            self.wal.v = max(self.wal.v, self._saved_v)
            self._replay()
        self.no_reveal = False        # tests/demo: take locks, never reveal t (a withholding provider)
        self.held: list = []

    def _replay(self):
        """At start: a session's meter from the RouteWal where its snapshot is newer than the routes
        file (v above walV), then one save, so the routes file carries it."""
        changed = False
        for sid, r in self.wal.read().items():
            s = self.sessions.get(sid)
            if s is None or r["v"] <= self._saved_v:
                continue
            s.seq, s.calls = max(int(s.seq), r["seq"]), r["calls"]
            s.accrued_amsat, s.unpaid_since = int(r["acc"]), float(r["us"])
            changed = True
        if changed:
            self._save()

    def _persisted(self, s: RouteSession) -> dict:
        """A session as the routes file keeps it: its meter projected over its calls in flight (the
        same snapshot a RouteWal line holds), so a save supersedes no reservation (AGP-054)."""
        d = asdict(s)
        if s.session in self._inflight:
            d["seq"], d["calls"], d["accrued_amsat"], d["unpaid_since"] = self._projected(s)
        return d

    def _save(self):
        if not self.path:
            return
        if self.wal is not None:
            self._saved_v = self.wal.v    # every snapshot up to here is superseded by this file
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"sessions": {k: self._persisted(v) for k, v in self.sessions.items()}, "walV": self._saved_v}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if self.wal is not None:
            # every caller holds self.lock: the file is durable and covers each session as it is now
            for sid, s in self.sessions.items():
                seq, calls, acc, _ = self._projected(s)
                self._snap[sid] = (0, seq, calls, acc)

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
        """The window's signed invoice. It only changes with the window (and ECDSA signing is
        deterministic), so it is signed once per window, not on every ROUTE-STATE (AGP-054)."""
        o = self.offers[s.path]
        key = (s.lock_id, s.point, round(s.valid_until, 3), json.dumps(o.hubs, sort_keys=True))
        hit = self._invoices.get(s.session)
        if hit is not None and hit[0] == key:
            return dict(hit[1])
        inv = asdict(Invoice(self.p.pay_to, self.p.network, s.session, s.lock_id, s.point,
                             round(s.valid_until, 3), o.hubs).sign(self.p.secret))
        self._invoices[s.session] = (key, inv)
        return dict(inv)

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

    def begin_call(self, path: str, hdr: str, method: str, bind: str, body: bytes):
        """Authenticate a routed call. Returns (session, None) to serve or (session|None, error).
        `bind` is the request's URL as request_digest_v2 binds it."""
        from .x402_channel import request_digest_v2, unb64json
        try:
            h = unb64json(hdr)
            sid, seq, auth = str(h["session"]), int(h["seq"]), str(h["auth"])
        except (ValueError, KeyError, TypeError):
            return None, "bad_payload"
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s.path != path:
                return None, "unknown_session"
            want = call_auth(self._key(s), s.session, seq, request_digest_v2(method, bind, body))
            if seq <= s.seq or not hmac.compare_digest(want, auth):
                return None, "bad_auth"
            s.seq = seq
            err = self._serving(s, time.time())
            return s, err

    def _projected(self, s: RouteSession) -> tuple:
        """Under self.lock: (seq, calls, accrued, unpaid_since) with the calls in flight counted at
        their reserved charges: what a restart may bill (AGP-054)."""
        n, amt = self._inflight.get(s.session) or (0, 0)
        us = s.unpaid_since
        if amt > 0 and s.owed_amsat() <= 0:
            us = time.time()
        return s.seq, s.calls + n, s.accrued_amsat + amt, us

    def _submit(self, s: RouteSession) -> int:
        seq, calls, acc, us = self._projected(s)
        v = self.wal.submit(s.session, seq, calls, acc, us)
        self._snap[s.session] = (v, seq, calls, acc)
        return v

    def _covering(self, s: RouteSession) -> int:
        """Under self.lock, as a state is built from the session's meter: the version of a snapshot
        that covers it (seq, calls and accrued each >= the state's), queuing a fresh one if the
        latest does not. The state carries the session's CURRENT meter, which may already hold a
        concurrent call metered in memory whose own snapshot is still queued, or a seq taken by
        begin_call and not reserved yet: waiting only for this call's own reserved snapshot could
        let a state leave that a crash would take back (AGP-054 rework 1)."""
        snap = self._snap.get(s.session)
        if snap is not None and snap[1] >= s.seq and snap[2] >= s.calls and snap[3] >= s.accrued_amsat:
            return snap[0]
        return self._submit(s)

    def reserve(self, s: RouteSession, expect_amsat: int) -> Optional[tuple]:
        """Before the handler runs (AGP-054): count the call in flight at `expect_amsat` and queue its
        session's projected meter, so the fsync overlaps the handler. Returns the ticket for
        end_call (None without a RouteWal)."""
        if self.wal is None:
            return None
        expect = max(0, int(expect_amsat))
        with self.lock:
            inf = self._inflight.setdefault(s.session, [0, 0])
            inf[0] += 1
            inf[1] += expect
            return (self._submit(s), expect)

    def _unreserve(self, s: RouteSession, ticket) -> None:
        inf = self._inflight.get(s.session)
        if ticket is None or inf is None:
            return
        inf[0] -= 1
        inf[1] -= ticket[1]
        if inf[0] <= 0:
            self._inflight.pop(s.session, None)

    def cancel(self, s: RouteSession, ticket) -> None:
        """The handler raised: the call bills nothing. Its projection is corrected (not waited for:
        no answer leaves, and until the correction is on disk the call is an in-doubt one)."""
        if ticket is None:
            return
        with self.lock:
            self._unreserve(s, ticket)
            self._submit(s)

    def end_call(self, s: RouteSession, charge_amsat: int, ticket=None) -> dict:
        """Meter the call and return its ROUTE-STATE. With a RouteWal the state is returned only once
        a snapshot covering it is durable: the reserved one when the charge is what was projected
        and no routes-file save superseded it, else a fresh one. On a write failure the call is taken
        back (nothing billed) and ChannelError('route_wal_failed') is raised: no state may leave."""
        with self.lock:
            now = time.time()
            self._unreserve(s, ticket)
            if charge_amsat > 0:
                if s.owed_amsat() <= 0:
                    s.unpaid_since = now
                s.accrued_amsat += charge_amsat
            s.calls += 1
            state = self.state(s, charge_amsat)
            if self.wal is None:
                return state
            gen = self._states[s.session] = self._states.get(s.session, 0) + 1
            if ticket is None or ticket[1] != charge_amsat:
                # the durable meter must not keep a projection the call did not bill
                v = self._submit(s)
            else:
                # the session's latest snapshot, not only this call's own: the state carries the
                # session's meter as it is now (sequentially, that is the reserved one)
                v = self._covering(s)
        try:
            self.wal.wait(v)
        except OSError as e:
            with self.lock:
                # taken back only while no later state carries it (a later answer's snapshot may be
                # durable and hold it: taking it back would make the next state go backwards; it
                # then stays billed, like a call in flight at a crash)
                if self._states.get(s.session) == gen:
                    s.accrued_amsat -= charge_amsat
                    s.calls -= 1
                    if s.owed_amsat() <= 0:
                        s.unpaid_since = 0.0
            raise ChannelError("route_wal_failed", str(e))
        return state

    def refusal_state(self, s: RouteSession) -> Optional[dict]:
        """The ROUTE-STATE a refused call's 402 carries, once a snapshot covering it is durable (the
        refused call's seq was taken, and a concurrent call may be metered in memory). None when the
        RouteWal cannot make it durable: the 402 then carries no state."""
        with self.lock:
            state = self.state(s)
            if self.wal is None:
                return state
            self._states[s.session] = self._states.get(s.session, 0) + 1
            v = self._covering(s)
        try:
            self.wal.wait(v)
        except OSError:
            return None
        return state

    # adaptor-locked ch2 states (from the hub) ----------------------------------------------------
    def complete_lock(self, st, pl: dict, route: dict) -> dict:
        """Called by the provider with its ledger lock held, after the hub's channel auth passed.
        Checks the lock, completes it with the window's t, saves the plain state write-ahead, and
        only then credits the session and returns t. Every answer has written `st` (and with it the
        seq the request spent); after a ChannelError the caller writes it.

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
                self.p.ledger.save(st)                       # the seq this answer spent (AGP-078)
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
                self.p.ledger.save(st)
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
            st.extra = {**(st.extra or {}), "route_locks": locks, "routed_sat": routed + amount,
                        "max_lock": max(int((st.extra or {}).get("max_lock", 0)), amount)}
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


def find_spend_at(rpc, txid: str, vout: int, from_height: int):
    """(the transaction spending txid:vout, how deep it is), from the mempool (depth 0) or blocks at or
    above `from_height` (depth 1 at the tip); None if nothing spends it. Needs no txindex (the hub's
    node may be pruned). AGP-088: gettxspendingprevout sees the mempool only, so a spender it names is
    unconfirmed; one found by reading blocks is as deep as its block. The hub never reads "in a block"
    off gettxout answering nothing: a node answers nothing for an output of an unconfirmed transaction
    too."""
    from .tx import Tx
    try:
        r = rpc.gettxspendingprevout([{"txid": txid, "vout": vout}])
        spender = (r[0] if r else {}).get("spendingtxid")
        if spender:
            return Tx.parse(bytes.fromhex(rpc.getrawtransaction(spender, False))), 0
    except Exception:  # noqa: BLE001 - older node or no mempool entry
        pass
    tip = rpc.getblockcount()
    for h in range(max(0, from_height), tip + 1):
        blk = rpc.getblock(rpc.getblockhash(h), 2)
        for tx in blk.get("tx", []):
            for i in tx.get("vin", []):
                if i.get("txid") == txid and i.get("vout") == vout:
                    return Tx.parse(bytes.fromhex(tx["hex"])), tip - h + 1
    return None


def find_spend(rpc, txid: str, vout: int, from_height: int):
    """The transaction spending txid:vout (`find_spend_at` without the depth); None if nothing does."""
    found = find_spend_at(rpc, txid, vout, from_height)
    return found[0] if found else None


def hub_channel_message(chan: str) -> bytes:
    """What a hub's payTo signs to bind a hub-funded ch2 to itself at open."""
    return tagged_hash("xbt402/route/hub-channel", chan.encode())
