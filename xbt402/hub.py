"""xbt402 routing hub (AGP-021): one client -> hub channel pays many providers through hub-funded
hub -> provider channels, with adaptor-locked states on both hops (design: AGP-019).

Experimental: not production-ready; do not route funds you cannot lose (AGP-064).

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
    fails after it broadcast leaves a record the watcher reconciles: the wallet's sends to the ch2
    address (gettransaction), gettxout incl. the mempool, getmempoolentry, then scantxoutset (AGP-045).
    Found in a block or the mempool -> funded, the open goes on; not found within
    funding_timeout_blocks -> archived as `dropped`, key kept; a send the wallet still knows is watched
    while dropped and refunded at expiry if it confirms late, a failed one (conflicted, abandoned, none) is final;
  * every non-final ch2 (funded, open, refunded, closing, closed but unconfirmed) is checked each tick: a
    spent funding is read (find_spend) and its locks' secrets recovered (_from_close); a provider's close
    in the mempool makes the ch2 `closing`, and only a confirmed one `closed` (AGP-045); the hub's own
    refund is final once it confirms, rebroadcast while it is not; a provider close that beats the refund
    reverts the refund fee once it confirms (a mempool close that vanishes restores the refund, fee booked);
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
  * origins are canonical (canon_origin), and one origin never has two live ch2s.

ch2 identity (AGP-056, replacing AGP-044's one live ch2 per payTo): a ch2 belongs to one provider
PROCESS, the origin it was funded at, because that process's ledger is the only one that holds the
channel and its route sessions. An operator may run several provider processes on one payTo key (cmp
merchants), each with its own ledger and origin: each gets its own ch2, and a lock is forwarded to the
origin the client named, on that origin's ch2. One key takes at most ch2_max_per_pay_to live ch2s
(refused pay_to_limit beyond it), so an operator cannot spread the hub's capital without bound.

Settle floor (AGP-056, as the Rust hub): the provider's threshold (settleMultiple x closeFee) says when
a settlement is worth its fee; with locks larger than it, every lock would roll the ch2 over. A due
rollover therefore waits until the ch2 has taken settle_lock_multiple x the largest lock routed to
that provider, but never past the point where another lock of that size would not fit, and never
once the ch2 has had no lock for settle_idle seconds.

Rollover relay (AGP-056): the provider broadcasts the rollover on ITS node. A hub on another node sees
it only after P2P relay, so "not in my mempool" right after a rollover is not "vanished": the child is
blocked only if the hub's node showed the rollover before, or still does not rollover_relay_grace
seconds after it.

Close fees (xbt402 v1.2 closeFeePayer, AGP-023): ch2 is payee-pays by default (Mike, 2026-09-28): the
provider pays its own settlement's close fee out of its output, so the hub's fees price only liquidity
and routing, and the settle threshold counts the provider's net payout. ch1 stays payer-pays (the
client pays, as on any plain channel) unless the operator configures otherwise. extra.routing
advertises both.

Make-before-break rollover (AGP-053, as the Rust hub): the next ch2 is opened right after the rollover
reply, unconfirmed, where the provider takes it (`zeroConf` in its /open reply: the child of its own
confirmed hub-bound channel, up to maxCum and before `until`), so routing never pauses for a block; the
hub keeps within those bounds itself, never rolls an unconfirmed child over, and blocks or drops a child
whose rollover left the mempool or was replaced. A watcher tick waits (bounded) for a provider that
streams locks, so its rollover is not starved.

Make-before-break refill (AGP-057, as the Rust hub): a rollover adds no coins, so a ch2 line carries its
capacity in locks and is then closed and replaced by a ch2 funded from the wallet, which opens only at
minConf (the provider cannot take a wallet funding unconfirmed: its payer could spend it again). The hub
therefore funds the origin's NEXT ch2 ahead: once the live ch2's room is under refill_ahead_locks x the
largest lock routed to that provider (`OutBook.next_chans`, at most one per origin, counted by
liquidity_cap_sat with the live one). The live ch2 keeps taking locks, rollovers included; the next one
takes over (`ch2_switch`) with the first lock the live one cannot take (exhausted, closed, or an
unconfirmed rollover child at the provider's bounds), when the live one is closed as too small to roll
over (not before the next one is open, while the live one still takes a lock), or once the live one has
had no lock for settle_idle seconds. The replaced ch2 is `retired`: the
watcher asks the provider to close it and reconciles it like any archived ch2.

The zero-conf cap and the watcher (AGP-057): the hub's `confirmed` flag of a rollover child is the
watcher's last look. Before a lock is refused on the provider's bounds the hub looks at the chain itself,
so a child that confirmed since the last tick is never refused.
"""
import contextlib
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
from .hub_keys import WRAP_KEY_FILE, WrapKey
from .route import (HUB_ROUTE_PATH, ROLLOVER_PATH, ROUTE_LOCK_PATH, TERMS_PATH, FeeQuote, Invoice, canon_origin,
                    fee_due, find_spend, hub_channel_message, next_cum, route_ok)
from .rpc import RPCError
from .tx import Tx, address_to_spk, segwit_address
from .x402_channel import (XbtChannelClient, XbtChannelProvider, b64json, binding_url, request_auth, request_digest_v2,
                           safe_code, unb64json)
from .channel import channel_auth_key


@dataclass
class OutChannel:
    """One hub -> provider channel (ch2); the hub is the payer."""
    origin: str
    pay_to: str                  # the provider operator's payTo (one key may serve many devices)
    params: dict
    secret: str                  # payer key (hex); sealed on disk under the hub's wrap key (AGP-073 K1)
    state: str = "funded"        # funding -> funded -> open -> closing -> closed | rolled | refunded; funding -> dropped
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
    close_prev: str = ""         # the state a `closing` ch2 left (AGP-045): "refunded" is restored if the close vanishes
    fund_txid: str = ""          # the funding send the hub knows of (wallet), watched while `dropped` (AGP-045)
    fund_vout: int = 0
    rolled_from: str = ""        # the ch2 whose rollover funds this one (AGP-053)
    zero_conf: dict = field(default_factory=dict)   # the provider took it unconfirmed (AGP-053): {parent, maxCum, until, confirmed}
    max_lock: int = 0            # the largest lock routed over this ch2 and the ones it was rolled from (AGP-056)
    last_lock_at: float = 0.0    # when the last lock on it completed (the settle floor holds only while locks come)
    rolled_at: float = 0.0       # when the rollover that funds it was co-signed (AGP-056: relay grace)
    fund_seen: bool = False      # the hub's node has shown that rollover (mempool or a block)
    retired: bool = False        # replaced by the origin's next ch2 (AGP-057): the watcher has it closed

    def p(self) -> ChannelParams:
        return ChannelParams(**self.params)


LIVE = ("funding", "funded", "open")                        # the hub's coins are committed
WATCH_WAIT_ONE, WATCH_WAIT_BUDGET = 0.25, 1.0    # a watcher tick waits for one busy provider's mutex, and for all (AGP-053)
ROLLOVER_GONE = "the rollover that funds this ch2 is in no block and not in the mempool"   # AGP-053
NONFINAL = ("funded", "open", "refunded", "closing", "closed")   # the watcher reconciles these until final


def watched(r: dict) -> bool:
    """An archived record the watcher still reconciles: a non-final ch2, or a dropped funding whose
    send is known (it may confirm late: AGP-045)."""
    if r.get("final"):
        return False
    return r.get("state") in NONFINAL or (r.get("state") == "dropped" and bool(r.get("fund_txid")))


COUNTERS = (("routed_sat", "routed"), ("fee_units", "units"), ("fee_paid", "paid"))   # ch1's base, a lock's `after`


def hold_in_base(ex: dict, lock: dict):
    """AGP-064 (H2): a lock written off after its ch2 pre-signature left stays in ch1's base until that
    ch2 resolves. Raise the counters to the lock's `after` and record on it what was added (`hold`),
    so a release takes back exactly that, whatever came after."""
    hold = {}
    for k, a in COUNTERS:
        cur = int(ex.get(k, 0))
        to = max(cur, int((lock.get("after") or {}).get(a, 0)))
        ex[k], hold[a] = to, to - cur
    lock["hold"] = hold


def ch1_view(st1) -> dict:
    """ch1 as the hub counts it, for a client to resync on: the held locks, and the last ones
    released (AGP-064)."""
    ex = st1.extra or {}
    return {"bestCum": st1.best_cum, "routedSat": int(ex.get("routed_sat", 0)), "feeUnits": int(ex.get("fee_units", 0)),
            "feePaid": int(ex.get("fee_paid", 0)),
            "held": [s["lockId"] for s in ex.get("stale_locks", []) if isinstance(s.get("hold"), dict)],
            "released": list(ex.get("released", []))}


def refund_booked(r: dict) -> bool:
    """The record's refund fee counts: refunded, or refunded and now `closing` on a spender that has
    not confirmed (it is un-booked only when that close confirms: AGP-045)."""
    return r.get("state") == "refunded" or (r.get("state") == "closing" and r.get("close_prev") == "refunded")


def _each_record(doc: dict, f):
    """Every ch2 record in a state file's JSON: the live and next ones, the archive, and the
    rollover's next ch2 written ahead inside a record."""
    recs = list((doc.get("chans") or {}).values()) + list((doc.get("next_chans") or {}).values()) + list(doc.get("archived") or [])
    for r in recs:
        f(r)
        if isinstance(r.get("next"), dict) and "params" in r["next"]:
            f(r["next"])


class OutBook:
    """The hub's ch2s, fsynced JSON, 0600 (each payer key sealed: AGP-073 K1).

    One LIVE ch2 per origin (AGP-056): `chans` is keyed by the canonical origin, one provider process.
    `next_chans` (AGP-057) holds at most one more per origin: the ch2 funded ahead of the live one
    running out, which takes its place in `chans` at the switch. `origins` maps every origin the hub
    connected to the payTo its /terms named (a record, and the per-payTo count).

    On disk every record's payer key is `secret_sealed` (hub_keys), never `secret`; in memory the
    records hold the key as before. A file from before (plaintext keys) is read once and rewritten
    sealed. Refused (`keystore`): a blob that does not open (another wrap key, a changed file), or a key
    that is not its record's payer_pub (a blob moved to another record)."""

    def __init__(self, path: str, wrap: WrapKey = None):
        if wrap is None:
            raise ChannelError("keystore", "a hub state file needs a wrap key (its ch2 keys are sealed)")
        self.path, self.lock, self.wrap = path, threading.RLock(), wrap
        self._sealed: Dict[str, dict] = {}       # each key's blob, sealed once: a save seals only keys it has not seen
        self.legacy_sealed = 0                   # plaintext keys the file had when opened (now sealed)
        self.chans: Dict[str, OutChannel] = {}
        self.next_chans: Dict[str, OutChannel] = {}
        self.archived: list = []
        self.origins: Dict[str, str] = {}
        if os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            _each_record(raw, self._unseal)
            self.chans = {k: OutChannel(**v) for k, v in raw.get("chans", {}).items()}
            self.next_chans = {k: OutChannel(**v) for k, v in raw.get("next_chans", {}).items()}
            self.archived = raw.get("archived", [])
            self.origins = {k: str(v) for k, v in raw.get("origins", {}).items()}
        self.mutex: Dict[str, threading.Lock] = {}
        if self.legacy_sealed:
            self.save()

    def _unseal(self, r: dict):
        if "secret_sealed" in r:
            blob = r.pop("secret_sealed")
            k = self.wrap.open(blob)
            self._sealed[k] = blob
            r["secret"] = k
        elif r.get("secret"):
            self.legacy_sealed += 1
        # a key only ever signs for a record still watched: check that one is its own
        k, pp = r.get("secret"), (r.get("params") or {}).get("payer_pub")
        if k and pp and not r.get("final"):
            try:
                ok = ecc.pubkey(int(k, 16)).hex() == pp.lower()
            except (TypeError, ValueError):
                ok = False
            if not ok:
                raise ChannelError("keystore", f"the ch2 key of {r.get('origin', '')} is not its payer_pub: "
                                               "a sealed key moved to another record")

    def _seal(self, r: dict):
        k = r.pop("secret", "")
        if not k:
            return
        if not self._sealed.get(k):
            self._sealed[k] = self.wrap.seal(k)
        r["secret_sealed"] = self._sealed[k]

    def live_keys(self, pay_to: str) -> list:
        """The origins with a live ch2 (funding, funded or open) to `pay_to`: their own, or the next
        one funded ahead of it (AGP-057: an origin counts once)."""
        with self.lock:
            keys = [k for k, c in self.chans.items() if c.pay_to.lower() == pay_to.lower() and c.state in LIVE]
            return keys + [k for k, c in self.next_chans.items()
                           if k not in keys and c.pay_to.lower() == pay_to.lower() and c.state in LIVE]

    def key_for(self, origin: str) -> Optional[str]:
        """The key of the ch2 that serves `origin` (canonical): its own, and no other (AGP-056: the
        ch2 of another origin under the same payTo is in another process's ledger)."""
        with self.lock:
            return origin if origin in self.chans else None

    def save(self):
        with self.lock:
            doc = {"chans": {k: asdict(v) for k, v in self.chans.items()}, "archived": [{**r, "next": dict(r["next"])} if isinstance(r.get("next"), dict) else dict(r)
                                                                     for r in self.archived],
                   "origins": self.origins, "next_chans": {k: asdict(v) for k, v in self.next_chans.items()}}
            _each_record(doc, self._seal)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f)
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
    signed is re-signed at a higher fee (RBF, AGP-044; 0: never). A `funding` record that neither the
    wallet, the mempool nor the chain shows is dropped after funding_timeout_blocks (a known send is
    still watched: AGP-045). zero_conf_rollover (AGP-053, default on): open a rollover's next ch2 at
    once, unconfirmed, where the provider takes it (its /open reply carries zeroConf), so routing to the
    provider never pauses for a block (make-before-break); a provider that refuses is opened at minConf.

    AGP-056: ch2_max_per_pay_to bounds the live ch2s one payTo key may hold over its origins (provider
    processes; 0: no bound). settle_lock_multiple (k) delays a due rollover until the ch2 has taken k x
    the largest lock routed to that provider (0: roll over at the provider's threshold, as before), for
    as long as locks keep coming (settle_idle seconds without one: roll over). k = 4: at most one
    rollover per four of the largest locks, and with the usual capacity of five such locks (100k / 20k,
    200k / 40k) it is the largest k that still leaves room for one more lock when the rollover is due.
    rollover_relay_grace: seconds a rollover the hub's own node has not shown yet is given to arrive
    over P2P before its ch2 is blocked as vanished.

    AGP-057: refill_ahead_locks (N) funds an origin's next ch2 while the live one still has room: once
    that room is under N x the largest lock routed to the provider (0: never; the ch2 is closed and then
    refilled, and routing to the provider waits for the refill's minConf). N locks must cover what the
    provider is paid while a funding confirms and opens: about (locks per block interval + locks per
    watcher tick). The live and the next ch2 both count against liquidity_cap_sat, so a hub that should
    never pause needs room for one more ch2_capacity than it has origins; without that room nothing is
    funded ahead (`ch2_refill_ahead_failed`, liquidity_cap) and the refill follows the close as before."""
    fee_base_msat: int = 1_000
    fee_ppm: int = 2_000
    fee_strategy: dict = field(default_factory=lambda: {"kind": "flat"})
    quote_ttl: int = 600
    max_lock_sat: int = 20_000
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
    zero_conf_rollover: bool = True
    ch2_max_per_pay_to: int = 8
    settle_lock_multiple: int = 4
    settle_idle: float = 600.0
    rollover_relay_grace: float = 60.0
    refill_ahead_locks: int = 4

    @classmethod
    def from_dict(cls, d: dict) -> "HubConfig":
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown hub config keys: {sorted(unknown)}")
        return cls(**d)

    def __post_init__(self):
        self.validate()

    def validate(self):
        """The bounds a config must keep however it was built: checked when one is constructed and again
        when a RouteHub is built from it (AGP-078: a config changed after construction went around the
        first)."""
        if self.ch1_close_fee_payer not in FEE_PAYERS or self.ch2_close_fee_payer not in FEE_PAYERS:
            raise ValueError("ch1_close_fee_payer / ch2_close_fee_payer are payer or payee")
        # AGP-064: a written-off lock holds the client's base and blocks its ch2 until that ch2
        # resolves, so a lock is a small share of a ch2: at most half (the default is a fifth)
        if self.max_lock_sat <= 0 or 2 * self.max_lock_sat > self.ch2_capacity:
            raise ValueError(f"max_lock_sat {self.max_lock_sat} must be at most half of ch2_capacity {self.ch2_capacity}")

    def funding_policy(self) -> FundingPolicy:
        return FundingPolicy(**{"close_margin": self.close_margin, **self.policy})


class RouteHub:
    def __init__(self, rpc, pay_to_secret: int, network: str, datadir: str, fund: Callable[[str, int], tuple],
                 config: HubConfig = None, *, http: Callable = None, policy: FundingPolicy = None,
                 fee_strategy: Callable = None, refill: Callable[[str], "OutChannel"] = None,
                 refund_to: Callable[[], str] = None, wallet=None,
                 refill_ahead: Callable[[str], "OutChannel"] = None, wrap_key: WrapKey = None, **overrides):
        """`config` (a HubConfig) holds the operator's choices; keyword `overrides` set single fields
        (fee_ppm=..., liquidity_cap_sat=...). `fee_strategy`, if given, is a callable(hub) ->
        (fee_base_msat, fee_ppm) that replaces the configured one. `refill(origin)` funds the ch2 that
        replaces a closed one (default `connect`: an embedder passes its own path, with its lock and
        cap); it is looked up at each call, so assigning `hub.refill` or `hub.connect` later takes effect
        (AGP-045). `refill_ahead(origin)` funds the origin's NEXT ch2 while its live one still routes
        (AGP-057; default `connect_next`, or nothing when the embedder passed its own `refill`: see the
        `refill_ahead` property). `refund_to()` gives the address a ch2 refund pays (default: the ch2's payer key).
        `wallet` is an RPC handle on the fund wallet (default `rpc`): listtransactions/gettransaction,
        how the watcher finds a funding send whose fund call failed (AGP-045). `wrap_key` seals the ch2 keys in
        ch2.json (AGP-073 K1; default `<datadir>/hub-wrap-key`, made 0600 on first run): a state file sealed
        under another key is refused (`keystore`)."""
        cfg = config or HubConfig()
        if isinstance(fee_strategy, dict):              # a configured strategy, not a callable
            overrides["fee_strategy"], fee_strategy = fee_strategy, None
        if overrides:
            cfg = HubConfig(**{**asdict(cfg), **overrides})
        cfg.validate()
        self.config = cfg
        os.makedirs(datadir, exist_ok=True)
        self.rpc, self.secret, self.network, self.fund, self.hrp = rpc, pay_to_secret, network, fund, cfg.hrp
        self.pay_to = ecc.pubkey(pay_to_secret).hex()
        self.inbound = XbtChannelProvider(
            rpc, pay_to_secret, network, os.path.join(datadir, "ch1.sqlite"), price=lambda m, p: 0,
            handler=lambda m, p, b: (404, {}, b"not found"), close_fee=cfg.close_fee, close_margin=cfg.close_margin,
            policy=policy or cfg.funding_policy(), close_fee_payer=cfg.ch1_close_fee_payer)
        self.out = OutBook(os.path.join(datadir, "ch2.json"),
                           wrap_key or WrapKey.load_or_create(os.path.join(datadir, WRAP_KEY_FILE)))
        self.fee_base_msat, self.fee_ppm, self.quote_ttl = cfg.fee_base_msat, cfg.fee_ppm, cfg.quote_ttl
        self.max_lock_sat, self.max_unguarded_lock_sat, self.delta = cfg.max_lock_sat, cfg.max_unguarded_lock_sat, cfg.delta
        self.reveal_timeout, self.close_margin, self.close_fee = cfg.reveal_timeout, cfg.close_margin, cfg.close_fee
        self.ch2_capacity, self.ch2_expiry_blocks = cfg.ch2_capacity, cfg.ch2_expiry_blocks
        self.rollover_margin, self.liquidity_cap_sat = cfg.rollover_margin, cfg.liquidity_cap_sat
        self.zero_conf_rollover = bool(cfg.zero_conf_rollover)
        self._zc_tried: set = set()  # (chan, tip): a rollover child's unconfirmed open, tried once a block
        self._ahead_tried: set = set()    # (origin, tip): an ahead refill that failed, tried once a block (AGP-057)
        self._retire_tried: set = set()   # (chan, tip): a retired ch2's close, asked once a block
        self._stale_tried: set = set()    # (chan, tip): the early close of a ch2 a written-off lock blocks (AGP-073)
        self.fee_strategy = fee_strategy or self._configured_fees
        self.http = http or XbtChannelClient.http
        self._refill = refill
        self._refill_ahead = refill_ahead
        self.refund_to = refund_to
        self.wallet = wallet if wallet is not None else rpc
        self._quote: Optional[FeeQuote] = None
        self._quote_seq = int(time.time())
        self.withhold = ""           # tests/demo: "" | "receipt" (keep t + r from the client) | "all"
        self.events: list = []
        if self.out.legacy_sealed:
            print(f"hub: sealed {self.out.legacy_sealed} plaintext ch2 keys in ch2.json (AGP-073); older copies of that "
                  "file (backups) still hold them", file=sys.stderr)
            self.events.append({"event": "ch2_keys_sealed", "count": self.out.legacy_sealed})
        # uncollected (AGP-064): locks completed after their ch1 closed below them (paid to the provider,
        # not collected: only an operator's close or a margin close past its wait can do that)
        self.stats = {"routed": 0, "floor": 0, "refused": {}, "lock_ms": [], "uncollected": 0}

    @property
    def refill(self) -> Callable[[str], "OutChannel"]:
        """The refill hook, looked up at call time (AGP-045): the embedder's, else `self.connect` as it
        is now (so replacing `connect` after construction takes effect)."""
        return self._refill or self.connect

    @refill.setter
    def refill(self, f):
        self._refill = f

    @property
    def refill_ahead(self) -> Optional[Callable[[str], "OutChannel"]]:
        """The hook that funds an origin's next ch2 ahead of exhaustion (AGP-057), looked up at call time:
        the embedder's; else `connect_next` as it is now. An embedder that passed its own `refill` (its
        path, lock and cap) and no `refill_ahead` gets None: the hub funds nothing on its own, and the
        refill follows the close as before."""
        if self._refill_ahead is not None:
            return self._refill_ahead
        return None if self._refill is not None else self.connect_next

    @refill_ahead.setter
    def refill_ahead(self, f):
        self._refill_ahead = f

    # ---------------------------------------------------------------------------------------------
    def committed_sat(self) -> int:
        """The hub's own coins in live ch2s (funding, funded or open): every origin's live one, its next
        one funded ahead (AGP-057), and a retired one until its close is out."""
        with self.out.lock:
            live = [c for c in list(self.out.chans.values()) + list(self.out.next_chans.values()) if c.state in LIVE]
            return sum(c.p().capacity for c in live) + sum(
                int(r["params"]["capacity"]) for r in self.out.archived if r.get("retired") and r.get("state") in LIVE)

    def refund_fees_sat(self) -> int:
        """Fees of the hub's own ch2 refunds that spent (or still may spend) their fundings."""
        with self.out.lock:
            recs = [asdict(c) for c in self.out.chans.values()] + list(self.out.archived)
        return sum(int(r.get("refund_fee") or 0) for r in recs if refund_booked(r))

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
        """Every origin whose own ch2 is open and not blocked, or whose next one is open to take over
        (AGP-057) unless the hub stopped routing to the provider."""
        with self.out.lock:
            ok = {o for o, c in self.out.chans.items() if c.state == "open" and not c.blocked}
            for o, n in self.out.next_chans.items():
                c = self.out.chans.get(o)
                if n.state == "open" and (c is None or not c.blocked or c.blocked == ROLLOVER_GONE):
                    ok.add(o)
            return sorted(ok)

    def ch2_for(self, origin: str) -> Optional[OutChannel]:
        """The ch2 that serves `origin`: its own (AGP-056)."""
        with self.out.lock:
            return self.out.chans.get(canon_origin(origin))

    def body_limit(self, path: str, max_body: int = None) -> int:
        return self.inbound.body_limit(path, max_body)

    def serve(self, method: str, path: str, headers: dict, body: bytes, url: str = "", max_body: int = None):
        if len(body or b"") > self.body_limit(path, max_body):
            return 400, {}, b"bad request framing or body over MAX_BODY"
        if path.split("?", 1)[0] == HUB_ROUTE_PATH:
            hdr = {k.upper(): v for k, v in headers.items()}.get("PAYMENT-SIGNATURE")
            if method == "POST" and hdr:
                return self.route(method, binding_url(url, HUB_ROUTE_PATH), hdr, body)
            st, h, b = self.inbound._payment_required(url or path, 0, "payment_required")
            doc = json.loads(b)
            doc["accepts"][0]["extra"]["routing"] = self.routing_extra()
            h["PAYMENT-REQUIRED"] = b64json(doc)
            return 402, h, json.dumps(doc).encode()
        # a rollover spends ch1's funding as a close does (AGP-078): the same sweep before either
        if method == "POST" and path.split("?", 1)[0] in ("/x402/xbt-channel/close", "/x402/xbt-channel/rollover"):
            try:
                self._sweep_orphan_lock(canonical_chan(json.loads(body)["chan"]))
            except (ValueError, KeyError, TypeError, ChannelError):
                pass                                    # the provider's close refuses it with its own error
        return self.inbound.serve(method, path, headers, body, url, max_body)

    def _sweep_orphan_lock(self, ch1: str) -> Optional[dict]:
        """A ch1 lock that no route is forwarding and no ch2 has pending: the hub stopped between its
        write-ahead and the ch2 one, or between a void's ch2 write and its ch1 write (or the withholding
        test hook). Checked under the provider's mutex, which route() holds from before it writes the lock
        until its forward ends. AGP-073: if a ch2 of that provider has the lock written off, its
        pre-signature may be out, so it is held in ch1's base as the void would have held it; otherwise
        nothing can complete it and it is dropped (AGP-064), so it does not keep ch1 from closing. Run by
        the watcher for every ch1 with a lock, and before a ch1 close."""
        st1 = self.inbound.ledger.channels.get(ch1)
        rl = (st1.extra or {}).get("route_lock") if st1 is not None else None
        if not rl:
            return None
        origin, lid = rl.get("provider", ""), rl.get("lockId")
        mtx = self.out.mutex_for(origin)
        if not mtx.acquire(blocking=False):
            return None
        try:
            with self.out.lock:
                live = [c for c in (self.out.chans.get(origin), self.out.next_chans.get(origin)) if c is not None]
                if any(c.pending.get("lockId") == lid for c in live):
                    return None
                written_off = (any(not c.final and any(s.get("lockId") == lid for s in c.stale) for c in live)
                               or any(r.get("origin") == origin and not r.get("final")
                                      and any(s.get("lockId") == lid for s in r.get("stale") or []) for r in self.out.archived))
            with self.inbound.ledger.lock:
                ex = st1.extra or {}
                if (ex.get("route_lock") or {}).get("lockId") != lid:
                    return None
                ex = {**ex, "route_lock": None}
                if written_off:
                    held = {**rl, "voided": round(time.time(), 3)}
                    hold_in_base(ex, held)
                    ex["stale_locks"] = list(ex.get("stale_locks", [])) + [held]
                st1.extra = ex
                self.inbound.ledger.save(st1)
        finally:
            mtx.release()
        ev = {"event": "orphan_lock_held" if written_off else "orphan_lock_dropped", "chan": ch1, "lockId": lid,
              "provider": origin}
        self.events.append(ev)
        return ev

    def http_server(self, port: int):
        return XbtChannelProvider.http_server(self, port)

    # --- POST /x402/route --------------------------------------------------------------------------
    @staticmethod
    def _err(code: str, detail: str = "", status: int = 400, **extra):
        return status, {"Content-Type": "application/json"}, json.dumps(
            {"error": code, "detail": detail, **extra}).encode()

    def route(self, method: str, bind: str, hdr: str, body: bytes):
        """`bind`: the request's URL as request_digest_v2 binds it."""
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
            if not ib._authentic(st1, pl, method, bind, body):
                return self._err("bad_auth", status=401)
            st1.seq = int(pl["seq"])
            # AGP-078 (review T4): the seq this request spent is durable before its refusal (or the error
            # that ended it) leaves. Kept only in memory it came back after a restart, and the refused
            # header authenticated again
            try:
                adm, refusal = self._admit(st1, pl, rt, d, f, lock_id, provider)
            except BaseException:
                ib.ledger.save(st1)
                raise
            if adm is None:
                ib.ledger.save(st1)
                return refusal
            oc, lock1, mtx = adm
        try:
            return self._forward(st1, oc, lock1, rt, pl, t0)
        finally:
            mtx.release()

    def _admit(self, st1, pl: dict, rt: dict, d: int, f: int, lock_id: str, provider: str):
        """Checks 2 to 7 of a /x402/route whose auth passed, and the ch1 write-ahead of its lock (the
        ledger lock is the caller's). `((oc, lock1, mtx), None)`: the ch2 the lock goes over, the lock as
        written on ch1, and that provider's mutex, held. `(None, answer)`: the answer to send instead (a
        refusal, or a completed lock's answer again); nothing was written."""
        ib = self.inbound
        done = ((st1.extra or {}).get("route_done") or {}).get(lock_id)
        if done:                                   # the client lost our answer: the same one again
            return None, (200, {"Content-Type": "application/json"}, json.dumps(done).encode())
        if st1.closed_txid or ib.height() >= st1.params.expiry - ib.close_margin:
            return None, self._err("channel_closing")
        if st1.suspended:
            return None, self._err("unconfirmed")
        # 2 point --------------------------------------------------------------------------
        try:
            T = adaptor.dec(rt["point"])
            r = int(rt["tweak"], 16) % adaptor.N
            T1 = adaptor.dec(pl["point"]) if pl.get("point") else None
        except (KeyError, TypeError, ValueError):
            return None, self._err("bad_point", "points must be compressed secp256k1 points")
        if T1 is not None and (not r or adaptor.add(T, adaptor._mul_pub(r)) != T1):
            return None, self._err("bad_point", "T1 != T + r*G")
        # 3 amount -------------------------------------------------------------------------
        ex1 = st1.extra or {}
        routed1 = int(ex1.get("routed_sat", 0))
        cum = int(pl.get("cum", -1))
        need1 = next_cum(routed1, d + f, st1.params.min_amount)
        if d < 1 or f < 0 or d > self.max_lock_sat:
            return None, self._err("bad_amount", f"lock amount must be in [1, {self.max_lock_sat}]")
        floor1 = need1 <= st1.best_cum
        # our view of ch1, so a client that gave up a lock we later completed (t read off a ch2
        # close), held or released can resync: it adopts only states and counters it implied itself
        view = ch1_view(st1)
        if floor1:
            if cum != st1.best_cum or pl.get("adaptor"):
                return None, self._err("bad_amount", f"the dust floor covers this lock: cum {st1.best_cum}, no adaptor",
                                 expectCum=st1.best_cum, **view)
        elif cum != need1 or cum > st1.params.max_amount or T1 is None:
            return None, self._err("bad_amount", f"lock pays {cum}, expected {need1}", expectCum=need1, **view)
        # 4 pre-verify ---------------------------------------------------------------------
        pre1 = None
        if not floor1:
            try:
                pre1 = adaptor.PreSig.from_json(pl["adaptor"])
            except (KeyError, TypeError, ValueError):
                return None, self._err("bad_adaptor", "malformed adaptor")
            z1 = st1.params.sighash(st1.params.state_tx(cum))
            if not adaptor.preverify(bytes.fromhex(st1.params.payer_pub), z1, T1, pre1):
                return None, self._err("bad_adaptor", "pre-signature does not verify under T1")
        # 5 fee quote ----------------------------------------------------------------------
        try:
            q = FeeQuote.from_dict(rt["feeQuote"])
        except (ChannelError, KeyError):
            return None, self._err("route_fee", "no fee quote")
        # any live quote this hub signed is honoured, including one the fee strategy has since moved
        if q.hub != self.pay_to or q.network != self.network or not q.verify() or not q.live(time.time()):
            return None, self._err("route_fee", "not a live fee quote of this hub")
        f_due, units = fee_due(q, d, int(ex1.get("fee_units", 0)), int(ex1.get("fee_paid", 0)))
        if f < f_due:
            return None, self._err("route_fee", f"fee {f} < {f_due} due under quote {q.seq}", feeDue=f_due)
        # 6 expiry rule --------------------------------------------------------------------
        # the provider is the origin the client named: its own ch2, in that process's ledger (AGP-056)
        key = provider
        oc = self.out.chans.get(key)
        # a rollover's next ch2 is opened (AGP-053) under the mutex the lock takes below: it is checked
        # again there, once it is open
        opening = oc is not None and oc.state == "funded" and oc.rolled_from and self.zero_conf_rollover
        # the origin's next ch2, funded ahead (AGP-057), takes the lock its live one cannot: decided
        # under the mutex below
        nxt = self.out.next_chans.get(key)
        spare = nxt is not None and nxt.state == "open"
        if (oc is None or (oc.state != "open" and not opening)) and not spare:
            return None, self._err("route_blocked", self._no_channel(provider, oc))
        if oc is not None and oc.blocked and not (spare and oc.blocked == ROLLOVER_GONE):
            return None, self._err("route_blocked", oc.blocked)
        if oc is None:
            oc = nxt
        try:
            inv = Invoice.from_dict(rt["invoice"])
        except (ChannelError, KeyError):
            return None, self._err("bad_invoice")
        if (inv.payTo != oc.pay_to or not inv.verify() or inv.point.lower() != str(rt["point"]).lower()
                or inv.lockId != lock_id or inv.validUntil < time.time() + 0.5
                or (inv.hubs != "any" and self.pay_to not in inv.hubs)):
            return None, self._err("bad_invoice", "invoice not signed by the provider for this point, or expiring")
        p2 = oc.p()
        if not spare and not route_ok(ib.height(), st1.params.expiry, p2.expiry, self.close_margin, self.delta) \
                and d > self.max_unguarded_lock_sat:
            return None, self._err("route_expiry", f"ch2 outlives ch1 and {d} > maxUnguardedLockSat")
        # 7 one lock per channel -----------------------------------------------------------
        if ex1.get("route_lock"):
            return None, self._err("lock_outstanding", "a lock on this ch1 is pending")
        mtx = self.out.mutex_for(key)
        if not mtx.acquire(timeout=0.5):
            return None, self._err("lock_outstanding", "a lock on this provider's ch2 is pending")
        # re-read under the mutex: the watcher may have rolled this ch2 over meanwhile (AGP-053), so
        # the checks that depend on the channel are made again on the one the lock will use
        oc = self.out.chans.get(key)
        why = self._ch2_refusal(oc, st1, d)
        if oc is None or why or self._exhausted(oc, d):
            # AGP-057: the next ch2, funded ahead, takes over with this lock (make-before-break refill)
            alt = self._switch_for(key, oc, st1, d, why)
            if alt is not None:
                oc, why = alt, None
        if why:
            mtx.release()
            return None, self._err(*why)
        # write-ahead: pre1 (enough to complete ch1 from t on-chain after a crash)
        lock1 = {"lockId": lock_id, "cum": cum, "floor": floor1, "pre": pre1.to_json() if pre1 else None,
                 "T": rt["point"], "T1": pl.get("point"), "r": f"{r:064x}", "d": d, "f": f, "units": units,
                 "provider": provider, "at": round(time.time(), 3), "session": rt.get("session"),
                 "after": {"routed": routed1 + d + f, "units": units, "paid": int(ex1.get("fee_paid", 0)) + f}}
        st1.extra = {**ex1, "route_lock": lock1}
        try:
            ib.ledger.save(st1)
        except BaseException:
            st1.extra = ex1                              # not written: the lock is not there
            mtx.release()
            raise
        return (oc, lock1, mtx), None

    def _ch2_refusal(self, oc: Optional[OutChannel], st1, d: int) -> Optional[tuple]:
        """(code, detail) if the ch2 (as read under its mutex) cannot take a lock of `d` now: another
        lock is pending, it is not open (a rollover child the provider did not take unconfirmed), it is blocked, the expiry rule, or (AGP-053) it is an
        unconfirmed rollover child past the provider's zero-conf bounds."""
        if oc is None or oc.pending:
            return "lock_outstanding", "a lock on this provider's ch2 is pending"
        # AGP-064 (H2): a written-off lock's pre-signature may be out. Nothing more over this ch2 until it
        # resolves: its close shows whether t was used, its refund that it was not
        if oc.stale:
            return "route_blocked", "a written-off lock on this ch2 is unresolved"
        if oc.state != "open":
            return "route_blocked", self._no_channel(oc.origin, oc)
        if oc.blocked:
            return "route_blocked", oc.blocked
        p2, tip = oc.p(), self.inbound.height()
        if not route_ok(tip, st1.params.expiry, p2.expiry, self.close_margin, self.delta) and d > self.max_unguarded_lock_sat:
            return "route_expiry", f"ch2 outlives ch1 and {d} > maxUnguardedLockSat"
        zc = oc.zero_conf
        if zc and not zc.get("confirmed"):
            need2 = max(next_cum(oc.routed, d, p2.min_amount), oc.signed)
            late, over = tip >= int(zc.get("until", 0)), need2 > int(zc.get("maxCum", 0))
            if late or over:
                # AGP-057: `confirmed` is the watcher's last look, which a block or a busy tick can be behind.
                # Past a bound, look at the chain before refusing (the provider does the same)
                try:
                    self._zero_conf_tick(oc, p2)
                except Exception as e:  # noqa: BLE001 - the node did not answer: the bounds stand
                    self._watch_error(oc.origin, "zero_conf", e)
            if not oc.zero_conf.get("confirmed"):
                if late:
                    return "route_blocked", "the rollover funding this ch2 is unconfirmed at the parent's close margin"
                if over:
                    return "route_blocked", (f"the rollover funding this ch2 is unconfirmed: cum {need2} > the provider's "
                                             f"zero-conf cap {zc.get('maxCum', 0)}")
        return None

    @staticmethod
    def _exhausted(oc: OutChannel, d: int) -> bool:
        """A lock of `d` needs a state above the ch2's capacity."""
        p2 = oc.p()
        need2 = next_cum(oc.routed, d, p2.min_amount)
        return need2 > oc.signed and need2 > p2.max_amount

    def _switch_for(self, key: str, oc: Optional[OutChannel], st1, d: int, why: Optional[tuple]) -> Optional[OutChannel]:
        """AGP-057: the origin's live ch2 (`oc`, as read under its mutex) cannot take a lock of `d`: `why`
        is its refusal, None when it is only exhausted. If the origin's next ch2 is open and can take the
        lock, it becomes the live one (`_promote`) and is returned. Never while a lock is pending on the
        live one, and never when the hub stopped routing to the PROVIDER (a lock it did not reveal): a
        fresh channel does not mend that."""
        with self.out.lock:
            nxt = self.out.next_chans.get(key)
        if nxt is None or nxt.state != "open":
            return None
        if oc is not None and (oc.pending or (oc.blocked and oc.blocked != ROLLOVER_GONE)):
            return None
        if self._ch2_refusal(nxt, st1, d) or self._exhausted(nxt, d):
            return None
        return self._promote(key, why[1] if why else "exhausted")

    def _promote(self, origin: str, why: str) -> Optional[OutChannel]:
        """AGP-057: the origin's next ch2 becomes its live one. The caller holds the origin's mutex, or the
        live one takes no lock any more. The ch2 it replaces goes to the archive; while its coins are
        still committed (funded, open) it is `retired`: the watcher has the provider close it."""
        with self.out.lock:
            nxt = self.out.next_chans.pop(origin, None)
            if nxt is None:
                return None
            old = self.out.chans.get(origin)
            if old is not None:
                if old.state in LIVE:
                    old.retired = True
                nxt.max_lock = max(nxt.max_lock, old.max_lock)
                nxt.last_lock_at = max(nxt.last_lock_at, old.last_lock_at)
                self.out.archived.append(asdict(old))
            self.out.chans[origin] = nxt
            self.out.save()
        ev = {"event": "ch2_switch", "provider": origin, "from": old.p().channel_id if old is not None else "",
              "to": nxt.p().channel_id, "why": why}
        self.events.append(ev)
        return nxt

    def _no_channel(self, origin: str, oc: Optional[OutChannel]) -> str:
        """Why there is no open ch2 to `origin`, for the client (AGP-056: a refusal names its cause)."""
        if oc is None:
            with self.out.lock:
                pt = self.out.origins.get(origin)
                other = [k for k in (self.out.live_keys(pt) if pt else []) if k != origin]
            if other:
                return (f"no open channel to that provider: its payTo has a ch2 at {other[0]}, another provider "
                        f"process (a ch2 serves the origin it was opened at)")
            return "no open channel to that provider"
        if oc.state == "funded" and oc.rolled_from:
            return "no open channel to that provider: its ch2 is a rollover the provider takes once it confirms"
        return f"no open channel to that provider: its ch2 is {oc.state}"

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
                with self.out.lock:                   # the settle floor counts it (AGP-056): this ch2 is rolled
                    oc.max_lock = max(oc.max_lock, int(d))        # over (or refilled) as soon as it is due
                    self.out.save()
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
            view = self._void(st1, oc, lock1, "no reveal within revealTimeoutSec",
                              block="the provider did not reveal a lock in time")
            return self._err("route_failed", "provider did not reveal within revealTimeoutSec", status=502, **view)
        if "error" in ans:
            view = self._void(st1, oc, lock1, f"provider refused: {ans['error']}", block="")
            self.stats["refused"][ans["error"]] = self.stats["refused"].get(ans["error"], 0) + 1
            code = ans["error"] if safe_code(ans["error"]) else "provider_error"
            return self._err("route_failed", f"provider refused the lock: {code}"
                             + (f" ({ans['detail']})" if ans.get("detail") else ""), providerError=ans["error"],
                             status=502, **view)
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
        pl["auth"] = request_auth(key, p2.channel_id, seq, pl["cum"], None, request_digest_v2("POST", oc.origin + ROUTE_LOCK_PATH, body))
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
            # the detail is the provider's free text (untrusted): printable ASCII only, bounded
            det = doc.get("detail")
            det = "".join(ch for ch in det[:160] if " " <= ch <= "~") if isinstance(det, str) else ""
            code = doc["error"][:40]
            if det.startswith(code):                      # str(ChannelError) leads with its code
                det = det[len(code):].lstrip(": ")
            return {"error": code, "detail": det}
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
        # ch1 first (AGP-073): a stop between the two leaves the ch2 lock pending, which the provider's
        # answer or its close completes again; the other order left a ch1 lock with no ch2 lock, which
        # the watcher's sweep would drop unpaid
        done = self._complete_ch1(ch1, pend["lockId"], t, via="provider")
        with self.out.lock:
            if oc.pending.get("lockId") == pend["lockId"]:
                oc.signed = max(oc.signed, pend["cum"])
                oc.routed += pend["d"]
                oc.max_lock, oc.last_lock_at = max(oc.max_lock, int(pend["d"])), round(time.time(), 3)
                oc.pending = {}
                self.out.save()
        return done

    def _complete_ch1(self, ch1: str, lock_id: str, t: int, via: str) -> Optional[dict]:
        """Complete ch1's lock `lock_id` (its current one or a written-off one) with t + r. A lock it
        completed already gets the same answer again (a stop between this and the ch2 write)."""
        ib = self.inbound
        with ib.ledger.lock:
            st1 = ib.ledger.channels.get(ch1)
            if st1 is None:
                return None
            ex = st1.extra or {}
            lock1 = ex.get("route_lock") if (ex.get("route_lock") or {}).get("lockId") == lock_id else None
            stale = False
            if lock1 is None:
                lock1 = next((s for s in ex.get("stale_locks", []) if s["lockId"] == lock_id), None)
                stale = True
            if lock1 is None:
                done = (ex.get("route_done") or {}).get(lock_id)
                return done or next((r for r in ex.get("recovered", []) if r.get("lockId") == lock_id), None)
            s1 = (t + int(lock1["r"], 16)) % adaptor.N
            # ch1 closed below this lock (an operator's close, or the margin close past its wait): the
            # provider is paid and the client is not charged. Never counted as routed (AGP-064 H1)
            closed_below = bool(st1.closed_txid) and st1.best_cum < lock1["cum"]
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
                # a held lock is in the base already (AGP-064); one written off before that is counted
                # once it is our best state
                aft = lock1.get("after")
                if aft and not isinstance(lock1.get("hold"), dict) and st1.best_cum == lock1["cum"]:
                    for k, a in COUNTERS:
                        ex[k] = max(int(ex.get(k, 0)), aft[a])
            elif closed_below:
                ex["route_lock"] = None
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
        if closed_below:
            self.stats["uncollected"] += 1
            self.events.append({"event": "lock_uncollected", "chan": ch1, "lockId": lock_id, "cum": lock1["cum"],
                                "closedAt": st1.best_cum, "close": st1.closed_txid})
            return ans
        self.stats["routed"] += 1
        if lock1["floor"]:
            self.stats["floor"] += 1
        return ans

    def _void(self, st1, oc: OutChannel, lock1: dict, why: str, block: str) -> dict:
        """Write both locks off. If the ch2 pre-signature may have left (the lock was pending on ch2),
        they are kept for on-chain recovery, and ch1's lock stays in its base until that ch2 resolves
        (AGP-064 H2): a later lock is quoted above it, so a t read off the ch2 close later still
        collects, and routing over that ch2 or rolling it over waits. Otherwise nothing can complete
        the lock and ch1's is dropped. Returns ch1's view for the client when the lock is held."""
        ib = self.inbound
        with self.out.lock:
            pend_id = None
            if oc.pending:
                # a ch2 already resolved for good (its close or refund confirmed) can pay nothing more
                pend_id = None if oc.final else oc.pending.get("lockId")
                oc.stale.append({**oc.pending, "voided": round(time.time(), 3), "why": why})
                oc.pending = {}
            if block:
                oc.blocked = block
            self.out.save()
        view, held = {}, False
        with ib.ledger.lock:
            st1 = ib.ledger.channels[st1.params.channel_id]
            ex = st1.extra or {}
            rl = ex.get("route_lock")
            if rl:
                ex["route_lock"] = None
                if pend_id is not None and rl.get("lockId") == pend_id:
                    rl = {**rl, "voided": round(time.time(), 3)}
                    hold_in_base(ex, rl)
                    ex.setdefault("stale_locks", []).append(rl)
                    held = True
            st1.extra = ex
            ib.ledger.save(st1)
            if held:
                view = ch1_view(st1)
        self.events.append({"event": "void", "provider": oc.origin, "lockId": lock1.get("lockId"), "why": why,
                            "blocked": bool(block), "held": held})
        return view

    def _release_unpaid(self, locks: list) -> list:
        """AGP-064: written-off locks whose ch2 resolved without paying them (a confirmed refund, a
        confirmed close that does not reveal their t). Each (ch1, lockId) leaves ch1's stale_locks, and
        its hold leaves the base: the client is quoted below its best state again (the floor), so what
        it paid ahead for that lock pays its next ones. The lockId goes on ch1's `released` list, the
        last 64, for the client to resync on."""
        out, ib = [], self.inbound
        with ib.ledger.lock:
            for ch1, lid in locks:
                st1 = ib.ledger.channels.get(ch1)
                if st1 is None:
                    continue
                ex = st1.extra or {}
                gone = next((s for s in ex.get("stale_locks", []) if s.get("lockId") == lid), None)
                if gone is None:
                    continue
                ex["stale_locks"] = [s for s in ex["stale_locks"] if s is not gone]
                ev = {"event": "lock_released", "chan": ch1, "lockId": lid, "held": False}
                hold = gone.get("hold")
                if isinstance(hold, dict):
                    for k, a in COUNTERS:
                        ex[k] = max(0, int(ex.get(k, 0)) - int(hold.get(a, 0)))
                    ex["released"] = (list(ex.get("released", [])) + [lid])[-64:]
                    ev.update(held=True, hold=hold)
                st1.extra = ex
                ib.ledger.save(st1)
                out.append(ev)
        self.events.extend(out)
        return out

    def _release_stale(self, oc: OutChannel) -> list:
        """Release the written-off locks still on `oc` (its ch2 resolved without revealing them) and
        clear them from the ch2 record."""
        with self.out.lock:
            locks = [(s.get("ch1"), s.get("lockId")) for s in oc.stale]
            if not locks:
                return []
            oc.stale = []
            self.out.save()
        return self._release_unpaid(locks)

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

        One live ch2 per origin (AGP-056): if this origin already has a live ch2 to the payTo its /terms
        name, nothing is funded and that ch2 is returned; if its next ch2 was funded ahead (AGP-057), that
        one takes the place of a ch2 that is no longer live. Another origin under the same payTo is another
        provider process with its own ledger: it gets its own ch2, up to ch2_max_per_pay_to live ch2s
        for that key (ChannelError pay_to_limit beyond it; nothing is funded)."""
        origin = canon_origin(origin)
        cur = self.out.chans.get(origin)
        if cur is not None and cur.state == "funding":
            raise ChannelError("ch2_funding", f"a ch2 to {origin} is being funded (the watcher reconciles it)")
        terms = self._terms(origin)
        cap, blocks = self.ch2_terms(terms, capacity, expiry_blocks)
        pay_to = str(terms["payTo"]).lower()
        with self.out.lock:
            self.out.origins[origin] = pay_to
            own = self.out.chans.get(origin)
            ahead = self.out.next_chans.get(origin)
            self.out.save()
        if own is not None and own.state in LIVE and own.pay_to.lower() == pay_to:
            if own.state == "funding":
                raise ChannelError("ch2_funding", f"a ch2 to {origin} is being funded (the watcher reconciles it)")
            return own
        if ahead is not None and ahead.pay_to.lower() == pay_to:
            # its next ch2 is funded already (AGP-057): that one replaces the closed one, nothing is funded
            nxt = self._promote(origin, "refill")
            if nxt is not None:
                return nxt
        return self._fund_ch2(origin, terms, cap, self.rpc.getblockcount() + blocks)

    def _terms(self, origin: str) -> dict:
        """GET the provider's /terms: a JSON object with `extra` that offers the close-fee payer this hub
        funds ch2s with."""
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
        return terms

    def connect_next(self, origin: str, capacity: int = None, expiry_blocks: int = None) -> OutChannel:
        """Fund the origin's NEXT ch2 from the hub's wallet while its live one still routes (AGP-057: the
        default `refill_ahead` hook). It opens at the provider's minConf (the watcher) and takes over at
        the switch. At most one per origin: an origin that has one gets it back and nothing is funded.

        Refused, nothing funded: no_live_ch2 (the origin has no funded or open ch2: `connect` funds one),
        pay_to_changed (its /terms now name another payTo than the live ch2's), liquidity_cap (the live
        and the next ch2 both count), and connect's bad_terms / bad_fee_payer / pay_to_limit."""
        origin = canon_origin(origin)
        with self.out.lock:
            cur, nxt = self.out.chans.get(origin), self.out.next_chans.get(origin)
        if nxt is not None:
            if nxt.state == "funding":
                raise ChannelError("ch2_funding", f"the next ch2 to {origin} is being funded (the watcher reconciles it)")
            return nxt
        if cur is None or cur.state not in ("funded", "open"):
            raise ChannelError("no_live_ch2", f"{origin} has no live ch2 to fund ahead of")
        terms = self._terms(origin)
        cap, blocks = self.ch2_terms(terms, capacity, expiry_blocks)
        if str(terms["payTo"]).lower() != cur.pay_to.lower():
            raise ChannelError("pay_to_changed", f"{origin} now names another payTo than its live ch2's")
        return self._fund_ch2(origin, terms, cap, self.rpc.getblockcount() + blocks, ahead=True)

    def _fund_ch2(self, origin: str, terms: dict, cap: int, expiry: int, ahead: bool = False) -> OutChannel:
        """Write-ahead (AGP-037): the ch2's key and params are on disk, state `funding`, before the fund
        hook runs, and the cap check and that record are one step under the book's lock. `ahead`
        (AGP-057): the record is the origin's next ch2 (`next_chans`), beside its live one."""
        secret = secrets.randbelow(adaptor.N - 1) + 1
        pub = ecc.pubkey(secret).hex()
        p = ChannelParams.derive(terms["payTo"], pub, expiry, int(terms["extra"]["closeFeeSat"]), network=self.network,
                                 close_fee_payer=self.config.ch2_close_fee_payer)
        p.capacity = cap
        self._preflight_ch2(origin, terms, p)
        tip = self.rpc.getblockcount()
        oc = OutChannel(origin, terms["payTo"], p.to_dict(), f"{secret:064x}", "funding",
                        settle_multiple=int(terms["extra"].get("settleMultiple", 20)), terms=terms,
                        opened_at=tip, scanned_to=tip)
        with self.out.lock:
            old = self.out.chans.get(origin)
            if old is not None and old.state == "funding":
                raise ChannelError("ch2_funding", f"a ch2 to {origin} is being funded")
            pay_to = str(terms["payTo"]).lower()
            if ahead:
                # at most one live ch2 plus one next per origin (AGP-057), checked with the insert
                if origin in self.out.next_chans:
                    raise ChannelError("ch2_funding", f"a next ch2 to {origin} exists")
                if old is None or old.state not in LIVE or old.pay_to.lower() != pay_to:
                    raise ChannelError("no_live_ch2", f"{origin} has no live ch2 to fund ahead of")
            elif old is not None and old.state in LIVE and old.pay_to.lower() == pay_to:
                # one live ch2 per origin, checked with the insert (racing connects)
                raise ChannelError("ch2_funding", f"a live ch2 to {origin} exists")
            others = [k for k in self.out.live_keys(pay_to) if k != origin]
            limit = int(self.config.ch2_max_per_pay_to)
            if limit and len(others) >= limit:
                raise ChannelError("pay_to_limit", f"payTo {pay_to[:16]}... has {len(others)} live ch2s "
                                                   f"({', '.join(others[:3])}): ch2_max_per_pay_to {limit}")
            if self.liquidity_cap_sat:
                freed = old.p().capacity if not ahead and old is not None and old.state in LIVE else 0
                if self.committed_sat() - freed + cap > self.liquidity_cap_sat:
                    raise ChannelError("liquidity_cap", f"{self.committed_sat()} + {cap} sat > liquidity_cap_sat "
                                                        f"{self.liquidity_cap_sat}")
            if ahead:
                self.out.next_chans[origin] = oc
            else:
                if old is not None:
                    self.out.archived.append(asdict(old))
                self.out.chans[origin] = oc
            self.out.origins[origin] = pay_to           # also for an embedder that funds without connect
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

    def _preflight_ch2(self, origin: str, terms: dict, p: ChannelParams):
        """Ask the provider whether it opens `p` (not funded yet) for this hub before anything is written
        or funded (review C2, AGP-073): a refusal after the funding locks the capacity until the refund. A
        provider from before the preflight answers bad_request (no outpoint), having passed the terms it
        checks before the outpoint: that alone lets the funding go ahead."""
        body = {"x402Version": 2, "network": self.network, "preflight": True,
                "channel": {"capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub, "payerSpk": p.payer_spk,
                            "redeemScript": p.script.hex(),
                            **({"closeFeePayer": p.close_fee_payer} if p.close_fee_payer != "payer" else {})},
                "hub": {"payTo": self.pay_to}}
        st, _, raw = self.http("POST", origin + terms["extra"].get("openUrl", "/x402/xbt-channel/open"), json.dumps(body).encode(),
                               {"Content-Type": "application/json"})
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            doc = {}
        if st != 200:
            code = doc.get("error") if isinstance(doc.get("error"), str) and safe_code(doc.get("error")) else "provider_error"
            if code == "bad_request":
                return
            det = "".join(ch for ch in str(doc.get("detail", ""))[:160] if " " <= ch <= "~")
            self.events.append({"event": "ch2_preflight_refused", "provider": origin, "error": code, "detail": det})
            raise ChannelError(code, f"{origin} would not open this ch2: {det}")
        if doc.get("preflight") is not True:
            raise ChannelError("bad_open", f"{origin} did not answer the open preflight")
        if doc.get("closeFeePayer", "payer") != p.close_fee_payer:
            raise ChannelError("bad_fee_payer", f"{origin} would open this ch2 with another closeFeePayer")

    def _funded(self, oc: OutChannel, txid: str, vout: int, cap: int):
        p = oc.p()
        p.funding_txid, p.funding_vout, p.capacity = txid, int(vout), int(cap)
        with self.out.lock:
            oc.params, oc.state = p.to_dict(), "funded"
            oc.fund_txid, oc.fund_vout = txid, int(vout)
            oc.refund_hex = p.refund_tx(int(oc.secret, 16)).hex()   # fallback; the watcher refunds at its own fee
            self.out.save()

    def _wallet_sends(self, oc: OutChannel) -> list:
        """What the fund wallet knows of sends to this ch2's address: [{txid, vout, sats, confirmations,
        abandoned}] (listtransactions + gettransaction; confirmations < 0: conflicted). The record's
        own fund_txid is looked up first. [] without a wallet."""
        p = oc.p()
        addr = segwit_address(self.hrp, p.spk)
        txids = [oc.fund_txid] if oc.fund_txid else []
        try:
            for t in self.wallet.listtransactions("*", 1000, 0, True) or []:
                if t.get("category") == "send" and t.get("address") == addr and t.get("txid") not in txids:
                    txids.append(t["txid"])
        except Exception as e:  # noqa: BLE001 - no wallet on this RPC handle: the chain checks still run
            sys.stderr.write(f"hub: listtransactions for {oc.origin}: {e}\n")
        out = []
        for txid in txids:
            try:
                wt = self.wallet.gettransaction(txid, True, True) or {}
            except Exception:  # noqa: BLE001 - not the wallet's (e.g. an embedder's own fund hook)
                wt = {}
            vout, sats = (oc.fund_vout, None) if txid == oc.fund_txid else (None, None)
            for o in (wt.get("decoded") or {}).get("vout", []):
                if str((o.get("scriptPubKey") or {}).get("hex", "")).lower() == p.spk.hex():
                    vout, sats = int(o["n"]), round(float(o["value"]) * 1e8)
                    break
            if vout is None:
                continue
            out.append({"txid": txid, "vout": vout, "sats": sats,
                        "confirmations": int(wt.get("confirmations", 0) or 0),
                        "abandoned": any(d.get("abandoned") for d in wt.get("details", []) or [])})
        return out

    def _in_mempool(self, txid: str) -> bool:
        try:
            return bool(self.rpc.getmempoolentry(txid))
        except Exception:  # noqa: BLE001 - "Transaction not in mempool"
            return False

    def _utxo_sats(self, txid: str, vout: int) -> Optional[int]:
        """gettxout incl. the mempool: the output's sats while it is unspent, else None."""
        u = self.rpc.gettxout(txid, int(vout), True)
        return round(float(u["value"]) * 1e8) if u else None

    def _reconcile_funding(self, oc: OutChannel, tip: int) -> list:
        """A `funding` record (the fund hook raised, or the hub stopped mid-fund). Where the funding may be
        (AGP-045, not only scantxoutset, which sees the confirmed UTXO set only): the sends the wallet
        knows (gettransaction), each checked with gettxout incl. the mempool and getmempoolentry, then
        scantxoutset (a fund hook outside the wallet). Found, in a block or the mempool -> funded, and the
        open goes on once it has minConf. Not found within funding_timeout_blocks -> dropped (archived with
        its key): a send the wallet still knows (not conflicted or abandoned) is watched while dropped,
        and refunded at expiry if it confirms late; a genuinely failed send is final."""
        p = oc.p()
        sends = self._wallet_sends(oc)
        pending = None
        for w in sends:
            sats = self._utxo_sats(w["txid"], w["vout"])
            if sats is not None and sats >= DUST:
                return self._recovered(oc, w["txid"], w["vout"], sats)
            if w["confirmations"] < 0 or w["abandoned"]:
                continue                                # conflicted or abandoned: never confirms
            if pending is None or self._in_mempool(w["txid"]):
                pending = w
        try:
            r = self.rpc.scantxoutset("start", [f"raw({p.spk.hex()})"]) or {}
        except Exception as e:  # noqa: BLE001 - a node without scantxoutset: the wallet checks above
            sys.stderr.write(f"hub: scantxoutset for {oc.origin}: {e}\n")
            r = {}
        hits = [u for u in r.get("unspents", []) if round(float(u.get("amount", 0)) * 1e8) >= DUST]
        if hits:
            u = hits[0]
            return self._recovered(oc, u["txid"], int(u["vout"]), round(float(u["amount"]) * 1e8))
        if tip - oc.opened_at < self.config.funding_timeout_blocks:
            return []
        with self.out.lock:
            oc.state = "dropped"
            if pending is not None:                     # its send may still confirm: keep watching it
                oc.fund_txid, oc.fund_vout = pending["txid"], int(pending["vout"])
            else:
                oc.final = True
            self.out.archived.append(asdict(oc))
            if self.out.chans.get(oc.origin) is oc:
                del self.out.chans[oc.origin]
            elif self.out.next_chans.get(oc.origin) is oc:
                del self.out.next_chans[oc.origin]
            self.out.save()
        ev = {"event": "ch2_funding_dropped", "provider": oc.origin, "error": oc.fund_error,
              **({"watching": oc.fund_txid} if pending is not None else {})}
        self.events.append(ev)
        return [ev]

    def _recovered(self, oc: OutChannel, txid: str, vout: int, sats: int) -> list:
        self._funded(oc, txid, vout, sats)
        ev = {"event": "ch2_funding_recovered", "provider": oc.origin, "chan": oc.p().channel_id, "txid": txid}
        self.events.append(ev)
        return [ev]

    def _reconcile_dropped(self, oc: OutChannel, tip: int) -> list:
        """A dropped funding whose send is known (AGP-045). Its output appears (it confirmed late, or is
        back in the mempool) -> funded, in the archive: never opened, refunded at expiry by the reconcile
        like any unused ch2 (event ch2_funding_late). The wallet says it can never confirm (conflicted or
        abandoned) -> final (event ch2_funding_failed)."""
        sats = self._utxo_sats(oc.fund_txid, oc.fund_vout)
        if sats is not None and sats >= DUST:
            p = oc.p()
            p.funding_txid, p.funding_vout, p.capacity = oc.fund_txid, int(oc.fund_vout), sats
            oc.params, oc.state = p.to_dict(), "funded"
            oc.refund_hex = p.refund_tx(int(oc.secret, 16)).hex()
            ev = {"event": "ch2_funding_late", "provider": oc.origin, "chan": p.channel_id, "txid": oc.fund_txid,
                  "capacity": sats, "refundAt": p.expiry}
            self.events.append(ev)
            return [ev]
        w = next((w for w in self._wallet_sends(oc) if w["txid"] == oc.fund_txid), None)
        if w is not None and (w["confirmations"] < 0 or w["abandoned"]):
            oc.final = True
            ev = {"event": "ch2_funding_failed", "provider": oc.origin, "txid": oc.fund_txid,
                  "why": "abandoned" if w["abandoned"] else "conflicted"}
            self.events.append(ev)
            return [ev]
        return []

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
            # said, not only returned (AGP-057): a refused open is why a ch2 stays `funded`
            why = "".join(ch for ch in raw[:160].decode("latin-1") if " " <= ch <= "~")
            sys.stderr.write(f"hub: open {p.channel_id} at {oc.origin}: HTTP {st} {why}\n")
            return False
        try:
            doc = json.loads(raw)
            echoed = doc.get("closeFeePayer", "payer")
        except (ValueError, AttributeError):
            doc, echoed = {}, None
        if echoed != p.close_fee_payer:
            # every state we would sign would fail at the provider: never route over this channel
            with self.out.lock:
                oc.blocked = f"the provider opened ch2 with closeFeePayer {echoed!r}"
                self.out.save()
            return False
        zc = {}
        z = doc.get("zeroConf")
        if isinstance(z, dict):
            # AGP-053: the provider took this ch2 unconfirmed (a rollover child), bounded; a malformed
            # bound routes nothing until it confirms
            try:
                if not isinstance(z["parent"], str) or any(isinstance(z[k], float) for k in ("maxCum", "until")):
                    raise TypeError("zeroConf")
                zc = {"parent": z["parent"], "maxCum": int(z["maxCum"]), "until": int(z["until"]), "confirmed": False}
                if zc["maxCum"] < 0 or zc["until"] < 0:
                    raise ValueError("zeroConf")
            except (KeyError, TypeError, ValueError):
                zc = {"parent": "", "maxCum": 0, "until": 0, "confirmed": False}
        with self.out.lock:
            oc.state, oc.zero_conf = "open", zc
            self.out.save()
        ev = {"event": "ch2_open", "provider": oc.origin, "chan": p.channel_id, "capacity": p.capacity}
        if zc:
            ev["zeroConf"] = zc["maxCum"]
        self.events.append(ev)
        return True

    def rollover(self, oc: OutChannel) -> dict:
        """One tx pays the provider its balance and funds the next ch2 (rollover instead of close). The
        next ch2's key is written ahead (`oc.next`), and its funding txid is known before the request
        leaves, so a lost answer is finished by the watcher when that tx spends the funding."""
        # AGP-064 (H2): a rollover spends the funding a written-off lock's pre-signature is on, and its
        # secret could no longer be read off a close
        if oc.pending or oc.stale:
            raise ChannelError("lock_pending", "a lock on this ch2 is pending or written off and unresolved")
        p = oc.p()
        amount = oc.signed
        next_cap = p.rollover_next_capacity(amount)      # payee-pays: capacity - amount, the fee is the provider's
        min_cap = int(oc.terms["extra"]["minCapacity"])
        tip = self.rpc.getblockcount()
        _, blocks = self.ch2_terms(oc.terms)
        expiry = tip + blocks
        # too small to keep: under the provider's minimum, or (AGP-056) it could not take one more lock of
        # the size this provider is paid in (it would sit exhausted and unsigned until its expiry)
        if next_cap < max(min_cap, p.min_amount) or (oc.max_lock and next_cap - p.payer_fee < max(oc.max_lock, p.min_amount)):
            nxt = self.out.next_chans.get(oc.origin)
            if nxt is not None and nxt.state in ("funding", "funded") and not self._exhausted(oc, max(oc.max_lock, 1)):
                # AGP-057: its next ch2 is funded but not open yet, and this one still takes a lock: it is
                # kept until the next one is usable or it is drained (closing it now would pause routing)
                return {"event": "ch2_wait_next", "provider": oc.origin, "chan": p.channel_id}
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
                         opened_at=tip, scanned_to=tip, rolled_from=p.channel_id, max_lock=oc.max_lock,
                         last_lock_at=oc.last_lock_at, rolled_at=round(time.time(), 3))
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
        ev = self._finish_rollover(oc, amount)
        new = self.out.chans.get(oc.origin)
        if new is not None and new.rolled_from == p.channel_id and not new.fund_seen:
            # a hub on the provider's node sees it at once (AGP-056); the watcher's reconcile looks again
            with contextlib.suppress(OSError, ValueError, KeyError, RPCError):
                if self.rpc.gettxout(txid, 1, True) is not None:
                    with self.out.lock:
                        new.fund_seen = True
                        self.out.save()
        # make-before-break (AGP-053): open the next ch2 now, still under this provider's mutex, so the
        # next lock goes over it; a provider that wants confirmations first refuses, and the watcher
        # opens it at minConf
        self._open_child(self.out.chans.get(oc.origin), p.channel_id)
        return ev

    def _open_child(self, new: Optional[OutChannel], parent: str) -> bool:
        """Open a rollover child before it confirms (AGP-053), at most once a block. Never raises."""
        if not self.zero_conf_rollover or new is None or new.state != "funded" or new.rolled_from != parent:
            return False
        try:
            key = (new.p().channel_id, self.rpc.getblockcount())
            if key in self._zc_tried:
                return False
            self._zc_tried = {k for k in self._zc_tried if k[1] >= key[1] - 1} | {key}
            return self._open(new)
        except (OSError, ValueError, KeyError, ChannelError) as e:
            self.events.append({"event": "ch2_open_failed", "provider": new.origin, "error": f"{type(e).__name__}: {e}"[:200]})
            return False

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
        bad_close_reply and changes nothing: the watcher reads the real close off the chain. A good reply
        makes the ch2 `closing` (AGP-045): it is `closed` once the watcher sees the close confirm."""
        from .x402_channel import close_message
        p = oc.p()
        if not oc.signed and not oc.stale:
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
            oc.state, oc.close_prev, oc.close_txid = "closing", oc.state, txid
            self.out.save()
        ev = {"event": "ch2_close", "provider": oc.origin, "chan": p.channel_id, "txid": txid, "amount": cum,
              "payeeFee": p.payee_fee, "payeeNet": max(0, cum - p.payee_fee)}
        self.events.append(ev)
        if refill and self.out.next_chans.get(oc.origin) is not None:
            # funded ahead (AGP-057): the next ch2 takes over, nothing more to fund
            nxt = self._promote(oc.origin, "closed")
            if nxt is not None:
                ev["next"] = nxt.p().channel_id
        elif refill:
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
        if oc.state not in ("funded", "open", "closing", "closed") or oc.pending or not oc.p().funding_txid:
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
        skipped = []
        for origin, oc in list(self.out.chans.items()):
            try:
                acts = self._watch_out(oc, tip)
                if acts is None:
                    skipped.append((origin, oc))
                else:
                    actions += acts
            except Exception as e:  # noqa: BLE001 - one channel never stops the rest
                self._watch_error(origin, "watch", e)
        # a provider streaming locks holds its mutex most of the time, and a tick in step with its locks
        # could miss every gap (a rollover never due to run, AGP-053): wait for it between two locks,
        # within a budget per tick
        until = time.time() + WATCH_WAIT_BUDGET
        for origin, oc in skipped:
            try:
                actions += self._watch_out(oc, tip, wait=max(0.0, min(WATCH_WAIT_ONE, until - time.time()))) or []
            except Exception as e:  # noqa: BLE001
                self._watch_error(origin, "watch", e)
        # AGP-057: every origin's next ch2 (reconciled, opened at minConf, taking over from a live one that
        # is gone or idle), then the ones due to be funded ahead. Neither needs the origin's mutex until a
        # switch: a next ch2 takes no lock before it
        with self.out.lock:
            nexts = list(self.out.next_chans.items())
        for origin, oc in nexts:
            try:
                actions += self._watch_next(origin, oc, tip)
            except Exception as e:  # noqa: BLE001
                self._watch_error(origin, "next", e)
        for origin in list(self.out.chans):
            try:
                actions += self._refill_ahead_due(origin, tip)
            except Exception as e:  # noqa: BLE001
                self._watch_error(origin, "refill_ahead", e)
        with self.out.lock:
            archived = [(i, r) for i, r in enumerate(self.out.archived) if watched(r)]
        for i, rec in archived:                             # replaced ch2s are still the hub's coins
            try:
                oc = OutChannel(**rec)
                acts = self._reconcile_dropped(oc, tip) if oc.state == "dropped" else self._reconcile(oc, tip)
                if oc.retired:
                    acts += self._close_retired(oc, tip)
                with self.out.lock:
                    self.out.archived[i] = asdict(oc)
                    self.out.save()
                actions += acts
            except Exception as e:  # noqa: BLE001
                self._watch_error(rec.get("origin", "?"), "archived", e)
        # AGP-073: the ch1 locks a stop left (before a margin close, so one held is in that close)
        with self.inbound.ledger.lock:
            locked = [c for c, st in self.inbound.ledger.channels.items()
                      if not st.closed_txid and (st.extra or {}).get("route_lock")]
        for ch1 in locked:
            ev = self._sweep_orphan_lock(ch1)
            if ev is not None:
                actions.append(ev)
        try:
            actions += [{"event": "ch1_close", "txid": t} for t in self.inbound.close_due()]
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"hub watcher ch1: {e}\n")
        return actions

    def _watch_next(self, origin: str, oc: OutChannel, tip: int) -> list:
        """AGP-057: one origin's next ch2. A `funding` one is reconciled like any (the fund hook failed); a
        funded one is checked against the chain and opened at the provider's minConf (never unconfirmed: a
        wallet funding is the hub's to spend again). One that is no longer live (refunded at its expiry,
        its funding spent) leaves for the archive. It takes over, under the origin's mutex, when the live
        ch2 is gone (closing, closed, refunded, dropped), or when both are open and the live one has had no
        lock for settle_idle seconds, so two ch2s do not stay committed to an idle provider."""
        if self.out.next_chans.get(origin) is not oc:
            return []
        if oc.state == "funding":
            return self._reconcile_funding(oc, tip)
        out = []
        try:
            out += self._reconcile(oc, tip)
        except Exception as e:  # noqa: BLE001
            self._watch_error(origin, "reconcile", e)
        if oc.state == "funded":
            p = oc.p()
            utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
            if utxo and utxo.get("confirmations", 0) >= int(oc.terms["extra"].get("minConf", 1)) and self._open(oc):
                out.append({"event": "ch2_open", "provider": origin, "next": True})
        if oc.state not in LIVE:
            with self.out.lock:
                if self.out.next_chans.get(origin) is oc:
                    del self.out.next_chans[origin]
                    self.out.archived.append(asdict(oc))
                    self.out.save()
            return out

        def due():
            cur = self.out.chans.get(origin)
            if cur is None or cur.state not in LIVE:
                return "the live ch2 is " + (cur.state if cur is not None else "gone")
            idle = time.time() - cur.last_lock_at >= float(self.config.settle_idle)
            return "idle" if cur.state == "open" and oc.state == "open" and not cur.pending and idle else ""
        if due():
            mtx = self.out.mutex_for(origin)
            if mtx.acquire(timeout=WATCH_WAIT_ONE):
                try:
                    why = due()                              # again, under the mutex
                    if why and self._promote(origin, why) is not None:
                        out.append({"event": "ch2_switch", "provider": origin, "why": why})
                finally:
                    mtx.release()
        return out

    def _refill_ahead_due(self, origin: str, tip: int) -> list:
        """AGP-057: fund the origin's next ch2 once its live one's room is under refill_ahead_locks x the
        largest lock routed to that provider (the room is what a rollover child keeps, less the provider's
        minCapacity: a rollover adds no coins). Not for a provider the hub stopped routing to, nor for one with no lock for settle_idle
        seconds. A refusal (the liquidity cap, the provider's /terms) is an event and is tried again next
        block; until a next ch2 is open, the refill follows the close as before."""
        n = int(self.config.refill_ahead_locks)
        hook = self.refill_ahead if n > 0 else None
        if hook is None:
            return []
        with self.out.lock:
            oc = self.out.chans.get(origin)
            if oc is None or oc.state != "open" or oc.blocked or origin in self.out.next_chans or oc.max_lock <= 0:
                return []
            p = oc.p()
            # what the line still takes: a rollover child keeps capacity - signed, and one under the
            # provider's minCapacity is not made (the ch2 is closed instead)
            room = max(0, p.max_amount - max(oc.signed, int((oc.pending or {}).get("cum", 0)))
                       - int(oc.terms["extra"].get("minCapacity", 0)))
            big, chan = int(oc.max_lock), p.channel_id
        if room >= n * big or time.time() - oc.last_lock_at >= float(self.config.settle_idle):
            return []
        if (origin, tip) in self._ahead_tried:
            return []
        try:
            nxt = hook(origin)
        except Exception as e:  # noqa: BLE001 - reported; the live ch2 goes on, the refill follows its close
            self._ahead_tried = {k for k in self._ahead_tried if k[1] >= tip - 1} | {(origin, tip)}
            ev = {"event": "ch2_refill_ahead_failed", "provider": origin, "error": f"{type(e).__name__}: {e}"[:200]}
            self.events.append(ev)
            return [ev]
        ev = {"event": "ch2_refill_ahead", "provider": origin, "live": chan, "room": room, "maxLock": big,
              "next": nxt.p().channel_id if nxt is not None else "", "capacity": nxt.p().capacity if nxt is not None else 0}
        self.events.append(ev)
        return [ev]

    def _close_retired(self, oc: OutChannel, tip: int) -> list:
        """AGP-057: a ch2 its origin's next one replaced (an archived record: it takes no lock any more).
        Ask the provider to close it with the best state, once a block until it answers; the close is then
        reconciled like any (`closing`, `closed` once confirmed). With nothing signed there is nothing to
        close: the hub's refund returns it at its expiry, as for any unused ch2."""
        if oc.state != "open" or oc.pending or (not oc.signed and not oc.stale):
            return []
        key = (oc.p().channel_id, tip)
        if key in self._retire_tried:
            return []
        self._retire_tried = {k for k in self._retire_tried if k[1] >= tip - 1} | {key}
        try:
            return [self.close_ch2(oc)]
        except ChannelError as e:
            ev = {"event": "ch2_retire_failed", "provider": oc.origin, "chan": key[0], "error": str(e)[:200]}
            self.events.append(ev)
            return [ev]

    def _close_written_off(self, oc: OutChannel, tip: int) -> list:
        """AGP-073: the live ch2 holds a written-off lock (its pre-signature may be out), so it takes no lock
        and is not rolled over until that resolves, which left alone is its refund at expiry. Ask the
        provider to close it now, once a block until it does: a close that shows t pays the hub on ch1, one
        that confirms without t releases the hold. A provider that refused the lock gets a new ch2 (its next
        one, funded ahead, takes over at once and the old one is closed as retired); one the hub stopped
        routing to (no reveal in time) does not."""
        chan = oc.p().channel_id
        key = (chan, tip)
        if key in self._stale_tried:
            return []
        self._stale_tried = {k for k in self._stale_tried if k[1] >= tip - 1} | {key}
        refill = not oc.blocked
        try:
            nxt = self.out.next_chans.get(oc.origin)
            if refill and nxt is not None and nxt.state == "open":
                new = self._promote(oc.origin, "written_off")
                return [] if new is None else [{"event": "ch2_switch", "provider": oc.origin, "from": chan,
                                                "to": new.p().channel_id, "why": "written_off"}]
            ev = self.close_ch2(oc, refill=refill)
            ev["why"] = "written_off"
            return [ev]
        except ChannelError as e:
            ev = {"event": "ch2_written_off_close_failed", "provider": oc.origin, "chan": chan, "error": str(e)[:200]}
            self.events.append(ev)
            return [ev]

    def _watch_error(self, origin: str, step: str, e: Exception):
        msg = f"{type(e).__name__}: {e}"[:200]
        sys.stderr.write(f"hub watcher {origin} ({step}): {msg}\n")
        self.events.append({"event": "ch2_watch_error", "provider": origin, "step": step, "error": msg})

    def _watch_out(self, oc: OutChannel, tip: int, wait: float = 0.0) -> Optional[list]:
        """None when a route request in flight owns this ch2 (its mutex) past `wait`: never race it
        for the same lock."""
        mtx = self.out.mutex_for(oc.origin)
        if not (mtx.acquire(timeout=wait) if wait > 0 else mtx.acquire(blocking=False)):
            return None
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
            elif oc.rolled_from and self._open_child(oc, oc.rolled_from):
                # a rollover child not opened right after the rollover (a lost reply, a restart)
                out.append({"event": "ch2_open", "provider": oc.origin, "zeroConf": True})
            return out
        if oc.state != "open":
            return out
        if oc.zero_conf:
            out += self._zero_conf_tick(oc, p)
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
        if oc.stale:
            # AGP-064: no rollover until the written-off locks resolve (the provider's close, or the
            # refund); AGP-073: the hub asks for that close now
            return out + self._close_written_off(oc, tip)
        # settlement: the provider's net payout >= its settleMultiple x closeFee (on a payee-pays ch2 the
        # close fee is the provider's, so it counts against the payout), or near ch2's close margin as
        # the provider counts it (it co-signs only then): roll over. Past expiry the refund took over.
        ex = oc.terms.get("extra", {})
        due = self._settle_due(oc, p)
        margin = int(ex.get("closeMarginBlocks", self.close_margin))
        grace = min(self.rollover_margin, int(ex.get("rolloverGraceBlocks", self.rollover_margin)))
        near = tip >= p.expiry - margin - grace
        # an unconfirmed rollover child is not rolled over again before it confirms (AGP-053)
        unconfirmed = oc.zero_conf and not oc.zero_conf.get("confirmed")
        if (due or near) and oc.signed >= p.min_amount and not oc.pending and tip < p.expiry and not unconfirmed:
            out.append(self.rollover(oc))
        return out

    def _settle_due(self, oc: OutChannel, p: ChannelParams) -> bool:
        """The ch2 is due to roll over: the provider's net payout is at its threshold (settleMultiple x
        closeFee: the least it co-signs) and, while locks keep coming (AGP-056), the ch2 has taken
        settle_lock_multiple x the largest lock routed to it, so a provider whose locks are larger than
        its threshold is not rolled over on every lock. Never later than the point where another lock of that size would not
        fit (the ch2 would be exhausted), and at once after settle_idle seconds without a lock."""
        if not settle_due(p, oc.signed, oc.settle_multiple):
            return False
        k, big = int(self.config.settle_lock_multiple), int(oc.max_lock)
        if k <= 0 or big <= 0:
            return True
        if time.time() - oc.last_lock_at >= float(self.config.settle_idle):
            return True
        return oc.signed >= k * big or oc.signed + big > p.max_amount

    def _zero_conf_tick(self, oc: OutChannel, p: ChannelParams) -> list:
        """A ch2 the provider took unconfirmed (AGP-053): confirmed with minConf, or unconfirmed again (a
        reorg), and the provider's bounds apply again."""
        utxo = self.rpc.gettxout(p.funding_txid, p.funding_vout, False)
        now = bool(utxo) and utxo.get("confirmations", 0) >= int(oc.terms["extra"].get("minConf", 1))
        if now == bool(oc.zero_conf.get("confirmed")):
            return []
        with self.out.lock:
            oc.zero_conf = {**oc.zero_conf, "confirmed": now}
            self.out.save()
        ev = {"event": "ch2_zero_conf_confirmed" if now else "ch2_zero_conf_reorg", "provider": oc.origin,
              "chan": p.channel_id}
        self.events.append(ev)
        return [ev]

    def _reconcile(self, oc: OutChannel, tip: int) -> list:
        """Check one non-final ch2's funding against the chain (AGP-037).
        unspent: refund it when due; rebroadcast our refund if it left the mempool. spent by the
        rollover we wrote ahead: finish it. spent by our refund: final once confirmed. spent by
        anything else (the provider's close): read the locks' secrets off it; in the mempool it is only
        `closing` (AGP-045: the refund fee stays booked), and once it confirms the ch2 is `closed` with the
        real txid and the refund fee is taken back if our refund lost. A `closing` ch2 whose spender left
        the mempool is `refunded` again if it was (the fee re-booked), else it stays `closing` and is
        refunded at expiry unless the close comes back. Spent, spender not found: with locks outstanding
        leave it (their secrets are on that tx); without, closing (closed once confirmed), txid unknown."""
        if oc.final or oc.state not in NONFINAL:
            return []
        p = oc.p()
        if not p.funding_txid:
            return []
        out = []
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, True) is not None:
            if oc.rolled_from and not oc.fund_seen:          # our node shows the rollover (AGP-056)
                with self.out.lock:
                    oc.fund_seen = True
                    self.out.save()
            if oc.blocked == ROLLOVER_GONE:                  # the rollover is back (AGP-053)
                with self.out.lock:
                    oc.blocked = ""
                    self.out.save()
                out.append({"event": "ch2_rollover_back", "provider": oc.origin, "chan": p.channel_id})
                self.events.append(out[-1])
            if oc.state == "closing" and (oc.close_txid or oc.close_prev == "refunded"):
                out += self._close_vanished(oc)
            if oc.state == "refunded" or self._refund_due(oc, tip):
                # due, or our refund left the mempool: send it (again, or bumped once it waited)
                return out + self._refund(oc, tip)
            return out
        if oc.rolled_from and oc.state in ("funded", "open"):
            gone = self._rollover_gone(oc, p)
            if gone is not None:
                return out + gone
        confirmed = self.rpc.gettxout(p.funding_txid, p.funding_vout, False) is None
        if oc.state == "closing" and oc.close_txid and not (oc.pending or oc.stale) and not oc.refund_txid and confirmed:
            with self.out.lock:                             # the provider's close as it told us, confirmed: done
                oc.state, oc.final = "closed", True
                self.out.save()
            ev = {"event": "ch2_closed", "provider": oc.origin, "chan": p.channel_id, "txid": oc.close_txid, "by": "provider"}
            self.events.append(ev)
            return [ev]
        tx = find_spend(self.rpc, p.funding_txid, p.funding_vout, oc.scanned_to)
        if tx is None:
            # a funded one may not be visible yet; with locks, their secrets are on that tx: wait for it.
            # A closing one closes once the spend confirms, unless it was refunded (the spender may be our
            # refund: the fee stays booked until the spender is found)
            if oc.pending or oc.stale or oc.state not in ("open", "closing"):
                return out
            if oc.state == "closing" and (not confirmed or oc.close_prev == "refunded"):
                return out
            st = "closed" if confirmed else "closing"
            with self.out.lock:
                if oc.state == "open":
                    oc.close_prev, oc.close_txid = "open", ""
                oc.state = st
                self.out.save()
            ev = {"event": "ch2_" + st, "provider": oc.origin, "chan": p.channel_id, "txid": oc.close_txid, "by": "unknown"}
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
                out += self._release_stale(oc)              # the refund proves the written-off locks unpaid
            elif self._bump_due(oc, tip):                   # stuck in the mempool: replace it at a higher fee
                out += self._refund(oc, tip)
            return out
        if oc.pending or oc.stale:
            out += self._from_close(oc, tx)                 # the secrets are on it, confirmed or not
        if not confirmed:
            # in the mempool: it may still be replaced or expire, so the ch2 is only closing and a refund
            # fee stays booked until it confirms
            if oc.state == "closing" and oc.close_txid == spender:
                return out
            with self.out.lock:
                if oc.state != "closing":
                    oc.close_prev = oc.state
                oc.state, oc.close_txid = "closing", spender
                self.out.save()
            ev = {"event": "ch2_closing", "provider": oc.origin, "chan": p.channel_id, "txid": spender, "by": "provider",
                  **({"refundAtRisk": oc.refund_txid} if refund_booked(asdict(oc)) else {})}
            self.events.append(ev)
            out.append(ev)
            return out
        lost = oc.refund_fee if oc.refund_txid else 0
        with self.out.lock:
            oc.state, oc.close_txid, oc.final, oc.next = "closed", spender, True, {}
            if lost:
                oc.refund_fee = 0
            self.out.save()
        ev = {"event": "ch2_closed", "provider": oc.origin, "chan": p.channel_id, "txid": spender, "by": "provider",
              **({"refundLost": oc.refund_txid, "refundFeeReverted": lost} if oc.refund_txid else {})}
        self.events.append(ev)
        out.append(ev)
        out += self._release_stale(oc)          # a confirmed close that did not reveal a written-off lock's t did not pay it
        return out

    def _rollover_gone(self, oc: OutChannel, p: ChannelParams) -> Optional[list]:
        """A rollover child's funding output is not in the UTXO set nor the mempool (AGP-053). The
        rollover tx exists (in the mempool, or its output confirmed): None, the usual reconcile (it was
        spent). The parent is unspent even counting the mempool: the rollover left the mempool (the
        provider, who holds it signed, sends it again), so routing stops (blocked) until it is back. The
        parent was spent by another tx (the provider's own close): this ch2 never existed; it is dropped
        (final) and any secrets of the parent's written-off locks are read off that close."""
        if self.rpc.gettxout(p.funding_txid, p.funding_vout, False) is not None or self._in_mempool(p.funding_txid):
            if not oc.fund_seen:
                with self.out.lock:
                    oc.fund_seen = True
                    self.out.save()
            return None
        ptxid, pvout = oc.rolled_from.split(":")
        pvout = int(pvout)
        if self.rpc.gettxout(ptxid, pvout, True) is not None:
            if oc.blocked == ROLLOVER_GONE:
                return []
            # the provider broadcast it on ITS node: ours may not have it yet (AGP-056). Vanished only if
            # our node showed it before, or still does not after the relay grace
            if not oc.fund_seen and time.time() - oc.rolled_at < float(self.config.rollover_relay_grace):
                return []
            with self.out.lock:
                oc.blocked = ROLLOVER_GONE
                self.out.save()
            ev = {"event": "ch2_rollover_vanished", "provider": oc.origin, "chan": p.channel_id, "parent": oc.rolled_from}
            self.events.append(ev)
            return [ev]
        tx = find_spend(self.rpc, ptxid, pvout, max(0, oc.opened_at - 6))
        if tx is None or tx.txid() == p.funding_txid:
            return None
        spender = tx.txid()
        with self.out.lock:
            oc.state, oc.final, oc.blocked = "dropped", True, f"the rollover was replaced by {spender}"
            self.out.save()
        ev = {"event": "ch2_rollover_replaced", "provider": oc.origin, "chan": p.channel_id, "parent": oc.rolled_from,
              "spender": spender}
        self.events.append(ev)
        out = [ev]
        with self.out.lock:
            found = [(i, OutChannel(**r)) for i, r in enumerate(self.out.archived)
                     if r.get("rolled_to") == p.channel_id and r.get("stale")]
        for i, parent in found:
            out += self._from_close(parent, tx)
            with self.out.lock:
                self.out.archived[i] = asdict(parent)
                self.out.save()
        return out

    def _close_vanished(self, oc: OutChannel) -> list:
        """A `closing` ch2's funding is unspent again: the close left the mempool (replaced, expired) or
        never reached this node. A ch2 that was refunded is refunded again (its fee booked again, and the
        refund goes out once more); any other stays `closing` (the hub never routes over it again) and is
        refunded at expiry unless the provider's close comes back."""
        was = oc.close_txid
        with self.out.lock:
            if oc.close_prev == "refunded":
                oc.state, oc.close_prev = "refunded", ""
            oc.close_txid = ""
            self.out.save()
        ev = {"event": "ch2_close_vanished", "provider": oc.origin, "chan": oc.p().channel_id, "txid": was,
              "state": oc.state, **({"feeRebooked": oc.refund_fee} if oc.state == "refunded" else {})}
        self.events.append(ev)
        return [ev]

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
            # ch1 first, as in _settled (AGP-073)
            res = self._complete_ch1(lk["ch1"], lk["lockId"], t, via=f"ch2 close {tx.txid()}")
            with self.out.lock:
                oc.signed = max(oc.signed, lk["cum"])
                if oc.pending and oc.pending.get("lockId") == lk["lockId"]:
                    oc.routed += lk["d"]
                    oc.max_lock = max(oc.max_lock, int(lk["d"]))
                    oc.pending = {}
                oc.stale = [s for s in oc.stale if s["lockId"] != lk["lockId"]]
                self.out.save()
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
     "wrap_key_file": "~/.config/xbt-hub/hub-wrap-key",   seals the ch2 keys in ch2.json (default <datadir>/hub-wrap-key)
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
    datadir = os.path.expanduser(conf["datadir"])
    wrap_path = os.path.expanduser(conf.get("wrap_key_file") or os.path.join(datadir, WRAP_KEY_FILE))
    if not conf.get("wrap_key_file"):
        sys.stderr.write(f"hub: ch2 wrap key {wrap_path} (beside the state it seals: set wrap_key_file to keep it apart)\n")
    os.makedirs(datadir, exist_ok=True)
    hub = RouteHub(rpc, secret, conf["network"], datadir, fund, cfg, wallet=wallet,
                   refund_to=lambda: wallet.getnewaddress("", "bech32"),   # bech32 whatever the wallet default (AGP-044)
                   wrap_key=WrapKey.load_or_create(wrap_path))
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
