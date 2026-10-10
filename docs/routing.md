# xbt402 hub routing (AGP-021)

> **Experimental** (AGP-064): the hub is not production-ready; do not route funds you cannot lose.
> Since AGP-064 (external review H1, H2): a ch1 close is refused `lock_pending` while a routed lock
> it does not cover is open; a lock completed after ch1 closed below it is not counted as routed; a
> write-off whose ch2 pre-signature may have left stays in ch1's base (`stale_locks[].hold`) and
> blocks routing over, and rollover of, that ch2 until the ch2 closes or is refunded (then the hold
> is released, `released`); `max_lock_sat` defaults to 20,000 and is at most half of `ch2_capacity`.
> The client resyncs on the `held` / `released` lists in the hub's view. Details: xbt-rs README,
> "Hub routing safety (AGP-064)"; tests `tests/security/test_agp064_hub_safety.py`.
> Since AGP-078 (closure audit): a ch1 rollover is refused `lock_pending` exactly as a close is; the
> seq an authentic `/x402/route` or `/x402/xbt-channel/lock` spent is saved before its refusal leaves;
> a `RouteHub` checks its `HubConfig` again when it is built. Details: xbt-rs README, "Hub
> closure-audit fixes (AGP-078)"; tests `tests/security/test_agp078_hub_closure.py`.
> Since AGP-084: a channel whose close or rollover was signed and written ahead (`close_intent`) and
> answered with an error by the node takes no new state (`channel_closing` on a paid call, `/x402/route`
> and `/x402/xbt-channel/lock`): that tx can still confirm. The watcher sends such a close again every
> tick and records a spend the node shows after all; `connect` / `connect_next` refuse `bad_config` when
> `max_lock_sat` is more than half of the capacity the ch2 would be funded with. Limits: a rollover is
> never sent again (its client was told it failed and may no longer hold the next channel's key: it
> rolls over again or closes); a superseded intent that lands after a second failed spend is not
> recorded; a rollover child may be smaller than 2 x `max_lock_sat`. Tests
> `tests/security/test_agp084_hub_leftovers.py`.
> Since AGP-085: (1) the next ch2 a rollover writes ahead (`next`: key, refund) is kept whatever the
> provider answers, and there is one next key per ch2: a later attempt asks under the same key and
> expiry, the watcher adopts whichever attempt spends the funding by its script (output 1), and `next`
> is cleared only when a confirmed spend of the funding is something else (the provider's close, the
> hub's refund). A kept next too old to ask for again (its expiry under `minExpiryBlocks + minConf +
> closeMarginBlocks`) is not replaced: the ch2 is closed and refilled, `next` still kept. A rollover
> adopted over written-off locks waits for its confirmation and then releases them (it shows no t).
> (2) ch1's counters move by what a lock adds (`unitsBy` on the lock record, written at admission),
> on completion and on a hold: a hold released while another lock was in flight no longer comes back
> with it. The client adopts a release that arrives in the same view as a hold or a completion.
> Tests `tests/security/test_agp085_hub.py`.

Implements the AGP-019 design (`~/notes/projects/xbt-agentpay/Research/AGP-019 xbt402 hub routing.md`):
a client pays many providers over ONE channel to a hub, using adaptor-locked states on both hops.
Regtest only. The script, close and watcher are those of xbt402 v1.1; the state format is v1.2's
(`closeFeePayer`, spec §12): ch2 is payee-pays by default, so each provider pays its own settlement
close fee and hub fees price only liquidity and routing (AGP-023). Everything below is additive.

```
client --ch1 (client pays, hub is payee; payer-pays)--> hub --ch2 (hub pays, provider is payee, hub-funded; payee-pays)--> provider
provider: t per window, T = t*G in a payTo-signed invoice      client: tweak r, T1 = T + r*G
ch1: client pre-signs next_cum(routed1, d + f) under T1 -> hub checks 1..7 -> hub pre-signs ch2 under T
provider completes ch2 with t (plain 0x21 state, saved write-ahead) -> t -> hub completes ch1 with t + r
```

## Modules
| module | role |
|---|---|
| `xbt402/adaptor.py` | ECDSA adaptor (AGP-008/014 encoding). Secret scalar mults in libsecp256k1 via coincurve (constant time), else B1's fixed ladder; secret inversions blinded; about 1 ms per presign. No libsecp256k1-zkp binding exists here. |
| `xbt402/route.py` | `route_ok`, `FeeQuote` (hub, signed, expiring) and `fee_due` (the carry), `PriceQuote` and `Invoice` (provider, payTo-signed), `call_auth` / `lock_auth` (client<->provider ECDH key the hub never sees), `RouteSeller` (provider sessions, amsat meter, credit window, `complete_lock`), `find_spend` |
| `xbt402/x402_channel.py` | provider: `offer_route`, routed calls (`ROUTE-AUTH` / `ROUTE-STATE`), `POST /x402/xbt-channel/lock`, `POST /x402/xbt-channel/rollover`, `GET /x402/xbt-channel/terms`, hub binding at open |
| `xbt402/hub.py` | `RouteHub` (library) + `python -m xbt402.hub --config hub.json` (service); `HubConfig` holds every operator choice (fees, fee strategy, liquidity cap, lock caps, timeouts) |
| `xbt402/route_client.py` | `RoutePayer`: one ch1, per-provider sessions, per-window locks off the data path |
| `xbt402/signer.py` | `ChannelSigner.sign_state_adaptor / resolve_lock / void_lock / adopt_lock / recover_lock` (B2 has the same: `agentwallet/routing.py`) |

## Wire
- **Provider 402 on a routed path**, `accepts[0].extra.route`: `{window, lockWait, invoiceTtl, hubs, creditMsat, quote: PriceQuote, lockUrl, settleMultiple, session?, invoice?}`. `session` and `invoice` are present when the request carried `ROUTE-CLIENT: <client route pubkey>`.
- **Routed call**: header `ROUTE-AUTH: b64json{session, seq, auth}`, auth = HMAC(ECDH key, `xbt402/route/call|session|seq|sha256(method|path|body)`). The answer carries `ROUTE-STATE: b64json{session, seq, calls, chargeAmsat, accruedAmsat, paidSat, quote, lastLock{lockId, amount, secret}, invoice, sig}`, signed by payTo. A 402 with `error: route_credit` means the provider stopped serving the client (its credit ran out).
- **Hub 402** (`GET /x402/route`), `extra.routing`: `{feeBaseMsat, feePpm, maxLockSat, maxUnguardedLockSat, minInExpiryDelta, revealTimeoutSec, routeUrl, quote: FeeQuote, ch1CloseFeePayer, ch2CloseFeePayer, providers}`. `ch2CloseFeePayer: "payee"` (default) tells the client the providers pay their own ch2 closes; `ch1CloseFeePayer` is ch1's term (default `"payer"`, the client, as on any plain channel).
- **Provider terms** (`GET /x402/xbt-channel/terms`): the 402 requirements plus `settleMultiple`, `closeFeePayer` (for hub-funded channels, default `"payee"`) and `rolloverGraceBlocks`. The hub opens ch2 with `channel.closeFeePayer` and checks the provider's echo; a hub with `ch2_close_fee_payer: "payee"` refuses a provider that does not offer it (`bad_fee_payer`); `"payer"` funds v1.1 providers and pays their closes.
- **Client -> hub** `POST /x402/route`: `PAYMENT-SIGNATURE` payload `{chan, seq, cum, adaptor, point: T1, auth}` (no `adaptor`/`point` when the dust floor already covers the lock). The body is `{"route": {provider, payTo, network, amount d, point T, tweak r, fee f, feeQuote, invoice, session, lockId, lockAuth}}`, and `auth` covers it. The answer is `{lockId, secret: t + r, cum, fee, amount}`. Errors, in check order: `bad_auth`, `bad_point`, `bad_amount` (with the hub's view `bestCum/routedSat/feeUnits/feePaid/held/released` for a resync), `bad_adaptor`, `route_fee`, `route_blocked`/`bad_invoice`/`route_expiry`, `lock_outstanding`; after forwarding: `route_failed` (502, the provider refused or did not reveal in time), `route_pending` (504).
- **Hub -> provider** `POST /x402/xbt-channel/lock`: a `PAYMENT-SIGNATURE` on ch2, payload `{chan, seq, cum, point: T, adaptor?, auth}`, body `{"route": {session, lockId, amount, lockAuth, hub}}`. The answer is `{lockId, secret: t, cum, chan, routedSat, session: <signed>}`, idempotent per lockId.
- The floor: a routed channel's cumulative state is `next_cum(routed, d, minCum) = max(routed + d, minCum)`, with `minCum` = 546 on a payer-pays channel (ch1) and 546 + closeFee on a payee-pays one (ch2: 1,146 at 600). A lock the floor already covers has no adaptor; the payer pre-pays the floor once per channel. The hub's loss to a provider that closes at the floor is `1,146 − routed` either way (v1.1: 546 floor plus the 600 fee the hub paid).
- **Rollover** (`POST /x402/xbt-channel/rollover`, `{chan, amount, sig, next}`): on a payee-pays ch2 the tx pays the provider `amount − closeFee` and the next ch2 `capacity − amount` (never more). The provider co-signs only when its net payout `amount − closeFee ≥ settleMultiple × closeFee`, or within `rolloverGraceBlocks` of its close margin; otherwise `settle_early`.

## Bounds (cmp-lead's M2 constraints)
1. **Rate.** Data calls go straight to the provider and never wait on routing. Locks run beside them, one per provider per window, serially on ch1. Demo: ≥ 12 calls/s per provider on 4 providers, call p50 about 5 ms, routed lock p50 about 30–50 ms (both hops, loopback, soak-capped). 
2. **Sub-sat.** Provider and client meter in amsat (1e-18 msat) and agree exactly. Each lock pays `ceil(accrued) - paid`. The hub fee is carried in 1e-6 msat units and charged as the ceil of its running total. Nothing is rounded per chunk.
3. **Fan-out.** Per-provider serial locks on one ch1: one outstanding lock per channel, as AGP-019 found multi-provider locks unsafe for the hub. A client that needs more parallelism opens a second ch1 (a lane) to the same hub. Loss bound: at most one lock is ever at risk on a ch1, and it is one provider's accrual since its last lock (≤ (window + lockWait) × rate × price, because the provider stops serving after that).
4. **Market fees.** No fixed fee. The hub signs expiring `FeeQuote`s, and its fee strategy is config (`flat`, `utilization`, or a callable). The provider's `PriceQuote`, invoices and ROUTE-STATE are payTo-signed and checked by the client. `lockAuth` binds (session, lockId, amount, T, hub) with a key the hub does not have, so the hub can neither reprice nor redirect a lock.
5. **Small providers.** The hub funds ch2 (`connect`), bound to its payTo at open. It rolls ch2 over when the provider's net payout reaches `settleMultiple × closeFee` and the ch2 has taken `settle_lock_multiple` × the largest lock routed to that provider (AGP-056, below), or near the provider's close margin, never while a lock is pending. `liquidity_cap_sat` bounds the hub's coins. The provider pays its own ch2 close fee (payee-pays, AGP-023), so it alone decides when a settlement is worth it.
6. **Withholding.** The provider serves a session while its unpaid charges are younger than `window + lockWait`. The hub's stall costs the provider at most that, and the client at most its one outstanding lock, which it gives up when the invoice expires unanswered. A hub that keeps receipts back does not stall anything: the client takes t from the provider's signed ROUTE-STATE.
7. **Identity.** One payTo per operator. Each device (provider process: its own origin, ledger and sessions) has its own ch2 (the per-channel payee keys differ). Invoices and quotes of all devices verify under the same payTo. One key holds at most `ch2_max_per_pay_to` live ch2s (AGP-056).

## For xbt-compute (cmp)
```python
# provider (shard server) — meter your own work in amsat
prov = XbtChannelProvider(rpc, pay_to_secret, network, ledger, price, handler, settle_multiple=20)
prov.offer_route("/forward", window=1.0, lock_wait=2.0, invoice_ttl=15.0,
                 charge=lambda method, path, status, body: amsat_for_this_chunk)
# client
payer = RoutePayer(hub_url, network, height=node.getblockcount, fund=wallet_fund, signer=b2_route_signer)
payer.open(); sh = payer.shard(shard_url + "/forward"); payer.start()
status, headers, body = payer.call(sh, "POST", chunk)   # per chunk
# hub (merchant --hub mode)
hub = RouteHub(rpc, pay_to_secret, network, datadir, fund, HubConfig.from_dict(conf["hub"]))
hub.connect(provider_url); hub.watch(5); hub.http_server(port).serve_forever()
```

The hub seals its ch2 payer keys in `<datadir>/ch2.json` (AES-256-GCM, aad `xbt402/hub-ch2`, AGP-073).
Pass `wrap_key=WrapKey.load_or_create(path)` (`xbt402.hub_keys`) to keep the wrap key off the data
dir (a secrets mount); without one the hub makes `<datadir>/hub-wrap-key` (0600). A plaintext
`ch2.json` from an older hub is read once and rewritten sealed; older copies (backups) still hold
the keys. An older hub cannot read a sealed file. `cryptography` is needed for this.

## Routed billing throughput (AGP-054)
cmp measured routed decode at 0.742 of unpaid (CMP-024), about 4-5 ms of billing per stage per
token. A profile of the per-call path (`scripts/route_perf.py`, spans on cmp's operator app) put
most of it in one place: cmp's `RouteJournal` fdatasyncs every routed call's meter after the
handler and before the answer (2.5 ms on the lab's ext4, 66% of the provider-side cost). The
rails' own crypto is small: ROUTE-STATE signing 0.12 ms, the client's verify 0.03 ms.

**RouteWal** (`XbtChannelProvider(route_wal=path)`, `offer_route(..., precharge=)`) makes the same
guarantee the rails' own, with the fsync off the critical path:
* before the handler runs, `reserve` counts the call in flight at its expected charge (`precharge`,
  or `amsat_per_call` on a flat path) and queues the session's projected meter
  `{s, v, seq, calls, acc, us}`;
* one writer thread appends what is queued and fdatasyncs it (group commit), while the handler
  computes;
* `end_call` returns the ROUTE-STATE only once a snapshot covering it is durable. The state
  carries the session's *current* meter (seq, calls, accrued), which can already hold a concurrent
  call metered in memory, or a seq a later `begin_call` took. So it waits for the session's
  *latest* snapshot when that covers the state (sequentially, that is the call's own reserved
  one), else queues a fresh one. A charge other than the projection always writes a corrected
  snapshot (one more fsync). A refused call's 402 `routeState` waits the same way;
* a write failure answers `500 route_wal_failed`, with no ROUTE-STATE and nothing billed, unless a
  later state of the session already carries the call (then it stays billed, like a call in
  flight at a crash, so no state goes backwards);
* the routes file keeps each session projected over its calls in flight, plus `walV`. A save during
  a call (a lock completing) therefore covers that call's reservation. At start, a WAL snapshot wins
  over the routes file when its `v` is above `walV`, and versions resume above `walV` even if the
  log was lost. The log is compacted to one line per session past 1 MiB.

What a crash can do now:
* every answered state survives it;
* a seq is durable before its handler runs, so a ROUTE-AUTH is never served twice;
* the restart counts more only for calls in flight at the crash, once each, at their projected
  charge. Those are the in-doubt chunks a client already reconciles (cmp: `MAX_IN_DOUBT` per route
  session).

**RoutePayer.** A data call no longer resolves a lock whose POST to the hub is still out. The hub's
answer settles it off the data path, so a signer's write-ahead fsyncs (B2 `resolve_lock`: about
3 fsyncs) no longer land on a chunk. A hub refusal of a lock that the provider's signed ROUTE-STATE
shows as paid now resolves it through the provider, instead of voiding it.

**ROUTE-STATE.** The window's invoice is signed once per window, not on every call. The bytes are
identical because ECDSA signing is deterministic.

Tests: `tests/security/test_agp054_route_wal.py` (23, 7 from rework 1: concurrent calls on one
session with the writer held on the later snapshot). In Rust: `crates/xbt402-interop/tests/route_wal.rs`
(19) and `routing_checks.rs` `agp054_*` (2).

## ch2 identity, rollover relay and the settle floor (AGP-056)
**ch2 identity: one per provider process.** A ch2 lives in ONE provider process's ledger, with that
process's route sessions. AGP-044 kept one live ch2 per payTo and sent the locks of a second origin
under that key to the origin that opened the ch2: with two provider processes on one operator key (cmp
merchants) that process has no session for them (`unknown_session`, the client sees `route_failed`).
The hub now keys a ch2 by the canonical origin again:

- `connect(origin)` funds that origin's own ch2; an origin that already has a live one gets it back and
  nothing is funded (racing connects fund one).
- A lock goes to the origin the client named, on that origin's ch2.
- One payTo key holds at most `ch2_max_per_pay_to` live ch2s (default 8, 0: no bound): the next
  `connect` is refused `pay_to_limit` and nothing is funded. `liquidity_cap_sat` counts every ch2.
- A refusal says why: `route_blocked` "no open channel to that provider: its payTo has a ch2 at
  <origin>, another provider process ...".

An operator who serves ONE provider process at two URLs should give the hub one of them: each URL would
get its own ch2 (they work, the capital is split).

**Rollover relay.** The provider broadcasts a rollover on its own node. A hub on another node sees it
only after P2P relay, so the hub no longer blocks the child as vanished (`ch2_rollover_vanished`) unless
its node showed the rollover before (`fund_seen`), or still does not `rollover_relay_grace` seconds
(default 60) after the rollover. Before, a hub with its own node blocked every rollover child until
the next block.

**Settle floor.** `settleMultiple × closeFee` (12,600 sat at the defaults) is when a settlement is
worth its fee to the provider. With locks larger than that, the ch2 rolled over on every lock.

- Hub: a due rollover waits until the ch2 has taken `settle_lock_multiple` (k, default 4) × the largest
  lock routed to that provider (`max_lock`, carried over rollovers). It never waits past the point
  where another lock of that size would not fit, and not at all once the ch2 has had no lock for
  `settle_idle` seconds (default 600). `settle_lock_multiple: 0` restores the old rule.
- A rollover child that could not take one more lock of that size is not made: the ch2 is closed and
  refilled instead (before, such a child sat exhausted and unsigned until its expiry).
- Provider: the default zero-conf cap of a rollover child is now
  `max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × largest lock on the parent's line)`,
  so the first lock on an unconfirmed child is not above the cap. An explicit
  `rollover_zero_conf_max` is used as it is.
- Why k = 4: at most one rollover per four of the largest locks (the provider's close fees and the
  unconfirmed windows fall by the same factor), and with a ch2 capacity of five such locks, the usual
  sizing (100k / 20k, 200k / 40k), it is the largest k that still leaves room for one more lock when
  the rollover is due.

**Refusal detail.** `RoutePayer.lock` returns `{"status": "refused", "error", "detail"}`, as the Rust
client does. A provider's refusal reaches the client as `route_failed` with detail
`provider refused the lock: <code> (<the provider's detail, printable ASCII, bounded>)`.

No wire change: no new field or message. Tests: `tests/security/test_agp056_multi_process.py` (21); in
Rust `crates/xbt402-interop/tests/hub_multi_process.rs`.

## ch2 lifecycle under load: the zero-conf cap and make-before-break refill (AGP-057)
Two things paused routing to a provider under load. Both are in the hub (and one line in the provider),
the same in the Rust hub; no wire change.

### A. The zero-conf cap of a rollover child (cmp CMP-149)
cmp saw about 20 `route_blocked` per R14 replay: "the rollover funding this ch2 is unconfirmed: cum
134687 > the provider's zero-conf cap 132120". The cap is the provider's bound on what it takes over a
rollover child that is still unconfirmed (`rollover_zero_conf_max`; by default
`max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × the largest lock)`, here 8 × 16,515).

What it is not: nothing of the parent is carried into the cap. A child's cum starts at 0 (the hub's
`routed` and `signed`, the provider's `best_cum` and `routed_sat`); `childCumCarried` is 0 in every load
run below.

What it was, reproduced at cmp's lock size (`scripts/rollover_load_regtest.sh`, kinds `cmp*`, in xbt-rs):

1. **The hub's stale flag (fixed).** The hub refuses before it sends anything, on its own
   `zero_conf.confirmed`, and that flag was only the watcher's last look. A child that confirmed since
   the last tick was still refused until the next one. The hub now looks at the chain itself before it
   refuses on either bound (the cap, or the parent's close margin), as the provider already did. A node
   that does not answer leaves the bound standing (`ch2_watch_error`, step `zero_conf`).
2. **A block that lands while the provider checks the child (fixed).** The provider read the child's
   funding unconfirmed; then the block with the rollover came, so the parent was spent in a block and
   the child was no "zero-conf child" any more. The open was refused `unconfirmed` although the child
   was confirmed, and it stayed `funded` until the hub's next tick. The provider now reads the funding
   once more before it refuses. A refused open is also written to the hub's stderr now.
3. **The provider's own stale look at a lock (fixed).** The provider's watcher can meet the block the
   same way and leave a confirmed child `suspended` until its next tick: a lock in between was refused
   `unconfirmed` (two `route_failed` in a `high-nofloor` load run). Before it refuses a lock on a
   suspended rollover child the provider now reads the chain, as the hub does before it sends one. Any
   other suspended channel is refused as before.
4. **A child that really is unconfirmed (sizing, not a bug).** With more than the cap's worth of locks
   per block interval, the hub still refuses: that is the provider's risk bound. A provider that is paid
   faster than `2 × settle_lock_multiple` of its largest locks per block sets
   `rollover_zero_conf_max` to what it earns from one hub in a block interval or two. What it risks on
   an unconfirmed child is bounded: before the parent's expiry only the provider can sign another spend
   of the parent, so the child exists unless the rollover is still unconfirmed at the parent's close
   margin (`until`).

### B. Make-before-break refill
A rollover adds no coins, so a ch2 line carries its capacity in locks and was then closed and refilled.
The refill is a wallet funding, which the provider cannot take unconfirmed (its payer could spend it
again), so it opened at minConf: a block without routing to that provider.

- **Funded ahead.** Once the live ch2's room is under `refill_ahead_locks` (N, default 4) × the largest
  lock routed to that provider, the watcher funds the origin's NEXT ch2 (`OutBook.next_chans`, at most
  one per origin; `connect_next`). Room is what the line still takes: `max_amount − signed`, less the
  provider's `minCapacity` (a rollover child under it is not made). Not for a provider the hub stopped
  routing to, nor for one with no lock for `settle_idle` seconds.
- **Usable** means open at the provider, at its minConf. The live ch2 keeps taking locks meanwhile,
  rollovers included.
- **The switch** (`ch2_switch`): with the first lock the live ch2 cannot take (exhausted, no longer
  open, or an unconfirmed rollover child at the provider's bounds); when the live ch2 is closed as too
  small to roll over (`close_ch2(refill=True)` hands over instead of funding; while the next one is
  funded but not open yet and the live one still takes a lock, it is kept: `ch2_wait_next`); or once the live ch2
  has had no lock for `settle_idle` seconds, so two ch2s do not stay committed to an idle provider.
  Never while a lock is pending on the live ch2, and never because the hub stopped routing to the
  provider (a lock it did not reveal).
- **The old ch2** is `retired`: the watcher asks the provider to close it on its best state (once a
  block until it answers), and it is reconciled like any archived ch2. One with nothing signed has
  nothing to close and is refunded at its expiry, as an unused ch2 always was.
- **Bounds.** Per origin: one live ch2 plus at most one next (the AGP-056 guard, widened). An origin
  counts once for `ch2_max_per_pay_to`. `committed_sat` counts the live ch2, the next one and a retired
  one until its close is out, so `liquidity_cap_sat` needs room for one more `ch2_capacity` than the
  hub has origins. Without that room nothing is funded ahead (`ch2_refill_ahead_failed`, tried again
  next block) and the refill follows the close as before.
- **Sizing N.** N locks must cover what the provider is paid while a funding confirms and opens: the
  locks of one block interval plus one watcher tick. `refill_ahead_locks: 0` is the old behaviour.
- **Embedders.** The hook is `refill_ahead(origin)` (constructor argument and property, like
  `refill`). Its default is `connect_next`; an embedder that passed its own `refill` and no
  `refill_ahead` gets none, so its own path, lock and cap are never bypassed (cmp: unchanged until it
  passes one). `ch2.json` has a new key `next_chans`, and a record a new field `retired`.

Events: `ch2_refill_ahead` {live, next, room, maxLock, capacity}, `ch2_refill_ahead_failed`,
`ch2_switch` {from, to, why}, `ch2_wait_next`, `ch2_retire_failed`.

Tests: `tests/security/test_agp057_refill_ahead.py` (25; 12 of 13 mutations of the hub caught, the
13th is equivalent); in Rust `crates/xbt402-interop/tests/hub_refill_ahead.rs` (25). Load runs and
their numbers: xbt-rs `README.md`, "ch2 lifecycle under load (AGP-057)".
