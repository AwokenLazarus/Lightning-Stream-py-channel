# xbt402 hub routing (AGP-021)

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
- **Client -> hub** `POST /x402/route`: `PAYMENT-SIGNATURE` payload `{chan, seq, cum, adaptor, point: T1, auth}` (no `adaptor`/`point` when the dust floor already covers the lock). The body is `{"route": {provider, payTo, network, amount d, point T, tweak r, fee f, feeQuote, invoice, session, lockId, lockAuth}}`, and `auth` covers it. The answer is `{lockId, secret: t + r, cum, fee, amount}`. Errors, in check order: `bad_auth`, `bad_point`, `bad_amount` (with the hub's view `bestCum/routedSat/feeUnits/feePaid` for a resync), `bad_adaptor`, `route_fee`, `route_blocked`/`bad_invoice`/`route_expiry`, `lock_outstanding`; after forwarding: `route_failed` (502, the provider refused or did not reveal in time), `route_pending` (504).
- **Hub -> provider** `POST /x402/xbt-channel/lock`: a `PAYMENT-SIGNATURE` on ch2, payload `{chan, seq, cum, point: T, adaptor?, auth}`, body `{"route": {session, lockId, amount, lockAuth, hub}}`. The answer is `{lockId, secret: t, cum, chan, routedSat, session: <signed>}`, idempotent per lockId.
- The floor: a routed channel's cumulative state is `next_cum(routed, d, minCum) = max(routed + d, minCum)`, with `minCum` = 546 on a payer-pays channel (ch1) and 546 + closeFee on a payee-pays one (ch2: 1,146 at 600). A lock the floor already covers has no adaptor; the payer pre-pays the floor once per channel. The hub's loss to a provider that closes at the floor is `1,146 − routed` either way (v1.1: 546 floor plus the 600 fee the hub paid).
- **Rollover** (`POST /x402/xbt-channel/rollover`, `{chan, amount, sig, next}`): on a payee-pays ch2 the tx pays the provider `amount − closeFee` and the next ch2 `capacity − amount` (never more). The provider co-signs only when its net payout `amount − closeFee ≥ settleMultiple × closeFee`, or within `rolloverGraceBlocks` of its close margin; otherwise `settle_early`.

## Bounds (cmp-lead's M2 constraints)
1. **Rate.** Data calls go straight to the provider and never wait on routing. Locks run beside them, one per provider per window, serially on ch1. Demo: ≥ 12 calls/s per provider on 4 providers, call p50 about 5 ms, routed lock p50 about 30–50 ms (both hops, loopback, soak-capped). 
2. **Sub-sat.** Provider and client meter in amsat (1e-18 msat) and agree exactly. Each lock pays `ceil(accrued) - paid`. The hub fee is carried in 1e-6 msat units and charged as the ceil of its running total. Nothing is rounded per chunk.
3. **Fan-out.** Per-provider serial locks on one ch1: one outstanding lock per channel, as AGP-019 found multi-provider locks unsafe for the hub. A client that needs more parallelism opens a second ch1 (a lane) to the same hub. Loss bound: at most one lock is ever at risk on a ch1, and it is one provider's accrual since its last lock (≤ (window + lockWait) × rate × price, because the provider stops serving after that).
4. **Market fees.** No fixed fee. The hub signs expiring `FeeQuote`s, and its fee strategy is config (`flat`, `utilization`, or a callable). The provider's `PriceQuote`, invoices and ROUTE-STATE are payTo-signed and checked by the client. `lockAuth` binds (session, lockId, amount, T, hub) with a key the hub does not have, so the hub can neither reprice nor redirect a lock.
5. **Small providers.** The hub funds ch2 (`connect`), bound to its payTo at open. It rolls ch2 over when the provider's net payout reaches `settleMultiple × closeFee` (or near the provider's close margin), never while a lock is pending. `liquidity_cap_sat` bounds the hub's coins. The provider pays its own ch2 close fee (payee-pays, AGP-023), so it alone decides when a settlement is worth it.
6. **Withholding.** The provider serves a session while its unpaid charges are younger than `window + lockWait`. The hub's stall costs the provider at most that, and the client at most its one outstanding lock, which it gives up when the invoice expires unanswered. A hub that keeps receipts back does not stall anything: the client takes t from the provider's signed ROUTE-STATE.
7. **Identity.** One payTo per operator. Each device has its own ch2 (the per-channel payee keys differ). Invoices and quotes of all devices verify under the same payTo.

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
* `end_call` returns the ROUTE-STATE only once a snapshot covering it is durable: the reserved one
  when the charge is as projected, else a corrected one (one more fsync);
* a write failure answers `500 route_wal_failed`, with no ROUTE-STATE and nothing billed;
* the routes file keeps each session projected over its calls in flight, plus `walV`. A save during
  a call (a lock completing) therefore covers that call's reservation. At start, a WAL snapshot wins
  over the routes file when its `v` is above `walV`. The log is compacted to one line per session
  past 1 MiB.

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

Tests: `tests/security/test_agp054_route_wal.py` (16). In Rust: `crates/xbt402-interop/tests/route_wal.rs`
(12) and `routing_checks.rs` `agp054_*` (2).
