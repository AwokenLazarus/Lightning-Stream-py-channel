# xbt402 hub routing (AGP-021)

Implements the AGP-019 design (`~/notes/projects/xbt-agentpay/Research/AGP-019 xbt402 hub routing.md`):
a client pays many providers over ONE channel to a hub, using adaptor-locked states on both hops.
Regtest only. The state format, script, close and watcher are those of xbt402 v1.1. Everything
below is additive.

```
client --ch1 (client pays, hub is payee)--> hub --ch2 (hub pays, provider is payee, hub-funded)--> provider
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
- **Hub 402** (`GET /x402/route`), `extra.routing`: `{feeBaseMsat, feePpm, maxLockSat, maxUnguardedLockSat, minInExpiryDelta, revealTimeoutSec, routeUrl, quote: FeeQuote, providers}`.
- **Client -> hub** `POST /x402/route`: `PAYMENT-SIGNATURE` payload `{chan, seq, cum, adaptor, point: T1, auth}` (no `adaptor`/`point` when the dust floor already covers the lock). The body is `{"route": {provider, payTo, network, amount d, point T, tweak r, fee f, feeQuote, invoice, session, lockId, lockAuth}}`, and `auth` covers it. The answer is `{lockId, secret: t + r, cum, fee, amount}`. Errors, in check order: `bad_auth`, `bad_point`, `bad_amount` (with the hub's view `bestCum/routedSat/feeUnits/feePaid` for a resync), `bad_adaptor`, `route_fee`, `route_blocked`/`bad_invoice`/`route_expiry`, `lock_outstanding`; after forwarding: `route_failed` (502, the provider refused or did not reveal in time), `route_pending` (504).
- **Hub -> provider** `POST /x402/xbt-channel/lock`: a `PAYMENT-SIGNATURE` on ch2, payload `{chan, seq, cum, point: T, adaptor?, auth}`, body `{"route": {session, lockId, amount, lockAuth, hub}}`. The answer is `{lockId, secret: t, cum, chan, routedSat, session: <signed>}`, idempotent per lockId.
- The dust floor: a routed channel's cumulative state is `next_cum(routed, d) = max(routed + d, 546)`. A lock the floor already covers has no adaptor; the payer pre-pays the floor once per channel.

## Bounds (cmp-lead's M2 constraints)
1. **Rate.** Data calls go straight to the provider and never wait on routing. Locks run beside them, one per provider per window, serially on ch1. Demo: ≥ 12 calls/s per provider on 4 providers, call p50 about 5 ms, routed lock p50 about 30–50 ms (both hops, loopback, soak-capped). 
2. **Sub-sat.** Provider and client meter in amsat (1e-18 msat) and agree exactly. Each lock pays `ceil(accrued) - paid`. The hub fee is carried in 1e-6 msat units and charged as the ceil of its running total. Nothing is rounded per chunk.
3. **Fan-out.** Per-provider serial locks on one ch1: one outstanding lock per channel, as AGP-019 found multi-provider locks unsafe for the hub. A client that needs more parallelism opens a second ch1 (a lane) to the same hub. Loss bound: at most one lock is ever at risk on a ch1, and it is one provider's accrual since its last lock (≤ (window + lockWait) × rate × price, because the provider stops serving after that).
4. **Market fees.** No fixed fee. The hub signs expiring `FeeQuote`s, and its fee strategy is config (`flat`, `utilization`, or a callable). The provider's `PriceQuote`, invoices and ROUTE-STATE are payTo-signed and checked by the client. `lockAuth` binds (session, lockId, amount, T, hub) with a key the hub does not have, so the hub can neither reprice nor redirect a lock.
5. **Small providers.** The hub funds ch2 (`connect`), bound to its payTo at open. It rolls ch2 over at the provider's `settleMultiple × closeFee` (or near expiry), never while a lock is pending. `liquidity_cap_sat` bounds the hub's coins. Who pays a ch2 close fee follows the channel's `closeFeeSat` terms (AGP-023 will make routed payees pay their own).
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
