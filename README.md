# xbt402 / `xbt-channel` (P-003 B1) wave 2

x402 v2 scheme **`xbt-channel`**: HTTP 402 payments for AI agents on XBT over Spillman-style
unidirectional channels. Every channel signature is `SIGHASH_ALL|UNIFIED` (0x21). Spec:
`docs/x402/xbt402-spec-v1.1-draft.md` (protocol v1.1: payee key committed to the network,
`extra.derivation: "v2"`; `PAYMENT-RESPONSE` as an x402 `SettlementResponse`; x402 v2 facilitator
bodies), x402 proposal `docs/x402/scheme_xbt-channel.md`, vectors `docs/x402/check_vectors.py`.
Earlier design: `~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402 HTTP 402 payment channels.md`.

**No remote. Never push.** Branch `wave2`. Keys for paid calls live in `ChannelSigner` (B2 hooks
the same method names). `ecc.py` is libsecp256k1 via `coincurve`; `ecc_oracle.py` is the
pure-Python test oracle.

| Path | What |
|---|---|
| `xbt402/ecc.py` | coincurve backend (`BACKEND`); oracle in `ecc_oracle.py` |
| `xbt402/ledger.py` | SQLite WAL, one row per channel |
| `xbt402/channel.py` | states, 0xA3 fee-input variant, rollover tx, CPFP child |
| `xbt402/conditional.py` | hash-locked increment (XBT-055 / B4) |
| `xbt402/watcher.py` | `close_due()` loop + CPFP |
| `xbt402/asgi.py` | Starlette app / middleware |
| `xbt402/client_httpx.py` | httpx transport |
| `xbt402/signer.py` | ChannelSigner (secrets never leave) + B2 socket adapter |
| `xbt402/mcp_server.py` | `xbt402_pay`, `xbt_channels`, `xbt_close`, `xbt_refunds_due` |
| `xbt402/x402_channel.py` | provider + SDK (facilitator `/x402/verify` `/x402/settle` `/x402/supported`) |
| `demo.sh` | units + chain rules + 1,000 calls + conditional + MCP + close + refund |
| `docs/embedders.md` | AGP-059: client `headers=`/`cum=`, `provider.close_channel`, a call in flight at a crash |

Ports **30100–30199**, datadirs under `~/xbt-rnd/xbt-060/run/`. Isolated Knots 29.4.2 with RDTS
and `#419` (`-testcoinbasematuritylong=200:200:6680`). No miners.

verify: `cd ~/xbt-rnd/b1 && ./demo.sh && python3 ~/xbt-rnd/tools/miners_left.py 30100-30199`

B2 (XBT-062) should implement these signer methods: `xbt402_new_key`, `xbt402_attach`,
`xbt402_sign_state`, `xbt402_sign_state_a3`, `xbt402_sign_close`, `xbt402_sign_refund`,
`xbt402_fund`, `xbt402_channels`. Wrap with `SignerSocketAdapter`.

## Transport and channel limits (AGP-081, closure audit)

- **A paid answer needs its receipt.** `XbtChannelClient.request` and `request_conditional` raise
  `bad_receipt` when a request that carried a `PAYMENT-SIGNATURE` is answered below 400 without a
  `PAYMENT-RESPONSE`. An answer of 400 or above without one is returned as it is; nothing is adopted
  from it. Routed calls (`route_client.py`) have no per-call receipt by design: `ROUTE-STATE` is the
  provider's signed running meter.
- **No `#` in a paid URL.** The request digest drops a fragment and the server routes on the raw
  target, so both sides refuse one: the payer before anything is signed or sent (`bad_request`), the
  provider, the hub and both HTTP adapters with a 400 before anything is authenticated or routed.
- **Connections.** `http_server(port, max_per_address=48)`: 64 connections in all, 48 from one client
  address (an IPv6 address counts as its /64, an IPv4-mapped one as its IPv4 address), then 503. Pass
  `max_per_address=0` when the only peer is a reverse proxy, and limit clients there.
- **The ASGI path has no such limits.** `xbt402/asgi.py` runs under an ASGI server that owns the
  sockets: uvicorn has no header deadline and no connection cap. It needs a reverse proxy (header and
  body timeouts, per-client connection limits) or a server configured with them. `serve_asgi` and
  `scripts/mainnet_provider.py` refuse any host that is not loopback.
- **Channel lifetime.** A payer (client open and rollover, the hub's ch2) asks for at least
  `minExpiryBlocks + minConf + closeMarginBlocks` blocks, each from the offer
  (`funding.offer_expiry_blocks`), and refuses an offer without those terms before it funds.

Tests: `tests/security/test_agp081_closure_audit.py`.

## Fix wave 3, the hub (AGP-085)

- **A hub's rollover keeps its next ch2.** The next ch2's key and refund are written before the
  rollover request leaves and stay whatever the provider answers (it holds the request signed and
  may broadcast it). One next key per ch2: a retry asks under the same key and expiry, and the
  watcher adopts whichever attempt spends the funding, by its script. `next` is cleared only when a
  confirmed spend of the funding is not a rollover into it.
- **ch1's counters move by what a lock adds** (`unitsBy`), on completion and on a hold, so a hold
  released while another lock was in flight does not come back with that lock.

- **A replaced close or rollover intent is kept** (`close_intents`) until the node shows one of them;
  a rollover is refused `channel_closing` once 8 are unresolved.

Details: `docs/routing.md` (the AGP-085 note). Tests: `tests/security/test_agp085_hub.py`,
`tests/security/test_agp085_intents.py`.

## Fix wave 4, channel client and transport (AGP-090)

As xbt-rs (its README, same heading); `XbtChannelClient` and `funding.py`.

- **A funded channel is never forgotten.** `ClientChannel.stage` is `keyed` (on the books before
  `fund` is called), `funded` (refund held and handed out, before the provider hears of the
  outpoint) or `open`. `_ensure_open` is the only way to `open`, for a plain call, a conditional call
  and the routed client's ch1. A seller that refuses the funded open, or whose answer is lost, is
  asked again on the next call and nothing is funded again; nothing is signed before `open`. A retry
  after a `fund` that raised pays the same script under the same key (`fund` is a bare callable, so
  the client cannot ask the wallet what it sent). A keyed channel too old to fund moves to
  `unfunded` and is derived again (changed by AGP-096, below).
- **The owner bounds the expiry.** `offer_expiry_blocks(extra, want, owner_max=4032)`: an offer
  whose floor is above the bound is `bad_offer` before a key is made. `XbtChannelClient(...,
  max_expiry_blocks=4032)`.
- **Receipts.** A receipt must be for the seq just sent. The provider's spent total may be ahead of
  the last verified receipt by one quote per paid request it has not answered (`unanswered_msat`; a
  402 is an answer), plus the channel's one call of slack. A lost answer no longer ends the channel,
  and each served call is paid once.
- **Transport.** A bare target is bound byte for byte (`split_scheme`: `://` in a query is not a
  scheme). A HEAD answer, and a 1xx, 204 or 304, is not compared with its Content-Length, and its
  receipt is checked on the status.

Tests: `tests/security/test_agp087_hub_b_client.py`, `test_agp087_transport.py`,
`test_agp090_client.py`. Changed: `test_agp081_closure_audit.py` pinned the wedge after a stripped
receipt (now the next call goes through); `tests/test_agp068.py` and `tests/test_x402_envelopes.py`
build a channel by hand and now say which call it sent.

## Fix wave 5, the library client (AGP-096)

As xbt-rs (its README, same heading); `XbtChannelClient`, `funding.py` and `signer.py`.

- **A channel that holds no coins never stands in the way.** A keyed channel whose `fund` call
  failed is retried as it is while it has `offer_retry_floor` blocks left (`minExpiryBlocks +
  minConf` plus the larger half of `closeMarginBlocks`: 72 blocks of retries against the reference
  provider, where AGP-090 called it too old after one). Past that it moves to `unfunded` and the
  same call derives it again and funds that. Every channel derived for an origin until one is funded
  pays one key (`ChannelSigner.new_key` answers the key it issued and has not bound; a local key is
  read back from `unfunded`), so past 16 kept scripts the oldest is forgotten and its key is not.
  Only a channel `fund` was called for is kept there (`fund_tried`). Nothing needs
  `forget_unfunded` any more.
- **Funded only on terms the seller offers that day.** Before a keyed channel of an earlier call is
  funded, the offer of this call must still describe it and the provider must answer yes to its
  preflight again; else it is set aside, derived again, and the call fails `open_unresolved` with
  nothing funded (the next call funds the new one). `budget_sats` is checked when the coins leave.
- **One seller, one origin.** `split_url` gives the origin as the request binding reads it
  (`canonical_origin`), and the client's book is keyed by it.
- **The expiry has a lower bound.** `offer_expiry_blocks` refuses a window below the offer's own
  floor, or below 144 blocks (or the owner's wish, if smaller).
- **`ChannelSigner` keeps the keys it issued** and binds one key to each channel that pays it.

Stated limits, as xbt-rs: a refusal (402) is not signed, so a second charge hidden behind a forged
refusal ends the channel with `bad_offer` (`test_limit_two_forged_refusals_end_the_channel`, which
AGP-101 turned round from the audit's `test_hole_...`: see below); a provider is believed for one
quote per paid request that got no receipt. B1's client keeps no ledger, so "a request is counted
before it leaves" is Rust only.

Tests: `tests/security/test_agp096_client.py` (14) and the audit's `test_agp093_client.py`.
Changed: two tests in `test_agp090_client.py` pinned the stop at a stale keyed channel.

## Fix wave 5 leftover (AGP-101)

Tests and words only; no code of B1 changed.

- **The second forged refusal is a limit, not a hole.** `test_agp093_client.py`'s
  `test_hole_two_forged_refusals_do_not_end_the_channel` is now
  `test_limit_two_forged_refusals_end_the_channel` and asserts what happens: after the second charge
  hidden behind a forged 402 every call is `bad_offer` (the provider served nine calls, the payer
  holds seven answers), and the payer closes at what it signed. The one small rule that would let
  the channel go on (a refused request stays among the unanswered ones) was run in xbt-rs: it makes
  `test_a_provider_that_refuses_every_call_cannot_claim_them` (review M3) fail there, because a seller
  that serves nothing is then owed a quote for every 402 it answers. Telling that seller from a
  wronged one needs a signed refusal, a change of the protocol.
- **A funding the signer made that the client never heard of** (xbt-rs README, same heading) does
  not exist here as a path: `ChannelSigner.fund` and the client's `fund` are the embedder's bare
  callable, which keeps no record to ask, and `SignerSocketAdapter.fund` calls `xbt402_fund`, a
  method neither signer serves. What B1 does when its `fund` raises after it sent is unchanged and
  measured: the retry pays the same script a second time (two sends, one script, one key). The
  key is on the books, so both outputs are refundable after the expiry; the client holds a refund
  for the second only. An embedder whose `fund` can fail after it sent must make it answer the send
  it made when asked again for the same address.

- **One test of AGP-094 met AGP-096 on the wave 5 branch and failed.** B1's routed client opens ch1
  through `XbtChannelClient._ensure_open`, so a keyed ch1 too near its expiry is derived again and
  funded by the same call (AGP-096's rule), where AGP-094's test pinned `open_unresolved` until
  `forget_unfunded`. The test now states the merged rule
  (`test_agp094_a_keyed_ch1_too_old_to_fund_is_derived_again_and_funded_once`) and the two
  docstrings in `route_client.py` say the same. xbt-rs `RoutePayer` has an open of its own and still
  refuses `open_unresolved` there.

## Review close-out (AGP-107) and fix wave 6 in the hub (AGP-105)

The limits of this reference are in `docs/LIMITS.md`, which points at the Rust workspace's file for
everything the two share. After fix wave 6 three of the fourth audit's tests were still red here.
Each got one decision (xbt-rs `README.md`, "Review close-out", has the rule for a limit test):

| test (as the audit named it) | audit item | does B1 have the code path | decision |
|---|---|---|---|
| `test_agp102_client` `Origin.test_hole_a_refusing_seller_is_funded_once_however_its_host_is_spelled` | 15 (and 1) | yes: the number forms of an IPv4 address resolve to one host and were four keys in the book | ported: `x402_channel.sendable_url`, as xbt-rs `wire::sendable_url` (AGP-105), called by `request`, `request_conditional` and the routed client's `shard`. Those spellings are refused before anything is asked or funded. The test is `test_limit_a_refusing_seller_is_funded_once_for_each_spelling_that_is_not_refused`: it pins the refusal and the limit that is left, a trailing dot on a name |
| `test_agp102_client` `ForgedRefusal.test_hole_after_the_close_that_follows_two_forged_refusals_...` | 15 | yes, the same | limit (`test_limit_..._every_call_is_refused_until_the_record_is_removed`): `close()` leaves the record |
| `test_agp102_hub` `RoutedOpen.test_a_ch1_funding_that_failed_after_it_was_sent_is_not_sent_again` | 6 | yes, and not the fix: `fund` is a bare callable and the routed client opens ch1 through the library client's `_fund_keyed` | limit (`test_limit_a_ch1_funding_that_failed_after_it_was_sent_is_sent_again_by_every_open`). xbt-rs asks its wallet whether it keeps a record of its sends; here that would be a new contract for every embedder's hook, and the control beside the test requires a `fund` that raised to be asked again |

The backslash URL of the audit's item 1 never split here: `urllib` reads it as the book does
(`Origin.test_limit_what_the_canonical_origin_unifies`). `sendable_url` refuses it all the same,
with whitespace, a second `@`, percent-encoding in a host and a port that is no number, so that an
embedder with another HTTP library is not handed such a string. New tests:
`tests/security/test_agp107_client.py` (4), the first of which runs 9,723 authorities and checks
that whatever the rule lets through is read alike by the book, by `urllib` and by the resolver.

From fix wave 6 (AGP-105, `xbt402/hub.py`; the tests are `tests/security/test_agp105_hub.py`):

- The hub's question to a provider about a lock is bounded by `reveal_timeout`, and nothing waits
  for a provider inside ch1's ledger lock.
- A provider that did not answer that question is set aside until it answers the watcher, which
  asks one such provider per tick.
- A spend the watcher found in a block is looked for in that block while it waits for depth, not
  from the ch2's first block.

## The hub's returns (AGP-104)

Before this, two kinds of coin the hub got back stayed on keys only its state files know: the hub's
remainder when a provider closed a ch2 (paid to that ch2's own payer key), and what clients paid,
when a ch1 closed (paid to that ch1's own payee key). `sweep_payee` existed and nothing called it.

**Rule R1: no coin of the hub's rests on a key only its state files know.** With
`RouteHub(..., return_to=...)` (`python -m xbt402.hub` passes its wallet's `getnewaddress`): every
ch2 the hub funds, and every rollover's next ch2, names a return address as its `payerSpk`; a refund
pays it too; the watcher sweeps a closed ch1's payout there once the close is `spend_final_depth`
deep; and what a ledger from before left on a ch2's own key is swept there after the upgrade.
`_return_spk()` is the one function every return goes through. Without `return_to` nothing changes.

**Rule R2: one signed sweep per output.** A sweep is written to the ledger before it is sent
(`payee_sweep_intent` on a ch1, `sweep` on a ch2 record), the same bytes are sent again each block
until the chain has them, and it is never signed again at another fee or to another address
(`sweep_payee` called by hand gets the written one back). A sweep is final six blocks deep.

Also: `capital_sat` (the liquidity cap as one setting, with one spare `ch2_capacity` kept for
funding ahead), and `ch2_expiry_blocks` ships as 1,153, a default seller's floor (was 1,100, raised
to 1,153 on every such open). The limits, the status page and the start-up checks (xbt-rs only) are
in xbt-rs `README.md`, "The hub's returns, status and start-up checks (AGP-104)".

Tests: `tests/security/test_agp104_returns.py` (18; xbt-rs has the same names). On regtest:
xbt-rs `scripts/hub_returns_regtest.sh` runs this hub through a full cycle.

## Fix wave 5, the hub and the routed client (AGP-094)

The hub and routed-client items of the third closure audit (AGP-093), as xbt-rs agp-094 (its README
has the table, one rule a row). `xbt402/hub.py`, `route.py`, `route_client.py`.

- **The hub asks before it pre-signs (item 1).** A lock that needs a ch2 pre-signature is first put
  to the provider as the lock's own request, marked `route.check` and without `adaptor`
  (`RouteHub._check_lock`). The provider runs every check and answers `{"check": lockId}`; a refusal
  there (a client's bad `lockAuth`, session or amount) leaves nothing written off, held or blocked:
  `502 route_failed` with `providerError` (`no_answer` when it did not answer). `bad_adaptor` is the
  yes of a provider from before the check. Once it said yes the provider pays that invoice over that
  channel alone (`RouteSession.bound`; another channel is refused `lock_outstanding`) and does not
  end its window before `validUntil`. A refused lock the ch2's floor covers (nothing pre-signed) is
  dropped. The hub counts a lock only if the provider counted it (`routedSat`). An invoice must be
  valid for the hub's reveal timeout (it was half a second).
- **`spend_final_depth` (item 2)**, 6 by default, at least 1: a hold is given back, a ch2 record
  made final and a refund fee taken back when the spend is that deep (`_spend_depth`), not one block.
  Until then a spend in a block is treated as one in the mempool (its secrets are read), except that
  the hub's own refund is not bumped. The depth is `find_spend_at`'s; with no spender found it is
  counted from the block where the watcher first saw the funding spent (`gone_at`). The test rigs
  mean one confirmation and say `spend_final_depth=1`.
- **Item 12.** A ch1 lock from a ledger before AGP-088 is given its ch2 at the start and on every
  tick (`name_legacy_locks`), and until then matches only a ch2 that holds it. The hub's view of ch1
  lists the last 16 completed written-off locks with their `t + r` (`completed`); `RoutePayer` stops
  counting a held lock that one of them proves completed. The cap check takes nothing off for a ch2
  a changed payTo replaces, and that ch2 is `retired`. A completion ch1's ledger did not take leaves
  the lock on the ch2 record (`ch1_not_written`); `refill_owed` is written with the close; a lock
  pending on an archived open ch2 is written off and that ch2 closed as retired.
- **The routed client's open (items 5, 18).** B1 already opened ch1 in stages through
  `XbtChannelClient._ensure_open` (AGP-090). New: a ch1 the hub has not opened signs no lock, a ch1
  already bound in the signer is not bound again, `open` says `resumed`, `RoutePayer.forget_unfunded`.
  Not in B1: asking the wallet for an earlier send (`fund` is a bare callable).
- **Item 13.** B1's watcher loops already caught a tick that raised (`RouteHub.watch`,
  `watcher.Watcher._loop`): nothing changed.

Tests: `tests/security/test_agp094_hub.py`, `test_agp093_hub.py`. Changed: two lines that asserted
`route_blocked` after a provider refused for a channel-level reason (`test_agp053_make_before_break.py`,
`test_agp057_refill_ahead.py`): refused at the check now, so nothing is written off.

## Fix wave 4, the hub (AGP-088)

The hub items of the second closure audit (AGP-087), as xbt-rs agp-088 (its README has the table).

- **A lock on ch1 is the lock of one ch2.** It records that ch2 (`ch2`, its payer key) and is
  completed or released by its lockId AND that ch2 (`hub.is_lock`), never by the lockId alone, which
  is the provider's choice. A ch2 does not take a lock under a lockId ch1 still holds written off
  (`lock_held`, with the hub's view).
- **"In a block" is not gettxout answering nothing** (a node answers nothing for an output of an
  unconfirmed transaction too): it is the depth `find_spend_at` found the spender at
  (`_spent_in_block`). The test node (`routehelp.RouteNode`) now reports a mined spend through
  `getblock`, as a node does, and no longer through `gettxspendingprevout`.
- **A rolled ch2 is watched until its rollover is in a block**, and refunded at its expiry if it never
  comes. **A refill is funded when this node shows the close**, and `committed_sat` counts a ch2
  until then (`closing` on the provider's word counts; archived records count).
- **The routed client** adopts a completion only with the `t + r` that opens that lock (the view's
  `secret`), and at most `max_held_locks` (2) holds; at that many it pre-signs nothing and asks for
  the hub's view (`POST /x402/route/view`). Trust left: `max_held_locks - 1` locks.
- **Kept intents are bounded for closes too** (`intents_full`): once one slot is left a rollover is
  refused and the state no longer moves, so every close is the same transaction.
- **Smaller:** the locks a confirmed spend did not pay leave ch1 before the ch2 record is final; a
  lock pending on a ch2 that is no longer open is written off; a ch2 with a pending lock is not
  replaced (`connect`: `lock_pending`) nor switched away from; an adopted earlier rollover attempt's
  event carries what it paid.

Tests: `tests/security/test_agp088_hub.py` (13), `test_agp087_hub_a.py`, `test_agp087_hub_b.py`.
