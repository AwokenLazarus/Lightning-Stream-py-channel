# Scheme: `batch-settlement` on XBT (`bip122`) — channel binding

> **Draft proposal, unpublished.** Written against the x402 v2 specification and the scheme
> templates in `x402-foundation/x402` (`specs/scheme_template.md`, `specs/scheme_impl_template.md`,
> `main` at `4fcf836`, 2026-09-25). The full protocol text is `xbt402-spec-v1.1-draft.md` in this
> directory; this file is the part an x402 reviewer needs. The reference implementation emits exactly
> the shapes below (xbt402 v1.1, this binding). This is the XBT network binding of upstream
> `batch-settlement` (`scheme: "batch-settlement"`, `extra.assetTransferMethod: "channel"`).
> `xbt-channel` is accepted as an input alias for one release. See [Appendix: binding name](#binding-name-decided-xbt-binding-of-batch-settlement).

## Summary
`batch-settlement` (XBT channel binding) lets a client pay an HTTP resource per request in XBT through a unidirectional payment
channel between the client and the resource server. The client locks funds once in an on-chain
output. Each request then carries the client's signature on a transaction that pays the server a
slightly higher cumulative total. The server verifies one signature per request and broadcasts only
the last one, before a timelock returns the rest to the client.

It is capital-backed and needs no facilitator. The client's timelocked refund protects the client, and
the client's signatures protect the server. Neither side can take more than one request's price from
the other.

**Why a channel instead of one on-chain payment per request.** A request priced at 150 sat is far
below any transaction fee, and XBT blocks arrive every 7–10 minutes. A channel costs one funding and
one close transaction whatever the number of requests, and verifying a request costs one ECDSA
verification and one HMAC (about 4 ms p50 in the reference server). XBT has no stablecoin and no
facilitator service. It has a young Lightning network (forked LND and Core Lightning, live since
September 2026), but paying through it needs an LN node, a watchtower and an invoice round-trip per
request, and it cannot enforce sub-dust amounts. A direct channel needs none of those.

## Use Cases
- An AI agent paying an inference, search or data API per call, with a budget it cannot exceed.
- Metered responses (`upto`-style): the client authorizes a per-request maximum and the server charges
  the actual cost.
- Machine-to-machine APIs where neither side should hold the other's funds, and the client may go
  offline for good (its refund needs nothing from the server).

## Scheme and Networks
- `scheme` MUST be `"batch-settlement"`. A server MUST also accept `"xbt-channel"` as an input alias for one release and MUST emit `"batch-settlement"` on output.
- `network` uses the CAIP-2 `bip122` namespace. XBT shares Bitcoin's genesis block, so, following the
  convention used for other Bitcoin forks (Bitcoin Cash uses its first post-fork block), the reference is
  the first 32 lowercase hex characters of the hash of block **961640**, XBT's first BLAKE2b
  block:
  - mainnet: `bip122:0000000000000050c1e5f69672f45929`
    (block hash `0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb`);
  - regtest: `bip122:` + the first 32 hex characters of block 101 (where regtest switches to BLAKE2b).
    Regtest identifiers are local; they MUST NOT be accepted by a mainnet server.
- `asset` MUST be `"XBT:sat"`, and `amount` is in satoshis.

### The chain, for readers new to it
XBT is a Bitcoin-derived chain. It shares Bitcoin's history to block 961631; block 961632 is the first
block of the BIP-110 branch (Bitcoin's 961632 differs), and Knots 29.4.x pins 961632–961640 with
checkpoints. From block 961640 its proof of work is BLAKE2b, and Knots 29.4.2 enforces BIP-110 ("RDTS",
a reduced-data soft fork) as consensus until the parent block's median-time-past reaches 2027-09-01
00:00 UTC. The node software is
Bitcoin Knots with the BLAKE2b hard fork; this scheme was tested on Knots 29.4.2. Its script and
transaction formats are Bitcoin's. Four chain rules shape this scheme:
- **BIP-110** makes an output script longer than 34 bytes (83 for OP_RETURN) consensus-invalid and bans
  `OP_IF` in tapscript. So the channel script is P2WSH, and every payout script must be P2WPKH, P2WSH
  or P2TR.
- **`SIGHASH_UNIFIED`** (flag `0x20`, so `ALL|UNIFIED` = `0x21`) makes a signature commit to a different
  message (`UnifiedSighash`), which XBT accepts and SHA-256 Bitcoin rejects. Coins older than the split
  exist on both chains, so a spend signed with a legacy hash type can be replayed on Bitcoin and a `0x21`
  spend cannot. Like BIP341, `UnifiedSighash` commits to every input's amount and scriptPubKey. Every
  signature in this scheme is `0x21`.
- **Coinbase maturity.** Knots 29.4.2 relays no coinbase spend younger than 6,480 blocks (and consensus
  requires that depth for coinbases from 973,440 until 979,920). A channel funded by a coinbase output
  could be neither closed nor refunded in time, so such fundings are refused.
- **Deep reorgs are cheaper than on Bitcoin** (much lower hashrate), so large channels need more
  confirmations.

## Asset Transfer Method and Payment Flow
- One asset transfer method, `"channel"`. `extra.assetTransferMethod` MUST be `"channel"` on offers this binding emits. A client MUST refuse any other explicit value.
- The payment flow is **`authorization`** (the x402 default; `extra.paymentFlow` MAY be omitted): the
  server verifies the channel state, runs the handler, then "settles" by storing the state, as in
  `batch-settlement`. Value moves on-chain only when the channel closes.
- Billing within the channel is `extra.billing`: `"postpay"` (a request is paid by the state sent with
  the next request; the server risks one request) or `"prepay"` (paid before it is served; the client
  risks one request).

## Channel Lifecycle
1. **402.** An unpaid request gets `402` with `PaymentRequirements` (below). `payTo` is the server's
   identity public key.
2. **Derive and fund.** The client picks a fresh key `A` and an `expiry` height. It derives the
   channel's server key `P` from `payTo`, `A` and `expiry` (Keys below), and pays `capacity` sat to
   the P2WSH channel address, signing the funding `0x21`. It signs its own refund transaction and keeps it.
3. **Open.** `POST extra.openUrl` with the funding outpoint and terms. The server rebuilds the script,
   checks the funding on its own node, and records the channel. Before funding, the client asks the
   same endpoint whether it would open on these terms (preflight, below).
4. **Pay.** Each request carries `PAYMENT-SIGNATURE` with the cumulative total `cum`, the client's
   signature on the state transaction for `cum` (when it rises), a strictly increasing `seq`, and an HMAC
   `auth` binding the payload to this exact request.
5. **Close.** At any time, and at the latest at `expiry − closeMarginBlocks`, the server adds its own
   signature to the best state and broadcasts it. The client MAY request a cooperative close
   (`POST extra.closeUrl`) with a final state.
6. **Refund.** From `expiry`, the client can broadcast its refund. If the server has not closed by then,
   the refund and a late close race.

### Keys
All keys are 33-byte compressed secp256k1 keys. `tagged_hash` is the BIP340 tagged hash (SHA-256).
```
NET = UTF-8 of the `network` string, e.g. "bip122:0000000000000050c1e5f69672f45929"
t = int(tagged_hash("xbt-channel/payee/v2", len8(NET) ‖ NET ‖ payTo ‖ A ‖ LE32(expiry))) mod n
P = payTo + t·G                                  (server secret p = payTo_secret + t)
K = tagged_hash("xbt402/auth-key", x(a·P)) = tagged_hash("xbt402/auth-key", x(p·A))
```
`len8(NET)` is one byte, the length of `NET`. `P` is computable from the 402 alone, so opening needs one
round trip, and no two channels share a key. Because `t` commits to the network, one `payTo` used on
several networks derives unrelated channel keys. The 402 advertises the channel binding as
`extra.derivation: "v3"` (this payee key, with the v2 request binding and the v2 receipt below), and a
client MUST refuse any other value before funding. `K` (ECDH) is known
only to the two parties. See Security Considerations for the cost of this derivation.

### Scripts and transactions
Funding output: P2WSH of
```
OP_IF    <P> OP_CHECKSIGVERIFY
OP_ELSE  <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
OP_ENDIF <A> OP_CHECKSIG
```
- Close witness: `[sigA, sigP, 0x01, script]`.
- Refund witness: `[sigA, <empty>, script]`, `nLockTime = expiry`, sequence `0xfffffffe`.

**State transaction for `cum`.** Both sides build it deterministically and never parse it from the peer:
- version 2, locktime 0;
- one input, the funding outpoint, sequence `0xfffffffd`;
- output 0: `cum − payeeFee` → `P2WPKH(P)`;
- output 1: `capacity − payerFee − cum` → the client's payout script (`P2WPKH(A)` or `payerSpk`),
  omitted when below 546;
- `546 + payeeFee ≤ cum ≤ capacity − payerFee`.

`closeFeePayer` (fixed at open, absent = `"payer"`) splits the close fee: `"payer"` gives
`payerFee = closeFeeSat, payeeFee = 0` (the client pays, as on any plain channel); `"payee"` gives
`payerFee = 0, payeeFee = closeFeeSat` (the server pays its own settlement; used on hub-funded routed
channels). `cum` is always what the client has paid.

The client signs it `SIGHASH_ALL|UNIFIED` (`0x21`), strict DER, low S.

## `PaymentRequirements`
```json
{
  "scheme": "batch-settlement",
  "network": "bip122:0000000000000050c1e5f69672f45929",
  "amount": "150",
  "asset": "XBT:sat",
  "payTo": "02caf6f4712d871ae8f807ca4ea6696b088dc1c8bcf6796a6d52f902e2fbb1b770",
  "maxTimeoutSeconds": 30,
  "extra": {
    "minCapacity": "20000",
    "maxCapacity": "10000000",
    "minExpiryBlocks": 1008,
    "maxExpiryBlocks": 8640,
    "closeMarginBlocks": 144,
    "minConf": 1,
    "closeFeeSat": "600",
    "openUrl": "/x402/xbt-channel/open",
    "closeUrl": "/x402/xbt-channel/close",
    "billing": "postpay",
    "derivation": "v3",
    "assetTransferMethod": "channel"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `amount` | string | yes | Per-request **maximum**, in sat. The server may charge less. |
| `payTo` | string | yes | Server identity key, 33-byte compressed, hex. Not an address. |
| `extra.minCapacity`, `extra.maxCapacity` | string | yes | Accepted channel sizes, sat. |
| `extra.minExpiryBlocks`, `extra.maxExpiryBlocks` | number | yes | Accepted `expiry − tip` at open, in blocks. |
| `extra.closeMarginBlocks` | number | yes | The server stops serving and closes at `expiry − closeMarginBlocks`. |
| `extra.minConf` | number | yes | Funding confirmations before the channel is credited. Servers MAY require more for large channels. |
| `extra.closeFeeSat` | string | yes | Close fee, fixed for the channel's life. Clients SHOULD cap it. |
| `extra.closeFeePayer` | string | no | `"payer"` (default: the client's side pays the close fee) or `"payee"` (the server's output does). Clients MUST refuse other values before funding. |
| `extra.openUrl`, `extra.closeUrl` | string | yes | Channel control endpoints, relative to the resource origin. |
| `extra.billing` | string | yes | `"postpay"` or `"prepay"`. |
| `extra.derivation` | string | yes | Channel binding, `"v3"`: the payee key (Keys), request binding v2 and receipt v2. Clients MUST refuse other values before funding. |
| `extra.conditional` | object | no | Hash-locked deliverable (experimental; see Appendix). |

On a refused request the server returns a new 402 whose `error` is the refusal reason. It adds
`"channel": {"chan","cum","seq","spentMsat"}` to the `PaymentRequired` object **only** if the request was
authenticated for that channel.

## Payment payload
### Open request (once per channel)
`POST extra.openUrl` (the server rebuilds `redeemScript` from `network`, `payTo`, `A` and `expiry`):
```json
{"x402Version":2,"network":"bip122:0000000000000050c1e5f69672f45929",
 "channel":{"txid":"<funding txid>","vout":0,"capacity":200000,"expiry":2014,
            "payerPub":"<A>","payerSpk":"<optional payout script>","redeemScript":"<script hex>",
            "closeFeePayer":"<optional: payer | payee>"}}
```
Reply `200 {"chan":"<txid>:<vout>","expiry":2014,"maxCum":"199400","confirmations":1}` (a payee-pays
open adds `"closeFeePayer":"payee","minCum":"1146"`), or `400 {"error","detail"}`. A server MUST accept
`closeFeePayer: "payer"` and MUST refuse `"payee"` it did not offer (`invalid_batch_settlement_xbt_fee_payer`).
A client MUST check the echoed `closeFeePayer` (absent = `"payer"`) before signing a state.

`chan` is canonical: the txid in 64 lowercase hex, `:`, the output index in decimal with no leading zeros.

**Preflight (before funding).** A client SHOULD first send the same request with `"preflight": true`
and a `channel` without `txid` and `vout`. The server runs every check of the funded open that does not
need the funding output (network, `closeFeePayer`, `redeemScript`, capacity and expiry against its
policy), records nothing, and replies `200 {"preflight":true,"expiry":2014,"maxCum":"199400","minConf":1}`
(plus `closeFeePayer` and `minCum` under payee-pays), or with the refusal the funded open would get.
Then a refusal, such as a stale `payTo` after a server restart, costs the client nothing on-chain. A
server from before this rule answers `bad_request` (no `vout`) only after its own terms checks pass,
so on that answer the client funds and opens as before.

### `PAYMENT-SIGNATURE`
```json
{
  "x402Version": 2,
  "accepted": { "...": "the PaymentRequirements object from the 402" },
  "payload": {
    "chan": "1a3bbba628a29edc3ec0befb30cc2a422db05d610229887a8aa24854dfe5b969:0",
    "seq": 5,
    "cum": "600",
    "sig": "3044…21",
    "auth": "9c1e…"
  }
}
```
| Field | Required | Description |
|---|---|---|
| `chan` | yes | Channel id from the open. |
| `seq` | yes | Integer, strictly greater than every `seq` the server has accepted on this channel. |
| `cum` | yes | Cumulative sat signed to the server (decimal string). |
| `sig` | when `cum` rises | Client's DER signature ‖ `0x21` on the state transaction for `cum`, hex. |
| `auth` | yes | `hex(HMAC-SHA256(K, "xbt402/auth|" ‖ chan ‖ "|" ‖ seq ‖ "|" ‖ cum ‖ "|" ‖ (sig or "") ‖ "|" ‖ req))`. |
| `hashlock` | conditional only | See Appendix. |

**Request binding.**
```
req = hex(tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body)))
f(x) = LE64(len(x)) ‖ x
```
over the absolute URL the request was sent to. `scheme` and `host` are ASCII-lowercased (an IPv6
literal keeps its brackets), userinfo and fragment are dropped, `port` is decimal without leading
zeros or the scheme's default (`80` for http, `443` for https), and `target` is the path and query
exactly as sent (not percent-decoded; `/` when empty). `body` is the raw body bytes. The server
rebuilds the URL from its public scheme, the `Host` header and the request target. A payload with
no request (a close) binds the empty request `("", "", "", "", "", "")`. Every field is
length-prefixed, so no two requests share a digest; the v1 form `SHA256(method|target|body)` let
`("/q?a|b", "")` and `("/q?a", "b|")` collide and bound no origin. `auth` ties one payload to one
request at one origin, one `seq` and one state, so a captured header can be neither replayed nor
moved to another request or origin. A request MUST carry at most one `PAYMENT-SIGNATURE` header.

**Client construction.** Under postpay, `cum = max(⌈spentMsat / 1000⌉, last signed)`; under prepay
it also adds this request's `amount`. A `cum` between 1 and 545 is raised to 546. Sign only when `cum`
rises, and never sign a lower `cum` than before.

## Verification
The resource server (or a facilitator acting for it) MUST apply these checks in order. The cost is
constant: one HMAC, at most one ECDSA verification, no node call on the request path.
1. `x402Version` is 2, and `accepted.scheme`, `accepted.network` and `accepted.payTo` match its own
   (`invalid_batch_settlement_xbt_scheme_or_network`); the payload decodes (`invalid_batch_settlement_xbt_payload`).
2. The canonical `chan` is a known open channel (`invalid_batch_settlement_xbt_unknown_channel`).
3. `auth` is valid, compared in constant time, and `seq` is fresh (`invalid_batch_settlement_xbt_auth`). The
   refusal MUST NOT reveal anything about the channel. Then record `seq`; it is consumed even if the
   request is refused later.
4. The channel is not closed and `tip < expiry − closeMarginBlocks` (`invalid_batch_settlement_xbt_closing`). The
   tip MAY be cached for a few seconds.
5. The funding is still confirmed to the required depth (`invalid_batch_settlement_xbt_unconfirmed`).
6. If `cum` is below the stored value: `invalid_batch_settlement_xbt_stale_amount`. If above: `sig` ends in
   `0x21` (`invalid_batch_settlement_xbt_sighash`), is BIP66 strict DER with low S, **checked before signature
   verification**, and verifies under `A` over the `UnifiedSighash` of the state transaction for `cum`
   (`invalid_batch_settlement_xbt_signature`). `cum` must be within `[546, capacity − closeFeeSat]`
   (`invalid_batch_settlement_xbt_amount`). If equal with a different signature: `invalid_batch_settlement_xbt_signature`.
7. Billing: postpay requires `cum·1000 ≥ spentMsat`; prepay requires `cum·1000 ≥ spentMsat + amount·1000`
   (`invalid_batch_settlement_xbt_insufficient_payment`).
8. `spentMsat + amount·1000 ≤ (capacity − closeFeeSat)·1000` (`invalid_batch_settlement_xbt_exhausted`).

A refusal is returned as `402` with a fresh `PaymentRequired` whose `error` is the code.

**Open checks.** The server MUST refuse an open whose `network` is not its own; whose `payerPub` is not a
valid key; whose `payerSpk` is not P2WPKH, P2WSH or P2TR (a longer script makes every close
consensus-invalid under BIP-110); whose `redeemScript` differs from the script rebuilt from
`(payTo, A, expiry)`; whose canonical `chan` is already known; or, checked on its own node, whose
funding is unknown, a coinbase output, of the wrong script or value, outside the capacity or expiry
bounds, or not confirmed deeply enough.

## Settlement
Settlement has two levels, as in `batch-settlement`:
1. **Per request (store).** After verification the server reserves `amount` against the channel,
   durably records the new state (`cum`, `sig`, `seq`, `spentMsat`) **before** running the handler,
   then charges the actual amount (≤ `amount`) and releases the rest. A handler response with status
   ≥ 500 is not charged. A higher state accepted on a request that is then refused MUST still be
   recorded.
2. **Redeem (close).** The server completes the best state with its own `0x21` signature and broadcasts
   it: on a cooperative close request, whenever it chooses, and at the latest at
   `expiry − closeMarginBlocks`. Only the server can complete a state, and every older state pays it
   less, so there is nothing to dispute on-chain.

A **watcher** (at least once per block) MUST, for each channel independently: suspend a channel whose
funding is no longer confirmed to depth (reorg), close channels reaching the margin, and rebroadcast a
close whose funding is unspent again. It SHOULD bump a stuck close by CPFP from the server's output. It
MUST be supervised: after `expiry`, a missing close means the client's refund wins.

The reference watcher bumps every block the close is unconfirmed. It works out the package feerate the
close needs: the highest of a configured minimum, the node's estimate for confirming within a quarter
of the blocks left, and the mempool's floor, doubled from the last send once a few blocks pass without a
confirmation in the second half of the margin. It sends the close alone if that pays enough, and
otherwise sends a package (`submitpackage`): the close plus a child that spends the server's own close
output back to its key and pays the difference. Each new child replaces the last (BIP125). The child's
fee is capped by configuration and by that output less dust. Package relay lets a close below the
mempool's dynamic floor in on its child's fee, but not one below the node's static `minrelaytxfee`.

### `PAYMENT-RESPONSE`
Every served request returns a `SettlementResponse` with an empty `transaction` and `amount` (nothing was
broadcast) and the channel receipt in `extra`:
```json
{
  "success": true,
  "transaction": "",
  "network": "bip122:0000000000000050c1e5f69672f45929",
  "payer": "<A hex>",
  "amount": "",
  "extra": {
    "chargedAmount": "150",
    "receipt": {"scheme":"xbt-channel","chan":"…:0","seq":5,"cum":"600","charged":"150",
                "spentMsat":"750000","owedMsat":"150000","creditMsat":"0","expiry":2014,
                "req":"<hex>","status":200,"bodyHash":"<hex>","sig":"<DER hex>"}
  }
}
```
`receipt.sig` is `P`'s ECDSA signature over
`tagged_hash("xbt402/receipt/v2", f(chan) ‖ f(seq) ‖ f(cum) ‖ f(charged) ‖ f(spentMsat) ‖ f(req) ‖ f(status) ‖ f(bodyHash))`,
each field in its decimal or hex text form. `status` is the HTTP status of the answer and `bodyHash`
the hex SHA-256 of its body exactly as sent. `seq`, `cum` and `spentMsat` are the numbers of this
request's own reservation: a request served beside it does not change them.
Only the receipt is signed. `extra.chargedAmount` MUST equal `receipt.charged`, and `success` is `true`
when the handler's status is below 400.

**Client checks.** `network` and `payer` are its channel's; the receipt verifies under `P`; `req` is the
digest of its own request; `status` and `bodyHash` match the answer it received (a truncated or
altered body is not the answer that was paid for); `cum` is not above what it signed; `charged ≤ amount`; `spentMsat` grew by
at most one request. On a conditional request the client keeps the hash lock and its ciphertext pending
until the receipt checks out, so after a `bad_receipt` it still recovers the deliverable from the
payee's claim, which reveals k. On a 402 for an open channel, the client MUST NOT accept a higher `amount` than it
opened the channel with, and MUST NOT adopt more than one request's worth of unreceipted charges over
the channel's life. Otherwise a malicious server could drain the channel with 402 loops.

### Close
`POST extra.closeUrl` with `{"chan","sig","payload"?}`. `sig` is `A`'s signature over
`tagged_hash("xbt402/close", chan)`; `payload` is an optional final state (as in `PAYMENT-SIGNATURE`).
Reply `{"chan","txid","cum","unpaidMsat"}`: `cum` is the gross state the client paid and `unpaidMsat`
= `spentMsat − cum × 1000` (at least 0). Under `closeFeePayer: "payee"` the reply adds `"payeeFee"` (sat)
and `"payeeNet"` (`cum − payeeFee`, the server's output); the server's close fee is never reported as
unpaid.

## Facilitator Interface
Optional. The reference server needs no facilitator. A server that exposes the standard interface MUST
serve it under `/x402/` (`/x402/verify`, `/x402/settle`, `/x402/supported`), never at bare paths that
could shadow the API's own routes.

### POST /x402/verify
Request: `{"x402Version":2,"paymentPayload":{"x402Version":2,"accepted":{…},"payload":{"chan","cum","sig"}},
"paymentRequirements":{…}}`. Both `paymentRequirements` and `paymentPayload.accepted` MUST name this
scheme, the server's network and its `payTo`. It checks a signed state and records it if higher. It is
unauthenticated, so it:
- MUST require `sig` for exactly the `cum` given;
- MUST NOT move `seq`, and MUST NOT check `auth` (a stranger could otherwise lock a client out with a
  huge `seq`);
- MUST report only what the caller sent;
- MUST answer `isValid: false` for a channel that is closed, closing or suspended
  (`invalid_batch_settlement_xbt_closing` / `invalid_batch_settlement_xbt_unconfirmed`), whatever the signature: a resource
  server serves on `isValid`.
```json
{"isValid":true,"payer":"<A hex>","extra":{"chan":"…:0","cum":"600"}}
```
or `{"isValid":false,"invalidReason":"invalid_batch_settlement_xbt_signature"}`, both with HTTP 200. A client
also uses it to hand over the plain state that folds a hash-locked increment (Appendix).

### POST /x402/settle
Request as for `/verify`, with `paymentPayload.payload` = `{"chan","sig","payload"?}` (the close
request). It closes the channel; settling a channel that is already closed returns the same close:
```json
{"success":true,"transaction":"<close txid>","network":"bip122:…","payer":"<A hex>","amount":"750",
 "extra":{"chan":"…:0","unpaidMsat":"0"}}
```
`amount` is the gross `cum` of the recorded close (under `"payee"`, `extra` adds `payeeFee` and
`payeeNet`); repeats report that same close, and a
`payload` sent after the close changes nothing. A refusal is
`{"success":false,"errorReason":"invalid_batch_settlement_xbt_signature","transaction":"","network":"bip122:…"}`.

### GET /x402/supported
```json
{"kinds":[{"x402Version":2,"scheme":"xbt-channel","network":"bip122:0000000000000050c1e5f69672f45929"}],
 "extensions":[],"signers":{}}
```

## Error Codes

`invalidReason` and `errorReason` carry the error code. The 402 `error` field and the `400 {"error"}`
answers of `openUrl` and `closeUrl` carry the short code in the second column: the reference keeps the
short codes there until the scheme name is decided, because a `batch-settlement` binding would change
the prefix (Appendix). The mapping is one to one.

| Error code | Short code | Meaning |
|---|---|---|
| `invalid_batch_settlement_xbt_scheme_or_network` | `unsupported_scheme_or_network` | Scheme, network or `payTo` differs |
| `invalid_batch_settlement_xbt_payload` | `bad_payload` | Undecodable or malformed payload |
| `invalid_batch_settlement_xbt_unknown_channel` | `unknown_channel` | No such open channel |
| `invalid_batch_settlement_xbt_auth` | `bad_auth` | `auth` invalid or `seq` not fresh |
| `invalid_batch_settlement_xbt_closing` | `channel_closing` | Closed, or inside the close margin |
| `invalid_batch_settlement_xbt_unconfirmed` | `unconfirmed` | Funding not confirmed to the required depth |
| `invalid_batch_settlement_xbt_stale_amount` | `stale_amount` | `cum` below the stored state |
| `invalid_batch_settlement_xbt_signature` | `bad_sig` | State signature invalid, not strict DER, or differs for the same `cum` |
| `invalid_batch_settlement_xbt_sighash` | `bad_sighash` | Signature hash type is not `0x21` |
| `invalid_batch_settlement_xbt_amount` | `bad_amount` | `cum` outside `[minCum, maxCum]` (`[546, capacity − closeFeeSat]` under payer-pays) |
| `invalid_batch_settlement_xbt_fee_payer` | `bad_fee_payer` | `closeFeePayer` not offered for this channel |
| `invalid_batch_settlement_xbt_hashlock` | `bad_hashlock` | Conditional call with the wrong hash |
| `invalid_batch_settlement_xbt_conditional_outstanding` | `conditional_outstanding` | A hash-locked increment is not folded yet |
| `invalid_batch_settlement_xbt_insufficient_payment` | `insufficient_payment` | `cum` does not cover the billing rule |
| `invalid_batch_settlement_xbt_exhausted` | `channel_exhausted` | The channel cannot cover another request |
| `invalid_batch_settlement_xbt_coinbase_funding` | `coinbase_funding` | Funding is a coinbase output |
| `invalid_batch_settlement_xbt_funding` | `bad_funding` | Script or value mismatch, or `redeemScript` differs |
| `invalid_batch_settlement_xbt_unknown_funding` | `unknown_funding` | Funding transaction not found |
| `invalid_batch_settlement_xbt_capacity` | `bad_capacity` | Capacity outside the advertised range |
| `invalid_batch_settlement_xbt_expiry` | `bad_expiry` | Expiry outside the advertised range |
| `invalid_batch_settlement_xbt_payer_spk` | `bad_payer_spk` | `payerSpk` is not P2WPKH, P2WSH or P2TR |
| `invalid_network` | `wrong_network` | Open for another network |
| `invalid_batch_settlement_xbt_duplicate_channel` | `duplicate_channel` | Channel already open |
| `unexpected_settle_error` | `close_failed` | The node refused the close |

## Security Considerations
### Neither side can steal
A state counts only with `A`'s signature over its exact outputs, and only `P` can complete it, so the
server can never take more than the client signed, and the client can never broadcast a state. A
postpay server risks one request; a prepay client risks one request.

### Signature encoding and hash type
Verifiers MUST reject non-strict-DER and high-S signatures before verifying: some ECDSA libraries accept
BER, but segwit v0 consensus does not, and a state that verifies only in software can never be closed.
Every state signature MUST be `0x21`. `UnifiedSighash` commits to the funding outpoint, amount and
script, so a state cannot be moved to another channel and cannot be replayed on SHA-256 Bitcoin.

### Channel identity
Nodes parse txids case-insensitively. A server that keys channels by the string it received can be made
to open one funding under several ids and credit one state several times. Servers MUST canonicalize every
channel id.

### Client payout script
Under BIP-110 an output script over 34 bytes is consensus-invalid. An unchecked `payerSpk` would let a
client make every close invalid while being served; servers MUST accept only P2WPKH, P2WSH and P2TR.

### Replay and bearer tokens
Without `auth`, `{chan, cum}` is a bearer token: anyone who sees a channel id could spend the client's
prepaid credit, and a captured header could be replayed. `auth` binds each payload to one request and a
fresh `seq`. Refusals reveal channel state only to authenticated callers. The unauthenticated `/verify`
needs a signature for the exact `cum` and never moves `seq`.

### Reorgs
XBT's hashrate is small next to Bitcoin's, so orphaning a block is comparatively cheap. An attacker can
open many channels in a block it plans to orphan and double-spend. Servers MUST re-check fundings every
block, suspend channels whose funding is no longer confirmed, and SHOULD require more confirmations for
large channels (the reference: 3 above 1,000,000 sat).

### Key derivation (known weakness)
`P = payTo + t·G` with public `t` is non-hardened: any single leaked per-channel secret `p` reveals
`payTo_secret = p − t`, hence every channel's key. Servers MUST NOT export per-channel secrets
(delegate closing by handing out signed close transactions), and MUST sign in constant time (the
server signs a receipt on every paid request, which gives any client a signing oracle). `t` commits to
the network, so a `payTo` reused on a test network does not derive production channel keys; servers
MUST still use a distinct `payTo` per network, since `payTo_secret` itself is one key. A hardened
derivation would need a server-chosen key per channel and a second round trip before funding.

### Who pays the close fee
Under `closeFeePayer: "payee"` the client's output is `capacity − cum`: it depends on `cum` alone, so no
choice of the server's, `closeFeeSat` included, can lower it, and the client's `0x21` signature (over
every output) commits to the fee payer, so a state signed under one value does not verify under the
other. The server's output must clear 546 after the fee, so the least state is `546 + closeFeeSat`. The
server bumps its own close (CPFP from its output, or a `0xA3` state whose output 0 stays the client's
`capacity − cum`). In a hash-locked state the fee comes out of the server's unconditional output, never
the hash-lock output. A server settles once its **net** payout `cum − closeFeeSat` reaches its settle
threshold, and refuses a payee-pays rollover below it except near its close margin, so a client cannot
make it pay many close fees on small payouts.

### Fees and timing
The close fee is fixed at open. A fee spike longer than the close margin can delay the close past
`expiry`, when the client's refund can win. Mitigations: CPFP from the server's output, an optional
`SINGLE|ANYONECANPAY|UNIFIED` (`0xA3`) fee-input state whose output 0 is the client's change, and a
margin sized in blocks, not hours (XBT block intervals have varied widely).

### Hot keys
The server's identity key must be online to sign receipts and closes; its compromise exposes the
server's earned, unswept funds (not the clients'). The client's channel key must be online to sign
states; its compromise exposes that channel's unspent capacity. Clients SHOULD sign through a policy
signer with per-request, per-channel and per-day limits and an allowlist of `payTo` keys.

### HTTP layer
Servers MUST bound request bodies, refuse `Transfer-Encoding` where they cannot handle it safely, accept
one `PAYMENT-SIGNATURE`, and never emit a handler header containing CR, LF or NUL.

### Privacy
Funding and close link client and server on-chain, and the close reveals both keys. Per-channel keys
avoid reuse across channels. Individual requests never touch the chain.

## Test Vectors
`vectors.json` in this directory holds byte-exact vectors: the key derivation on three networks (with
the v1.0 key for the same inputs, which a v1.1 server refuses), `K` and three `auth` values, four state
transactions with their sighashes and signatures, a signed close and refund, three invalid signatures,
and a full exchange (402, open, five paid requests with exact `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`
values, a refused replay, `/x402/supported`, a valid and an invalid `/x402/verify`, the cooperative
close and `/x402/settle`), a hash-locked conditional request, and a payee-pays (`closeFeePayer`)
channel's states, close, `0xA3` state, rollover and conditional state with its refusals and its open.
`check_vectors.py` recomputes them all from the reference implementation, under both libsecp256k1 and
a pure-Python backend.

## Reference Implementation
Python (`xbt402` v1.1, stdlib plus `coincurve`/libsecp256k1): server, client SDK, ASGI middleware, httpx
transport, watcher, SQLite channel store, and an MCP tool for AI agents that returns the provider's
answer as labelled untrusted data. Tested against Knots 29.4.2 with BIP-110 enforced: funding,
close and refund relay between nodes; a 1,000-request run settles exactly on-chain; the refund wins
after `expiry` and a late close is rejected. It has been through a security review whose Critical and
High findings are fixed and covered by tests.

## Appendix
### Binding name: decided — XBT binding of `batch-settlement`
Mike decided 2026-09-30: this is the **XBT network binding of upstream `batch-settlement`**, not a new
scheme. The wire is `scheme: "batch-settlement"` with `extra.assetTransferMethod: "channel"`. Errors
are `invalid_batch_settlement_xbt_*`. Servers and clients accept `"xbt-channel"` as an input alias for
one release and emit `"batch-settlement"`. The derivation tag `xbt-channel/payee/v2` and the control
paths `/x402/xbt-channel/*` are unchanged, so existing channels and keys are unaffected.

| Item | Value after AGP-050 |
|---|---|
| `scheme` on the wire (emit) | `"batch-settlement"` |
| `scheme` accepted on input | `"batch-settlement"` or `"xbt-channel"` (one release) |
| Spec file | `specs/schemes/batch-settlement/scheme_batch_settlement_xbt.md` (not `_bitcoin`; that is PR #3544) |
| Error prefix | `invalid_batch_settlement_xbt_*` |
| `extra.assetTransferMethod` | `"channel"` (emitted) |
| Control paths | `/x402/xbt-channel/open`, `/close`, `/rollover`, `/terms`, `/lock` (advertised in `extra`) |
| Key-derivation tag | `xbt-channel/payee/v2` (unchanged) |

**Mapping to what `batch-settlement` requires of a network binding:**

| `batch-settlement` requirement | This scheme | Section |
|---|---|---|
| Commitment format | A `0x21` signature on the state transaction for `cum`, plus `chan`, `seq`, `auth` | Payment payload |
| Verification rules | Eight ordered checks, constant cost (one HMAC, at most one ECDSA verification, no node call) | Verification |
| Storage and commitment id | The channel `chan` (funding outpoint); the best `(cum, sig)`, `seq` and `spentMsat` recorded before serving | Settlement, step 1 |
| Double-spend prevention | Cumulative states (only the highest pays), a strictly increasing `seq`, and `auth` binding one payload to one request | Verification, steps 3 and 6 |
| Commitment expiry | The CLTV `expiry`; the server stops serving and closes at `expiry − closeMarginBlocks` | Channel Lifecycle, Settlement |
| Redemption | The server completes and broadcasts the best state (`closeUrl`, `/x402/settle`, or the watcher) | Settlement, step 2; Close |
| Trust model | Capital-backed: the client's refund protects the client, its signatures protect the server; each risks at most one request | Security Considerations |

### Hash-locked conditional requests (experimental)
A server MAY offer a deliverable that is paid atomically with a secret: `extra.conditional =
{"hash","amount","csvDelta","cipher"}`, where `cipher` is the deliverable encrypted under `k`
(`SHA256(k) = hash`). The client MUST have the ciphertext before it signs, MUST hold `amount` to its
per-request cap, and signs a state paying `amount` to
`OP_IF OP_SHA256 <H> OP_EQUALVERIFY <P> OP_CHECKSIG OP_ELSE <csvDelta> OP_CSV OP_DROP <A> OP_CHECKSIG OP_ENDIF`
(P2WSH). The response body carries `k`. Once `k` checks, the client decrypts the ciphertext it was
offered, signs a plain state for the folded total and hands it over (`/x402/verify` or its next request).
A server that offers conditional requests MUST close with the conditional state whenever it pays more
than the best plain state, MUST record that close before broadcasting it, and then MUST claim the
hash-lock output with `k` before `csvDelta` blocks pass, raising the claim's fee as needed. The claim
publishes `k`, so a client whose response was lost still gets the deliverable from the ciphertext it
holds; for the same reason the server MUST use a fresh `k` for every sale. It MUST refuse a new
conditional request while one increment is unfolded (`invalid_batch_settlement_xbt_conditional_outstanding`).
The reference server does all of this.

### Open questions
- `asset: "XBT:sat"` is not a CAIP-19 identifier. Is a slip44-style `bip122:…/slip44:0` preferred, or a
  bare `"XBT"` with `amount` in sat, as `exact` on `lnbtc` uses `"BTC"`?
- `network` uses the first post-fork (first BLAKE2b) block rather than genesis, as other Bitcoin forks do.
  Is that acceptable in the registry, and is a regtest identifier worth listing?
- Should `billing` be expressed through `paymentFlow` instead of a scheme-private `extra` field?

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1-draft | 2026-09-25 | First draft against x402 v2 (`x402-foundation/x402` `main` `4fcf836`), from xbt402 v1.0/v1.1-draft |
| 0.2-draft | 2026-09-25 | Matches the xbt402 v1.1 reference: network in the key tweak (`extra.derivation: "v2"`), `SettlementResponse` and facilitator shapes implemented, enforceable hash-locked close, binding-name appendix |
| 0.3-draft | 2026-09-28 | xbt402 v1.2: optional `closeFeePayer` (`"payer"` default, `"payee"`), `minCum`, `invalid_xbt_channel_fee_payer` (renamed in 0.4), payee-pays vectors; wire-compatible with 0.2 |
| 0.4-draft | 2026-09-30 | AGP-050: wire `scheme` is `batch-settlement`, `extra.assetTransferMethod: "channel"`, errors `invalid_batch_settlement_xbt_*`; `xbt-channel` accepted as an input alias |
| 0.5-draft | 2026-10-08 | xbt402 v1.3 (AGP-068), not wire-compatible with 0.4: `extra.derivation: "v3"`; request binding v2 (length-prefixed, binds scheme, host and port); receipt v2 adds `status` and `bodyHash`; receipt numbers are the request's own reservation |
