# Scheme: `xbt-channel` on XBT (`bip122`)

> **Draft proposal, unpublished.** Written against the x402 v2 specification and the scheme
> templates in `x402-foundation/x402` (`specs/scheme_template.md`, `specs/scheme_impl_template.md`,
> `main` at `4fcf836`, 2026-09-25). The full protocol text is `xbt402-spec-v1.1-draft.md` in this
> directory; this file is the part an x402 reviewer needs. See [Appendix: relationship to
> `batch-settlement`](#relationship-to-batch-settlement) before deciding where it belongs upstream.

## Summary
`xbt-channel` lets a client pay an HTTP resource per request in XBT through a unidirectional payment
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
verification and one HMAC (about 4 ms p50 in the reference server). XBT has no stablecoin, no
Lightning network and no facilitator service. A direct channel is the only rail that works for
sub-cent HTTP payments on it today.

## Use Cases
- An AI agent paying an inference, search or data API per call, with a budget it cannot exceed.
- Metered responses (`upto`-style): the client authorizes a per-request maximum and the server charges
  the actual cost.
- Machine-to-machine APIs where neither side should hold the other's funds, and the client may go
  offline for good (its refund needs nothing from the server).

## Scheme and Networks
- `scheme` MUST be `"xbt-channel"`.
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
XBT is a Bitcoin-derived chain. It shares Bitcoin's history to block 961631, enforces BIP-110 ("RDTS",
a reduced-data soft fork) from 961632, and uses BLAKE2b proof of work from 961640. The node software is
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
- One asset transfer method, `"channel"`. `extra.assetTransferMethod` MAY be omitted; any explicit value
  MUST be `"channel"`.
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
   checks the funding on its own node, and records the channel.
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
t = int(tagged_hash("xbt-channel/payee", payTo ‖ A ‖ LE32(expiry))) mod n
P = payTo + t·G                                  (server secret p = payTo_secret + t)
K = tagged_hash("xbt402/auth-key", x(a·P)) = tagged_hash("xbt402/auth-key", x(p·A))
```
`P` is computable from the 402 alone, so opening needs one round trip, and no two channels share a key.
`K` (ECDH) is known only to the two parties. See Security Considerations for the cost of this
derivation.

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
- output 0: `cum` → `P2WPKH(P)`;
- output 1: `capacity − closeFeeSat − cum` → the client's payout script (`P2WPKH(A)` or `payerSpk`),
  omitted when below 546;
- `546 ≤ cum ≤ capacity − closeFeeSat`.

The client signs it `SIGHASH_ALL|UNIFIED` (`0x21`), strict DER, low S.

## `PaymentRequirements`
```json
{
  "scheme": "xbt-channel",
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
    "billing": "postpay"
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
| `extra.closeFeeSat` | string | yes | Close fee, fixed for the channel's life, paid from the client's side. Clients SHOULD cap it. |
| `extra.openUrl`, `extra.closeUrl` | string | yes | Channel control endpoints, relative to the resource origin. |
| `extra.billing` | string | yes | `"postpay"` or `"prepay"`. |
| `extra.conditional` | object | no | Hash-locked deliverable (experimental; see Appendix). |

On a refused request the server returns a new 402 whose `error` is the refusal reason. It adds
`"channel": {"chan","cum","seq","spentMsat"}` to the `PaymentRequired` object **only** if the request was
authenticated for that channel.

## Payment payload
### Open request (once per channel)
`POST extra.openUrl`:
```json
{"x402Version":2,"network":"bip122:0000000000000050c1e5f69672f45929",
 "channel":{"txid":"<funding txid>","vout":0,"capacity":200000,"expiry":2014,
            "payerPub":"<A>","payerSpk":"<optional payout script>","redeemScript":"<script hex>"}}
```
Reply `200 {"chan":"<txid>:<vout>","expiry":2014,"maxCum":"199400","confirmations":1}`, or
`400 {"error","detail"}`.

`chan` is canonical: the txid in 64 lowercase hex, `:`, the output index in decimal with no leading zeros.

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

**Request binding.** `req = hex(SHA256(method ‖ "|" ‖ target ‖ "|" ‖ body))`, where `target` is the
request target exactly as sent (path and query, not percent-decoded) and `body` the raw body bytes.
`auth` ties one payload to one request, one `seq` and one state, so a captured header can be neither
replayed nor moved to another request. A request MUST carry at most one `PAYMENT-SIGNATURE` header.

**Client construction.** Under postpay, `cum = max(⌈spentMsat / 1000⌉, last signed)`; under prepay
it also adds this request's `amount`. A `cum` between 1 and 545 is raised to 546. Sign only when `cum`
rises, and never sign a lower `cum` than before.

## Verification
The resource server (or a facilitator acting for it) MUST apply these checks in order. The cost is
constant: one HMAC, at most one ECDSA verification, no node call on the request path.
1. `x402Version` is 2, and `accepted.scheme`, `accepted.network` and `accepted.payTo` match its own
   (`invalid_xbt_channel_scheme_or_network`); the payload decodes (`invalid_xbt_channel_payload`).
2. The canonical `chan` is a known open channel (`invalid_xbt_channel_unknown_channel`).
3. `auth` is valid, compared in constant time, and `seq` is fresh (`invalid_xbt_channel_auth`). The
   refusal MUST NOT reveal anything about the channel. Then record `seq`; it is consumed even if the
   request is refused later.
4. The channel is not closed and `tip < expiry − closeMarginBlocks` (`invalid_xbt_channel_closing`). The
   tip MAY be cached for a few seconds.
5. The funding is still confirmed to the required depth (`invalid_xbt_channel_unconfirmed`).
6. If `cum` is below the stored value: `invalid_xbt_channel_stale_amount`. If above: `sig` ends in
   `0x21` (`invalid_xbt_channel_sighash`), is BIP66 strict DER with low S, **checked before signature
   verification**, and verifies under `A` over the `UnifiedSighash` of the state transaction for `cum`
   (`invalid_xbt_channel_signature`). `cum` must be within `[546, capacity − closeFeeSat]`
   (`invalid_xbt_channel_amount`). If equal with a different signature: `invalid_xbt_channel_signature`.
7. Billing: postpay requires `cum·1000 ≥ spentMsat`; prepay requires `cum·1000 ≥ spentMsat + amount·1000`
   (`invalid_xbt_channel_insufficient_payment`).
8. `spentMsat + amount·1000 ≤ (capacity − closeFeeSat)·1000` (`invalid_xbt_channel_exhausted`).

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

### `PAYMENT-RESPONSE`
Every served request returns a `SettlementResponse` with an empty `transaction` (nothing was broadcast)
and the channel receipt in `extra`:
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
                "req":"<hex>","sig":"<DER hex>"}
  }
}
```
`receipt.sig` is `P`'s ECDSA signature over
`tagged_hash("xbt402/receipt", chan ‖ "|" ‖ seq ‖ "|" ‖ cum ‖ "|" ‖ charged ‖ "|" ‖ spentMsat ‖ "|" ‖ req)`.

> **Conformance note.** The reference implementation (xbt402 v1.0) sends the receipt object itself as
> the `PAYMENT-RESPONSE` value, with `success`, `scheme` and `network` at top level. The envelope above
> is the proposed upstream form. The receipt fields and signature are unchanged; see the spec's §13.

**Client checks.** The receipt verifies under `P`; `req` is the digest of its own request; `cum` is not
above what it signed; `charged ≤ amount`; `spentMsat` grew by at most one request. On a 402 for an
open channel, the client MUST NOT accept a higher `amount` than it opened the channel with, and MUST
NOT adopt more than one request's worth of unreceipted charges over the channel's life. Otherwise a
malicious server could drain the channel with 402 loops.

### Close
`POST extra.closeUrl` with `{"chan","sig","payload"?}`. `sig` is `A`'s signature over
`tagged_hash("xbt402/close", chan)`; `payload` is an optional final state (as in `PAYMENT-SIGNATURE`).
Reply `{"chan","txid","cum","unpaidMsat"}`.

## Facilitator Interface
Optional. The reference server needs no facilitator. A server that exposes the standard interface MUST
serve it under `/x402/` (`/x402/verify`, `/x402/settle`, `/x402/supported`), never at bare paths that
could shadow the API's own routes.

### POST /x402/verify
Request: `{"x402Version":2,"paymentPayload":{…},"paymentRequirements":{…}}`. It checks a signed state and
records it if higher. It is unauthenticated, so it:
- MUST require `sig` for exactly the `cum` given;
- MUST NOT move `seq`, and MUST NOT check `auth` (a stranger could otherwise lock a client out with a
  huge `seq`);
- MUST report only what the caller sent.
```json
{"isValid":true,"payer":"<A hex>","extra":{"chan":"…:0","cum":"600"}}
```
or `{"isValid":false,"invalidReason":"invalid_xbt_channel_signature"}`.

### POST /x402/settle
Request as for `/verify`, with `paymentPayload.payload` = `{"chan","sig","payload"?}` (the close
request). It closes the channel:
```json
{"success":true,"transaction":"<close txid>","network":"bip122:…","payer":"<A hex>","amount":"750",
 "extra":{"chan":"…:0","unpaidMsat":"0"}}
```
`amount` is the sat paid to the server by the close.

### GET /x402/supported
```json
{"kinds":[{"x402Version":2,"scheme":"xbt-channel","network":"bip122:0000000000000050c1e5f69672f45929"}],
 "extensions":[],"signers":{}}
```

## Error Codes

| Error code | v1.0 code | Meaning |
|---|---|---|
| `invalid_xbt_channel_scheme_or_network` | `unsupported_scheme_or_network` | Scheme, network or `payTo` differs |
| `invalid_xbt_channel_payload` | `bad_payload` | Undecodable or malformed payload |
| `invalid_xbt_channel_unknown_channel` | `unknown_channel` | No such open channel |
| `invalid_xbt_channel_auth` | `bad_auth` | `auth` invalid or `seq` not fresh |
| `invalid_xbt_channel_closing` | `channel_closing` | Closed, or inside the close margin |
| `invalid_xbt_channel_unconfirmed` | `unconfirmed` | Funding not confirmed to the required depth |
| `invalid_xbt_channel_stale_amount` | `stale_amount` | `cum` below the stored state |
| `invalid_xbt_channel_signature` | `bad_sig` | State signature invalid, not strict DER, or differs for the same `cum` |
| `invalid_xbt_channel_sighash` | `bad_sighash` | Signature hash type is not `0x21` |
| `invalid_xbt_channel_amount` | `bad_amount` | `cum` outside `[546, capacity − closeFeeSat]` |
| `invalid_xbt_channel_hashlock` | `bad_hashlock` | Conditional call with the wrong hash |
| `invalid_xbt_channel_insufficient_payment` | `insufficient_payment` | `cum` does not cover the billing rule |
| `invalid_xbt_channel_exhausted` | `channel_exhausted` | The channel cannot cover another request |
| `invalid_xbt_channel_coinbase_funding` | `coinbase_funding` | Funding is a coinbase output |
| `invalid_xbt_channel_funding` | `bad_funding` | Script or value mismatch, or `redeemScript` differs |
| `invalid_xbt_channel_unknown_funding` | `unknown_funding` | Funding transaction not found |
| `invalid_xbt_channel_capacity` | `bad_capacity` | Capacity outside the advertised range |
| `invalid_xbt_channel_expiry` | `bad_expiry` | Expiry outside the advertised range |
| `invalid_xbt_channel_payer_spk` | `bad_payer_spk` | `payerSpk` is not P2WPKH, P2WSH or P2TR |
| `invalid_network` | `wrong_network` | Open for another network |
| `invalid_xbt_channel_duplicate_channel` | `duplicate_channel` | Channel already open |
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
`payTo_secret = p − t`, hence every channel's key. `t` also does not commit to the network. Servers
MUST NOT export per-channel secrets (delegate closing by handing out signed close transactions), MUST
use a distinct `payTo` per network, and MUST sign in constant time (the server signs a receipt on every
paid request, which gives any client a signing oracle). The v1.1 draft proposes committing the network
in `t`.

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
`vectors.json` in this directory holds byte-exact vectors: the key derivation, `K` and three `auth`
values, four state transactions with their sighashes and signatures, a signed close and refund, three
invalid signatures, and a full exchange (402, open, five paid requests with exact header values, a
refused replay, cooperative close). `check_vectors.py` recomputes them all from the reference
implementation. The exchange vectors use the v1.0 `PAYMENT-RESPONSE` shape (see the conformance note).

## Reference Implementation
Python (`xbt402`, stdlib plus `coincurve`/libsecp256k1): server, client SDK, ASGI middleware, httpx
transport, watcher, SQLite channel store. Tested against Knots 29.4.2 with BIP-110 enforced: funding,
close and refund relay between nodes; a 1,000-request run settles exactly on-chain; the refund wins
after `expiry` and a late close is rejected. It has been through a security review whose Critical and
High findings are fixed and covered by tests.

## Appendix
### Relationship to `batch-settlement`
Upstream `batch-settlement` already describes "payment channel streaming" as a capital-backed
commitment model, with the same commit → accumulate → redeem lifecycle as this scheme. This proposal
could therefore be submitted as the XBT network binding of `batch-settlement`
(`scheme_batch_settlement_xbt.md`, `scheme: "batch-settlement"`) instead of a new scheme. The mechanics
above would not change; the scheme string, the error-code prefix (`invalid_batch_settlement_xbt_*`) and
the file name would. The seven items `batch-settlement` requires of a network binding map as follows:
commitment format (Payment payload), verification rules (Verification), storage and commitment id
(`chan` + `seq`, Settlement), double-spend prevention (cumulative states, `seq`, `auth`), commitment
expiry (`expiry − closeMarginBlocks`), redemption (close), trust model (capital-backed).

### Hash-locked conditional requests (experimental)
A server MAY offer a deliverable that is paid atomically with a secret: `extra.conditional =
{"hash","amount","csvDelta"}`, and the client signs a state paying `amount` to
`OP_IF OP_SHA256 <H> OP_EQUALVERIFY <P> OP_CHECKSIG OP_ELSE <csvDelta> OP_CSV OP_DROP <A> OP_CHECKSIG OP_ENDIF`
(P2WSH). The response body carries the ciphertext and the preimage. The reference server cannot yet
close with such a state, so today the increment is only postpay credit. A server MUST NOT offer
conditional requests until it closes with the conditional state whenever it pays more than the best
plain state (then claims with the preimage before `csvDelta`), or refuses a new conditional request
until the previous increment is folded into a plain state.

### Open questions
- `asset: "XBT:sat"` is not a CAIP-19 identifier. Is a slip44-style `bip122:…/slip44:0` preferred, or a
  bare `"XBT"` with `amount` in sat, as `exact` on `lnbtc` uses `"BTC"`?
- `network` uses the first post-fork (first BLAKE2b) block rather than genesis, as other Bitcoin forks do.
  Is that acceptable in the registry, and is a regtest identifier worth listing?
- New scheme or `batch-settlement` binding (above)?
- Should `billing` be expressed through `paymentFlow` instead of a scheme-private `extra` field?

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1-draft | 2026-09-25 | First draft against x402 v2 (`x402-foundation/x402` `main` `4fcf836`), from xbt402 v1.0/v1.1-draft |
