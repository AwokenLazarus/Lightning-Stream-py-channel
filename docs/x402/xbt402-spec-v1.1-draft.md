# xbt402: HTTP 402 payment channels on XBT (x402 scheme `xbt-channel`)

**Version 1.1-draft**, 2026-09-25. Status: draft, unpublished. Wire-compatible with v1.0 except where
[Changes from v1.0](#changes-from-v10) says otherwise.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are to be interpreted as described
in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

Companion documents in this directory:
- `scheme_xbt-channel.md`: the same protocol as an x402 scheme proposal, in the upstream format.
- `vectors.json` and `check_vectors.py`: test vectors, recomputed from the reference implementation.

## Contents
1. [Overview](#1-overview)
2. [The chain](#2-the-chain)
3. [Roles and trust](#3-roles-and-trust)
4. [Constants and parameters](#4-constants-and-parameters)
5. [Keys](#5-keys)
6. [Scripts and transactions](#6-scripts-and-transactions)
7. [Wire format](#7-wire-format)
8. [Channel state machine](#8-channel-state-machine)
9. [Security requirements](#9-security-requirements)
10. [Known weaknesses](#10-known-weaknesses)
11. [Proposed for v1.1: network in the payee tweak](#11-proposed-for-v11-network-in-the-payee-tweak)
12. [Test vectors](#12-test-vectors)
13. [Changes from v1.0](#changes-from-v10)
- [Appendix A: security findings referenced in this document](#appendix-a-security-findings-referenced-in-this-document)
- [Appendix B: error codes](#appendix-b-error-codes)

## 1. Overview
xbt402 lets a client (typically an AI agent) pay an HTTP API per request, in XBT, with no on-chain
transaction per request and no intermediary holding funds.

It is a unidirectional payment channel in the style Jeremy Spillman described for Bitcoin in 2013,
carried in the headers of the x402 v2 protocol:
1. The client locks funds once in an output that the provider and the client can spend together,
   and that returns to the client alone after a block height (`expiry`).
2. Each paid request carries the client's signature on a transaction that pays the provider a
   cumulative total (`cum`) out of that output. Each new signature pays a little more.
3. The provider checks one signature per request, keeps only the highest state, and broadcasts it
   once, before `expiry`.

Why a channel and not one on-chain payment per call:
- **Cost.** A call priced at 150 sat is far below the fee of any transaction. A channel costs one
  funding and one close, whatever the number of calls.
- **Latency.** Verifying a state costs one ECDSA verification and one HMAC. The reference provider
  answers a paid call in about 4 ms (p50) on commodity hardware. XBT blocks arrive every 7–10 minutes.
- **No facilitator and no custody.** The chain has no stablecoin, no Lightning network and no
  facilitator service. The client's timelocked refund protects the client, and the client's
  signatures protect the provider. Neither side trusts the other beyond one call.

What it costs:
- Capital is locked per client–provider pair until the channel closes.
- The first paid call waits for the funding to confirm (unless the provider accepts zero-conf).
- Money flows one way.
- The provider must be online, and must close before `expiry`.

## 2. The chain
XBT is a Bitcoin-derived chain with these properties that matter here:

| Property | Value |
|---|---|
| History | Shares Bitcoin's history up to block 961631. From 961632 its nodes enforce BIP-110 (below). From block **961640** its proof of work is BLAKE2b instead of SHA-256d. |
| Node software | Bitcoin Knots with the BLAKE2b hard fork. This spec was tested against Knots **29.4.2** (`v29.4.2.knots20260508`). |
| Script and transactions | Bitcoin's: segwit v0 (P2WPKH, P2WSH), taproot, CLTV, CSV. Amounts in satoshis (`sat`). |
| **BIP-110 (RDTS)** | A "reduced data" soft fork, enforced as consensus. The rules this protocol depends on: an output's scriptPubKey is at most 34 bytes (83 for OP_RETURN), pushes and witness items are at most 256 bytes, and `OP_IF`/`OP_NOTIF` are invalid in tapscript. Its data limits are temporary by design. |
| **`SIGHASH_UNIFIED`** | A signature-hash flag, `0x20`, that XBT consensus accepts and SHA-256 Bitcoin rejects. With it, a signature commits to a different message (`UnifiedSighash`, below). `ALL\|UNIFIED` is `0x21`. |
| Replay protection | Opt-in, per signature. Coins that existed before the split exist on both chains under the same keys. A spend signed with a legacy hash type (for example `0x01`) can be replayed on SHA-256 Bitcoin. A spend signed with `0x21` cannot. |
| Coinbase maturity | Knots 29.4.2 relay policy requires 6,480 confirmations for **any** coinbase spend, and consensus requires it for coinbases created from block 973,440 until block 979,920. Normal outputs are unaffected. |

**UnifiedSighash.** The message signed under `0x20` is `tagged_hash("UnifiedSighash", m)` (BIP340 tagged
hash, SHA-256), where `m` serializes, in order: a zero epoch byte, the hash type, the version, the
locktime, a zero spend-type byte; unless ANYONECANPAY, the SHA-256 of all prevouts, of all input
amounts, of all input scriptPubKeys and of all sequences; unless NONE or SINGLE, the SHA-256 of all
outputs; a script-type byte (`1` for segwit v0); then either this input's outpoint, amount,
scriptPubKey and sequence (ANYONECANPAY) or its index; the length-prefixed script code; and, for
SINGLE, the SHA-256 of the output at this input's index. Like BIP341 it commits to every input's amount
and scriptPubKey, for every script type. The reference implementation is `xbt402/tx.py`
`unified_sighash`, checked against the node's own reference vectors (`tests/data/unified_sighash.json`,
166 cases).

Consequences for this protocol:
- The channel script uses `OP_IF`, so it lives in **P2WSH**, not tapscript.
- A client's payout script must fit in 34 bytes, or no close can ever be mined (finding C3).
- Every channel signature uses `0x21`, so channel transactions cannot be replayed elsewhere and
  commit to the funding amount.
- A funding output must not be a coinbase output (the maturity would block both close and refund).

## 3. Roles and trust
- **Client (payer).** Holds a fresh key `A` per channel. Funds the channel, signs states, keeps its
  refund. Needs nothing online to stay safe: the refund becomes valid at `expiry`.
- **Provider (payee).** Publishes an identity key `payTo` and runs a node. Verifies states, serves
  calls, closes before `expiry`.
- **Facilitator.** Not needed. A provider MAY expose the x402 facilitator endpoints
  (`/x402/verify`, `/x402/settle`, `/x402/supported`) for stacks that expect them; they are served by
  the provider itself.

Trust bound: under **postpay** billing the provider risks one call (the client may stop paying after
being served). Under **prepay** the client risks one call. Neither can take more.

## 4. Constants and parameters

| Name | Value | Where | Notes |
|---|---|---|---|
| `scheme` | `xbt-channel` | wire | |
| `network`, mainnet | `bip122:0000000000000050c1e5f69672f45929` | wire | CAIP-2 `bip122:` + the first 32 hex characters of the hash of block 961640, the first BLAKE2b block (`0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb`). XBT shares Bitcoin's genesis, so, as other Bitcoin forks do, it is identified by a post-fork block. Block 961640 rather than 961632 (the first BIP-110 block) because a SHA-256 chain enforcing BIP-110 without the proof-of-work change would share 961632–961639. |
| `network`, regtest | `bip122:` + first 32 hex of block 101 | wire | Same rule, on the block where regtest switches to BLAKE2b. |
| `asset` | `XBT:sat` | wire | Not a CAIP-19 identifier; see [open questions](scheme_xbt-channel.md#open-questions). |
| `DUST` | 546 sat | protocol | Smallest output either side creates, and smallest signed `cum`. |
| `closeFeeSat` | 600 sat (reference) | `extra` | Fixed at open, paid out of the client's side. A close is 170–171 vB, so about 3.5 sat/vB. Clients SHOULD refuse offers above a cap (reference: 2,000). |
| `minCapacity`, `maxCapacity` | 20,000 / 10,000,000 sat (reference) | `extra` | Provider policy. |
| `minExpiryBlocks`, `maxExpiryBlocks` | 1,008 / 8,640 (reference) | `extra` | Blocks from the tip at open (about 7 and 60 days). |
| `closeMarginBlocks` | 144 (reference) | `extra` | The provider stops serving and MUST close at `expiry − closeMarginBlocks`. |
| `minConf` | 1 (reference) | `extra` | Confirmations before a channel is credited. |
| Large-channel confirmations | 3 above 1,000,000 sat (reference) | provider policy | Reorg defence (H2). Not advertised in v1.0; see §13. |
| Zero-conf tier | 0 = off (reference) | provider policy | Capacity up to which an unconfirmed funding is accepted, at the provider's risk. |
| `expiry` | absolute block height, `0 < expiry < 500,000,000` | open | |
| `maxTimeoutSeconds` | 30 | wire | |
| Request body bound | 1 MiB | HTTP | |
| Conditional `csvDelta` | 10 blocks | `extra.conditional` | Optional hash-locked calls, §6.5. |

Reference client defaults (informative): capacity 200,000 sat; per-call cap 1,000 sat; total budget
1,000,000 sat; channel lifetime `min(max(1008, minExpiryBlocks + 6), maxExpiryBlocks − 1)` blocks.

## 5. Keys
All public keys are 33-byte compressed SEC1 secp256k1 keys. `G` is the generator, `n` the group order.
`tagged_hash(tag, m) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ m)` (BIP340). `‖` is concatenation.

### 5.1 Per-channel payee key
```
t = int(tagged_hash("xbt-channel/payee", payTo ‖ A ‖ LE32(expiry))) mod n
P = payTo + t·G                   (provider's secret: p = payTo_secret + t mod n)
```
The client computes `P` from the 402 challenge and its own `A` and `expiry`, so opening needs one
round trip and no two channels share a payee key.

The derivation is **non-hardened** and does **not** commit to the network. See §10.1 for what that
means and the rules that follow from it.

### 5.2 Request-authentication key
```
K = tagged_hash("xbt402/auth-key", x(a·P))  =  tagged_hash("xbt402/auth-key", x(p·A))
```
`x(·)` is the 32-byte x coordinate. Only the client and the provider can compute `K`. A client that
keeps `a` in a separate signer SHOULD compute `K` and every `auth` value inside that signer.

### 5.3 Signing
Every signature is ECDSA over secp256k1, DER-encoded, low S, with nonces per RFC 6979 or equivalent.
Signing with `payTo_secret`, `p` or `a` MUST be constant-time (for example libsecp256k1). The provider
signs a receipt on every paid call, which gives any client a signing oracle (finding H4).

## 6. Scripts and transactions

### 6.1 Funding output
P2WSH (a 34-byte output) of this 79-byte witness script:
```
OP_IF    <P> OP_CHECKSIGVERIFY
OP_ELSE  <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
OP_ENDIF <A> OP_CHECKSIG
```
`<expiry>` is a minimal script number.
- Pay path witness: `[sigA, sigP, 0x01, script]`.
- Refund path witness: `[sigA, <empty>, script]`, with `nLockTime = expiry` and the input's sequence
  `0xfffffffe`.

Rules:
- The funding transaction MUST be signed with `0x21` whenever it spends coins that exist on both chains
  (outputs created before the split). Signed with `0x01` it can be replayed on SHA-256 Bitcoin, locking
  the client's coins there in a script with the provider. Clients SHOULD sign every funding `0x21`.
- A funding output MUST NOT be a coinbase output (`coinbase_funding`).

### 6.2 Payout scripts
- Provider output: `P2WPKH(P)`.
- Client output: `P2WPKH(A)` by default, or the open's `payerSpk`. `payerSpk` MUST be P2WPKH (22 bytes),
  P2WSH (34) or P2TR (34); the provider MUST refuse anything else (`bad_payer_spk`). Under BIP-110 a
  longer output is consensus-invalid, so every close would fail (C3).

### 6.3 State transaction (`0x21`)
The state for cumulative amount `cum` is deterministic. Both sides build it byte for byte from the
channel terms; neither ever parses it from the other.
- version 2, locktime 0;
- one input: the funding outpoint, sequence `0xfffffffd` (signals replaceability);
- output 0: `cum` to the provider script;
- output 1: `capacity − closeFeeSat − cum` to the client script, **omitted** (added to the fee) when
  below 546;
- `546 ≤ cum ≤ capacity − closeFeeSat` (`maxCum`).

The client signs it with `0x21`. The signature MUST be BIP66 strict DER with low S, and a verifier
MUST reject any other encoding **before** verifying the signature (C1): segwit v0 consensus rejects
non-strict DER, so a loosely encoded state can never be closed.

### 6.4 Fee-input state (`0xA3`, optional)
For fee spikes a client MAY also sign `SINGLE|ANYONECANPAY|UNIFIED` (`0xA3`) states, so the provider
can attach fee inputs:
- output 0: `capacity − closeFeeSat − cum` to the **client** script (the output SINGLE commits to);
- output 1: `cum` to the provider script;
- a state without client change ≥ 546 has no `0xA3` variant.

The provider adds inputs and outputs freely. Output 0 MUST be the client's change: if the provider's
output came first, the client's whole remainder would be uncommitted and the provider could take it
(H5). A signer MUST apply its never-sign-lower rule to `0xA3` states too.

The reference x402 flow never requests `0xA3` states. It relies on a fixed `closeFeeSat` plus CPFP
from the provider output (§10.2).

### 6.5 Hash-locked conditional state (optional, experimental)
For deliverables that should be paid atomically with a secret: a state that pays `uncond` to the
provider, `condAmount ≥ 546` to the P2WSH script
```
OP_IF   OP_SHA256 <H> OP_EQUALVERIFY <P> OP_CHECKSIG
OP_ELSE <csvDelta> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG
OP_ENDIF
```
and the rest, minus `closeFeeSat`, to the client. Signed `0x21`. Once the client has the preimage `k`
(`SHA256(k) = H`), it SHOULD fold the increment into an ordinary state paying `uncond + condAmount`.

**Status: not enforceable in v1.0** (finding M6): the reference provider stores the conditional
signature but has no close path that uses it. Until a provider implements one, a conditional increment
is only postpay credit. A provider MUST NOT offer conditional calls unless it either (a) closes with the
conditional state whenever it pays more than the best plain state and then claims with `k` before
`csvDelta` expires, or (b) refuses a new conditional call until the previous increment has been folded
into a plain `0x21` state.

### 6.6 Refund
The client signs its refund at open (§6.1 refund path; one output to a script of its choice) and keeps
it. From `expiry` on, the refund and any late provider close race; whichever confirms first wins.

## 7. Wire format
x402 v2 transport. JSON is compact (no insignificant whitespace). Header values are base64 (RFC 4648,
with padding) of the UTF-8 JSON. Satoshi amounts are decimal strings; millisatoshi (`msat`) fields are
decimal strings; heights, block counts, `seq` and `vout` are JSON numbers. Hex is case-insensitive on
input; implementations emit lowercase.

### 7.1 Payment required (402)
`HTTP 402`, header `PAYMENT-REQUIRED: base64(PaymentRequired)`, body = the same JSON:
```json
{"x402Version":2,"error":"payment_required",
 "resource":{"url":"https://api.example.com/v1/infer?model=small"},
 "accepts":[{"scheme":"xbt-channel","network":"bip122:0000000000000050c1e5f69672f45929",
   "amount":"150","asset":"XBT:sat",
   "payTo":"02caf6f4712d871ae8f807ca4ea6696b088dc1c8bcf6796a6d52f902e2fbb1b770",
   "maxTimeoutSeconds":30,
   "extra":{"minCapacity":"20000","maxCapacity":"10000000","minExpiryBlocks":1008,
            "maxExpiryBlocks":8640,"closeMarginBlocks":144,"minConf":1,"closeFeeSat":"600",
            "openUrl":"/x402/xbt-channel/open","closeUrl":"/x402/xbt-channel/close",
            "billing":"postpay"}}]}
```
- `amount` is the per-call **maximum**. A metered call may charge less (x402 `upto`).
- `payTo` is the provider's 33-byte identity key (hex), not an address.
- `billing` is `postpay` (a call is paid by the next state) or `prepay` (a call is paid before it is served).
- `extra.conditional = {"hash","amount","csvDelta"}` appears only on a path offering a hash-locked
  deliverable (§6.5).
- On a refusal, `error` carries the code (Appendix B). The body adds
  `"channel":{"chan","cum","seq","spentMsat"}` **only when the request was authenticated for that
  channel** (H3). An unauthenticated caller learns nothing about any channel.

### 7.2 Open
`POST extra.openUrl` with
```json
{"x402Version":2,"network":"bip122:…",
 "channel":{"txid":"<hex>","vout":0,"capacity":200000,"expiry":2014,
            "payerPub":"<A hex>","payerSpk":"<hex, optional>","redeemScript":"<hex>"}}
```
The provider MUST check, in this order, refusing with the code shown:
1. `network` is its own, else `wrong_network`;
2. `payerPub` is a valid compressed key; `payerSpk`, if present, is P2WPKH, P2WSH or P2TR, else `bad_payer_spk`;
3. `redeemScript` equals the script it builds from `(payTo, A, expiry)`, else `bad_funding`;
4. canonicalize the channel id (below); if already known, `duplicate_channel`;
5. on its own node: funding transaction unknown → `unknown_funding`; a coinbase → `coinbase_funding`;
   output script or value differs → `bad_funding`; capacity outside `[minCapacity, maxCapacity]` →
   `bad_capacity`; blocks to expiry outside `[minExpiryBlocks, maxExpiryBlocks]` → `bad_expiry`;
   fewer confirmations than required and capacity above the zero-conf tier → `unconfirmed`.

Success: `200 {"chan":"<txid>:<vout>","expiry":2014,"maxCum":"199400","confirmations":1}`.
Failure: `400 {"error":"<code>","detail":"<text>"}`.

**Channel id.** `chan = <txid, 64 lowercase hex> ":" <vout, decimal, no leading zeros>`. Nodes parse
txids case-insensitively, so a provider MUST canonicalize every channel id it receives (open, pay,
close, verify) and key its records by the canonical form (C2).

### 7.3 Pay
Header `PAYMENT-SIGNATURE: base64(PaymentPayload)`:
```json
{"x402Version":2,"accepted":<the PaymentRequirements object from the 402>,
 "payload":{"chan":"<txid>:<vout>","seq":5,"cum":"600",
            "sig":"<DER ‖ 0x21, hex; optional>","auth":"<hex>",
            "hashlock":"<hex; conditional calls only>"}}
```
- `cum`: the cumulative total the client has signed. `sig` is REQUIRED when `cum` is above the
  provider's stored value and OPTIONAL when it repeats it.
- `seq`: an integer **strictly greater than every `seq` the provider has accepted on this channel**.
  A stale `seq` is refused whatever else the request carries, and an accepted `seq` is consumed even if
  the call is then refused.
- `auth` (REQUIRED):
  ```
  req  = hex(SHA256(method ‖ "|" ‖ target ‖ "|" ‖ body))
  auth = hex(HMAC-SHA256(K, "xbt402/auth|" ‖ chan ‖ "|" ‖ seq ‖ "|" ‖ cum ‖ "|" ‖ (sig or "") ‖ "|" ‖ req))
  ```
  `method` is the HTTP method, `target` the request target exactly as sent (path and query, not
  percent-decoded), `body` the raw body bytes. `seq` is its decimal form, `cum` and `sig` exactly as
  in the payload. `auth` binds one payload to one request, one `seq` and one state; without it
  `{chan, cum}` would be a bearer token (H3).
- A request MUST carry at most one `PAYMENT-SIGNATURE` header.

**Provider checks, in order** (constant work: one HMAC, at most one ECDSA verification, no node RPC):
1. decode; `x402Version` is 2; `accepted.scheme`, `accepted.network` and `accepted.payTo` match →
   else `unsupported_scheme_or_network` (or `bad_payload` if undecodable);
2. canonical `chan` is known → else `unknown_channel`;
3. `auth` is valid (constant-time comparison) and `seq` is fresh → else `bad_auth`, with no channel
   details; then record `seq`;
4. the channel is closed, or the tip is at or above `expiry − closeMarginBlocks` → `channel_closing`;
5. the channel is suspended (funding not confirmed to depth, §8) → `unconfirmed`;
6. `cum` below the stored value → `stale_amount`; above it: the signature is strict DER, `0x21`, and
   valid over the state for `cum` → else `bad_sighash` / `bad_sig` / `bad_amount`; equal to it with a
   different signature → `bad_sig`;
7. billing: postpay serves if `cum·1000 ≥ spentMsat`; prepay serves if `cum·1000 ≥ spentMsat + amount·1000`
   → else `insufficient_payment`;
8. `spentMsat + amount·1000 > maxCum·1000` → `channel_exhausted`;
9. reserve `amount`, durably record this channel (fsync), serve. A higher state accepted on a call
   that is then refused MUST also be recorded.

Conditional calls replace steps 6–7: `hashlock` equals the offered `H` → else `bad_hashlock`; `sig` is a
valid `0x21` signature over the conditional state with `uncond` = stored `cum` → else `bad_sig`; the
charge is `condAmount`. The response body is `{"cipher","preimage","hash"}` (hex).

### 7.4 Payment response
On every served call, header `PAYMENT-RESPONSE: base64(receipt)`:
```json
{"success":true,"scheme":"xbt-channel","network":"bip122:…","chan":"<txid>:<vout>","seq":5,
 "cum":"600","charged":"150","spentMsat":"750000","owedMsat":"150000","creditMsat":"0",
 "expiry":2014,"req":"<hex>","sig":"<DER hex>"}
```
`sig` is `P`'s ECDSA signature over
`tagged_hash("xbt402/receipt", chan ‖ "|" ‖ seq ‖ "|" ‖ cum ‖ "|" ‖ charged ‖ "|" ‖ spentMsat ‖ "|" ‖ req)`.
A handler response with status ≥ 500 is not billed (`charged` = "0"). A handler header containing CR,
LF or NUL MUST be replaced by an unbilled 500 (M4).

**Client checks:** the receipt verifies under `P`; `req` is its own request's digest; `cum` is not more
than it signed; `charged ≤ amount` (or the conditional amount); `spentMsat` grew by at most one call.
When a 402 arrives on an open channel, the client MUST NOT accept a higher `amount` than it opened the
channel at, and MUST NOT adopt more than **one call's worth of unreceipted charges over the channel's
life** (M3).

### 7.5 Close
`POST extra.closeUrl` with `{"chan","sig","payload"?}`. `sig` is `A`'s signature over
`tagged_hash("xbt402/close", chan)`. `payload` is an optional final state (as in §7.3) paying what is
owed. The provider completes the best state with its own signature and broadcasts it. Reply:
`{"chan","txid","cum","unpaidMsat"}`. Replaying a close request only closes the same channel with the
best state, which the provider may do at any time anyway.

### 7.6 Facilitator endpoints (optional)
A provider MAY serve the x402 facilitator interface itself. The paths MUST be under `/x402/` so that
they never shadow an API route of the same name (L6):
- `GET /x402/supported` → `{"kinds":[{"x402Version":2,"scheme":"xbt-channel","network":"bip122:…"}]}`.
- `POST /x402/verify` checks a signed state and records it if higher. It is unauthenticated, so it MUST
  require `sig` for exactly the `cum` given, MUST report nothing the caller did not send, and MUST NOT
  move `seq` (otherwise a stranger learns `cum`, or locks the client out with a huge `seq`).
- `POST /x402/settle` closes the channel, with the same body and rules as §7.5.

Request bodies follow x402 v2: `{"x402Version":2,"paymentPayload":{…},"paymentRequirements":{…}}`.
`/x402/verify` answers `{"isValid":true,"payer":"<A hex>","extra":{"chan","cum"}}` or
`{"isValid":false,"invalidReason":"<code>"}`; `/x402/settle` answers a `SettlementResponse` with the close
txid as `transaction` and the sat paid to the provider as `amount`. Full shapes: `scheme_xbt-channel.md`,
Facilitator Interface. (The v1.0 reference accepts `{payload}` and answers `{"valid","chan","cum"}`; see §13.)

### 7.7 Upstream envelope for `PAYMENT-RESPONSE` (proposed)
x402 v2 defines `PAYMENT-RESPONSE` as a `SettlementResponse` (`success`, `transaction`, `network`,
`payer`, `amount`, `extra`). v1.0 sends the receipt object of §7.4 directly. v1.1 proposes wrapping it,
unchanged and with the same signature:
```json
{"success":true,"transaction":"","network":"bip122:…","payer":"<A hex>","amount":"",
 "extra":{"chargedAmount":"150","receipt":{<the §7.4 receipt>}}}
```
`transaction` is empty because a paid call broadcasts nothing. A client SHOULD accept both shapes during
the transition: if the decoded object has `extra.receipt`, verify that; otherwise treat the object itself
as the receipt.

## 8. Channel state machine

Provider view:

| State | Entered when | Serves | Next |
|---|---|---|---|
| `open` | the open checks pass | yes | `suspended`, `closing`, `closed` |
| `suspended` | a watcher tick finds the funding not confirmed to the required depth (reorg) | no (`unconfirmed`) | `open` when it confirms again |
| `closing` | tip ≥ `expiry − closeMarginBlocks`, or a cooperative close request | no (`channel_closing`) | `closed` |
| `closed` | the node accepted the close (its txid recorded) | no | rebroadcast while the funding is unspent |
| `lost` | tip ≥ `expiry` and the client's refund confirmed first | no | none |

Watcher rules (run at least every block):
- Handle each channel independently. One failing close (a node error, a bad state) MUST NOT stop the
  others (H1). Record the error and retry on the next tick.
- Re-check every open channel's funding and suspend a channel whose funding is not confirmed to depth (H2).
- Rebroadcast a recorded close whose funding is unspent again (mempool eviction).
- SHOULD bump a close by CPFP from the provider output when the feerate is above what `closeFeeSat` pays.
- MUST run supervised, so that it cannot silently die: after `expiry` a missing close means the refund wins.

Client view: `unfunded → funded (refund signed and stored) → open → closed | refunded`. A client that
stored its refund needs nothing online; it (or anyone it gives the refund to) broadcasts it at `expiry`.

## 9. Security requirements
An implementation of this spec MUST meet all of these. Each names the finding in Appendix A it answers.
1. Strict DER, low S and `0x21` on every state signature, checked before verification (C1).
2. Canonical channel ids everywhere (C2).
3. `payerSpk` ∈ {P2WPKH, P2WSH, P2TR} (C3).
4. Per-channel watcher isolation, supervision and rebroadcast (H1).
5. Funding re-checked every block; more confirmations for large channels (H2).
6. Per-request `auth` with a fresh `seq`; nothing about a channel to strangers; `/x402/verify` needs a
   signature and never moves `seq` (H3).
7. Constant-time secret-key operations (H4).
8. `0xA3` states commit to the client's change (H5).
9. Never export per-channel secrets; one `payTo` per network (M2, §10.1).
10. Client: price pinned at open; at most one unreceipted call per channel life (M3).
11. HTTP: one bounded `Content-Length`, no `Transfer-Encoding`, one `PAYMENT-SIGNATURE`, no CR/LF/NUL in
    response headers (M4).
12. Recording a paid call costs O(1), independent of the number of channels (M5).
13. Facilitator endpoints only under `/x402/` (L6).
14. No conditional calls without an enforceable close path (M6, §6.5).

## 10. Known weaknesses
This section is deliberately blunt. None of these is a way to steal funds from a correct
implementation that follows the rules above, but each is a place where the protocol leans on operating
discipline or on assumptions about the chain.

### 10.1 M2: the payee key derivation is non-hardened and network-agnostic
`t` is computable by anyone who knows `payTo`, `A` and `expiry`, which the client (and anyone who
watches the funding script appear on-chain) does. So any one per-channel secret `p` reveals
`payTo_secret = p − t`, and with it the secret of **every** channel the provider has ever had or will
have. This is the same property as BIP32 non-hardened derivation, and it is the price of opening in one
round trip without a provider-chosen key.

`t` also omits the network, so the same `payTo` on mainnet, testnet and regtest derives the same channel
keys. A key leaked from a test deployment compromises production.

Operating rules, which are normative (§9 item 9):
- A provider MUST NOT export a per-channel secret: not to a closing service, a watchtower, a log, a
  crash dump, or another process. To delegate closing, hand out **fully signed close transactions**,
  never `p`.
- A provider MUST use a distinct `payTo` per network.
- Signing MUST be constant-time (H4): a timing leak of one `p` is a leak of `payTo_secret`.

§11 proposes committing to the network in `t`. Making the derivation hardened would need a
provider-chosen per-channel key, and so a second round trip before funding; this draft does not propose
that.

### 10.2 Fees and expiry
- **Fixed close fee.** `closeFeeSat` is fixed at open (600 sat ≈ 3.5 sat/vB for the 171-vB close). If
  feerates rise above that for longer than `closeMarginBlocks`, the close may not confirm before
  `expiry`, and the client's refund (which pays the same or less fee) can win the race. Mitigations are
  CPFP from the provider output (needs the provider output to be large enough and the node's package
  relay to accept the child) and the optional `0xA3` state. Neither is guaranteed. Providers SHOULD
  size `closeMarginBlocks` for the worst fee event they want to survive and SHOULD close early when
  the mempool is rising.
- **Block time variance.** Heights are the unit of `expiry`, but XBT block intervals have ranged from
  about 1 minute (just after the proof-of-work change) to about 10, as difficulty chased a hashrate that
  moved several-fold in weeks. The 144-block margin is "about a day" only at 10-minute blocks. A
  provider SHOULD treat the margin as a block count and alert on it, not as a duration.
- **Reorg depth.** XBT's hashrate is small next to SHA-256 Bitcoin's, so deep reorgs are cheaper. An
  attacker can open many large channels in a block it plans to orphan and double-spend. The reference
  waits for 3 confirmations above 1,000,000 sat and suspends channels whose funding disappears (H2).
  Providers with a larger exposure SHOULD require more.
- **Coinbase maturity and BIP-110 are moving targets.** Both are recent, one has a scheduled end, and
  further maturity changes are planned by Knots developers. This protocol refuses coinbase fundings and
  keeps every output ≤ 34 bytes, which stays valid under either rule set, but a change to relay policy for
  P2WSH or `0x21` would need a new version.
- **The first call waits for a confirmation** (7–10 minutes) unless the provider takes zero-conf risk.

### 10.3 Hot keys
- **Provider.** `payTo_secret` (or every `p`) must be online: the provider signs a receipt per call,
  derives `K` per channel and signs every close. A compromise of the provider host gives the attacker
  every channel key (§10.1): it can close channels with the best states to outputs it controls and
  spend the provider's unswept close outputs, and it can sign receipts in the provider's name. Earned
  but unswept funds are at risk; the clients' funds are not. Providers SHOULD sweep close outputs to
  cold storage promptly, SHOULD keep the signing key in a separate process or HSM that exposes only
  "sign this receipt / this close", and SHOULD rotate `payTo` (a new identity) after any suspected
  compromise.
- **Client.** Each channel key `a` must be online to sign states and `auth`. A compromise lets the
  attacker sign states paying the provider up to `maxCum` (loss bounded by the channel's unspent
  capacity) and, after `expiry`, spend the refund path. Clients SHOULD keep `a` in a policy signer that
  enforces per-call, per-channel and per-day limits and an allowlist of `payTo` keys, and SHOULD keep
  channel capacities small.
- **The pure-Python fallback** in the reference implementation is not constant-time and MUST NOT hold
  keys with real value.

### 10.4 Other limits
- Privacy: the funding and the close link client and provider on-chain; the P2WSH script reveals both
  keys at close. Per-channel keys avoid key reuse across channels.
- One call of trust in each direction (§3). Receipts document every charge, but disputes are off-chain.
- The facilitator `/x402/verify` endpoint is unauthenticated by design; it can be used to probe whether
  a given signed state is valid, which only the holder of that state can do.

## 11. Proposed for v1.1: network in the payee tweak
**Proposal (not implemented in the reference):**
```
t' = int(tagged_hash("xbt-channel/payee/v2", NET ‖ payTo ‖ A ‖ LE32(expiry))) mod n
NET = UTF-8 of the CAIP-2 network string, e.g. "bip122:0000000000000050c1e5f69672f45929",
      length-prefixed with one byte
```
The tag changes as well as the preimage, so no `t'` can equal a v1.0 `t` by construction.

What it fixes: the cross-network half of M2. A `payTo` accidentally reused on regtest, testnet and
mainnet no longer derives the same channel keys, so a leaked test key stops being a production key. It
does **not** fix the non-hardened half (one leaked `p` still gives `payTo_secret`).

Compatibility cost:
- It changes `P`, hence the funding script and address. A v1.0 client and a v1.1 provider (or the
  reverse) would disagree on `redeemScript`, and the open fails with `bad_funding`. The failure is safe
  (the client's refund still works) but it strands the funding until `expiry` unless the client notices
  before funding.
- So it needs negotiation. Proposed: the 402 advertises `extra.derivation: "v2"`; a provider that
  supports both accepts an open whose `redeemScript` matches either derivation and records which one;
  clients use `v2` when offered. Existing channels keep their derivation until they close.
- Test vectors for `t'` would be added to `vectors.json` once the reference implements it.

Recommendation: adopt it in the first published version, before any third-party implementation exists;
after that it costs a negotiation field forever. The operating rule (one `payTo` per network) stays
either way.

Other candidates for a later version: advertise the large-channel confirmation rule in `extra`
(`largeCapacity`, `minConfLarge`); a taproot variant `xbt-channel-tr` (MuSig2 key path, script leaves
without `OP_IF`, smaller and more private closes); hash-locked outputs inside states so a hub can route
payments without custody.

## 12. Test vectors
`vectors.json` holds, for fixed test keys:
- the payee derivation (`t`, `P`, redeem script, funding scriptPubKey and address) for three channels;
- the request-authentication key (ECDH x, `K` from both sides) and three `auth` values;
- four state transactions with their UnifiedSighash and the client's signature, a fully signed close,
  a signed refund, and three invalid signatures with the error each must produce;
- an eight-step exchange: the 402, the open, five paid calls (with the exact `PAYMENT-SIGNATURE` and
  `PAYMENT-RESPONSE` header values), a replayed header refused with `bad_auth`, and a cooperative close
  with its transaction.

`check_vectors.py` recomputes every value with the reference implementation and exits non-zero on any
difference. It also verifies every signature under the key that should have made it. The vectors are
identical under the libsecp256k1 backend and the pure-Python backend.

## Changes from v1.0
- **Facilitator paths moved under `/x402/`** (`/x402/verify`, `/x402/settle`, `/x402/supported`), and
  `kinds` entries carry `x402Version`. v1.0 also answered the bare `/verify`, `/settle`, `/supported`,
  which shadowed any API route of those names (L6). Breaking for facilitator clients only.
- **Upstream x402 v2 shapes (proposed, not yet in the reference):** `PAYMENT-RESPONSE` wrapped in a
  `SettlementResponse` (§7.7); facilitator requests as `{x402Version, paymentPayload,
  paymentRequirements}` and responses as `VerifyResponse` / `SettlementResponse` (§7.6); upstream-style
  error codes `invalid_xbt_channel_*` mapped one-to-one from the v1.0 codes (`scheme_xbt-channel.md`,
  Error Codes). The vectors in `vectors.json` use the v1.0 shapes the reference emits today.
- **Hash-locked conditional calls marked experimental** and gated on an enforceable close path (M6).
  v1.0 described them as available.
- **Known weaknesses stated in one place** (§10): M2 and its operating rules, fee and expiry
  assumptions, hot-key custody.
- **Proposed network commitment in the payee tweak** (§11), with its compatibility cost. Not in effect.
- **Test vectors** added (§12).
- **Standalone text.** The chain, `SIGHASH_UNIFIED`, BIP-110 and the maturity rule are described here;
  references to internal documents and deployments are removed. Wire bytes are unchanged apart from the
  facilitator paths and the `kinds` entry.

## Appendix A: security findings referenced in this document
Identifiers come from the security review of the reference implementation that preceded v1.0.
All Critical and High findings are fixed in the reference and have tests.

| ID | Finding | Rule |
|---|---|---|
| C1 | A non-strict-DER state signature verified in software but is consensus-invalid, so the close fails | §6.3 |
| C2 | One funding opened under several channel ids (txid letter case) was credited several times | §7.2 |
| C3 | An unchecked client payout script made every close invalid under BIP-110 | §6.2 |
| H1 | One failing close stopped the watcher for every other channel | §8 |
| H2 | A reorged-out, double-spent funding kept being served | §8 |
| H3 | The payment payload was a bearer token (replay, strangers spending credit, `/verify` leaking `cum`) | §7.3 |
| H4 | A variable-time signing fallback on a path any client can trigger | §5.3 |
| H5 | The `0xA3` state left the client's remainder uncommitted | §6.4 |
| M2 | Non-hardened, network-agnostic payee derivation (open by design) | §10.1, §11 |
| M3 | A malicious provider could drain a client with 402 loops and price rises | §7.4 |
| M4 | Header injection, request smuggling and unbounded bodies in the HTTP layer | §7.4, §9 |
| M5 | Each paid call rewrote every channel's record | §9 |
| M6 | The hash-locked conditional state had no provider close path (open) | §6.5 |
| L6 | Facilitator paths shadowed API routes of the same name | §7.6 |

## Appendix B: error codes
`payment_required`, `unsupported_scheme_or_network`, `bad_payload`, `unknown_channel`, `bad_auth`,
`channel_closing`, `unconfirmed`, `stale_amount`, `bad_sig`, `bad_sighash`, `bad_amount`,
`bad_hashlock`, `insufficient_payment`, `channel_exhausted`, `coinbase_funding`, `bad_funding`,
`unknown_funding`, `bad_capacity`, `bad_expiry`, `bad_payer_spk`, `wrong_network`,
`duplicate_channel`, `close_failed` (close and watcher only).
