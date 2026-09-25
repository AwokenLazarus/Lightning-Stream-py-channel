# xbt402: HTTP 402 payment channels on XBT (x402 scheme `xbt-channel`)

**Version 1.1-draft**, 2026-09-25. Status: draft, unpublished. **Not wire-compatible with v1.0**: the
payee key commits to the network (§5.1, §11) and the payment response and facilitator bodies use the
x402 v2 shapes (§7.4, §7.6). [Changes from v1.0](#changes-from-v10) lists every difference. The
reference implementation (`xbt402`) implements this text, and `vectors.json` is generated from it.

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
11. [v1.1: network in the payee tweak](#11-v11-network-in-the-payee-tweak)
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
| `derivation` | `v2` | `extra` | The payee-key derivation of §5.1. v1.0 had no such field (its derivation omitted the network). A client MUST refuse any other value **before funding**. |
| `DUST` | 546 sat | protocol | Smallest output either side creates, and smallest signed `cum`. Above the node's own floors (Knots 29.4.2, default `dustrelayfee`): 294 sat for P2WPKH, 330 for P2WSH and P2TR. |
| `closeFeeSat` | 600 sat (reference) | `extra` | Fixed at open, paid out of the client's side. A close is 170–171 vB with P2WPKH client change, so about 3.5 sat/vB (183 vB, 3.3 sat/vB, with P2WSH or P2TR change; 139–140 vB without change; a conditional close, §6.5, is 214 vB, 2.8 sat/vB). Clients SHOULD refuse offers above a cap (reference: 2,000). |
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
NET = UTF-8 bytes of the CAIP-2 `network` string exactly as in the 402, 1..255 bytes
t   = int(tagged_hash("xbt-channel/payee/v2", len8(NET) ‖ NET ‖ payTo ‖ A ‖ LE32(expiry))) mod n
P   = payTo + t·G                 (provider's secret: p = payTo_secret + t mod n)
```
`len8` is one byte holding the length of `NET`. The client computes `P` from the 402 challenge and its
own `A` and `expiry`, so opening needs one round trip and no two channels share a payee key. The same
`payTo`, `A` and `expiry` give unrelated keys on different networks (§11).

The derivation is **non-hardened**. See §10.1 for what that means and the rules that follow from it.

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
P2WSH (a 34-byte output) of this witness script, 79 bytes for any `expiry` from 32,768 to 8,388,607
(every mainnet height; 78 bytes below 32,768, as on a fresh regtest chain):
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

**Ciphertext first** (M7). The 402 carries the encrypted deliverable, `extra.conditional.cipher`,
and a client MUST refuse a conditional offer without one, before it signs. The provider's claim (below)
publishes `k` in its witness, so whatever happens to the paid response, a client that holds the
ciphertext gets the deliverable: from `k` in the response, or from the claim transaction. A client MUST
decrypt the ciphertext it was offered, not one a later response substitutes. Because the ciphertext is
public and every sale reveals `k`, a provider MUST offer each sale under a fresh `k` (the reference
re-keys a path after every conditional call).

**Client caps** (H6). `condAmount` is the price of a call: a client MUST hold it to its per-call cap and
its budgets before signing. Since the provider can close with a conditional state and claim it, an
unchecked `condAmount` lets one conditional call take the whole channel.

**Enforceable since v1.1** (finding M6; in v1.0 the provider stored the conditional signature but had
no close path that used it). A provider that offers conditional calls MUST do both:
1. **Close with the conditional state when it pays more.** When the provider closes (cooperatively, or
   at `expiry − closeMarginBlocks`) and `uncond + condAmount − claimFee` exceeds the best plain `cum`
   (the client took the deliverable and never signed the fold), it completes the conditional state
   with its own signature, broadcasts it, and then spends the hash-lock output with `k` to its own
   key. The claim MUST confirm within `csvDelta` blocks of the close, when the client's branch opens
   (checked on Knots 29.4.2: the client's branch is non-final at `csvDelta − 1` confirmations of the close
   and final at `csvDelta`, and from then on the two race; a claim paying more replaces the client's spend
   in the mempool). The watcher rebroadcasts the claim every tick until it confirms, and raises its fee
   while it waits (the reference doubles it for each block of the close's depth, keeping the output
   above dust: L8). The claim fee comes out of `condAmount`; the claim is 138 vB, so the reference's
   starting 300 sat is about 2.2 sat/vB.
   The provider MUST record the close before broadcasting it (M8): a close the node accepted but the
   provider never recorded (a lost RPC answer, a crash) is never claimed, and once it confirms no re-send
   is accepted. The reference saves the close transaction and its txid first, treats a failed broadcast
   of a transaction the node already has as sent, and adopts a recorded close it finds on-chain.
2. **Hold at most one outstanding conditional increment.** While the stored conditional state pays more
   than the best plain state, a new conditional call is refused with `conditional_outstanding`.

The client folds the increment as soon as it has checked `k`: it signs an ordinary `0x21` state for
`uncond + condAmount` and hands it over, through `POST /x402/verify` (§7.6) or on its next paid call.
The provider then closes with the plain state as usual.

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
            "billing":"postpay","derivation":"v2"}}]}
```
- `amount` is the per-call **maximum**. A metered call may charge less (x402 `upto`).
- `payTo` is the provider's 33-byte identity key (hex), not an address.
- `billing` is `postpay` (a call is paid by the next state) or `prepay` (a call is paid before it is served).
- `derivation` names the payee-key derivation, `"v2"` (§5.1). A client MUST refuse an offer with any
  other value, or none, before it funds anything: a script built with another derivation fails the open
  (`bad_funding`) and strands the funding until `expiry`.
- `extra.conditional = {"hash","amount","csvDelta","cipher"}` appears only on a path offering a
  hash-locked deliverable (§6.5). `cipher` is the encrypted deliverable (hex); the header can get large,
  so a provider SHOULD offer conditional calls only for small deliverables (the last chunk of a stream,
  a key).
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
3. `redeemScript` equals the script it builds from `(network, payTo, A, expiry)` with the §5.1
   derivation, else `bad_funding` (a v1.0-derived script, or one derived for another network, fails here);
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
charge is `condAmount`. The response body is `{"cipher","preimage","hash"}` (hex); `cipher` repeats the
offered ciphertext. After the call the provider offers the path under a new `k` (§6.5).

### 7.4 Payment response
On every served call, header `PAYMENT-RESPONSE: base64(SettlementResponse)`, the x402 v2 settlement
response with the channel receipt in `extra`:
```json
{"success":true,"transaction":"","network":"bip122:…","payer":"<A hex>","amount":"",
 "extra":{"chargedAmount":"150",
          "receipt":{"scheme":"xbt-channel","chan":"<txid>:<vout>","seq":5,"cum":"600","charged":"150",
                     "spentMsat":"750000","owedMsat":"150000","creditMsat":"0","expiry":2014,
                     "req":"<hex>","sig":"<DER hex>"}}}
```
- `transaction` and `amount` are empty: a paid call broadcasts nothing. Value moves at the close
  (§7.5, `/x402/settle`).
- `success` is `true` when the handler's status is below 400. `payer` is the channel's `A`.
- `extra.chargedAmount` MUST equal `receipt.charged`. Only the receipt is signed; a client MUST use the
  receipt's fields and refuse a response whose envelope disagrees with it.

`receipt.sig` is `P`'s ECDSA signature over
`tagged_hash("xbt402/receipt", chan ‖ "|" ‖ seq ‖ "|" ‖ cum ‖ "|" ‖ charged ‖ "|" ‖ spentMsat ‖ "|" ‖ req)`.
A handler response with status ≥ 500 is not billed (`charged` = "0"). A handler header containing CR,
LF or NUL MUST be replaced by an unbilled 500 (M4).

**Client checks:** `network` and `payer` are its channel's; the receipt verifies under `P`; `req` is
its own request's digest; `cum` is not more than it signed; `charged` is at most the price pinned at
open (for a conditional call, that call's `condAmount`, already held to the client's caps; never a
quote from a later 402: H6); `spentMsat` grew by at most one call.
When a 402 arrives on an open channel, the client MUST NOT accept a higher `amount` than it opened the
channel at, and MUST NOT adopt more than **one call's worth of unreceipted charges over the channel's
life** (M3).

### 7.5 Close
`POST extra.closeUrl` with `{"chan","sig","payload"?}`. `sig` is `A`'s signature over
`tagged_hash("xbt402/close", chan)`. `payload` is an optional final state (as in §7.3) paying what is
owed. The provider completes the best state with its own signature and broadcasts it. Reply:
`{"chan","txid","cum","unpaidMsat"}`, where `cum` is what the recorded close pays the provider (for a
conditional close, `uncond + condAmount`) and every repeat of the close reports that same close: once a
channel is closed, a `payload` changes nothing (L10). Replaying a close request only closes the same channel with the
best state, which the provider may do at any time anyway.

### 7.6 Facilitator endpoints (optional)
A provider MAY serve the x402 facilitator interface itself. The paths MUST be under `/x402/` so that
they never shadow an API route of the same name (L6). Bodies follow x402 v2:
```json
{"x402Version":2,
 "paymentPayload":{"x402Version":2,"accepted":<PaymentRequirements>,"payload":{…}},
 "paymentRequirements":<PaymentRequirements>}
```
Both `paymentRequirements` and `paymentPayload.accepted` MUST name this scheme, the provider's network
and its `payTo` (else `invalid_xbt_channel_scheme_or_network`); anything else malformed is
`invalid_xbt_channel_payload`. Answers are HTTP 200 whether valid or not; the reason codes are the
upstream-style names of Appendix B.
- `GET /x402/supported` →
  `{"kinds":[{"x402Version":2,"scheme":"xbt-channel","network":"bip122:…"}],"extensions":[],"signers":{}}`.
- `POST /x402/verify`, `payload = {"chan","cum","sig"}`: checks a signed state and records it if higher.
  It is unauthenticated, so it MUST require `sig` for exactly the `cum` given, MUST report nothing the
  caller did not send, MUST NOT check `auth` and MUST NOT move `seq` (otherwise a stranger learns `cum`,
  or locks the client out with a huge `seq`). A state for a channel that is closed, closing (tip at or
  above `expiry − closeMarginBlocks`) or suspended is answered `isValid: false`
  (`invalid_xbt_channel_closing` / `invalid_xbt_channel_unconfirmed`) even when its signature is good:
  a resource server serves on `isValid` (L11). A higher state is still recorded while the channel is
  open or closing. Answer: a `VerifyResponse`,
  `{"isValid":true,"payer":"<A hex>","extra":{"chan","cum"}}` or
  `{"isValid":false,"invalidReason":"invalid_xbt_channel_signature"}`. This is also how a client hands
  over a folded conditional state (§6.5).
- `POST /x402/settle`, `payload` = the close request of §7.5 (`{"chan","sig","payload"?}`): closes the
  channel under the same rules. Answer: a `SettlementResponse`,
  `{"success":true,"transaction":"<close txid>","network":"bip122:…","payer":"<A hex>","amount":"<sat paid
  to the provider by the recorded close>","extra":{"chan","unpaidMsat"}}`, or
  `{"success":false,"errorReason":"<code>","transaction":"","network":"bip122:…"}`. Settling a channel
  that is already closed returns the same close.

### 7.7 Relation to the x402 v2 types
`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`, `VerifyResponse` and `SettlementResponse`
are the x402 v2 types; everything scheme-specific rides in `extra` or `payload`. v1.0 sent the bare
receipt as `PAYMENT-RESPONSE` and took `{payload}` at `/x402/verify`. v1.1 needs no transition rule for
those shapes: a v1.1 client refuses a v1.0 offer before funding (it has no `extra.derivation`), so a
v1.1 client never talks to a v1.0 provider past the 402.

## 8. Channel state machine

Provider view:

| State | Entered when | Serves | Next |
|---|---|---|---|
| `open` | the open checks pass | yes | `suspended`, `closing`, `closed` |
| `suspended` | a watcher tick finds the funding not confirmed to the required depth (reorg) | no (`unconfirmed`) | `open` when it confirms again |
| `closing` | tip ≥ `expiry − closeMarginBlocks`, or a cooperative close request | no (`channel_closing`) | `closed` |
| `closed` | the node has the close (recorded before the broadcast, M8) | no | rebroadcast while the funding is unspent; claim a conditional close |
| `lost` | tip ≥ `expiry` and the client's refund confirmed first | no | none |

Watcher rules (run at least every block):
- Handle each channel independently. One failing close (a node error, a bad state) MUST NOT stop the
  others (H1). Record the error and retry on the next tick.
- Re-check every open channel's funding and suspend a channel whose funding is not confirmed to depth (H2).
- Rebroadcast a recorded close whose funding is unspent again (mempool eviction).
- Record every close before broadcasting it, and adopt a recorded close that is found on-chain or in the
  mempool (M8).
- For a conditional close, rebroadcast the claim until it confirms and raise its fee as `csvDelta` nears (L8).
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
14. Conditional calls only with the enforceable close path and one outstanding increment (M6, §6.5).
15. The payee key commits to the network; clients refuse other derivations before funding (M2, §5.1).
16. An agent-facing client (an MCP tool) returns the provider's body and receipt verbatim, labelled as
    untrusted data (the reference: an `untrusted_provider_response` object with `trust: "untrusted"`), and
    filters only its own fields for key material (L7). Filtering the body made a paid call whose answer
    merely mentioned "seed" look failed after it had been charged. **Every** provider-controlled string
    goes under that label: offer fields and error replies quoted in the tool's errors, and close replies
    too. The tool's own fields are values it can check (its channel id, a txid-shaped txid, integers,
    error codes from a fixed alphabet) (L12).
17. Client: a conditional `condAmount` is held to the per-call cap and budgets before signing (H6).
18. Conditional calls: ciphertext in the 402 before the client signs, a fresh `k` per sale (M7).
19. Provider: record a close before broadcasting it; adopt a recorded close found on-chain (M8). Raise
    the claim's fee as `csvDelta` nears (L8).
20. Facilitator: `/x402/settle` and close repeats report the recorded close (L10); `/x402/verify` is never
    `isValid` for a closed, closing or suspended channel (L11).

## 10. Known weaknesses
This section is deliberately blunt. None of these is a way to steal funds from a correct
implementation that follows the rules above, but each is a place where the protocol leans on operating
discipline or on assumptions about the chain.

### 10.1 M2: the payee key derivation is non-hardened
`t` is computable by anyone who knows `payTo`, `A` and `expiry`, which the client (and anyone who
watches the funding script appear on-chain) does. So any one per-channel secret `p` reveals
`payTo_secret = p − t`, and with it the secret of **every** channel the provider has ever had or will
have. This is the same property as BIP32 non-hardened derivation, and it is the price of opening in one
round trip without a provider-chosen key.

In v1.0, `t` also omitted the network, so the same `payTo` on mainnet, testnet and regtest derived the
same channel keys, and a key leaked from a test deployment compromised production. v1.1 commits to the
network (§5.1, §11), which removes that half. The non-hardened half remains.

Operating rules, which are normative (§9 item 9):
- A provider MUST NOT export a per-channel secret: not to a closing service, a watchtower, a log, a
  crash dump, or another process. To delegate closing, hand out **fully signed close transactions**,
  never `p`.
- A provider MUST use a distinct `payTo` per network. The network in `t` makes a reuse harmless for
  channel keys, but `payTo_secret` itself is still one key: a test host holding it holds production.
- Signing MUST be constant-time (H4): a timing leak of one `p` is a leak of `payTo_secret`.

Making the derivation hardened would need a provider-chosen per-channel key, and so a second round trip
before funding; this draft does not propose that.

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

## 11. v1.1: network in the payee tweak
```
t = int(tagged_hash("xbt-channel/payee/v2", len8(NET) ‖ NET ‖ payTo ‖ A ‖ LE32(expiry))) mod n
```
**Encoding.** `NET` is the CAIP-2 `network` string from the 402, as UTF-8 bytes, prefixed with its
length in one byte. It is the value both sides already hold and compare for equality (the offer's
`network`, the open's `network`), so there is no second representation to get wrong; a genesis or
block hash would bring its own byte-order and length conventions and could disagree with the string both
sides check. The length prefix makes the preimage injective: without it, a network string and a `payTo`
could in principle be re-split into another pair with the same concatenation. The fixed 33-byte `payTo`
makes that unlikely; the prefix makes it impossible for one byte.

**Tag.** `xbt-channel/payee/v2`, not v1.0's `xbt-channel/payee`. A new tag domain-separates the two
derivations: no v1.1 preimage can hash to a v1.0 tweak, whatever the lengths.

What it fixes: the cross-network half of M2. A `payTo` reused on regtest, testnet and mainnet no longer
derives the same channel keys, so a per-channel key leaked from a test deployment is not a production
channel key. It does **not** fix the non-hardened half (one leaked `p` still gives `payTo_secret`).

**Negotiation.** The 402 advertises `extra.derivation: "v2"`. There is no dual support: nothing depends
on v1.0, so a v1.1 provider accepts only v2-derived scripts, and a v1.0 open fails with `bad_funding`.
A v1.1 client refuses an offer without `derivation: "v2"` before funding, so a mismatch costs a 402 and
never strands coins. A later derivation would be `"v3"` under the same rule.

Other candidates for a later version: advertise the large-channel confirmation rule in `extra`
(`largeCapacity`, `minConfLarge`); a taproot variant `xbt-channel-tr` (MuSig2 key path, script leaves
without `OP_IF`, smaller and more private closes); hash-locked outputs inside states so a hub can route
payments without custody.

## 12. Test vectors
`vectors.json` holds, for fixed test keys:
- the payee derivation (`network`, the tweak preimage, `t`, `P`, redeem script, funding scriptPubKey and
  address) for three channels on mainnet and for the first of them on two other networks, each with the
  v1.0 key for the same inputs as a cross-check (`_payeePubV10`);
- the request-authentication key (ECDH x, `K` from both sides) and three `auth` values;
- four state transactions with their UnifiedSighash and the client's signature, a fully signed close,
  a signed refund, and three invalid signatures with the error each must produce;
- a twelve-step exchange: the 402, the open, five paid calls (with the exact `PAYMENT-SIGNATURE` and
  `PAYMENT-RESPONSE` header values and the decoded `SettlementResponse`), a replayed header refused with
  `bad_auth`, `/x402/supported`, `/x402/verify` with a valid state and with a relabelled `cum`, a
  cooperative close with its transaction, and `/x402/settle` returning the same close.

`check_vectors.py` recomputes every value with the reference implementation and exits non-zero on any
difference. It also checks what does not depend on the generator: the preimage layout, `t` against
the tagged hash, `p·G = P`, one key per network and none equal to v1.0's, every signature under the key
that should have made it, and every `PAYMENT-RESPONSE` against the receipt it wraps. The vectors are
identical under the libsecp256k1 backend and the pure-Python backend.

## Changes from v1.0
Breaking (a v1.1 party refuses a v1.0 one at the 402 or the open, before any funds move):
- **Payee key commits to the network** (§5.1, §11): new tag `xbt-channel/payee/v2`, preimage
  `len8(NET) ‖ NET ‖ payTo ‖ A ‖ LE32(expiry)`, advertised as `extra.derivation: "v2"`. Every channel
  address changes. Fixes the cross-network half of M2.
- **`PAYMENT-RESPONSE` is an x402 v2 `SettlementResponse`** (§7.4) with the receipt in
  `extra.receipt` and `extra.chargedAmount`. The receipt keeps its signed fields and signature; its
  `success` and `network` moved to the envelope, and it names its `scheme`.
- **Facilitator bodies are x402 v2** (§7.6): `{x402Version, paymentPayload, paymentRequirements}` in,
  `VerifyResponse` / `SettlementResponse` out, with `invalid_xbt_channel_*` reasons (Appendix B).
  `kinds` entries carry `x402Version`.
- **Facilitator paths moved under `/x402/`** (`/x402/verify`, `/x402/settle`, `/x402/supported`). v1.0
  also answered the bare `/verify`, `/settle`, `/supported`, which shadowed any API route of those
  names (L6).

Breaking, from the pre-publication review of v1.1 (conditional calls only):
- **`extra.conditional.cipher`** (§6.5, §7.1, M7): the 402 carries the ciphertext, and a v1.1 client
  refuses a conditional offer without it before signing. Plain calls are unchanged.

Not breaking:
- **Pre-publication review of v1.1**: clients cap `condAmount` (H6); providers record a close before sending it
  (M8), bump the claim fee (L8) and re-key a conditional path after each sale (M7); the facilitator never
  reports a state that cannot settle (L10, L11); agent tools label every provider string (L12).
- **Hash-locked conditional calls are enforceable** (§6.5, M6): the provider closes with the conditional
  state when it pays more and claims with `k`, refuses a second outstanding increment
  (`conditional_outstanding`), and the client hands over the fold through `/x402/verify`.
- **Agent-facing clients return the provider's response as labelled untrusted data** (§9 item 16, L7).
- **Known weaknesses stated in one place** (§10): M2 and its operating rules, fee and expiry
  assumptions, hot-key custody.
- **Test vectors** (§12), for all of the above.
- **Standalone text.** The chain, `SIGHASH_UNIFIED`, BIP-110 and the maturity rule are described here;
  references to internal documents and deployments are removed.

## Appendix A: security findings referenced in this document
Identifiers come from the security review of the reference implementation that preceded v1.0
(C1–L7), and from the review of the v1.1 changes before publication (H6–L12).
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
| M2 | Non-hardened, network-agnostic payee derivation (network half fixed in v1.1; non-hardened half open by design) | §10.1, §11 |
| M3 | A malicious provider could drain a client with 402 loops and price rises | §7.4 |
| M4 | Header injection, request smuggling and unbounded bodies in the HTTP layer | §7.4, §9 |
| M5 | Each paid call rewrote every channel's record | §9 |
| M6 | The hash-locked conditional state had no provider close path (fixed in v1.1) | §6.5 |
| L6 | Facilitator paths shadowed API routes of the same name | §7.6 |
| L7 | The agent-facing client filtered the provider body for key material, so a charged call could look failed | §9 |
| H6 | The client signed a conditional increment of any size the provider named (one call could take the channel) | §6.5, §7.4 |
| M7 | The ciphertext came after the client signed, so the hash lock paid a provider that never answered | §6.5 |
| M8 | A close the node accepted but the provider never recorded was never claimed | §6.5, §8 |
| L8 | The hash-lock claim's fee was never raised before `csvDelta` | §6.5 |
| L9 | A lost fold blocked later conditional calls (reference client) | §6.5 |
| L10 | Repeated settles reported states the close does not pay | §7.5, §7.6 |
| L11 | `/x402/verify` answered `isValid` for channels that can no longer settle | §7.6 |
| L12 | Provider text reached the model outside the untrusted label (errors, close replies) | §9 |

## Appendix B: error codes
Codes in the 402 `error` field and in `400 {"error"}` answers of the control endpoints:
`payment_required`, `unsupported_scheme_or_network`, `bad_payload`, `unknown_channel`, `bad_auth`,
`channel_closing`, `unconfirmed`, `stale_amount`, `bad_sig`, `bad_sighash`, `bad_amount`,
`bad_hashlock`, `conditional_outstanding`, `insufficient_payment`, `channel_exhausted`,
`coinbase_funding`, `bad_funding`, `unknown_funding`, `bad_capacity`, `bad_expiry`, `bad_payer_spk`,
`wrong_network`, `duplicate_channel`, `close_failed` (close and watcher only).

The facilitator answers (§7.6) carry the upstream-style name of the same code in
`invalidReason` / `errorReason`: `invalid_xbt_channel_<code>`, except `unsupported_scheme_or_network` →
`invalid_xbt_channel_scheme_or_network`, `bad_payload` → `invalid_xbt_channel_payload`, `bad_auth` →
`invalid_xbt_channel_auth`, `channel_closing` → `invalid_xbt_channel_closing`, `bad_sig` →
`invalid_xbt_channel_signature`, `wrong_network` → `invalid_network`, and `close_failed` →
`unexpected_settle_error` (full table: `scheme_xbt-channel.md`, Error Codes). The 402 `error` field
keeps the short codes until the scheme name is settled, because the upstream prefix depends on it
(`invalid_xbt_channel_*` for a new scheme, `invalid_batch_settlement_xbt_*` for a `batch-settlement`
binding; `PUBLISHING.md`).
