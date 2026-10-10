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
