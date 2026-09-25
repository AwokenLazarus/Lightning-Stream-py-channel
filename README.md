# xbt402 / `xbt-channel` (P-003 B1): reference library, local only

x402 v2 scheme **`xbt-channel`**: HTTP 402 payments for AI agents on XBT over Spillman-style
unidirectional channels (P2WSH: payee+payer pay path / CLTV refund). Every channel signature is
`SIGHASH_ALL|UNIFIED` (0x21). Design, wire spec and threat model:
`~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402 HTTP 402 payment channels.md`.

**No remote. Never push.** `xbt402/ecc.py` / `schnorr.py` are pure-Python prototypes (not constant time).

| Path | What |
|---|---|
| `xbt402/tx.py` | tx (de)serialization, scripts, bech32, `unified_sighash` (Knots hf-sighash-opt-in port), BIP143 (tests) |
| `xbt402/ecc.py`, `schnorr.py` | secp256k1 ECDSA (RFC 6979, low-S, Jacobian), BIP340/341 helpers |
| `xbt402/channel.py` | funding script, per-channel payee key from `payTo`, deterministic states, `Payer`, `Payee`, refund |
| `xbt402/funding.py` | provider funding checks (script, capacity, expiry window, confs, **no coinbase funding**) |
| `xbt402/x402_channel.py` | x402 v2 `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`, provider middleware, client SDK |
| `tests/test_*.py` | 166 UnifiedSighash vectors, offline channel rules |
| `tests/regtest_rules.py` + `scripts/rules.sh` | chain-rule experiment: Knots 29.4.2 A+B (RDTS on) + Core 29.0 |
| `tests/regtest_channel.py` | older lifecycle test (run against `scripts/node.sh up`) |
| `demo.sh` | all of the above, then 1,000 paid calls + close + refund-after-expiry (`scripts/demo_run.py`) |

Nodes live under `~/lazarus-regtest/b1-xbt402/` (binaries `knots-29.4.2/`, `core-29.0/`; datadirs wiped
on exit), on ports 19553-19584 and http 19402-19403, never the shared `:18443` rig. No miners are started:
blocks come from `generatetoaddress`.

verify: `cd ~/xbt-rnd/b1 && ./demo.sh && python3 ~/lazarus-regtest/killminer.py | grep -q 'killed nothing'`
