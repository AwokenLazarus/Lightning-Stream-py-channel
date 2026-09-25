# xbt402 (P-003 B1) — reference library, local only

HTTP 402 payments for AI agents on XBT through Spillman-style unidirectional channels
(P2WSH 2-of-2 pay path + CLTV refund), every channel signature `SIGHASH_ALL|UNIFIED` (0x21).
Design + threat model: `~/notes/projects/lazarus-xbt/Research/P-003/B1 xbt402 HTTP 402 payment channels.md`.

**No remote. Never push.** Prototype crypto (`xbt402/ecc.py`) is pure Python and not constant time.

| Path | What |
|---|---|
| `xbt402/tx.py` | tx (de)serialization, scripts, bech32, `unified_sighash` (Knots hf-sighash-opt-in port) |
| `xbt402/ecc.py` | secp256k1 ECDSA, RFC 6979, low-S (swap for libsecp256k1 in production) |
| `xbt402/channel.py` | funding script, deterministic state txs, `Payer`, `Payee`, refund |
| `xbt402/funding.py` | payee funding checks (script, capacity, expiry window, confs, **no coinbase funding**) |
| `xbt402/http402.py` | 402 challenge / credential / receipt headers, stdlib server middleware, client SDK |
| `tests/` | 166 UnifiedSighash vectors, offline channel rules, on-node lifecycle (`regtest_channel.py`) |
| `demo.sh` | fresh private regtest node (ports 19553/19544, http 19402) → all tests → HTTP agent demo |

verify: `cd ~/xbt-rnd/b1 && ./demo.sh && python3 ~/lazarus-regtest/killminer.py | grep -q 'killed nothing'`

The demo starts no miners (blocks via `generatetoaddress` on its own node) and wipes its node on exit.
