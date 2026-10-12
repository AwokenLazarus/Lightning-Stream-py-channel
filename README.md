# xbt402

Python reference for the on-chain one-way channel of Lightning Stream: HTTP 402 payments on XBT
over a one-way payment channel, carried as the x402 v2 scheme `batch-settlement` (the `xbt-channel`
name is accepted as an input alias for one release).

**This channel is frozen.** On 2026-10-11 Lightning Stream was redirected onto Lightning: it adds
stream tickets to ordinary XBT Lightning channels (in design, not built; see the Rust repository).
The channel here is kept and tested, off the main path, with no new work. The hub, which routed
payments between such channels, was retired the same day and removed from this tree: Lightning's
routing does that job. Its code is in the git history, last at commit `dfd6791`.

**Status: reference, test networks only.** It has had an internal review, and it carries the fixes that followed an external review of the Rust tree and four follow-up audits of our own; some findings end as stated limits (`docs/LIMITS.md`; the open items are listed in the Rust repository). None of this is an independent audit. Do not
use it with mainnet funds. The Rust implementation is [Lightning Stream](https://github.com/AwokenLazarus/Lightning-Stream).

| Path | What |
|---|---|
| `xbt402/` | Channel scripts and transactions, UnifiedSighash, provider and client, ledger, watcher, signer, HTTP transport |
| `tests/` | Unit tests. `tests/security/` has one module per review finding |
| `docs/x402/` | The scheme write-up and the byte-exact vectors |
| `docs/embedders.md` | Embedder surface |
| `scripts/` | Throwaway regtest node, chain-rule checks, demos, and the loopback-only provider the interop tests run (`mainnet_provider.py`; it refuses to serve mainnet) |

## Checks

Python 3.12. `coincurve` (libsecp256k1) is optional for the tests and required for any key with
real value; without it the library uses a pure-Python backend that is not constant-time.

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m unittest discover -s tests/security
.venv/bin/python docs/x402/check_vectors.py
```

Regtest scripts take a Bitcoin Knots 29.4.2 build (BLAKE2b) from the environment:

```sh
export XBT_BIN=/path/to/knots-29.4.2 XBT402_DATADIR=$(mktemp -d)
```

## Licence

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE`.
