#!/bin/bash
# Fresh isolated nodes for tests/regtest_rules.py, all under ~/lazarus-regtest/b1-xbt402 on
# spare ports (never the shared :18443 rig): Knots 29.4.2 A (rpc 19563/p2p 19564),
# Knots 29.4.2 B peered to A (19573/19574), Core 29.0 peered to A (19583/19584), which stays at
# block 100, the last block before blake2b@101 (a stand-in for the SHA-256 chain). No miners;
# everything is stopped and wiped on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
R=$HOME/lazarus-regtest/b1-xbt402
K=$R/knots-29.4.2; C=$R/core-29.0
nodeA()    { XBT_BIN=$K XBT402_DATADIR=$R/rules-a    XBT402_RPCPORT=19563 XBT402_P2PPORT=19564 scripts/node.sh "$@"; }
nodeB()    { XBT_BIN=$K XBT402_DATADIR=$R/rules-b    XBT402_RPCPORT=19573 XBT402_P2PPORT=19574 XBT402_CONNECT=19564 XBT402_BLOCKS=0 scripts/node.sh "$@"; }
nodeCore() { XBT_BIN=$C XBT402_DATADIR=$R/rules-core XBT402_RPCPORT=19583 XBT402_P2PPORT=19584 XBT402_CONNECT=19564 XBT402_BLOCKS=0 scripts/node.sh "$@"; }
cleanup() { [ -n "${KEEP_ON_FAIL:-}" ] && [ "${rc:-0}" != 0 ] && { tail -20 $R/rules-a/regtest/debug.log; }; nodeA wipe; nodeB wipe; nodeCore wipe; } 2>/dev/null
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
cleanup || true
XBT402_BLOCKS=0 nodeA up
# block 1's coinbase pays a key the library holds: the "pre-split coin" for the replay check
PRESPLIT=$(python3 -c "from xbt402 import ecc; from xbt402.tx import p2wpkh_spk, segwit_address; print(segwit_address('bcrt', p2wpkh_spk(ecc.pubkey(0x9E5B11))))")
nodeA cli generatetoaddress 1 "$PRESPLIT" >/dev/null
nodeA cli generatetoaddress 99 "$(nodeA cli -rpcwallet=w getnewaddress)" >/dev/null
nodeCore up
for _ in $(seq 60); do [ "$(nodeCore cli getblockcount)" = 100 ] && break; sleep 0.5; done
echo "core synced the shared history to $(nodeCore cli getblockcount)"
nodeA cli generatetoaddress 200 "$(nodeA cli -rpcwallet=w getnewaddress)" >/dev/null
nodeB up
for _ in $(seq 60); do [ "$(nodeB cli getblockcount)" = 300 ] && break; sleep 0.5; done
echo "A h=$(nodeA cli getblockcount) B h=$(nodeB cli getblockcount) core h=$(nodeCore cli getblockcount) (core refuses BLAKE2b blocks)"
python3 tests/regtest_rules.py
