#!/bin/bash
# Fresh isolated nodes for tests/regtest_rules.py. Ports XBT402_TEST_PORT_BASE + 32..37 (default
# base 30200, XBT-061's range 30200-30299).
# Datadirs under ~/xbt-rnd/xbt-061/run/. Knots 29.4.2 A+B (RDTS + #419) and Core 29.0 stuck at
# block 100. No miners; everything is stopped and wiped on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
# demo.sh exports a pad for the HTTP node; rules nodes must mine the presplit as block 1 first
unset XBT402_MATURITY_PAD
R=${RULES_ROOT:-$HOME/xbt-rnd/xbt-061/run}
K=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
C=${XBT_CORE_BIN:-$HOME/lazarus-regtest/b1-xbt402/core-29.0}
export RULES_ROOT=$R
PB=${XBT402_TEST_PORT_BASE:-30200}
export RULES_A_RPC=$((PB + 32)) RULES_B_RPC=$((PB + 34)) RULES_CORE_RPC=$((PB + 36))
A_P2P=$((PB + 33))
nodeA()    { XBT_BIN=$K XBT402_DATADIR=$R/rules-a    XBT402_RPCPORT=$RULES_A_RPC XBT402_P2PPORT=$A_P2P scripts/node.sh "$@"; }
nodeB()    { XBT_BIN=$K XBT402_DATADIR=$R/rules-b    XBT402_RPCPORT=$RULES_B_RPC XBT402_P2PPORT=$((PB + 35)) XBT402_CONNECT=$A_P2P XBT402_BLOCKS=0 scripts/node.sh "$@"; }
nodeCore() { XBT_BIN=$C XBT402_DATADIR=$R/rules-core XBT402_RPCPORT=$RULES_CORE_RPC XBT402_P2PPORT=$((PB + 37)) XBT402_CONNECT=$A_P2P XBT402_BLOCKS=0 scripts/node.sh "$@"; }
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
# #419: mature the presplit coinbase (block 1) and wallet UTXOs before the spend tests
if [ "$(nodeA cli getblockcount)" -lt 6800 ]; then
  NEED=$((6800 - $(nodeA cli getblockcount)))
  nodeA cli -rpcwallet=w generatetodescriptor "$NEED" "raw(51)" >/dev/null 2>&1 \
    || nodeA cli generatetoaddress "$NEED" "$(nodeA cli -rpcwallet=w getnewaddress)" >/dev/null
fi
nodeB up
for _ in $(seq 240); do [ "$(nodeB cli getblockcount)" = "$(nodeA cli getblockcount)" ] && break; sleep 0.5; done
echo "A h=$(nodeA cli getblockcount) B h=$(nodeB cli getblockcount) core h=$(nodeCore cli getblockcount) (core refuses BLAKE2b blocks)"
python3 tests/regtest_rules.py
