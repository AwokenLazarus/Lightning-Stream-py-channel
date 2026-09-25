#!/bin/bash
# xbt402 demo: fresh private regtest node -> sighash vectors, offline channel tests,
# on-node channel lifecycle, then the HTTP 402 agent demo. Starts NO miners (blocks come from
# generatetoaddress); the node is stopped and its datadir wiped on any exit.
set -euo pipefail
cd "$(dirname "$0")"
export XBT402_DATADIR="$PWD/.regtest-demo" XBT402_RPCPORT=19553 XBT402_HTTP_PORT=19402
node() { XBT402_DATADIR=$XBT402_DATADIR XBT402_RPCPORT=$XBT402_RPCPORT scripts/node.sh "$@"; }
cleanup() { node wipe >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
node wipe >/dev/null 2>&1 || true

echo "== unit: UnifiedSighash reference vectors + channel rules"
python3 -m unittest -q tests.test_sighash_vectors tests.test_channel
echo "== node"
node up
echo "== on-node channel lifecycle"
python3 -m tests.regtest_channel 2>&1 | grep -E '^(  |Ran|OK|FAILED)'
echo "== HTTP 402 agent demo"
python3 scripts/demo_run.py
