#!/bin/bash
# xbt-channel (x402 v2) demo on isolated nodes under ~/lazarus-regtest/b1-xbt402 (never the shared
# :18443 rig). Runs: sighash vectors + offline channel tests, the chain-rule experiment
# (Knots 29.4.2 A+B, Core 29.0), then the HTTP demo (1,000 paid calls, close, refund after expiry).
# Starts NO miners: blocks come from generatetoaddress. Every node is stopped and wiped on exit.
set -euo pipefail
cd "$(dirname "$0")"
R=$HOME/lazarus-regtest/b1-xbt402
export XBT_BIN=$R/knots-29.4.2 XBT402_DATADIR=$R/demo XBT402_RPCPORT=19553 XBT402_P2PPORT=19554 XBT402_HTTP_PORT=19402
cleanup() { scripts/node.sh wipe >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
cleanup

echo "== unit: 166 UnifiedSighash vectors + channel rules"
python3 -m unittest -q tests.test_sighash_vectors tests.test_channel
echo "== chain rules: (a) UNIFIED on taproot, (b) RDTS relay of P2WSH channels, (r) replay"
scripts/rules.sh | grep -E '^(  ok|  FAIL|A /|rules:)'
echo "== x402 xbt-channel demo"
scripts/node.sh up
python3 scripts/demo_run.py
