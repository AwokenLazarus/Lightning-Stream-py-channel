#!/bin/bash
# xbt-channel wave 2 demo. Isolated Knots 29.4.2 (RDTS + #419) on ports 30100-30199.
# Datadirs under ~/xbt-rnd/xbt-060/run/. Starts NO miners. Nodes wiped on exit.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PWD/.venv/bin:$PATH"
R=${XBT060_RUN:-$HOME/xbt-rnd/xbt-060/run}
mkdir -p "$R"
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/demo
export XBT402_RPCPORT=30100
export XBT402_P2PPORT=30101
export XBT402_HTTP_PORT=30120
export XBT402_MATURITY_PAD=6800
export RULES_ROOT=$R
cleanup() { scripts/node.sh wipe >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
cleanup

echo "== unit: UnifiedSighash + channel + coincurve oracle + ledger + a3 + conditional + property + mcp"
python3 -m unittest -q tests.test_sighash_vectors tests.test_channel tests.test_ecc_oracle \
  tests.test_ledger tests.test_a3 tests.test_conditional tests.test_property tests.test_mcp
echo "== chain rules: (a) UNIFIED on taproot, (b) RDTS relay of P2WSH channels, (r) replay"
scripts/rules.sh | grep -E '^(  ok|  FAIL|A /|rules:)'
echo "== x402 xbt-channel wave2 demo (ASGI + signer + 1000 calls + conditional + refund)"
scripts/node.sh up
python3 scripts/demo_run.py
