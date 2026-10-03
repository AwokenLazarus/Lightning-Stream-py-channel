#!/bin/bash
# AGP-021 demo: xbt402 hub routing on regtest. 1 client, 1 hub, 4 providers (A and B: two provider processes
# under one payee key), ~10 s of streamed chunks at >= 10 updates/s per provider, rollover, a non-revealing provider
# and a withholding hub. Prints PASS/FAIL and latency numbers (scripts/demo_route.py).
# Ports XBT402_TEST_PORT_BASE + 1/2 (node), + 10..14 (hub, providers); default base 32300.
# Own Knots 29.4.2 regtest node (RDTS + #419) in run/agp021-demo-<pid>, wiped on exit. No miners.
# Runs under the soak cap (systemd-run --user --scope CPUQuota=200% MemoryMax=4G, nice 19) when it can.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -z "${DEMO_ROUTE_SCOPED:-}" ] && command -v systemd-run >/dev/null 2>&1 \
   && systemd-run --user --scope -q true >/dev/null 2>&1; then
  export DEMO_ROUTE_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
PY=${PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
PB=${XBT402_TEST_PORT_BASE:-32300}
export XBT402_TEST_PORT_BASE=$PB
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export DEMO_RUN="$PWD/run/agp021-demo-$$"
export XBT402_DATADIR="$DEMO_RUN/node"
export XBT402_RPCPORT=$((PB + 1))
export XBT402_P2PPORT=$((PB + 2))
export XBT402_BLOCKS=300
export XBT402_MATURITY_PAD=6800
mkdir -p "$DEMO_RUN"
cleanup() {
  scripts/node.sh down >/dev/null 2>&1 || true
  pid=$(cat "$XBT402_DATADIR/regtest/bitcoind.pid" 2>/dev/null || true)
  if [ -n "$pid" ] && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "$XBT402_DATADIR"; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  if [ -f "$DEMO_RUN/demo_route_report.json" ]; then
    mkdir -p run && cp "$DEMO_RUN/demo_route_report.json" run/demo_route_report.json
  fi
  rm -rf "$DEMO_RUN"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
echo "== regtest node (Knots, RDTS + #419) on rpc $XBT402_RPCPORT"
scripts/node.sh up
"$PY" scripts/demo_route.py
