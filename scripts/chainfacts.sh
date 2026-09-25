#!/bin/bash
# Re-check the spec's chain facts (tests/chainfacts.py) on a fresh throwaway Knots 29.4.2 node.
# env: XBT_BIN (Knots 29.4.2 binary dir), XBT402_RPCPORT, XBT402_P2PPORT, XBT402_DATADIR (wiped after)
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
: "${XBT_BIN:?set XBT_BIN to a Knots 29.4.2 binary dir}" "${XBT402_RPCPORT:?}" "${XBT402_P2PPORT:?}" "${XBT402_DATADIR:?}"
export XBT_BIN XBT402_RPCPORT XBT402_P2PPORT XBT402_DATADIR XBT402_BLOCKS=300 XBT402_MATURITY_PAD=6800
trap '"$HERE/scripts/node.sh" wipe' EXIT
"$HERE/scripts/node.sh" wipe
nice -n 10 "$HERE/scripts/node.sh" up
"${PYTHON:-python3}" "$HERE/tests/chainfacts.py"
