#!/bin/bash
# Private throwaway regtest node for xbt402 (own datadir + ports; never the shared rig node).
# usage: scripts/node.sh up|down|cli ARGS...
set -euo pipefail
B1=$(cd "$(dirname "$0")/.." && pwd)
BIN=${XBT_BIN:-$HOME/lazarus-regtest/prefix/bin}
DD=${XBT402_DATADIR:-$B1/.regtest}
RPCPORT=${XBT402_RPCPORT:-19543}
ARGS=(-regtest -datadir="$DD" -rpcport="$RPCPORT" -port=19544 -rpcbind=127.0.0.1
      -rpcallowip=127.0.0.1 -listen=0 -discover=0 -listenonion=0 -upnp=0 -natpmp=0
      -fallbackfee=0.0002 -txindex=1 -testactivationheight=blake2b@101 -blake2b_headline=xbt402)
cli() { "$BIN/bitcoin-cli" -regtest -datadir="$DD" -rpcport="$RPCPORT" "$@"; }
case "${1:-}" in
  up)
    mkdir -p "$DD"
    if ! cli getblockcount >/dev/null 2>&1; then
      "$BIN/bitcoind" "${ARGS[@]}" -daemon >/dev/null
      for _ in $(seq 120); do cli getblockcount >/dev/null 2>&1 && break; sleep 0.5; done
    fi
    cli -named createwallet wallet_name=w load_on_startup=false >/dev/null 2>&1 || cli loadwallet w >/dev/null 2>&1 || true
    if [ "$(cli getblockcount)" -lt 300 ]; then
      cli generatetoaddress $((300 - $(cli getblockcount))) "$(cli -rpcwallet=w getnewaddress)" >/dev/null
    fi
    echo "xbt402 node up: height $(cli getblockcount), rpc 127.0.0.1:$RPCPORT, datadir $DD" ;;
  down) cli stop >/dev/null 2>&1 || true
    for _ in $(seq 60); do cli getblockcount >/dev/null 2>&1 || break; sleep 0.5; done ;;
  wipe) "$0" down; rm -rf "$DD" ;;
  cli) shift; cli "$@" ;;
  *) echo "usage: $0 up|down|wipe|cli ..." >&2; exit 2 ;;
esac
