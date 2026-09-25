#!/bin/bash
# Private throwaway regtest node for xbt402 (own datadir + ports; never the shared rig node :18443).
# usage: scripts/node.sh up|down|wipe|cli ARGS...
# env: XBT_BIN (binary dir), XBT402_DATADIR, XBT402_RPCPORT, XBT402_P2PPORT, XBT402_CONNECT, XBT402_BLOCKS
set -euo pipefail
BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
DD=${XBT402_DATADIR:-$HOME/lazarus-regtest/b1-xbt402/node-dev}
RPCPORT=${XBT402_RPCPORT:-19543}
P2P=${XBT402_P2PPORT:-19544}
BLOCKS=${XBT402_BLOCKS:-300}
ARGS=(-regtest -datadir="$DD" -rpcport="$RPCPORT" -port="$P2P" -bind=127.0.0.1 -rpcbind=127.0.0.1
      -rpcallowip=127.0.0.1 -discover=0 -listenonion=0 -upnp=0 -natpmp=0 -dnsseed=0 -fixedseeds=0
      -fallbackfee=0.0002 -txindex=1)
if ! "$BIN/bitcoind" -version | head -1 | grep -q "Bitcoin Core daemon"; then
  # RDTS applies from the hardfork until MTP passes -rdtsexpiry; set it a year out so RDTS is on
  ARGS+=(-testactivationheight=blake2b@101 -blake2b_headline=xbt402 -rdtsexpiry=$(( $(date +%s) + 31536000 )))
fi
[ -n "${XBT402_CONNECT:-}" ] && ARGS+=(-connect="127.0.0.1:$XBT402_CONNECT")
cli() { "$BIN/bitcoin-cli" -regtest -datadir="$DD" -rpcport="$RPCPORT" "$@"; }
case "${1:-}" in
  up)
    mkdir -p "$DD"
    if ! cli getblockcount >/dev/null 2>&1; then
      "$BIN/bitcoind" "${ARGS[@]}" -daemon >/dev/null
      for _ in $(seq 120); do cli getblockcount >/dev/null 2>&1 && break; sleep 0.5; done
      if ! cli getblockcount >/dev/null 2>&1; then
        echo "node at $DD failed to start:" >&2; tail -8 "$DD/regtest/debug.log" >&2 || true; exit 1
      fi
    fi
    cli -named createwallet wallet_name=w load_on_startup=false >/dev/null 2>&1 || cli loadwallet w >/dev/null 2>&1 || true
    if [ "$BLOCKS" -gt 0 ] && [ "$(cli getblockcount)" -lt "$BLOCKS" ]; then
      cli generatetoaddress $((BLOCKS - $(cli getblockcount))) "$(cli -rpcwallet=w getnewaddress)" >/dev/null
    fi
    echo "node up: $("$BIN/bitcoind" -version | head -1 | sed 's/.*version //'), height $(cli getblockcount), rpc $RPCPORT, p2p $P2P, datadir $DD" ;;
  down) cli stop >/dev/null 2>&1 || true
    # bitcoind deletes its pid file as the very last step of shutdown
    for _ in $(seq 240); do [ -e "$DD/regtest/bitcoind.pid" ] || break; sleep 0.25; done ;;
  wipe) "$0" down; rm -rf "$DD" ;;
  cli) shift; cli "$@" ;;
  *) echo "usage: $0 up|down|wipe|cli ..." >&2; exit 2 ;;
esac
