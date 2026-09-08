#!/usr/bin/env bash
# Live tx-matrix against MacBook Pro loopback LWD + public testnet explorer URLs.
#
# Usage:
#   ./scripts/e2e_tx_matrix.sh
#   E2E_TX_HASHES="hash1 hash2" ./scripts/e2e_tx_matrix.sh
#
# Does not start/stop darkfid or lightwalletd. Refuses Studio/ngrok endpoints.
set -euo pipefail

LWD_URL="${LWD_URL:-http://127.0.0.1:9067}"
DARKFID_RPC="${DARKFID_RPC:-127.0.0.1:18345}"
EXPLORER="${EXPLORER:-https://explorer.testnet.dark.fi}"
PROTO="${PROTO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/proto/lightwallet.proto}"

if [[ "$LWD_URL" == *ngrok* || "$LWD_URL" == *epidermis* || "$LWD_URL" != *127.0.0.1* && "$LWD_URL" != *localhost* ]]; then
  echo "refusing remote/Studio LWD_URL=$LWD_URL — use http://127.0.0.1:9067"
  exit 1
fi

if ! lsof -nP -iTCP:9067 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "lightwalletd not listening on 127.0.0.1:9067"
  exit 1
fi

echo "LWD_URL=$LWD_URL"
echo "explorer=$EXPLORER"

grpcurl -plaintext -proto "$PROTO" -import-path "$(dirname "$PROTO")" \
  127.0.0.1:9067 darkfi.lightwallet.DarkFiLightWallet/GetLightInfo
echo
grpcurl -plaintext -proto "$PROTO" -import-path "$(dirname "$PROTO")" \
  127.0.0.1:9067 darkfi.lightwallet.DarkFiLightWallet/GetOmrCapabilities
echo

rpc() {
  printf '%s\n' "$1" | nc -w3 "$DARKFID_RPC" "${DARKFID_RPC##*:}" 2>/dev/null || \
    printf '%s\n' "$1" | nc -w3 127.0.0.1 18345
}

echo "=== darkfid tip ==="
printf '%s\n' '{"jsonrpc":"2.0","method":"blockchain.last_confirmed_block","params":[],"id":1}' | nc -w3 127.0.0.1 18345
echo
echo "=== mempool ==="
printf '%s\n' '{"jsonrpc":"2.0","method":"tx.pending","params":[],"id":1}' | nc -w3 127.0.0.1 18345
echo

# Default: the MacBook Pro local-LWD UnifOMR send confirmed at height 62369.
E2E_TX_HASHES="${E2E_TX_HASHES:-685d3b0faa7e5e71bd8a331042b837456a4bbec9e14afdf83e42ebee81e83b5b}"

echo "=== public testnet explorer URLs ==="
for h in $E2E_TX_HASHES; do
  echo "tx:    $EXPLORER/tx/$h"
  echo "block: $EXPLORER/block/62369  # 685d3b0f confirmed here (scan LWD GetBlock if hash differs)"
  resp=$(printf '%s\n' "{\"jsonrpc\":\"2.0\",\"method\":\"blockchain.get_tx\",\"params\":[\"$h\"],\"id\":1}" | nc -w3 127.0.0.1 18345)
  if echo "$resp" | grep -q '"result"'; then
    echo "darkfid blockchain.get_tx: present ($(echo -n "$resp" | wc -c) bytes)"
  else
    echo "darkfid blockchain.get_tx: $resp"
  fi
  echo
done
