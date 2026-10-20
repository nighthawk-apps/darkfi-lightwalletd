#!/usr/bin/env bash
# Localnet end-to-end: one darkfid, xmrig, UnifOMR lightwalletd, then
# 100 wallet transfers between each Nighthawk client send path.
#
# Clients:
#   moonshine          — Moonshine CLI
#   android-desktop    — Android FFI (desktop and both Android trees use this send path)
#   ios                — iOS FFI
#
# Usage:
#   COUNT=100 ./scripts/e2e_localnet_clients.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GH="$(cd "$ROOT/.." && pwd)"
PIN="$GH/darkfi-nighthawk-testnet"
LWD_DIR="$ROOT"
MOON_DIR="$GH/moonshine"
AND_FFI="$GH/nighthawk-android-wallet/rust/darkfi-mobile-ffi"
IOS_FFI="$GH/nighthawk-ios-wallet/rust/darkfi-mobile-ffi"
WORK="${WORK:-$HOME/.local/nighthawk-e2e/localnet}"
COUNT="${COUNT:-100}"
AMOUNT="${AMOUNT:-0.01}"
FEE="${FEE:-1000000}"
LWD_URL="${LWD_URL:-http://127.0.0.1:9067}"
TARGET="$PIN/target"
TRIPLE="x86_64-unknown-linux-gnu"
LOG="$WORK/matrix.log"

mkdir -p "$WORK"/{darkfid,drk,lwd,wallets}
exec > >(tee -a "$LOG") 2>&1

echo "=== localnet UnifOMR client matrix $(date -Is) count=$COUNT ==="

bin_of() {
  local base="$1" name="$2"
  if [[ -x "$base/$name" ]]; then
    echo "$base/$name"
  elif [[ -x "$base/target/release/$name" ]]; then
    echo "$base/target/release/$name"
  elif [[ -x "$base/target/$TRIPLE/release/$name" ]]; then
    echo "$base/target/$TRIPLE/release/$name"
  elif [[ -x "$TARGET/$TRIPLE/release/$name" ]]; then
    echo "$TARGET/$TRIPLE/release/$name"
  else
    echo ""
  fi
}

DARKFID="$(bin_of "$PIN" darkfid)"
DRK="$(bin_of "$PIN" drk)"
LWD="$(bin_of "$LWD_DIR" darkfi-lightwalletd)"
MOON="$(bin_of "$MOON_DIR" moonshine)"
XMRIG="${XMRIG:-/tmp/xmrig/build/xmrig}"

if [[ -z "$DARKFID" || -z "$DRK" || -z "$LWD" || -z "$MOON" || ! -x "$XMRIG" ]]; then
  echo "missing binaries:"
  echo "  darkfid=$DARKFID"
  echo "  drk=$DRK"
  echo "  lightwalletd=$LWD"
  echo "  moonshine=$MOON"
  echo "  xmrig=$XMRIG"
  exit 1
fi

export CARGO_TARGET_DIR="$TARGET"
build_client() {
  local dir="$1"
  if [[ ! -x "$TARGET/$TRIPLE/release/localnet_tx" ]]; then
    :
  fi
  (cd "$dir" && cargo build --release --target "$TRIPLE" --bin localnet_tx)
}

# Each FFI crate is named darkfi-mobile-ffi, so they cannot share one binary name
# in the same target dir. Build into crate-local target dirs.
build_named() {
  local dir="$1" out="$2"
  (cd "$dir" && cargo build --release --bin localnet_tx)
  local built
  built="$(find "$dir" "$dir/../.." -path '*/release/localnet_tx' -type f -printf '%T@ %p\n' | sort -nr | awk 'NR==1{print $2}')"
  cp -f "$built" "$out"
}

if [[ ! -x "$WORK/android-desktop-tx" ]]; then
  echo "building android/desktop localnet_tx"
  build_named "$AND_FFI" "$WORK/android-desktop-tx"
fi
if [[ ! -x "$WORK/ios-tx" ]]; then
  echo "building ios localnet_tx"
  build_named "$IOS_FFI" "$WORK/ios-tx"
fi

listening() {
  ss -lnt | awk -v p=":$1" '$4 ~ p"$" { found=1 } END { exit found ? 0 : 1 }'
}

if ! listening 48345; then
  echo "starting darkfid"
  cp "$PIN/contrib/localnet/darkfid-single-node/darkfid.toml" "$WORK/darkfid.toml"
  # database path in the toml is relative to the process cwd
  cd "$WORK"
  "$DARKFID" -vv --config "$WORK/darkfid.toml" >"$WORK/darkfid.log" 2>&1 &
  echo $! >"$WORK/darkfid.pid"
  for _ in $(seq 1 60); do
    listening 48345 && break
    sleep 1
  done
  listening 48345 || { echo "darkfid failed"; tail -40 "$WORK/darkfid.log"; exit 1; }
fi

DRK_CFG="$WORK/drk.toml"
cat >"$DRK_CFG" <<EOF
network = "localnet"
[network_config."localnet"]
cache_path = "$WORK/drk/cache"
wallet_path = "$WORK/drk/wallet.db"
wallet_pass = "testing"
endpoint = "tcp://127.0.0.1:48345"
history_path = "$WORK/drk/history.txt"
EOF

if [[ ! -f "$WORK/drk/wallet.db" ]]; then
  "$DRK" --config "$DRK_CFG" wallet initialize
  "$DRK" --config "$DRK_CFG" wallet keygen
  "$DRK" --config "$DRK_CFG" wallet default-address 1
fi
FAUCET="$("$DRK" --config "$DRK_CFG" wallet address | awk 'NF{print $NF; exit}')"
echo "faucet=$FAUCET"

echo "waiting for faucet rewards"
for _ in $(seq 1 180); do
  "$DRK" --config "$DRK_CFG" scan >"$WORK/drk-scan.log" 2>&1 || true
  bal="$("$DRK" --config "$DRK_CFG" wallet balance 2>/dev/null || true)"
  echo "$bal" | tee "$WORK/faucet-balance.txt"
  # Epoch-1 reward is 20 DRK. Need >40 so a 40 DRK transfer still covers the fee.
  if echo "$bal" | awk 'NF && $NF+0 > 45 { found=1 } END { exit found ? 0 : 1 }'; then
    break
  fi
  sleep 5
done
if ! echo "$(cat "$WORK/faucet-balance.txt")" | awk 'NF && $NF+0 > 45 { found=1 } END { exit found ? 0 : 1 }'; then
  echo "faucet never received rewards"
  tail -30 "$WORK/xmrig.log" || true
  tail -30 "$WORK/darkfid.log" || true
  exit 1
fi

# Stop the miner so wallet scans can catch a stable tip. It is restarted
# after the faucet payment is broadcast.
if [[ -f "$WORK/xmrig.pid" ]]; then
  kill "$(cat "$WORK/xmrig.pid")" 2>/dev/null || true
fi
pkill -f '/tmp/xmrig/build/xmrig' 2>/dev/null || true

if ! listening 9067; then
  echo "starting lightwalletd"
  cat >"$WORK/lightwalletd.toml" <<EOF
darkfid_endpoint = "tcp://127.0.0.1:48345"
grpc_listen = "127.0.0.1:9067"
cache_path = "$WORK/lwd/cache"
poll_interval = 2
chain_name = "darkfi-testnet"
network = "localnet"
EOF
  RUST_LOG=info "$LWD" --config "$WORK/lightwalletd.toml" >"$WORK/lightwalletd.log" 2>&1 &
  echo $! >"$WORK/lwd.pid"
  for _ in $(seq 1 30); do
    listening 9067 && break
    sleep 1
  done
  listening 9067 || { echo "lightwalletd failed"; tail -40 "$WORK/lightwalletd.log"; exit 1; }
fi

export E2E_LWD="$LWD_URL"
# Sender change notes are not in the recipient UnifOMR clue. The FFI
# runners trial-decrypt between sends when this is set.
export E2E_FORCE_TRIAL=1

init_ffi() {
  local name="$1" bin="$2"
  local dir="$WORK/wallets/$name"
  mkdir -p "$dir"
  E2E_WALLET_DIR="$dir" "$bin" init >"$dir/init.out"
  awk -F= '/^ADDRESS=/{print $2}' "$dir/init.out"
}

echo "init moonshine"
# wallet create prints the seed and refuses a non-TTY stderr
if ! "$MOON" -w e2e_moon address default >/dev/null 2>&1; then
  script -qefc "$MOON wallet create e2e_moon" "$WORK/moon-create.log"
fi
MOON_ADDR="$("$MOON" -w e2e_moon address default | awk '/Default address:/ {print $NF; exit} /^f/{print; exit}')"
echo "moonshine=$MOON_ADDR"
AND_ADDR="$(init_ffi android-desktop "$WORK/android-desktop-tx")"
IOS_ADDR="$(init_ffi ios "$WORK/ios-tx")"
echo "android-desktop=$AND_ADDR"
echo "ios=$IOS_ADDR"

# darkfid/drk encode localnet addresses with the mainnet prefix. Moonshine
# and the mobile wallets use the testnet prefix. The payment is to the public
# key, so rewrite only the prefix the faucet wallet will accept.
echo "fund moonshine from faucet"
if [[ ! -x "$WORK/reprefix" ]]; then
  echo "missing $WORK/reprefix (mainnet address prefix helper)"
  exit 1
fi
MOON_FOR_DRK="$("$WORK/reprefix" "$MOON_ADDR")"
echo "moonshine mainnet-prefix=$MOON_FOR_DRK"
tx="$("$DRK" --config "$DRK_CFG" transfer 40 DRK "$MOON_FOR_DRK")"
printf '%s\n' "$tx" | "$DRK" --config "$DRK_CFG" broadcast | tee "$WORK/fund-moon.log"
"$DRK" --config "$DRK_CFG" scan >"$WORK/drk-scan.log" 2>&1 || true

if ! pgrep -f '/tmp/xmrig/build/xmrig' >/dev/null; then
  echo "starting xmrig for confirmations"
  "$XMRIG" -r 1000 -R 20 -o 127.0.0.1:48347 -t 1 -u "$FAUCET" >"$WORK/xmrig.log" 2>&1 &
  echo $! >"$WORK/xmrig.pid"
fi

echo "moonshine trial-decrypt faucet funds and register UnifOMR"
for _ in $(seq 1 40); do
  "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial | tee "$WORK/moon-sync.log" | tail -5
  if "$MOON" -w e2e_moon balance | awk '/Raw:/{ if ($2+0 > 1000000000) ok=1 } END { exit ok ? 0 : 1 }'; then
    break
  fi
  sleep 5
done
"$MOON" -w e2e_moon balance | tee "$WORK/moon-balance.txt"

echo "register android and ios clue keys"
E2E_WALLET_DIR="$WORK/wallets/android-desktop" "$WORK/android-desktop-tx" sync | tee "$WORK/wallets/android-desktop/sync.out"
E2E_WALLET_DIR="$WORK/wallets/ios" "$WORK/ios-tx" sync | tee "$WORK/wallets/ios/sync.out"

fund_light() {
  local name="$1" addr="$2"
  echo "moonshine -> $name stake"
  local i
  for i in $(seq 1 20); do
    "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial >/dev/null 2>&1 || true
    "$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$addr" --amount 8 --fee "$FEE" --memo "stake-$name" \
      >"$WORK/stake-$name.log" 2>&1 || true
    cat "$WORK/stake-$name.log"
    if ! grep -q "Insufficient funds" "$WORK/stake-$name.log"; then
      return 0
    fi
    echo "stake $name waiting for a confirmed change output ($i)"
    sleep 5
  done
  echo "stake $name failed"
  return 1
}

fund_light android-desktop "$AND_ADDR"
fund_light ios "$IOS_ADDR"

echo "wait for stake confirms"
sleep 20
E2E_WALLET_DIR="$WORK/wallets/android-desktop" "$WORK/android-desktop-tx" sync | tee -a "$WORK/wallets/android-desktop/sync.out"
E2E_WALLET_DIR="$WORK/wallets/ios" "$WORK/ios-tx" sync | tee -a "$WORK/wallets/ios/sync.out"
"$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial | tee -a "$WORK/moon-sync.log" | tail -8

send_pair() {
  local src="$1" dst="$2" dst_addr="$3"
  echo "=== $src -> $dst x$COUNT ==="
  case "$src" in
    moonshine)
      local ok=0 fail=0
      for ((i=0; i<COUNT; i++)); do
        # Own change notes are not addressed by the recipient clue, so strict
        # UnifOMR sync never credits them. Trial-decrypt keeps the next input.
        "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial >/dev/null 2>&1 || true
        if out="$("$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$dst_addr" --amount "$AMOUNT" --fee "$FEE" --memo "e2e-$src-$dst-$i" 2>&1)"; then
          echo "$out" | awk '/TX hash:/{print}'
          ok=$((ok+1))
        else
          echo "$out" | tail -5
          fail=$((fail+1))
          if (( fail >= 5 )); then
            break
          fi
        fi
      done
      echo "PAIR $src->$dst ok=$ok fail=$fail"
      ;;
    android-desktop)
      E2E_WALLET_DIR="$WORK/wallets/android-desktop" "$WORK/android-desktop-tx" send --to "$dst_addr" --count "$COUNT" --amount "$AMOUNT"
      ;;
    ios)
      E2E_WALLET_DIR="$WORK/wallets/ios" "$WORK/ios-tx" send --to "$dst_addr" --count "$COUNT" --amount "$AMOUNT"
      ;;
  esac
}

send_pair moonshine android-desktop "$AND_ADDR" || echo "PAIR_FAIL moonshine->android-desktop"
send_pair moonshine ios "$IOS_ADDR" || echo "PAIR_FAIL moonshine->ios"
send_pair android-desktop moonshine "$MOON_ADDR" || echo "PAIR_FAIL android-desktop->moonshine"
send_pair android-desktop ios "$IOS_ADDR" || echo "PAIR_FAIL android-desktop->ios"
send_pair ios moonshine "$MOON_ADDR" || echo "PAIR_FAIL ios->moonshine"
send_pair ios android-desktop "$AND_ADDR" || echo "PAIR_FAIL ios->android-desktop"

echo "=== done $(date -Is) log=$LOG ==="
