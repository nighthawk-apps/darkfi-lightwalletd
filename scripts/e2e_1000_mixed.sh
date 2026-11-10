#!/usr/bin/env bash
# Mixed localnet payments.
#
# Main loop: strict UnifOMR. Receivers sync with E2E_STRICT=1 and without
# E2E_FORCE_TRIAL or --force-trial. Every send carries a clue.
#
# Trial leg: labelled separately. Receivers sync with E2E_FORCE_TRIAL=1.
# Those sends omit the clue (--no-omr) and are counted on their own.
#
# ffi-a and ffi-b are headless darkfi-mobile-ffi wallets (localnet_tx).
# The Android emulator and the Tauri desktop app are NOT exercised.
#
# Usage:
#   ./scripts/e2e_1000_mixed.sh
#   COUNT=2 TRIAL_COUNT=1 ./scripts/e2e_1000_mixed.sh
set -euo pipefail

export MOONSHINE_WALLET_PASS="${MOONSHINE_WALLET_PASS:-e2e-localnet}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GH="$(cd "$ROOT/.." && pwd)"
PIN="$GH/darkfi-nighthawk-testnet"
MOON_DIR="$GH/moonshine"
AND_FFI="$GH/nighthawk-android-wallet/rust/darkfi-mobile-ffi"
WORK="${WORK:-$HOME/.local/nighthawk-e2e/mixed-1000}"
COUNT="${COUNT:-1000}"
TRIAL_COUNT="${TRIAL_COUNT:-$COUNT}"
AMOUNT="${AMOUNT:-0.001}"
FEE="${FEE:-1000000}"
LWD_URL="${LWD_URL:-http://127.0.0.1:9067}"
XMRIG="${XMRIG:-$GH/nighthawk-desktop/src-tauri/target/release/xmrig}"
LOG="$WORK/matrix.log"
HASHES="$WORK/hashes.txt"
BALANCE_TIMEOUT="${BALANCE_TIMEOUT:-180}"

started_darkfid=0
started_lwd=0
started_xmrig=0
darkfid_pid=""
lwd_pid=""
xmrig_pid=""

cleanup() {
  if [[ "$started_xmrig" == 1 && -n "$xmrig_pid" ]]; then
    kill "$xmrig_pid" 2>/dev/null || true
  fi
  if [[ "$started_lwd" == 1 && -n "$lwd_pid" ]]; then
    kill "$lwd_pid" 2>/dev/null || true
  fi
  if [[ "$started_darkfid" == 1 && -n "$darkfid_pid" ]]; then
    kill "$darkfid_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "$WORK"/{darkfid,drk,lwd,wallets}
exec > >(tee -a "$LOG") 2>&1

echo "=== mixed localnet $(date -Is) strict_count=$COUNT trial_count=$TRIAL_COUNT ==="
echo "NOTE: ffi-a and ffi-b are headless darkfi-mobile-ffi wallets (localnet_tx)."
echo "NOTE: the Android emulator and the Tauri desktop app are NOT exercised."

bin_of() {
  local base="$1" name="$2"
  if [[ -x "$base/target/release/$name" ]]; then
    echo "$base/target/release/$name"
  elif [[ -x "$base/$name" ]]; then
    echo "$base/$name"
  else
    echo ""
  fi
}

listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lnt | awk -v p=":${port}$" '$4 ~ p { found=1 } END { exit found ? 0 : 1 }'
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    echo "need ss or lsof to see whether port $port is listening" >&2
    return 1
  fi
}

# Rewrite a testnet address to the mainnet prefix drk localnet accepts.
# Payload is prefix || 32-byte key || 4-byte blake3. bs58check wraps that.
reprefix_for_drk() {
  local addr="$1"
  python3 - "$addr" <<'PY'
import hashlib, struct, sys
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def g(st, a, b, c, d, mx, my):
    st[a] = (st[a] + st[b] + mx) & 0xFFFFFFFF
    st[d] = rotr(st[d] ^ st[a], 16)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] = rotr(st[b] ^ st[c], 12)
    st[a] = (st[a] + st[b] + my) & 0xFFFFFFFF
    st[d] = rotr(st[d] ^ st[a], 8)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] = rotr(st[b] ^ st[c], 7)

def blake3_32(data: bytes) -> bytes:
    if len(data) > 64:
        raise SystemExit("reprefix: blake3 input longer than one block")
    block = data + b"\x00" * (64 - len(data))
    st = IV[:] + IV[:4] + [0, 0, len(data), 1 | 2 | 8]
    m = list(struct.unpack("<16I", block))
    for _ in range(7):
        g(st, 0, 4, 8, 12, m[0], m[1]); g(st, 1, 5, 9, 13, m[2], m[3])
        g(st, 2, 6, 10, 14, m[4], m[5]); g(st, 3, 7, 11, 15, m[6], m[7])
        g(st, 0, 5, 10, 15, m[8], m[9]); g(st, 1, 6, 11, 12, m[10], m[11])
        g(st, 2, 7, 8, 13, m[12], m[13]); g(st, 3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in PERM]
    for i in range(8):
        st[i] ^= st[i + 8]
    return struct.pack("<8I", *st[:8])

if blake3_32(b"") != bytes.fromhex(
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
):
    raise SystemExit("reprefix: blake3 self-check failed")

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + ALPH.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPH[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + (out or "")

def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 4:
        raise SystemExit("reprefix: address too short")
    body, check = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    if check != digest:
        raise SystemExit("reprefix: bad base58 checksum")
    return body

def b58check_encode(body: bytes) -> str:
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return b58encode(body + digest)

body = bytearray(b58check_decode(sys.argv[1]))
if len(body) != 37:
    raise SystemExit(f"reprefix: expected 37-byte address payload, got {len(body)}")
if body[0] not in (0xAF, 0x39):
    raise SystemExit(f"reprefix: unexpected address prefix {body[0]:#x}")
body[0] = 0x39
body[33:37] = blake3_32(bytes(body[:33]))[:4]
print(b58check_encode(bytes(body)))
PY
}

DARKFID="${DARKFID:-$(bin_of "$PIN" darkfid)}"
DRK="${DRK:-$(bin_of "$PIN" drk)}"
LWD="${LWD:-$(bin_of "$ROOT" darkfi-lightwalletd)}"
MOON="${MOON:-$(bin_of "$MOON_DIR" moonshine)}"
AND_TX="${AND_TX:-$WORK/android-ffi-tx}"

if [[ -z "$DARKFID" || -z "$DRK" || -z "$LWD" || -z "$MOON" || ! -x "$XMRIG" ]]; then
  echo "missing binaries darkfid=$DARKFID drk=$DRK lwd=$LWD moon=$MOON xmrig=$XMRIG"
  exit 1
fi

if [[ ! -x "$AND_TX" ]]; then
  echo "building headless ffi localnet_tx (not the emulator or the Tauri app)"
  (cd "$AND_FFI" && cargo build --release --bin localnet_tx --features localnet)
  # Workspace target is rust/target, not inside the crate directory.
  built="$(find "$AND_FFI" "$AND_FFI/../target" -path '*/release/localnet_tx' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1{print $2}')"
  if [[ -z "$built" ]]; then
    echo "localnet_tx binary was not produced"
    exit 1
  fi
  cp -f "$built" "$AND_TX"
  chmod +x "$AND_TX"
fi

if ! listening 48345; then
  echo "starting darkfid"
  cp "$PIN/contrib/localnet/darkfid-single-node/darkfid.toml" "$WORK/darkfid.toml"
  "$DARKFID" -vv --config "$WORK/darkfid.toml" >"$WORK/darkfid.log" 2>&1 &
  darkfid_pid=$!
  started_darkfid=1
  for _ in $(seq 1 90); do
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

if ! pgrep -f "$XMRIG" >/dev/null; then
  echo "starting xmrig"
  "$XMRIG" -r 1000 -R 20 -o 127.0.0.1:48347 -t 2 -u "$FAUCET" >"$WORK/xmrig.log" 2>&1 &
  xmrig_pid=$!
  started_xmrig=1
fi

echo "waiting for faucet rewards"
faucet_ok=0
for _ in $(seq 1 180); do
  # Balance first. A scan walks every block and, while xmrig is running,
  # the chain grows faster than drk scan, so the scan never returns.
  bal="$("$DRK" --config "$DRK_CFG" wallet balance 2>/dev/null || true)"
  echo "$bal" | tee "$WORK/faucet-balance.txt"
  if echo "$bal" | awk 'NF && $NF+0 > 80 { found=1 } END { exit found ? 0 : 1 }'; then
    faucet_ok=1
    break
  fi
  # scan can exit non-zero before the wallet has a block
  "$DRK" --config "$DRK_CFG" scan >"$WORK/drk-scan.log" 2>&1 || true
  sleep 5
done
if [[ "$faucet_ok" != 1 ]]; then
  echo "faucet never received rewards"
  tail -20 "$WORK/xmrig.log" || true
  exit 1
fi

if ! listening 9067; then
  echo "starting lightwalletd"
  cat >"$WORK/lightwalletd.toml" <<EOF
darkfid_endpoint = "tcp://127.0.0.1:48345"
grpc_listen = "127.0.0.1:9067"
cache_path = "$WORK/lwd/cache"
poll_interval = 1
chain_name = "darkfi-testnet"
network = "localnet"
# A full trial-decrypt catch-up issues more than the public 120/min cap.
rpc_rate_limit_per_min = 100000
omr_rate_limit_per_min = 100000
EOF
  RUST_LOG=info "$LWD" --config "$WORK/lightwalletd.toml" >"$WORK/lightwalletd.log" 2>&1 &
  lwd_pid=$!
  started_lwd=1
  for _ in $(seq 1 40); do
    listening 9067 && break
    sleep 1
  done
  listening 9067 || { echo "lightwalletd failed"; tail -40 "$WORK/lightwalletd.log"; exit 1; }
fi

init_ffi() {
  local name="$1"
  local dir="$WORK/wallets/$name"
  mkdir -p "$dir"
  E2E_WALLET_DIR="$dir" E2E_LWD="$LWD_URL" "$AND_TX" init >"$dir/init.out"
  awk -F= '/^ADDRESS=/{print $2}' "$dir/init.out"
}

if ! "$MOON" -w e2e_moon address default >/dev/null 2>&1; then
  if ! command -v script >/dev/null 2>&1; then
    echo "moonshine wallet create needs a TTY; install util-linux script" >&2
    exit 1
  fi
  # The mnemonic is printed on the TTY script allocates. Discard it.
  script -qefc "$MOON wallet create e2e_moon" /dev/null >/dev/null 2>&1
fi
MOON_ADDR="$("$MOON" -w e2e_moon address default | awk '/Default address:/ {print $NF; exit}')"
if [[ -z "$MOON_ADDR" ]]; then
  echo "moonshine address missing"
  exit 1
fi
echo "moonshine=$MOON_ADDR"
FFI_A="$(init_ffi ffi-a)"
FFI_B="$(init_ffi ffi-b)"
echo "ffi-a=$FFI_A"
echo "ffi-b=$FFI_B"
printf 'moonshine %s\nffi-a %s\nffi-b %s\n' "$MOON_ADDR" "$FFI_A" "$FFI_B" >"$WORK/addresses.txt"

MOON_FOR_DRK="$(reprefix_for_drk "$MOON_ADDR")"
echo "fund moonshine via drk prefix $MOON_FOR_DRK"
tx="$("$DRK" --config "$DRK_CFG" transfer 60 DRK "$MOON_FOR_DRK")"
printf '%s\n' "$tx" | "$DRK" --config "$DRK_CFG" broadcast | tee "$WORK/fund-moon.log"

echo "funding sync uses --force-trial because the faucet payment has no clue"
"$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial --rebuild-merkle >/dev/null
funded=0
for _ in $(seq 1 30); do
  if "$MOON" -w e2e_moon balance | awk '
      /DRK:/ && /atomic units/ && match($0, /[0-9]+ atomic units/) {
        v = substr($0, RSTART, RLENGTH)
        sub(/ atomic units/, "", v)
        if (v+0 > 1000000000) ok=1
      }
      END { exit ok ? 0 : 1 }
    '; then
    funded=1
    break
  fi
  "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial >/dev/null
  sleep 3
done
if [[ "$funded" != 1 ]]; then
  echo "moonshine still unfunded after force-trial"
  exit 1
fi
"$MOON" -w e2e_moon balance | tee "$WORK/moon-balance.txt"

parties=(moonshine ffi-a ffi-b)

addr_of() {
  case "$1" in
    moonshine) echo "$MOON_ADDR" ;;
    ffi-a) echo "$FFI_A" ;;
    ffi-b) echo "$FFI_B" ;;
    *)
      echo "unknown party $1" >&2
      return 1
      ;;
  esac
}

# Never returns the sender. salt picks among the other parties.
other_party() {
  local src="$1" salt="$2"
  local -a opts=()
  local p
  for p in "${parties[@]}"; do
    if [[ "$p" != "$src" ]]; then
      opts+=("$p")
    fi
  done
  echo "${opts[$((salt % ${#opts[@]}))]}"
}

sync_sender() {
  # Own change is not covered by the recipient clue.
  case "$1" in
    moonshine)
      "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial >/dev/null
      ;;
    ffi-a|ffi-b)
      env -u E2E_STRICT E2E_FORCE_TRIAL=1 E2E_LWD="$LWD_URL" \
        E2E_WALLET_DIR="$WORK/wallets/$1" "$AND_TX" sync >/dev/null
      ;;
    *)
      echo "unknown sender $1" >&2
      return 1
      ;;
  esac
}

read_balance() {
  local who="$1" mode="$2" out
  case "$who" in
    moonshine)
      if [[ "$mode" == trial ]]; then
        "$MOON" -w e2e_moon -s "$LWD_URL" sync --force-trial >/dev/null
      else
        "$MOON" -w e2e_moon -s "$LWD_URL" sync >/dev/null
      fi
      # Read the whole balance printout. Exiting awk early closes the
      # pipe and current Rust panics on that SIGPIPE.
      "$MOON" -w e2e_moon balance | awk '
        /DRK:/ && /atomic units/ && match($0, /[0-9]+ atomic units/) {
          v = substr($0, RSTART, RLENGTH)
          sub(/ atomic units/, "", v)
          print v
        }
      '
      ;;
    ffi-a|ffi-b)
      if [[ "$mode" == trial ]]; then
        out="$(env -u E2E_STRICT E2E_FORCE_TRIAL=1 E2E_LWD="$LWD_URL" \
          E2E_WALLET_DIR="$WORK/wallets/$who" "$AND_TX" sync)"
      else
        out="$(env -u E2E_FORCE_TRIAL E2E_STRICT=1 E2E_LWD="$LWD_URL" \
          E2E_WALLET_DIR="$WORK/wallets/$who" "$AND_TX" sync)"
      fi
      printf '%s\n' "$out" | awk -F= '/^BALANCE=/{b=$2} END{print b+0}'
      ;;
    *)
      echo "unknown wallet $who" >&2
      return 1
      ;;
  esac
}

wait_balance_above() {
  local who="$1" mode="$2" before="$3"
  local start now bal
  start="$(date +%s)"
  while true; do
    # A sync can fail until the block is cached.
    bal="$(read_balance "$who" "$mode" || true)"
    if [[ "$bal" =~ ^[0-9]+$ && "$bal" -gt "$before" ]]; then
      echo "$bal"
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= BALANCE_TIMEOUT )); then
      echo "balance for $who ($mode) did not rise above $before (last=${bal:-missing})" >&2
      return 1
    fi
    sleep 3
  done
}

send_one() {
  local src="$1" dst="$2" mode="$3" memo="${4-}" amount="${5:-$AMOUNT}"
  local to out hash before after
  local -a extra=()
  case "$mode" in
    self|self-trial) ;;
    *)
      if [[ "$src" == "$dst" ]]; then
        echo "refusing to send from $src to itself" >&2
        return 1
      fi
      ;;
  esac
  to="$(addr_of "$dst")"
  sync_sender "$src"
  if [[ "$src" != "$dst" ]]; then
    if [[ "$mode" == trial ]]; then
      before="$(read_balance "$dst" trial)"
    else
      before="$(read_balance "$dst" strict)"
    fi
  fi
  if [[ "$src" == moonshine ]]; then
    if [[ "$mode" == trial || "$mode" == self-trial ]]; then
      extra+=(--no-omr)
    fi
    if [[ -n "$memo" ]]; then
      extra+=(--memo "$memo")
    fi
    if ((${#extra[@]})); then
      out="$("$MOON" -w e2e_moon -s "$LWD_URL" tx send "${extra[@]}" --to "$to" --amount "$amount" --fee "$FEE")"
    else
      out="$("$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$to" --amount "$amount" --fee "$FEE")"
    fi
    hash="$(printf '%s\n' "$out" | awk '/TX hash:/{print $NF; exit}')"
  else
    if [[ "$mode" == trial || "$mode" == self-trial ]]; then
      echo "trial sends must come from moonshine; $src always attaches a memo and a clue" >&2
      return 1
    fi
    if [[ -z "$memo" ]]; then
      echo "empty memo must be sent by moonshine; $src's send always sets a memo" >&2
      return 1
    fi
    # Without E2E_UNIFOMR the headless wallet omits the clue, and a strict
    # UnifOMR receiver never sees the payment.
    out="$(E2E_UNIFOMR=1 E2E_WALLET_DIR="$WORK/wallets/$src" E2E_LWD="$LWD_URL" \
      "$AND_TX" send --to "$to" --count 1 --amount "$amount")"
    hash="$(printf '%s\n' "$out" | awk -F= '/^TX=/{print $2; exit}')"
  fi
  if [[ -z "$hash" ]]; then
    printf '%s\n' "$out" | tail -8 >&2
    echo "send produced no tx hash ($src -> $dst $mode)" >&2
    return 1
  fi
  echo "$hash $mode $src $dst" | tee -a "$HASHES"
  if [[ "$src" == "$dst" ]]; then
    echo "TX=$hash mode=$mode self-send (fee leaves the balance lower, so this is not an increase check)"
    return 0
  fi
  if [[ "$mode" == trial ]]; then
    after="$(wait_balance_above "$dst" trial "$before")"
  else
    after="$(wait_balance_above "$dst" strict "$before")"
  fi
  echo "TX=$hash mode=$mode $src->$dst balance=$after"
}

echo "=== stake ffi wallets with UnifOMR, strict receive ==="
send_one moonshine ffi-a strict "stake-ffi-a" 12
send_one moonshine ffi-b strict "stake-ffi-b" 12

echo "=== main loop strict UnifOMR (E2E_STRICT=1, no --force-trial) count=$COUNT ==="
strict_ok=0
for ((i = 0; i < COUNT; i++)); do
  src="${parties[$((i % 3))]}"
  dst="$(other_party "$src" "$((i + 1))")"
  send_one "$src" "$dst" strict "e2e-strict-$i"
  strict_ok=$((strict_ok + 1))
  if (( i % 25 == 0 )); then
    echo "PROGRESS strict i=$i ok=$strict_ok $(date -Is)"
  fi
done

echo "=== trial-decrypt leg (E2E_FORCE_TRIAL=1, --no-omr) count=$TRIAL_COUNT ==="
trial_ok=0
for ((i = 0; i < TRIAL_COUNT; i++)); do
  src="moonshine"
  dst="$(other_party "$src" "$i")"
  send_one "$src" "$dst" trial "e2e-trial-$i"
  trial_ok=$((trial_ok + 1))
done

echo "=== edge cases ==="
send_one moonshine moonshine self "edge-self-omr"
send_one moonshine moonshine self-trial "edge-self-trial"
send_one moonshine ffi-a strict "edge-dust" "0.00000001"
send_one moonshine ffi-b strict "edge-memo-lock"
# localnet_tx always passes a memo. Empty memo is a moonshine send.
send_one moonshine ffi-a strict ""

if "$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$FFI_A" --amount 0 --fee "$FEE" --memo "edge-zero" >"$WORK/edge-zero.log" 2>&1; then
  echo "zero amount was accepted"
  exit 1
fi
if "$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$FFI_A" --amount "$AMOUNT" --fee 1 --memo "edge-feefloor" >"$WORK/edge-fee.log" 2>&1; then
  echo "fee floor was accepted"
  exit 1
fi
if "$MOON" -w e2e_moon -s "$LWD_URL" tx send --to "$FFI_A" --amount 1000000 --fee "$FEE" --memo "edge-drain" >"$WORK/edge-drain.log" 2>&1; then
  echo "oversized send was accepted"
  exit 1
fi

echo "RESULT strict_ok=$strict_ok trial_ok=$trial_ok count=$COUNT trial_count=$TRIAL_COUNT"
if [[ "$strict_ok" != "$COUNT" || "$trial_ok" != "$TRIAL_COUNT" ]]; then
  echo "count mismatch"
  exit 1
fi
echo "=== done $(date -Is) ==="
