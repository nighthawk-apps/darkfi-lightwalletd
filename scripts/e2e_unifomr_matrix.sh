#!/usr/bin/env bash
# UnifOMR registration matrix e2e against a live lightwalletd.
#
# Cases (checklist):
#   both / recv_only — receiver clue PK registered → UnifOMR clue
#   send_only / neither — receiver NOT registered → decoy PK (no registration leak)
#   GetUnifOmrDigest decrypt round-trip
#
# Also runs mobile FFI UnifOMR unit parity (iOS + Android trees).
#
# Usage:
#   ./scripts/e2e_unifomr_matrix.sh
#   LWD_URL=http://127.0.0.1:9067 ./scripts/e2e_unifomr_matrix.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LWD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IOS_FFI="$(cd "$LWD_DIR/../nighthawk-ios-wallet/rust/darkfi-mobile-ffi" && pwd)"
AND_FFI="$(cd "$LWD_DIR/../new-nighthawk-android-wallet/rust/darkfi-mobile-ffi" && pwd)"
LWD_URL="${LWD_URL:-http://127.0.0.1:9067}"
NETWORK="${NETWORK:-testnet}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0

report() {
  local st=$1 name=$2
  if [ "$st" = PASS ]; then
    echo -e "  ${GREEN}✓${NC} $name"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗${NC} $name"
    FAIL=$((FAIL + 1))
  fi
}

echo -e "${CYAN}UnifOMR registration matrix → ${LWD_URL}${NC}"

# Local default requires :9067; remote HTTPS (e.g. Studio ngrok) skips that check.
case "$LWD_URL" in
  http://127.0.0.1:9067|http://localhost:9067|http://[::1]:9067)
    if ! lsof -nP -iTCP:9067 -sTCP:LISTEN >/dev/null 2>&1; then
      echo "lightwalletd not listening on :9067 — start it first"
      exit 1
    fi
    ;;
esac

cd "$LWD_DIR"
cargo build -q --release --bin e2e_unifomr_matrix --features fhe-omr

E2E_LWD_URL="$LWD_URL" E2E_NETWORK="$NETWORK" \
  ./target/release/e2e_unifomr_matrix | tee /tmp/e2e_unifomr_matrix.log

while IFS= read -r line; do
  case "$line" in
    MATRIX_PASS:*) report PASS "${line#MATRIX_PASS:}" ;;
    MATRIX_FAIL:*) report FAIL "${line#MATRIX_FAIL:}" ;;
  esac
done < /tmp/e2e_unifomr_matrix.log

echo -e "\n${CYAN}Mobile FFI UnifOMR unit parity${NC}"
for label_dir in "ios:$IOS_FFI" "android:$AND_FFI"; do
  label="${label_dir%%:*}"
  dir="${label_dir#*:}"
  if (cd "$dir" && cargo test --lib test_unifomr_any_match_second_clue -- --nocapture >/tmp/e2e_${label}_unifomr.log 2>&1); then
    report PASS "${label} any-match unit"
  else
    report FAIL "${label} any-match unit"
    tail -20 "/tmp/e2e_${label}_unifomr.log" || true
  fi
done

echo ""
echo "Matrix summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
