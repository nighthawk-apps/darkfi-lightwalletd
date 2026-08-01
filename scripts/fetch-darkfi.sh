#!/usr/bin/env bash
# Fetch the sibling `darkfi` checkout required by Cargo path deps (`../darkfi`).
#
# Layout (default):
#   <parent>/
#     darkfi/                 ← cloned here
#     darkfi-lightwalletd/    ← this repo
#
# Behavior:
#   - Missing ../darkfi → clone + checkout scripts/darkfi.rev (or DARKFI_GIT_REF)
#   - Existing ../darkfi → reuse as-is (no checkout), unless FORCE_DARKFI_PIN=1
#
# Overrides:
#   DARKFI_DIR=/path/to/darkfi ./scripts/fetch-darkfi.sh
#   DARKFI_GIT_URL=… DARKFI_GIT_REF=… FORCE_DARKFI_PIN=1 ./scripts/fetch-darkfi.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARENT="$(cd "$ROOT/.." && pwd)"

DARKFI_DIR="${DARKFI_DIR:-$PARENT/darkfi}"
DARKFI_GIT_URL="${DARKFI_GIT_URL:-https://github.com/darkrenaissance/darkfi.git}"
REV_FILE="$SCRIPT_DIR/darkfi.rev"
DEFAULT_REF="$(tr -d '[:space:]' <"$REV_FILE" 2>/dev/null || true)"
DARKFI_GIT_REF="${DARKFI_GIT_REF:-${DEFAULT_REF:-master}}"
FORCE_DARKFI_PIN="${FORCE_DARKFI_PIN:-0}"

echo "darkfi target: $DARKFI_DIR"
echo "git url:       $DARKFI_GIT_URL"
echo "git ref:       $DARKFI_GIT_REF"

checkout_pin() {
  local ref="$1"
  git fetch --tags origin 2>/dev/null || git fetch origin || true
  if git rev-parse --verify "${ref}^{commit}" >/dev/null 2>&1; then
    git checkout --detach "$ref"
  elif git rev-parse --verify "origin/${ref}^{commit}" >/dev/null 2>&1; then
    git checkout --detach "origin/${ref}"
  else
    echo "error: cannot resolve DARKFI_GIT_REF='$ref' in $DARKFI_DIR" >&2
    exit 1
  fi
}

if [[ ! -d "$DARKFI_DIR/.git" ]]; then
  echo "Cloning darkfi into $DARKFI_DIR …"
  mkdir -p "$(dirname "$DARKFI_DIR")"
  git clone "$DARKFI_GIT_URL" "$DARKFI_DIR"
  cd "$DARKFI_DIR"
  checkout_pin "$DARKFI_GIT_REF"
else
  cd "$DARKFI_DIR"
  if [[ "$FORCE_DARKFI_PIN" == "1" ]]; then
    echo "FORCE_DARKFI_PIN=1 — checking out $DARKFI_GIT_REF"
    checkout_pin "$DARKFI_GIT_REF"
  else
    echo "Reusing existing darkfi checkout (set FORCE_DARKFI_PIN=1 to pin scripts/darkfi.rev)"
  fi
fi

echo "darkfi ready at $DARKFI_DIR @ $(git rev-parse --short HEAD)"
