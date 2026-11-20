#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for darkfi-lightwalletd.
#
# Runs after the repository is checked out. Prepares everything needed to
# build the server + the UnifOMR e2e client and to run `cargo test`:
#   - system packages (protoc, sqlite dev, C/C++ toolchain, cmake)
#   - stable Rust toolchain + wasm32 target (edition-2024 deps need >=1.85)
#   - sibling ../darkfi checkout pinned by scripts/darkfi.rev
#   - darkfi contract wasm (required by the dev-only test harness)
#   - release build of darkfi-lightwalletd + e2e_unifomr_matrix
#
# Safe to run repeatedly. Runtime connection to the Mac Studio worker is
# configured separately via the E2E_LWD_URL / E2E_NETWORK environment
# secrets and does not belong in this one-time bootstrap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '\n\033[0;36m==> %s\033[0m\n' "$*"; }

# --- 1. System packages -----------------------------------------------------
# RandomX (pulled in transitively by the darkfi test harness) is built via
# cmake using clang as /usr/bin/c++, which selects the gcc-14 toolchain, so
# libstdc++-14-dev must be present or the link fails with `cannot find -lstdc++`.
PKGS=(
  protobuf-compiler
  libsqlite3-dev
  build-essential
  g++
  cmake
  pkg-config
  libstdc++-14-dev
  git
  curl
  ca-certificates
)

if command -v apt-get >/dev/null 2>&1; then
  SUDO=""
  if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
  log "Installing system packages: ${PKGS[*]}"
  $SUDO apt-get update -y
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends "${PKGS[@]}"
else
  log "apt-get not found; assuming system packages are already provided by the image"
fi

# --- 2. Rust toolchain ------------------------------------------------------
# Cargo.lock pins deps that require Rust edition 2024 (>= 1.85). Ensure a
# recent stable toolchain and the wasm target used to build the contracts.
if command -v rustup >/dev/null 2>&1; then
  log "Ensuring stable Rust toolchain + wasm32 target"
  rustup toolchain install stable --profile minimal --no-self-update
  rustup default stable
  rustup target add wasm32-unknown-unknown
else
  log "rustup not found; using preinstalled cargo ($(cargo --version 2>/dev/null || echo 'missing'))"
  rustup() { :; }  # no-op guard if invoked later
fi

# --- 3. Sibling darkfi checkout --------------------------------------------
# Cargo path deps resolve `../darkfi` relative to this repo. Make sure the
# parent directory is writable before cloning into it.
PARENT="$(cd "$ROOT/.." && pwd)"
DARKFI_DIR="${DARKFI_DIR:-$PARENT/darkfi}"
export DARKFI_DIR
if [ ! -d "$DARKFI_DIR" ]; then
  if ! mkdir -p "$DARKFI_DIR" 2>/dev/null; then
    log "Creating $DARKFI_DIR (needs elevated permissions)"
    sudo mkdir -p "$DARKFI_DIR"
    sudo chown "$(id -u):$(id -g)" "$DARKFI_DIR"
  fi
fi
log "Fetching sibling darkfi checkout into $DARKFI_DIR"
"$SCRIPT_DIR/fetch-darkfi.sh"

# --- 4. darkfi contract wasm ------------------------------------------------
# The dev-dependency darkfi-contract-test-harness pulls in darkfi's validator,
# which include_bytes! the compiled contract wasm. Build them so `cargo test`
# compiles. Skips work when the wasm artifacts already exist.
NEED_CONTRACTS=0
for c in money dao deployooor; do
  if [ ! -f "$DARKFI_DIR/src/contract/$c/darkfi_${c}_contract.wasm" ]; then
    NEED_CONTRACTS=1
  fi
done
if [ "$NEED_CONTRACTS" -eq 1 ]; then
  log "Building darkfi contract wasm (zkas + money/dao/deployooor)"
  make -C "$DARKFI_DIR" contracts
else
  log "darkfi contract wasm already present; skipping"
fi

# --- 5. Build lightwalletd + e2e client -------------------------------------
log "Building darkfi-lightwalletd (release, fhe-omr default)"
cd "$ROOT"
cargo build --release
cargo build --release --bin e2e_unifomr_matrix --features fhe-omr

log "Bootstrap complete. Point the UnifOMR e2e client at the Mac Studio worker with:"
log "  E2E_LWD_URL=<studio-grpc-url> E2E_NETWORK=<testnet|mainnet> ./scripts/e2e_unifomr_matrix.sh"
