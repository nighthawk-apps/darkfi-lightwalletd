#!/usr/bin/env bash
# Cloud Agent install script for darkfi-lightwalletd.
#
# Idempotent bootstrap that prepares a full build/test/run environment:
#   - system packages (protoc, sqlite, C/C++ toolchain, cmake)
#   - Rust stable (>= 1.85; edition 2024 deps) + wasm32 target
#   - sibling darkfi checkout at the pinned rev (Cargo path deps use ../darkfi)
#   - darkfi contract .wasm blobs (required by the dev-only test harness)
#   - release build of darkfi-lightwalletd + compiled test binaries
#
# Safe to re-run: apt/rustup/git/cargo steps all converge without side effects.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> [1/6] System packages"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
# protobuf-compiler: build.rs (tonic-build) needs protoc on PATH
# libsqlite3-dev: darkfi_money_contract links -lsqlite3
# build-essential/g++/cmake: darkfi-contract-test-harness builds RandomX via CMake (C++)
# pkg-config: generic build glue
sudo apt-get install -y -qq --no-install-recommends \
  protobuf-compiler \
  libsqlite3-dev \
  build-essential \
  cmake \
  pkg-config

echo "==> [2/6] Default cc/c++ to GNU gcc/g++ (RandomX CMake build fails under clang)"
# The base image defaults cc/c++ to clang, which cannot locate libstdc++.so when
# CMake link-tests the C++ compiler. Point the alternatives at gcc/g++.
if command -v gcc >/dev/null && command -v g++ >/dev/null; then
  sudo update-alternatives --install /usr/bin/cc  cc  /usr/bin/gcc 100 || true
  sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++ 100 || true
  sudo update-alternatives --set cc  /usr/bin/gcc || true
  sudo update-alternatives --set c++ /usr/bin/g++ || true
fi

echo "==> [3/6] Rust toolchain (stable) + wasm32 target"
# A transitive dependency (slotmap-careful) requires edition 2024 (Rust >= 1.85).
rustup toolchain install stable --profile minimal
rustup default stable
rustup target add wasm32-unknown-unknown
rustc --version

echo "==> [4/6] Sibling darkfi checkout at pinned rev"
# Cargo path deps in Cargo.toml reference ../darkfi. With this repo at /workspace,
# that resolves to /darkfi. Create it (root-owned parent) and pin the exact commit.
DARKFI_DIR="${DARKFI_DIR:-$(cd "$ROOT/.." && pwd)/darkfi}"
DARKFI_GIT_URL="${DARKFI_GIT_URL:-https://github.com/darkrenaissance/darkfi.git}"
DARKFI_REF="$(tr -d '[:space:]' < "$ROOT/scripts/darkfi.rev")"
echo "    darkfi dir: $DARKFI_DIR"
echo "    darkfi ref: $DARKFI_REF"

if [ ! -d "$DARKFI_DIR/.git" ]; then
  parent="$(dirname "$DARKFI_DIR")"
  if [ ! -w "$parent" ]; then
    sudo mkdir -p "$DARKFI_DIR"
    sudo chown -R "$(id -u):$(id -g)" "$DARKFI_DIR"
  else
    mkdir -p "$DARKFI_DIR"
  fi
  git clone "$DARKFI_GIT_URL" "$DARKFI_DIR"
fi

git -C "$DARKFI_DIR" config remote.origin.url "$DARKFI_GIT_URL"
if ! git -C "$DARKFI_DIR" cat-file -e "${DARKFI_REF}^{commit}" 2>/dev/null; then
  # The pinned commit may not be reachable from a default clone; fetch it directly.
  git -C "$DARKFI_DIR" fetch --depth 1 origin "$DARKFI_REF"
fi
git -C "$DARKFI_DIR" checkout --detach "$DARKFI_REF"
echo "    darkfi @ $(git -C "$DARKFI_DIR" rev-parse --short HEAD)"

echo "==> [5/6] Build darkfi contract wasm blobs (needed by test harness)"
make -C "$DARKFI_DIR" contracts

echo "==> [6/6] Build darkfi-lightwalletd (release) + test binaries"
cd "$ROOT"
cargo build --release
cargo test --no-run

echo "==> install.sh complete"
