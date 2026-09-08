#!/usr/bin/env bash
# Independent build entrypoint: ensure sibling `darkfi-nighthawk-testnet/` exists,
# then cargo build.
#
# Usage:
#   ./scripts/build.sh
#   ./scripts/build.sh --no-default-features
#   DARKFI_DIR=/path/to/darkfi-nighthawk-testnet ./scripts/build.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

"$SCRIPT_DIR/fetch-darkfi.sh"

cd "$ROOT"
echo "Building darkfi-lightwalletd (release)…"
cargo build --release "$@"
echo "Binary: $ROOT/target/release/darkfi-lightwalletd"
