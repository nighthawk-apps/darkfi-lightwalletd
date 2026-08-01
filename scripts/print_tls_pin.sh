#!/usr/bin/env bash
# Thin wrapper: print LIGHTWALLET_TLS_PIN_SHA256 for a PEM or live host.
# See generate_tls_cert.sh for full self-signed / Let's Encrypt provisioning.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "${SCRIPT_DIR}/generate_tls_cert.sh" pin "$@"
