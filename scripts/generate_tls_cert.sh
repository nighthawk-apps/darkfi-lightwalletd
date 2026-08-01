#!/usr/bin/env bash
# =============================================================================
# generate_tls_cert.sh — TLS for darkfi-lightwalletd + client pin export
#
# Modes:
#   self-signed   Dev / private deploy (openssl)
#   letsencrypt   Production (certbot standalone or webroot)
#   pin           Print leaf DER SHA-256 pin from an existing PEM
#   copy-renewed  Certbot deploy-hook helper
#
# Client pin format (all Nighthawk clients):
#   LIGHTWALLET_TLS_PIN_SHA256 = 64 lowercase hex chars
#   = SHA-256( leaf certificate DER )   [NOT SPKI, NOT the public key]
#
# Usage:
#   ./scripts/generate_tls_cert.sh self-signed [--domain lw.local] [--days 825]
#   ./scripts/generate_tls_cert.sh letsencrypt --domain lw.example.com --email ops@example.com
#   ./scripts/generate_tls_cert.sh letsencrypt --domain lw.example.com --email ops@example.com \
#       --webroot /var/www/html
#   ./scripts/generate_tls_cert.sh pin --cert ./certs/server.crt
#   ./scripts/generate_tls_cert.sh pin --host lw.example.com:9067
#
# After generating certs, wire lightwalletd.toml:
#   grpc_listen = "0.0.0.0:9067"
#   tls_cert_path = "/path/to/certs/server.crt"
#   tls_key_path  = "/path/to/certs/server.key"
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
DAYS=825
DOMAIN="localhost"
EMAIL=""
KEY_SIZE=4096
WEBROOT=""
CERT_PATH=""
HOST=""
CERTBOT_NAME="lightwalletd"

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \?//'
    exit 1
}

need_openssl() {
    command -v openssl >/dev/null 2>&1 || {
        echo "ERROR: openssl is required" >&2
        exit 1
    }
}

# Leaf DER SHA-256 → 64 hex (no "SHA256(stdin)=" prefix noise)
leaf_pin_from_pem() {
    local pem="$1"
    openssl x509 -in "${pem}" -outform DER 2>/dev/null \
        | openssl dgst -sha256 -hex \
        | awk '{print $NF}' \
        | tr 'A-F' 'a-f'
}

leaf_pin_from_host() {
    local hostport="$1"
    local sni="${hostport%%:*}"
    echo | openssl s_client -connect "${hostport}" -servername "${sni}" 2>/dev/null \
        | openssl x509 -outform DER 2>/dev/null \
        | openssl dgst -sha256 -hex \
        | awk '{print $NF}' \
        | tr 'A-F' 'a-f'
}

write_pin_artifacts() {
    local pem="$1"
    local pin
    pin="$(leaf_pin_from_pem "${pem}")"
    if [[ ! "${pin}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: failed to compute leaf DER pin from ${pem}" >&2
        exit 1
    fi
    mkdir -p "${CERT_DIR}"
    printf '%s\n' "${pin}" > "${CERT_DIR}/LIGHTWALLET_TLS_PIN_SHA256.txt"
    cat > "${CERT_DIR}/client-pins.env" <<EOF
# Paste into client builds / desktop prefs (64 hex, leaf DER SHA-256)
LIGHTWALLET_TLS_PIN_SHA256=${pin}
EOF
    cat > "${CERT_DIR}/lightwalletd-tls.snippet.toml" <<EOF
# Merge into lightwalletd.toml (paths absolute preferred on the Mac Studio host)
grpc_listen = "0.0.0.0:9067"
tls_cert_path = "${CERT_DIR}/server.crt"
tls_key_path = "${CERT_DIR}/server.key"
EOF
    echo ""
    echo "=== Client TLS pin (leaf DER SHA-256) ==="
    echo "  LIGHTWALLET_TLS_PIN_SHA256=${pin}"
    echo "  wrote ${CERT_DIR}/LIGHTWALLET_TLS_PIN_SHA256.txt"
    echo "  wrote ${CERT_DIR}/client-pins.env"
    echo ""
    echo "Android:"
    echo "  ./gradlew :app:assembleDarkfimainnetRelease -PLIGHTWALLET_TLS_PIN_SHA256=${pin}"
    echo "iOS xcconfig / build setting:"
    echo "  LIGHTWALLET_TLS_PIN_SHA256 = ${pin}"
    echo "Desktop Settings → LWD TLS pin (or prefs.json lightwalletTlsPinSha256)"
    echo "Moonshine: set server_url=https://… and tls pin in client config if required"
}

print_pin_mode() {
    need_openssl
    local pin=""
    if [[ -n "${CERT_PATH}" ]]; then
        pin="$(leaf_pin_from_pem "${CERT_PATH}")"
        echo "Cert: ${CERT_PATH}"
    elif [[ -n "${HOST}" ]]; then
        pin="$(leaf_pin_from_host "${HOST}")"
        echo "Host: ${HOST}"
    elif [[ -f "${CERT_DIR}/server.crt" ]]; then
        pin="$(leaf_pin_from_pem "${CERT_DIR}/server.crt")"
        echo "Cert: ${CERT_DIR}/server.crt"
    else
        echo "ERROR: pass --cert PATH, --host host:port, or generate certs first" >&2
        exit 1
    fi
    if [[ ! "${pin}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: could not derive pin" >&2
        exit 1
    fi
    echo "LIGHTWALLET_TLS_PIN_SHA256=${pin}"
}

generate_self_signed() {
    need_openssl
    echo "=== Generating self-signed TLS certificate ==="
    echo "  Domain:   ${DOMAIN}"
    echo "  Key size: ${KEY_SIZE}"
    echo "  Days:     ${DAYS}"
    echo "  Output:   ${CERT_DIR}/"
    echo ""

    mkdir -p "${CERT_DIR}"
    umask 077

    openssl genrsa -out "${CERT_DIR}/server.key" "${KEY_SIZE}" 2>/dev/null
    openssl req -new -x509 \
        -key "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.crt" \
        -days "${DAYS}" \
        -subj "/C=XX/ST=Anon/L=Sovereign/O=Nighthawk/OU=Lightwalletd/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1,IP:::1" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        2>/dev/null

    chmod 600 "${CERT_DIR}/server.key"
    chmod 644 "${CERT_DIR}/server.crt"

    echo "✓ ${CERT_DIR}/server.crt"
    echo "✓ ${CERT_DIR}/server.key"
    echo ""
    openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -dates -ext subjectAltName 2>/dev/null || true
    write_pin_artifacts "${CERT_DIR}/server.crt"
    echo ""
    echo "=== lightwalletd.toml snippet ==="
    cat "${CERT_DIR}/lightwalletd-tls.snippet.toml"
    echo ""
    echo "⚠️  Self-signed: clients MUST set the pin above (fail-closed without it on remote HTTPS)."
    echo "   For public DNS hosts prefer: $0 letsencrypt --domain ${DOMAIN} --email you@example.com"
}

generate_letsencrypt() {
    if [[ -z "${EMAIL}" ]]; then
        echo "ERROR: --email is required for letsencrypt" >&2
        usage
    fi
    if [[ "${DOMAIN}" == "localhost" ]]; then
        echo "ERROR: Let's Encrypt needs a public DNS domain (--domain)" >&2
        exit 1
    fi
    if ! command -v certbot >/dev/null 2>&1; then
        echo "ERROR: certbot not installed" >&2
        echo "  macOS:  brew install certbot" >&2
        echo "  Debian: sudo apt install certbot" >&2
        exit 1
    fi

    echo "=== Obtaining Let's Encrypt certificate ==="
    echo "  Domain: ${DOMAIN}"
    echo "  Email:  ${EMAIL}"
    echo ""

    local -a cb=(
        certbot certonly
        --non-interactive --agree-tos
        --email "${EMAIL}"
        --domain "${DOMAIN}"
        --cert-name "${CERTBOT_NAME}"
    )

    if [[ -n "${WEBROOT}" ]]; then
        echo "  Challenge: webroot (${WEBROOT})"
        cb+=(--webroot -w "${WEBROOT}")
    else
        echo "  Challenge: standalone (needs free TCP :80)"
        cb+=(--standalone)
    fi

    sudo "${cb[@]}"

    local le_dir="/etc/letsencrypt/live/${CERTBOT_NAME}"
    if [[ ! -d "${le_dir}" ]]; then
        # certbot may name by domain
        le_dir="/etc/letsencrypt/live/${DOMAIN}"
    fi
    if [[ ! -f "${le_dir}/fullchain.pem" ]]; then
        echo "ERROR: certs not found under /etc/letsencrypt/live/{${CERTBOT_NAME},${DOMAIN}}" >&2
        exit 1
    fi

    mkdir -p "${CERT_DIR}"
    sudo cp "${le_dir}/fullchain.pem" "${CERT_DIR}/server.crt"
    sudo cp "${le_dir}/privkey.pem" "${CERT_DIR}/server.key"
    sudo chown "$(id -u):$(id -g)" "${CERT_DIR}/server.crt" "${CERT_DIR}/server.key"
    chmod 600 "${CERT_DIR}/server.key"
    chmod 644 "${CERT_DIR}/server.crt"

    # Prefer leaf-only for pin computation (first cert in fullchain)
    openssl x509 -in "${CERT_DIR}/server.crt" -out "${CERT_DIR}/leaf.crt"
    echo "✓ Copied LE certs → ${CERT_DIR}/"
    write_pin_artifacts "${CERT_DIR}/leaf.crt"

    echo ""
    echo "=== Renew ==="
    echo "  sudo certbot renew --deploy-hook '${SCRIPT_DIR}/generate_tls_cert.sh copy-renewed'"
    echo "  After renew: re-distribute pin ONLY if the leaf cert changed (rare with same key)."
}

copy_renewed() {
    local le_dir="/etc/letsencrypt/live/${CERTBOT_NAME}"
    [[ -d "${le_dir}" ]] || le_dir="/etc/letsencrypt/live/${DOMAIN}"
    if [[ ! -f "${le_dir}/fullchain.pem" ]]; then
        echo "ERROR: renewed certs not found" >&2
        exit 1
    fi
    mkdir -p "${CERT_DIR}"
    sudo cp "${le_dir}/fullchain.pem" "${CERT_DIR}/server.crt"
    sudo cp "${le_dir}/privkey.pem" "${CERT_DIR}/server.key"
    sudo chown "$(id -u):$(id -g)" "${CERT_DIR}/server.crt" "${CERT_DIR}/server.key"
    chmod 600 "${CERT_DIR}/server.key"
    chmod 644 "${CERT_DIR}/server.crt"
    openssl x509 -in "${CERT_DIR}/server.crt" -out "${CERT_DIR}/leaf.crt"
    write_pin_artifacts "${CERT_DIR}/leaf.crt"
    echo "✓ Renewed certs copied; restart lightwalletd to load new chain"
}

# =============================================================================
if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        --output) CERT_DIR="$2"; shift 2 ;;
        --key-size) KEY_SIZE="$2"; shift 2 ;;
        --webroot) WEBROOT="$2"; shift 2 ;;
        --cert) CERT_PATH="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --cert-name) CERTBOT_NAME="$2"; shift 2 ;;
        -h|--help) usage ;;
        *)
            echo "Unknown option: $1" >&2
            usage ;;
    esac
done

case "${MODE}" in
    self-signed) generate_self_signed ;;
    letsencrypt) generate_letsencrypt ;;
    pin) print_pin_mode ;;
    copy-renewed) copy_renewed ;;
    *)
        echo "Unknown mode: ${MODE}" >&2
        usage ;;
esac
