#!/usr/bin/env bash
# Install latest darkfi-lightwalletd on a macOS host and (re)start launchd + verify ngrok.
# Run directly on the target host, or remotely with --remote (requires STUDIO_SSH_TARGET).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: deploy-studio-lwd.sh [--remote] [-h|--help]

Install darkfi-lightwalletd into INSTALL_BIN, write the launchd plist,
restart the service, and verify it is listening on LWD_PORT.

Options:
  --remote    Execute this script on STUDIO_SSH_TARGET over ssh
  -h, --help  Show this help and exit

Environment variables:
  STUDIO_SSH_TARGET  SSH destination (e.g. user@host); required for --remote
  STUDIO_REPO_DIR    Path to darkfi-lightwalletd checkout on target
                     (default: $REPO if set, else $HOME/darkfi-lightwalletd)
  LWD_NGROK_DOMAIN   Optional ngrok hostname mapped to 127.0.0.1:LWD_PORT
  LWD_PORT           Loopback gRPC port to verify (default: 9067)
  LWD_BIN_SRC        Explicit path to compiled darkfi-lightwalletd binary
  INSTALL_BIN        Destination binary path (default: $HOME/bin/darkfi-lightwalletd)
  CONFIG             lightwalletd TOML path (default: $HOME/.config/darkfi/lightwalletd.toml)
  LOG_DIR            launchd log dir (default: $HOME/Library/Logs/darkfi)
  PLIST_ID           launchd label (default: org.darkfi.lightwalletd)

Example (remote):
  STUDIO_SSH_TARGET=user@mac-host STUDIO_REPO_DIR='$HOME/GitHub/darkfi-lightwalletd' \
    LWD_NGROK_DOMAIN=example.ngrok-free.dev ./scripts/deploy-studio-lwd.sh --remote
EOF
}

REMOTE=0
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      usage
      exit 0
      ;;
    --remote)
      REMOTE=1
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

STUDIO_SSH_TARGET="${STUDIO_SSH_TARGET:-}"
STUDIO_REPO_DIR="${STUDIO_REPO_DIR:-${REPO:-$HOME/darkfi-lightwalletd}}"
LWD_NGROK_DOMAIN="${LWD_NGROK_DOMAIN:-}"
LWD_PORT="${LWD_PORT:-9067}"

if [[ "$REMOTE" == 1 ]]; then
  if [[ -z "$STUDIO_SSH_TARGET" ]]; then
    echo "Error: STUDIO_SSH_TARGET must be set when using --remote (e.g. user@host)" >&2
    usage >&2
    exit 1
  fi
  REMOTE_ENV=$(printf 'STUDIO_REPO_DIR=%q LWD_NGROK_DOMAIN=%q LWD_PORT=%q LWD_BIN_SRC=%q INSTALL_BIN=%q CONFIG=%q LOG_DIR=%q PLIST_ID=%q' \
    "$STUDIO_REPO_DIR" \
    "$LWD_NGROK_DOMAIN" \
    "$LWD_PORT" \
    "${LWD_BIN_SRC:-}" \
    "${INSTALL_BIN:-}" \
    "${CONFIG:-}" \
    "${LOG_DIR:-}" \
    "${PLIST_ID:-org.darkfi.lightwalletd}")
  exec ssh "$STUDIO_SSH_TARGET" "env $REMOTE_ENV bash -s" < "${BASH_SOURCE[0]}"
fi

LWD_BIN_SRC="${LWD_BIN_SRC:-}"
REPO="$STUDIO_REPO_DIR"
INSTALL_BIN="${INSTALL_BIN:-$HOME/bin/darkfi-lightwalletd}"
PLIST_ID="${PLIST_ID:-org.darkfi.lightwalletd}"
PLIST="$HOME/Library/LaunchAgents/${PLIST_ID}.plist"
CONFIG="${CONFIG:-$HOME/.config/darkfi/lightwalletd.toml}"
LOG_DIR="${LOG_DIR:-$HOME/Library/Logs/darkfi}"

mkdir -p "$(dirname "$INSTALL_BIN")" "$LOG_DIR" "$(dirname "$CONFIG")"

if [[ -z "$LWD_BIN_SRC" ]]; then
  if [[ -x "$REPO/target/release/darkfi-lightwalletd" ]]; then
    LWD_BIN_SRC="$REPO/target/release/darkfi-lightwalletd"
  elif [[ -x "$REPO/darkfi-lightwalletd" ]]; then
    LWD_BIN_SRC="$REPO/darkfi-lightwalletd"
  else
    echo "missing LWD binary; set LWD_BIN_SRC=... or build in $REPO (override via STUDIO_REPO_DIR)" >&2
    exit 1
  fi
fi

echo "Installing $(basename "$LWD_BIN_SRC") -> $INSTALL_BIN"
cp -f "$LWD_BIN_SRC" "$INSTALL_BIN"
chmod 755 "$INSTALL_BIN"
"$INSTALL_BIN" --version || true

if [[ ! -f "$CONFIG" ]]; then
  echo "missing config $CONFIG" >&2
  exit 1
fi

# Ensure loopback gRPC for ngrok TLS termination in front.
if ! grep -q 'grpc_listen' "$CONFIG"; then
  echo "config missing grpc_listen" >&2
  exit 1
fi

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_ID}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_BIN}</string>
    <string>--config</string>
    <string>${CONFIG}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/lightwalletd.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/lightwalletd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
  </dict>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)/${PLIST_ID}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl enable "gui/$(id -u)/${PLIST_ID}" 2>/dev/null || true
launchctl kickstart -k "gui/$(id -u)/${PLIST_ID}"

sleep 2
if ! lsof -nP -iTCP:"$LWD_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "lightwalletd not listening on :$LWD_PORT" >&2
  tail -50 "$LOG_DIR/lightwalletd.err.log" 2>/dev/null || true
  exit 1
fi

echo "lightwalletd listening on :$LWD_PORT"
if [[ -n "$LWD_NGROK_DOMAIN" ]]; then
  echo "expected ngrok tunnel: $LWD_NGROK_DOMAIN -> 127.0.0.1:$LWD_PORT"
fi
if command -v ngrok >/dev/null 2>&1; then
  ngrok api endpoints list 2>/dev/null | head -40 || true
fi
if launchctl list | grep -q ngrok || pgrep -lf ngrok >/dev/null 2>&1; then
  echo "ngrok process present"
else
  echo "warning: ngrok not detected — start the ngrok tunnel to :$LWD_PORT" >&2
fi

echo "OK: deploy complete"
