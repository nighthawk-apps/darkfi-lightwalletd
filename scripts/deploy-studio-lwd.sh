#!/usr/bin/env bash
# Install latest darkfi-lightwalletd on Mac Studio and (re)start launchd + verify ngrok.
# Run ON the Studio as user `adi`, or via: ssh adi@mac-studio 'bash -s' < scripts/deploy-studio-lwd.sh
set -euo pipefail

LWD_BIN_SRC="${LWD_BIN_SRC:-}"
REPO="${REPO:-$HOME/GitHub/darkfi-lightwalletd}"
INSTALL_BIN="${INSTALL_BIN:-$HOME/bin/darkfi-lightwalletd}"
PLIST_ID="org.darkfi.lightwalletd"
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
    echo "missing LWD binary; set LWD_BIN_SRC=... or build in $REPO" >&2
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
if ! lsof -nP -iTCP:9067 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "lightwalletd not listening on :9067" >&2
  tail -50 "$LOG_DIR/lightwalletd.err.log" 2>/dev/null || true
  exit 1
fi

echo "lightwalletd listening on :9067"
# ngrok should already map epidermis-sandbox-marshland.ngrok-free.dev -> 127.0.0.1:9067
if command -v ngrok >/dev/null 2>&1; then
  ngrok api endpoints list 2>/dev/null | head -40 || true
fi
if launchctl list | grep -q ngrok || pgrep -lf ngrok >/dev/null 2>&1; then
  echo "ngrok process present"
else
  echo "warning: ngrok not detected — start the existing Studio ngrok tunnel to :9067" >&2
fi

echo "OK: deploy complete"
