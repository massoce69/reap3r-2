#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# MassVision Agent – macOS Installation Script
# Run as root (sudo)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run this script as root: sudo $0 ..."
    exit 1
fi

# ── Parameters ────────────────────────────────────────────────
SERVER_URL="${1:-}"
ENROLLMENT_TOKEN="${2:-}"

if [ -z "$SERVER_URL" ] || [ -z "$ENROLLMENT_TOKEN" ]; then
    echo "Usage: sudo $0 <server_url> <enrollment_token>"
    exit 1
fi

INSTALL_DIR="/usr/local/bin"
DATA_DIR="/Library/Application Support/MassVision"
LOG_DIR="/Library/Logs/MassVision"
CONFIG_DIR="/etc/massvision"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== MassVision Agent Installer (macOS) ==="

# 1) Directories
echo "[1/6] Creating directories..."
mkdir -p "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR" \
         "$DATA_DIR/staging" "$DATA_DIR/rollback" \
         "$DATA_DIR/modules" "$DATA_DIR/sandbox"

# 2) Binary
echo "[2/6] Installing binary..."
BINARY="$SCRIPT_DIR/../massvision-agent"
if [ ! -f "$BINARY" ]; then
    BINARY="$SCRIPT_DIR/../target/release/massvision-agent"
fi
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found. Build: cargo build --release"
    exit 1
fi
cp "$BINARY" "$INSTALL_DIR/massvision-agent"
chmod 755 "$INSTALL_DIR/massvision-agent"

# 3) Config
echo "[3/6] Installing config..."
CONFIG_SRC="$SCRIPT_DIR/../config.toml"
if [ -f "$CONFIG_SRC" ]; then
    sed -e "s|https://massvision.example.com|${SERVER_URL}|g" \
        -e "s|wss://massvision.example.com/ws/agents|${SERVER_URL/https/wss}/ws/agents|g" \
        "$CONFIG_SRC" > "$CONFIG_DIR/config.toml"
fi

# 4) Enroll
echo "[4/6] Enrolling agent..."
"$INSTALL_DIR/massvision-agent" enroll --token "$ENROLLMENT_TOKEN" --server "$SERVER_URL"

# 5) Launchd plist
echo "[5/6] Installing launchd service..."
PLIST="/Library/LaunchDaemons/com.massvision.agent.plist"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.massvision.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/massvision-agent</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/MassVision/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/MassVision/agent-stderr.log</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
EOF
chmod 644 "$PLIST"

# 6) Start
echo "[6/6] Starting service..."
launchctl load -w "$PLIST"

sleep 2
if launchctl list | grep -q com.massvision.agent; then
    echo ""
    echo "=== Installation Complete ==="
    echo "Binary  : $INSTALL_DIR/massvision-agent"
    echo "Data    : $DATA_DIR"
    echo "Logs    : $LOG_DIR"
    echo "Config  : $CONFIG_DIR/config.toml"
else
    echo "WARNING: Service may not be running."
    echo "Check: launchctl list | grep massvision"
fi
