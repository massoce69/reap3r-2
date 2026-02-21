#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# MassVision Agent – Linux Installation Script
# Run as root
# ─────────────────────────────────────────────────────────────
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run this script as root (sudo)."
    exit 1
fi

# ── Parameters ────────────────────────────────────────────────
SERVER_URL="${1:-}"
ENROLLMENT_TOKEN="${2:-}"

if [ -z "$SERVER_URL" ] || [ -z "$ENROLLMENT_TOKEN" ]; then
    echo "Usage: $0 <server_url> <enrollment_token>"
    echo "  e.g. $0 https://massvision.example.com tk_abc123"
    exit 1
fi

INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/massvision"
LOG_DIR="/var/log/massvision"
CONFIG_DIR="/etc/massvision"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== MassVision Agent Installer (Linux) ==="

# 1) Create directories
echo "[1/6] Creating directories..."
mkdir -p "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR" \
         "$DATA_DIR/staging" "$DATA_DIR/rollback" \
         "$DATA_DIR/modules" "$DATA_DIR/sandbox"

# 2) Create service user
echo "[2/6] Creating service user..."
id -u massvision &>/dev/null || useradd -r -s /usr/sbin/nologin massvision
chown -R massvision:massvision "$DATA_DIR" "$LOG_DIR"

# 3) Install binary
echo "[3/6] Installing binary..."
BINARY="$SCRIPT_DIR/../massvision-agent"
if [ ! -f "$BINARY" ]; then
    BINARY="$SCRIPT_DIR/../target/release/massvision-agent"
fi
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Cannot find massvision-agent binary. Build first: cargo build --release"
    exit 1
fi
cp "$BINARY" "$INSTALL_DIR/massvision-agent"
chmod 755 "$INSTALL_DIR/massvision-agent"

# 4) Install config
echo "[4/6] Installing config..."
CONFIG_SRC="$SCRIPT_DIR/../config.toml"
if [ -f "$CONFIG_SRC" ]; then
    sed -e "s|https://massvision.example.com|${SERVER_URL}|g" \
        -e "s|wss://massvision.example.com/ws/agents|${SERVER_URL/https/wss}/ws/agents|g" \
        "$CONFIG_SRC" > "$CONFIG_DIR/config.toml"
else
    echo "WARNING: config.toml not found"
fi

# 5) Enroll
echo "[5/6] Enrolling agent..."
"$INSTALL_DIR/massvision-agent" enroll --token "$ENROLLMENT_TOKEN" --server "$SERVER_URL"

# 6) Install systemd service
echo "[6/6] Installing systemd service..."
cat > /etc/systemd/system/massvision-agent.service <<EOF
[Unit]
Description=MassVision Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/massvision-agent run
Restart=always
RestartSec=5
WatchdogSec=120
User=massvision
Group=massvision
ProtectSystem=strict
ReadWritePaths=/var/lib/massvision /var/log/massvision
PrivateTmp=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now massvision-agent

sleep 2
if systemctl is-active --quiet massvision-agent; then
    echo ""
    echo "=== Installation Complete ==="
    echo "Service Status : $(systemctl is-active massvision-agent)"
    echo "Binary         : $INSTALL_DIR/massvision-agent"
    echo "Data           : $DATA_DIR"
    echo "Logs           : $LOG_DIR"
    echo "Config         : $CONFIG_DIR/config.toml"
else
    echo "WARNING: Service may not be running."
    echo "Check: systemctl status massvision-agent"
fi
