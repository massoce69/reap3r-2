#!/usr/bin/env bash
# =============================================================================
# Reap3r Agent — Zabbix-triggered Linux installer
# Execute via Zabbix Script (scope: Manual host action)
#
# ZABBIX SETUP:
#   Scripts > Create Script
#     Name        : Reap3r Install
#     Type        : Script
#     Execute on  : Zabbix agent
#     Commands    : REAP3R_SERVER="{$REAP3R_SERVER}" \
#                   REAP3R_TOKEN="{$REAP3R_TOKEN}" \
#                   bash /tmp/reap3r-deploy.sh
#
#   Host macros:
#     {$REAP3R_SERVER} = wss://massvision.pro/ws/agent
#     {$REAP3R_TOKEN}  = <enrollment_token>
#     {$REAP3R_DLURL}  = https://massvision.pro/api/agent-binary/download?os=linux&arch=x86_64
#
# USAGE:
#   # Interactive:
#   REAP3R_SERVER="wss://massvision.pro/ws/agent" \
#   REAP3R_TOKEN="tok_abc123" \
#   bash deploy-zabbix-linux.sh
#
# SUPPORTS: Ubuntu 18.04+, Debian 9+, CentOS 7+, RHEL 7+, Rocky 8+
# =============================================================================
set -euo pipefail

# ── Colors (CI-safe) ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
if [ ! -t 1 ]; then RED=''; GREEN=''; YELLOW=''; NC=''; fi

# ── Constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/reap3r"
BIN_PATH="$INSTALL_DIR/reap3r-agent"
SERVICE_NAME="reap3r-agent"
CONFIG_DIR="/etc/xefi-agent-2"
LOG_FILE="$INSTALL_DIR/install.log"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

# ── Params from environment (set by Zabbix macro expansion) ──────────────────
SERVER_URL="${REAP3R_SERVER:-}"
TOKEN="${REAP3R_TOKEN:-}"
DOWNLOAD_URL="${REAP3R_DLURL:-}"
FORCE="${REAP3R_FORCE:-0}"
HEALTH_PORT="${REAP3R_HEALTH_PORT:-9090}"
HB_INTERVAL="${REAP3R_HEARTBEAT_INTERVAL:-30}"

# ── Helpers ───────────────────────────────────────────────────────────────────
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo -e "$(ts) [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$1${NC}"; }
warn()  { log "WARN " "${YELLOW}$1${NC}"; }
die()   { log "ERROR" "${RED}$1${NC}"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Must run as root (got uid=$(id -u))"

# ── Validate required params ──────────────────────────────────────────────────
[ -n "$SERVER_URL" ] || die "REAP3R_SERVER not set. Export REAP3R_SERVER=wss://..."
[ -n "$TOKEN"      ] || die "REAP3R_TOKEN not set."

# Derive HTTP base URL from WebSocket URL
HTTP_BASE="${SERVER_URL//wss:\/\//https://}"
HTTP_BASE="${HTTP_BASE//ws:\/\//http://}"
HTTP_BASE="${HTTP_BASE//\/ws\/agent/}"

# Default download URL
if [ -z "$DOWNLOAD_URL" ]; then
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  DL_ARCH="x86_64" ;;
        *)
            die "Unsupported architecture '$ARCH': only x86_64 Linux agent binaries are currently published."
            ;;
    esac
    DOWNLOAD_URL="$HTTP_BASE/api/agent-binary/download?os=linux&arch=$DL_ARCH"
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
chmod 750 "$INSTALL_DIR" "$CONFIG_DIR"

info "===== Reap3r Agent Zabbix Deploy ====="
info "Hostname  : $(hostname -f 2>/dev/null || hostname)"
info "Server    : $SERVER_URL"
info "DL URL    : $DOWNLOAD_URL"
info "Install   : $BIN_PATH"
info "Health    : port $HEALTH_PORT"

# ── Check if already installed and healthy (skip unless --force) ──────────────
if [ "$FORCE" = "0" ] && [ -x "$BIN_PATH" ] && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Service $SERVICE_NAME is already running."
    # Verify backend reachability
    HEALTH_URL="$HTTP_BASE/api/health"
    if curl -sf --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
        info "Backend reachable. Agent OK — nothing to do. Set REAP3R_FORCE=1 to reinstall."
        exit 0
    else
        warn "Service running but backend unreachable ($HEALTH_URL). Reinstalling..."
    fi
fi

# ── Stop existing service ─────────────────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Stopping existing service..."
    systemctl stop "$SERVICE_NAME" || true
    sleep 2
fi

# ── Download binary ───────────────────────────────────────────────────────────
TMP_BIN="$INSTALL_DIR/reap3r-agent-new"
info "Downloading binary from $DOWNLOAD_URL ..."

HTTP_CODE=200
if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=$(curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
        -H "User-Agent: Reap3r-Installer/1.0 Linux/$(uname -m)" \
        -w "%{http_code}" -o "$TMP_BIN" "$DOWNLOAD_URL")
elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=120 --tries=3 -O "$TMP_BIN" "$DOWNLOAD_URL"
else
    die "Neither curl nor wget found. Install one then retry."
fi

[ -s "$TMP_BIN" ] || die "Downloaded file is empty (HTTP $HTTP_CODE). Check REAP3R_DLURL."
SIZE=$(stat -c%s "$TMP_BIN" 2>/dev/null || stat -f%z "$TMP_BIN")
[ "$SIZE" -gt 100000 ] || die "Downloaded file too small (${SIZE} bytes) — likely an error page."
info "Downloaded: $SIZE bytes"

# ── Install binary ────────────────────────────────────────────────────────────
mv "$TMP_BIN" "$BIN_PATH"
chmod 755 "$BIN_PATH"
chown root:root "$BIN_PATH"
info "Binary installed: $BIN_PATH"

# ── One-shot enrollment ───────────────────────────────────────────────────────
info "Enrolling agent with server..."
"$BIN_PATH" --enroll --server "$SERVER_URL" --token "$TOKEN" || \
    die "Enrollment failed. Check token and server connectivity."
info "Enrollment successful"

# ── Create systemd service ────────────────────────────────────────────────────
info "Creating systemd unit $SYSTEMD_UNIT ..."
cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Reap3r Remote Management Agent
Documentation=https://massvision.pro
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$BIN_PATH --run --health-port $HEALTH_PORT --heartbeat-interval $HB_INTERVAL
Restart=always
RestartSec=10
StartLimitBurst=0
Environment=REAP3R_HEALTH_PORT=$HEALTH_PORT
Environment=REAP3R_HEARTBEAT_INTERVAL=$HB_INTERVAL

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR $CONFIG_DIR
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

# Ensure we can reach the network
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# ── Enable + start ────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "SUCCESS: Service $SERVICE_NAME is RUNNING"
else
    STATUS=$(systemctl is-active "$SERVICE_NAME" || true)
    warn "Service status: $STATUS"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
    die "Service failed to start"
fi

# ── Optional: verify health endpoint ─────────────────────────────────────────
if [ "$HEALTH_PORT" != "0" ]; then
    sleep 2
    HEALTH_RESP=$(curl -sf --max-time 3 "http://127.0.0.1:$HEALTH_PORT/health" 2>/dev/null || true)
    if [ -n "$HEALTH_RESP" ]; then
        info "Health check: $HEALTH_RESP"
    else
        warn "Health endpoint not responding yet (port $HEALTH_PORT). Normal during first start."
    fi
fi

info "===== Deploy complete ====="
info "Version  : $("$BIN_PATH" --version 2>/dev/null | head -1 || echo 'unknown')"
info "Logs     : journalctl -u $SERVICE_NAME -f"
info "Status   : $BIN_PATH --status"
info "Health   : curl http://127.0.0.1:$HEALTH_PORT/health"
exit 0
