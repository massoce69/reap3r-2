#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# MASSVISION Reap3r — Upgrade Script
# ─────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="${REAP3R_DIR:-/opt/massvision/reap3r}"
COMPOSE_FILE="docker-compose.prod.yml"
BACKUP_SCRIPT="$INSTALL_DIR/infra/scripts/backup.sh"

log()  { echo "[UPGRADE] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

cd "$INSTALL_DIR" || err "Install directory not found: $INSTALL_DIR"

log "MASSVISION Reap3r — Upgrade starting..."

# Step 1: Create backup before upgrade
log "Step 1/5: Creating pre-upgrade backup..."
if [[ -x "$BACKUP_SCRIPT" ]]; then
    bash "$BACKUP_SCRIPT" --label "pre-upgrade-$(date +%Y%m%d_%H%M%S)"
else
    log "Skipping backup (script not found)"
fi

# Step 2: Pull latest code
log "Step 2/5: Pulling latest changes..."
if [[ -d ".git" ]]; then
    git fetch --all
    git pull origin main
else
    log "Not a git repo — ensure files are updated manually"
fi

# Step 3: Rebuild images
log "Step 3/5: Rebuilding Docker images..."
docker compose -f "$COMPOSE_FILE" build --no-cache

# Step 4: Apply database migrations (backend auto-migrates on start)
log "Step 4/5: Restarting services (migrations will auto-apply)..."
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

# Step 5: Health check
log "Step 5/5: Verifying deployment..."
sleep 10

HEALTH=$(curl -sf http://localhost:4000/health || echo '{"status":"error"}')
if echo "$HEALTH" | jq -e '.status == "ok"' &>/dev/null; then
    log "✓ Backend healthy"
else
    err "Backend health check failed: $HEALTH"
fi

READY=$(curl -sf http://localhost:4000/ready || echo '{"status":"error"}')
if echo "$READY" | jq -e '.status == "ok"' &>/dev/null; then
    log "✓ Backend ready (DB connected)"
else
    err "Backend readiness check failed: $READY"
fi

log "Upgrade complete!"
