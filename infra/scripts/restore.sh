#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# MASSVISION Reap3r — Restore Script
# ─────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="${REAP3R_DIR:-/opt/massvision/reap3r}"
COMPOSE_FILE="docker-compose.prod.yml"

log()  { echo "[RESTORE] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    echo ""
    echo "Available backups:"
    ls -lh "$INSTALL_DIR/backups/"*.tar.gz 2>/dev/null || echo "  (none found)"
    exit 1
fi

BACKUP_FILE="$1"
[[ -f "$BACKUP_FILE" ]] || err "Backup file not found: $BACKUP_FILE"

cd "$INSTALL_DIR" || err "Install directory not found"

RESTORE_DIR=$(mktemp -d)
log "MASSVISION Reap3r — Restore starting"
log "Backup: $BACKUP_FILE"
log "Temp dir: $RESTORE_DIR"

# Step 1: Extract backup
log "Step 1/4: Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"
EXTRACTED_DIR=$(ls "$RESTORE_DIR")
RESTORE_PATH="$RESTORE_DIR/$EXTRACTED_DIR"

# Step 2: Stop services
log "Step 2/4: Stopping services..."
docker compose -f "$COMPOSE_FILE" stop backend frontend nginx

# Step 3: Restore database
log "Step 3/4: Restoring database..."
source "$INSTALL_DIR/.env" 2>/dev/null || true

cat "$RESTORE_PATH/database.dump" | docker compose -f "$COMPOSE_FILE" exec -T postgres \
    pg_restore -U "${DB_USER:-reap3r}" -d "${DB_NAME:-reap3r}" --clean --if-exists

# Step 4: Restore config
log "Step 4/4: Restoring configuration..."
if [[ -f "$RESTORE_PATH/.env" ]]; then
    cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.pre-restore.bak"
    cp "$RESTORE_PATH/.env" "$INSTALL_DIR/.env"
    log "Config restored (previous saved as .env.pre-restore.bak)"
fi

# Restart
log "Restarting services..."
docker compose -f "$COMPOSE_FILE" up -d

# Cleanup
rm -rf "$RESTORE_DIR"

log "Restore complete!"
log "Verify with: curl -s http://localhost:4000/ready | jq ."
