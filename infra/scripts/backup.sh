#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# MASSVISION Reap3r — Backup Script
# ─────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="${REAP3R_DIR:-/opt/massvision/reap3r}"
BACKUP_DIR="${REAP3R_BACKUP_DIR:-$INSTALL_DIR/backups}"
RETENTION_DAYS="${REAP3R_BACKUP_RETENTION:-30}"
LABEL=""
COMPOSE_FILE="docker-compose.prod.yml"

log()  { echo "[BACKUP] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --label) LABEL="$2"; shift 2 ;;
        --dir)   BACKUP_DIR="$2"; shift 2 ;;
        *) err "Unknown option: $1" ;;
    esac
done

cd "$INSTALL_DIR" || err "Install directory not found"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="${LABEL:-backup}_${TIMESTAMP}"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

mkdir -p "$BACKUP_PATH"

log "MASSVISION Reap3r — Backup starting"
log "Destination: $BACKUP_PATH"

# Step 1: Database dump
log "Step 1/3: Dumping PostgreSQL database..."
# shellcheck disable=SC1091
source "$INSTALL_DIR/.env" 2>/dev/null || true

docker compose -f "$COMPOSE_FILE" exec -T postgres \
    pg_dump -U "${DB_USER:-reap3r}" -Fc "${DB_NAME:-reap3r}" \
    > "$BACKUP_PATH/database.dump"

DB_SIZE=$(du -sh "$BACKUP_PATH/database.dump" | cut -f1)
log "Database dump: $DB_SIZE"

# Step 2: Config backup
log "Step 2/3: Backing up configuration..."
cp "$INSTALL_DIR/.env" "$BACKUP_PATH/.env"
cp -r "$INSTALL_DIR/infra" "$BACKUP_PATH/infra"

# Step 3: Compress
log "Step 3/3: Compressing backup..."
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_PATH"

FINAL_SIZE=$(du -sh "${BACKUP_NAME}.tar.gz" | cut -f1)
log "Backup compressed: $FINAL_SIZE"

# Cleanup old backups
log "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +"$RETENTION_DAYS" -delete

BACKUP_COUNT=$(find "$BACKUP_DIR" -name "*.tar.gz" | wc -l)
log "Backup complete! ($BACKUP_COUNT backups retained)"
log "File: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
