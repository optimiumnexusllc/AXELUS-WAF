#!/usr/bin/env bash
# AXELUS — Automated Backup Script
# Backs up PostgreSQL database and configuration files.
# Usage: bash scripts/backup.sh [--dest /path/to/backups]
set -euo pipefail

BACKUP_DIR="${IRONWALL_BACKUP_DIR:-/data/axelus-backups}"
SAFELINE_DIR="${SAFELINE_DIR:-/data/axelus}"
RETAIN_DAYS="${BACKUP_RETAIN_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/axelus-$TIMESTAMP"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[backup]${NC} $*"; }
warn() { echo -e "${YELLOW}[backup]${NC} $*"; }

mkdir -p "$BACKUP_PATH"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --dest) BACKUP_PATH="$2/axelus-$TIMESTAMP"; mkdir -p "$BACKUP_PATH"; shift 2 ;;
        *) shift ;;
    esac
done

log "Starting AXELUS backup → $BACKUP_PATH"

# ── 1. PostgreSQL dump ────────────────────────────────────────────────────────
log "Dumping PostgreSQL..."
if docker ps --format '{{.Names}}' | grep -q axelus-pg; then
    docker exec axelus-pg pg_dump -U axelus -d axelus \
        --no-password --format=custom \
        > "$BACKUP_PATH/postgres.dump"
    log "PostgreSQL dump: $(du -sh "$BACKUP_PATH/postgres.dump" | cut -f1)"
else
    warn "axelus-pg container not running — skipping DB backup"
fi

# ── 2. Configuration backup ───────────────────────────────────────────────────
log "Backing up configuration..."
tar -czf "$BACKUP_PATH/config.tar.gz" \
    -C "$(dirname "$SAFELINE_DIR")" \
    "$(basename "$SAFELINE_DIR")/resources/mgt" \
    "$(basename "$SAFELINE_DIR")/resources/nginx" \
    2>/dev/null || warn "Some config files missing — partial backup"

# ── 3. .env backup ────────────────────────────────────────────────────────────
if [ -f "$(dirname "$0")/../.env" ]; then
    cp "$(dirname "$0")/../.env" "$BACKUP_PATH/env.backup"
    chmod 600 "$BACKUP_PATH/env.backup"
    log ".env file backed up"
fi

# ── 4. Create manifest ────────────────────────────────────────────────────────
cat > "$BACKUP_PATH/manifest.json" <<EOF
{
  "axelus_version": "1.0.0",
  "backup_timestamp": "$TIMESTAMP",
  "hostname": "$(hostname)",
  "files": $(ls "$BACKUP_PATH" | jq -R . | jq -s .)
}
EOF

# ── 5. Compress backup ────────────────────────────────────────────────────────
ARCHIVE="$BACKUP_DIR/axelus-$TIMESTAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" "axelus-$TIMESTAMP"
rm -rf "$BACKUP_PATH"
log "Backup archive: $ARCHIVE ($(du -sh "$ARCHIVE" | cut -f1))"

# ── 6. Prune old backups ──────────────────────────────────────────────────────
log "Pruning backups older than ${RETAIN_DAYS} days..."
find "$BACKUP_DIR" -name "axelus-*.tar.gz" -mtime "+$RETAIN_DAYS" -delete
REMAINING=$(find "$BACKUP_DIR" -name "axelus-*.tar.gz" | wc -l)
log "Backup complete. Total backups retained: $REMAINING"
