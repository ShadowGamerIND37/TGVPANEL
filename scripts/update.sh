#!/usr/bin/env bash
# ==============================================================================
# HKVM V3 — Safe Zero-Data-Loss Updater
# Automatically backs up data/hkvm.db via SQLite VACUUM INTO before migrating.
# ==============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

log() { printf "\033[1;34m[HKVM-UPDATE]\033[0m %s\n" "$*"; }
ok()  { printf "\033[1;32m[  OK  ]\033[0m %s\n" "$*"; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p data/backups

if [[ -f data/hkvm.db ]]; then
  BACKUP_FILE="data/backups/hkvm_pre_update_${STAMP}.db"
  log "Creating verified pre-update SQLite backup: $BACKUP_FILE"
  node -e "
    const sqlite3 = require('sqlite3');
    const db = new sqlite3.Database('data/hkvm.db');
    db.run(\"VACUUM INTO '${BACKUP_FILE}'\", (err) => {
      if (err) { console.error(err); process.exit(1); }
      db.close();
    });
  "
  ok "Backup saved to $BACKUP_FILE"
fi

if [[ -d .git && "${SKIP_GIT_PULL:-0}" != "1" ]]; then
  log "Fetching latest repository updates..."
  git pull --ff-only || log "Skipping git fast-forward (local working branch)."
fi

if [[ -d /usr/local/include/node ]]; then
  export npm_config_nodedir="/usr/local"
fi

log "Updating Node.js packages & rebuilding TypeScript..."
npm install
npm run build

log "Applying versioned database migrations..."
npm run migrate

if [[ $EUID -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet hkvm-panel.service && systemctl restart hkvm-panel.service && ok "Restarted hkvm-panel.service"
  systemctl is-active --quiet hkvm-node-agent.service && systemctl restart hkvm-node-agent.service && ok "Restarted hkvm-node-agent.service"
fi

ok "HKVM V3 update finished cleanly."
