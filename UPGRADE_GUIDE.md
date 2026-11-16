# TGVPANEL Upgrade Guide

TGVPANEL uses an ordered, additive SQLite migration system. Upgrades apply
pending migrations automatically, with an automatic database backup before any
migration runs. This guide covers upgrading an existing installation, the
migration model, rollback, and importing legacy HVM data.

## Before you upgrade

1. **Back up the database.** Migrations run inside a transaction and an automatic
   pre-migration backup is created (`pre_migration_v<N>`), but take an explicit
   backup of the SQLite file (and the `.tgvpanel-secret` vault) before upgrading
   in production.
2. **Stop the panel** (and node agents) if upgrading a multi-node deployment, to
   avoid concurrent writes during the migration.
3. **Note the credential key.** The vault's `credentialKeyHex` decrypts
   encrypted local LXC backups. Preserve the vault; losing the key makes
   encrypted backups unrecoverable.

## Applying an upgrade

### Via the update script

```bash
sudo bash scripts/update.sh
```

`scripts/update.sh` pulls the latest code, reinstalls dependencies, rebuilds the
TypeScript services, and restarts the services. The panel applies any pending
migrations on startup.

### Manual upgrade

```bash
git pull
npm ci
npm run build
npm run migrate     # applies pending migrations (idempotent; safe to re-run)
npm start
```

`npm run migrate` (`lib/db/cli-migrate.js`) runs `runMigrations()`, which:

- creates/verifies the `schema_migrations` table,
- computes pending migrations (those not yet recorded),
- creates an automatic `pre_migration_v<N>` database backup,
- applies each migration in a transaction and records it in `schema_migrations`.

Migrations are **additive and ordered**; re-running `migrate` is safe and only
applies what is pending.

## Migration model

Migrations live in `src/db/migrations.ts` as an ordered array
(`version`, `name`, `up`). Current schema version is **v026**. Each migration
uses `CREATE TABLE IF NOT EXISTS` / `ensureColumn(...)` so it is safe against
existing databases. Summary of the schema evolution:

| Version | Name | Purpose |
|---|---|---|
| v001–v005 | core/unified tables | HKVM core tables, unified virtualization/node tables, network/backup/monitoring/security tables, default seeding, service-column unification. |
| v006–v009 | nesting, branding, FKs | LXC/KVM nesting, rebrand to TGVPANEL, cascade VM child FKs. |
| v010–v012 | snapshots, multinode, PVE | VM snapshot columns, multi-node pairing, Proxmox LXC images/logos. |
| v013–v016 | descriptions, v4, schedules | Proxmox descriptions, v4 version defaults, backup/snapshot schedule + retention metadata. |
| v017–v018 | reseller | Reseller HMAC API keys + audit; reseller customer directory. |
| v019–v022 | tasks, devices, VNC, locks | Instance task history + operation locks; KVM offline device config; KVM local VNC console; non-suspending service lock. |
| v023–v024 | backup DR | Backup encryption-at-rest; backup destination (cross-node) copies. |
| v025 | snapshot accounting | KVM snapshot `allocated_gb` column (Phase 13). |
| v026 | webhook status | `webhooks.last_error` column for retry delivery diagnostics (Phase 22). |

## Upgrade checklist

- [ ] Back up the SQLite database and the `.tgvpanel-secret` vault.
- [ ] Stop the panel (and remote node agents if upgrading a cluster).
- [ ] Pull the latest code and run `npm ci && npm run build`.
- [ ] Run `npm run migrate` (or start the panel) and confirm no migration errors.
- [ ] Confirm the schema version in `schema_migrations` matches the expected latest.
- [ ] Restart services; verify `/api/v1/health` and node health.
- [ ] Run `npm test` against a temporary database to confirm the acceptance suite passes.
- [ ] Verify backups still decrypt (credential key intact) and snapshots/disks read correctly.

See [`docs/MIGRATION_CHECKLIST.md`](docs/MIGRATION_CHECKLIST.md) for an
operational migration runbook and
[`docs/POSTGRESQL_MIGRATION.md`](docs/POSTGRESQL_MIGRATION.md) for moving the
database to PostgreSQL.

## Rollback

- **Code rollback:** revert to the previous commit/tag and restart. Because
  migrations are additive, a newer database is generally readable by an older
  panel, but **do not downgrade across a migration that changed semantics**
  without restoring a pre-upgrade database backup.
- **Database rollback:** restore the `pre_migration_v<N>` backup (or your explicit
  backup) taken before the upgrade. This is the supported path if a migration
  must be undone.
- Migrations are intentionally additive; there is no automatic downgrade script.
  Always keep a pre-upgrade backup.

## Importing legacy HVM data

TGVPANEL can import a legacy HVM (V9) SQLite database:

```bash
npm run import:hvm -- <path-to-hvm.db>
```

Before committing an import, run a **dry-run/preflight** (Phase 11) to validate
required tables, row counts, password-hash formats, and username/email
collisions without writing:

- API: `POST /api/v1/database/import-hvm/dry-run` (admin)
- CLI: follow the importer's dry-run option (see `src/db/hvm-importer.ts`).

The real import creates a pre-import backup and upgrades Werkzeug `pbkdf2`
password hashes transparently. See [`docs/MIGRATION_CHECKLIST.md`](docs/MIGRATION_CHECKLIST.md).

## Compatibility notes

- The reseller subsystem, API keys, and integrations are preserved across
  upgrades and are not rebuilt.
- Legacy `/api/vms/*` KVM routes remain available; prefer `/api/v1` for new
  integrations.
- Node agents should be upgraded alongside the controller; mismatched agent
  versions may reduce reported capabilities.
