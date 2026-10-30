# HKVM V3 — Optional PostgreSQL Migration Path

HKVM V3 preserves `data/hkvm.db` (SQLite 3 in WAL mode) as the zero-configuration primary database for full backward compatibility with HKVM V2 deployments. For multi-region high-concurrency controller clusters (> 250 active nodes or > 5,000 concurrent API requests/min), HKVM's unified schema is designed to map 1:1 to PostgreSQL 15+.

## 1. Schema Compatibility Design

All tables in `src/db/migrations.ts` follow strict ANSI-compatible conventions so automated translation requires no application logic rewrite:
- **Primary keys**: `INTEGER PRIMARY KEY AUTOINCREMENT` maps directly to `BIGSERIAL PRIMARY KEY`.
- **Timestamps**: Stored in ISO-8601 UTC (`TEXT` / `TIMESTAMPTZ DEFAULT NOW()`).
- **Structured columns**: Stored as validated JSON strings (`TEXT` in SQLite -> `JSONB` in PostgreSQL: `shared_with`, `metadata`, `suspension_history`, `permissions`, `events`, `details`).
- **Secrets**: `*_enc` columns hold `enc:v1:<iv>:<tag>:<ciphertext>` strings encrypted by `src/security/crypto-vault.ts` using AES-256-GCM; PostgreSQL stores the exact same ciphertext without needing `pgcrypto`.
- **Foreign keys**: `ON DELETE CASCADE` / `ON DELETE SET NULL` constraints are already declared across `nodes`, `lxc_instances`, `vms`, `port_forwards`, `container_snapshots`, `container_backups`, and `notifications`.

## 2. Step-by-Step Migration Procedure

1. **Quiesce HKVM Controller & Create Verified SQLite Snapshot**
   ```bash
   systemctl stop hkvm
   npm run migrate
   sqlite3 data/hkvm.db "PRAGMA wal_checkpoint(TRUNCATE);"
   cp data/hkvm.db data/backups/hkvm_pre_postgres.db
   ```

2. **Provision PostgreSQL 15+ Database**
   ```sql
   CREATE ROLE hkvm WITH LOGIN PASSWORD '<strong-secret>';
   CREATE DATABASE hkvm OWNER hkvm ENCODING 'UTF8';
   ```

3. **Migrate Schema & Data with `pgloader`**
   Create `hkvm.load`:
   ```lisp
   LOAD DATABASE
        FROM sqlite:///opt/hkvm/data/backups/hkvm_pre_postgres.db
        INTO postgresql://hkvm:<strong-secret>@127.0.0.1:5432/hkvm
   WITH include drop, create tables, create indexes, reset sequences
   CAST type text to jsonb drop typemod using empty-string-to-null
        when (or (and (string= "lxc_instances" table-name) (member column-name '("shared_with" "metadata" "suspension_history") :test #'string=))
                 (and (string= "activity_logs" table-name) (string= "details" column-name)));
   ```
   Execute:
   ```bash
   pgloader hkvm.load
   ```

4. **Adapter Cutover (`UnifiedDatabase` Driver)**
   `src/db/database.ts` centralizes all persistence through four async methods (`run`, `get`, `all`, `exec`, `transaction`). Implementing a `PostgresUnifiedDatabase` driver requires only translating `?` positional placeholders to `$1..$n` (`sql.replace(/\?/g, () => '$' + (++i))`) and returning `RETURNING id` for `run().lastID`.

5. **Preserve `.hkvm-secret`**
   Copy `.hkvm-secret` (or `HKVM_ENCRYPTION_KEY` in `.env`) unchanged so all AES-256-GCM encrypted node credentials, LXC/KVM passwords, and TOTP secrets decrypt seamlessly after cutover.
