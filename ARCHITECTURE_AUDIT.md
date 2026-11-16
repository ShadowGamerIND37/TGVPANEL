# TGVPANEL Architecture Audit

## Product and runtime

- **Repository/product:** `ShadowGamerIND37/TGVPANEL`; existing product, TGVPANEL branding. This change must preserve it and extend in place.
- **Process:** root `app.js` is the existing Express 4 / `http.Server` entry point, legacy KVM integration and static/EJS server. It initializes the TypeScript runtime compiled into `lib/`, attaches session/CSRF/auth middleware and mounts `/api/v1` and unified web routes. Do not replace the root runtime.
- **Application code:** `src/` is TypeScript and compiles to checked-in runtime `lib/` via `npm run build` (`tsconfig.json`). Frontend remains EJS plus browser JavaScript/CSS in `views/` and `public/`; do not rewrite it.
- **Persistence:** SQLite (`src/db/database.ts`, `src/db/migrations.ts`, `data/tgvpanel.db`) with ordered, checksummed migrations and pre-migration backup behavior. `docs/POSTGRESQL_MIGRATION.md` is a migration plan, not evidence of PostgreSQL runtime support. Keep production/user DBs untouched in tests; the suite clones the DB to temp storage.
- **Node agents:** `src/node-agent/` implements an independent Node HTTP agent, allowlisted command execution, container/console/snapshot/transfer facilities, signed communication and health. `src/services/nodes/NodeClient.ts` owns controller pairing, HTTPS/TLS pinning, remote requests and node lifecycle.

## Code ownership map

| Area | Current source of truth | Notes |
|---|---|---|
| HTTP entry/legacy compatibility | `app.js` | Large legacy KVM/runtime surface remains active. Changes crossing auth or user role behavior need compatibility review. |
| Unified APIs and web routes | `src/api/v1/router.ts`, `src/api/web-routes.ts` | Versioned APIs use runtime context and existing services; web pages render EJS. `lib/api/*` is generated from `src/`. |
| Authentication/security | `src/security/middleware.ts`, `src/security/crypto-vault.ts` | Session and bearer PAT auth; CSRF and role gates; AES-256-GCM secret vault; API key hashing; separate node-agent HMAC/replay authentication. Generic PATs are not reseller HMAC keys. |
| Data/migrations/import | `src/db/database.ts`, `src/db/migrations.ts`, `src/db/hvm-importer.ts` | SQLite wrapper; versioned migrations; importer preserves legacy data. `lib/db/*` generated. |
| Runtime construction | `src/context.ts` | Creates existing KVM/LXC adapters, instance/storage/network/backup/migration/monitoring/node services and in-process loops. |
| Virtualization | `src/services/virtualization/{VirtualizationAdapter,VirtualizationManager,InstanceManager,KVMAdapter,LXCAdapter}.ts` | Unified engine currently KVM + LXC. Adapter capability profile and owner/shared checks centralize behavior. |
| Host operations | `src/node-agent/{agent,authentication,command-runner,container-manager,container-console,snapshot-manager,transfer-manager,host-stats,dns-relay,shell-manager}.ts` | Host operations are native Node services and allowlisted commands; do not use arbitrary root shell input. |
| Storage/network | `src/services/storage/StorageManager.ts`, `src/services/network/NetworkManager.ts` | Pools/templates/ISO and IP/port/firewall records/configuration with node delegation. Supported backend scope is narrower than full roadmap. |
| Backup/migration | `src/services/backup/BackupSnapshotManager.ts`, `src/services/migration/MigrationManager.ts` | Real archives/snapshots, schedules, retention/checksum and offline LXC state machine. No live KVM migration. |
| Monitoring | `src/services/monitoring/MonitoringService.ts` | Real host/instance/node observations, historical metrics, alerts/notifications/webhooks; incomplete against all requested telemetry. |
| User/admin UI | `views/admin/*`, `views/users/*`, `views/partials/*`, `public/css/admin.css`, `public/js/tgvpanel-v3.js` | Existing EJS app. User dashboard uses unified sections; admin dashboard has a unified page with section controls. |
| Operations/deploy | `scripts/{install,update,fetch}.sh`, `menu.sh`, `.env.example`, `package.json` | Shell-based installation/update and Node scripts; changes require safe upgrade/migration behavior. |
| Verification/docs | `tests/run-all.js`, `README.md`, `docs/*` | Single broad integration suite includes real SQLite/Express and host-dependent LXC tests; historical `docs/PHASE1_SOURCE_AUDIT.md` is a legacy map and has stale feature claims. |

## Existing request/data flow

1. `app.js` parses JSON and retains raw request bytes, establishes the session, applies CSRF/security checks and sets a unified principal through compiled TypeScript middleware.
2. `/api/v1` routes use `HkvmRuntimeContext` and delegate to services; instance access checks use `InstanceManager.getAuthorizedInstance` and role/owner/shared state.
3. Adapters perform virtualization operations; remote compute operations pass through `NodeClient` to a Node Agent using signed requests/TLS checks. Agent commands use allowlists and path validation.
4. Service state is stored in the SQLite database through versioned migrations; timers currently run in-process, with limited domain-specific task state.
5. Existing EJS pages call same-origin JSON endpoints. The changes retain that model.

## Observed security and compatibility constraints

- `normalizeRole` originally recognized only admin/subadmin/operator/user/readonly; role additions must be explicit and avoid treating reseller as staff.
- `InstanceManager.isStaff` deliberately excludes normal users; resellers must remain non-staff and their API listing must filter to records they own, not shared instances or other tenants.
- Generic `api_keys` are SHA-256 hashed bearer tokens with coarse read/write/admin permissions. Do not retrofit HMAC storage in a way that invalidates existing keys.
- Session mutations require CSRF. Machine-signed reseller calls need a dedicated signature verification path before generic principal enforcement and must not weaken browser CSRF checks.
- HMAC secrets need verification material: store a hash and an encrypted copy under the existing AES-GCM vault, show raw values once, never put secrets in logs/admin views, and use durable unique nonce records to prevent replay across process restarts.
- Rate limits and IP allowlists must be keyed to individual reseller keys. Admin inspection must expose metadata only; disable/revoke must take effect immediately.
- Additive SQLite migrations and existing row preservation are mandatory. Do not change engine support claims or replace working operations with fakes.

## Architecture findings and consequences

- TGVPANEL is a KVM/LXC platform with optional multi-node agent communication, not a generic Virtualizor-compatible adapter framework yet.
- Migration v018 adds a reseller-owned CRM contact registry with strict owner filtering and direct deletion; it intentionally does not link contacts to TGVPANEL users or VPS records. There is still no customer/VPS ownership graph, reseller quota ledger, plans, invoices, verified payment integration or billing model. Current user-owned VPS records are not a substitute for reseller customer isolation.
- Implemented and verified in this audit branch: a reseller account role, isolated HMAC API key/secret lifecycle, signed owner-scoped paginated/filterable VPS listing and read/start/stop/restart, actual stats/resource telemetry, durable nonces, per-key permissions/IP/rates/logs, admin reseller account oversight/suspension with key disablement, reseller/admin key pages, and additive SQLite v017 and v018 migrations. `FEATURE_STATUS.md` and `docs/API_RESELLER.md` record exact boundaries and signing bytes.
- CRM customer CRUD is now implemented in v018, but it creates no customer login and confers no VPS access. Still not implemented: customer-VPS relation, resource quotas/allocation, plans, IP assignment guarantees, invoices/payment verification, or those APIs. Do not advertise these as available until their models/services/tests land.
- Controller timer loops cannot provide distributed job locking or cluster HA guarantees. Keep those gaps visible and do not claim safe failover.
