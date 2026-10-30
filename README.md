# HKVM V3 — Unified Virtualization Control Panel (QEMU/KVM + LXC)

**HKVM V3** merges **HVM V9** (multi-node LXC container VPS platform & remote node agent) directly into **HKVM V2** (Express, EJS, SQLite, QEMU/KVM virtualization panel) as a single cohesive Node.js + TypeScript virtualization platform named **HKVM**.

No Python/Flask runtime is required or executed. All backend services, multi-node communication, HMAC/mTLS security, PTY consoles, storage/network orchestration, backups, offline verified migrations, and monitoring run natively in Node.js + TypeScript (`src/**/*.ts` compiled to `lib/**/*.js`) atop the preserved HKVM Express + EJS foundation (`app.js`).

---

## Architecture Overview

```
TGVPANEL/
├── app.js                                # HKVM V3 Express + HTTP + WebSocket entrypoint
├── licenses.js                           # Free Edition license module (preserved)
├── data/
│   ├── hkvm.db                           # Primary unified SQLite database (WAL mode)
│   └── backups/                          # Automatic VACUUM INTO pre-migration & scheduled backups
├── src/
│   ├── context.ts                        # Unified runtime bootstrap & authenticated WS multiplexer
│   ├── security/
│   │   ├── crypto-vault.ts               # .hkvm-secret (0600), AES-256-GCM, SHA-256 PATs, HMAC, RFC 6238 TOTP, CSRF
│   │   └── middleware.ts                 # RBAC (admin/subadmin/operator/user/readonly), CSRF, rate limiting, validators
│   ├── db/
│   │   ├── database.ts                   # Transactional SQLite wrapper + audit logger + VACUUM INTO backup
│   │   ├── migrations.ts                 # Versioned migrations v001..v005 (non-destructive)
│   │   ├── hvm-importer.ts               # Legacy HVM V9 SQLite importer + Werkzeug pbkdf2/scrypt -> bcrypt upgrader
│   │   ├── cli-migrate.ts                # `npm run migrate`
│   │   └── hvm-importer-cli.ts           # `npm run import:hvm -- <path/to/hvm.db>`
│   ├── node-agent/                       # Standalone & Local Compute Node Agent (replaces Python node.py)
│   │   ├── agent.ts                      # HTTP/HTTPS/mTLS + WebSocket remote compute server & LocalNodeRuntime
│   │   ├── authentication.ts             # Per-node API key hash, HMAC-SHA256 signature + timestamp + nonce replay guard
│   │   ├── command-runner.ts             # Strict binary allowlist (`execFile` only, shell: false)
│   │   ├── health.ts & host-stats.ts     # Real /dev/kvm, QEMU, LXC, cgroup v2 & /proc telemetry
│   │   ├── container-manager.ts          # Native lxc-* lifecycle, cgroups v1/v2 limits & realpath-confined rootfs I/O
│   │   ├── container-console.ts          # Real node-pty `lxc-attach` interactive container PTY
│   │   ├── shell-manager.ts              # Safe diagnostic presets + opt-in audited Admin Node PTY shell
│   │   ├── snapshot-manager.ts           # Native LXC snapshots & SHA-256 verified tar.gz backups
│   │   └── transfer-manager.ts           # Checksum-verified container archive export/import
│   ├── services/
│   │   ├── virtualization/               # VirtualizationAdapter, KVMAdapter, LXCAdapter, VirtualizationManager, InstanceManager
│   │   ├── nodes/NodeClient.ts           # Multi-node registry, circuit breakers, health sync & key rotation
│   │   ├── storage/StorageManager.ts     # Storage pools (RAW/QCOW2/dir/LVM/ZFS/Btrfs), ISOs & LXC OS template catalog
│   │   ├── network/NetworkManager.ts     # Bridges, NAT, IPv4/IPv6 pools, port forwards, bandwidth & iptables rollback
│   │   ├── backup/BackupSnapshotManager.ts # Unified KVM QCOW2 + LXC snapshots, backups & SHA-256 verification
│   │   ├── migration/MigrationManager.ts # Honest 7-stage Offline Snapshot-Transfer VPS Migration with rollback
│   │   └── monitoring/MonitoringService.ts # Live/historical node & VPS metrics, alert rules, notifications & webhooks
│   └── api/
│       ├── v1/router.ts                  # Versioned `/api/v1/*` REST API
│       └── web-routes.ts                 # Unified Admin (23 sidebar sections) & User EJS routes
├── views/                                # Preserved & unified EJS views (dark/light themes, local xterm.js)
├── public/                               # Static CSS, unified V3 client helper (`hkvm-v3.js`), local `/vendor/xterm/`
├── scripts/                              # `install.sh` & `update.sh` with capability detection & DB backup
├── docs/                                 # Source audit, Migration Checklist & PostgreSQL 15+ migration guide
└── tests/run-all.js                      # 12-suite end-to-end integration & security acceptance runner
```

---

## Quick Start

### 1. Automated Installer (Ubuntu / Debian / AlmaLinux / Rocky)
```bash
sudo bash scripts/install.sh
```
The installer detects `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, `lxc-*`, `cgroups v2`, and networking tools, lets you choose **Unified (KVM + LXC)**, **KVM Only**, **LXC Only**, or **Standalone Remote Node Agent**, builds TypeScript, initializes `.hkvm-secret` (`0600`), backs up `data/hkvm.db`, runs migrations, and writes systemd service units.

### 2. Manual Build, Migration & Run
```bash
# If building native addons offline where Node headers live in /usr/local/include/node:
npm_config_nodedir=/usr/local npm install

npm run build          # Compile src/**/*.ts -> lib/**/*.js
npm run migrate        # Backup data/hkvm.db & apply migrations v001..v005
npm start              # Start HKVM V3 Panel on 0.0.0.0:8080 (override via PORT=...)
```

### 3. Importing an Existing HVM V9 Database
```bash
npm run import:hvm -- /path/to/legacy/hvm.db
```
- Automatically creates a `VACUUM INTO` backup of `data/hkvm.db` before importing.
- Maps colliding usernames/emails safely, imports Werkzeug `pbkdf2:sha256` / `scrypt` password hashes and transparently upgrades them to `bcrypt` on next login, encrypts remote node API keys with AES-256-GCM, and imports LXC containers, port forwards, snapshots, backups, notifications, and API keys.

### 4. Starting a Standalone Remote Compute Node Agent
```bash
HKVM_NODE_ID="eu-node-1" \
HKVM_AGENT_PORT=8443 \
HKVM_NODE_API_KEY="hkvm_node_..." \
HKVM_NODE_HMAC_SECRET="..." \
npm run agent:start
```
Supports HTTPS + optional mutual TLS (`HKVM_NODE_MTLS=true`), per-request HMAC-SHA256 signing (`X-HKVM-Timestamp`, `X-HKVM-Nonce`, `X-HKVM-Signature`) with replay protection, and live key rotation from **Admin -> Nodes**.

---

## VPS Migration Model (Honest Architecture)

HKVM V3 implements **Offline Verified Snapshot-Transfer Migration** (`strategy = 'offline_snapshot_transfer'`):
1. Preflight check on source & target node health, LXC support, and free storage capacity.
2. Graceful container stop on source node to ensure filesystem consistency.
3. Rootfs + config export (`tar.gz`) with streaming **SHA-256** digest computation.
4. Authenticated stream transfer to target node and SHA-256 verification before unpack.
5. Target container registration, resource/network configuration, and startup health verification.
6. Atomic SQLite node ownership commit (`lxc_instances` + `instances` + `vps_migrations`).
7. Source cleanup only after target verification succeeds; any pre-commit failure automatically cleans up partial target artifacts and restarts the source container.

*(CRIU memory-page live migration is intentionally not claimed.)*

---

## Running Acceptance Tests

```bash
npm test
```
Executes all 12 end-to-end suites in `tests/run-all.js` against an isolated temporary clone of `data/hkvm.db` (migrations, AES-256-GCM tamper defense, legacy HVM Werkzeug import + login rehash, CSRF + PAT scopes, RFC 6238 TOTP 2FA, RBAC + ownership isolation + VPS sharing, standalone Node Agent HMAC + replay rejection, Linux `/proc` telemetry, rootfs path-traversal jail + command allowlist, storage/templates/networking/ports/firewall, SHA-256 backups/monitoring/impersonation, and all 23 Admin + User EJS views + `node-pty` WebSocket shell).
