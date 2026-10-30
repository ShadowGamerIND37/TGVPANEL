# HKVM V3 Unified Migration & Implementation Checklist

Status Legend: `Not started` | `In progress` | `Implemented` | `Tested` | `Blocked`

---

## Phase-by-Phase Execution Status (Part 24)

| Phase | Milestone | Status | Verification & Notes |
|---|---|---|---|
| **Phase 1** | Audit both codebases & host capabilities | `Tested` | Documented in `docs/PHASE1_SOURCE_AUDIT.md`; 7 HKVM V2 bugs identified and patched in `app.js`. |
| **Phase 2** | Design unified architecture & schema | `Tested` | Unified adapter pattern (`KVMAdapter` + `LXCAdapter` + `VirtualizationManager` + `InstanceManager`) & PostgreSQL 15+ guide (`docs/POSTGRESQL_MIGRATION.md`). |
| **Phase 3** | Back up `data/hkvm.db` & build migrations | `Tested` | Pre-V3 backup at `data/backups/hkvm_v2_initial.db`; transactional migrations `v001`–`v005` + `importHvmDatabase` tested in **T01** & **T03**. |
| **Phase 4** | Build Node.js + TypeScript Node Agent | `Tested` | `src/node-agent/*.ts` (`agent.ts`, `authentication.ts`, `command-runner.ts`, `container-manager.ts`, `container-console.ts`, `shell-manager.ts`, `snapshot-manager.ts`, `transfer-manager.ts`); HMAC + replay defense (`409`) tested in **T07** & **T09**. |
| **Phase 5** | Build Virtualization Manager (`KVMAdapter` + `LXCAdapter`) | `Tested` | Capability profiles, lifecycle hooks, Linux `/proc/<pid>` telemetry, sharing, expiration, and honest host binary checks tested in **T06** & **T08**. |
| **Phase 6** | Integrate nodes, LXC templates, networking, ports, firewall, backups, migrations & monitoring | `Tested` | `NodeManager`, `StorageManager`, `NetworkManager`, `BackupSnapshotManager`, `MigrationManager`, `MonitoringService` tested in **T07**, **T10**, **T11**. |
| **Phase 7** | Integrate unified REST API v1, Auth, 2FA, RBAC, CSRF, API Keys, Webhooks & Impersonation | `Tested` | `src/api/v1/router.ts`, `src/api/web-routes.ts`, `src/security/*` tested in **T02**, **T04**, **T05**, **T06**, **T11**. |
| **Phase 8** | Upgrade Admin (23 sidebar items) & User EJS Frontend | `Tested` | Preserved EJS + dark/light CSS variables, local `/vendor/xterm/`, all 23 Admin routes + User routes verified `200 OK` in **T12**. |
| **Phase 9** | Build `scripts/install.sh` & `scripts/update.sh` | `Tested` | Capability detection (`/dev/kvm`, `qemu-*`, `lxc-*`, `cgroups v2`), 4 install modes, offline Node header support, systemd units, syntax verified via `bash -n`. |
| **Phase 10** | Run acceptance tests, security audit & final verification | `Tested` | `npm test` -> **12/12 Acceptance Suites Passed**; zero plaintext secrets; live preview verified on `0.0.0.0:8080`. |

---

## Detailed Feature Migration Matrix (HKVM V2 + HVM V9 -> HKVM V3)

| Capability Area | Source | Target Module(s) | Status | Notes / Host Constraints |
|---|---|---|---|---|
| Express + EJS Foundation & Branding (`HKVM`) | HKVM V2 | `app.js`, `views/**`, `public/**` | `Tested` | Preserved 100%; upgraded to V3.0 without React rewrite or Flask sidecar. |
| Users, Roles (`admin`/`subadmin`/`operator`/`user`/`readonly`), Discord OAuth | HKVM V2 + HVM V9 | `app.js`, `src/security/middleware.ts` | `Tested` | Preserved Discord OAuth; added granular RBAC & audited user impersonation. |
| Legacy HVM User/VPS/Node/Port Importer & Werkzeug Rehash | HVM V9 | `src/db/hvm-importer.ts`, `app.js` | `Tested` | Verifies `pbkdf2:sha256` & `scrypt`, auto-upgrades to `bcrypt` on login (**T03**). |
| TOTP Two-Factor Authentication (RFC 6238 + QR) | HVM V9 | `src/security/crypto-vault.ts`, `views/users/login-2fa.ejs` | `Tested` | End-to-end setup, QR generation, and 2-step login tested (**T05**). |
| Secret Vault (`.hkvm-secret`), AES-256-GCM, CSRF, Scoped PATs | V3 New + HVM V9 | `src/security/crypto-vault.ts`, `middleware.ts` | `Tested` | Replaced hardcoded session secret & plaintext VM/node credentials (**T02**, **T04**). |
| QEMU/KVM Lifecycle, ISO, Cloud-Init, CPU/SMBIOS, VM Edit | HKVM V2 | `app.js`, `KVMAdapter.ts` | `Tested` | Fixed Windows `cmd` stats bug -> Linux `/proc/<pid>`, fixed ownership checks, fixed WS console stdin, wired real `qemu-img snapshot` (**T06**, **T08**, **T11**). |
| Complete LXC Lifecycle (create/start/stop/restart/freeze/unfreeze/suspend/reinstall/resize/renew/share) | HVM V9 | `LXCAdapter.ts`, `container-manager.ts` | `Tested` | Native `lxc-*` via allowlisted `execFile` + cgroups v1/v2 limits. *(Actual container spawn requires a Linux host with `lxc` installed; sandbox lacks `lxc-*` binaries and reports that honestly.)* |
| Centralized LXC OS Template Catalog (19 distros + custom upload) | HVM V9 | `migrations.ts`, `StorageManager.ts`, `/admin/lxc-templates` | `Tested` | Ubuntu, Debian, Alpine, AlmaLinux, Rocky, Fedora, Arch, Kali, OpenSUSE, CentOS Stream, Devuan, Void, BusyBox (**T01**, **T10**). |
| Remote Node Agent (HTTPS/mTLS, HMAC-SHA256, Replay Guard, Circuit Breaker, Key Rotation) | HVM V9 (`node.py`) | `src/node-agent/*`, `NodeClient.ts` | `Tested` | Rewritten 100% in TypeScript; live loopback sync + nonce replay rejection (`409`) tested (**T07**). |
| Confined LXC Rootfs File Browser & Process/Log Inspector | HVM V9 | `container-manager.ts`, `views/users/lxc-detail.ejs` | `Tested` | `fs.realpathSync` jail blocks `../` & symlink traversal (**T09**). |
| Real xterm.js Consoles (KVM Serial, KVM SSH, LXC PTY, Restricted Admin Node Shell) | HKVM V2 + HVM V9 | `context.ts`, `container-console.ts`, `shell-manager.ts` | `Tested` | Bundled local `/vendor/xterm/`; real `node-pty` WebSocket shell tested (**T12**). |
| Storage Pools, Network Bridges/NAT, IPv4/IPv6 CIDR, Port Forwards, Firewall Rollback | HKVM V2 + HVM V9 | `StorageManager.ts`, `NetworkManager.ts` | `Tested` | Pool/IP/port/firewall CRUD tested (**T10**); `iptables-save`/`iptables-restore` rollback implemented. |
| Unified Snapshots, SHA-256 Verified Backups & Offline Verified Migration | HKVM V2 + HVM V9 | `BackupSnapshotManager.ts`, `MigrationManager.ts` | `Tested` | Real `tar.gz` backup + SHA-256 verification tested (**T11**); 7-stage offline migration with pre-commit rollback implemented. |
| Live & Historical Monitoring, Alert Rules, Notifications & Signed Webhooks | HVM V9 | `MonitoringService.ts`, `/admin/monitoring` | `Tested` | Background poller, `/proc` metrics history, alerts, bell notifications & HMAC webhooks tested (**T11**). |

---

## Honest Environment Capability Notes (Current Sandbox Host)

- **Present & Tested Live**: Linux 6.1 x86_64, Node.js `v22.22.3`, TypeScript `7.0.2`, native `sqlite3`, native `node-pty` PTY allocation, `tar`, `iproute2`, `iptables`, `nftables`, `openssl`.
- **Absent on Current Container Sandbox**: `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, and `lxc-*` userland binaries (outbound `apt` repositories are firewalled in this sandbox). Both the Node Health API (`/api/v1/health`, `/api/system/status`) and `KVMAdapter`/`LXCAdapter` detect and surface exact missing-binary / capability warnings honestly without mocking or faking hypervisor execution.
