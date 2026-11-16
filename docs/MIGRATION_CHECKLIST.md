# TGVPANEL Unified Migration & Implementation Checklist

Status Legend: `Not started` | `In progress` | `Implemented` | `Tested` | `Blocked`

---

## Phase-by-Phase Execution Status (Part 24)

| Phase | Milestone | Status | Verification & Notes |
|---|---|---|---|
| **Phase 1** | Audit codebases & host capabilities | `Tested` | Documented in `docs/PHASE1_SOURCE_AUDIT.md`; legacy KVM bugs identified and patched in `app.js`. |
| **Phase 2** | Design unified architecture & schema | `Tested` | Unified adapter pattern (`KVMAdapter` + `LXCAdapter` + `VirtualizationManager` + `InstanceManager`) & PostgreSQL 15+ guide (`docs/POSTGRESQL_MIGRATION.md`). |
| **Phase 3** | Back up `data/tgvpanel.db` & build migrations | `Tested` | Automatic pre-migration backups (`tgvpanel_pre_migration_*.db`), automatic legacy DB & secret-vault file migration, transactional migrations `v001`–`v016` + `importHvmDatabase` tested in **T01** & **T03**. |
| **Phase 4** | Build Node.js + TypeScript Node Agent | `Tested` | `src/node-agent/*.ts` (`agent.ts`, `authentication.ts`, `command-runner.ts`, `container-manager.ts`, `container-console.ts`, `shell-manager.ts`, `snapshot-manager.ts`, `transfer-manager.ts`); HMAC + replay defense (`409`) tested in **T07** & **T09**. |
| **Phase 5** | Build Virtualization Manager (`KVMAdapter` + `LXCAdapter`) | `Tested` | Capability profiles, lifecycle hooks, Linux `/proc/<pid>` telemetry, sharing, expiration, and honest host binary checks tested in **T06** & **T08**. |
| **Phase 6** | Integrate nodes, LXC templates, networking, ports, firewall, backups, migrations & monitoring | `Tested` | `NodeManager`, `StorageManager`, `NetworkManager`, `BackupSnapshotManager`, `MigrationManager`, `MonitoringService`, scheduled backup execution/retention, and scheduled snapshot execution/retention tested in **T07**, **T10**, **T11**, **T31**, **T32**. |
| **Phase 7** | Integrate unified REST API v1, Auth, 2FA, RBAC, CSRF, API Keys, Webhooks & Impersonation | `Tested` | `src/api/v1/router.ts`, `src/api/web-routes.ts`, `src/security/*` tested in **T02**, **T04**, **T05**, **T06**, **T11**. |
| **Phase 8** | Upgrade Admin (23 sidebar items) & User EJS Frontend | `Tested` | Preserved EJS + dark/light CSS variables, local `/vendor/xterm/`, `public/js/tgvpanel-v3.js`, all 23 Admin routes + User routes verified `200 OK` with `TGVPANEL` branding in **T12**. |
| **Phase 9** | Build `scripts/install.sh` & `scripts/update.sh` | `Tested` | Capability detection (`/dev/kvm`, `qemu-*`, `lxc-*`, `cgroups v2`), 4 install modes, offline Node header support, `tgvpanel.service` systemd units, syntax verified via `bash -n`. |
| **Phase 10** | Run acceptance tests, security audit & final verification | `Tested` | `npm run build` and `npm test` -> **32/32 Acceptance Suites Passed** (`T01`–`T32`); zero plaintext secrets. |

---

## Detailed Feature Migration Matrix (TGVPANEL Unified Platform)

| Capability Area | Source | Target Module(s) | Status | Notes / Host Constraints |
|---|---|---|---|---|
| Express + EJS Foundation & Branding (`TGVPANEL`) | Core KVM Panel | `app.js`, `views/**`, `public/**` | `Tested` | Preserved 100%; rebranded UI, routes, database (`data/tgvpanel.db`), secret vault (`.tgvpanel-secret`), and docs to `TGVPANEL` (**T01**, **T02**, **T12**). |
| Users, Roles (`admin`/`subadmin`/`operator`/`user`/`readonly`), Discord OAuth | Unified Auth | `app.js`, `src/security/middleware.ts` | `Tested` | Preserved Discord OAuth; added granular RBAC & audited user impersonation. |
| Legacy User/VPS/Node/Port Importer & Werkzeug Rehash | Legacy Importer | `src/db/hvm-importer.ts`, `app.js` | `Tested` | Verifies `pbkdf2:sha256` & `scrypt`, auto-upgrades to `bcrypt` on login (**T03**). |
| TOTP Two-Factor Authentication (RFC 6238 + QR) | Security Module | `src/security/crypto-vault.ts`, `views/users/login-2fa.ejs` | `Tested` | End-to-end setup (`issuer=TGVPANEL`), QR generation, and 2-step login tested (**T05**). |
| Secret Vault (`.tgvpanel-secret`), AES-256-GCM, CSRF, Scoped PATs | Security Module | `src/security/crypto-vault.ts`, `middleware.ts` | `Tested` | Auto-migrates legacy secret vaults to `.tgvpanel-secret`; encrypts VM/LXC/node credentials (**T02**, **T04**). |
| QEMU/KVM Lifecycle, Proxmox VE 8 & 9 Templates, ISO, Cloud-Init, CPU/SMBIOS, VM Edit | KVM Engine | `app.js`, `KVMAdapter.ts`, `views/admin/vm-create.ejs` | `Tested` | Built-in Proxmox VE 8 (Bookworm) & Proxmox VE 9 (Trixie) hypervisor templates, unattended Cloud-Init bootstrap (`pve-no-subscription`, `vmbr0`, serial GRUB), native ISO-9660 `cidata` fallback, QEMU NAT `:8006` Web UI forwarding + collision avoidance, encrypted reinstall, Linux `/proc/<pid>` telemetry, persistent VM deletion (**T06**, **T08**, **T11**, **T20**, **T24**). |
| Complete LXC Lifecycle (create/start/stop/restart/freeze/unfreeze/suspend/reinstall/resize/renew/share) | LXC Engine | `LXCAdapter.ts`, `container-manager.ts` | `Tested` | Native `lxc-*` via allowlisted `execFile`, ext4 loop disk quotas, KVM nesting, and cgroup v2 `init.scope` + `hkvm.lxc` full controller delegation with `"domain threaded"` / `"domain invalid"` self-healing (**T13**–**T19**). |
| Centralized LXC OS Template Catalog (Proxmox VE 8/9 + 19 distros + custom upload) with Local OS Logos | Storage Module | `migrations.ts`, `StorageManager.ts`, `/admin/lxc-templates`, `/admin/instances/create` | `Tested` | Proxmox VE 8 (Bookworm) & Proxmox VE 9 (Trixie) LXC hypervisor images (Debian base + first-boot PVE bootstrap, `:8006`, 4 GB/40 GB minimums, privileged + KVM nesting), owner-triggered Cloudflare Quick Tunnel installer for Proxmox-only LXC (disables subscription-only Enterprise APT sources before package updates, `cloudflared` setup, persistent service, live progress/logs + extracted public URL), local `/images/os/*.svg` logos on create grid / list / catalog / detail (Ubuntu, Debian, AlmaLinux, Rocky, CentOS, Fedora, Kali, Alpine, Proxmox), custom upload with auto icon (**T01**, **T10**, **T13**, **T26**, **T29**). |
| Real xterm.js Consoles (KVM Serial, KVM SSH, LXC PTY, Restricted Admin Node Shell) | Console Module | `context.ts`, `container-console.ts`, `shell-manager.ts` | `Tested` | Bundled local `/vendor/xterm/`; real `node-pty` WebSocket shell tested (**T12**, **T14**). |
| Storage Pools, Network Bridges/NAT, IPv4/IPv6 CIDR, Port Forwards, Firewall Rollback | Storage & Network | `StorageManager.ts`, `NetworkManager.ts` | `Tested` | Pool/IP/port/firewall CRUD, DNS relay, Netplan sync & `iptables-save`/`iptables-restore` rollback (**T10**, **T16**, **T17**). |
| Unified Snapshots, Scheduled Snapshots, SHA-256 Verified Backups & Offline Verified Migration | Backup & Migration | `BackupSnapshotManager.ts`, `MigrationManager.ts` | `Tested` | Real LXC snapshot runs with schedule-scoped retention, manual snapshot preservation, owner notices, and run status; running KVM schedules are rejected before invoking disk snapshot operations. Scheduled KVM snapshots require a stopped VM. Real `tar.gz` backup + SHA-256 verification & 7-stage offline migration with pre-commit rollback (**T11**, **T14**, **T32**). |
| Multi-Node Agent, Cloudflare Tunnel (No-IPv4) Support, 1-Command Pairing (`--join`), TOFU TLS Pinning, Push Heartbeats, Remote Storage/Ports/Firewall, Circuit Breakers & Monitoring | Nodes & Monitoring | `NodeClient.ts`, `MonitoringService.ts`, `agent.ts`, `menu.sh` | `Tested` | Cloudflare Tunnel / Reverse Proxy domain-only onboarding without public IPv4, combined system Root CA + TOFU X.509 pinning, single-use join tokens (`TGVPANEL_ADVERTISE_URL`), active agent->controller heartbeats, remote `statfs`/NAT/firewall/custom-template staging, multi-node `sync-host`, cross-node backup restore & bridged WSS PTY (**T07**, **T11**, **T21**, **T22**, **T25**). |


## V4 Release Baseline

| Area | V4 work in this branch | Verification / boundaries |
|---|---|---|
| Release/versioning | Package, panel/API/agent health version, menu, and visible license/settings labels are V4.0 / 4.0.0. | Schema migration v014 backs up before migration through the existing migration runner, upgrades only known panel-owned V3 defaults, and leaves customized settings unchanged. |
| Account security | Working self-service password change replaces the settings-page placeholder. Requires the current password and the owner’s browser session, applies CSRF protection and IP throttling, rejects password reuse, hashes with bcrypt, and writes success/failure audit events. | Acceptance test T30 exercises incorrect/current/reused passwords, API-key denial, persistence, and audit logging. |
| Backups & recovery | Hourly/daily/weekly scheduled backups for KVM and LXC, post-create SHA-256 verification, per-schedule retention, owner notifications, run status/error visibility, and schedule CRUD in the admin UI/API. Retention prunes only that schedule’s verified archives, never manual backups. | T31 runs three real LXC archive cycles, verifies checksums, confirms retention=1 and manual backup preservation, checks owner notifications, and removes the schedule/artifact. KVM archive creation uses the existing real QCOW2 disk tar/verify path; restore remains LXC-only. |
| Scheduled snapshots | Hourly/daily/weekly KVM/LXC snapshot schedules with per-schedule retention, API/UI CRUD, run status/errors, audit events, owner notifications, and retention that excludes manual snapshots. | T32 executes three real LXC schedule cycles and tests retention/manual-snapshot preservation, owner notifications, owner authorization, plus rejection of scheduled KVM snapshots while the VM is running. KVM snapshots are disk-level QCOW2 and require the VM to be stopped; they are not guest-consistent or risk-free. |
| Cluster & operations | Existing multi-node health, alerting, and node-agent compatibility remain in place. | No live migration or new HA guarantee is introduced by the version bump. |
| User workflows | Existing KVM/LXC lifecycle and UI remain in place. | No virtualization operation has been replaced with a mock. |

### V4 follow-on backlog (not implemented in this slice)

- `Not started` — Add configurable retry windows for failed scheduled archives and restore-rehearsal workflows across local/remote nodes.
- `Not started` — Add more cluster-operational workflows and actionable alert delivery, with no unsupported HA or live-migration claims.
- `Not started` — Extend security policy administration, session management, and auditable API-key lifecycle controls beyond the V4 password-change fix.
- `Not started` — Add high-value KVM/LXC user-workflow improvements based on deployment needs while preserving real host operations and existing EJS UI.
