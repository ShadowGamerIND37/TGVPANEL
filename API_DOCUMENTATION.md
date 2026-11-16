# TGVPANEL API Documentation

TGVPANEL exposes a versioned HTTP API under `/api/v1` (Express, JSON), a set of
legacy root routes under `/api` and `/api/vms` (preserved for backward
compatibility), and a Node Agent API used for controller ↔ node communication.
This document describes the public contract of each surface. All responses are
JSON. Authentication uses session cookies (browser) or bearer API keys
(`Authorization: Bearer <key>` / `X-API-Key: <key>`).

> This document describes what the codebase actually implements. Endpoints that
> are not implemented are listed as such rather than implied.

## Authentication & authorization

| Mechanism | Use | Notes |
|---|---|---|
| Session cookie | Browser UI and `/api/v1` session routes | `httpOnly`, `sameSite=lax`. Set `SESSION_COOKIE_SECURE=1` behind HTTPS. |
| Bearer API key | Programmatic `/api/v1` access | `Authorization: Bearer <key>` or `X-API-Key: <key>`. Scoped generic keys stored hashed in `api_keys`. |
| Reseller HMAC | Reseller-owned endpoints | Separate HMAC-signed credentials (`reseller-api-auth.ts`); see [Reseller API](#reseller-api). |
| Node Agent HMAC | Controller → node calls | HMAC-signed, replay-protected; managed by `NodeClient`. |

Role gates use `requireRole([...])`: `admin`, `subadmin`, `operator`, `reseller`,
`user`. Mutating browser-session requests are CSRF-protected (see
[SECURITY.md](SECURITY.md)). API-key/HMAC requests are exempt from cookie CSRF.

## Versioned API (`/api/v1`)

### Health & nodes

| Method | Path | Roles | Description |
|---|---|---|---|
| GET | `/health` | public | Liveness probe. |
| POST | `/nodes/agent-heartbeat` | agent | Node agent heartbeat. |
| GET | `/nodes` | staff | List registered nodes. |
| POST | `/nodes` | admin | Register a node. |
| PATCH | `/nodes/:id` | admin | Update a node (name, location, credentials, maintenance). |
| DELETE | `/nodes/:id` | admin | Remove a node. |
| POST | `/nodes/:id/check` | admin/subadmin/operator | Force a health + stats sample; records a `metrics_history` row. |
| POST | `/nodes/:id/rotate-credentials` | admin | Rotate a remote node's HMAC credential. |

### Instances (KVM + LXC)

| Method | Path | Roles | Description |
|---|---|---|---|
| GET | `/instances` | authenticated | List instances (scoped by ownership). |
| POST | `/instances/bulk-action` | staff | Bulk lifecycle action. |
| GET | `/instances/:engine/:id` | authenticated | Instance detail (`engine` = `kvm` | `lxc`). |
| GET | `/instances/:engine/:id/tasks` | authenticated | Persisted task history for the instance. |
| GET | `/instances/:engine/:id/telemetry` | authenticated | Live resource telemetry. KVM disk uses honest `qemu-img` stats; unavailable RX/TX return `null` (never fabricated). |
| GET | `/instances/:engine/:id/metrics` | authenticated | Metrics history for the instance. |
| POST | `/instances/:engine/:id/action` | authenticated | Lifecycle action (`start`, `stop`, `restart`, `shutdown`, `suspend`, `unsuspend`, `freeze`, `unfreeze`, `delete`, …). Opt-in `async: true` returns a durable task id. |
| GET | `/tasks/:taskId` | authenticated | Fetch a task by id (ownership-checked). |

#### KVM-specific

| Method | Path | Roles | Description |
|---|---|---|---|
| POST | `/instances/kvm/:id/disk/resize` | staff | Offline virtual-disk expansion (never shrinks). Returns `virtualSizeBytes` + `guestFilesystemResizeRequired`. |
| GET/POST | `/instances/kvm/:id/vnc` | staff | Local-only QEMU VNC console settings. |
| POST | `/instances/kvm/:id/clone` | staff | Offline clone of a stopped NAT VM's standalone primary disk. |
| POST | `/instances/kvm/:id/rescue` | staff | Guided operator-supplied rescue ISO next-boot / disk-first restore. |
| GET | `/instances/kvm/:id/devices` | staff | List attached disks and NICs. |
| POST | `/instances/kvm/:id/devices/disks` | staff | Attach a secondary QCOW2 disk (stopped VM). |
| POST | `/instances/kvm/:id/devices/disks/:deviceId/attach` | staff | Reattach a detached disk. |
| DELETE | `/instances/kvm/:id/devices/disks/:deviceId` | staff | Detach a disk (image preserved). |
| POST | `/instances/kvm/:id/devices/nics` | staff | Attach a user-mode NAT NIC (stopped VM). |
| DELETE | `/instances/kvm/:id/devices/nics/:deviceId` | staff | Detach a NIC. |

#### LXC-specific

| Method | Path | Roles | Description |
|---|---|---|---|
| GET | `/lxc` | staff | List LXC containers. |
| GET/POST | `/lxc/templates` | staff | LXC OS template catalog. |
| PATCH/DELETE | `/lxc/templates/:id` | staff | Toggle/delete a template. |
| POST | `/lxc` | staff | Provision an LXC container. |
| PATCH | `/lxc/:id` | staff | Update container config (CPU/RAM/disk/nesting/kvmNesting). |
| DELETE | `/lxc/:id` | staff | Delete a container (host-verified). |
| POST | `/lxc/:id/reinstall` | staff | Reinstall/reset a container. |
| POST | `/lxc/:id/cloudflare-tunnel` | staff | Start/manage a Cloudflare tunnel. |
| GET | `/lxc/:id/cloudflare-tunnel` | staff | Tunnel status. |
| POST | `/lxc/:id/repair-network` | staff | Live network repair. |
| POST | `/lxc/:id/password` | staff | Reset root password. |
| POST | `/lxc/:id/ssh-key` | staff | Inject an SSH key. |
| PUT | `/lxc/:id/sharing` | staff | Sharing/ownership settings. |
| GET | `/lxc/:id/processes` | staff | Container processes. |
| GET | `/lxc/:id/logs` | staff | Container logs. |
| GET/POST/DELETE | `/lxc/:id/files[/content]` | staff | Rootfs file read/write/delete (confined). |
| POST | `/lxc/:id/clone` | staff | Stopped `lxc-copy` clone. |
| POST | `/lxc/expirations/sweep` | admin/subadmin | Run the VPS expiration sweep: suspends expired LXC instances (auto-suspend enabled) through the normal lifecycle path and notifies owners. Also runs automatically every 5 minutes. |

### Storage

| Method | Path | Roles | Description |
|---|---|---|---|
| GET | `/storage/pools` | staff | List pools. `?sync=1` re-measures capacity via `statfs`. |
| POST | `/storage/pools` | admin | Create a storage pool. |
| DELETE | `/storage/pools/:id` | admin | Delete a pool (refused while volumes exist). |
| GET | `/storage/orphans` | staff | Report-only orphan image detection: scans local pool directories for disk images (qcow2/raw/img/vmdk) not referenced by any KVM VM, LXC container rootfs, or OS template. Returns `{ orphans: [{ poolId, poolName, poolPath, filePath, sizeBytes, reason }] }`; never deletes or modifies files. Remote pools are skipped. |
| GET | `/iso/inventory` | staff | ISO library inventory with honest `sizeBytes` + SHA-256 `sha256`. |

### Networking, ports & firewall

| Method | Path | Roles | Description |
|---|---|---|---|
| GET/POST | `/network/pools` | staff/admin | List/create IP network pools. Listing returns `pools` + `ips`. |
| POST | `/network/pools/:id/ips` | admin | Add IPs to a pool. |
| GET/POST/DELETE | `/network/ports[/:id]` | staff | Port forwards (NAT). |
| GET/POST/DELETE | `/network/firewall[/:id]` | staff/admin | Node firewall rules. |

### Backups & snapshots

| Method | Path | Roles | Description |
|---|---|---|---|
| GET/POST | `/backups` | staff | List/create backups. |
| POST | `/backups/:id/restore` | staff | Restore a backup. Optional body `{ copyId }` (positive integer) restores from a recorded backup copy (`backup_copies`) instead of the primary archive; encrypted copies are decrypted and checksum-verified at the panel first. |
| POST | `/backups/:id/rehearse` | staff | Restore rehearsal (dry-run pre-check; Phase 9). |
| POST | `/backups/:id/copy` | admin/subadmin | Copy a backup to a destination node with integrity verification (Phase 10). |
| GET | `/backups/:id/copies` | admin/subadmin | List cross-node backup copies. |
| DELETE | `/backups/:id` | admin/subadmin | Delete a backup. Removes the archive file and, first, all recorded copies (files on their target nodes + rows); if a copy cleanup fails the backup is left intact for retry. |
| GET/PUT/DELETE | `/backup-schedules[/:engine/:id]` | staff | Backup schedules (hourly/daily/weekly) + retention. |
| GET/PUT/DELETE | `/snapshot-schedules[/:engine/:id]` | staff | Snapshot schedules + retention. |
| GET/POST | `/snapshots/:engine/:id` | staff | List/create snapshots. KVM snapshots expose honest `sizeGb` + `allocatedGb` (Phase 13). |
| POST | `/snapshots/:engine/:id/:snapId/restore` | staff | Restore a snapshot. |
| DELETE | `/snapshots/:engine/:id/:snapId` | staff | Delete a snapshot. |

### Monitoring, API keys & webhooks

| Method | Path | Roles | Description |
|---|---|---|---|
| GET/POST/DELETE | `/api-keys[/:id]` | authenticated/admin | Manage scoped generic API keys. |
| GET/POST/DELETE | `/webhooks[/:id]` | admin | Alert/webhook delivery targets. Deliveries retry up to 3 attempts with 2s/4s backoff; `GET` exposes `last_status_code`, `last_error`, and `failure_count`. |

### Database / import

| Method | Path | Roles | Description |
|---|---|---|---|
| POST | `/database/import-hvm` | admin | Import a legacy HVM database (creates a pre-import backup). |
| POST | `/database/import-hvm/dry-run` | admin | Dry-run/preflight HVM import validation without writing (Phase 11). |

### Auth (2FA)

| Method | Path | Roles | Description |
|---|---|---|---|
| POST | `/auth/password/change` | authenticated | Change password (rate-limited). |
| POST | `/auth/2fa/setup` | authenticated | Generate TOTP secret + QR. |
| POST | `/auth/2fa/enable` | authenticated | Enable TOTP 2FA. |
| POST | `/auth/2fa/disable` | authenticated | Disable TOTP 2FA. |
| POST | `/auth/stop-impersonation` | staff | End an admin impersonation session. |

## Reseller API

Reseller endpoints use isolated HMAC credentials and scoped access
(`reseller-api-auth.ts`). See [`docs/API_RESELLER.md`](docs/API_RESELLER.md) for
canonical request signing and examples.

| Method | Path | Scope | Description |
|---|---|---|---|
| GET/POST | `/reseller/api-keys` | `api_keys.read`/`create` | List/create reseller API keys (secret returned once). |
| GET/PUT/POST | `/reseller/api-keys/:id[/rotate]` | `api_keys.read`/`create` | Read/update/rotate a key. |
| POST/DELETE | `/reseller/api-keys/:id/:action` | `api_keys.revoke` | Enable/disable/revoke a key. |
| GET/POST | `/reseller/customers[/:id]` | `customers.*` | Reseller CRM customer CRUD. |
| GET | `/reseller/vps[/:id]` | `vps.read` | Owner-scoped VPS list/detail. |
| POST | `/reseller/vps/:id/:action` | scoped | Owner-scoped VPS lifecycle. |
| GET | `/reseller/stats` | `stats.read` | Reseller stats. |
| GET | `/reseller/resources[/usage]` | `resources.read` | Reseller resource usage. |
| GET/POST | `/reseller/admin/accounts` | admin | Admin oversight of reseller accounts. |
| GET/POST/DELETE | `/reseller/admin/api-keys[/:id]` | admin | Admin oversight of reseller keys. |

## Node Agent API (`:8443`, HMAC-authenticated)

The controller calls node agents over HTTPS with HMAC-signed requests. Key
routes exposed by `lib/node-agent/agent.js`:

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/ping` | Liveness. |
| GET | `/api/v1/health` | Node health report (capabilities + warnings). |
| GET | `/api/v1/stats` | Host resource stats (CPU/RAM/disk/net via `/proc` + `df`). |
| GET/POST | `/api/v1/containers[/:name]` | LXC container inventory/create. |
| POST | `/api/v1/containers/:name/action` | Container lifecycle. |
| POST | `/api/v1/containers/:name/clone` / `reinstall` / `repair-network` / `cloudflare-tunnel` | Container operations. |
| GET | `/api/v1/containers/:name/{processes,logs,files,snapshots}` | Container introspection. |
| POST/DELETE | `/api/v1/containers/:name/backups[/restore]` | Container backup/restore. |
| POST | `/api/v1/backups/{download,verify,rehearse,receive}` | Backup transfer/verification/rehearsal/receive (Phases 9–10). |
| DELETE | `/api/v1/backups/file` | Delete a backup file. |
| POST | `/api/v1/storage/statfs` | Filesystem capacity probe (used by pool capacity sync). |

## Legacy routes (`/api`, `/api/vms`)

Legacy KVM routes in `app.js` remain for backward compatibility and share the
task lock/history mechanism: `POST /api/vms/:vm_id/{start,stop,restart,shutdown}`,
`DELETE /api/vms/:vm_id`, `POST /api/vms/:vm_id/{iso/attach,iso/detach,reinstall,snapshot}`,
`GET /api/vms/:vm_id/snapshots`, `GET /api/iso-list` (bare filenames), and admin
template/dashboard routes. Prefer the `/api/v1` surface for new integrations.

## Error model

Errors return a JSON `{ "error": "<message>" }` body with an appropriate HTTP
status (`400` validation, `401`/`403` auth, `404` not found, `409` conflict,
`429` rate-limited, `502` upstream node error, `500` server error). Task-backed
mutations return `202` with a `task` object when `async: true`.
