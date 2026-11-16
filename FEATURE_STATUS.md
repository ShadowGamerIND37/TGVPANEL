# TGVPANEL Feature Status

Status is based on code and acceptance tests, not marketing pages or historical planning documents. **Implemented** means the referenced path exists; **Verified** means tests exercise it. A UI/API route alone is not evidence of a working hypervisor feature.

| Capability area | Current status | Evidence / boundaries |
|---|---|---|
| Existing KVM/QEMU virtualization | PARTIALLY IMPLEMENTED | `KVMAdapter.ts`, legacy root `app.js` routes and T11/T20/T24. Create/lifecycle/disk, QCOW2 snapshots/backups, templates, consoles and selected config exist. Does not mean every Virtualizor operation is supported. |
| Existing LXC VPS operations | PARTIALLY IMPLEMENTED | `LXCAdapter.ts`, `src/node-agent/container-manager.ts`, T13–T19, T22/T23/T26–T29/T32. Real Linux LXC, config/resource/network/file/console operations are used. Host-dependent requirements still apply. |
| Proxmox, Xen/XCP-ng, OpenVZ, Docker adapters | NOT IMPLEMENTED | PVE templates exist; external Proxmox management does not. Adapter set is KVM/LXC. |
| Existing multi-node agent | PARTIALLY IMPLEMENTED / TESTED | `NodeClient.ts`, node-agent HMAC/TLS and T07/T21/T22. Not a quorum HA control plane. |
| Storage pools, templates, network/IP/ports/firewall | PARTIALLY IMPLEMENTED / TESTED | `StorageManager.ts`, `NetworkManager.ts`; T10/T16/T17 and T26. Does not imply all backends/protocols in the roadmap. |
| Backups / snapshots / offline migration | PARTIALLY IMPLEMENTED / TESTED | `BackupSnapshotManager.ts`, `MigrationManager.ts`; T11/T14/T31/T32. Scheduled backup/snapshot frequencies are hourly/daily/weekly. Scheduled KVM snapshots require stopped VMs and are disk-level, not guest-consistent. Migration is offline LXC; live KVM migration is not supported. |
| Monitoring and notifications | PARTIALLY IMPLEMENTED / TESTED | `MonitoringService.ts`, node-agent host stats, metrics tables, T08/T11/T23. No synthetic metrics. |
| Generic user/admin API keys | IMPLEMENTED / TESTED | `api_keys` table, `POST/GET/DELETE /api/v1/api-keys`, SHA-256 hashed bearer token, permissions; T04. This legacy PAT system does not satisfy reseller HMAC requirements. |
| Reseller role/key/API ecosystem | PARTIALLY IMPLEMENTED; VERIFIED slices | T33 covers HMAC signing, raw-body binding, timestamp/nonce replay defense, granular permissions, key lifecycle, exact IP allowlist, per-key rates, owner isolation, reseller-owned CRM customer records, and admin oversight. Migration v018 adds the contact directory. `docs/API_RESELLER.md` documents signing and exact boundaries. Customer account/VPS linking, plans, quotas, and billing remain unimplemented. |
| Billing, payments, invoices, PowerDNS, HAProxy | NOT IMPLEMENTED | No corresponding production services/schema were found. |
| General persistent task queue/distributed locks | NOT IMPLEMENTED | Current schedulers and monitoring use in-process loops; LXC installs/migrations have domain-specific state, not a general queue. |

## Reseller API key slice (verified)

- Credentials: random `tgvpk_…` key ID and 256-bit secret; key and secret hashes plus AES-256-GCM-encrypted HMAC secret at rest. The pair is returned only at create/rotate.
- Request protection: documented HMAC-SHA256 canonicalization, five-minute timestamp tolerance, durable one-use nonce records, exact IP allowlists, per-key requests/minute, and request outcome logs.
- Scope model: permissions come from an allowlisted catalog; current endpoints enforce granular scopes and owner checks. Generic API keys and node-agent signatures remain separate and backward-compatible.
- Administration: reseller owner can list/update/disable/enable/revoke/rotate their own keys; admin can inspect key metadata, disable, or revoke without seeing a secret. Admin can list reseller accounts with real owned-VPS resource totals and suspend/unsuspend accounts; suspension disables keys and unsuspension does not silently re-enable them.
- Actual data APIs: reseller VPS read/list (owner-only, paginated and filterable), start/stop/restart, stats, aggregate resources, and per-VPS resource usage delegate to existing database and virtualization managers. Customer CRUD manages isolated CRM records only; there is no linked customer login, customer-VPS relationship, or reseller provisioning. Quotas, plans, billing, and reserved scopes remain unavailable until their backing services are implemented.
- Verification: `npm run build`, `npm test` (**33/33**), including T33 HMAC, tamper, replay, authorization, rotation, IP/rate, audit and owner-isolation checks.
