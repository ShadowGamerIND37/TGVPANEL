# TGVPANEL Security

This document describes the security controls TGVPANEL implements and the
operational hardening required for a production deployment. TGVPANEL is a
self-hosted control panel; its security posture depends on host configuration,
network exposure, and secret management.

## Authentication & access control

### Sessions & roles

- Panel access uses server-side sessions with an `httpOnly`, `sameSite=lax`
  cookie. Set **`SESSION_COOKIE_SECURE=1`** when serving over HTTPS so the
  cookie is never sent in clear.
- Authorization uses role gates (`admin`, `subadmin`, `operator`, `reseller`,
  `user`). Staff-only operations require an appropriate role; instance
  ownership is enforced on customer-facing reads and mutations.
- Admin **impersonation** is supported for support workflows and can be
  explicitly terminated (`POST /auth/stop-impersonation`).

### Two-factor authentication (TOTP)

- RFC 6238 TOTP 2FA is supported (`crypto-vault.ts`). Setup generates a secret
  and QR (`POST /auth/2fa/setup`); enable/disable requires the current
  authenticated session (`/auth/2fa/enable`, `/auth/2fa/disable`).
- The TOTP secret is stored encrypted (`two_factor_secret_enc`); logins for
  2FA-enabled users require a valid TOTP code before a session is established.

### API keys

- Programmatic access uses scoped generic API keys. Only a hash is stored; the
  raw key is returned once at creation. Keys carry an optional expiry, IP
  allowlist, and scope, and last-use is recorded.
- Reseller access uses a **separate HMAC credential system**
  (`reseller-api-auth.ts`) with isolated keys, scoped endpoints, and signed
  requests. Reseller keys are independent of generic API keys. See
  [`docs/API_RESELLER.md`](docs/API_RESELLER.md).

## Request security

### CSRF

- State-mutating browser-session requests are verified against a CSRF token
  (`X-CSRF-Token` header or `_csrf` body field). Requests authenticated via
  `Authorization: Bearer` / `X-API-Key` or Node Agent HMAC are exempt from
  cookie CSRF (they are not cookie-authenticated).

### Rate limiting

- Mutation endpoints are rate-limited. The limiter keys on the client address.
- **`X-Forwarded-For` is honored only from configured trusted reverse proxies**
  (`TRUSTED_PROXIES`, exact IPs or IPv4 CIDRs). Directly-exposed clients cannot
  spoof the header to bypass limits. Configure `TRUSTED_PROXIES` to match your
  actual proxy topology.

### Security headers

- A security-headers + CSRF-token middleware injects response headers and the
  CSRF token into views.

## Secrets & encryption

### Cryptographic vault

- Secrets (session secret, credential key, encrypted values) are stored in the
  `.tgvpanel-secret` vault (`crypto-vault.ts`), with legacy `.hkvm-secret`
  migration supported.
- **The credential key (`credentialKeyHex`) is the master secret for
  backup encryption-at-rest.** Back it up and restrict access; losing it makes
  encrypted local LXC backups unrecoverable.

### Backup encryption at rest

- Local **LXC and KVM** backup archives are encrypted at rest with **AES-256-GCM**
  (`backup-crypto.ts`, format `TGVENC1`). Encrypted archives are written as
  `<file>.enc` (0600) and the plaintext is removed; verification/rehearsal/restore
  decrypt to a confined temp file. KVM disk backups (panel-host `tar.gz` archives)
  are encrypted the same way, with the recorded checksum remaining the
  decrypted-content SHA-256.
- Remote-node backups (archives created and stored by a remote node agent) are left
  unencrypted for compatibility; apply transport security (TLS) and
  destination-side protection for remote copies.
- Migration **v023** records `encrypted` + `encryption_alg` per backup.

## Command execution boundary

- All host command execution goes through an **allowlisted command runner**
  (`lib/node-agent/command-runner`). Only known hypervisor/system binaries
  (`qemu-img`, `lxc-*`, `ip`, `iptables`, `nft`, `tc`, `df`, …) are permitted;
  arbitrary shell execution is rejected. Arguments are validated (no null bytes,
  string-only).
- Node Agent shell access is **disabled by default** and enabled only via an
  explicit opt-in (`TGVPANEL_ENABLE_NODE_SHELL`/`HKVM_ENABLE_NODE_SHELL`).
- Filesystem operations (rootfs file read/write, backup staging) are **confined**
  to managed directories with path-traversal protection.

## Node Agent & multi-node security

- Controller ↔ node communication uses **HMAC-signed, replay-protected**
  requests over HTTPS. Node credentials can be rotated
  (`POST /nodes/:id/rotate-credentials`).
- Node agents expose an HTTPS API (default `:8443`); restrict network exposure
  to the controller.

## Data integrity

- Backups and cross-node backup copies are **SHA-256 verified**; mismatches
  fail the operation and the bad copy is removed.
- HVM database import supports a **dry-run/preflight** that validates required
  tables, counts, password-hash formats, and collisions without writing.
- Migrations run in transactions with an automatic pre-migration database backup.

## Operational hardening checklist

- [ ] Serve the panel over HTTPS and set `SESSION_COOKIE_SECURE=1`.
- [ ] Restrict panel/agent ports to trusted networks; place behind a reverse
      proxy and set `TRUSTED_PROXIES` to the proxy address.
- [ ] Enable TOTP 2FA for all admin/operator accounts.
- [ ] Rotate API keys regularly; revoke unused keys; enforce IP allowlists and
      expiry where possible.
- [ ] Back up and protect `.tgvpanel-secret` (especially the credential key).
- [ ] Keep the panel, node agents, QEMU/KVM, and LXC packages patched.
- [ ] Do not enable the interactive node shell unless required.
- [ ] Verify backup decryption and cross-node copy checksums after configuration.

## Disclosures & scope

- TGVPANEL is the operator's custom panel. It does **not** integrate with
  Proxmox/vendor APIs or external credential flows; it manages its own native
  KVM/LXC control plane.
- Generic bearer API keys are bearer credentials; treat them like passwords.
  Reseller HMAC credentials are a distinct, isolated mechanism.
- No payment/billing gateway is implemented; no order is ever marked paid without
  a verified provider confirmation.
