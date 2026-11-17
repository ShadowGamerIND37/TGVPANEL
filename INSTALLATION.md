# TGVPANEL Installation Guide

TGVPANEL is a unified QEMU/KVM + LXC VPS virtualization control panel. It runs
as a Node.js service (Express + SQLite) with an optional Node Agent for remote
compute nodes. This guide covers prerequisites, the supported install modes,
configuration, and first-run steps.

## Prerequisites

### Host / OS

- **Supported distributions:** Ubuntu 22.04/24.04, Debian 12/13,
  AlmaLinux/Rocky 9 (see `scripts/install.sh`).
- **Root or passwordless `sudo`** for installing host virtualization packages and
  managing KVM/LXC resources.
- **Hardware virtualization** for KVM: `/dev/kvm` present and enabled in the BIOS
  (VMX/SVM). Without it, QEMU falls back to TCG software emulation (slower).
- **LXC** requires a cgroup v2 host for native per-container RAM/CPU enforcement
  (cgroup v1 hosts are detected and warned about).

### Software

- **Node.js** (LTS) and **npm**.
- **QEMU/KVM:** `qemu-system-x86_64` (or `qemu-system-aarch64` on ARM),
  `qemu-img`.
- **LXC:** `lxc`, `lxc-create`, `lxc-start`, `lxc-info`, and (for accurate guest
  `/proc` telemetry) `lxcfs` mounted at `/var/lib/lxcfs`.
- **Networking:** `ip`, `iptables`/`nftables`, `tc` (for bridges, NAT, port
  forwards, bandwidth controls).
- **Storage:** `mkfs.ext4`, `mount` (and `lvs`/`zfs`/`btrfs` only if you use those
  pool backends).

The installer (`scripts/install.sh`) detects installed binaries and reports
capability warnings; install missing hypervisor packages as needed.

## Install modes

`scripts/install.sh` supports four modes (select with `TGVPANEL_INSTALL_MODE`):

1. **Unified Panel + KVM + LXC** — Single-server / Master + local compute (default `auto`).
2. **Unified Panel + KVM only** — Panel with KVM compute, no LXC.
3. **Unified Panel + LXC only** — Panel with LXC compute, no KVM.
4. **Standalone Remote Node Agent only** — A compute node without the panel, to
   be registered against a master controller.

### Ports

| Service | Default port | Env |
|---|---|---|
| Panel (HTTP) | 8080 | `PORT` |
| Node Agent (HTTPS) | 8443 | `AGENT_PORT` |

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/ShadowGamerIND37/TGVPANEL.git
cd TGVPANEL

# 2. Install dependencies
npm ci

# 3. (Optional but recommended) Build the TypeScript services
npm run build

# 4. Run the installer (interactive; auto-detects capabilities)
sudo bash scripts/install.sh
```

Non-interactive install (for automation):

```bash
TGVPANEL_INSTALL_MODE=1        # 1=Panel+KVM+LXC, 2=KVM, 3=LXC, 4=Agent-only
TGVPANEL_NONINTERACTIVE=1
sudo bash scripts/install.sh
```

The installer creates the SQLite database, applies migrations, writes a
`.env`/secret vault, installs the systemd units, and starts the panel and (for
compute modes) the node agent.

## Configuration

Configuration is read from environment variables (see `.env.example`). Key
settings:

| Variable | Purpose |
|---|---|
| `PORT` | Panel HTTP port (default 8080). |
| `AGENT_PORT` | Node agent HTTPS port (default 8443). |
| `TGVPANEL_DB_PATH` | SQLite database file path. |
| `TGVPANEL_LXC_PATH` | LXC container root directory. |
| `SESSION_COOKIE_SECURE` | Set `1` behind HTTPS so session cookies are Secure. |
| `TRUSTED_PROXIES` | Comma-separated reverse-proxy IPs/CIDRs trusted for `X-Forwarded-For` (rate-limiter keying). |
| `TGVPANEL_ENABLE_NODE_SHELL` / `HKVM_ENABLE_NODE_SHELL` | Opt-in interactive node shell (disabled by default). |

Secrets (session secret, credential key) are stored in the encrypted vault
(`.tgvpanel-secret`). The credential key (`credentialKeyHex`) is used for
backup encryption-at-rest (AES-256-GCM) — **back it up and keep it private**;
losing it makes encrypted local LXC backups unrecoverable.

## First run

1. Start the panel: `npm start` (or the systemd unit installed by the script).
2. Open `http://<host>:8080` and complete the first-run admin setup.
3. Verify host capabilities: the panel reports KVM/LXC availability, `/dev/kvm`
   presence, QEMU architecture match, `lxcfs` mount state, and cgroup version.
   Address any warnings before provisioning guests.
4. For multi-node deployments, register remote nodes and install the Node Agent
   on each (see [`docs/MULTINODE_SETUP.md`](docs/MULTINODE_SETUP.md)).

## Verifying the install

```bash
npm run build     # TypeScript compiles cleanly
npm test          # 34/34 acceptance suites (uses a temp DB; does not touch production data)
node app.js       # Panel starts and listens on $PORT
```

## Troubleshooting

- **`/dev/kvm` unavailable:** enable hardware virtualization in the BIOS, or KVM
  guests will run under TCG (slow).
- **LXC RAM/CPU limits not enforced:** ensure cgroup v2 and `lxcfs` is mounted.
- **Rate-limiter blocks legitimate clients behind a proxy:** set `TRUSTED_PROXIES`
  to the proxy address.
- **Encrypted backups cannot be restored:** confirm the credential key in the
  vault matches the one used at encryption time.

For upgrades and migration between versions, see [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md).
