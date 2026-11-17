import crypto from 'crypto';
import os from 'os';
import path from 'path';
import { UnifiedDatabase } from './database';
import {
  encryptSecret,
  generateApiKeyPair,
  isEncryptedSecret,
} from '../security/crypto-vault';

export interface MigrationDefinition {
  version: number;
  name: string;
  up: (db: UnifiedDatabase) => Promise<void>;
}

export const BUILTIN_LXC_OS_CATALOG = [
  {
    key: 'ubuntu-20.04',
    label: 'Ubuntu 20.04 LTS (Focal)',
    alias: 'ubuntu:20.04',
    fallback: 'images:ubuntu/20.04',
    family: 'debian',
    category: 'Ubuntu',
    version: '20.04',
    icon: '/images/os/ubuntu.svg',
    minDiskGb: 5,
    minRamMb: 256,
    description: 'Long-Term Support release, supported until 2030.',
  },
  {
    key: 'ubuntu-22.04',
    label: 'Ubuntu 22.04 LTS (Jammy)',
    alias: 'ubuntu:22.04',
    fallback: 'images:ubuntu/22.04',
    family: 'debian',
    category: 'Ubuntu',
    version: '22.04',
    icon: '/images/os/ubuntu.svg',
    minDiskGb: 5,
    minRamMb: 256,
    description: 'Long-Term Support release, supported until 2032.',
  },
  {
    key: 'ubuntu-24.04',
    label: 'Ubuntu 24.04 LTS (Noble)',
    alias: 'ubuntu:24.04',
    fallback: 'images:ubuntu/24.04',
    family: 'debian',
    category: 'Ubuntu',
    version: '24.04',
    icon: '/images/os/ubuntu.svg',
    minDiskGb: 5,
    minRamMb: 256,
    description: 'Latest Long-Term Support release, supported until 2034.',
  },
  {
    key: 'debian-11',
    label: 'Debian 11 (Bullseye)',
    alias: 'images:debian/11',
    fallback: null,
    family: 'debian',
    category: 'Debian',
    version: '11',
    icon: '/images/os/debian.svg',
    minDiskGb: 3,
    minRamMb: 256,
    description: 'Stable, conservative defaults. LTS support.',
  },
  {
    key: 'debian-12',
    label: 'Debian 12 (Bookworm)',
    alias: 'images:debian/12',
    fallback: null,
    family: 'debian',
    category: 'Debian',
    version: '12',
    icon: '/images/os/debian.svg',
    minDiskGb: 3,
    minRamMb: 256,
    description: 'Current Debian stable. Recommended for most workloads.',
  },
  {
    key: 'debian-13',
    label: 'Debian 13 (Trixie)',
    alias: 'images:debian/13',
    fallback: 'images:debian/12',
    family: 'debian',
    category: 'Debian',
    version: '13',
    icon: '/images/os/debian.svg',
    minDiskGb: 3,
    minRamMb: 256,
    description: 'Latest Debian release.',
  },
  {
    key: 'centos-9-stream',
    label: 'CentOS Stream 9',
    alias: 'images:centos/9-Stream',
    fallback: null,
    family: 'rhel',
    category: 'CentOS Stream',
    version: '9-Stream',
    icon: '/images/os/centos.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Rolling upstream of RHEL 9.',
  },
  {
    key: 'centos-10-stream',
    label: 'CentOS Stream 10',
    alias: 'images:centos/10-Stream',
    fallback: 'images:centos/9-Stream',
    family: 'rhel',
    category: 'CentOS Stream',
    version: '10-Stream',
    icon: '/images/os/centos.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Rolling upstream of RHEL 10.',
  },
  {
    key: 'almalinux-8',
    label: 'AlmaLinux 8',
    alias: 'images:almalinux/8',
    fallback: null,
    family: 'rhel',
    category: 'AlmaLinux',
    version: '8',
    icon: '/images/os/almalinux.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Community-driven RHEL 8 rebuild.',
  },
  {
    key: 'almalinux-9',
    label: 'AlmaLinux 9',
    alias: 'images:almalinux/9',
    fallback: 'images:almalinux/8',
    family: 'rhel',
    category: 'AlmaLinux',
    version: '9',
    icon: '/images/os/almalinux.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Community-driven RHEL 9 rebuild.',
  },
  {
    key: 'almalinux-10',
    label: 'AlmaLinux 10',
    alias: 'images:almalinux/10',
    fallback: 'images:almalinux/9',
    family: 'rhel',
    category: 'AlmaLinux',
    version: '10',
    icon: '/images/os/almalinux.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Community-driven RHEL 10 rebuild.',
  },
  {
    key: 'rockylinux-8',
    label: 'Rocky Linux 8',
    alias: 'images:rockylinux/8',
    fallback: null,
    family: 'rhel',
    category: 'Rocky Linux',
    version: '8',
    icon: '/images/os/rocky.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Enterprise-grade RHEL 8 rebuild.',
  },
  {
    key: 'rockylinux-9',
    label: 'Rocky Linux 9',
    alias: 'images:rockylinux/9',
    fallback: 'images:rockylinux/8',
    family: 'rhel',
    category: 'Rocky Linux',
    version: '9',
    icon: '/images/os/rocky.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Enterprise-grade RHEL 9 rebuild.',
  },
  {
    key: 'rockylinux-10',
    label: 'Rocky Linux 10',
    alias: 'images:rockylinux/10',
    fallback: 'images:rockylinux/9',
    family: 'rhel',
    category: 'Rocky Linux',
    version: '10',
    icon: '/images/os/rocky.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Enterprise-grade RHEL 10 rebuild.',
  },
  {
    key: 'fedora-40',
    label: 'Fedora 40',
    alias: 'images:fedora/40',
    fallback: null,
    family: 'rhel',
    category: 'Fedora',
    version: '40',
    icon: '/images/os/fedora.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Cutting-edge Red Hat-based distribution.',
  },
  {
    key: 'fedora-41',
    label: 'Fedora 41',
    alias: 'images:fedora/41',
    fallback: 'images:fedora/40',
    family: 'rhel',
    category: 'Fedora',
    version: '41',
    icon: '/images/os/fedora.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Cutting-edge Red Hat-based distribution.',
  },
  {
    key: 'fedora-42',
    label: 'Fedora 42',
    alias: 'images:fedora/42',
    fallback: 'images:fedora/41',
    family: 'rhel',
    category: 'Fedora',
    version: '42',
    icon: '/images/os/fedora.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Cutting-edge Red Hat-based distribution.',
  },
  {
    key: 'fedora-43',
    label: 'Fedora 43',
    alias: 'images:fedora/43',
    fallback: 'images:fedora/42',
    family: 'rhel',
    category: 'Fedora',
    version: '43',
    icon: '/images/os/fedora.svg',
    minDiskGb: 5,
    minRamMb: 512,
    description: 'Latest Fedora release.',
  },
  {
    key: 'kali-rolling',
    label: 'Kali Linux',
    alias: 'images:kali',
    fallback: 'images:kali/current',
    family: 'debian',
    category: 'Kali',
    version: 'rolling',
    icon: '/images/os/kali.svg',
    minDiskGb: 8,
    minRamMb: 512,
    description: 'Debian-based security & penetration testing distribution.',
  },
  {
    key: 'proxmox-ve-8',
    label: 'Proxmox VE 8 (LXC)',
    alias: 'debian:12',
    fallback: 'images:debian/12',
    family: 'debian',
    category: 'Proxmox',
    version: '8',
    icon: '/images/os/proxmox.svg',
    minDiskGb: 40,
    minRamMb: 4096,
    description:
      'Proxmox Virtual Environment 8 hypervisor container (Debian 12 Bookworm base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).',
  },
  {
    key: 'proxmox-ve-9',
    label: 'Proxmox VE 9 (LXC)',
    alias: 'debian:13',
    fallback: 'images:debian/13',
    family: 'debian',
    category: 'Proxmox',
    version: '9',
    icon: '/images/os/proxmox.svg',
    minDiskGb: 40,
    minRamMb: 4096,
    description:
      'Proxmox Virtual Environment 9 hypervisor container (Debian 13 Trixie base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).',
  },
];

async function ensureColumn(
  db: UnifiedDatabase,
  table: string,
  column: string,
  definition: string
): Promise<void> {
  const cols = await db.all<{ name: string }>(`PRAGMA table_info(${table})`);
  if (cols.length > 0 && !cols.some((c) => c.name === column)) {
    await db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

export const MIGRATIONS: MigrationDefinition[] = [
  {
    version: 1,
    name: 'v001_extend_hkvm_core_tables',
    up: async (db) => {
      // Ensure core baseline tables exist when `npm run migrate` runs on a brand-new empty DB
      await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          email TEXT UNIQUE,
          full_name TEXT,
          role TEXT DEFAULT 'user',
          is_active BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME
        );

        CREATE TABLE IF NOT EXISTS vms (
          vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_name TEXT UNIQUE NOT NULL,
          os_type TEXT,
          template_type TEXT,
          hostname TEXT,
          username TEXT,
          password TEXT,
          memory INTEGER,
          cpus INTEGER,
          cpu_sockets INTEGER DEFAULT 1,
          cpu_cores INTEGER DEFAULT 2,
          cpu_threads INTEGER DEFAULT 1,
          cpu_model TEXT DEFAULT 'host',
          custom_cpu_name TEXT,
          machine_type TEXT DEFAULT 'pc',
          board_name TEXT DEFAULT 'Main-Board',
          product_name TEXT DEFAULT 'Virtual Machine',
          custom_smbios_manufacturer TEXT DEFAULT 'QEMU',
          disk_size TEXT,
          img_file TEXT,
          seed_file TEXT,
          disk_file TEXT,
          status TEXT DEFAULT 'stopped',
          pid INTEGER,
          uptime INTEGER DEFAULT 0,
          node_name TEXT DEFAULT 'localhost',
          smbios_manufacturer TEXT DEFAULT 'QEMU',
          smbios_product TEXT DEFAULT 'KVM Virtual Machine',
          smbios_version TEXT DEFAULT '1.0',
          smbios_serial TEXT,
          extra_args TEXT,
          enable_acpi BOOLEAN DEFAULT 1,
          enable_kvm BOOLEAN DEFAULT 1,
          network_type TEXT DEFAULT 'nat',
          ipv4_address TEXT,
          gateway TEXT,
          ipv4_gateway TEXT,
          netmask TEXT DEFAULT '24',
          ipv4_netmask TEXT DEFAULT '255.255.255.0',
          dns_servers TEXT DEFAULT '8.8.8.8,8.8.4.4',
          dns_primary TEXT DEFAULT '8.8.8.8',
          dns_secondary TEXT DEFAULT '8.8.4.4',
          ssh_port INTEGER,
          ssh_port_static INTEGER DEFAULT 22,
          http_port INTEGER DEFAULT 80,
          ipv6_address TEXT,
          ipv6_gateway TEXT,
          mac_address TEXT,
          bridge_interface TEXT,
          bridge_device TEXT DEFAULT 'vmbr0',
          vlan_id INTEGER,
          iso_attached TEXT,
          boot_from_iso BOOLEAN DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          owner_id INTEGER,
          FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS vm_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_id INTEGER,
          action TEXT,
          status TEXT,
          message TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vm_snapshots (
          snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
          vm_id INTEGER,
          snapshot_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          size_gb REAL,
          description TEXT,
          FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS os_templates (
          template_id INTEGER PRIMARY KEY AUTOINCREMENT,
          template_key TEXT UNIQUE NOT NULL,
          template_name TEXT NOT NULL,
          template_type TEXT DEFAULT 'cloud-init',
          icon TEXT,
          description TEXT,
          disk_size TEXT DEFAULT '20G',
          memory INTEGER DEFAULT 2048,
          cpus INTEGER DEFAULT 2,
          download_url TEXT,
          local_path TEXT,
          username TEXT,
          password TEXT,
          is_custom BOOLEAN DEFAULT 0,
          is_active BOOLEAN DEFAULT 1,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          setting_key TEXT UNIQUE NOT NULL,
          setting_value TEXT,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Extend users safely without overwriting existing rows
      await ensureColumn(db, 'users', 'two_factor_secret_enc', 'TEXT');
      await ensureColumn(db, 'users', 'two_factor_enabled', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'users', 'preferences', "TEXT DEFAULT '{}'");
      await ensureColumn(db, 'users', 'avatar_url', 'TEXT');
      await ensureColumn(db, 'users', 'hvm_legacy_id', 'INTEGER');

      // Extend KVM vms table with node_id, firmware (BIOS/UEFI), suspension, SSH keys, clone tracking
      await ensureColumn(db, 'vms', 'node_id', 'INTEGER DEFAULT 1');
      await ensureColumn(db, 'vms', 'firmware_type', "TEXT DEFAULT 'bios'");
      await ensureColumn(db, 'vms', 'boot_order', "TEXT DEFAULT 'disk,cdrom'");
      await ensureColumn(db, 'vms', 'suspended', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vms', 'suspended_reason', 'TEXT');
      await ensureColumn(db, 'vms', 'ssh_keys', 'TEXT');
      await ensureColumn(db, 'vms', 'storage_pool_id', 'INTEGER');
      await ensureColumn(db, 'vms', 'disk_format', "TEXT DEFAULT 'qcow2'");
      await ensureColumn(db, 'vms', 'clone_of', 'INTEGER');

      // Extend vm_snapshots for real qemu-img snapshot metadata
      await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
    },
  },
  {
    version: 2,
    name: 'v002_create_unified_virtualization_and_node_tables',
    up: async (db) => {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS nodes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          hostname TEXT,
          ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
          location TEXT DEFAULT 'Local Datacenter',
          url TEXT NOT NULL DEFAULT 'http://127.0.0.1:5050',
          is_local INTEGER DEFAULT 0,
          verify_ssl INTEGER DEFAULT 0,
          status TEXT DEFAULT 'unknown',
          health_status TEXT DEFAULT 'unknown',
          cpu_model TEXT DEFAULT 'Unknown',
          cpu_cores INTEGER DEFAULT 0,
          ram_total_mb INTEGER DEFAULT 0,
          disk_total_gb REAL DEFAULT 0,
          max_instances INTEGER DEFAULT 100,
          agent_version TEXT DEFAULT '4.0.0',
          lxc_version TEXT,
          qemu_version TEXT,
          network_interfaces TEXT DEFAULT '[]',
          ip_aliases TEXT DEFAULT '[]',
          tags TEXT DEFAULT '[]',
          circuit_breaker_open INTEGER DEFAULT 0,
          consecutive_failures INTEGER DEFAULT 0,
          last_failure_at DATETIME,
          last_seen DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS node_capabilities (
          node_id INTEGER PRIMARY KEY,
          supports_kvm INTEGER DEFAULT 1,
          supports_lxc INTEGER DEFAULT 1,
          kvm_available INTEGER DEFAULT 0,
          lxc_available INTEGER DEFAULT 0,
          lxc_driver TEXT DEFAULT 'none',
          storage_backends TEXT DEFAULT '["dir","qcow2","raw"]',
          network_bridges TEXT DEFAULT '[]',
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS node_credentials (
          node_id INTEGER PRIMARY KEY,
          api_key_prefix TEXT NOT NULL,
          api_key_hash TEXT NOT NULL,
          api_key_enc TEXT NOT NULL,
          hmac_secret_enc TEXT NOT NULL,
          tls_cert_fingerprint TEXT,
          rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_used_at DATETIME,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS storage_pools (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          engine TEXT NOT NULL DEFAULT 'both',
          pool_type TEXT NOT NULL DEFAULT 'dir',
          path TEXT NOT NULL,
          volume_group TEXT,
          thin_provisioning INTEGER DEFAULT 1,
          total_bytes INTEGER DEFAULT 0,
          used_bytes INTEGER DEFAULT 0,
          avail_bytes INTEGER DEFAULT 0,
          allocated_bytes INTEGER DEFAULT 0,
          is_default INTEGER DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          status TEXT DEFAULT 'online',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS lxc_instances (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          container_name TEXT UNIQUE NOT NULL,
          container_id TEXT,
          hostname TEXT NOT NULL,
          os_template TEXT NOT NULL DEFAULT 'ubuntu:22.04',
          os_family TEXT DEFAULT 'debian',
          os_version TEXT DEFAULT '22.04',
          cpu_cores INTEGER NOT NULL DEFAULT 1,
          cpu_limit TEXT,
          cpu_shares INTEGER DEFAULT 1024,
          ram_mb INTEGER NOT NULL DEFAULT 1024,
          swap_mb INTEGER NOT NULL DEFAULT 0,
          disk_gb INTEGER NOT NULL DEFAULT 10,
          storage_pool TEXT DEFAULT 'default',
          storage_pool_id INTEGER,
          rootfs_path TEXT,
          mount_points TEXT DEFAULT '[]',
          privileged INTEGER DEFAULT 0,
          nesting INTEGER DEFAULT 1,
          security_profile TEXT DEFAULT 'default',
          root_password_enc TEXT,
          ssh_port INTEGER DEFAULT 22,
          ssh_keys TEXT,
          ip_address TEXT,
          ip_cidr INTEGER DEFAULT 24,
          ip_alias TEXT,
          gateway TEXT,
          ipv6_address TEXT,
          ipv6_gateway TEXT,
          dns_servers TEXT DEFAULT '8.8.8.8,1.1.1.1',
          mac_address TEXT,
          bridge_name TEXT DEFAULT 'lxcbr0',
          network_mode TEXT DEFAULT 'nat',
          is_routed_ip INTEGER DEFAULT 0,
          status TEXT DEFAULT 'stopped',
          suspended INTEGER DEFAULT 0,
          suspended_reason TEXT,
          suspension_history TEXT DEFAULT '[]',
          whitelisted INTEGER DEFAULT 0,
          shared_with TEXT DEFAULT '[]',
          bandwidth_quota_gb INTEGER DEFAULT 0,
          bandwidth_used_gb REAL DEFAULT 0.0,
          bandwidth_reset_date DATETIME,
          network_ingress_mbps INTEGER DEFAULT 0,
          network_egress_mbps INTEGER DEFAULT 0,
          network_priority INTEGER DEFAULT 5,
          snapshot_limit INTEGER DEFAULT 5,
          install_progress INTEGER DEFAULT 100,
          install_message TEXT DEFAULT 'Ready',
          notes TEXT,
          metadata TEXT DEFAULT '{}',
          expires_at DATETIME,
          expiration_days INTEGER DEFAULT 0,
          auto_suspend_enabled INTEGER DEFAULT 0,
          last_renewed_at DATETIME,
          last_started DATETIME,
          last_stopped DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS instances (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          engine TEXT NOT NULL CHECK(engine IN ('kvm', 'lxc')),
          ref_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          hostname TEXT,
          owner_id INTEGER,
          node_id INTEGER NOT NULL DEFAULT 1,
          status TEXT DEFAULT 'stopped',
          suspended INTEGER DEFAULT 0,
          os_label TEXT,
          cpu_cores INTEGER DEFAULT 1,
          ram_mb INTEGER DEFAULT 1024,
          disk_gb REAL DEFAULT 10,
          primary_ip TEXT,
          shared_with TEXT DEFAULT '[]',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(engine, ref_id),
          FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL,
          FOREIGN KEY(node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS lxc_templates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          template_key TEXT UNIQUE NOT NULL,
          label TEXT NOT NULL,
          image_alias TEXT NOT NULL,
          fallback_alias TEXT,
          family TEXT DEFAULT 'debian',
          category TEXT DEFAULT 'Linux',
          version TEXT,
          arch TEXT DEFAULT 'amd64',
          description TEXT,
          icon TEXT DEFAULT 'linux',
          min_disk_gb INTEGER DEFAULT 5,
          min_ram_mb INTEGER DEFAULT 256,
          download_url TEXT,
          local_path TEXT,
          sha256 TEXT,
          size_bytes INTEGER DEFAULT 0,
          download_status TEXT DEFAULT 'remote',
          download_progress INTEGER DEFAULT 0,
          verified INTEGER DEFAULT 0,
          is_custom INTEGER DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
    },
  },
  {
    version: 3,
    name: 'v003_create_network_backup_migration_monitoring_security_tables',
    up: async (db) => {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS ip_allocations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          ip_address TEXT UNIQUE NOT NULL,
          cidr INTEGER DEFAULT 24,
          gateway TEXT,
          ip_version INTEGER DEFAULT 4,
          bridge TEXT DEFAULT 'vmbr0',
          vlan_id INTEGER,
          mac_address TEXT,
          is_routed INTEGER DEFAULT 0,
          ip_alias TEXT,
          instance_type TEXT,
          instance_ref_id INTEGER,
          assigned_user_id INTEGER,
          notes TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
          FOREIGN KEY(assigned_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS port_allocations (
          user_id INTEGER PRIMARY KEY,
          allocated_ports INTEGER DEFAULT 10,
          used_ports INTEGER DEFAULT 0,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS port_forwards (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER,
          container_name TEXT NOT NULL,
          guest_port INTEGER NOT NULL,
          host_port INTEGER NOT NULL,
          protocol TEXT NOT NULL DEFAULT 'tcp,udp',
          description TEXT,
          is_custom INTEGER DEFAULT 0,
          is_bulk INTEGER DEFAULT 0,
          bulk_range_id TEXT,
          created_by_admin INTEGER DEFAULT 0,
          hits INTEGER DEFAULT 0,
          last_used DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(node_id, host_port, protocol),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS container_snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER NOT NULL,
          snapshot_name TEXT NOT NULL,
          description TEXT,
          size_bytes INTEGER DEFAULT 0,
          snapshot_type TEXT DEFAULT 'manual',
          stateful INTEGER DEFAULT 0,
          file_path TEXT,
          sha256 TEXT,
          status TEXT DEFAULT 'completed',
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS container_backups (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL DEFAULT 1,
          backup_name TEXT NOT NULL,
          file_path TEXT NOT NULL,
          size_bytes INTEGER DEFAULT 0,
          sha256 TEXT,
          verified INTEGER DEFAULT 0,
          progress INTEGER DEFAULT 100,
          status TEXT DEFAULT 'completed',
          logs TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS backup_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          enabled INTEGER DEFAULT 1,
          frequency TEXT NOT NULL DEFAULT 'daily',
          retention_count INTEGER DEFAULT 7,
          last_run DATETIME,
          next_run DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(instance_type, instance_ref_id)
        );

        CREATE TABLE IF NOT EXISTS snapshot_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          enabled INTEGER DEFAULT 1,
          frequency TEXT NOT NULL DEFAULT 'daily',
          retention_count INTEGER DEFAULT 7,
          last_run DATETIME,
          next_run DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(instance_type, instance_ref_id)
        );

        CREATE TABLE IF NOT EXISTS vps_migrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER NOT NULL,
          container_name TEXT NOT NULL,
          source_node_id INTEGER NOT NULL,
          target_node_id INTEGER NOT NULL,
          strategy TEXT NOT NULL DEFAULT 'offline_snapshot_transfer',
          status TEXT NOT NULL DEFAULT 'preparing',
          progress INTEGER DEFAULT 0,
          message TEXT,
          snapshot_name TEXT,
          transfer_id TEXT,
          transfer_sha256 TEXT,
          transfer_bytes INTEGER DEFAULT 0,
          was_running INTEGER DEFAULT 0,
          destination_verified INTEGER DEFAULT 0,
          source_deleted INTEGER DEFAULT 0,
          error_message TEXT,
          rollback_log TEXT,
          initiated_by INTEGER,
          started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          committed_at DATETIME,
          completed_at DATETIME,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE,
          FOREIGN KEY(source_node_id) REFERENCES nodes(id),
          FOREIGN KEY(target_node_id) REFERENCES nodes(id)
        );

        CREATE TABLE IF NOT EXISTS vps_expiration (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lxc_id INTEGER UNIQUE NOT NULL,
          expires_at DATETIME,
          expiration_days INTEGER DEFAULT 0,
          auto_suspend_enabled INTEGER DEFAULT 0,
          warned_at DATETIME,
          last_renewed_at DATETIME,
          renewed_by INTEGER,
          renewal_count INTEGER DEFAULT 0,
          notes TEXT,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(lxc_id) REFERENCES lxc_instances(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vps_metrics (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          instance_type TEXT NOT NULL DEFAULT 'lxc',
          instance_ref_id INTEGER NOT NULL,
          node_id INTEGER DEFAULT 1,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          ram_percent REAL DEFAULT 0,
          swap_used_mb REAL DEFAULT 0,
          disk_used_bytes INTEGER DEFAULT 0,
          disk_total_bytes INTEGER DEFAULT 0,
          disk_percent REAL DEFAULT 0,
          disk_read_bytes INTEGER DEFAULT 0,
          disk_write_bytes INTEGER DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          processes INTEGER DEFAULT 0,
          load_1 REAL DEFAULT 0,
          load_5 REAL DEFAULT 0,
          load_15 REAL DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS node_metrics (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          ram_percent REAL DEFAULT 0,
          disk_used_bytes INTEGER DEFAULT 0,
          disk_total_bytes INTEGER DEFAULT 0,
          disk_percent REAL DEFAULT 0,
          disk_read_bytes INTEGER DEFAULT 0,
          disk_write_bytes INTEGER DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          load_1 REAL DEFAULT 0,
          load_5 REAL DEFAULT 0,
          load_15 REAL DEFAULT 0,
          uptime_seconds INTEGER DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          type TEXT NOT NULL DEFAULT 'info',
          title TEXT NOT NULL,
          message TEXT NOT NULL,
          is_read INTEGER DEFAULT 0,
          data TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS webhooks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          url TEXT NOT NULL,
          events TEXT NOT NULL DEFAULT '["*"]',
          secret_enc TEXT,
          is_active INTEGER DEFAULT 1,
          last_triggered_at DATETIME,
          last_status_code INTEGER,
          failure_count INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS api_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          description TEXT,
          key_prefix TEXT NOT NULL,
          key_hash TEXT UNIQUE NOT NULL,
          permissions TEXT DEFAULT '["read","write"]',
          is_active INTEGER DEFAULT 1,
          last_used_at DATETIME,
          expires_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS agent_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_token TEXT UNIQUE NOT NULL,
          user_id INTEGER NOT NULL,
          node_id INTEGER NOT NULL,
          session_type TEXT NOT NULL DEFAULT 'lxc_shell',
          target_name TEXT,
          remote_session_id TEXT,
          status TEXT DEFAULT 'active',
          ip_address TEXT,
          started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_active_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          closed_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          action TEXT NOT NULL,
          resource_type TEXT,
          resource_id TEXT,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          ip_address TEXT,
          used INTEGER DEFAULT 0,
          used_at DATETIME,
          expires_at DATETIME NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS os_icons (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          os_name TEXT UNIQUE NOT NULL,
          icon_path TEXT NOT NULL,
          uploaded_by INTEGER,
          uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
        );

        -- Performance Indexes
        CREATE INDEX IF NOT EXISTS idx_instances_owner ON instances(owner_id);
        CREATE INDEX IF NOT EXISTS idx_instances_node ON instances(node_id);
        CREATE INDEX IF NOT EXISTS idx_instances_engine_status ON instances(engine, status);
        CREATE INDEX IF NOT EXISTS idx_lxc_user ON lxc_instances(user_id);
        CREATE INDEX IF NOT EXISTS idx_lxc_node ON lxc_instances(node_id);
        CREATE INDEX IF NOT EXISTS idx_lxc_status ON lxc_instances(status);
        CREATE INDEX IF NOT EXISTS idx_lxc_expires ON lxc_instances(expires_at);
        CREATE INDEX IF NOT EXISTS idx_port_forwards_user ON port_forwards(user_id);
        CREATE INDEX IF NOT EXISTS idx_port_forwards_container ON port_forwards(container_name);
        CREATE INDEX IF NOT EXISTS idx_vps_metrics_lookup ON vps_metrics(instance_type, instance_ref_id, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_node_metrics_lookup ON node_metrics(node_id, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);
      `);
    },
  },
  {
    version: 4,
    name: 'v004_seed_defaults_encrypt_credentials_and_sync_instances',
    up: async (db) => {
      // 1. Seed default localhost node if no nodes exist yet
      const existingNode = await db.get<{ id: number }>(`SELECT id FROM nodes ORDER BY id ASC LIMIT 1`);
      let localNodeId = existingNode?.id;
      if (!localNodeId) {
        const cpus = os.cpus();
        const agentPort = parseInt(process.env.LOCAL_NODE_AGENT_PORT || '5050', 10);
        const ins = await db.run(
          `INSERT INTO nodes (name, hostname, ip_address, location, url, is_local, verify_ssl, status, health_status, cpu_model, cpu_cores, ram_total_mb)
           VALUES (?, ?, '127.0.0.1', 'Primary Local Host', ?, 1, 0, 'online', 'healthy', ?, ?, ?)`,
          [
            'localhost',
            os.hostname(),
            `http://127.0.0.1:${agentPort}`,
            cpus[0]?.model || 'Linux Host CPU',
            cpus.length || 1,
            Math.round(os.totalmem() / (1024 * 1024)),
          ]
        );
        localNodeId = ins.lastID;

        const keyPair = generateApiKeyPair('hkvm_node');
        const hmacSecret = crypto.randomBytes(32).toString('hex');
        await db.run(
          `INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc)
           VALUES (?, ?, ?, ?, ?)`,
          [
            localNodeId,
            keyPair.keyPrefix,
            keyPair.keyHash,
            encryptSecret(keyPair.rawKey),
            encryptSecret(hmacSecret),
          ]
        );

        await db.run(
          `INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc, kvm_available, lxc_available)
           VALUES (?, 1, 1, 0, 0)`,
          [localNodeId]
        );
      }

      // 2. Seed default KVM & LXC storage pools if empty
      const poolCount = await db.get<{ cnt: number }>(`SELECT COUNT(*) as cnt FROM storage_pools`);
      if (!poolCount || poolCount.cnt === 0) {
        const vmPath =
          process.env.TGVPANEL_VM_DIR || process.env.HKVM_VM_DIR || path.join(os.homedir(), 'vms');
        const lxcPath =
          process.env.TGVPANEL_LXC_DIR || process.env.HKVM_LXC_DIR || '/var/lib/lxc';
        await db.run(
          `INSERT INTO storage_pools (name, node_id, engine, pool_type, path, thin_provisioning, is_default, is_active, status)
           VALUES ('local-kvm', ?, 'kvm', 'qcow2', ?, 1, 1, 1, 'online')`,
          [localNodeId, vmPath]
        );
        await db.run(
          `INSERT INTO storage_pools (name, node_id, engine, pool_type, path, thin_provisioning, is_default, is_active, status)
           VALUES ('local-lxc', ?, 'lxc', 'dir', ?, 0, 1, 1, 'online')`,
          [localNodeId, lxcPath]
        );
      }

      // 3. Seed built-in HVM V9 LXC OS template catalog
      for (const tpl of BUILTIN_LXC_OS_CATALOG) {
        await db.run(
          `INSERT OR IGNORE INTO lxc_templates
           (template_key, label, image_alias, fallback_alias, family, category, version, icon, min_disk_gb, min_ram_mb, description, is_custom, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)`,
          [
            tpl.key,
            tpl.label,
            tpl.alias,
            tpl.fallback,
            tpl.family,
            tpl.category,
            tpl.version,
            tpl.icon,
            tpl.minDiskGb,
            tpl.minRamMb,
            tpl.description,
          ]
        );
      }

      // 4. Encrypt any legacy plaintext VM passwords & template passwords in-place
      const vms = await db.all<{
        vm_id: number;
        vm_name: string;
        hostname: string;
        owner_id: number | null;
        node_id: number | null;
        status: string;
        os_type: string;
        cpus: number;
        memory: number;
        disk_size: string;
        ipv4_address: string | null;
        password: string | null;
      }>(`SELECT * FROM vms`);

      for (const vm of vms) {
        if (vm.password && !isEncryptedSecret(vm.password)) {
          await db.run(`UPDATE vms SET password = ? WHERE vm_id = ?`, [
            encryptSecret(vm.password),
            vm.vm_id,
          ]);
        }
        const diskGb = parseFloat(String(vm.disk_size || '20').replace(/[^0-9.]/g, '')) || 20;
        await db.run(
          `INSERT OR REPLACE INTO instances
           (engine, ref_id, name, hostname, owner_id, node_id, status, os_label, cpu_cores, ram_mb, disk_gb, primary_ip)
           VALUES ('kvm', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            vm.vm_id,
            vm.vm_name,
            vm.hostname || vm.vm_name,
            vm.owner_id,
            vm.node_id || localNodeId,
            vm.status || 'stopped',
            vm.os_type || 'KVM Linux',
            vm.cpus || 1,
            vm.memory || 1024,
            diskGb,
            vm.ipv4_address || null,
          ]
        );
      }

      // 5. Ensure default unified settings exist without overwriting customized values
      const defaultV3Settings: Record<string, string> = {
        panel_version: 'V4.0',
        maintenance_mode: '0',
        maintenance_message: 'TGVPANEL is currently undergoing scheduled maintenance.',
        cpu_threshold: '90',
        ram_threshold: '90',
        auto_suspend_high_usage: '0',
        backup_enabled: '1',
        backup_retention: '7',
        default_user_port_quota: '10',
      };
      for (const [key, val] of Object.entries(defaultV3Settings)) {
        const existing = await db.get<{ setting_value: string }>(
          `SELECT setting_value FROM settings WHERE setting_key = ?`,
          [key]
        );
        if (!existing) {
          await db.run(
            `INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
            [key, val]
          );
        }
      }
    },
  },
  {
    version: 5,
    name: 'v005_unify_service_columns_and_auxiliary_tables',
    up: async (db) => {
      // Extend vms for unified KVM telemetry & sharing
      await ensureColumn(db, 'vms', 'pid', 'INTEGER');
      await ensureColumn(db, 'vms', 'shared_with', "TEXT DEFAULT '[]'");
      await ensureColumn(db, 'vms', 'expires_at', 'DATETIME');

      // Extend nodes, capabilities & credentials
      await ensureColumn(db, 'nodes', 'maintenance_mode', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'nodes', 'mtls_enabled', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'nodes', 'last_heartbeat', 'DATETIME');
      await ensureColumn(db, 'nodes', 'circuit_state', "TEXT DEFAULT 'closed'");
      await ensureColumn(db, 'nodes', 'notes', 'TEXT');

      await ensureColumn(db, 'node_capabilities', 'nested_virt', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'node_capabilities', 'cgroup_version', 'INTEGER DEFAULT 2');
      await ensureColumn(db, 'node_capabilities', 'network_backends', "TEXT DEFAULT '[]'");
      await ensureColumn(db, 'node_capabilities', 'qemu_version', 'TEXT');
      await ensureColumn(db, 'node_capabilities', 'lxc_version', 'TEXT');
      await ensureColumn(db, 'node_capabilities', 'kernel_version', 'TEXT');

      await ensureColumn(db, 'node_credentials', 'tls_ca_pem', 'TEXT');
      await ensureColumn(db, 'node_credentials', 'tls_client_cert_pem', 'TEXT');
      await ensureColumn(db, 'node_credentials', 'tls_client_key_enc', 'TEXT');

      // Extend lxc_instances & lxc_templates
      await ensureColumn(db, 'lxc_instances', 'arch', "TEXT DEFAULT 'amd64'");
      await ensureColumn(db, 'lxc_instances', 'cpu_limit_pct', 'INTEGER DEFAULT 100');
      await ensureColumn(db, 'lxc_instances', 'cpu_pinning', 'TEXT');
      await ensureColumn(db, 'lxc_instances', 'rootfs_storage_type', "TEXT DEFAULT 'dir'");
      await ensureColumn(db, 'lxc_instances', 'autostart', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'lxc_instances', 'bridge', "TEXT DEFAULT 'lxcbr0'");
      await ensureColumn(db, 'lxc_instances', 'vlan_id', 'INTEGER');

      await ensureColumn(db, 'lxc_templates', 'slug', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'name', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'distro', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'release', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'variant', "TEXT DEFAULT 'default'");
      await ensureColumn(db, 'lxc_templates', 'file_path', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'checksum_sha256', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'enabled', 'INTEGER DEFAULT 1');

      const tpls = await db.all<any>(`SELECT * FROM lxc_templates`);
      for (const t of tpls) {
        const alias = String(t.image_alias || 'ubuntu:24.04').replace(/^images:/, '');
        const parts = alias.split(/[:/]/);
        const distro = parts[0] || 'ubuntu';
        const release = parts[1] || t.version || '24.04';
        await db.run(
          `UPDATE lxc_templates
           SET slug = COALESCE(slug, template_key),
               name = COALESCE(name, label),
               distro = COALESCE(distro, ?),
               release = COALESCE(release, ?),
               enabled = COALESCE(enabled, is_active, 1)
           WHERE id = ?`,
          [distro, release, t.id]
        );
      }
      await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_lxc_templates_slug ON lxc_templates(slug)`);

      // Extend storage_pools & add storage_volumes
      await ensureColumn(db, 'storage_pools', 'engine_scope', "TEXT DEFAULT 'both'");
      await ensureColumn(db, 'storage_pools', 'available_bytes', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'storage_pools', 'overcommit_ratio', 'REAL DEFAULT 1.5');
      await ensureColumn(db, 'storage_pools', 'enabled', 'INTEGER DEFAULT 1');
      await db.run(`UPDATE storage_pools SET engine_scope = COALESCE(engine, 'both')`);

      await db.exec(`
        CREATE TABLE IF NOT EXISTS storage_volumes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          pool_id INTEGER NOT NULL,
          instance_type TEXT NOT NULL,
          instance_ref_id INTEGER NOT NULL,
          volume_name TEXT NOT NULL,
          format TEXT DEFAULT 'qcow2',
          file_path TEXT NOT NULL,
          size_bytes INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(pool_id) REFERENCES storage_pools(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS network_pools (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          name TEXT NOT NULL,
          network_type TEXT NOT NULL DEFAULT 'bridge',
          bridge_name TEXT NOT NULL DEFAULT 'lxcbr0',
          cidr TEXT,
          gateway TEXT,
          ipv6_cidr TEXT,
          ipv6_gateway TEXT,
          vlan_id INTEGER,
          dns_servers TEXT DEFAULT '["1.1.1.1","8.8.8.8"]',
          enabled INTEGER DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL DEFAULT 1,
          instance_type TEXT,
          instance_ref_id INTEGER,
          direction TEXT NOT NULL DEFAULT 'in',
          action TEXT NOT NULL DEFAULT 'ACCEPT',
          protocol TEXT NOT NULL DEFAULT 'tcp',
          source_cidr TEXT,
          dest_port TEXT,
          priority INTEGER DEFAULT 100,
          enabled INTEGER DEFAULT 1,
          comment TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS metrics_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          target_type TEXT NOT NULL,
          target_id INTEGER NOT NULL,
          cpu_percent REAL DEFAULT 0,
          ram_used_mb REAL DEFAULT 0,
          ram_total_mb REAL DEFAULT 0,
          disk_used_gb REAL DEFAULT 0,
          disk_total_gb REAL DEFAULT 0,
          net_rx_bytes INTEGER DEFAULT 0,
          net_tx_bytes INTEGER DEFAULT 0,
          load_avg_1 REAL DEFAULT 0,
          recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_history_target ON metrics_history(target_type, target_id, recorded_at);

        CREATE TABLE IF NOT EXISTS alert_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          target_scope TEXT NOT NULL DEFAULT 'node',
          metric TEXT NOT NULL DEFAULT 'cpu_percent',
          operator TEXT NOT NULL DEFAULT '>=',
          threshold REAL NOT NULL DEFAULT 90,
          severity TEXT NOT NULL DEFAULT 'warning',
          enabled INTEGER DEFAULT 1,
          last_triggered_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await ensureColumn(db, 'ip_allocations', 'pool_id', 'INTEGER');
      await ensureColumn(db, 'ip_allocations', 'version', 'INTEGER DEFAULT 4');
      await ensureColumn(db, 'ip_allocations', 'status', "TEXT DEFAULT 'available'");
      await ensureColumn(db, 'port_forwards', 'guest_ip', 'TEXT');
      await ensureColumn(db, 'container_backups', 'checksum_sha256', 'TEXT');
      await ensureColumn(db, 'vps_migrations', 'instance_type', "TEXT DEFAULT 'lxc'");
      await ensureColumn(db, 'vps_migrations', 'instance_ref_id', 'INTEGER');
      await ensureColumn(db, 'vps_migrations', 'migration_mode', "TEXT DEFAULT 'offline_snapshot'");
      await ensureColumn(db, 'vps_migrations', 'checksum_sha256', 'TEXT');
      await ensureColumn(db, 'vps_migrations', 'bytes_transferred', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vps_migrations', 'rollback_performed', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'api_keys', 'ip_whitelist', 'TEXT');
      await ensureColumn(db, 'password_reset_tokens', 'requested_ip', 'TEXT');
    },
  },
  {
    version: 6,
    name: 'v006_add_lxc_kvm_nesting',
    up: async (db) => {
      await ensureColumn(db, 'lxc_instances', 'kvm_nesting', 'INTEGER DEFAULT 0');
    },
  },
  {
    version: 7,
    name: 'v007_rebrand_default_admin_email',
    up: async (db) => {
      await db.run(
        `UPDATE users
         SET email = 'admin@shadowgamerind.local'
         WHERE LOWER(email) IN ('admin@hopingboyz.local', 'admin@hopingboy.local')`
      );
    },
  },
  {
    version: 8,
    name: 'v008_rebrand_visible_hkvm_to_tgvpanel',
    up: async (db) => {
      await db.run(
        `UPDATE settings
         SET setting_value = 'TGVPANEL', updated_at = datetime('now')
         WHERE setting_key = 'site_name'
           AND LOWER(TRIM(setting_value)) IN ('hkvm', 'hkvm panel', 'hkvm v3', 'my custom panel')`
      );
      await db.run(
        `UPDATE settings
         SET setting_value = 'TGVPANEL V3.0', updated_at = datetime('now')
         WHERE setting_key = 'panel_title'
           AND LOWER(TRIM(setting_value)) LIKE 'hkvm%'`
      );
      await db.run(
        `UPDATE settings
         SET setting_value = 'TGVPANEL is currently undergoing scheduled maintenance.', updated_at = datetime('now')
         WHERE setting_key = 'maintenance_message'
           AND setting_value = 'HKVM is currently undergoing scheduled maintenance.'`
      );
    },
  },
  {
    version: 9,
    name: 'v009_cascade_vm_child_foreign_keys',
    up: async (db) => {
      const hasVms = await db.get<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vms'`
      );
      if (!hasVms) return;

      const hasVmLogs = await db.get<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_logs'`
      );
      if (hasVmLogs) {
        await db.exec(`
          CREATE TABLE vm_logs_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vm_id INTEGER,
            action TEXT,
            status TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
          );
          INSERT INTO vm_logs_new (id, vm_id, action, status, message, timestamp)
          SELECT id, vm_id, action, status, message, timestamp
          FROM vm_logs
          WHERE vm_id IS NULL OR vm_id IN (SELECT vm_id FROM vms);
          DROP TABLE vm_logs;
          ALTER TABLE vm_logs_new RENAME TO vm_logs;
          CREATE INDEX IF NOT EXISTS idx_vm_logs_vm_id ON vm_logs(vm_id);
        `);
      }

      const hasVmSnapshots = await db.get<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_snapshots'`
      );
      if (hasVmSnapshots) {
        await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
        await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
        await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
        await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
        await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
        await db.exec(`
          CREATE TABLE vm_snapshots_new (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vm_id INTEGER,
            snapshot_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            size_gb REAL,
            description TEXT,
            tag_name TEXT,
            file_path TEXT,
            sha256 TEXT,
            stateful INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY(vm_id) REFERENCES vms(vm_id) ON DELETE CASCADE
          );
          INSERT INTO vm_snapshots_new (snapshot_id, vm_id, snapshot_name, created_at, size_gb, description, tag_name, file_path, sha256, stateful, status)
          SELECT snapshot_id, vm_id, snapshot_name, created_at, size_gb, description, tag_name, file_path, sha256, COALESCE(stateful, 0), COALESCE(status, 'completed')
          FROM vm_snapshots
          WHERE vm_id IS NULL OR vm_id IN (SELECT vm_id FROM vms);
          DROP TABLE vm_snapshots;
          ALTER TABLE vm_snapshots_new RENAME TO vm_snapshots;
          CREATE INDEX IF NOT EXISTS idx_vm_snapshots_vm_id ON vm_snapshots(vm_id);
        `);
      }

      // Also clean up any orphaned `instances` registry rows whose KVM VM was already deleted
      const hasInstances = await db.get<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'instances'`
      );
      if (hasInstances) {
        await db.run(
          `DELETE FROM instances
           WHERE engine = 'kvm' AND ref_id NOT IN (SELECT vm_id FROM vms)`
        );
      }
    },
  },
  {
    version: 10,
    name: 'v010_ensure_vm_snapshots_extended_columns',
    up: async (db) => {
      const hasVmSnapshots = await db.get<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vm_snapshots'`
      );
      if (!hasVmSnapshots) return;
      await ensureColumn(db, 'vm_snapshots', 'tag_name', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'file_path', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'sha256', 'TEXT');
      await ensureColumn(db, 'vm_snapshots', 'stateful', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vm_snapshots', 'status', "TEXT DEFAULT 'completed'");
    },
  },
  {
    version: 11,
    name: 'v011_multi_node_pairing_and_error_tracking',
    up: async (db) => {
      await ensureColumn(db, 'nodes', 'last_error', 'TEXT');
      await ensureColumn(db, 'nodes', 'last_error_at', 'DATETIME');

      await db.exec(`
        CREATE TABLE IF NOT EXISTS node_join_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          token_prefix TEXT NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          controller_url TEXT,
          expires_at DATETIME NOT NULL,
          used_at DATETIME,
          used_from_ip TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_node_join_tokens_node_id ON node_join_tokens(node_id);
      `);
    },
  },
  {
    version: 12,
    name: 'v012_proxmox_lxc_images_and_os_logos',
    up: async (db) => {
      await ensureColumn(db, 'lxc_templates', 'proxmox_codename', 'TEXT');
      await ensureColumn(db, 'lxc_templates', 'icon_path', 'TEXT');

      // Normalize legacy bare icon names ('ubuntu', 'alma', ...) to local SVG paths
      await db.run(
        `UPDATE lxc_templates
         SET icon = CASE
           WHEN LOWER(COALESCE(icon, '')) IN ('ubuntu', 'ubuntu.svg') THEN '/images/os/ubuntu.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('debian', 'debian.svg') THEN '/images/os/debian.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('centos', 'centos.svg') THEN '/images/os/centos.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('alma', 'almalinux', 'almalinux.svg') THEN '/images/os/almalinux.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('rocky', 'rocky.svg') THEN '/images/os/rocky.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('fedora', 'fedora.svg') THEN '/images/os/fedora.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('kali', 'kali.svg') THEN '/images/os/kali.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('proxmox', 'proxmox.svg', 'pve') THEN '/images/os/proxmox.svg'
           WHEN LOWER(COALESCE(icon, '')) IN ('alpine', 'alpine.svg') THEN '/images/os/alpine.svg'
           WHEN COALESCE(icon, '') = '' OR LOWER(COALESCE(icon, '')) = 'linux' THEN '/images/os/linux.svg'
           ELSE icon
         END,
         icon_path = CASE
           WHEN COALESCE(icon_path, '') = '' THEN icon
           ELSE icon_path
         END`
      );
      // Second pass: copy normalized icon into icon_path where still empty
      await db.run(
        `UPDATE lxc_templates SET icon_path = icon WHERE COALESCE(icon_path, '') = ''`
      );

      // Seed Proxmox VE 8/9 LXC hypervisor images (Debian base + first-boot PVE bootstrap)
      const proxmoxSeed: Array<{
        key: string;
        label: string;
        alias: string;
        fallback: string;
        family: string;
        category: string;
        version: string;
        icon: string;
        minDiskGb: number;
        minRamMb: number;
        description: string;
        distro: string;
        release: string;
        codename: string;
      }> = [
        {
          key: 'proxmox-ve-8',
          label: 'Proxmox VE 8 (LXC)',
          alias: 'debian:12',
          fallback: 'images:debian/12',
          family: 'debian',
          category: 'Proxmox',
          version: '8',
          icon: '/images/os/proxmox.svg',
          minDiskGb: 40,
          minRamMb: 4096,
          description:
            'Proxmox Virtual Environment 8 hypervisor container (Debian 12 Bookworm base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).',
          distro: 'debian',
          release: '12',
          codename: 'bookworm',
        },
        {
          key: 'proxmox-ve-9',
          label: 'Proxmox VE 9 (LXC)',
          alias: 'debian:13',
          fallback: 'images:debian/13',
          family: 'debian',
          category: 'Proxmox',
          version: '9',
          icon: '/images/os/proxmox.svg',
          minDiskGb: 40,
          minRamMb: 4096,
          description:
            'Proxmox Virtual Environment 9 hypervisor container (Debian 13 Trixie base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).',
          distro: 'debian',
          release: '13',
          codename: 'trixie',
        },
      ];
      for (const tpl of proxmoxSeed) {
        await db.run(
          `INSERT OR IGNORE INTO lxc_templates
           (template_key, label, image_alias, fallback_alias, family, category, version, icon, icon_path, min_disk_gb, min_ram_mb, description, is_custom, is_active, slug, name, distro, release, enabled, proxmox_codename)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, 1, ?)`,
          [
            tpl.key,
            tpl.label,
            tpl.alias,
            tpl.fallback,
            tpl.family,
            tpl.category,
            tpl.version,
            tpl.icon,
            tpl.icon,
            tpl.minDiskGb,
            tpl.minRamMb,
            tpl.description,
            tpl.key,
            tpl.label,
            tpl.distro,
            tpl.release,
            tpl.codename,
          ]
        );
        // Backfill codename/icon for installs that already had the row from a partial seed
        await db.run(
          `UPDATE lxc_templates SET proxmox_codename = COALESCE(proxmox_codename, ?), icon = ?, icon_path = ? WHERE template_key = ?`,
          [tpl.codename, tpl.icon, tpl.icon, tpl.key]
        );
      }

      // Seed os_icons lookup table for admin icon management
      const osIcons: Array<[string, string]> = [
        ['ubuntu', '/images/os/ubuntu.svg'],
        ['debian', '/images/os/debian.svg'],
        ['centos', '/images/os/centos.svg'],
        ['almalinux', '/images/os/almalinux.svg'],
        ['rocky', '/images/os/rocky.svg'],
        ['fedora', '/images/os/fedora.svg'],
        ['kali', '/images/os/kali.svg'],
        ['alpine', '/images/os/alpine.svg'],
        ['proxmox', '/images/os/proxmox.svg'],
        ['linux', '/images/os/linux.svg'],
      ];
      for (const [osName, iconPath] of osIcons) {
        await db.run(
          `INSERT OR IGNORE INTO os_icons (os_name, icon_path) VALUES (?, ?)`,
          [osName, iconPath]
        );
      }
    },
  },
  {
    version: 13,
    name: 'v013_clarify_proxmox_lxc_debian_base_descriptions',
    up: async (db) => {
      await db.run(
        `UPDATE lxc_templates
         SET description = 'Proxmox Virtual Environment 8 hypervisor container (Debian 12 Bookworm base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).'
         WHERE template_key = 'proxmox-ve-8'`
      );
      await db.run(
        `UPDATE lxc_templates
         SET description = 'Proxmox Virtual Environment 9 hypervisor container (Debian 13 Trixie base + first-boot PVE install, HTTPS Web UI on :8006; neofetch shows Debian by design).'
         WHERE template_key = 'proxmox-ve-9'`
      );
    },
  },
  {
    version: 14,
    name: 'v014_tgvpanel_v4_release_version_defaults',
    up: async (db) => {
      // Upgrade only panel-owned defaults; preserve operator-customized settings verbatim.
      await db.run(
        `UPDATE settings
         SET setting_value = 'V4.0', updated_at = datetime('now')
         WHERE setting_key = 'panel_version'
           AND LOWER(TRIM(setting_value)) IN ('v3.0', '3.0', 'v3')`
      );
      await db.run(
        `UPDATE settings
         SET setting_value = 'TGVPANEL V4.0', updated_at = datetime('now')
         WHERE setting_key = 'panel_title'
           AND LOWER(TRIM(setting_value)) IN ('tgvpanel v3.0', 'tgvpanel v3', 'hkvm panel v2.0')`
      );
    },
  },
  {
    version: 15,
    name: 'v015_scheduled_backup_status_and_retention_metadata',
    up: async (db) => {
      await ensureColumn(db, 'backup_schedules', 'created_by', 'INTEGER');
      await ensureColumn(db, 'backup_schedules', 'owner_user_id', 'INTEGER');
      await ensureColumn(db, 'backup_schedules', 'last_status', "TEXT DEFAULT 'never'");
      await ensureColumn(db, 'backup_schedules', 'last_error', 'TEXT');
      await ensureColumn(db, 'backup_schedules', 'last_backup_id', 'INTEGER');
      await ensureColumn(db, 'container_backups', 'is_scheduled', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'container_backups', 'schedule_id', 'INTEGER');
      await db.run(`UPDATE backup_schedules SET frequency = 'daily' WHERE frequency NOT IN ('hourly', 'daily', 'weekly') OR frequency IS NULL`);
      await db.run(`UPDATE backup_schedules SET retention_count = 7 WHERE retention_count IS NULL OR retention_count < 1 OR retention_count > 365`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_backup_schedules_due ON backup_schedules(enabled, next_run)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_scheduled_backups_retention ON container_backups(schedule_id, is_scheduled, id DESC)`);
    },
  },
  {
    version: 16,
    name: 'v016_scheduled_snapshot_status_and_retention_metadata',
    up: async (db) => {
      await ensureColumn(db, 'snapshot_schedules', 'created_by', 'INTEGER');
      await ensureColumn(db, 'snapshot_schedules', 'owner_user_id', 'INTEGER');
      await ensureColumn(db, 'snapshot_schedules', 'last_status', "TEXT DEFAULT 'never'");
      await ensureColumn(db, 'snapshot_schedules', 'last_error', 'TEXT');
      await ensureColumn(db, 'snapshot_schedules', 'last_snapshot_id', 'INTEGER');
      await ensureColumn(db, 'vm_snapshots', 'is_scheduled', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vm_snapshots', 'schedule_id', 'INTEGER');
      await ensureColumn(db, 'container_snapshots', 'is_scheduled', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'container_snapshots', 'schedule_id', 'INTEGER');
      await db.run(`UPDATE snapshot_schedules SET frequency = 'daily' WHERE frequency NOT IN ('hourly', 'daily', 'weekly') OR frequency IS NULL`);
      await db.run(`UPDATE snapshot_schedules SET retention_count = 7 WHERE retention_count IS NULL OR retention_count < 1 OR retention_count > 365`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_snapshot_schedules_due ON snapshot_schedules(enabled, next_run)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_vm_scheduled_snapshots_retention ON vm_snapshots(schedule_id, is_scheduled, snapshot_id DESC)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_lxc_scheduled_snapshots_retention ON container_snapshots(schedule_id, is_scheduled, id DESC)`);
    },
  },
  {
    version: 17,
    name: 'v017_reseller_hmac_api_keys_and_audit',
    up: async (db) => {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS reseller_api_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          description TEXT,
          key_prefix TEXT NOT NULL,
          key_hash TEXT UNIQUE NOT NULL,
          secret_hash TEXT NOT NULL,
          secret_enc TEXT NOT NULL,
          permissions TEXT NOT NULL DEFAULT '["vps.read","stats.read"]',
          ip_allowlist TEXT NOT NULL DEFAULT '[]',
          rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
          rate_window_start INTEGER,
          rate_window_count INTEGER NOT NULL DEFAULT 0,
          is_active INTEGER NOT NULL DEFAULT 1,
          last_used_at DATETIME,
          expires_at DATETIME,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reseller_api_nonces (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          api_key_id INTEGER NOT NULL,
          nonce TEXT NOT NULL,
          expires_at DATETIME NOT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(api_key_id, nonce),
          FOREIGN KEY(api_key_id) REFERENCES reseller_api_keys(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reseller_api_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          api_key_id INTEGER,
          user_id INTEGER,
          key_fingerprint TEXT,
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          ip_address TEXT,
          status_code INTEGER NOT NULL,
          success INTEGER NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(api_key_id) REFERENCES reseller_api_keys(id) ON DELETE SET NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reseller_api_keys_owner ON reseller_api_keys(user_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_reseller_api_nonces_expiry ON reseller_api_nonces(expires_at);
        CREATE INDEX IF NOT EXISTS idx_reseller_api_requests_key_time ON reseller_api_requests(api_key_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_reseller_api_requests_owner_time ON reseller_api_requests(user_id, created_at DESC);
      `);
    },
  },
  {
    version: 18,
    name: 'v018_reseller_customer_directory',
    up: async (db) => {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS reseller_customers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          reseller_user_id INTEGER NOT NULL,
          display_name TEXT NOT NULL,
          email TEXT NOT NULL,
          external_reference TEXT,
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended')),
          notes_enc TEXT,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(reseller_user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_reseller_customers_owner_email
          ON reseller_customers(reseller_user_id, email COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_reseller_customers_owner_status
          ON reseller_customers(reseller_user_id, status, id DESC);
      `);
    },
  },
  {
    version: 19,
    name: 'v019_instance_task_history_and_operation_locks',
    up: async (db) => {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS instance_tasks (
          id TEXT PRIMARY KEY,
          engine TEXT NOT NULL CHECK(engine IN ('kvm', 'lxc')),
          instance_ref_id INTEGER NOT NULL CHECK(instance_ref_id > 0),
          actor_id INTEGER,
          action TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued'
            CHECK(status IN ('queued', 'running', 'succeeded', 'failed')),
          progress INTEGER CHECK(progress BETWEEN 0 AND 100),
          current_step TEXT,
          result_json TEXT,
          error_message TEXT,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          started_at DATETIME,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          completed_at DATETIME,
          FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_instance_tasks_active_lock
          ON instance_tasks(engine, instance_ref_id)
          WHERE status IN ('queued', 'running');
        CREATE INDEX IF NOT EXISTS idx_instance_tasks_instance_history
          ON instance_tasks(engine, instance_ref_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_instance_tasks_status_updated
          ON instance_tasks(status, updated_at);
      `);
    },
  },
  {
    version: 20,
    name: 'v020_kvm_offline_device_configuration',
    up: async (db) => {
      await ensureColumn(db, 'vms', 'extra_disks_json', "TEXT NOT NULL DEFAULT '[]'");
      await ensureColumn(db, 'vms', 'extra_nics_json', "TEXT NOT NULL DEFAULT '[]'");
    },
  },
  {
    version: 21,
    name: 'v021_kvm_local_vnc_console',
    up: async (db) => {
      await ensureColumn(db, 'vms', 'vnc_port', 'INTEGER');
    },
  },
  {
    version: 22,
    name: 'v022_non_suspending_instance_service_lock',
    up: async (db) => {
      for (const table of ['vms', 'lxc_instances']) {
        await ensureColumn(db, table, 'service_locked', 'INTEGER NOT NULL DEFAULT 0');
        await ensureColumn(db, table, 'service_lock_reason', 'TEXT');
        await ensureColumn(db, table, 'service_locked_at', 'DATETIME');
        await ensureColumn(db, table, 'service_locked_by', 'INTEGER');
      }
    },
  },
  {
    version: 23,
    name: 'v023_backup_encryption_at_rest',
    up: async (db) => {
      // Marks local LXC backup archives that are encrypted on disk (AES-256-GCM).
      // Defaults to 0 so existing and remote-node backups remain unencrypted and compatible.
      await ensureColumn(db, 'container_backups', 'encrypted', 'INTEGER NOT NULL DEFAULT 0');
      await ensureColumn(db, 'container_backups', 'encryption_alg', 'TEXT');
    },
  },
  {
    version: 24,
    name: 'v024_backup_destination_copies',
    up: async (db) => {
      // Records copies of a backup archive placed on a destination node (backup
      // replication/offload). Each copy is verified against the source checksum.
      await db.run(
        `CREATE TABLE IF NOT EXISTS backup_copies (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           backup_id INTEGER NOT NULL,
           target_node_id INTEGER NOT NULL,
           file_path TEXT NOT NULL,
           checksum_sha256 TEXT,
           size_bytes INTEGER DEFAULT 0,
           status TEXT NOT NULL DEFAULT 'completed',
           encrypted INTEGER NOT NULL DEFAULT 0,
           encryption_alg TEXT,
           created_by INTEGER,
           created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY(backup_id) REFERENCES container_backups(id) ON DELETE CASCADE,
           FOREIGN KEY(target_node_id) REFERENCES nodes(id)
         )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_backup_copies_backup_id ON backup_copies(backup_id)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_backup_copies_target_node ON backup_copies(target_node_id)`);
    },
  },
  {
    version: 25,
    name: 'v025_kvm_snapshot_allocated_gb',
    up: async (db) => {
      // Records the actual on-disk (allocated) consumption of a KVM QCOW2 snapshot
      // alongside the existing size_gb. size_gb remains the snapshot disk's virtual
      // capacity; allocated_gb is the honest bytes consumed on the host. Existing
      // rows keep NULL until re-measured; additive and backward-compatible.
      await ensureColumn(db, 'vm_snapshots', 'allocated_gb', 'REAL');
    },
  },
  {
    version: 26,
    name: 'v026_webhook_last_error',
    up: async (db) => {
      // Records the most recent webhook delivery failure (HTTP status or network
      // error) alongside the existing last_status_code/failure_count columns so
      // operators can see why a webhook is not delivering. Cleared on success.
      // Additive and backward-compatible.
      await ensureColumn(db, 'webhooks', 'last_error', 'TEXT');
    },
  },
  {
    version: 27,
    name: 'v027_firewall_profiles',
    up: async (db) => {
      // Reusable per-VPS firewall policy profiles (security-group style).
      // A profile holds an ordered list of rules; applying a profile to an
      // instance materializes instance-scoped firewall_rules rows enforced
      // against that instance's IPs (Phase 24 enforcement path).
      await db.run(
        `CREATE TABLE IF NOT EXISTS firewall_profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          description TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        )`
      );
      await db.run(
        `CREATE TABLE IF NOT EXISTS firewall_profile_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          profile_id INTEGER NOT NULL,
          position INTEGER NOT NULL DEFAULT 0,
          direction TEXT NOT NULL DEFAULT 'in',
          action TEXT NOT NULL DEFAULT 'ACCEPT',
          protocol TEXT NOT NULL DEFAULT 'tcp',
          source_cidr TEXT,
          dest_port TEXT,
          priority INTEGER DEFAULT 100,
          comment TEXT,
          FOREIGN KEY(profile_id) REFERENCES firewall_profiles(id) ON DELETE CASCADE
        )`
      );
    },
  },
  {
    version: 28,
    name: 'v028_instance_traffic',
    up: async (db) => {
      // Cumulative per-instance bandwidth ledger. A background loop reads each
      // instance's real network counters and accumulates the delta since the
      // last sample, so totals are measured traffic, not estimates.
      await db.run(
        `CREATE TABLE IF NOT EXISTS instance_traffic (
          instance_type TEXT NOT NULL,
          instance_id INTEGER NOT NULL,
          rx_bytes INTEGER NOT NULL DEFAULT 0,
          tx_bytes INTEGER NOT NULL DEFAULT 0,
          last_rx_bytes INTEGER,
          last_tx_bytes INTEGER,
          last_sampled_at DATETIME,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (instance_type, instance_id)
        )`
      );
    },
  },
  {
    version: 29,
    name: 'v029_load_balancers',
    up: async (db) => {
      // HAProxy load balancer registry: frontends plus their backend pools.
      // The panel renders the HAProxy config from these rows, validates it
      // with `haproxy -c`, and starts/reloads the process on the target node.
      await db.run(
        `CREATE TABLE IF NOT EXISTS load_balancers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          node_id INTEGER NOT NULL DEFAULT 1,
          listen_ip TEXT NOT NULL DEFAULT '0.0.0.0',
          listen_port INTEGER NOT NULL,
          protocol TEXT NOT NULL DEFAULT 'tcp',
          algorithm TEXT NOT NULL DEFAULT 'roundrobin',
          enabled INTEGER DEFAULT 1,
          last_applied_at DATETIME,
          last_validated_at DATETIME,
          last_error TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
        )`
      );
      await db.run(
        `CREATE TABLE IF NOT EXISTS load_balancer_backends (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          load_balancer_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          target TEXT NOT NULL,
          port INTEGER NOT NULL,
          weight INTEGER DEFAULT 1,
          enabled INTEGER DEFAULT 1,
          position INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(load_balancer_id) REFERENCES load_balancers(id) ON DELETE CASCADE
        )`
      );
    },
  },
  {
    version: 30,
    name: 'v030_sessions',
    up: async (db) => {
      // Persistent panel sessions so administrators can inventory and revoke
      // active logins (the default express-session store is in-memory only).
      await db.run(
        `CREATE TABLE IF NOT EXISTS sessions (
          sid TEXT PRIMARY KEY,
          data TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER,
          user_id INTEGER,
          ip TEXT,
          user_agent TEXT
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
    },
  },
  {
    version: 31,
    name: 'v031_docker_containers',
    up: async (db) => {
      // Docker container registry (Area I): panel-managed containers rendered
      // as `docker run`/lifecycle commands, executed on the target node via
      // the allowlisted command runner (local or via the node agent).
      await db.run(
        `CREATE TABLE IF NOT EXISTS docker_containers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          node_id INTEGER NOT NULL DEFAULT 1,
          image TEXT NOT NULL,
          ports TEXT NOT NULL DEFAULT '[]',
          env TEXT NOT NULL DEFAULT '{}',
          restart_policy TEXT NOT NULL DEFAULT 'unless-stopped',
          network TEXT NOT NULL DEFAULT 'tgvpanel',
          status TEXT NOT NULL DEFAULT 'created',
          container_id TEXT,
          last_applied_at TEXT,
          last_error TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_docker_containers_node ON docker_containers(node_id)`);
    },
  },
  {
    version: 32,
    name: 'v032_billing',
    up: async (db) => {
      // Internal billing & invoicing (Area K). Payments are recorded only
      // after admin-verified confirmation — no automated payment gateway is
      // integrated or simulated.
      await db.run(
        `CREATE TABLE IF NOT EXISTS billing_plans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
          billing_cycle TEXT NOT NULL DEFAULT 'monthly',
          description TEXT,
          features TEXT NOT NULL DEFAULT '[]',
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );
      await db.run(
        `CREATE TABLE IF NOT EXISTS customer_subscriptions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          plan_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          auto_renew INTEGER NOT NULL DEFAULT 1,
          started_at TEXT NOT NULL DEFAULT (datetime('now')),
          current_period_start TEXT NOT NULL,
          current_period_end TEXT NOT NULL,
          cancelled_at TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now')),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(plan_id) REFERENCES billing_plans(id)
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON customer_subscriptions(user_id)`);
      await db.run(
        `CREATE TABLE IF NOT EXISTS invoices (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          invoice_number TEXT NOT NULL UNIQUE,
          user_id INTEGER NOT NULL,
          subscription_id INTEGER,
          plan_id INTEGER NOT NULL,
          amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
          billing_cycle TEXT NOT NULL,
          period_start TEXT NOT NULL,
          period_end TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'issued',
          issued_at TEXT NOT NULL DEFAULT (datetime('now')),
          paid_at TEXT,
          payment_reference TEXT,
          payment_method TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now')),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY(subscription_id) REFERENCES customer_subscriptions(id) ON DELETE SET NULL,
          FOREIGN KEY(plan_id) REFERENCES billing_plans(id)
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id)`);
      await db.run(
        `CREATE TABLE IF NOT EXISTS credit_ledger (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          type TEXT NOT NULL,
          amount_cents INTEGER NOT NULL,
          reason TEXT,
          reference TEXT,
          balance_after INTEGER NOT NULL DEFAULT 0,
          created_by INTEGER,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_credit_ledger_user ON credit_ledger(user_id)`);
    },
  },
  {
    version: 33,
    name: 'v033_ddos_protection',
    up: async (db) => {
      // DDoS protection (Area D hardening): real network-connection
      // monitoring with threat scoring and iptables-based blocking.
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_ips (
          ip TEXT PRIMARY KEY,
          requests INTEGER DEFAULT 0,
          bandwidth INTEGER DEFAULT 0,
          threads INTEGER DEFAULT 0,
          blocked INTEGER NOT NULL DEFAULT 0,
          blocked_at INTEGER,
          first_seen INTEGER,
          last_seen INTEGER,
          country TEXT,
          threat_level TEXT NOT NULL DEFAULT 'low'
        )`
      );
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_attack_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT NOT NULL,
          timestamp INTEGER NOT NULL,
          requests INTEGER DEFAULT 0,
          bandwidth INTEGER DEFAULT 0,
          action TEXT NOT NULL
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_logs_ip ON ddos_attack_logs(ip)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_logs_ts ON ddos_attack_logs(timestamp)`);
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_settings (
          id INTEGER PRIMARY KEY,
          rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
          max_bandwidth_per_minute INTEGER NOT NULL DEFAULT 1048576,
          auto_block INTEGER NOT NULL DEFAULT 1,
          block_duration INTEGER NOT NULL DEFAULT 3600,
          threat_threshold_medium INTEGER NOT NULL DEFAULT 100,
          threat_threshold_high INTEGER NOT NULL DEFAULT 500,
          threat_threshold_critical INTEGER NOT NULL DEFAULT 1000,
          auto_block_syn_recv INTEGER NOT NULL DEFAULT 50,
          auto_block_high_connections INTEGER NOT NULL DEFAULT 150,
          auto_block_port_scan INTEGER NOT NULL DEFAULT 10,
          auto_block_time_wait INTEGER NOT NULL DEFAULT 300,
          intelligent_blocking INTEGER NOT NULL DEFAULT 1
        )`
      );
      await db.run(`INSERT OR IGNORE INTO ddos_settings (id) VALUES (1)`);
    },
  },
  {
    version: 34,
    name: 'v034_ddos_enterprise',
    up: async (db) => {
      // Enterprise DDoS protection upgrade (Area D hardening, enterprise).
      // Expanded detection, mitigation, profiles, multi-node, per-VPS,
      // HTTP protection, Cloudflare integration and notifications.

      // --- Enhanced settings (supersedes v033 ddos_settings) ---
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN syn_cookies INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN connection_limit INTEGER NOT NULL DEFAULT 1000`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN packet_rate_limit INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN per_ip_rate_limit INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN emergency_mode INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN max_bandwidth_mbps INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 10000`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN ack_flood_threshold INTEGER NOT NULL DEFAULT 200`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN icmp_flood_threshold INTEGER NOT NULL DEFAULT 500`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN http_get_threshold INTEGER NOT NULL DEFAULT 300`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN http_post_threshold INTEGER NOT NULL DEFAULT 150`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN slowloris_threshold INTEGER NOT NULL DEFAULT 20`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN dns_amp_threshold INTEGER NOT NULL DEFAULT 100`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN udp_amp_threshold INTEGER NOT NULL DEFAULT 100`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN packet_rate_threshold INTEGER NOT NULL DEFAULT 5000`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN suspicious_user_agent_block INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN trusted_proxies TEXT NOT NULL DEFAULT ''`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN cloudflare_enabled INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN cloudflare_zone TEXT`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN cloudflare_security_level TEXT NOT NULL DEFAULT 'medium'`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_attack_detected INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_attack_mitigated INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_attack_ended INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_critical_bandwidth INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_suspicious_traffic INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_node_failure INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_firewall_failure INTEGER NOT NULL DEFAULT 1`);
      await db.run(`ALTER TABLE ddos_settings ADD COLUMN notify_engine_failure INTEGER NOT NULL DEFAULT 1`);

      // --- Enhanced IP records (supersedes v033 ddos_ips) ---
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN ack_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN icmp_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN http_get_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN http_post_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN slowloris_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN dns_amp_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN udp_amp_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN packet_rate INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN reputation INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN banned INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN ban_type TEXT NOT NULL DEFAULT 'temporary'`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN ban_reason TEXT`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN ban_expires INTEGER`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN whitelisted INTEGER NOT NULL DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN attack_types TEXT`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN pps INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN bps INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN conn_rate INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN last_attack_at INTEGER`);
      await db.run(`ALTER TABLE ddos_ips ADD COLUMN attack_count INTEGER DEFAULT 0`);

      // --- Attack history (distinct from event log) ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_attacks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT,
          attack_type TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'medium',
          detected_at INTEGER NOT NULL,
          ended_at INTEGER,
          duration_seconds INTEGER,
          pps INTEGER DEFAULT 0,
          bps INTEGER DEFAULT 0,
          connections INTEGER DEFAULT 0,
          node_id INTEGER,
          vps_id INTEGER,
          mitigated INTEGER DEFAULT 0,
          mitigation_method TEXT,
          details TEXT
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_attacks_ip ON ddos_attacks(ip)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_attacks_ts ON ddos_attacks(detected_at)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_attacks_type ON ddos_attacks(attack_type)`);

      // --- Active mitigations tracking ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_mitigations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT NOT NULL,
          method TEXT NOT NULL,
          attack_type TEXT,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          expired_at INTEGER,
          node_id INTEGER,
          vps_id INTEGER,
          rule_id TEXT,
          rolled_back INTEGER DEFAULT 0
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_mit_ip ON ddos_mitigations(ip)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_mit_active ON ddos_mitigations(active)`);

      // --- IP whitelist (separate from per-IP record for fast lookups) ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_whitelist (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip TEXT NOT NULL UNIQUE,
          reason TEXT,
          node_id INTEGER,
          vps_id INTEGER,
          created_by INTEGER,
          created_at INTEGER NOT NULL
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_wl_ip ON ddos_whitelist(ip)`);

      // --- Protection profiles ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          description TEXT,
          level TEXT NOT NULL DEFAULT 'custom',
          syn_cookies INTEGER DEFAULT 1,
          connection_limit INTEGER DEFAULT 1000,
          packet_rate_limit INTEGER DEFAULT 0,
          per_ip_rate_limit INTEGER DEFAULT 0,
          auto_block INTEGER DEFAULT 1,
          block_duration INTEGER DEFAULT 3600,
          threat_threshold_medium INTEGER DEFAULT 100,
          threat_threshold_high INTEGER DEFAULT 500,
          threat_threshold_critical INTEGER DEFAULT 1000,
          http_get_threshold INTEGER DEFAULT 300,
          http_post_threshold INTEGER DEFAULT 150,
          slowloris_threshold INTEGER DEFAULT 20,
          dns_amp_threshold INTEGER DEFAULT 100,
          udp_amp_threshold INTEGER DEFAULT 100,
          packet_rate_threshold INTEGER DEFAULT 5000,
          suspicious_ua_block INTEGER DEFAULT 1,
          emergency_mode INTEGER DEFAULT 0,
          protocols TEXT,
          ports TEXT,
          is_active INTEGER DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );
      await db.run(
        `INSERT OR IGNORE INTO ddos_profiles (name, level, description, is_active) VALUES
          ('Basic', 'basic', 'Minimal protection: SYN flood and basic connection flood detection.', 0),
          ('Standard', 'standard', 'Balanced protection for typical hosting workloads.', 0),
          ('Advanced', 'advanced', 'Comprehensive protection with HTTP and amplification detection.', 0),
          ('Aggressive', 'aggressive', 'Maximum protection with aggressive thresholds and auto-blocking.', 1)`
      );

      // --- Profile-to-node / profile-to-VPS assignments ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_profile_assignments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          profile_id INTEGER NOT NULL,
          node_id INTEGER,
          vps_id INTEGER,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          UNIQUE(profile_id, node_id, vps_id)
        )`
      );

      // --- Per-VPS protection policies ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_vps_policies (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          vps_id INTEGER NOT NULL UNIQUE,
          instance_type TEXT NOT NULL,
          instance_ref_id INTEGER NOT NULL,
          node_id INTEGER,
          enabled INTEGER NOT NULL DEFAULT 0,
          profile_id INTEGER,
          tcp_protection INTEGER DEFAULT 1,
          udp_protection INTEGER DEFAULT 1,
          icmp_protection INTEGER DEFAULT 1,
          connection_limit INTEGER DEFAULT 500,
          per_ip_rate_limit INTEGER DEFAULT 0,
          port_whitelist TEXT,
          ip_whitelist TEXT,
          auto_block INTEGER DEFAULT 1,
          block_duration INTEGER DEFAULT 3600,
          network_isolation INTEGER DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );

      // --- Node DDoS status ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_node_status (
          node_id INTEGER PRIMARY KEY,
          enabled INTEGER NOT NULL DEFAULT 0,
          profile_id INTEGER,
          online INTEGER DEFAULT 0,
          last_sync_at INTEGER,
          last_error TEXT,
          pps INTEGER DEFAULT 0,
          bps INTEGER DEFAULT 0,
          active_connections INTEGER DEFAULT 0,
          blocked_ips INTEGER DEFAULT 0,
          updated_at INTEGER
        )`
      );

      // --- Cloudflare / external integration credentials ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_integrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          provider TEXT NOT NULL,
          api_key_enc TEXT,
          api_email TEXT,
          zone TEXT,
          security_level TEXT DEFAULT 'medium',
          is_active INTEGER DEFAULT 0,
          last_sync_at INTEGER,
          last_error TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );

      // --- Audit log for firewall/mitigation operations ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action TEXT NOT NULL,
          target TEXT,
          ip TEXT,
          node_id INTEGER,
          vps_id INTEGER,
          method TEXT,
          rule_id TEXT,
          success INTEGER DEFAULT 1,
          detail TEXT,
          user_id INTEGER,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_audit_ts ON ddos_audit_log(created_at)`);

      // --- Firewall rule ownership tags (for safe rollback) ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS ddos_firewall_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_id TEXT NOT NULL UNIQUE,
          ip TEXT NOT NULL,
          protocol TEXT,
          port TEXT,
          action TEXT NOT NULL,
          direction TEXT DEFAULT 'INPUT',
          table_name TEXT DEFAULT 'filter',
          chain TEXT DEFAULT 'INPUT',
          node_id INTEGER,
          vps_id INTEGER,
          created_at INTEGER NOT NULL,
          active INTEGER DEFAULT 1,
          rolled_back INTEGER DEFAULT 0
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_fw_ip ON ddos_firewall_rules(ip)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_ddos_fw_active ON ddos_firewall_rules(active)`);
    }
  },
  {
    version: 35,
    name: 'v035_billing_store_gateways',
    up: async (db) => {
      // Store & payment gateway integration.
      // Adds plan specs (virtualization type, resources) and gateway
      // configuration for FamGateway (UPI), Stripe, and PayPal.

      // --- Plan specs (virtualization type + resources) ---
      await db.run(`ALTER TABLE billing_plans ADD COLUMN virtualization_type TEXT NOT NULL DEFAULT 'lxc'`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN cpu_cores INTEGER DEFAULT 1`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN ram_mb INTEGER DEFAULT 1024`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN storage_gb INTEGER DEFAULT 10`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN bandwidth_gb INTEGER DEFAULT 100`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN vps_count INTEGER DEFAULT 1`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN allowed_os TEXT`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN ports_count INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN dns_records INTEGER DEFAULT 0`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN backups_included INTEGER DEFAULT 1`);
      await db.run(`ALTER TABLE billing_plans ADD COLUMN sla_percent INTEGER DEFAULT 99.9`);

      // --- Payment gateway configuration ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS payment_gateways (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          provider TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 0,
          api_key_enc TEXT,
          api_secret_enc TEXT,
          webhook_secret_enc TEXT,
          webhook_url TEXT,
          account_id TEXT,
          merchant_id TEXT,
          currency TEXT NOT NULL DEFAULT 'INR',
          is_default INTEGER NOT NULL DEFAULT 0,
          last_test_at INTEGER,
          last_test_status TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`
      );
      await db.run(
        `INSERT OR IGNORE INTO payment_gateways (name, provider, enabled, currency) VALUES
          ('FamGateway (UPI)', 'famgateway', 0, 'INR'),
          ('Stripe', 'stripe', 0, 'INR'),
          ('PayPal', 'paypal', 0, 'USD')`
      );

      // --- Payment orders / transactions ---
      await db.run(
        `CREATE TABLE IF NOT EXISTS payment_orders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          invoice_id INTEGER,
          subscription_id INTEGER,
          user_id INTEGER NOT NULL,
          plan_id INTEGER,
          gateway TEXT NOT NULL,
          gateway_order_id TEXT,
          amount_cents INTEGER NOT NULL,
          currency TEXT NOT NULL DEFAULT 'INR',
          status TEXT NOT NULL DEFAULT 'pending',
          redirect_url TEXT,
          checkout_url TEXT,
          qr_url TEXT,
          upi_intent TEXT,
          utr TEXT,
          payment_reference TEXT,
          error TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now')),
          paid_at TEXT
        )`
      );
      await db.run(`CREATE INDEX IF NOT EXISTS idx_pay_orders_user ON payment_orders(user_id)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_pay_orders_status ON payment_orders(status)`);
      await db.run(`CREATE INDEX IF NOT EXISTS idx_pay_orders_invoice ON payment_orders(invoice_id)`);
    }
  },
  {
    version: 36,
    name: 'v036_vm_bandwidth_limits',
    up: async (db) => {
      // Bandwidth usage limits for KVM VMs.
      // LXC instances already had bandwidth_quota_gb/bandwidth_used_gb/
      // bandwidth_reset_date (migration v019); the vms table did not.
      // Adds the same columns plus an unlimited_bandwidth flag so that
      // "unlimited" is explicitly representable (0 GB quota + flag=1).
      // Uses ensureColumn so legacy DBs missing any table are skipped safely.
      await ensureColumn(db, 'vms', 'bandwidth_quota_gb', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'vms', 'bandwidth_used_gb', 'REAL DEFAULT 0.0');
      await ensureColumn(db, 'vms', 'bandwidth_reset_date', 'DATETIME');
      await ensureColumn(db, 'vms', 'unlimited_bandwidth', 'INTEGER DEFAULT 0');
      // LXC already had bandwidth_quota_gb/used/reset; add the unlimited flag.
      await ensureColumn(db, 'lxc_instances', 'unlimited_bandwidth', 'INTEGER DEFAULT 0');
      // Unified instance registry: carry bandwidth limit metadata for both engines.
      await ensureColumn(db, 'instances', 'bandwidth_quota_gb', 'INTEGER DEFAULT 0');
      await ensureColumn(db, 'instances', 'unlimited_bandwidth', 'INTEGER DEFAULT 0');
    }
  },
];

export async function runMigrations(db: UnifiedDatabase): Promise<{
  applied: string[];
  backupPath?: string;
}> {
  await db.run('PRAGMA foreign_keys = ON');
  await db.run(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const appliedRows = await db.all<{ version: number }>(`SELECT version FROM schema_migrations`);
  const appliedSet = new Set(appliedRows.map((r) => r.version));

  const pending = MIGRATIONS.filter((m) => !appliedSet.has(m.version));
  if (pending.length === 0) {
    return { applied: [] };
  }

  // Automatic database backup before applying any pending migration (Part 20 & Part 22)
  const backup = await db.createBackup(`pre_migration_v${pending[0].version}`);
  const newlyApplied: string[] = [];

  for (const migration of pending) {
    const checksum = crypto
      .createHash('sha256')
      .update(`${migration.version}:${migration.name}`)
      .digest('hex');

    await db.transaction(async () => {
      await migration.up(db);
      await db.run(
        `INSERT INTO schema_migrations (version, name, checksum, applied_at)
         VALUES (?, ?, ?, datetime('now'))`,
        [migration.version, migration.name, checksum]
      );
    });

    newlyApplied.push(migration.name);
  }

  return { applied: newlyApplied, backupPath: backup.backupPath };
}
