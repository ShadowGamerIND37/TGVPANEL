import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { UnifiedDatabase } from '../../db/database';
import {
  decryptSecret,
  encryptSecret,
  generateStrongPassword,
} from '../../security/crypto-vault';
import { SafeValidators } from '../../security/middleware';
import { NodeManager } from '../nodes/NodeClient';
import { privilegedFs } from '../../node-agent/command-runner';
import {
  LxcContainerRuntimeInfo,
  LxcCreateSpec,
  LxcNetworkRepairResult,
  PROXMOX_LXC_GPG_URLS,
  resolveProxmoxLxcCodename,
} from '../../node-agent/container-manager';
import {
  InstanceCapabilityProfile,
  InstanceTelemetry,
  LifecycleAction,
  UnifiedInstanceRecord,
  VirtualizationAdapter,
} from './VirtualizationAdapter';

export interface CreateLxcInstanceInput {
  userId: number;
  nodeId?: number;
  containerName: string;
  hostname?: string;
  templateSlug?: string;
  distro?: string;
  release?: string;
  arch?: string;
  cpuCores: number;
  cpuShares?: number;
  cpuLimitPercent?: number;
  cpuPinning?: string | null;
  ramMb: number;
  swapMb?: number;
  diskGb: number;
  backingStore?: 'dir' | 'lvm' | 'zfs' | 'btrfs';
  privileged?: boolean;
  nesting?: boolean;
  kvmNesting?: boolean;
  bridge?: string;
  ipv4Address?: string | null;
  ipv4Gateway?: string | null;
  ipv6Address?: string | null;
  macAddress?: string | null;
  vlanId?: number | null;
  rootPassword?: string;
  sshPublicKeys?: string[];
  autostart?: boolean;
  bandwidthQuotaGb?: number;
  unlimitedBandwidth?: boolean;
  expirationDays?: number;
  autoSuspendEnabled?: boolean;
  notes?: string;
  provisionOnHost?: boolean;
}

export class LXCAdapter implements VirtualizationAdapter {
  public readonly engine = 'lxc' as const;
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private prevContainerCpu = new Map<number, { cpuSec: number; tsMs: number }>();
  private inFlightPanelCreations = new Set<string>();

  constructor(db: UnifiedDatabase, nodeManager: NodeManager) {
    this.db = db;
    this.nodeManager = nodeManager;
  }

  public getCapabilityProfile(): InstanceCapabilityProfile {
    return {
      engine: 'lxc',
      supportsFreeze: true,
      supportsSuspend: true,
      supportsSnapshots: true,
      supportsBackups: true,
      supportsOfflineMigration: true,
      supportsIsoMount: false,
      supportsBootOrder: false,
      supportsSmbios: false,
      supportsCloudInit: false,
      supportsSerialConsole: false,
      supportsPtyConsole: true,
      supportsSshBridge: true,
      supportsRootfsFileBrowser: true,
      supportsContainerProcessList: true,
    };
  }

  private mapRowToUnified(row: any): UnifiedInstanceRecord {
    let shared: number[] = [];
    try {
      const parsed = JSON.parse(row.shared_with || '[]');
      if (Array.isArray(parsed)) shared = parsed.map(Number).filter(Boolean);
    } catch {
      shared = [];
    }

    return {
      uid: `lxc:${row.id}`,
      engine: 'lxc',
      refId: row.id,
      name: row.container_name,
      hostname: row.hostname || row.container_name,
      ownerId: row.user_id,
      ownerUsername: row.owner_username || undefined,
      nodeId: row.node_id,
      nodeName: row.node_name || 'localhost',
      status: row.suspended ? 'suspended' : row.status || 'stopped',
      suspended: Boolean(row.suspended),
      suspendedReason: row.suspended_reason || null,
      serviceLocked: Boolean(row.service_locked),
      serviceLockReason: row.service_lock_reason || null,
      osLabel: row.os_template || 'ubuntu:24.04',
      cpuCores: Number(row.cpu_cores || 1),
      ramMb: Number(row.ram_mb || 1024),
      swapMb: Number(row.swap_mb || 512),
      diskGb: Number(row.disk_gb || 20),
      primaryIp: row.ip_address || null,
      sshPort: 22,
      sharedWith: shared,
      expiresAt: row.expires_at || null,
      createdAt: row.created_at,
      capabilities: this.getCapabilityProfile(),
    };
  }

  public async syncRegistryRow(lxcId: number): Promise<void> {
    const row = await this.db.get<any>(`SELECT * FROM lxc_instances WHERE id = ?`, [lxcId]);
    if (!row) {
      await this.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]);
      return;
    }

    await this.db.run(
      `INSERT INTO instances
         (engine, ref_id, name, hostname, owner_id, node_id, status, suspended, os_label, cpu_cores, ram_mb, disk_gb, primary_ip, shared_with, bandwidth_quota_gb, unlimited_bandwidth, updated_at)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 0), COALESCE(?, 0), datetime('now'))
       ON CONFLICT(engine, ref_id) DO UPDATE SET
         name = excluded.name,
         hostname = excluded.hostname,
         owner_id = excluded.owner_id,
         node_id = excluded.node_id,
         status = excluded.status,
         suspended = excluded.suspended,
         os_label = excluded.os_label,
         cpu_cores = excluded.cpu_cores,
         ram_mb = excluded.ram_mb,
         disk_gb = excluded.disk_gb,
         primary_ip = excluded.primary_ip,
         shared_with = excluded.shared_with,
         bandwidth_quota_gb = excluded.bandwidth_quota_gb,
         unlimited_bandwidth = excluded.unlimited_bandwidth,
         updated_at = datetime('now')`,
      [
        row.id,
        row.container_name,
        row.hostname || row.container_name,
        row.user_id,
        row.node_id,
        row.status || 'stopped',
        row.suspended ? 1 : 0,
        row.os_template || 'ubuntu:24.04',
        row.cpu_cores || 1,
        row.ram_mb || 1024,
        row.disk_gb || 20,
        row.ip_address || null,
        row.shared_with || '[]',
        row.bandwidth_quota_gb || 0,
        row.unlimited_bandwidth ? 1 : 0,
      ]
    );
  }

  public async listInstances(filter?: {
    ownerId?: number;
    nodeId?: number;
  }): Promise<UnifiedInstanceRecord[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];

    if (filter?.ownerId !== undefined) {
      clauses.push(`(l.user_id = ? OR l.shared_with LIKE ?)`);
      params.push(filter.ownerId, `%${filter.ownerId}%`);
    }
    if (filter?.nodeId !== undefined) {
      clauses.push(`l.node_id = ?`);
      params.push(filter.nodeId);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await this.db.all<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       ${whereSql}
       ORDER BY l.id DESC`,
      params
    );

    const mapped = rows.map((r) => this.mapRowToUnified(r));
    if (filter?.ownerId !== undefined) {
      return mapped.filter(
        (m) => m.ownerId === filter.ownerId || m.sharedWith.includes(filter.ownerId!)
      );
    }
    return mapped;
  }

  public async getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined> {
    const row = await this.db.get<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       WHERE l.id = ?`,
      [refId]
    );
    return row ? this.mapRowToUnified(row) : undefined;
  }

  public async getRawLxcRow(refId: number): Promise<any | undefined> {
    return this.db.get<any>(
      `SELECT l.*, u.username AS owner_username, n.name AS node_name, n.is_local,
              t.icon AS template_icon, t.icon_path AS template_icon_path, t.proxmox_codename AS template_proxmox_codename
       FROM lxc_instances l
       LEFT JOIN users u ON u.id = l.user_id
       LEFT JOIN nodes n ON n.id = l.node_id
       LEFT JOIN lxc_templates t ON LOWER(t.slug) = LOWER(l.os_template)
       WHERE l.id = ?`,
      [refId]
    );
  }

  private async resolveCatalogTemplate(rawIdentifier: string): Promise<any | undefined> {
    const trimmed = String(rawIdentifier || '').trim();
    if (!trimmed) return undefined;
    const normalizedSlug = trimmed.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
    return this.db.get<any>(
      `SELECT * FROM lxc_templates
       WHERE (LOWER(slug) = LOWER(?) OR slug = ? OR LOWER(COALESCE(image_alias, '')) = LOWER(?))
         AND COALESCE(enabled, is_active, 1) = 1
       ORDER BY COALESCE(is_custom, 0) DESC, id ASC
       LIMIT 1`,
      [trimmed, normalizedSlug, trimmed]
    );
  }

  public async createLxcInstance(input: CreateLxcInstanceInput): Promise<{
    instance: UnifiedInstanceRecord;
    generatedRootPassword: string;
    hostProvisioned: boolean;
    warning?: string;
  }> {
    const safeName = SafeValidators.containerName(input.containerName);
    const lockKey = safeName.toLowerCase();
    if (this.inFlightPanelCreations.has(lockKey)) {
      throw new Error(
        `LXC container "${safeName}" is currently being provisioned (downloading OS template). Please wait for it to finish.`
      );
    }

    const existing = await this.db.get<{ id: number }>(
      `SELECT id FROM lxc_instances WHERE LOWER(container_name) = LOWER(?)`,
      [safeName]
    );
    if (existing) {
      throw new Error(`An LXC container named "${safeName}" already exists.`);
    }

    const node = input.nodeId
      ? await this.nodeManager.getNodeById(input.nodeId)
      : await this.nodeManager.getDefaultNodeForEngine('lxc');
    if (!node) throw new Error('Target node not found.');
    if (node.maintenance_mode) {
      throw new Error(`Node "${node.name}" is currently in maintenance mode.`);
    }
    const maxInst = Number(node.max_instances || 0);
    if (maxInst > 0 && Number(node.total_instances || 0) >= maxInst) {
      throw new Error(
        `Node "${node.name}" has reached its maximum instance quota (${node.total_instances}/${maxInst}).`
      );
    }

    this.inFlightPanelCreations.add(lockKey);
    try {
      // Resolve template metadata from lxc_templates catalog
      let distro = input.distro || 'ubuntu';
      let release = input.release || '24.04';
      let fallbackRelease: string | null = null;
      let templateArchivePath: string | null = null;
      let arch = input.arch || 'amd64';
      let osTemplateLabel = input.templateSlug || `${distro}:${release}`;
      let osFamily = 'debian';
      let proxmoxCodename: string | null = null;
      let tplMinRamMb = 0;
      let tplMinDiskGb = 0;

      if (input.templateSlug) {
        const tpl = await this.resolveCatalogTemplate(input.templateSlug);
        if (!tpl && !input.distro) {
          throw new Error(`Enabled LXC template "${input.templateSlug}" not found in catalog.`);
        }
        if (tpl) {
          distro = tpl.distro;
          release = tpl.release;
          fallbackRelease = tpl.fallback_alias || null;
          templateArchivePath = tpl.file_path || tpl.local_path || null;
          arch = tpl.arch || 'amd64';
          osTemplateLabel = tpl.slug;
          osFamily = tpl.family || 'debian';
          tplMinRamMb = Number(tpl.min_ram_mb || 0);
          tplMinDiskGb = Number(tpl.min_disk_gb || 0);
          proxmoxCodename = resolveProxmoxLxcCodename({
            proxmoxCodename: tpl.proxmox_codename || null,
            templateSlug: tpl.slug || input.templateSlug,
            distro: tpl.distro,
            release: tpl.release,
            category: tpl.category || null,
          });
        }
      }
      if (!proxmoxCodename) {
        proxmoxCodename = resolveProxmoxLxcCodename({
          templateSlug: input.templateSlug || null,
          distro,
          release,
        });
      }
      const isProxmoxLxc = proxmoxCodename !== null;
      // Proxmox VE hypervisor containers need KVM/LXC nesting + privileged mode + PVE minimums
      const effectiveCpuCores = Math.max(
        1,
        Number(input.cpuCores || 1),
        isProxmoxLxc ? 2 : 0
      );
      const effectiveRamMb = Math.max(
        128,
        Number(input.ramMb || 1024),
        tplMinRamMb,
        isProxmoxLxc ? 4096 : 0
      );
      const effectiveDiskGb = Math.max(
        2,
        Number(input.diskGb || 20),
        tplMinDiskGb,
        isProxmoxLxc ? 40 : 0
      );

      const plainPassword = input.rootPassword?.trim() || generateStrongPassword(18);
      const encryptedPass = encryptSecret(plainPassword);
      const mac =
        input.macAddress ||
        `00:16:3e:${[0, 1, 2]
          .map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0'))
          .join(':')}`;

      const expDays = Math.max(0, Number(input.expirationDays || 0));
      const expiresAt =
        expDays > 0
          ? new Date(Date.now() + expDays * 86_400_000).toISOString()
          : null;

      const spec: LxcCreateSpec = {
        containerName: safeName,
        hostname: input.hostname || safeName,
        distro,
        release,
        fallbackRelease,
        templateArchivePath,
        arch,
        cpuCores: effectiveCpuCores,
        cpuShares: Number(input.cpuShares || 1024),
        cpuLimitPercent: Number(input.cpuLimitPercent || 100),
        cpuPinning: input.cpuPinning || null,
        ramMb: effectiveRamMb,
        swapMb: Math.max(0, Number(input.swapMb ?? 512)),
        diskGb: effectiveDiskGb,
        backingStore: input.backingStore || 'dir',
        privileged: isProxmoxLxc ? true : input.privileged !== false,
        nesting: isProxmoxLxc ? true : input.nesting !== false,
        kvmNesting: isProxmoxLxc ? true : Boolean(input.kvmNesting),
        proxmoxCodename,
        proxmoxGpgUrl: proxmoxCodename ? PROXMOX_LXC_GPG_URLS[proxmoxCodename] || null : null,
        bridge: input.bridge || 'lxcbr0',
        ipv4Address: input.ipv4Address || null,
        ipv4Gateway: input.ipv4Gateway || null,
        ipv6Address: input.ipv6Address || null,
        macAddress: mac,
        vlanId: input.vlanId || null,
        rootPassword: plainPassword,
        sshPublicKeys: input.sshPublicKeys || [],
        autostart: Boolean(input.autostart),
        replaceOrphanOnHost: true,
      };

      let runtimeState = 'stopped';
      let detectedIp = input.ipv4Address || null;
      let detectedGw = spec.ipv4Gateway || null;
      let effectiveBackingStore: string = spec.backingStore || 'dir';
      let hostProvisioned = false;
      let warning: string | undefined;

      if (input.provisionOnHost !== false) {
        if (node.is_local) {
          const info = await this.nodeManager.localRuntime.containerManager.createContainer(spec);
          runtimeState = info.state === 'running' ? 'running' : 'stopped';
          if (info.backingStore) effectiveBackingStore = info.backingStore;
          if (!detectedIp && (info.ips.length > 0 || info.configuredIpv4)) {
            detectedIp = info.ips[0] || info.configuredIpv4 || null;
          }
          if (!detectedGw && info.configuredGateway && info.configuredGateway !== 'auto') {
            detectedGw = info.configuredGateway;
          }
          if (info.startupWarning) warning = info.startupWarning;
          hostProvisioned = true;
        } else {
          if (spec.templateArchivePath && fs.existsSync(spec.templateArchivePath)) {
            spec.templateArchivePath = await this.ensureTemplateStagedOnRemoteNode(
              node.id,
              spec.templateArchivePath
            );
          }
          const info = await this.nodeManager.requestRemoteNode<LxcContainerRuntimeInfo>(
            node.id,
            'POST',
            '/api/v1/containers',
            spec,
            600_000
          );
          runtimeState = info.state === 'running' ? 'running' : 'stopped';
          if (info.backingStore) effectiveBackingStore = info.backingStore;
          if (!detectedIp && (info.ips?.length > 0 || info.configuredIpv4)) {
            detectedIp = info.ips?.[0] || info.configuredIpv4 || null;
          }
          if (!detectedGw && info.configuredGateway && info.configuredGateway !== 'auto') {
            detectedGw = info.configuredGateway;
          }
          if (info.startupWarning) warning = info.startupWarning;
          hostProvisioned = true;
        }
      } else {
        warning = isProxmoxLxc
          ? 'Registered in database without host provisioning — Proxmox VE bootstrap will NOT run until the container is provisioned on a host. Delete and recreate with "Provision Immediately on Host" enabled for the PVE install.'
          : 'Registered in database without immediate host provisioning.';
      }
      if (isProxmoxLxc && input.provisionOnHost !== false) {
        const proxmoxNotes: string[] = [];
        if (node.is_local && !fs.existsSync('/dev/kvm')) {
          proxmoxNotes.push(
            'Host has no /dev/kvm — Proxmox VE Web UI (:8006) will install, but QEMU/KVM VMs inside PVE will fail until nested KVM is available on the host.'
          );
        }
        if (!node.is_local) {
          proxmoxNotes.push(
            'Remote node: ensure the Node Agent is updated (injectProxmoxLxcBootstrap) or the container will remain plain Debian without the PVE bootstrap.'
          );
        }
        proxmoxNotes.push(
          'Proxmox VE installs on first boot (5-15 min, Debian base — neofetch shows Debian by design). Verify with pveversion and https://<container-ip>:8006.'
        );
        warning = warning ? `${warning} ${proxmoxNotes.join(' ')}` : proxmoxNotes.join(' ');
      }

      const ins = await this.db.run(
        `INSERT INTO lxc_instances (
          user_id, node_id, container_name, hostname, os_template, os_family, arch,
          cpu_cores, cpu_shares, cpu_limit_pct, cpu_pinning, ram_mb, swap_mb, disk_gb,
          rootfs_storage_type, privileged, nesting, kvm_nesting, autostart, root_password_enc,
          bridge, ip_address, gateway, ipv6_address, mac_address, vlan_id,
          status, bandwidth_quota_gb, unlimited_bandwidth, notes, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          input.userId,
          node.id,
          safeName,
          spec.hostname,
          osTemplateLabel,
          osFamily,
          arch,
          spec.cpuCores,
          spec.cpuShares,
          spec.cpuLimitPercent,
          spec.cpuPinning,
          spec.ramMb,
          spec.swapMb,
          spec.diskGb,
          effectiveBackingStore,
          spec.privileged ? 1 : 0,
          spec.nesting ? 1 : 0,
          spec.kvmNesting ? 1 : 0,
          spec.autostart ? 1 : 0,
          encryptedPass,
          spec.bridge,
          detectedIp,
          detectedGw,
          spec.ipv6Address,
          mac,
          spec.vlanId,
          runtimeState,
          Number(input.bandwidthQuotaGb || 0),
          input.unlimitedBandwidth ? 1 : 0,
          input.notes || null,
          expiresAt,
          expDays,
          input.autoSuspendEnabled !== false ? 1 : 0,
        ]
      );

      if (expiresAt || expDays > 0) {
        await this.db.run(
          `INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
           VALUES (?, ?, ?, ?, datetime('now'))`,
          [ins.lastID, expiresAt, expDays, input.autoSuspendEnabled !== false ? 1 : 0]
        );
      }

      await this.syncRegistryRow(ins.lastID);
      const created = (await this.getInstance(ins.lastID))!;

      return {
        instance: created,
        generatedRootPassword: plainPassword,
        hostProvisioned,
        warning,
      };
    } finally {
      this.inFlightPanelCreations.delete(lockKey);
    }
  }

  private async ensureTemplateStagedOnRemoteNode(
    nodeId: number,
    localArchivePath: string
  ): Promise<string> {
    const buf = fs.readFileSync(localArchivePath);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const safeName = `${sha256.slice(0, 12)}_${path.basename(localArchivePath)}`;

    try {
      const status = await this.nodeManager.requestRemoteNode<{
        cached: boolean;
        filePath: string;
      }>(
        nodeId,
        'GET',
        `/api/v1/templates/status?name=${encodeURIComponent(safeName)}&sha256=${encodeURIComponent(sha256)}`
      );
      if (status?.cached && status.filePath) {
        return status.filePath;
      }
    } catch {
      // Proceed to stage upload
    }

    const staged = await this.nodeManager.requestRemoteNode<{
      staged: boolean;
      filePath: string;
    }>(
      nodeId,
      'POST',
      '/api/v1/templates/stage',
      {
        name: safeName,
        archiveBase64: buf.toString('base64'),
        expectedSha256: sha256,
      },
      300_000
    );
    return staged.filePath;
  }

  /**
   * Discovers any existing native LXC containers across the local node and all online remote
   * Node Agents (or a specific target `nodeId`) that are not yet tracked in `lxc_instances`
   * and imports them cleanly with accurate `node_id` ownership.
   */
  public async syncHostContainers(
    defaultUserId = 1,
    targetNodeId?: number
  ): Promise<{ imported: string[]; count: number; byNode?: Record<number, string[]> }> {
    const allNodes = await this.nodeManager.listNodes();
    const candidates =
      targetNodeId !== undefined
        ? allNodes.filter((n) => n.id === Number(targetNodeId))
        : allNodes.filter((n) => n.is_local || n.status === 'online');

    const imported: string[] = [];
    const byNode: Record<number, string[]> = {};
    const cm = this.nodeManager.localRuntime.containerManager;

    for (const node of candidates) {
      let hostList: LxcContainerRuntimeInfo[] = [];
      try {
        if (node.is_local) {
          hostList = await cm.listContainers();
        } else {
          const resp = await this.nodeManager.requestRemoteNode<{
            containers: LxcContainerRuntimeInfo[];
          }>(node.id, 'GET', '/api/v1/containers', undefined, 15_000);
          hostList = Array.isArray(resp?.containers) ? resp.containers : [];
        }
      } catch {
        continue;
      }

      for (const ct of hostList) {
        const lockKey = ct.name.toLowerCase();
        if (
          this.inFlightPanelCreations.has(lockKey) ||
          (node.is_local && cm.isCreationInFlight(ct.name))
        ) {
          continue;
        }
        const existing = await this.db.get<{ id: number }>(
          `SELECT id FROM lxc_instances WHERE node_id = ? AND LOWER(container_name) = LOWER(?)`,
          [node.id, ct.name]
        );
        if (existing) {
          // Keep live runtime status & IP synchronized on already-tracked containers
          const liveState =
            ct.state === 'running' ? 'running' : ct.state === 'frozen' ? 'frozen' : 'stopped';
          const liveIp = ct.ips && ct.ips.length > 0 ? ct.ips[0] : null;
          await this.db
            .run(
              `UPDATE lxc_instances
               SET status = CASE WHEN suspended = 1 THEN status ELSE ? END,
                   ip_address = COALESCE(ip_address, ?)
               WHERE id = ?`,
              [liveState, liveIp, existing.id]
            )
            .catch(() => undefined);
          await this.syncRegistryRow(existing.id).catch(() => undefined);
          continue;
        }

        // Also avoid duplicate global name collisions if same name was registered before node_id scoping
        const anyNameMatch = await this.db.get<{ id: number }>(
          `SELECT id FROM lxc_instances WHERE LOWER(container_name) = LOWER(?)`,
          [ct.name]
        );
        if (anyNameMatch) continue;

        const status =
          ct.state === 'running' ? 'running' : ct.state === 'frozen' ? 'frozen' : 'stopped';
        const detectedIp = ct.ips && ct.ips.length > 0 ? ct.ips[0] : null;
        const ins = await this.db.run(
          `INSERT INTO lxc_instances (
            user_id, node_id, container_name, hostname, os_template, os_family, arch,
            cpu_cores, ram_mb, swap_mb, disk_gb, privileged, nesting, bridge, ip_address, status, notes
          ) VALUES (?, ?, ?, ?, 'imported', 'linux', 'amd64', 2, 1024, 512, 20, 1, 1, 'lxcbr0', ?, ?, ?)`,
          [
            defaultUserId,
            node.id,
            ct.name,
            ct.name,
            detectedIp,
            status,
            `Imported from node "${node.name}"`,
          ]
        );
        await this.syncRegistryRow(ins.lastID);
        imported.push(ct.name);
        if (!byNode[node.id]) byNode[node.id] = [];
        byNode[node.id].push(ct.name);
      }
    }

    return { imported, count: imported.length, byNode };
  }

  private async dispatchNodeContainerAction(
    nodeId: number,
    isLocal: boolean,
    containerName: string,
    action: string,
    extra: Record<string, unknown> = {}
  ): Promise<LxcContainerRuntimeInfo | null> {
    if (isLocal) {
      const mgr = this.nodeManager.localRuntime.containerManager;
      switch (action) {
        case 'start':
          await mgr.startContainer(containerName);
          break;
        case 'stop':
          await mgr.stopContainer(containerName, Boolean(extra.force));
          break;
        case 'restart':
          await mgr.restartContainer(containerName);
          break;
        case 'freeze':
          await mgr.freezeContainer(containerName);
          break;
        case 'unfreeze':
          await mgr.unfreezeContainer(containerName);
          break;
        case 'destroy':
          await mgr.destroyContainer(containerName);
          return mgr.inspectContainer(containerName);
        case 'password':
          await mgr.setRootPassword(containerName, String(extra.password || ''));
          break;
        case 'ssh_key':
          await mgr.injectSshPublicKey(containerName, String(extra.sshPublicKey || ''));
          break;
      }
      return mgr.inspectContainer(containerName);
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ container: LxcContainerRuntimeInfo }>(
        nodeId,
        'POST',
        `/api/v1/containers/${encodeURIComponent(containerName)}/action`,
        { action, ...extra }
      );
      return resp.container || null;
    }
  }

  private async inspectHostContainer(
    nodeId: number,
    isLocal: boolean,
    containerName: string
  ): Promise<LxcContainerRuntimeInfo | null> {
    if (isLocal) {
      return this.nodeManager.localRuntime.containerManager.inspectContainer(containerName);
    }
    const resp = await this.nodeManager.requestRemoteNode<LxcContainerRuntimeInfo>(
      nodeId,
      'GET',
      `/api/v1/containers/${encodeURIComponent(containerName)}`
    );
    return resp || null;
  }

  private assertContainerRuntimeState(
    action: string,
    info: LxcContainerRuntimeInfo | null,
    expected: 'running' | 'stopped' | 'frozen'
  ): void {
    if (!info) {
      throw new Error(
        `LXC ${action} did not return host container state; refusing to persist panel status.`
      );
    }
    if (info.state !== expected) {
      throw new Error(
        `LXC ${action} did not reach expected "${expected}" state on host; host reports "${info.state}".`
      );
    }
  }

  private assertContainerDestroyed(action: string, info: LxcContainerRuntimeInfo | null): void {
    if (!info) {
      throw new Error(
        `LXC ${action} did not return host container state after destruction; refusing to remove panel records.`
      );
    }
    if (info.state !== 'missing') {
      throw new Error(
        `LXC ${action} did not remove the container on host; host reports "${info.state}". Refusing to remove panel records.`
      );
    }
  }

  public async performLifecycleAction(
    refId: number,
    action: LifecycleAction,
    options?: { reason?: string; actorId?: number; force?: boolean }
  ): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    // LXC containers have no graceful guest-shutdown lifecycle; only the host can stop them.
    // Reject instead of silently no-op'ing so callers never mistake a no-op for a shutdown.
    if (action === 'shutdown') {
      throw Object.assign(
        new Error('Graceful shutdown is not supported for LXC containers; use stop.'),
        { statusCode: 501 }
      );
    }

    const isLocal = Boolean(row.is_local);
    const cname = row.container_name;

    if (action === 'start') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be started until unsuspended.');
      }
      const info = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'start');
      this.assertContainerRuntimeState('start', info, 'running');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', ip_address = COALESCE(?, ip_address), updated_at = datetime('now') WHERE id = ?`,
        [info?.ips?.[0] || null, refId]
      );
    } else if (action === 'stop') {
      const stopInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'stop', {
        force: options?.force,
      });
      this.assertContainerRuntimeState('stop', stopInfo, 'stopped');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'stopped', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'restart') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be restarted.');
      }
      const restartInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'restart');
      this.assertContainerRuntimeState('restart', restartInfo, 'running');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'freeze') {
      const freezeInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'freeze');
      this.assertContainerRuntimeState('freeze', freezeInfo, 'frozen');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'frozen', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'unfreeze') {
      if (row.suspended) {
        throw new Error('This LXC VPS is suspended and cannot be unfrozen until unsuspended.');
      }
      const unfreezeInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'unfreeze');
      this.assertContainerRuntimeState('unfreeze', unfreezeInfo, 'running');
      await this.db.run(
        `UPDATE lxc_instances SET status = 'running', updated_at = datetime('now') WHERE id = ?`,
        [refId]
      );
    } else if (action === 'suspend') {
      // Do not persist suspension if the host could not stop the guest; that would leave
      // a live container behind a panel state that claims it has been stopped.
      const stopInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'stop', { force: true });
      this.assertContainerRuntimeState('suspend', stopInfo, 'stopped');
      let history: any[] = [];
      try {
        history = JSON.parse(row.suspension_history || '[]');
      } catch {
        history = [];
      }
      history.push({
        event: 'suspended',
        reason: options?.reason || 'Administrative suspension',
        actorId: options?.actorId || null,
        at: new Date().toISOString(),
      });
      await this.db.run(
        `UPDATE lxc_instances
         SET suspended = 1, suspended_reason = ?, suspension_history = ?, status = 'stopped', updated_at = datetime('now')
         WHERE id = ?`,
        [options?.reason || 'Administrative suspension', JSON.stringify(history), refId]
      );
    } else if (action === 'unsuspend') {
      let history: any[] = [];
      try {
        history = JSON.parse(row.suspension_history || '[]');
      } catch {
        history = [];
      }
      history.push({
        event: 'unsuspended',
        actorId: options?.actorId || null,
        at: new Date().toISOString(),
      });
      await this.db.run(
        `UPDATE lxc_instances
         SET suspended = 0, suspended_reason = NULL, suspension_history = ?, updated_at = datetime('now')
         WHERE id = ?`,
        [JSON.stringify(history), refId]
      );
    } else if (action === 'delete') {
      // Preserve the panel record and allocations if the host refuses, fails, or leaves the container behind.
      const existing = await this.inspectHostContainer(row.node_id, isLocal, cname);
      if (!existing || existing.state === 'missing') {
        // Meta-only or already-missing containers have no host artifact to destroy.
      } else {
        const destroyInfo = await this.dispatchNodeContainerAction(row.node_id, isLocal, cname, 'destroy');
        this.assertContainerDestroyed('delete', destroyInfo);
      }
      await this.db
        .run(
          `UPDATE ip_allocations
           SET instance_type = NULL, instance_ref_id = NULL, assigned_user_id = NULL
           WHERE instance_type = 'lxc' AND instance_ref_id = ?`,
          [refId]
        )
        .catch(() => undefined);
      await this.db
        .run(`DELETE FROM port_forwards WHERE instance_type = 'lxc' AND instance_ref_id = ?`, [
          refId,
        ])
        .catch(() => undefined);
      await this.db
        .run(`DELETE FROM metrics_history WHERE target_type = 'lxc' AND target_id = ?`, [refId])
        .catch(() => undefined);
      await this.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [refId]);
      await this.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [refId]);
      return this.mapRowToUnified({ ...row, status: 'deleted' });
    }

    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async resizeAndUpdateConfig(
    refId: number,
    patch: {
      hostname?: string;
      cpuCores?: number;
      cpuShares?: number;
      cpuLimitPercent?: number;
      cpuPinning?: string | null;
      ramMb?: number;
      swapMb?: number;
      diskGb?: number;
      nesting?: boolean;
      kvmNesting?: boolean;
      autostart?: boolean;
      bridge?: string;
      ipAddress?: string | null;
      gateway?: string | null;
      ipv6Address?: string | null;
      macAddress?: string | null;
      bandwidthQuotaGb?: number;
      unlimitedBandwidth?: boolean;
      notes?: string;
    },
    applyToHost = true
  ): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    if (applyToHost) {
      const resourcePayload = {
        cpuCores: patch.cpuCores ?? row.cpu_cores,
        cpuShares: patch.cpuShares ?? row.cpu_shares,
        cpuLimitPercent: patch.cpuLimitPercent ?? row.cpu_limit_pct,
        cpuPinning: patch.cpuPinning !== undefined ? patch.cpuPinning : row.cpu_pinning,
        ramMb: patch.ramMb ?? row.ram_mb,
        swapMb: patch.swapMb ?? row.swap_mb,
        diskGb: patch.diskGb ?? row.disk_gb,
        nesting: patch.nesting !== undefined ? patch.nesting : Boolean(row.nesting),
        kvmNesting: patch.kvmNesting !== undefined ? patch.kvmNesting : Boolean(row.kvm_nesting),
        autostart: patch.autostart !== undefined ? patch.autostart : Boolean(row.autostart),
        bridge: patch.bridge ?? row.bridge,
        ipv4Address: patch.ipAddress !== undefined ? patch.ipAddress : row.ip_address,
        ipv4Gateway: patch.gateway !== undefined ? patch.gateway : row.gateway,
        ipv6Address: patch.ipv6Address !== undefined ? patch.ipv6Address : row.ipv6_address,
        macAddress: patch.macAddress !== undefined ? patch.macAddress : row.mac_address,
      };

      if (row.is_local) {
        const cfgFileExists =
          this.nodeManager.localRuntime.containerManager.getContainerDir(row.container_name);
        try {
          await this.nodeManager.localRuntime.containerManager.updateContainerResources(
            row.container_name,
            resourcePayload
          );
          const refreshed = await this.nodeManager.localRuntime.containerManager
            .inspectContainer(row.container_name)
            .catch(() => null);
          if (refreshed?.diskQuotaEnforced && row.rootfs_storage_type !== 'loop') {
            await this.db.run(
              `UPDATE lxc_instances SET rootfs_storage_type = 'loop' WHERE id = ?`,
              [refId]
            );
          }
        } catch (err: any) {
          // If container dir exists on disk, surface real error; otherwise allow DB config edit when host is in controller-only mode
          if (!String(err.message).includes('Container config not found') || !cfgFileExists) {
            throw err;
          }
        }
      } else {
        await this.nodeManager.requestRemoteNode(
          row.node_id,
          'PATCH',
          `/api/v1/containers/${encodeURIComponent(row.container_name)}/resources`,
          resourcePayload
        );
      }
    }

    await this.db.run(
      `UPDATE lxc_instances SET
         hostname = COALESCE(?, hostname),
         cpu_cores = COALESCE(?, cpu_cores),
         cpu_shares = COALESCE(?, cpu_shares),
         cpu_limit_pct = COALESCE(?, cpu_limit_pct),
         cpu_pinning = CASE WHEN ? = '__KEEP__' THEN cpu_pinning ELSE ? END,
         ram_mb = COALESCE(?, ram_mb),
         swap_mb = COALESCE(?, swap_mb),
         disk_gb = COALESCE(?, disk_gb),
         nesting = COALESCE(?, nesting),
         kvm_nesting = COALESCE(?, kvm_nesting),
         autostart = COALESCE(?, autostart),
         bridge = COALESCE(?, bridge),
         ip_address = CASE WHEN ? = '__KEEP__' THEN ip_address ELSE ? END,
         gateway = CASE WHEN ? = '__KEEP__' THEN gateway ELSE ? END,
         ipv6_address = CASE WHEN ? = '__KEEP__' THEN ipv6_address ELSE ? END,
         bandwidth_quota_gb = COALESCE(?, bandwidth_quota_gb),
         unlimited_bandwidth = COALESCE(?, unlimited_bandwidth),
         notes = COALESCE(?, notes),
         updated_at = datetime('now')
       WHERE id = ?`,
      [
        patch.hostname ?? null,
        patch.cpuCores ?? null,
        patch.cpuShares ?? null,
        patch.cpuLimitPercent ?? null,
        patch.cpuPinning === undefined ? '__KEEP__' : 'SET',
        patch.cpuPinning ?? null,
        patch.ramMb ?? null,
        patch.swapMb ?? null,
        patch.diskGb ?? null,
        patch.nesting !== undefined ? (patch.nesting ? 1 : 0) : null,
        patch.kvmNesting !== undefined ? (patch.kvmNesting ? 1 : 0) : null,
        patch.autostart !== undefined ? (patch.autostart ? 1 : 0) : null,
        patch.bridge ?? null,
        patch.ipAddress === undefined ? '__KEEP__' : 'SET',
        patch.ipAddress ?? null,
        patch.gateway === undefined ? '__KEEP__' : 'SET',
        patch.gateway ?? null,
        patch.ipv6Address === undefined ? '__KEEP__' : 'SET',
        patch.ipv6Address ?? null,
        patch.bandwidthQuotaGb ?? null,
        patch.unlimitedBandwidth !== undefined ? (patch.unlimitedBandwidth ? 1 : 0) : null,
        patch.notes ?? null,
        refId,
      ]
    );

    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async cloneStoppedLxcInstance(refId: number, newName: string): Promise<{
    instance: UnifiedInstanceRecord;
    sourceName: string;
    networkDetached: true;
    guestIdentityResetRequired: true;
  }> {
    const source = await this.getRawLxcRow(refId);
    if (!source) throw Object.assign(new Error(`LXC container #${refId} not found.`), { statusCode: 404 });
    if (source.suspended) throw Object.assign(new Error('Unsuspend the source before cloning.'), { statusCode: 409 });
    if (String(source.status || '').toLowerCase() !== 'stopped') {
      throw Object.assign(new Error('LXC cloning is offline-only; stop the source container first.'), { statusCode: 409 });
    }
    if (String(source.rootfs_storage_type || 'dir').toLowerCase() !== 'dir') {
      throw Object.assign(new Error('LXC clone currently supports directory-backed containers only; other storage backends are not exposed.'), { statusCode: 501 });
    }
    const name = SafeValidators.containerName(newName);
    if (name.toLowerCase() === String(source.container_name).toLowerCase()) throw new Error('Clone name must differ from the source name.');
    const duplicate = await this.db.get<any>(`SELECT id FROM lxc_instances WHERE LOWER(container_name) = LOWER(?)`, [name]);
    if (duplicate) throw Object.assign(new Error(`LXC container "${name}" already exists.`), { statusCode: 409 });

    const resources = {
      cpuCores: Number(source.cpu_cores || 1),
      cpuShares: Number(source.cpu_shares || 1024),
      cpuLimitPercent: Number(source.cpu_limit_pct || 100),
      cpuPinning: source.cpu_pinning || null,
      ramMb: Number(source.ram_mb || 1024),
      swapMb: Number(source.swap_mb || 0),
      nesting: Boolean(source.nesting),
      kvmNesting: Boolean(source.kvm_nesting),
    };
    const nodeId = Number(source.node_id);
    let hostCreated = false;
    let insertedLxcId: number | null = null;
    try {
      if (source.is_local) {
        await this.nodeManager.localRuntime.containerManager.cloneContainer(source.container_name, name, resources);
      } else {
        await this.nodeManager.requestRemoteNode(nodeId, 'POST', `/api/v1/containers/${encodeURIComponent(source.container_name)}/clone`, {
          targetName: name,
          ...resources,
        }, 600_000);
      }
      hostCreated = true;

      const macAddress = `00:16:3e:${[0, 1, 2].map(() => crypto.randomInt(0, 256).toString(16).padStart(2, '0')).join(':')}`;
      const inserted = await this.db.run(
        `INSERT INTO lxc_instances (
          user_id, node_id, container_name, hostname, os_template, os_family, arch,
          cpu_cores, cpu_shares, cpu_limit_pct, cpu_pinning, ram_mb, swap_mb, disk_gb,
          rootfs_storage_type, privileged, nesting, kvm_nesting, autostart, root_password_enc,
          bridge, ip_address, gateway, ipv6_address, mac_address, vlan_id,
          status, bandwidth_quota_gb, unlimited_bandwidth, notes, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'dir', ?, ?, ?, 0, ?, NULL, NULL, NULL, NULL, ?, NULL, 'stopped', ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          source.user_id, nodeId, name, name, source.os_template, source.os_family, source.arch,
          resources.cpuCores, resources.cpuShares, resources.cpuLimitPercent, resources.cpuPinning,
          resources.ramMb, resources.swapMb, Number(source.disk_gb || 20), source.privileged ? 1 : 0, source.nesting ? 1 : 0,
          source.kvm_nesting ? 1 : 0, source.root_password_enc || null, macAddress,
          Number(source.bandwidth_quota_gb || 0), source.unlimited_bandwidth ? 1 : 0, `Offline clone of ${source.container_name}; review guest identity and network before use.`,
          source.expires_at || null, Number(source.expiration_days || 0), source.auto_suspend_enabled !== 0 ? 1 : 0,
        ]
      );
      const newId = inserted.lastID;
      insertedLxcId = newId;
      if (source.expires_at || Number(source.expiration_days || 0) > 0) {
        await this.db.run(
          `INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
           VALUES (?, ?, ?, ?, datetime('now'))`,
          [newId, source.expires_at || null, Number(source.expiration_days || 0), source.auto_suspend_enabled !== 0 ? 1 : 0]
        );
      }
      await this.syncRegistryRow(newId);
      return {
        instance: (await this.getInstance(newId))!,
        sourceName: source.container_name,
        networkDetached: true,
        guestIdentityResetRequired: true,
      };
    } catch (err) {
      if (insertedLxcId) {
        await this.db.run(`DELETE FROM vps_expiration WHERE lxc_id = ?`, [insertedLxcId]).catch(() => undefined);
        await this.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [insertedLxcId]).catch(() => undefined);
        await this.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [insertedLxcId]).catch(() => undefined);
      }
      if (hostCreated) {
        if (source.is_local) await this.nodeManager.localRuntime.containerManager.destroyContainer(name).catch(() => undefined);
        else await this.nodeManager.requestRemoteNode(nodeId, 'POST', `/api/v1/containers/${encodeURIComponent(name)}/action`, { action: 'destroy' }).catch(() => undefined);
      }
      throw err;
    }
  }

  public async reinstallLxcInstance(
    refId: number,
    templateSlug: string,
    newRootPassword?: string
  ): Promise<{ instance: UnifiedInstanceRecord; rootPassword: string }> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.suspended) {
      throw Object.assign(
        new Error('This LXC VPS is suspended and cannot be reinstalled until unsuspended.'),
        { statusCode: 400 }
      );
    }

    const tpl = await this.resolveCatalogTemplate(templateSlug);
    if (!tpl) throw new Error(`Enabled LXC template "${templateSlug}" not found.`);

    const reinstallProxmoxCodename = resolveProxmoxLxcCodename({
      proxmoxCodename: tpl.proxmox_codename || null,
      templateSlug: tpl.slug || templateSlug,
      distro: tpl.distro,
      release: tpl.release,
      category: tpl.category || null,
    });
    const reinstallIsProxmox = reinstallProxmoxCodename !== null;

    const plainPassword = newRootPassword?.trim() || generateStrongPassword(18);
    const reinstallCpuCores = Math.max(Number(row.cpu_cores || 1), reinstallIsProxmox ? 2 : 0);
    const reinstallRamMb = Math.max(Number(row.ram_mb || 1024), Number(tpl.min_ram_mb || 0), reinstallIsProxmox ? 4096 : 0);
    const reinstallDiskGb = Math.max(Number(row.disk_gb || 20), Number(tpl.min_disk_gb || 0), reinstallIsProxmox ? 40 : 0);
    const reinstallSpec: LxcCreateSpec = {
      containerName: row.container_name,
      hostname: row.hostname || row.container_name,
      distro: tpl.distro,
      release: tpl.release,
      fallbackRelease: tpl.fallback_alias || null,
      templateArchivePath: tpl.file_path || tpl.local_path || null,
      arch: tpl.arch || 'amd64',
      cpuCores: reinstallCpuCores,
      cpuShares: row.cpu_shares,
      cpuLimitPercent: row.cpu_limit_pct,
      ramMb: reinstallRamMb,
      swapMb: row.swap_mb,
      diskGb: reinstallDiskGb,
      backingStore: row.rootfs_storage_type || 'dir',
      privileged: reinstallIsProxmox ? true : Boolean(row.privileged),
      nesting: reinstallIsProxmox ? true : Boolean(row.nesting),
      kvmNesting: reinstallIsProxmox ? true : Boolean(row.kvm_nesting),
      proxmoxCodename: reinstallProxmoxCodename,
      proxmoxGpgUrl: reinstallProxmoxCodename
        ? PROXMOX_LXC_GPG_URLS[reinstallProxmoxCodename] || null
        : null,
      bridge: row.bridge || 'lxcbr0',
      ipv4Address: row.ip_address || null,
      ipv4Gateway: row.gateway || null,
      rootPassword: plainPassword,
    };

    let reinstallState = 'running';
    if (row.is_local) {
      const info = await this.nodeManager.localRuntime.containerManager.reinstallContainer(reinstallSpec);
      reinstallState = info.state === 'running' ? 'running' : 'stopped';
    } else {
      if (reinstallSpec.templateArchivePath && fs.existsSync(reinstallSpec.templateArchivePath)) {
        reinstallSpec.templateArchivePath = await this.ensureTemplateStagedOnRemoteNode(
          row.node_id,
          reinstallSpec.templateArchivePath
        );
      }
      const resp = await this.nodeManager.requestRemoteNode<
        LxcContainerRuntimeInfo | { success?: boolean; container?: LxcContainerRuntimeInfo }
      >(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/reinstall`,
        reinstallSpec,
        600_000
      );
      const info = (resp as any)?.container || resp;
      reinstallState = info?.state === 'running' ? 'running' : 'stopped';
    }

    await this.db.run(
      `UPDATE lxc_instances
       SET os_template = ?, os_family = ?, root_password_enc = ?, status = ?,
           cpu_cores = ?, ram_mb = ?, disk_gb = ?,
           privileged = ?, nesting = ?, kvm_nesting = ?,
           updated_at = datetime('now')
       WHERE id = ?`,
      [
        tpl.slug,
        tpl.family || 'debian',
        encryptSecret(plainPassword),
        reinstallState,
        reinstallSpec.cpuCores,
        reinstallSpec.ramMb,
        reinstallSpec.diskGb,
        reinstallSpec.privileged ? 1 : 0,
        reinstallSpec.nesting ? 1 : 0,
        reinstallSpec.kvmNesting ? 1 : 0,
        refId,
      ]
    );

    await this.syncRegistryRow(refId);
    return { instance: (await this.getInstance(refId))!, rootPassword: plainPassword };
  }

  public async resetRootPassword(refId: number, newPassword?: string): Promise<string> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const password = newPassword?.trim() || generateStrongPassword(18);

    await this.dispatchNodeContainerAction(
      row.node_id,
      Boolean(row.is_local),
      row.container_name,
      'password',
      { password }
    );

    await this.db.run(
      `UPDATE lxc_instances SET root_password_enc = ?, updated_at = datetime('now') WHERE id = ?`,
      [encryptSecret(password), refId]
    );
    return password;
  }

  public async getDecryptedRootPassword(refId: number): Promise<string> {
    const row = await this.db.get<{ root_password_enc: string | null }>(
      `SELECT root_password_enc FROM lxc_instances WHERE id = ?`,
      [refId]
    );
    if (!row?.root_password_enc) return '';
    return decryptSecret(row.root_password_enc);
  }

  public async injectSshKey(refId: number, publicKey: string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    await this.dispatchNodeContainerAction(
      row.node_id,
      Boolean(row.is_local),
      row.container_name,
      'ssh_key',
      { sshPublicKey: publicKey }
    );
  }

  public async renewExpiration(refId: number, additionalDays: number): Promise<UnifiedInstanceRecord> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const days = Math.max(1, Number(additionalDays || 30));
    const baseMs =
      row.expires_at && new Date(row.expires_at).getTime() > Date.now()
        ? new Date(row.expires_at).getTime()
        : Date.now();
    const nextIso = new Date(baseMs + days * 86_400_000).toISOString();

    await this.db.run(
      `UPDATE lxc_instances
       SET expires_at = ?, expiration_days = ?, last_renewed_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
      [nextIso, days, refId]
    );
    await this.db.run(
      `INSERT OR REPLACE INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled, last_renewed_at)
       VALUES (?, ?, ?, COALESCE((SELECT auto_suspend_enabled FROM vps_expiration WHERE lxc_id = ?), 1), datetime('now'))`,
      [refId, nextIso, days, refId]
    );
    return (await this.getInstance(refId))!;
  }

  /**
   * Expiration sweeper: finds LXC instances whose `vps_expiration.expires_at` has
   * passed with `auto_suspend_enabled = 1` and suspends them through the normal
   * lifecycle path (host-verified stop, `suspended` flag, suspension history).
   * `warned_at` is stamped on first evaluation. Instances that are already
   * suspended, not running/frozen, or whose host refuses the stop are skipped
   * honestly (the skip reason is recorded on the expiration row's `notes`).
   * Returns a summary so callers (manual route or background loop) can notify
   * affected owners.
   */
  public async sweepExpiredInstances(): Promise<{
    evaluated: number;
    suspended: Array<{
      lxcId: number;
      containerName: string;
      ownerUserId: number;
      expiresAt: string;
    }>;
    skipped: Array<{ lxcId: number; reason: string }>;
  }> {
    const expired = await this.db.all<any>(
      `SELECT e.lxc_id, e.expires_at, e.warned_at,
              l.container_name, l.status, l.suspended, l.user_id
       FROM vps_expiration e
       JOIN lxc_instances l ON l.id = e.lxc_id
       WHERE e.expires_at IS NOT NULL
         AND datetime(e.expires_at) <= datetime('now')
         AND e.auto_suspend_enabled = 1
         AND l.suspended = 0
         AND l.status IN ('running', 'frozen')
       ORDER BY e.lxc_id ASC`
    );

    const suspended: Array<{ lxcId: number; containerName: string; ownerUserId: number; expiresAt: string }> = [];
    const skipped: Array<{ lxcId: number; reason: string }> = [];

    for (const row of expired) {
      await this.db.run(
        `UPDATE vps_expiration
            SET warned_at = COALESCE(warned_at, datetime('now')), updated_at = datetime('now')
          WHERE lxc_id = ?`,
        [row.lxc_id]
      );
      const reason = `VPS expired on ${row.expires_at}`;
      try {
        await this.performLifecycleAction(row.lxc_id, 'suspend', { reason });
        suspended.push({
          lxcId: row.lxc_id,
          containerName: row.container_name,
          ownerUserId: row.user_id,
          expiresAt: row.expires_at,
        });
      } catch (err: any) {
        const skipReason = `Suspension skipped: ${err?.message || err}`;
        await this.db.run(
          `UPDATE vps_expiration SET notes = ?, updated_at = datetime('now') WHERE lxc_id = ?`,
          [skipReason, row.lxc_id]
        );
        skipped.push({ lxcId: row.lxc_id, reason: skipReason });
      }
    }

    return { evaluated: expired.length, suspended, skipped };
  }

  private expirationTimer: NodeJS.Timeout | null = null;
  private expirationBootTimer: NodeJS.Timeout | null = null;

  /** Starts the periodic expiration sweep loop (default 5 minutes). */
  public startExpirationLoop(intervalMs = 300_000): void {
    if (this.expirationTimer) return;
    this.expirationBootTimer = setTimeout(() => {
      this.expirationBootTimer = null;
      this.sweepExpiredInstances().catch((err) => {
        console.error('[Expiration] Initial sweep failed:', err?.message || err);
      });
    }, 5000);
    this.expirationBootTimer.unref?.();
    this.expirationTimer = setInterval(() => {
      this.sweepExpiredInstances().catch((err) => {
        console.error('[Expiration] Sweep failed:', err?.message || err);
      });
    }, intervalMs);
    this.expirationTimer.unref?.();
  }

  public stopExpirationLoop(): void {
    if (this.expirationTimer) clearInterval(this.expirationTimer);
    if (this.expirationBootTimer) clearTimeout(this.expirationBootTimer);
    this.expirationTimer = null;
    this.expirationBootTimer = null;
  }

  public async transferOwnership(refId: number, newUserId: number): Promise<UnifiedInstanceRecord> {
    const user = await this.db.get<{ id: number }>(`SELECT id FROM users WHERE id = ?`, [newUserId]);
    if (!user) throw new Error(`Target user #${newUserId} not found.`);
    await this.db.run(
      `UPDATE lxc_instances SET user_id = ?, updated_at = datetime('now') WHERE id = ?`,
      [newUserId, refId]
    );
    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async updateSharing(refId: number, sharedUserIds: number[]): Promise<UnifiedInstanceRecord> {
    const clean = Array.from(new Set(sharedUserIds.map(Number).filter((n) => Number.isInteger(n) && n > 0)));
    await this.db.run(
      `UPDATE lxc_instances SET shared_with = ?, updated_at = datetime('now') WHERE id = ?`,
      [JSON.stringify(clean), refId]
    );
    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async setWhitelist(refId: number, whitelisted: boolean): Promise<void> {
    await this.db.run(
      `UPDATE lxc_instances SET whitelisted = ?, updated_at = datetime('now') WHERE id = ?`,
      [whitelisted ? 1 : 0, refId]
    );
  }

  private assertProxmoxLxcRow(row: any): void {
    const osTemplate = String(row?.os_template || '').toLowerCase();
    if (!osTemplate.includes('proxmox') && !osTemplate.includes('pve')) {
      throw new Error('Cloudflare Quick Tunnel is only available for Proxmox LXC images.');
    }
  }

  public async startProxmoxCloudflareTunnel(refId: number) {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    this.assertProxmoxLxcRow(row);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.startProxmoxCloudflareTunnel(row.container_name);
    }
    return this.nodeManager.requestRemoteNode(
      row.node_id,
      'POST',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/cloudflare-tunnel`,
      {},
      20_000
    );
  }

  public async getProxmoxCloudflareTunnelStatus(refId: number) {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    this.assertProxmoxLxcRow(row);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.getProxmoxCloudflareTunnelStatus(row.container_name);
    }
    return this.nodeManager.requestRemoteNode(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/cloudflare-tunnel`
    );
  }

  public async getProcesses(refId: number) {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.getContainerProcesses(row.container_name);
    }
    const resp = await this.nodeManager.requestRemoteNode<{ processes: any[] }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/processes`
    );
    return resp.processes || [];
  }

  public async getLogs(refId: number): Promise<string> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.getContainerLogs(row.container_name);
    }
    const resp = await this.nodeManager.requestRemoteNode<{ logs: string }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/logs`
    );
    return resp.logs || '';
  }

  public async listFiles(refId: number, subPath = '/') {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.listRootfsDirectory(
        row.container_name,
        subPath
      );
    }
    const resp = await this.nodeManager.requestRemoteNode<{ entries: any[] }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files?path=${encodeURIComponent(subPath)}`
    );
    return resp.entries || [];
  }

  public async readFile(refId: number, subPath: string): Promise<Buffer> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      return this.nodeManager.localRuntime.containerManager.readRootfsFile(
        row.container_name,
        subPath
      );
    }
    const resp = await this.nodeManager.requestRemoteNode<{ contentBase64: string }>(
      row.node_id,
      'GET',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files/content?path=${encodeURIComponent(subPath)}`
    );
    return Buffer.from(resp.contentBase64 || '', 'base64');
  }

  public async writeFile(refId: number, subPath: string, content: Buffer | string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    if (row.is_local) {
      this.nodeManager.localRuntime.containerManager.writeRootfsFile(
        row.container_name,
        subPath,
        buf
      );
      return;
    }
    await this.nodeManager.requestRemoteNode(
      row.node_id,
      'POST',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files/content`,
      { path: subPath, contentBase64: buf.toString('base64') }
    );
  }

  public async deleteFile(refId: number, subPath: string): Promise<void> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);
    if (row.is_local) {
      this.nodeManager.localRuntime.containerManager.deleteRootfsEntry(row.container_name, subPath);
      return;
    }
    await this.nodeManager.requestRemoteNode(
      row.node_id,
      'DELETE',
      `/api/v1/containers/${encodeURIComponent(row.container_name)}/files?path=${encodeURIComponent(subPath)}`
    );
  }

  public async getTelemetry(refId: number): Promise<InstanceTelemetry> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    let runtime: LxcContainerRuntimeInfo;
    if (row.is_local) {
      runtime = await this.nodeManager.localRuntime.containerManager.inspectContainer(
        row.container_name,
        { sampleCpu: true }
      );
    } else {
      runtime = await this.nodeManager.requestRemoteNode<LxcContainerRuntimeInfo>(
        row.node_id,
        'GET',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}?telemetry=1`
      );
    }

    const nowMs = Date.now();
    const cores = Math.max(1, Number(row.cpu_cores || 1));
    let cpuPercent = 0;

    if (runtime.state !== 'running') {
      cpuPercent = 0;
      this.prevContainerCpu.delete(refId);
    } else if (
      typeof runtime.cpuCoresUsed === 'number' &&
      Number.isFinite(runtime.cpuCoresUsed)
    ) {
      cpuPercent = Number(
        Math.min(100, Math.max(0, (runtime.cpuCoresUsed / cores) * 100)).toFixed(2)
      );
      this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
    } else {
      // Backward-compatible fallback for older remote Node Agents without `cpuCoresUsed`
      const prev = this.prevContainerCpu.get(refId);
      if (prev && nowMs > prev.tsMs && runtime.cpuUseSeconds >= prev.cpuSec) {
        const elapsedMs = nowMs - prev.tsMs;
        if (elapsedMs >= 200 && elapsedMs <= 60_000) {
          const elapsedSec = elapsedMs / 1000;
          const deltaCpuSec = runtime.cpuUseSeconds - prev.cpuSec;
          cpuPercent = Number(
            Math.min(100, Math.max(0, ((deltaCpuSec / elapsedSec) / cores) * 100)).toFixed(2)
          );
          this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
        } else if (elapsedMs > 60_000) {
          this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
        }
      } else {
        this.prevContainerCpu.set(refId, { cpuSec: runtime.cpuUseSeconds, tsMs: nowMs });
      }
    }

    const ramUsedMb = Math.round(runtime.memoryBytes / (1024 * 1024));
    const ramTotalMb = Math.max(1, Number(row.ram_mb || 1024));
    const diskUsedGb = Number((runtime.diskUsedBytes / (1024 * 1024 * 1024)).toFixed(2));
    const status =
      runtime.state === 'missing'
        ? row.suspended
          ? 'suspended'
          : row.status || 'stopped'
        : runtime.state;

    const liveIp = runtime.ips?.[0] || runtime.configuredIpv4 || row.ip_address || null;
    if (liveIp && !row.ip_address) {
      await this.db
        .run(
          `UPDATE lxc_instances SET ip_address = ?, gateway = COALESCE(gateway, ?), updated_at = datetime('now') WHERE id = ?`,
          [
            liveIp,
            runtime.configuredGateway && runtime.configuredGateway !== 'auto'
              ? runtime.configuredGateway
              : null,
            refId,
          ]
        )
        .catch(() => undefined);
      await this.syncRegistryRow(refId).catch(() => undefined);
    }

    return {
      engine: 'lxc',
      refId,
      status,
      pid: runtime.pid,
      cpuPercent,
      ramUsedMb,
      ramTotalMb,
      ramPercent: Number(Math.min(100, (ramUsedMb / ramTotalMb) * 100).toFixed(2)),
      diskUsedGb,
      diskTotalGb: Number(row.disk_gb || 20),
      netRxBytes: runtime.rxBytes,
      netTxBytes: runtime.txBytes,
      primaryIp: liveIp,
      measuredAt: new Date().toISOString(),
    };
  }

  public async repairLxcNetworking(refId: number): Promise<{
    repair: LxcNetworkRepairResult;
    instance: UnifiedInstanceRecord;
  }> {
    const row = await this.getRawLxcRow(refId);
    if (!row) throw new Error(`LXC container #${refId} not found.`);

    let repair: LxcNetworkRepairResult;
    const desiredBridge = row.bridge || 'lxcbr0';
    if (row.is_local) {
      repair = await this.nodeManager.localRuntime.containerManager.repairContainerNetworking(
        row.container_name,
        desiredBridge
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ repair: LxcNetworkRepairResult }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/repair-network`,
        { bridge: desiredBridge }
      );
      repair = resp.repair;
    }

    if (repair.ipv4Address || repair.gateway) {
      await this.db.run(
        `UPDATE lxc_instances
         SET ip_address = COALESCE(?, ip_address),
             gateway = COALESCE(?, gateway),
             updated_at = datetime('now')
         WHERE id = ?`,
        [repair.ipv4Address || null, repair.gateway || null, refId]
      );
      await this.syncRegistryRow(refId);
    }

    return {
      repair,
      instance: (await this.getInstance(refId))!,
    };
  }

  /**
   * Automatically heals bridge NAT/FORWARD/DNS-relay rules, cgroup RAM/CPU limits, `lxcfs`
   * `/proc` virtualization, and sparse `ext4` loop disk quotas on active local LXC containers
   * during HKVM server startup.
   */
  public async healLocalContainersNetworking(): Promise<void> {
    const localNode = await this.db.get<{ id: number }>(
      `SELECT id FROM nodes WHERE is_local = 1 LIMIT 1`
    );
    if (!localNode) return;

    const rows = await this.db.all<{
      id: number;
      container_name: string;
      hostname: string;
      bridge: string | null;
      cpu_cores: number;
      cpu_shares: number;
      cpu_limit_pct: number;
      cpu_pinning: string | null;
      ram_mb: number;
      swap_mb: number;
      disk_gb: number;
      rootfs_storage_type: string;
      nesting: number;
      kvm_nesting: number;
      autostart: number;
      ip_address: string | null;
      gateway: string | null;
      ipv6_address: string | null;
    }>(
      `SELECT id, container_name, hostname, bridge, cpu_cores, cpu_shares, cpu_limit_pct, cpu_pinning,
              ram_mb, swap_mb, disk_gb, rootfs_storage_type, nesting, kvm_nesting, autostart,
              ip_address, gateway, ipv6_address
       FROM lxc_instances WHERE node_id = ? AND suspended = 0`,
      [localNode.id]
    );
    const cm = this.nodeManager.localRuntime.containerManager;
    const isSystemStore = path.resolve(cm.getBaseDir()) === '/var/lib/lxc';
    if (isSystemStore) {
      await cm.ensureHostIsolationReady().catch(() => undefined);
    }

    for (const r of rows) {
      try {
        let info = await cm.inspectContainer(r.container_name);
        if (info.state === 'missing') continue;

        if (isSystemStore) {
          const needsLoopUpgrade = !info.diskQuotaEnforced && r.disk_gb >= 1;
          const cgHeal = cm.needsContainerCgroupRestartOrHeal(
            r.container_name,
            info.state === 'running' ? info.pid : null,
            {
              ramMb: r.ram_mb,
              swapMb: r.swap_mb,
              cpuCores: r.cpu_cores,
              cpuLimitPercent: r.cpu_limit_pct,
              cpuPinning: r.cpu_pinning,
            }
          );

          if (needsLoopUpgrade || cgHeal.rewriteConfig || cgHeal.requiresRestart) {
            const wasRunning = info.state === 'running';
            if (wasRunning && needsLoopUpgrade) {
              await cm.stopContainer(r.container_name).catch(() => undefined);
            }
            await cm.writeManagedConfigSection(r.container_name, {
              hostname: r.hostname || r.container_name,
              cpuCores: r.cpu_cores,
              cpuShares: r.cpu_shares,
              cpuLimitPercent: r.cpu_limit_pct,
              cpuPinning: r.cpu_pinning,
              ramMb: r.ram_mb,
              swapMb: r.swap_mb,
              nesting: Boolean(r.nesting),
              kvmNesting: Boolean(r.kvm_nesting),
              autostart: Boolean(r.autostart),
              bridge: r.bridge || 'lxcbr0',
              ipv4Address: r.ip_address,
              ipv4Gateway: r.gateway,
              ipv6Address: r.ipv6_address,
            });
            if (needsLoopUpgrade) {
              const converted = await cm
                .ensureContainerQuotaDisk(r.container_name, r.disk_gb)
                .catch(() => false);
              if (converted) {
                await this.db.run(
                  `UPDATE lxc_instances SET rootfs_storage_type = 'loop', updated_at = datetime('now') WHERE id = ?`,
                  [r.id]
                );
              }
              if (wasRunning) {
                await cm.startContainer(r.container_name).catch(() => undefined);
              }
            } else if (wasRunning && cgHeal.requiresRestart) {
              await cm.restartContainer(r.container_name).catch(() => undefined);
            } else if (wasRunning) {
              await cm
                .enforceLiveContainerCgroups(r.container_name, {
                  ramMb: r.ram_mb,
                  swapMb: r.swap_mb,
                  cpuCores: r.cpu_cores,
                  cpuLimitPercent: r.cpu_limit_pct,
                  cpuPinning: r.cpu_pinning,
                })
                .catch(() => false);
            }
            info = await cm.inspectContainer(r.container_name);
          } else {
            await cm.ensureExistingQuotaDiskMounted(r.container_name).catch(() => false);
            if (info.state === 'running' && cgHeal.enforceLive) {
              await cm
                .enforceLiveContainerCgroups(r.container_name, {
                  ramMb: r.ram_mb,
                  swapMb: r.swap_mb,
                  cpuCores: r.cpu_cores,
                  cpuLimitPercent: r.cpu_limit_pct,
                  cpuPinning: r.cpu_pinning,
                })
                .catch(() => false);
            }
          }
        }

        // Ensure bridge NAT/FORWARD/DNS-relay + guest DNS + auto-IP if missing
        const repair = await cm.repairContainerNetworking(r.container_name, r.bridge || 'lxcbr0');
        if (repair.ipv4Address || repair.gateway) {
          await this.db.run(
            `UPDATE lxc_instances
             SET ip_address = COALESCE(ip_address, ?),
                 gateway = COALESCE(gateway, ?),
                 updated_at = datetime('now')
             WHERE id = ?`,
            [repair.ipv4Address || null, repair.gateway || null, r.id]
          );
          await this.syncRegistryRow(r.id);
        }
      } catch {
        // non-fatal per-container self-heal
      }
    }
  }
}
